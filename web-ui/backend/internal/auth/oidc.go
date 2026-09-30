package auth

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/url"
	"os"
	"strings"
	"sync/atomic"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

const (
	ScopeRead   = "sysmon.read"
	ScopeManage = "sysmon.manage"
)

type OIDCConfig struct {
	Issuer, RedirectURL, ClientID, ClientSecret string
	ClientFile, RegistrationTokenFile           string
}

func OIDCConfigFromEnv() (OIDCConfig, error) {
	cfg := OIDCConfig{Issuer: strings.TrimSpace(os.Getenv("SYSMON_OIDC_ISSUER")),
		RedirectURL: strings.TrimSpace(os.Getenv("SYSMON_OIDC_REDIRECT_URL")),
		ClientID:    strings.TrimSpace(os.Getenv("SYSMON_OIDC_CLIENT_ID")), ClientSecret: os.Getenv("SYSMON_OIDC_CLIENT_SECRET"),
		ClientFile: strings.TrimSpace(os.Getenv("SYSMON_OIDC_CLIENT_FILE")), RegistrationTokenFile: strings.TrimSpace(os.Getenv("SYSMON_OIDC_REGISTRATION_TOKEN_FILE"))}
	if cfg == (OIDCConfig{}) {
		return cfg, nil
	}
	if cfg.Issuer == "" || cfg.RedirectURL == "" {
		return cfg, errors.New("set SYSMON_OIDC_ISSUER and SYSMON_OIDC_REDIRECT_URL together")
	}
	if (cfg.ClientID == "") != (cfg.ClientSecret == "") {
		return cfg, errors.New("set SYSMON_OIDC_CLIENT_ID and SYSMON_OIDC_CLIENT_SECRET together")
	}
	if cfg.ClientFile == "" {
		cfg.ClientFile = "/var/lib/sysmon/oidc-client.json"
	}
	return cfg, nil
}

func validateOIDCURL(raw string) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return nil, errors.New("invalid OIDC URL")
	}
	if u.Scheme == "https" {
		return u, nil
	}
	ip := net.ParseIP(u.Hostname())
	if u.Scheme == "http" && (u.Hostname() == "localhost" || (ip != nil && ip.IsLoopback())) {
		return u, nil
	}
	return nil, errors.New("OIDC URLs require HTTPS; loopback HTTP is allowed for development")
}

func oidcHTTPClient() *http.Client {
	return &http.Client{Timeout: 15 * time.Second, CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }}
}

func issuerEndpoint(issuer *url.URL, raw string) error {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != issuer.Scheme || u.Host != issuer.Host || u.User != nil || u.Fragment != "" {
		return errors.New("OIDC endpoint must share the issuer origin")
	}
	return nil
}

type OIDCClient struct {
	issuer, clientID, revocation string
	secure                       bool
	oauth                        oauth2.Config
	verifier                     *oidc.IDTokenVerifier
	http                         *http.Client
}

type OIDCIdentity struct {
	Issuer       string    `json:"issuer"`
	ClientID     string    `json:"client_id"`
	Subject      string    `json:"subject"`
	DisplayName  string    `json:"display_name"`
	Role         string    `json:"role"`
	RefreshToken string    `json:"refresh_token"`
	ExpiresAt    time.Time `json:"expires_at"`
}

func NewOIDCClient(ctx context.Context, cfg OIDCConfig) (*OIDCClient, error) {
	issuer, err := validateOIDCURL(cfg.Issuer)
	if err != nil {
		return nil, err
	}
	redirect, err := validateOIDCURL(cfg.RedirectURL)
	if err != nil || redirect.Path != "/auth/callback" {
		return nil, errors.New("OIDC redirect must end in /auth/callback")
	}
	if cfg.ClientID == "" || cfg.ClientSecret == "" {
		return nil, errors.New("OIDC client credentials are required")
	}
	httpClient := oidcHTTPClient()
	provider, err := oidc.NewProvider(oidc.ClientContext(ctx, httpClient), cfg.Issuer)
	if err != nil {
		return nil, fmt.Errorf("OIDC discovery: %w", err)
	}
	var metadata struct {
		Revocation string `json:"revocation_endpoint"`
	}
	if err := provider.Claims(&metadata); err != nil {
		return nil, err
	}
	endpoint := provider.Endpoint()
	if err := issuerEndpoint(issuer, endpoint.TokenURL); err != nil {
		return nil, err
	}
	if metadata.Revocation != "" {
		if err := issuerEndpoint(issuer, metadata.Revocation); err != nil {
			return nil, err
		}
	}
	endpoint.AuthStyle = oauth2.AuthStyleInHeader
	return &OIDCClient{issuer: cfg.Issuer, clientID: cfg.ClientID, revocation: metadata.Revocation, secure: redirect.Scheme == "https", http: httpClient,
		oauth:    oauth2.Config{ClientID: cfg.ClientID, ClientSecret: cfg.ClientSecret, RedirectURL: cfg.RedirectURL, Endpoint: endpoint, Scopes: strings.Fields(registrationScopes)},
		verifier: provider.VerifierContext(oidc.ClientContext(ctx, httpClient), &oidc.Config{ClientID: cfg.ClientID, SupportedSigningAlgs: []string{"RS256"}})}, nil
}

func (c *OIDCClient) SecureCookies() bool { return c.secure }
func (c *OIDCClient) AuthorizationURL(state, nonce, verifier string) string {
	return c.oauth.AuthCodeURL(state, oidc.Nonce(nonce), oauth2.S256ChallengeOption(verifier), oauth2.SetAuthURLParam("prompt", "consent"))
}

func (c *OIDCClient) Exchange(ctx context.Context, code, verifier, nonce string) (identity OIDCIdentity, err error) {
	token, err := c.oauth.Exchange(oidc.ClientContext(ctx, c.http), code, oauth2.VerifierOption(verifier))
	if err != nil {
		return identity, errors.New("OIDC code exchange failed")
	}
	defer func() {
		if err != nil {
			_ = c.Revoke(ctx, token.RefreshToken)
		}
	}()
	raw, _ := token.Extra("id_token").(string)
	id, err := c.verifier.Verify(ctx, raw)
	if err != nil {
		return identity, errors.New("OIDC ID token verification failed")
	}
	if nonce == "" || id.Nonce != nonce {
		return identity, errors.New("OIDC nonce mismatch")
	}
	if id.AccessTokenHash != "" {
		if err := id.VerifyAccessToken(token.AccessToken); err != nil {
			return identity, errors.New("OIDC access token hash mismatch")
		}
	}
	identity, err = c.identityFromAccess(ctx, token, id.Issuer, id.Subject)
	if err != nil {
		return identity, err
	}
	var profile struct {
		Username string `json:"preferred_username"`
		Name     string `json:"name"`
		Email    string `json:"email"`
	}
	if err := id.Claims(&profile); err != nil {
		return identity, err
	}
	identity.DisplayName = strings.TrimSpace(profile.Username)
	if identity.DisplayName == "" {
		identity.DisplayName = strings.TrimSpace(profile.Name)
	}
	if identity.DisplayName == "" {
		identity.DisplayName = strings.TrimSpace(profile.Email)
	}
	if identity.DisplayName == "" {
		identity.DisplayName = identity.Subject
	}
	if token.RefreshToken == "" {
		return identity, errors.New("OIDC client did not receive offline access")
	}
	identity.RefreshToken = token.RefreshToken
	return identity, nil
}

func (c *OIDCClient) Refresh(ctx context.Context, old OIDCIdentity) (identity OIDCIdentity, err error) {
	var connected atomic.Bool
	ctx = httptrace.WithClientTrace(ctx, &httptrace.ClientTrace{GotConn: func(httptrace.GotConnInfo) { connected.Store(true) }})
	source := c.oauth.TokenSource(oidc.ClientContext(ctx, c.http), &oauth2.Token{RefreshToken: old.RefreshToken, Expiry: time.Unix(0, 0)})
	token, err := source.Token()
	if err != nil {
		var transportError *url.Error
		// Only failures before acquiring a connection prove that the token
		// request could not reach authd. Any connected request is ambiguous.
		if !connected.Load() && errors.As(err, &transportError) {
			return OIDCIdentity{}, errOIDCRefreshNotSent
		}
		return OIDCIdentity{}, errors.New("OIDC refresh failed")
	}
	defer func() {
		if err != nil {
			_ = c.Revoke(ctx, token.RefreshToken)
		}
	}()
	identity, err = c.identityFromAccess(ctx, token, old.Issuer, old.Subject)
	if err != nil {
		return OIDCIdentity{}, err
	}
	if token.RefreshToken == "" || token.RefreshToken == old.RefreshToken {
		return OIDCIdentity{}, errors.New("OIDC refresh token did not rotate")
	}
	if raw, ok := token.Extra("id_token").(string); ok && raw != "" {
		id, err := c.verifier.Verify(ctx, raw)
		if err != nil || id.Issuer != old.Issuer || id.Subject != old.Subject {
			return OIDCIdentity{}, errors.New("refreshed OIDC identity changed")
		}
	}
	identity.RefreshToken, identity.DisplayName = token.RefreshToken, old.DisplayName
	return identity, nil
}

func (c *OIDCClient) identityFromAccess(ctx context.Context, token *oauth2.Token, issuer, subject string) (OIDCIdentity, error) {
	parts := strings.Split(token.AccessToken, ".")
	if len(parts) != 3 {
		return OIDCIdentity{}, errors.New("access token is not a JWT")
	}
	header, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return OIDCIdentity{}, errors.New("invalid access token header")
	}
	var h struct {
		Type string `json:"typ"`
	}
	if json.Unmarshal(header, &h) != nil || (h.Type != "at+jwt" && h.Type != "application/at+jwt") {
		return OIDCIdentity{}, errors.New("invalid access token type")
	}
	access, err := c.verifier.Verify(ctx, token.AccessToken)
	if err != nil {
		return OIDCIdentity{}, errors.New("access token verification failed")
	}
	if access.Issuer != issuer || access.Subject == "" || access.Subject != subject {
		return OIDCIdentity{}, errors.New("access token identity mismatch")
	}
	var claims struct {
		Scope    string `json:"scope"`
		ClientID string `json:"client_id"`
	}
	if err := access.Claims(&claims); err != nil {
		return OIDCIdentity{}, err
	}
	if claims.ClientID != c.clientID {
		return OIDCIdentity{}, errors.New("access token client binding mismatch")
	}
	read, manage := false, false
	for _, scope := range strings.Fields(claims.Scope) {
		if scope == ScopeRead {
			read = true
		}
		if scope == ScopeManage {
			manage = true
		}
	}
	if !read {
		return OIDCIdentity{}, errors.New("sysmon.read was not granted")
	}
	role := RoleUser
	if manage {
		role = RoleAdmin
	}
	return OIDCIdentity{Issuer: issuer, ClientID: c.clientID, Subject: subject, Role: role, ExpiresAt: access.Expiry}, nil
}

func oidcUsername(identity OIDCIdentity) string {
	sum := sha256.Sum256([]byte(identity.Issuer + "\x00" + identity.Subject))
	return "authd:" + hex.EncodeToString(sum[:16])
}

func (c *OIDCClient) Revoke(ctx context.Context, refresh string) error {
	if c.revocation == "" || refresh == "" {
		return nil
	}
	form := url.Values{"token": {refresh}, "token_type_hint": {"refresh_token"}}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.revocation, strings.NewReader(form.Encode()))
	if err != nil {
		return err
	}
	req.SetBasicAuth(c.oauth.ClientID, c.oauth.ClientSecret)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
	if resp.StatusCode != 200 && resp.StatusCode != 204 {
		return fmt.Errorf("OIDC revocation returned HTTP %d", resp.StatusCode)
	}
	return nil
}
