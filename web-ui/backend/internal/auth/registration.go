package auth

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"

	"github.com/coreos/go-oidc/v3/oidc"
)

const registrationScopes = "openid profile email offline_access sysmon.read sysmon.manage"

type oidcCredentials struct {
	Issuer          string   `json:"issuer"`
	ClientID        string   `json:"client_id"`
	ClientSecret    string   `json:"client_secret"`
	ManagementURI   string   `json:"registration_client_uri"`
	ManagementToken string   `json:"registration_access_token"`
	RedirectURI     string   `json:"redirect_uri"`
	Scope           string   `json:"scope"`
	GrantTypes      []string `json:"grant_types"`
	AuthMethod      string   `json:"token_endpoint_auth_method"`
}

type oidcRoleTemplate struct {
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Scopes      []string `json:"scopes"`
}

type registrationMetadata struct {
	ClientID        string             `json:"client_id,omitempty"`
	ClientSecret    string             `json:"client_secret,omitempty"`
	ClientName      string             `json:"client_name"`
	RedirectURIs    []string           `json:"redirect_uris"`
	Scope           string             `json:"scope"`
	GrantTypes      []string           `json:"grant_types"`
	ResponseTypes   []string           `json:"response_types"`
	AuthMethod      string             `json:"token_endpoint_auth_method"`
	Roles           []oidcRoleTemplate `json:"authd_role_templates,omitempty"`
	ManagementURI   string             `json:"registration_client_uri,omitempty"`
	ManagementToken string             `json:"registration_access_token,omitempty"`
}

func desiredRegistration(redirect string, withRoles bool) registrationMetadata {
	r := registrationMetadata{ClientName: "Sysmon", RedirectURIs: []string{redirect}, Scope: registrationScopes,
		GrantTypes: []string{"authorization_code", "refresh_token"}, ResponseTypes: []string{"code"}, AuthMethod: "client_secret_basic"}
	if withRoles {
		r.Roles = []oidcRoleTemplate{
			{Name: "sysmon.viewer", Description: "View Sysmon monitoring data", Scopes: []string{ScopeRead}},
			{Name: "sysmon.administrator", Description: "View and manage Sysmon", Scopes: []string{ScopeRead, ScopeManage}},
		}
	}
	return r
}

// EnsureOIDCRegistered uses configured credentials, or Relay's file-based
// bootstrap and managed scope update workflow. Client secrets never enter
// Sysmon's settings API or registration logs.
func EnsureOIDCRegistered(ctx context.Context, cfg OIDCConfig) (OIDCConfig, error) {
	issuer, err := validateOIDCURL(cfg.Issuer)
	if err != nil {
		return cfg, err
	}
	redirect, err := validateOIDCURL(cfg.RedirectURL)
	if err != nil || redirect.Path != "/auth/callback" {
		return cfg, errors.New("OIDC redirect must end in /auth/callback")
	}
	if cfg.ClientID != "" {
		if cfg.ClientSecret == "" {
			return cfg, errors.New("OIDC client secret is missing")
		}
		return cfg, nil
	}
	if cfg.ClientFile == "" {
		cfg.ClientFile = "/var/lib/sysmon/oidc-client.json"
	}
	creds, err := readOIDCCredentials(cfg.ClientFile)
	var response registrationMetadata
	if errors.Is(err, fs.ErrNotExist) {
		if cfg.RegistrationTokenFile == "" {
			return cfg, errors.New("OIDC client is missing; run sysmon-web oidc-bootstrap with a one-use registration token file")
		}
		token, err := readPrivateFile(cfg.RegistrationTokenFile)
		if err != nil {
			return cfg, fmt.Errorf("registration token: %w", err)
		}
		if strings.TrimSpace(token) == "" {
			return cfg, errors.New("registration token file is empty")
		}
		provider, err := oidc.NewProvider(oidc.ClientContext(ctx, oidcHTTPClient()), cfg.Issuer)
		if err != nil {
			return cfg, fmt.Errorf("OIDC discovery: %w", err)
		}
		var discovery struct {
			Endpoint string `json:"registration_endpoint"`
		}
		if provider.Claims(&discovery) != nil || discovery.Endpoint == "" {
			return cfg, errors.New("provider does not advertise dynamic client registration")
		}
		if err := issuerEndpoint(issuer, discovery.Endpoint); err != nil {
			return cfg, err
		}
		if err := registrationCall(ctx, http.MethodPost, discovery.Endpoint, strings.TrimSpace(token), desiredRegistration(cfg.RedirectURL, true), 201, &response); err != nil {
			return cfg, err
		}
		if response.ClientID == "" || response.ClientSecret == "" {
			return cfg, errors.New("registration response lacks client credentials; token may be spent")
		}
		creds = oidcCredentials{Issuer: cfg.Issuer, ClientID: response.ClientID, ClientSecret: response.ClientSecret}
		applyRegistrationResponse(&creds, response)
		if err := writeOIDCCredentials(cfg.ClientFile, creds); err != nil {
			return cfg, fmt.Errorf("registered client %s but could not save credentials; token is spent: %w", creds.ClientID, err)
		}
	} else if err != nil {
		return cfg, err
	} else {
		if creds.Issuer != cfg.Issuer || creds.RedirectURI != cfg.RedirectURL {
			return cfg, errors.New("saved OIDC client issuer or callback differs from configuration; restore configuration or register a new client")
		}
		if !sameScopes(creds.Scope, registrationScopes) || !slices.Contains(creds.GrantTypes, "refresh_token") {
			if creds.ManagementURI == "" || creds.ManagementToken == "" {
				return cfg, errors.New("OIDC client scopes need an update but management credentials are missing")
			}
			if err := issuerEndpoint(issuer, creds.ManagementURI); err != nil {
				return cfg, err
			}
			request := desiredRegistration(cfg.RedirectURL, false)
			request.ClientID, request.ClientSecret = creds.ClientID, creds.ClientSecret
			if err := registrationCall(ctx, http.MethodPut, creds.ManagementURI, creds.ManagementToken, request, 200, &response); err != nil {
				return cfg, err
			}
			if response.ClientID != "" && response.ClientID != creds.ClientID {
				return cfg, errors.New("management response changed OIDC client ID")
			}
			applyRegistrationResponse(&creds, response)
			// Persist returned rotations before judging grants: the provider may
			// have already invalidated the previous secret or management token.
			if err := writeOIDCCredentials(cfg.ClientFile, creds); err != nil {
				return cfg, fmt.Errorf("updated OIDC client but could not save replacement credentials: %w", err)
			}
		}
	}
	if creds.RedirectURI != cfg.RedirectURL || creds.AuthMethod != "client_secret_basic" || !sameScopes(creds.Scope, registrationScopes) ||
		!slices.Contains(creds.GrantTypes, "authorization_code") || !slices.Contains(creds.GrantTypes, "refresh_token") {
		return cfg, errors.New("OIDC registration did not grant the required callback, client authentication, scopes, and refresh support")
	}
	cfg.ClientID, cfg.ClientSecret = creds.ClientID, creds.ClientSecret
	return cfg, nil
}

func applyRegistrationResponse(creds *oidcCredentials, r registrationMetadata) {
	if r.ClientSecret != "" {
		creds.ClientSecret = r.ClientSecret
	}
	if r.ManagementURI != "" {
		creds.ManagementURI = r.ManagementURI
	}
	if r.ManagementToken != "" {
		creds.ManagementToken = r.ManagementToken
	}
	creds.RedirectURI = ""
	if len(r.RedirectURIs) == 1 {
		creds.RedirectURI = r.RedirectURIs[0]
	}
	creds.Scope, creds.GrantTypes, creds.AuthMethod = r.Scope, r.GrantTypes, r.AuthMethod
}

func registrationCall(ctx context.Context, method, endpoint, bearer string, body registrationMetadata, want int, out *registrationMetadata) error {
	raw, err := json.Marshal(body)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, method, endpoint, bytes.NewReader(raw))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+bearer)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	resp, err := oidcHTTPClient().Do(req)
	if err != nil {
		return errors.New("OIDC registration request failed")
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return errors.New("OIDC registration response could not be read")
	}
	if resp.StatusCode != want {
		return fmt.Errorf("OIDC registration returned HTTP %d", resp.StatusCode)
	}
	if json.Unmarshal(data, out) != nil {
		return errors.New("OIDC registration response is not JSON")
	}
	return nil
}

func readPrivateFile(path string) (string, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return "", err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 {
		return "", fmt.Errorf("%s must be a regular owner-only file (chmod 600)", path)
	}
	raw, err := os.ReadFile(path)
	return string(raw), err
}

func readOIDCCredentials(path string) (oidcCredentials, error) {
	raw, err := readPrivateFile(path)
	if err != nil {
		return oidcCredentials{}, err
	}
	var creds oidcCredentials
	if json.Unmarshal([]byte(raw), &creds) != nil || creds.ClientID == "" || creds.ClientSecret == "" {
		return creds, errors.New("OIDC credentials file is incomplete")
	}
	return creds, nil
}

func writeOIDCCredentials(path string, creds oidcCredentials) error {
	raw, err := json.MarshalIndent(creds, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".oidc-client-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(append(raw, '\n')); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}

func sameScopes(a, b string) bool {
	x, y := strings.Fields(a), strings.Fields(b)
	sort.Strings(x)
	sort.Strings(y)
	return slices.Equal(x, y)
}
