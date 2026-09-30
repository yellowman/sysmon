package auth

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	bolt "go.etcd.io/bbolt"
)

func signTestJWT(t *testing.T, key *rsa.PrivateKey, typ string, claims map[string]any) string {
	t.Helper()
	header, _ := json.Marshal(map[string]string{"alg": "RS256", "kid": "test", "typ": typ})
	body, _ := json.Marshal(claims)
	part := base64.RawURLEncoding.EncodeToString(header) + "." + base64.RawURLEncoding.EncodeToString(body)
	sum := sha256.Sum256([]byte(part))
	signature, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, sum[:])
	if err != nil {
		t.Fatal(err)
	}
	return part + "." + base64.RawURLEncoding.EncodeToString(signature)
}

func TestOIDCExchangeAndConcurrentRefresh(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	var server *httptest.Server
	var refreshes atomic.Int32
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		issuer := server.URL
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			_ = json.NewEncoder(w).Encode(map[string]any{"issuer": issuer, "authorization_endpoint": issuer + "/authorize", "token_endpoint": issuer + "/token", "jwks_uri": issuer + "/jwks", "revocation_endpoint": issuer + "/revoke", "id_token_signing_alg_values_supported": []string{"RS256"}})
		case "/jwks":
			_ = json.NewEncoder(w).Encode(map[string]any{"keys": []any{map[string]string{"kty": "RSA", "kid": "test", "alg": "RS256", "use": "sig", "n": base64.RawURLEncoding.EncodeToString(key.N.Bytes()), "e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.E)).Bytes())}}})
		case "/token":
			client, secret, basic := r.BasicAuth()
			if !basic || client != "sysmon-test" || secret != "secret" {
				t.Error("missing Basic client authentication")
				http.Error(w, "bad client", 401)
				return
			}
			_ = r.ParseForm()
			refresh := r.Form.Get("grant_type") == "refresh_token"
			if refresh {
				refreshes.Add(1)
				if r.Form.Get("refresh_token") != "refresh-1" {
					t.Error("wrong refresh credential")
				}
			} else if r.Form.Get("code_verifier") != "verifier" {
				t.Error("PKCE verifier was lost")
			}
			scope := "openid profile sysmon.read"
			if refresh {
				scope += " sysmon.manage"
			}
			if r.Form.Get("code") == "manage-only" {
				scope = "openid sysmon.manage"
			}
			now := time.Now().Unix()
			access := signTestJWT(t, key, "at+jwt", map[string]any{"iss": issuer, "sub": "alice-id", "aud": "sysmon-test", "client_id": "sysmon-test", "iat": now, "exp": now + 300, "scope": scope})
			hash := sha256.Sum256([]byte(access))
			nonce := "nonce"
			if r.Form.Get("code") == "wrong-nonce" {
				nonce = "other"
			}
			id := signTestJWT(t, key, "JWT", map[string]any{"iss": issuer, "sub": "alice-id", "aud": "sysmon-test", "iat": now, "exp": now + 300, "nonce": nonce, "at_hash": base64.RawURLEncoding.EncodeToString(hash[:16]), "preferred_username": "alice"})
			response := map[string]any{"access_token": access, "token_type": "Bearer", "expires_in": 300, "id_token": id, "refresh_token": "refresh-1"}
			if refresh {
				response["refresh_token"] = "refresh-2"
				delete(response, "id_token")
			}
			_ = json.NewEncoder(w).Encode(response)
		case "/revoke":
			w.WriteHeader(200)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	client, err := NewOIDCClient(context.Background(), OIDCConfig{Issuer: server.URL, RedirectURL: server.URL + "/auth/callback", ClientID: "sysmon-test", ClientSecret: "secret"})
	if err != nil {
		t.Fatal(err)
	}
	authorization := client.AuthorizationURL("state", "nonce", "verifier")
	if !strings.Contains(authorization, "code_challenge_method=S256") || !strings.Contains(authorization, "prompt=consent") {
		t.Fatal("PKCE or consent was omitted")
	}
	for _, code := range []string{"manage-only", "wrong-nonce"} {
		if _, err := client.Exchange(context.Background(), code, "verifier", "nonce"); err == nil {
			t.Fatalf("invalid grant %q accepted", code)
		}
	}
	identity, err := client.Exchange(context.Background(), "valid", "verifier", "nonce")
	if err != nil {
		t.Fatal(err)
	}
	if identity.Role != RoleUser || identity.DisplayName != "alice" {
		t.Fatalf("wrong identity: %+v", identity)
	}
	s, err := NewServiceWithBootstrap(filepath.Join(t.TempDir(), "auth.db"), false)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	s.SetOIDCClient(client)
	identity.ExpiresAt = time.Now().Add(time.Second)
	session, err := s.CreateOIDCSession(identity)
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	results := make(chan *Session, 16)
	for range 16 {
		wg.Add(1)
		go func() { defer wg.Done(); results <- s.ValidateSession(session.Token) }()
	}
	wg.Wait()
	close(results)
	for got := range results {
		if got == nil || got.Role != RoleAdmin || got.OIDCGrant.RefreshToken != "refresh-2" {
			t.Fatalf("wrong refreshed session: %+v", got)
		}
	}
	if refreshes.Load() != 1 {
		t.Fatalf("%d refresh calls; want one", refreshes.Load())
	}
	// A crash after sending a rotating token must require a fresh sign-in.
	if err := s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketSessions)
		var value Session
		if err := json.Unmarshal(b.Get([]byte(session.Token)), &value); err != nil {
			return err
		}
		value.RefreshInFlight = true
		data, _ := json.Marshal(value)
		return b.Put([]byte(session.Token), data)
	}); err != nil {
		t.Fatal(err)
	}
	if s.ValidateSession(session.Token) != nil {
		t.Fatal("ambiguous refresh was replayed")
	}
	if refreshes.Load() != 1 {
		t.Fatal("old rotating credential was retried")
	}
}

func TestOIDCModeAndMobileHandoff(t *testing.T) {
	s, err := NewServiceWithBootstrap(filepath.Join(t.TempDir(), "auth.db"), false)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if s.UserCount() != 0 {
		t.Fatal("OIDC installation created a local administrator")
	}
	if err := s.CreateUser("local", "secret", RoleAdmin); err != nil {
		t.Fatal(err)
	}
	local, err := s.Login("local", "secret")
	if err != nil {
		t.Fatal(err)
	}
	s.SetOIDCClient(&OIDCClient{issuer: "https://auth.test", clientID: "sysmon"})
	if s.ValidateSession(local.Token) != nil {
		t.Fatal("local session accepted after switching modes")
	}
	if _, err := s.Login("local", "secret"); err == nil {
		t.Fatal("password accepted in OIDC mode")
	}
	verifier := "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGH"
	hash := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(hash[:])
	if _, _, err := s.StartOIDCFlow("bad"); err == nil {
		t.Fatal("bad mobile challenge accepted")
	}
	id, flow, err := s.StartOIDCFlow(challenge)
	if err != nil {
		t.Fatal(err)
	}
	if flow.MobileChallenge != challenge {
		t.Fatal("challenge not bound to login flow")
	}
	if _, err := s.ConsumeOIDCFlow(id); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ConsumeOIDCFlow(id); err == nil {
		t.Fatal("flow replay accepted")
	}
	identity := OIDCIdentity{Issuer: "https://auth.test", ClientID: "sysmon", Subject: "alice-id", DisplayName: "alice", Role: RoleUser, RefreshToken: "refresh", ExpiresAt: time.Now().Add(time.Hour)}
	code, err := s.StartMobileHandoff(identity, challenge)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.ConsumeMobileHandoff(code, verifier+"wrong"); err == nil {
		t.Fatal("wrong mobile verifier accepted")
	}
	if _, err := s.ConsumeMobileHandoff(code, verifier); err == nil {
		t.Fatal("handoff replay accepted")
	}
	code, err = s.StartMobileHandoff(identity, challenge)
	if err != nil {
		t.Fatal(err)
	}
	got, err := s.ConsumeMobileHandoff(code, verifier)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.CreateOIDCSession(got); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ConsumeMobileHandoff(code, verifier); err == nil {
		t.Fatal("used mobile code accepted")
	}
}

func TestOIDCBootstrapPersistsAndUpdatesClient(t *testing.T) {
	dir := t.TempDir()
	tokenFile := filepath.Join(dir, "token")
	if err := os.WriteFile(tokenFile, []byte("one-use"), 0600); err != nil {
		t.Fatal(err)
	}
	var server *httptest.Server
	registers, updates := 0, 0
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			_ = json.NewEncoder(w).Encode(map[string]any{"issuer": server.URL, "authorization_endpoint": server.URL + "/authorize", "token_endpoint": server.URL + "/token", "jwks_uri": server.URL + "/jwks", "registration_endpoint": server.URL + "/register"})
		case "/register", "/manage":
			var request registrationMetadata
			if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
				t.Error(err)
				http.Error(w, "bad json", 400)
				return
			}
			response := request
			if r.URL.Path == "/register" {
				registers++
				if r.Header.Get("Authorization") != "Bearer one-use" || len(request.Roles) != 2 || request.Roles[0].Name != "sysmon.viewer" || request.Roles[1].Name != "sysmon.administrator" {
					t.Error("incorrect registration token or roles")
				}
				response.ClientID, response.ClientSecret = "sysmon-client", "secret-1"
				response.ManagementURI, response.ManagementToken = server.URL+"/manage", "management-1"
				w.WriteHeader(201)
			} else {
				updates++
				if r.Method != "PUT" || r.Header.Get("Authorization") != "Bearer management-1" || request.ClientSecret != "secret-1" {
					t.Error("incorrect managed update")
				}
				response.ClientSecret = "" // RFC 7592 permits retaining the existing secret.
				response.ManagementToken = "management-2"
				response.ManagementURI = server.URL + "/manage"
			}
			_ = json.NewEncoder(w).Encode(response)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	cfg := OIDCConfig{Issuer: server.URL, RedirectURL: "https://sysmon.test/auth/callback", ClientFile: filepath.Join(dir, "client.json"), RegistrationTokenFile: tokenFile}
	first, err := EnsureOIDCRegistered(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(cfg.ClientFile)
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatalf("credentials file permissions: %v %v", info, err)
	}
	if first.ClientID != "sysmon-client" || first.ClientSecret != "secret-1" {
		t.Fatal("credentials not returned")
	}
	cfg.RegistrationTokenFile = ""
	if _, err := EnsureOIDCRegistered(context.Background(), cfg); err != nil {
		t.Fatal(err)
	}
	if registers != 1 {
		t.Fatal("restart registered a second client")
	}
	creds, err := readOIDCCredentials(cfg.ClientFile)
	if err != nil {
		t.Fatal(err)
	}
	creds.Scope = "openid profile email sysmon.read"
	if err := writeOIDCCredentials(cfg.ClientFile, creds); err != nil {
		t.Fatal(err)
	}
	updated, err := EnsureOIDCRegistered(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	saved, err := readOIDCCredentials(cfg.ClientFile)
	if err != nil {
		t.Fatal(err)
	}
	if updates != 1 || updated.ClientSecret != "secret-1" || saved.ManagementToken != "management-2" || !sameScopes(saved.Scope, registrationScopes) {
		t.Fatal("managed update did not preserve and persist credentials")
	}
	moved := cfg
	moved.RedirectURL = "https://other.test/auth/callback"
	if _, err := EnsureOIDCRegistered(context.Background(), moved); err == nil {
		t.Fatal("changed callback accepted")
	}
	if err := os.Chmod(cfg.ClientFile, 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := EnsureOIDCRegistered(context.Background(), cfg); err == nil {
		t.Fatal("world-readable credentials accepted")
	}
}
