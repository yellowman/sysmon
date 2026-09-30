package api

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"sysmon-web/internal/auth"
	"sysmon-web/internal/config"
	"sysmon-web/internal/monitoring"
	"sysmon-web/internal/settings"
)

func callbackJWT(t *testing.T, key *rsa.PrivateKey, typ string, claims map[string]any) string {
	t.Helper()
	header, _ := json.Marshal(map[string]string{"alg": "RS256", "kid": "test", "typ": typ})
	body, _ := json.Marshal(claims)
	part := base64.RawURLEncoding.EncodeToString(header) + "." + base64.RawURLEncoding.EncodeToString(body)
	hash := sha256.Sum256([]byte(part))
	signature, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, hash[:])
	if err != nil {
		t.Fatal(err)
	}
	return part + "." + base64.RawURLEncoding.EncodeToString(signature)
}

func TestOIDCBrowserCompletionAndStoredAuthorship(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	const displayName = "Alice | Admin\nForged"
	var provider *httptest.Server
	provider = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			_ = json.NewEncoder(w).Encode(map[string]any{"issuer": provider.URL, "authorization_endpoint": provider.URL + "/authorize", "token_endpoint": provider.URL + "/token", "jwks_uri": provider.URL + "/jwks", "revocation_endpoint": provider.URL + "/revoke", "id_token_signing_alg_values_supported": []string{"RS256"}})
		case "/jwks":
			_ = json.NewEncoder(w).Encode(map[string]any{"keys": []any{map[string]string{"kty": "RSA", "kid": "test", "alg": "RS256", "use": "sig", "n": base64.RawURLEncoding.EncodeToString(key.N.Bytes()), "e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.E)).Bytes())}}})
		case "/token":
			_ = r.ParseForm()
			now := time.Now().Unix()
			access := callbackJWT(t, key, "application/at+jwt", map[string]any{"iss": provider.URL, "sub": "alice", "aud": "sysmon", "client_id": "sysmon", "iat": now, "exp": now + 300, "scope": "openid profile sysmon.read sysmon.manage"})
			id := callbackJWT(t, key, "JWT", map[string]any{"iss": provider.URL, "sub": "alice", "aud": "sysmon", "iat": now, "exp": now + 300, "nonce": r.Form.Get("code"), "preferred_username": displayName})
			_ = json.NewEncoder(w).Encode(map[string]any{"access_token": access, "id_token": id, "refresh_token": "refresh", "token_type": "Bearer", "expires_in": 300})
		case "/revoke":
			w.WriteHeader(200)
		default:
			http.NotFound(w, r)
		}
	}))
	defer provider.Close()
	client, err := auth.NewOIDCClient(context.Background(), auth.OIDCConfig{Issuer: provider.URL, RedirectURL: "https://sysmon.example/auth/callback", ClientID: "sysmon", ClientSecret: "secret"})
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	service, err := auth.NewServiceWithBootstrap(filepath.Join(dir, "auth.db"), false)
	if err != nil {
		t.Fatal(err)
	}
	defer service.Close()
	service.SetOIDCClient(client)
	store, err := settings.NewStore(filepath.Join(dir, "settings.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	configPath, auditPath := filepath.Join(dir, "sysmon.conf"), filepath.Join(dir, "audit.log")
	content := fmt.Sprintf("config pidfile %q;\n", filepath.Join(dir, "missing.pid"))
	if err := os.WriteFile(configPath, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
	cfg := config.NewService(configPath, filepath.Join(dir, "backups"), auditPath)
	mon := monitoring.NewService()
	mon.SetGenerations(store)
	files := []settings.GenFile{{Name: "sysmon.conf", Content: []byte(content)}}
	hash := config.HashFileSet([]string{"sysmon.conf"}, [][]byte{[]byte(content)})
	if _, err := store.PutGeneration("testsite", files, hash, "bootstrap", ""); err != nil {
		t.Fatal(err)
	}
	handler, stop := NewRouter(cfg, mon, nil, nil, service, store)
	defer stop()
	start := httptest.NewRecorder()
	handler.ServeHTTP(start, httptest.NewRequest("GET", "https://sysmon.example/auth/login", nil))
	location, err := url.Parse(start.Header().Get("Location"))
	if err != nil || start.Code != 302 {
		t.Fatalf("start failed: %d", start.Code)
	}
	callback := httptest.NewRequest("GET", "https://sysmon.example/auth/callback?state="+url.QueryEscape(location.Query().Get("state"))+"&code="+url.QueryEscape(location.Query().Get("nonce")), nil)
	for _, cookie := range start.Result().Cookies() {
		callback.AddCookie(cookie)
	}
	completed := httptest.NewRecorder()
	handler.ServeHTTP(completed, callback)
	if completed.Code != 200 || completed.Header().Get("Location") != "" || !strings.Contains(completed.Body.String(), `<meta http-equiv="refresh" content="0;url=/">`) {
		t.Fatalf("callback retained a cross-site redirect chain: %d %s", completed.Code, completed.Body.String())
	}
	var sessionCookie *http.Cookie
	for _, cookie := range completed.Result().Cookies() {
		if cookie.Name == "sysmon_session" {
			sessionCookie = cookie
		}
	}
	if sessionCookie == nil || sessionCookie.SameSite != http.SameSiteStrictMode || !sessionCookie.Secure || !sessionCookie.HttpOnly {
		t.Fatal("callback weakened the session cookie")
	}
	request := func(method, path string, body any) *httptest.ResponseRecorder {
		t.Helper()
		var payload bytes.Buffer
		if body != nil {
			if err := json.NewEncoder(&payload).Encode(body); err != nil {
				t.Fatal(err)
			}
		}
		req := httptest.NewRequest(method, "https://sysmon.example"+path, &payload)
		req.AddCookie(sessionCookie)
		req.Header.Set("X-Session-Display", "spoofed name")
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, req)
		return response
	}
	me := request("GET", "/api/auth/me", nil)
	var profile map[string]string
	if err := json.Unmarshal(me.Body.Bytes(), &profile); err != nil {
		t.Fatal(err)
	}
	if me.Code != 200 || profile["display_name"] != displayName || !strings.HasPrefix(profile["username"], "authd:") {
		t.Fatalf("bad identity after completion: %s", me.Body.String())
	}
	_, version, err := cfg.GetRawConfig()
	if err != nil {
		t.Fatal(err)
	}
	updated := request("PUT", "/api/config/raw", map[string]string{"content": content + "# edited\n", "version": version, "comment": "review test"})
	if updated.Code != 200 {
		t.Fatalf("config update: %d %s", updated.Code, updated.Body.String())
	}
	actor := "Alice Admin Forged (" + profile["username"] + ")"
	audit, err := os.ReadFile(auditPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(audit), " | "+actor+" | ") || strings.Contains(string(audit), "spoofed name") {
		t.Fatalf("audit lost or accepted an unverified actor: %s", audit)
	}
	files[0].Content = []byte(content + "# staged\n")
	staged := request("POST", "/api/config/stage/testsite", map[string]any{"files": toWire(files), "note": "review test"})
	if staged.Code != 200 {
		t.Fatalf("stage: %d %s", staged.Code, staged.Body.String())
	}
	if desired, ok := store.GetDesired("testsite"); !ok || desired.CreatedBy != actor {
		t.Fatalf("stored authorship lost the actor: %+v", desired)
	}
	loggedOut := request("POST", "/api/auth/logout", nil)
	if loggedOut.Code != 200 || service.ValidateSession(sessionCookie.Value) != nil {
		t.Fatal("logout did not end the cookie session")
	}
}
