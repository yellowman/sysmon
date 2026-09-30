package auth

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	bolt "go.etcd.io/bbolt"
	"golang.org/x/oauth2"
)

func lifecycleService(t *testing.T, server *httptest.Server) *Service {
	t.Helper()
	s, err := NewServiceWithBootstrap(filepath.Join(t.TempDir(), "auth.db"), false)
	if err != nil {
		t.Fatal(err)
	}
	s.SetOIDCClient(&OIDCClient{issuer: server.URL, clientID: "sysmon", http: server.Client(), revocation: server.URL + "/revoke",
		oauth: oauth2.Config{ClientID: "sysmon", ClientSecret: "secret", Endpoint: oauth2.Endpoint{TokenURL: server.URL + "/token", AuthStyle: oauth2.AuthStyleInHeader}}})
	t.Cleanup(s.Close)
	return s
}

func lifecycleSession(t *testing.T, s *Service, refresh string) *Session {
	t.Helper()
	session, err := s.CreateOIDCSession(OIDCIdentity{Issuer: s.oidc.issuer, ClientID: s.oidc.clientID, Subject: refresh,
		DisplayName: "Alice", Role: RoleUser, RefreshToken: refresh, ExpiresAt: time.Now().Add(time.Second)})
	if err != nil {
		t.Fatal(err)
	}
	return session
}

func hasSession(t *testing.T, s *Service, token string) bool {
	t.Helper()
	var exists bool
	if err := s.db.View(func(tx *bolt.Tx) error { exists = tx.Bucket(bucketSessions).Get([]byte(token)) != nil; return nil }); err != nil {
		t.Fatal(err)
	}
	return exists
}

func TestOIDCAmbiguousAndRefusedRefreshEndSession(t *testing.T) {
	for _, failure := range []string{"invalid_grant", "server_error", "lost_response"} {
		t.Run(failure, func(t *testing.T) {
			revoked := make(chan string, 1)
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				_ = r.ParseForm()
				if r.URL.Path == "/revoke" {
					revoked <- r.Form.Get("token")
					w.WriteHeader(200)
					return
				}
				if failure == "lost_response" {
					connection, _, err := w.(http.Hijacker).Hijack()
					if err != nil {
						t.Error(err)
						return
					}
					_ = connection.Close()
					return
				}
				w.Header().Set("Content-Type", "application/json")
				if failure == "invalid_grant" {
					w.WriteHeader(400)
				} else {
					w.WriteHeader(503)
				}
				_ = json.NewEncoder(w).Encode(map[string]string{"error": failure})
			}))
			defer server.Close()
			s := lifecycleService(t, server)
			session := lifecycleSession(t, s, "old-refresh")
			if s.ValidateSession(session.Token) != nil || hasSession(t, s, session.Token) {
				t.Fatal("unsafe refresh retained the session")
			}
			select {
			case token := <-revoked:
				if token != "old-refresh" {
					t.Fatalf("revoked %q", token)
				}
			default:
				t.Fatal("ended session did not attempt revocation")
			}
		})
	}
}

func TestOIDCRefreshLocksArePerSession(t *testing.T) {
	entered, release := make(chan struct{}), make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		if r.URL.Path == "/revoke" {
			w.WriteHeader(200)
			return
		}
		if r.Form.Get("refresh_token") == "slow-refresh" {
			close(entered)
			<-release
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(400)
		_, _ = w.Write([]byte(`{"error":"invalid_grant"}`))
	}))
	defer server.Close()
	s := lifecycleService(t, server)
	slow, fast := lifecycleSession(t, s, "slow-refresh"), lifecycleSession(t, s, "fast-refresh")
	slowDone := make(chan struct{})
	go func() { s.ValidateSession(slow.Token); close(slowDone) }()
	select {
	case <-entered:
	case <-time.After(2 * time.Second):
		close(release)
		t.Fatal("slow refresh never entered provider")
	}
	fastDone := make(chan struct{})
	go func() { s.ValidateSession(fast.Token); close(fastDone) }()
	select {
	case <-fastDone:
	case <-time.After(2 * time.Second):
		close(release)
		<-slowDone
		<-fastDone
		t.Fatal("one session blocked another user's refresh")
	}
	close(release)
	<-slowDone
	s.refreshLocksMu.Lock()
	defer s.refreshLocksMu.Unlock()
	if len(s.refreshLocks) != 0 {
		t.Fatal("unused session locks retained")
	}
}

func TestOIDCExpiryLogoutAndStartupSweepRevoke(t *testing.T) {
	var revocations atomic.Int32
	revoked := make(chan struct{}, 8)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		revocations.Add(1)
		revoked <- struct{}{}
		w.WriteHeader(200)
	}))
	defer server.Close()
	s := lifecycleService(t, server)
	active := lifecycleSession(t, s, "active-refresh")
	markExpired := func(session *Session) {
		t.Helper()
		session.ExpiresAt = time.Now().Add(-time.Second).Format(time.RFC3339)
		if err := s.saveOIDCSession(*session); err != nil {
			t.Fatal(err)
		}
	}
	expired := lifecycleSession(t, s, "expired-refresh")
	markExpired(expired)
	if s.ValidateSession(expired.Token) != nil || revocations.Load() != 1 {
		t.Fatal("accessed expired session did not revoke")
	}
	<-revoked
	abandoned := lifecycleSession(t, s, "abandoned-refresh")
	markExpired(abandoned)
	s.StartSessionCleanup()
	select {
	case <-revoked:
	case <-time.After(2 * time.Second):
		t.Fatal("startup cleanup did not revoke abandoned session")
	}
	if hasSession(t, s, abandoned.Token) || !hasSession(t, s, active.Token) {
		t.Fatal("cleanup removed the wrong session")
	}
	s.Logout(active.Token)
	if hasSession(t, s, active.Token) || revocations.Load() != 3 {
		t.Fatal("logout left the grant behind")
	}
	if err := s.SweepExpiredSessions(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestOIDCProviderChangeNeverReceivesOldGrant(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls.Add(1); w.WriteHeader(200) }))
	defer server.Close()
	s := lifecycleService(t, server)
	session := lifecycleSession(t, s, "old-provider-refresh")
	session.OIDCGrant.Issuer = "https://old-provider.example"
	if err := s.saveOIDCSession(*session); err != nil {
		t.Fatal(err)
	}
	if s.ValidateSession(session.Token) != nil || hasSession(t, s, session.Token) {
		t.Fatal("old provider's session remained usable")
	}
	if calls.Load() != 0 {
		t.Fatal("old refresh credential was sent to the new provider")
	}
}

func TestOIDCLogoutWorksDuringProviderOutage(t *testing.T) {
	provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200) }))
	s := lifecycleService(t, provider)
	session := lifecycleSession(t, s, "offline-refresh")
	provider.Close()
	session.OIDCGrant.ExpiresAt = time.Now().Add(-oidcOutageGrace - time.Second)
	if err := s.saveOIDCSession(*session); err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest("GET", "/api/auth/me", nil)
	request.AddCookie(&http.Cookie{Name: "sysmon_session", Value: session.Token})
	if current, err := s.AuthenticateRequest(request); current != nil || err != ErrOIDCProviderUnavailable {
		t.Fatal("expired outage grace still allowed access")
	}
	called := false
	handler := RequireAuth(s, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		cookie, _ := r.Cookie("sysmon_session")
		s.Logout(cookie.Value)
		w.WriteHeader(200)
	}))
	request.Method, request.URL.Path = "POST", "/api/auth/logout"
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if !called || response.Code != 200 || hasSession(t, s, session.Token) {
		t.Fatal("provider outage blocked local logout")
	}
}
