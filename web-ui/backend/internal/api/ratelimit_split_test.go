package api

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"
)

// The three rate-limit classes: login has a small brute-force bucket,
// logout is never limited (a 429 there strands a session the browser
// cannot end itself), everything else shares a generous bucket sized
// for the UI's own polling.

func TestLoginRateLimitedTightly(t *testing.T) {
	handler, _, cleanup := testRouter(t)
	defer cleanup()

	got429 := false
	for i := 0; i < 12; i++ {
		req := httptest.NewRequest(http.MethodPost, "/api/auth/login",
			bytes.NewBufferString(`{"username":"nobody","password":"wrong"}`))
		req.RemoteAddr = "203.0.113.9:1000"
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)
		if w.Code == http.StatusTooManyRequests {
			got429 = true
			if i < 10 {
				t.Fatalf("login limited after only %d attempts", i+1)
			}
			break
		}
	}
	if !got429 {
		t.Fatal("12 bad login attempts from one IP never hit the limiter")
	}
}

func TestLogoutIsNeverRateLimited(t *testing.T) {
	handler, authSvc, cleanup := testRouter(t)
	defer cleanup()
	token := sessionFor(t, authSvc, "rl-user", "rl-pass-123", "admin")

	// Exhaust the general bucket well past its limit.
	for i := 0; i < 350; i++ {
		req := httptest.NewRequest(http.MethodGet, "/api/sites", nil)
		req.RemoteAddr = "203.0.113.10:1000"
		req.Header.Set("Authorization", "Bearer "+token)
		handler.ServeHTTP(httptest.NewRecorder(), req)
	}
	// A monitoring call from this IP is now limited...
	req := httptest.NewRequest(http.MethodGet, "/api/sites", nil)
	req.RemoteAddr = "203.0.113.10:1000"
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusTooManyRequests {
		t.Fatalf("expected the general bucket to be exhausted, got %d", w.Code)
	}
	// ...but logout still goes through and revokes the session.
	req = httptest.NewRequest(http.MethodPost, "/api/auth/logout", nil)
	req.RemoteAddr = "203.0.113.10:1000"
	req.Header.Set("Authorization", "Bearer "+token)
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("logout under exhausted bucket: got %d, want 200", w.Code)
	}
	if sess := authSvc.ValidateSession(token); sess != nil {
		t.Fatal("session survived logout")
	}
}

func TestGeneralBucketAllowsUIPolling(t *testing.T) {
	handler, authSvc, cleanup := testRouter(t)
	defer cleanup()
	token := sessionFor(t, authSvc, "rl-user", "rl-pass-123", "admin")

	// A couple of minutes of a few open tabs - must not trip the limit.
	for i := 0; i < 120; i++ {
		req := httptest.NewRequest(http.MethodGet, "/api/sites", nil)
		req.RemoteAddr = "203.0.113.11:1000"
		req.Header.Set("Authorization", "Bearer "+token)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)
		if w.Code == http.StatusTooManyRequests {
			t.Fatalf("legitimate polling hit the limiter at request %d", i+1)
		}
	}
}
