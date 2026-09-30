package auth

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/http/httptrace"
	"sync/atomic"
	"testing"
	"time"
)

type oidcTestRoundTripper func(*http.Request) (*http.Response, error)

func (f oidcTestRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) { return f(req) }

func TestOIDCPooledConnectionTimeoutRetainsSession(t *testing.T) {
	release := make(chan struct{})
	var attempts atomic.Int32
	provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/warmup" {
			_, _ = io.WriteString(w, "ready")
			return
		}
		_ = r.ParseForm()
		attempts.Add(1)
		<-release
		w.WriteHeader(503)
	}))
	defer func() { close(release); provider.Close() }()
	s := lifecycleService(t, provider)
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	defer transport.CloseIdleConnections()
	var reused atomic.Bool
	client := &http.Client{Timeout: 250 * time.Millisecond, Transport: oidcTestRoundTripper(func(req *http.Request) (*http.Response, error) {
		if req.URL.Path == "/token" {
			trace := &httptrace.ClientTrace{GotConn: func(info httptrace.GotConnInfo) { reused.Store(info.Reused) }}
			req = req.WithContext(httptrace.WithClientTrace(req.Context(), trace))
		}
		return transport.RoundTrip(req)
	})}
	s.oidc.http = client
	warmup, err := client.Get(provider.URL + "/warmup")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.Copy(io.Discard, warmup.Body); err != nil {
		t.Fatal(err)
	}
	_ = warmup.Body.Close()
	session := lifecycleSession(t, s, "pooled-refresh")
	current := s.ValidateSession(session.Token)
	if !reused.Load() {
		t.Fatal("probe did not reuse the pooled connection")
	}
	if current == nil || current.RefreshInFlight || current.RefreshRetryAt == "" || !hasSession(t, s, session.Token) {
		t.Fatal("pooled connection timeout deleted the session")
	}
	if s.ValidateSession(session.Token) == nil || attempts.Load() != 1 {
		t.Fatal("pooled timeout retried before its delay")
	}
}

func TestOIDCLostRotatedResponseEndsOnReuseRefusal(t *testing.T) {
	var attempts atomic.Int32
	var familyRevoked atomic.Bool
	provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		if r.URL.Path == "/revoke" {
			familyRevoked.Store(true)
			w.WriteHeader(200)
			return
		}
		if r.Form.Get("refresh_token") != "old-refresh" {
			t.Error("retry changed the retained credential")
		}
		if attempts.Add(1) == 1 {
			// The provider committed rotation, but the response was lost.
			connection, _, err := w.(http.Hijacker).Hijack()
			if err != nil {
				t.Error(err)
				return
			}
			_ = connection.Close()
			return
		}
		// authd revokes the family when the consumed token is replayed.
		familyRevoked.Store(true)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(400)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "invalid_grant"})
	}))
	defer provider.Close()
	s := lifecycleService(t, provider)
	session := lifecycleSession(t, s, "old-refresh")
	current := s.ValidateSession(session.Token)
	if current == nil || current.RefreshInFlight || current.OIDCGrant.RefreshToken != "old-refresh" {
		t.Fatal("lost response did not retain a retryable session")
	}
	current.RefreshRetryAt = time.Now().Add(-time.Second).Format(time.RFC3339Nano)
	if err := s.saveOIDCSession(*current); err != nil {
		t.Fatal(err)
	}
	if s.ValidateSession(session.Token) != nil || hasSession(t, s, session.Token) || !familyRevoked.Load() || attempts.Load() != 2 {
		t.Fatal("retry accepted a consumed credential or retained the refused session")
	}
}
