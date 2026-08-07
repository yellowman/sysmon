package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func hit(h http.Handler, path string) int {
	req := httptest.NewRequest(http.MethodGet, path, nil)
	req.RemoteAddr = "203.0.113.7:41000"
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	return w.Code
}

func TestRateLimiterBlocksAtLimit(t *testing.T) {
	rl := NewRateLimiter(5, time.Minute)
	h := rl.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))

	for i := 0; i < 5; i++ {
		if code := hit(h, "/x"); code != http.StatusOK {
			t.Fatalf("request %d: got %d, want 200", i+1, code)
		}
	}
	if code := hit(h, "/x"); code != http.StatusTooManyRequests {
		t.Fatalf("request 6: got %d, want 429", code)
	}
}

func TestRateLimiterBucketsArePerIP(t *testing.T) {
	rl := NewRateLimiter(2, time.Minute)
	h := rl.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))

	req := func(addr string) int {
		r := httptest.NewRequest(http.MethodGet, "/x", nil)
		r.RemoteAddr = addr
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w.Code
	}
	req("203.0.113.7:1")
	req("203.0.113.7:2")
	if code := req("203.0.113.7:3"); code != http.StatusTooManyRequests {
		t.Fatalf("third request from same IP: got %d, want 429", code)
	}
	if code := req("203.0.113.8:1"); code != http.StatusOK {
		t.Fatalf("other IP: got %d, want 200", code)
	}
}
