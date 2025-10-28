package middleware

import (
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"
)

// RateLimiter implements a token bucket rate limiter
type RateLimiter struct {
	mu       sync.RWMutex
	visitors map[string]*visitor
	limit    int           // requests per window
	window   time.Duration // time window
	cleanup  time.Duration // cleanup interval
}

type visitor struct {
	tokens     int
	lastUpdate time.Time
}

// NewRateLimiter creates a new rate limiter
// limit: maximum requests per window
// window: time window duration (e.g., 1 * time.Minute)
func NewRateLimiter(limit int, window time.Duration) *RateLimiter {
	rl := &RateLimiter{
		visitors: make(map[string]*visitor),
		limit:    limit,
		window:   window,
		cleanup:  5 * time.Minute, // Clean up old visitors every 5 minutes
	}

	// Start cleanup goroutine
	go rl.cleanupVisitors()

	return rl
}

// Middleware wraps an HTTP handler with rate limiting
func (rl *RateLimiter) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Get client IP
		ip := getClientIP(r)

		// Check if allowed
		if !rl.allow(ip) {
			w.Header().Set("X-RateLimit-Limit", fmt.Sprintf("%d", rl.limit))
			w.Header().Set("X-RateLimit-Remaining", "0")
			w.Header().Set("X-RateLimit-Reset", fmt.Sprintf("%d", time.Now().Add(rl.window).Unix()))
			w.Header().Set("Retry-After", fmt.Sprintf("%d", int(rl.window.Seconds())))

			http.Error(w, "Rate limit exceeded. Too many requests.", http.StatusTooManyRequests)
			return
		}

		// Add rate limit headers
		remaining := rl.getRemaining(ip)
		w.Header().Set("X-RateLimit-Limit", fmt.Sprintf("%d", rl.limit))
		w.Header().Set("X-RateLimit-Remaining", fmt.Sprintf("%d", remaining))
		w.Header().Set("X-RateLimit-Reset", fmt.Sprintf("%d", time.Now().Add(rl.window).Unix()))

		next.ServeHTTP(w, r)
	})
}

// allow checks if a request from the given IP is allowed
func (rl *RateLimiter) allow(ip string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	v, exists := rl.visitors[ip]
	now := time.Now()

	if !exists {
		// First request from this IP
		rl.visitors[ip] = &visitor{
			tokens:     rl.limit - 1,
			lastUpdate: now,
		}
		return true
	}

	// Refill tokens based on time passed
	elapsed := now.Sub(v.lastUpdate)
	tokensToAdd := int(elapsed / (rl.window / time.Duration(rl.limit)))

	if tokensToAdd > 0 {
		v.tokens += tokensToAdd
		if v.tokens > rl.limit {
			v.tokens = rl.limit
		}
		v.lastUpdate = now
	}

	// Check if we have tokens available
	if v.tokens > 0 {
		v.tokens--
		return true
	}

	return false
}

// getRemaining returns the number of remaining requests for an IP
func (rl *RateLimiter) getRemaining(ip string) int {
	rl.mu.RLock()
	defer rl.mu.RUnlock()

	v, exists := rl.visitors[ip]
	if !exists {
		return rl.limit
	}

	return v.tokens
}

// cleanupVisitors removes old visitors to prevent memory leaks
func (rl *RateLimiter) cleanupVisitors() {
	ticker := time.NewTicker(rl.cleanup)
	defer ticker.Stop()

	for range ticker.C {
		rl.mu.Lock()
		now := time.Now()
		for ip, v := range rl.visitors {
			// Remove visitors that haven't made requests in 2x the cleanup interval
			if now.Sub(v.lastUpdate) > rl.cleanup*2 {
				delete(rl.visitors, ip)
			}
		}
		rl.mu.Unlock()
	}
}

// getClientIP extracts the client IP from the request
func getClientIP(r *http.Request) string {
	// Check X-Forwarded-For header
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		// X-Forwarded-For can be a comma-separated list, take the first one
		if idx := strings.Index(xff, ","); idx != -1 {
			return strings.TrimSpace(xff[:idx])
		}
		return strings.TrimSpace(xff)
	}

	// Check X-Real-IP header
	if xri := r.Header.Get("X-Real-IP"); xri != "" {
		return strings.TrimSpace(xri)
	}

	// Fall back to RemoteAddr
	ip := r.RemoteAddr
	// Remove port if present
	if idx := strings.LastIndex(ip, ":"); idx != -1 {
		ip = ip[:idx]
	}
	return ip
}
