package middleware

import (
	"fmt"
	"net/http"
	"strings"
)

// CacheConfig defines caching behavior for different endpoint types.
type CacheConfig struct {
	// Map of path prefixes to cache durations in seconds.
	//   >0  -> private, max-age=N (browser may reuse for N seconds)
	//    0  -> no-cache (must revalidate; we don't emit validators, so
	//          this is effectively "always refetch")
	//   -1  -> no-store (never cache; for mutable/sensitive endpoints)
	cacheDurations map[string]int
}

// NewCacheConfig creates a default cache configuration.
func NewCacheConfig() *CacheConfig {
	return &CacheConfig{
		cacheDurations: map[string]int{
			"/api/monitoring/": 5,    // Read-only views, change often
			"/api/config":      -1,   // Mutable admin config - never cache
			"/api/settings":    -1,   // Push credentials etc. - never cache
			"/api/metrics":     0,    // Always fresh
			"/api/backups":     0,    // Changes whenever config is saved
			"/api/traps":       10,   // Trap views
			"/api/xml/":        5,    // XML data
			"/api/bulk/":       -1,   // Mutations
			"/api/push":        -1,   // Subscriptions / credentials
			"/api/auth":        -1,   // Sessions / users
			"/static/":         3600, // embedded assets; change only with the binary
			"/api/docs":        3600, // API docs
			"/openapi.yaml":    3600, // OpenAPI spec
		},
	}
}

// Middleware sets Cache-Control headers based on the request path.
//
// It deliberately does NOT do ETag / If-None-Match / 304 conditional
// handling. That optimization buffers every response to hash it and then
// returns a bodyless 304 on a validator match - which breaks clients that
// sent the validator but have no cached body to fall back on (fetch with
// caching disabled, or responses to Authorization-bearing requests that
// the browser didn't store), surfacing as "JSON.parse: unexpected end of
// data". For a small authenticated admin API the saved bytes aren't worth
// that failure mode, so we just advise the browser via Cache-Control and
// always send the full body.
func (cc *CacheConfig) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet || r.Method == http.MethodHead {
			switch d := cc.getCacheDuration(r.URL.Path); {
			case d > 0:
				// private, not public: these responses are behind auth and
				// must never be stored by a shared cache/proxy.
				w.Header().Set("Cache-Control", fmt.Sprintf("private, max-age=%d", d))
			case d == 0:
				w.Header().Set("Cache-Control", "no-cache")
			default: // -1
				w.Header().Set("Cache-Control", "no-store")
			}
		}
		next.ServeHTTP(w, r)
	})
}

// getCacheDuration returns the cache duration for a given path, choosing
// the longest matching prefix. Unmatched paths default to no-cache.
func (cc *CacheConfig) getCacheDuration(path string) int {
	maxLen := -1
	duration := 0 // default: no-cache
	for prefix, dur := range cc.cacheDurations {
		if strings.HasPrefix(path, prefix) && len(prefix) > maxLen {
			maxLen = len(prefix)
			duration = dur
		}
	}
	return duration
}
