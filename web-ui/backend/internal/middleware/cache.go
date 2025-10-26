package middleware

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"net/http"
	"strings"
)

// CacheConfig defines caching behavior for different endpoint types
type CacheConfig struct {
	// Map of path prefixes to cache durations in seconds
	// 0 means no caching, -1 means no-store
	cacheDurations map[string]int
}

// NewCacheConfig creates a default cache configuration
func NewCacheConfig() *CacheConfig {
	return &CacheConfig{
		cacheDurations: map[string]int{
			"/api/monitoring/":  5,   // Monitoring data changes frequently - 5 seconds
			"/api/config":       60,  // Configuration changes less often - 60 seconds
			"/api/metrics":      0,   // Metrics should always be fresh - no cache
			"/api/backups":      30,  // Backup list - 30 seconds
			"/api/traps":        10,  // Traps - 10 seconds
			"/api/xml/":         5,   // XML data - 5 seconds
			"/api/bulk/":        -1,  // Bulk operations - no-store
			"/api/docs":         3600, // API docs - 1 hour
			"/openapi.yaml":     3600, // OpenAPI spec - 1 hour
		},
	}
}

// Middleware adds HTTP caching headers (ETag, Cache-Control)
func (cc *CacheConfig) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Only cache GET and HEAD requests
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			next.ServeHTTP(w, r)
			return
		}

		// Create a response recorder to capture the response
		recorder := &cacheResponseWriter{
			ResponseWriter: w,
			body:           &bytes.Buffer{},
			statusCode:     http.StatusOK,
		}

		// Call the next handler
		next.ServeHTTP(recorder, r)

		// Don't cache error responses
		if recorder.statusCode >= 400 {
			recorder.flush()
			return
		}

		// Generate ETag from response body
		etag := generateETag(recorder.body.Bytes())
		w.Header().Set("ETag", etag)

		// Check if client has a matching ETag
		clientETag := r.Header.Get("If-None-Match")
		if clientETag == etag {
			// Client has the current version, return 304 Not Modified
			w.WriteHeader(http.StatusNotModified)
			return
		}

		// Determine cache duration based on path
		cacheDuration := cc.getCacheDuration(r.URL.Path)

		// Set Cache-Control header
		if cacheDuration == -1 {
			w.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate")
		} else if cacheDuration == 0 {
			w.Header().Set("Cache-Control", "no-cache, must-revalidate")
		} else {
			w.Header().Set("Cache-Control", fmt.Sprintf("public, max-age=%d", cacheDuration))
		}

		// Write the response
		recorder.flush()
	})
}

// getCacheDuration returns the cache duration for a given path
func (cc *CacheConfig) getCacheDuration(path string) int {
	// Find the longest matching prefix
	maxLen := 0
	duration := 0 // Default: no-cache

	for prefix, dur := range cc.cacheDurations {
		if strings.HasPrefix(path, prefix) && len(prefix) > maxLen {
			maxLen = len(prefix)
			duration = dur
		}
	}

	return duration
}

// generateETag generates an ETag from response content
func generateETag(content []byte) string {
	hash := sha256.Sum256(content)
	return fmt.Sprintf(`W/"%x"`, hash[:16]) // Use weak ETag with first 16 bytes of hash
}

// cacheResponseWriter wraps http.ResponseWriter to capture response
type cacheResponseWriter struct {
	http.ResponseWriter
	body       *bytes.Buffer
	statusCode int
}

func (crw *cacheResponseWriter) Write(b []byte) (int, error) {
	return crw.body.Write(b)
}

func (crw *cacheResponseWriter) WriteHeader(code int) {
	crw.statusCode = code
}

func (crw *cacheResponseWriter) flush() {
	// Copy headers from original response
	for k, v := range crw.ResponseWriter.Header() {
		if k != "Etag" && k != "Cache-Control" {
			for _, val := range v {
				crw.ResponseWriter.Header().Add(k, val)
			}
		}
	}

	// Write status code
	crw.ResponseWriter.WriteHeader(crw.statusCode)

	// Write body
	crw.ResponseWriter.Write(crw.body.Bytes())
}
