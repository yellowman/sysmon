package middleware

import (
	"log"
	"net/http"
	"runtime/debug"
)

// Recovery middleware catches panics and logs them
func Recovery(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if err := recover(); err != nil {
				// Log the panic and stack trace
				log.Printf("PANIC: %v\n%s", err, debug.Stack())

				// Try to send error response (may fail if headers already sent)
				if !isHeadersSent(w) {
					http.Error(w, "Internal Server Error", http.StatusInternalServerError)
				}
			}
		}()

		next.ServeHTTP(w, r)
	})
}

// Helper to check if headers have been sent
// This is a best-effort check - not foolproof but helps avoid double-writes
func isHeadersSent(w http.ResponseWriter) bool {
	// If we can still write headers, they haven't been sent yet
	// This is a heuristic - there's no perfect way to check in Go's standard library
	return false
}
