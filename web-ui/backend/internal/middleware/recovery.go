package middleware

import (
	"bufio"
	"log"
	"net"
	"net/http"
	"runtime/debug"
)

// recoveryResponseWriter wraps http.ResponseWriter to track if headers have been sent
type recoveryResponseWriter struct {
	http.ResponseWriter
	wroteHeader bool
}

func (w *recoveryResponseWriter) WriteHeader(statusCode int) {
	if !w.wroteHeader {
		w.wroteHeader = true
		w.ResponseWriter.WriteHeader(statusCode)
	}
}

func (w *recoveryResponseWriter) Write(b []byte) (int, error) {
	if !w.wroteHeader {
		w.wroteHeader = true
		// Write implicitly calls WriteHeader(200) if not called yet
	}
	return w.ResponseWriter.Write(b)
}

// Flush implements http.Flusher if the underlying ResponseWriter supports it
func (w *recoveryResponseWriter) Flush() {
	if flusher, ok := w.ResponseWriter.(http.Flusher); ok {
		flusher.Flush()
	}
}

// Hijack implements http.Hijacker if the underlying ResponseWriter supports it
func (w *recoveryResponseWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	if hijacker, ok := w.ResponseWriter.(http.Hijacker); ok {
		return hijacker.Hijack()
	}
	return nil, nil, http.ErrNotSupported
}

// Recovery middleware catches panics and logs them
func Recovery(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Wrap the response writer to track header writes
		wrapped := &recoveryResponseWriter{ResponseWriter: w, wroteHeader: false}

		defer func() {
			if err := recover(); err != nil {
				// Log the panic and stack trace
				log.Printf("PANIC: %v\n%s", err, debug.Stack())

				// Only try to send error response if headers haven't been sent yet
				if !wrapped.wroteHeader {
					http.Error(wrapped, "Internal Server Error", http.StatusInternalServerError)
				}
				// If headers were already sent, we can't send an error response
				// The connection will just close with whatever was partially sent
			}
		}()

		next.ServeHTTP(wrapped, r)
	})
}
