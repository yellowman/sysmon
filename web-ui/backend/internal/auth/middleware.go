package auth

import (
	"encoding/json"
	"net/http"
	"strings"
)

// RequireAuth wraps a handler to require a valid session.
// Allows /api/auth/login and static assets through without auth.
func RequireAuth(authSvc *Service, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Strip auth headers to prevent client spoofing
		r.Header.Del("X-Session-User")
		r.Header.Del("X-Session-Role")

		path := r.URL.Path

		// Login endpoint and login page are always open
		if path == "/api/auth/login" || path == "/login.html" {
			next.ServeHTTP(w, r)
			return
		}

		// Static assets are open
		if strings.HasPrefix(path, "/static/") {
			next.ServeHTTP(w, r)
			return
		}

		sess := authSvc.GetSessionFromRequest(r)
		if sess == nil {
			// For API requests, return JSON 401
			if strings.HasPrefix(path, "/api/") {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusUnauthorized)
				json.NewEncoder(w).Encode(map[string]string{
					"error":   "Unauthorized",
					"message": "Login required",
				})
				return
			}
			// For page requests, redirect to login
			http.Redirect(w, r, "/login.html", http.StatusFound)
			return
		}

		// Store session in context-like header for downstream handlers
		r.Header.Set("X-Session-User", sess.Username)
		r.Header.Set("X-Session-Role", sess.Role)

		next.ServeHTTP(w, r)
	})
}

// RequireAdmin wraps a handler to require admin role.
func RequireAdmin(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		role := r.Header.Get("X-Session-Role")
		if role != RoleAdmin {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusForbidden)
			json.NewEncoder(w).Encode(map[string]string{
				"error":   "Forbidden",
				"message": "Admin access required",
			})
			return
		}
		next(w, r)
	}
}
