package api

import (
	"context"
	"crypto/hmac"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"net/url"
	"time"

	"sysmon-web/internal/auth"
)

const oidcFlowCookie = "sysmon_oidc_flow"

func (r *Router) handleOIDCLogin(w http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodGet {
		http.Error(w, "Method not allowed", 405)
		return
	}
	client := r.auth.OIDC()
	if client == nil {
		http.Error(w, "OIDC is not configured", 503)
		return
	}
	id, flow, err := r.auth.StartOIDCFlow(req.URL.Query().Get("mobile_challenge"))
	if err != nil {
		http.Error(w, "Could not start sign-in", 400)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Referrer-Policy", "no-referrer")
	http.SetCookie(w, &http.Cookie{Name: oidcFlowCookie, Value: id, Path: "/auth", MaxAge: 600, HttpOnly: true, Secure: client.SecureCookies(), SameSite: http.SameSiteLaxMode})
	http.Redirect(w, req, client.AuthorizationURL(flow.State, flow.Nonce, flow.Verifier), 302)
}

func (r *Router) revokeIdentity(identity auth.OIDCIdentity) {
	if client := r.auth.OIDC(); client != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = client.Revoke(ctx, identity.RefreshToken)
	}
}

func (r *Router) handleOIDCCallback(w http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodGet {
		http.Error(w, "Method not allowed", 405)
		return
	}
	client := r.auth.OIDC()
	if client == nil {
		http.Error(w, "OIDC is not configured", 503)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Referrer-Policy", "no-referrer")
	cookie, err := req.Cookie(oidcFlowCookie)
	if err != nil {
		http.Error(w, "Sign-in flow cookie is missing", 400)
		return
	}
	http.SetCookie(w, &http.Cookie{Name: oidcFlowCookie, Path: "/auth", MaxAge: -1, HttpOnly: true, Secure: client.SecureCookies(), SameSite: http.SameSiteLaxMode})
	flow, err := r.auth.ConsumeOIDCFlow(cookie.Value)
	if err != nil || !hmac.Equal([]byte(flow.State), []byte(req.URL.Query().Get("state"))) {
		http.Error(w, "Invalid or expired sign-in flow", 400)
		return
	}
	if req.URL.Query().Get("error") != "" {
		http.Error(w, "Sign-in was refused by authd", 401)
		return
	}
	code := req.URL.Query().Get("code")
	if code == "" {
		http.Error(w, "Authorization code is missing", 400)
		return
	}
	identity, err := client.Exchange(req.Context(), code, flow.Verifier, flow.Nonce)
	if err != nil {
		log.Printf("OIDC sign-in rejected: %v", err)
		http.Error(w, "Sign-in failed or Sysmon access was not granted", 403)
		return
	}
	if flow.MobileChallenge != "" {
		handoff, err := r.auth.StartMobileHandoff(identity, flow.MobileChallenge)
		if err != nil {
			r.revokeIdentity(identity)
			http.Error(w, "Mobile sign-in could not be completed", 500)
			return
		}
		http.Redirect(w, req, "sysmon://auth/callback?code="+url.QueryEscape(handoff), 302)
		return
	}
	session, err := r.auth.CreateOIDCSession(identity)
	if err != nil {
		r.revokeIdentity(identity)
		http.Error(w, "Could not create session", 500)
		return
	}
	http.SetCookie(w, &http.Cookie{Name: "sysmon_session", Value: session.Token, Path: "/", MaxAge: 30 * 86400, HttpOnly: true, Secure: client.SecureCookies(), SameSite: http.SameSiteStrictMode})
	// Commit a same-origin document before navigating: a 302 would keep
	// the cross-site redirect chain and withhold the Strict cookie.
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; base-uri 'none'; frame-ancestors 'none'")
	_, _ = io.WriteString(w, `<!doctype html><html><head><meta charset="utf-8"><meta http-equiv="refresh" content="0;url=/"><title>Signed in</title></head><body><a href="/">Continue to Sysmon</a></body></html>`)
}

func (r *Router) handleAuthMode(w http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodGet {
		r.sendError(w, 405, "Method not allowed")
		return
	}
	mode := "local"
	if r.auth.OIDC() != nil {
		mode = "oidc"
	}
	w.Header().Set("Cache-Control", "no-store")
	r.sendJSON(w, map[string]string{"mode": mode})
}

func (r *Router) handleMobileExchange(w http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodPost {
		r.sendError(w, 405, "Method not allowed")
		return
	}
	if r.auth.OIDC() == nil {
		r.sendError(w, 404, "OIDC is not configured")
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	var body struct {
		Code     string `json:"code"`
		Verifier string `json:"verifier"`
	}
	if json.NewDecoder(req.Body).Decode(&body) != nil {
		r.sendError(w, 400, "Invalid handoff")
		return
	}
	identity, err := r.auth.ConsumeMobileHandoff(body.Code, body.Verifier)
	if err != nil {
		r.sendError(w, 401, "Mobile sign-in expired or was invalid")
		return
	}
	session, err := r.auth.CreateOIDCSession(identity)
	if err != nil {
		r.revokeIdentity(identity)
		r.sendError(w, 401, "Mobile sign-in could not be completed")
		return
	}
	r.sendJSON(w, map[string]string{"token": session.Token, "username": session.Username, "display_name": identity.DisplayName, "role": session.Role})
}
