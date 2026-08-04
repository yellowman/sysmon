package api

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"sysmon-web/internal/auth"
	"sysmon-web/internal/config"
	"sysmon-web/internal/monitoring"
	"sysmon-web/internal/settings"
)

// Which endpoints a plain user may reach.
//
// This is a table of the routing table, and it exists because the
// routing table is the whole access-control policy: one missing
// RequireAdmin is a silent hole, and it stays silent because the UI
// never exercises the endpoint - the admin page works either way.
//
// That is exactly what happened. /api/config/site/<site> returns the
// bytes of a box's running config - config authkey, aggregator-token,
// SNMP communities, radius secrets - and it sat unguarded next to four
// endpoints that were guarded, under a comment saying reads are open.
//
// The line is content, not verb: per-site status is open, config
// content is not.

// adminOnly must refuse a logged-in non-admin.
var adminOnly = []struct{ method, path string }{
	{"GET", "/api/config"},
	{"GET", "/api/config/raw"},
	{"POST", "/api/config/validate"},
	{"POST", "/api/config/reload"},

	// The two this test was written for.
	{"GET", "/api/config/site/metro"},
	{"GET", "/api/config/site/metro/generation/1"},
	{"GET", "/api/config/generations/metro"},

	{"POST", "/api/config/adopt/metro"},
	{"POST", "/api/config/stage/metro"},
	{"POST", "/api/config/deliver/metro"},
	{"POST", "/api/config/rollback/metro"},
	{"POST", "/api/config/revert/metro"},
	{"POST", "/api/config/rollout"},

	// A token is a credential and the CA names the server.
	{"GET", "/api/settings/agents"},
	{"POST", "/api/settings/agents"},
	{"POST", "/api/settings/agents/revoke/metro"},
	{"GET", "/api/settings/agents/ca"},
}

// openToAnyone is the other half of the rule. Losing these to a
// too-broad gate would be its own regression: status belongs on a
// wallboard, and none of it carries a secret.
var openToAnyone = []struct{ method, path string }{
	{"GET", "/api/config/fleet"},
	{"GET", "/api/config/rollout"},
	{"GET", "/api/monitoring/status"},
	{"GET", "/api/sites"},
}

func TestConfigContentIsAdminOnly(t *testing.T) {
	handler, authSvc, stop := testRouter(t)
	defer stop()

	userToken := sessionFor(t, authSvc, "viewer", "pw-viewer", auth.RoleUser)
	adminToken := sessionFor(t, authSvc, "boss", "pw-boss", auth.RoleAdmin)

	for _, ep := range adminOnly {
		if got := status(handler, ep.method, ep.path, userToken); got != http.StatusForbidden {
			t.Errorf("%s %s as a plain user: got %d, want 403", ep.method, ep.path, got)
		}
		// The gate is the claim, not the handler's own answer: an admin
		// may still get 404 or 503 here because this router has no
		// daemon behind it. 403 is the only status that means refused.
		if got := status(handler, ep.method, ep.path, adminToken); got == http.StatusForbidden {
			t.Errorf("%s %s as an admin: 403, so the endpoint is unreachable to everyone",
				ep.method, ep.path)
		}
	}

	for _, ep := range openToAnyone {
		if got := status(handler, ep.method, ep.path, userToken); got == http.StatusForbidden {
			t.Errorf("%s %s as a plain user: 403, but status is meant to be open",
				ep.method, ep.path)
		}
	}
}

// No session at all is 401, not 403 - and never 200. RequireAuth runs
// before RequireAdmin, so an unauthenticated request must not reach a
// handler whatever the gate below it says.
func TestNoSessionReachesNothing(t *testing.T) {
	handler, _, stop := testRouter(t)
	defer stop()

	for _, ep := range append(append([]struct{ method, path string }{}, adminOnly...), openToAnyone...) {
		if got := status(handler, ep.method, ep.path, ""); got != http.StatusUnauthorized {
			t.Errorf("%s %s with no session: got %d, want 401", ep.method, ep.path, got)
		}
	}
}

// A client that supplies its own role header must not be believed.
// RequireAuth strips these before anything downstream sees them; this
// pins that, because the whole gate is one header comparison.
func TestRoleHeaderCannotBeSpoofed(t *testing.T) {
	handler, authSvc, stop := testRouter(t)
	defer stop()

	userToken := sessionFor(t, authSvc, "viewer", "pw-viewer", auth.RoleUser)

	req := httptest.NewRequest("GET", "/api/config/site/metro", nil)
	req.Header.Set("Authorization", "Bearer "+userToken)
	req.Header.Set("X-Session-Role", auth.RoleAdmin)
	req.Header.Set("X-Session-User", "boss")

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Errorf("a user claiming to be an admin got %d, want 403", rec.Code)
	}
}

func status(h http.Handler, method, path, token string) int {
	req := httptest.NewRequest(method, path, nil)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec.Code
}

func sessionFor(t *testing.T, authSvc *auth.Service, user, pass, role string) string {
	t.Helper()
	if err := authSvc.CreateUser(user, pass, role); err != nil {
		t.Fatalf("create %s: %v", user, err)
	}
	sess, err := authSvc.Login(user, pass)
	if err != nil {
		t.Fatalf("login %s: %v", user, err)
	}
	return sess.Token
}

// testRouter builds the real handler chain - RequireAuth, RequireAdmin,
// the real mux - over empty stores. Nothing is stubbed, because a test
// that stubs the middleware would pass with the bug in place.
func testRouter(t *testing.T) (http.Handler, *auth.Service, func()) {
	t.Helper()
	dir := t.TempDir()

	authSvc, err := auth.NewService(filepath.Join(dir, "auth.db"))
	if err != nil {
		t.Fatalf("auth service: %v", err)
	}

	settingsStore, err := settings.NewStore(filepath.Join(dir, "settings.db"))
	if err != nil {
		authSvc.Close()
		t.Fatalf("settings store: %v", err)
	}

	cfgSvc := config.NewService(
		filepath.Join(dir, "sysmon.conf"),
		filepath.Join(dir, "backups"),
		filepath.Join(dir, "audit.log"),
	)
	monSvc := monitoring.NewService("")

	handler, stopPush := NewRouter(cfgSvc, monSvc, nil, nil, authSvc, settingsStore)

	return handler, authSvc, func() {
		stopPush()
		settingsStore.Close()
		authSvc.Close()
	}
}
