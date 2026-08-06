package api

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"sysmon-web/internal/settings"
)

func TestParseSiteFilesWithInclude(t *testing.T) {
	files := []settings.GenFile{
		{Name: "sysmon.conf", Content: []byte(
			"root = \"gw\";\n" +
				"include \"hosts.conf\";\n" +
				"object gw {\n    ip \"192.0.2.1\";\n    type ping;\n    contact chris@example.net;\n};\n")},
		{Name: "hosts.conf", Content: []byte(
			"object web {\n    ip \"192.0.2.2\";\n    type tcp;\n    port 80;\n    dep \"gw\";\n    contact chris@example.net;\n};\n")},
	}
	cfg, err := parseSiteFiles(files)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(cfg.Hosts) != 2 {
		t.Fatalf("got %d hosts, want 2 (include not followed?)", len(cfg.Hosts))
	}
	if cfg.Root != "gw" {
		t.Fatalf("root = %q, want gw", cfg.Root)
	}
}

func TestParseSiteFilesEmptySet(t *testing.T) {
	if _, err := parseSiteFiles(nil); err == nil {
		t.Fatal("empty set parsed without error")
	}
}

// A site the aggregator has no connection to must come back 503, not a
// parse of the local file under a remote label.
func TestRemoteConfigUnknownSiteIs503(t *testing.T) {
	handler, authSvc, cleanup := testRouter(t)
	defer cleanup()
	token := sessionFor(t, authSvc, "rc-admin", "rc-pass-123", "admin")

	for _, url := range []string{
		"/api/config?site=nowhere",
		"/api/config/raw?site=nowhere",
	} {
		req := httptest.NewRequest(http.MethodGet, url, nil)
		req.Header.Set("Authorization", "Bearer "+token)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)
		if w.Code != http.StatusServiceUnavailable {
			t.Errorf("GET %s: got %d, want 503", url, w.Code)
		}
	}
}

// Structured saves stay local-only: a remote site gets a clear refusal,
// never a silent write to the local file.
func TestRemoteStructuredSaveRefused(t *testing.T) {
	handler, authSvc, cleanup := testRouter(t)
	defer cleanup()
	token := sessionFor(t, authSvc, "rc-admin2", "rc-pass-123", "admin")

	req := httptest.NewRequest(http.MethodPut, "/api/config?site=metro", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("PUT /api/config?site=metro: got %d, want 400", w.Code)
	}
}

// site=local and no site are the same thing: the local file.
func TestSiteLocalMeansLocal(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/api/config?site=local", nil)
	if got := remoteSite(req); got != "" {
		t.Fatalf("remoteSite(local) = %q, want empty", got)
	}
}
