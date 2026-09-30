package api

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"sysmon-web/internal/auth"
)

func TestOIDCModeDisablesPasswordRoute(t *testing.T) {
	handler, service, stop := testRouter(t)
	defer stop()
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest("GET", "/api/auth/mode", nil))
	if recorder.Code != 200 || !strings.Contains(recorder.Body.String(), `"local"`) {
		t.Fatalf("local mode: %s", recorder.Body.String())
	}
	service.SetOIDCClient(&auth.OIDCClient{})
	recorder = httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest("GET", "/api/auth/mode", nil))
	if recorder.Code != 200 || !strings.Contains(recorder.Body.String(), `"oidc"`) {
		t.Fatalf("OIDC mode: %s", recorder.Body.String())
	}
	recorder = httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest("POST", "/api/auth/login", strings.NewReader(`{"username":"admin","password":"sysmon"}`)))
	if recorder.Code != http.StatusForbidden {
		t.Fatalf("local login in OIDC mode: %d", recorder.Code)
	}
	recorder = httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest("POST", "/api/auth/mobile-exchange", strings.NewReader(`{"code":"bad","verifier":"bad"}`)))
	if recorder.Code != 401 {
		t.Fatalf("invalid mobile handoff: %d", recorder.Code)
	}
}
