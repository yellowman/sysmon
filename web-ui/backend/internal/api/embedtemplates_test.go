package api

import (
	"testing"

	webtemplates "sysmon-web/templates"
)

// The embedded templates are what production renders; a page that fails
// to parse must fail the build's tests, not the daemon's startup.
func TestEmbeddedTemplatesParse(t *testing.T) {
	if err := InitTemplatesFS(webtemplates.Files); err != nil {
		t.Fatalf("embedded templates: %v", err)
	}
}
