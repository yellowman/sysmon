package api

import (
	"bytes"
	"os"
	"testing"
)

// The shipped templates are what production parses at startup; a page
// that cannot parse must fail the tests, not the daemon's startup.
func TestShippedTemplatesParse(t *testing.T) {
	if err := InitTemplates("../../templates"); err != nil {
		t.Fatalf("templates: %v", err)
	}
}

// The config editor's secrets (the daemon authkey, per-check passwords,
// the RADIUS shared secret) must not be type="password" controls. A
// password input is the browser's cue that the page is a login form:
// Firefox offers to save a monitoring credential as a website login when
// the operator navigates away, and no autocomplete value suppresses
// that - "new-password" was tried and did not. The editor masks these
// with -webkit-text-security on plain text inputs instead. The genuine
// sysmon-web credentials (login.html, admin.html's create-user field)
// keep real password controls; this test deliberately covers only
// config.html.
func TestConfigEditorHasNoPasswordControls(t *testing.T) {
	b, err := os.ReadFile("../../templates/config.html")
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(b, []byte(`type="password"`)) {
		t.Fatal(`config.html must not use type="password": browsers treat configuration secrets as website credentials`)
	}
	// The replacement is masked text, not bare text: dropping the mask
	// would leave secrets readable over the operator's shoulder.
	if !bytes.Contains(b, []byte(`-webkit-text-security`)) {
		t.Fatal(`config.html secrets must stay visually masked (-webkit-text-security)`)
	}
}
