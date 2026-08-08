package api

import "testing"

// The shipped templates are what production parses at startup; a page
// that cannot parse must fail the tests, not the daemon's startup.
func TestShippedTemplatesParse(t *testing.T) {
	if err := InitTemplates("../../templates"); err != nil {
		t.Fatalf("templates: %v", err)
	}
}
