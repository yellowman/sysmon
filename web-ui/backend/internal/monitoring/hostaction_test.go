package monitoring

import (
	"strings"
	"testing"
)

// A host action must go to the daemon that owns the host.
//
// These used to split "site:object" apart, throw the site away, and dial
// s.sysmonAddr - the first configured daemon. In the default fleet
// nothing is dialled, so that address is empty and every ack failed with
// "missing address"; in a mixed fleet the command went to the wrong box,
// and hit its own object of that name if it had one. Sites cloned from a
// template usually do.
//
// The fleet here is empty, so the observable is which name the error
// blames: naming the site proves the routing looked for it. "missing
// address" would mean the site half went in the bin again.
func TestHostActionsRouteBySite(t *testing.T) {
	s := NewService("")

	check := func(what string, err error) {
		t.Helper()
		if err == nil {
			t.Fatalf("%s: an empty fleet cannot ack anything, but no error came back", what)
		}
		if !strings.Contains(err.Error(), "metro") {
			t.Errorf("%s: error does not name the site it was meant for: %v", what, err)
		}
		if strings.Contains(err.Error(), "missing address") {
			t.Errorf("%s: dialled the primary instead of routing by site: %v", what, err)
		}
	}

	check("AckHost", s.AckHost("metro:core", ""))
	check("UpdateHostStatus", s.UpdateHostStatus("metro:core", "a note", ""))

	_, err := s.ToggleTrace("metro:core", "")
	check("ToggleTrace", err)

	_, err = s.GetObjectXML("metro:core")
	check("GetObjectXML", err)
}

// An object name with no site half still has to work: a single-site
// install never qualifies anything.
func TestHostActionKeepsUnqualifiedNames(t *testing.T) {
	s := NewService("")
	err := s.AckHost("core", "")
	if err == nil {
		t.Fatal("expected an error from an empty fleet")
	}
	if strings.Contains(err.Error(), "no object name") {
		t.Errorf("an unqualified name lost its object half: %v", err)
	}
}

// A bulk selection crosses sites, so the results must stay lined up with
// the request and each host must be judged by its own site's outcome.
func TestBulkResultsStayInOrderAcrossSites(t *testing.T) {
	s := NewService("")

	hosts := []string{"metro:core", "depot:core", "metro:edge", "", "depot:edge"}
	results := s.BulkAckHosts(hosts, "")

	if len(results) != len(hosts) {
		t.Fatalf("got %d results for %d hosts", len(results), len(hosts))
	}
	for i, r := range results {
		if r.Hostname != hosts[i] {
			t.Errorf("result %d is for %q, want %q - the API pairs these by position",
				i, r.Hostname, hosts[i])
		}
		if r.Success {
			t.Errorf("result %d succeeded against an empty fleet", i)
		}
		if r.Error == "" {
			t.Errorf("result %d failed with no reason given", i)
		}
	}

	// The empty name is rejected on its own account, not blamed on a site.
	if !strings.Contains(results[3].Error, "no object name") {
		t.Errorf("an empty host name should be refused by name: %q", results[3].Error)
	}
	// Each real entry names the site it belongs to.
	for _, i := range []int{0, 2} {
		if !strings.Contains(results[i].Error, "metro") {
			t.Errorf("result %d should blame metro: %q", i, results[i].Error)
		}
	}
	for _, i := range []int{1, 4} {
		if !strings.Contains(results[i].Error, "depot") {
			t.Errorf("result %d should blame depot: %q", i, results[i].Error)
		}
	}
}
