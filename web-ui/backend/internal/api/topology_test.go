package api

import (
	"encoding/json"
	"strings"
	"testing"

	"sysmon-web/internal/models"
)

// The topology endpoint exists so a read-only user can have the map
// without being handed the config's secrets. That is a security
// boundary, and this is the test that holds it: fill every
// secret-bearing field on an object with a marker, run it through the
// sanitiser, and assert no marker survives into the JSON.
//
// It is written against the whole serialized output rather than a list
// of field names on purpose. A new secret added to models.Host later
// cannot quietly appear here - TopologyHost is an allow-list, and if
// somebody widens it, a marker shows up in this string.
func TestTopologyOmitsEverySecret(t *testing.T) {
	const marker = "SECRET-DO-NOT-LEAK"

	cfg := &models.Config{Hosts: []models.Host{{
		// The fields the map legitimately draws.
		ID:           "awbreyrouter",
		IP:           "10.20.4.1",
		Type:         "ping",
		Notes:        "Awbrey tower router",
		Group:        "tower-awbrey",
		Dependencies: "core-rtr-1",

		// Everything a config carries that the map has no business
		// showing to someone who cannot read the config.
		Password:      marker,
		Secret:        marker,
		Username:      marker,
		SNMPCommunity: marker,
		Spawn:         marker,
		Command:       marker,
		Contact:       marker,
		URL:           marker,
		URLText:       marker,
		Header:        marker,
		HeaderVal:     marker,
	}}}

	blob, err := json.Marshal(topologyOf(cfg))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(blob), marker) {
		t.Fatalf("topology leaked a secret field: %s", blob)
	}

	// And it still carries what the map needs, or it is useless.
	var got []TopologyHost
	if err := json.Unmarshal(blob, &got); err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Fatalf("want 1 host, got %d", len(got))
	}
	h := got[0]
	if h.ID != "awbreyrouter" || h.IP != "10.20.4.1" || h.Type != "ping" ||
		h.Notes != "Awbrey tower router" || h.Group != "tower-awbrey" ||
		h.Dependencies != "core-rtr-1" {
		t.Fatalf("topology dropped a field the map draws: %+v", h)
	}
}

// Severity and source filtering happens on the server, over the whole
// set, so the counts above the list describe the list.
func TestFilterTrapsNarrowsAndRecounts(t *testing.T) {
	in := &models.TrapInfo{
		RecentTraps: []models.Trap{
			{Site: "bend", SourceIP: "10.20.1.14", TrapType: "linkDown",
				Decoded: &models.TrapDecode{Severity: "critical"}},
			{Site: "bend", SourceIP: "10.20.1.14", TrapType: "linkUp",
				Decoded: &models.TrapDecode{Severity: "informational"}},
			{Site: "prineville", SourceIP: "10.20.1.14", TrapType: "authenticationFailure",
				Decoded: &models.TrapDecode{Severity: "critical"}},
			{Site: "bend", SourceIP: "10.20.9.9", TrapType: "coldStart"}, // no decode: unknown
		},
		TrapSources: []models.TrapSource{
			{Site: "bend", SourceIP: "10.20.1.14"},
			{Site: "prineville", SourceIP: "10.20.1.14"},
			{Site: "bend", SourceIP: "10.20.9.9"},
		},
		Summary: models.TrapSummary{Lost: 7},
	}

	crit := filterTraps(in, "critical", "")
	if len(crit.RecentTraps) != 2 {
		t.Fatalf("severity filter: want 2, got %d", len(crit.RecentTraps))
	}
	if crit.Summary.TrapsBySeverity["critical"] != 2 || crit.Summary.TrapsBySeverity["informational"] != 0 {
		t.Fatalf("summary not rebuilt for the filtered set: %+v", crit.Summary.TrapsBySeverity)
	}
	if crit.Summary.Lost != 7 {
		t.Fatal("lost-trap count is a property of collection and must survive filtering")
	}

	// An undecoded trap is "unknown", not invisible.
	unknown := filterTraps(in, "unknown", "")
	if len(unknown.RecentTraps) != 1 || unknown.RecentTraps[0].TrapType != "coldStart" {
		t.Fatalf("undecoded traps must be reachable as unknown: %+v", unknown.RecentTraps)
	}

	bySource := filterTraps(in, "", "10.20.9.9")
	if len(bySource.RecentTraps) != 1 || len(bySource.TrapSources) != 1 {
		t.Fatalf("source filter: %d traps, %d sources", len(bySource.RecentTraps), len(bySource.TrapSources))
	}
}

// A source is site plus address. Selecting Bend's 10.20.1.14 must not
// also select Prineville's device at the same address, and a severity
// filter must not leave sources in the rollup whose every trap it just
// removed - "Unique Sources" has to describe the list underneath it.
func TestFilterTrapsSourceIdentityIsSiteQualified(t *testing.T) {
	in := &models.TrapInfo{
		RecentTraps: []models.Trap{
			{Site: "bend", SourceIP: "10.20.1.14", TrapType: "linkDown",
				Decoded: &models.TrapDecode{Severity: "critical"}},
			{Site: "prineville", SourceIP: "10.20.1.14", TrapType: "authFailure",
				Decoded: &models.TrapDecode{Severity: "warning"}},
			{Site: "bend", SourceIP: "10.20.9.9", TrapType: "coldStart",
				Decoded: &models.TrapDecode{Severity: "warning"}},
		},
		TrapSources: []models.TrapSource{
			{Site: "bend", SourceIP: "10.20.1.14"},
			{Site: "prineville", SourceIP: "10.20.1.14"},
			{Site: "bend", SourceIP: "10.20.9.9"},
		},
	}

	one := filterTraps(in, "", "bend/10.20.1.14")
	if len(one.RecentTraps) != 1 || one.RecentTraps[0].Site != "bend" {
		t.Fatalf("site-qualified source selected the wrong devices: %+v", one.RecentTraps)
	}
	if len(one.TrapSources) != 1 || one.TrapSources[0].Site != "bend" {
		t.Fatalf("rollup should hold one device: %+v", one.TrapSources)
	}

	// A bare address means that address at any site: the only sensible
	// reading of a request that did not name one.
	both := filterTraps(in, "", "10.20.1.14")
	if len(both.RecentTraps) != 2 {
		t.Fatalf("bare address should match both sites, got %d", len(both.RecentTraps))
	}

	// Severity narrows the rollup too.
	warn := filterTraps(in, "warning", "")
	if len(warn.RecentTraps) != 2 {
		t.Fatalf("want 2 warnings, got %d", len(warn.RecentTraps))
	}
	if len(warn.TrapSources) != 2 {
		t.Fatalf("Unique Sources must reflect the filtered set, got %d: %+v",
			len(warn.TrapSources), warn.TrapSources)
	}
	for _, s := range warn.TrapSources {
		if s.Site == "bend" && s.SourceIP == "10.20.1.14" {
			t.Fatal("a source whose only trap was filtered out is still counted")
		}
	}
}
