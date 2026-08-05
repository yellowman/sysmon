package templates

import (
	"strings"
	"testing"
)

// Every shipped template must expand into objects sysmond will accept.
//
// This is not hypothetical. Writing the first full set produced four
// templates whose objects the daemon rejected outright: a dns check with
// no query, an imap check with no credentials (which a template cannot
// supply at all), and an http check missing both its url and the text to
// look for in the response - "type http" is a content check and needs
// both. Each looked perfectly reasonable in Go and was refused by the
// parser.
//
// The real gate is `sysmond -t` on the generated config, which is run
// separately because it needs the daemon built. This test catches the
// same class of mistake from the Go side, so a template with a check
// type that needs a field nobody supplied fails here first.
func TestEveryBuiltinExpandsCompletely(t *testing.T) {
	// What each check type cannot be written without. The daemon's own
	// rules, mirrored: see the validation block in src/parser.l where an
	// object is marked invalid.
	required := map[string][]string{
		"dns":   {"dns_query"},
		"http":  {"url", "url_text"},
		"https": {"url"},
		"snmp":  {"oid"},
		"imap":  {"username", "password"},
		"pop3":  {"username", "password"},
	}

	for _, tpl := range Builtins() {
		if tpl.ID == "" || tpl.Name == "" {
			t.Errorf("template with no id or name: %+v", tpl)
		}
		if len(tpl.Checks) == 0 {
			t.Errorf("%s: a template with no checks monitors nothing", tpl.ID)
		}

		// The first check is the device itself: everything else may
		// depend on it, and a suffix on the device object would mean
		// nothing to depend on.
		if tpl.Checks[0].Suffix != "" {
			t.Errorf("%s: the first check should be the device itself (empty suffix), got %q",
				tpl.ID, tpl.Checks[0].Suffix)
		}

		seen := map[string]bool{}
		for _, c := range tpl.Checks {
			if seen[c.Suffix] {
				t.Errorf("%s: two checks share the suffix %q, so they would be one object",
					tpl.ID, c.Suffix)
			}
			seen[c.Suffix] = true

			for _, need := range required[c.Type] {
				var got string
				switch need {
				case "dns_query":
					got = c.DNSQuery
				case "url":
					got = c.URL
				case "url_text":
					got = c.URLText
				case "oid":
					got = c.OID
				case "username", "password":
					// A template cannot carry credentials, so it must not
					// ship a check type that requires them.
					t.Errorf("%s: check %q is type %s, which sysmond will not accept "+
						"without %s - and a shipped template cannot supply one",
						tpl.ID, c.Suffix, c.Type, need)
					continue
				}
				if strings.TrimSpace(got) == "" {
					t.Errorf("%s: check %q is type %s but has no %s - sysmond refuses "+
						"the object and it is silently not monitored",
						tpl.ID, c.Suffix, c.Type, need)
				}
			}
		}

		// And it has to actually expand.
		hosts, err := Expand(&tpl, Params{
			Name: "dev", IP: "10.0.0.1", Parent: "core",
			Desc: "test", Contact: "noc@example.net", Community: "public"})
		if err != nil {
			t.Errorf("%s: %v", tpl.ID, err)
			continue
		}
		if len(hosts) != len(tpl.Checks) {
			t.Errorf("%s: %d checks produced %d objects", tpl.ID, len(tpl.Checks), len(hosts))
		}
		for _, h := range hosts {
			if h.Hostname == "" || h.Type == "" || h.IP == "" {
				t.Errorf("%s: incomplete object %+v", tpl.ID, h)
			}
		}
	}
}

// Thresholds are pitched by role, and the point of that is lost if
// someone later "tidies" them to one number. Backhaul and core are the
// links everything rides on; subscriber-facing gear loses packets in
// weather and must not page for it.
func TestThresholdsStayPitchedByRole(t *testing.T) {
	rttAvg := map[string]int{}
	lossTol := map[string]int{}
	for _, tpl := range Builtins() {
		for _, c := range tpl.Checks {
			if c.Type == "rtt" && c.RTTThreshold > 0 {
				rttAvg[tpl.ID] = c.RTTThreshold
			}
			if c.Type == "pktloss" {
				lossTol[tpl.ID] = c.PktLossTolerance
			}
		}
	}

	if core, sector := rttAvg["core-router"], rttAvg["ptmp-sector"]; core >= sector {
		t.Errorf("core latency threshold (%dms) should be tighter than a subscriber sector's (%dms)",
			core, sector)
	}
	if bh, sector := rttAvg["siklu-ptp"], rttAvg["ptmp-sector"]; bh >= sector {
		t.Errorf("backhaul latency threshold (%dms) should be tighter than a sector's (%dms)",
			bh, sector)
	}
	if core, ap := lossTol["core-router"], lossTol["ubnt-ap"]; core >= ap {
		t.Errorf("core loss tolerance (%d) should be tighter than a subscriber AP's (%d)",
			core, ap)
	}
}
