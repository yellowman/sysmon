package monitoring

import "testing"

// Two sites' private ranges overlap. 10.20.1.14 at Bend and 10.20.1.14
// at Prineville are different devices, and the fleet-wide trap view used
// to merge them: same address, one row in the source rollup, no way to
// tell which box saw what. A trap's identity is site plus address.
func TestTrapsCarrySiteThroughTheFleetMerge(t *testing.T) {
	traps := []sitedTrap{
		{site: "bend", t: xmlTrap{Source: "10.20.1.14", Time: 300, Name: "linkDown", Severity: "critical", Decoded: 1}},
		{site: "prineville", t: xmlTrap{Source: "10.20.1.14", Time: 200, Name: "authenticationFailure", Severity: "critical", Decoded: 1}},
		{site: "bend", t: xmlTrap{Source: "10.20.1.14", Time: 100, Name: "linkUp", Severity: "informational", Decoded: 1}},
	}

	info := buildTrapInfo(traps)

	if len(info.RecentTraps) != 3 {
		t.Fatalf("want 3 traps, got %d", len(info.RecentTraps))
	}
	for i, want := range []string{"bend", "prineville", "bend"} {
		if info.RecentTraps[i].Site != want {
			t.Errorf("trap %d: site %q, want %q", i, info.RecentTraps[i].Site, want)
		}
	}

	// One rollup row per device, not one per address shared between
	// sites: two sources here, both with the same IP.
	if len(info.TrapSources) != 2 {
		t.Fatalf("want 2 sources (one per site), got %d: %+v", len(info.TrapSources), info.TrapSources)
	}
	bySite := map[string]int{}
	for _, s := range info.TrapSources {
		if s.SourceIP != "10.20.1.14" {
			t.Errorf("unexpected source %q", s.SourceIP)
		}
		bySite[s.Site] = s.TrapCount
	}
	if bySite["bend"] != 2 || bySite["prineville"] != 1 {
		t.Fatalf("per-site counts wrong: %+v", bySite)
	}
}
