package monitoring

import (
	"testing"

	"sysmon-web/internal/models"
)

// twoSiteFleet is a snapshot of two boxes: bend answering with three
// hosts (one critical), redmond answering with two (both healthy).
func twoSiteFleet() *models.SysmonStatus {
	host := func(site, name, status string) models.HostStatus {
		return models.HostStatus{
			ObjectName:    Qualify(site, name),
			LocalName:     name,
			Site:          site,
			Hostname:      name,
			OverallStatus: status,
		}
	}
	return &models.SysmonStatus{
		Hosts: []models.HostStatus{
			host("bend", "core", "OK"),
			host("bend", "ap1", "CRITICAL"),
			host("bend", "ap2", "OK"),
			host("redmond", "core", "OK"),
			host("redmond", "ap1", "OK"),
		},
		Daemons: []models.DaemonInfo{
			{Site: "bend", Version: "1.0.0-bend", PID: 111, Uptime: 100},
			{Site: "redmond", Version: "2.0.0-redmond", PID: 222, Uptime: 200},
		},
		Daemon: models.DaemonInfo{Site: "bend", Version: "1.0.0-bend", PID: 111},
		Statistics: models.Stats{
			TotalHosts:     5,
			HealthyHosts:   4,
			CriticalHosts:  1,
			ChecksByType:   map[string]int{},
			ChecksByStatus: map[string]int{},
		},
		SitesTotal:     2,
		SitesReachable: 2,
	}
}

// The bug this pins: the dashboard's first (full) poll was site-scoped
// and every delta poll after it was not, so five seconds after selecting
// Bend the cards silently switched to fleet totals and the daemon block
// to whichever daemon was primary. Scoping has to cover the whole
// response, not just the host lists.
func TestDeltaIsEntirelySiteLocal(t *testing.T) {
	s := NewService()
	s.cacheMu.Lock()
	s.storeSnapshotLocked(twoSiteFleet())
	rev := s.rev
	s.cacheMu.Unlock()

	// Poll 1: the full fetch a client makes on selecting a site.
	full := s.GetDelta(0, "bend")
	if !full.Full {
		t.Fatal("since=0 must be a full resync")
	}
	if len(full.Changed) != 3 {
		t.Fatalf("full poll: want bend's 3 hosts, got %d", len(full.Changed))
	}
	if full.Statistics.TotalHosts != 3 || full.Statistics.CriticalHosts != 1 || full.Statistics.HealthyHosts != 2 {
		t.Fatalf("full poll stats not site-local: %+v", full.Statistics)
	}
	if full.Daemon.Site != "bend" || full.Daemon.Version != "1.0.0-bend" {
		t.Fatalf("full poll daemon not bend's: %+v", full.Daemon)
	}
	if full.SitesTotal != 1 || full.SitesReachable != 1 {
		t.Fatalf("full poll coverage = %d/%d, want 1/1", full.SitesReachable, full.SitesTotal)
	}

	// Poll 2: the steady-state delta. Everything the first poll got
	// right must still be right - this is where it used to go wrong.
	d := s.GetDelta(rev, "bend")
	if d.Full {
		t.Fatal("an up-to-date client should get a delta, not a resync")
	}
	if d.Statistics.TotalHosts != 3 || d.Statistics.CriticalHosts != 1 || d.Statistics.HealthyHosts != 2 {
		t.Fatalf("delta stats went fleet-wide: %+v", d.Statistics)
	}
	if d.Daemon.Site != "bend" || d.Daemon.Version != "1.0.0-bend" || d.Daemon.PID != 111 {
		t.Fatalf("delta daemon went fleet-wide: %+v", d.Daemon)
	}
	if d.SitesTotal != 1 || d.SitesReachable != 1 {
		t.Fatalf("delta coverage = %d/%d, want 1/1", d.SitesReachable, d.SitesTotal)
	}

	// And the other site's view is its own, from the same snapshot.
	r := s.GetDelta(rev, "redmond")
	if r.Statistics.TotalHosts != 2 || r.Statistics.CriticalHosts != 0 {
		t.Fatalf("redmond stats: %+v", r.Statistics)
	}
	if r.Daemon.Version != "2.0.0-redmond" {
		t.Fatalf("redmond daemon: %+v", r.Daemon)
	}
}

// A site that stopped answering is dark for a client watching it, even
// while the rest of the fleet is fine - and fine for a client watching a
// site that is answering, even while another is dark. Fleet-wide
// coverage numbers cannot express either.
func TestSiteCoverageIsPerSelectedSite(t *testing.T) {
	st := twoSiteFleet()
	// redmond went dark: its hosts remain (flagged stale by Refresh),
	// its DaemonInfo does not.
	st.Daemons = []models.DaemonInfo{{Site: "bend", Version: "1.0.0-bend", PID: 111}}
	st.SitesReachable = 1

	s := NewService()
	s.cacheMu.Lock()
	s.storeSnapshotLocked(st)
	rev := s.rev
	s.cacheMu.Unlock()

	if d := s.GetDelta(rev, "bend"); d.SitesReachable != 1 || d.SitesTotal != 1 {
		t.Fatalf("bend is answering: want 1/1, got %d/%d", d.SitesReachable, d.SitesTotal)
	}
	if d := s.GetDelta(rev, "redmond"); d.SitesReachable != 0 || d.SitesTotal != 1 {
		t.Fatalf("redmond is dark: want 0/1, got %d/%d", d.SitesReachable, d.SitesTotal)
	}
	// The fleet view still reports the fleet.
	if d := s.GetDelta(rev, ""); d.SitesReachable != 1 || d.SitesTotal != 2 {
		t.Fatalf("fleet view: want 1/2, got %d/%d", d.SitesReachable, d.SitesTotal)
	}
}

// FilterSite serves the non-delta path and must agree with the delta
// path field for field, or the first poll and the second disagree again.
func TestFilterSiteAgreesWithDelta(t *testing.T) {
	st := twoSiteFleet()
	s := NewService()
	s.cacheMu.Lock()
	s.storeSnapshotLocked(st)
	rev := s.rev
	s.cacheMu.Unlock()

	filtered := FilterSite(st, "bend")
	d := s.GetDelta(rev, "bend")

	if filtered.Statistics.TotalHosts != d.Statistics.TotalHosts ||
		filtered.Statistics.CriticalHosts != d.Statistics.CriticalHosts ||
		filtered.Statistics.HealthyHosts != d.Statistics.HealthyHosts {
		t.Fatalf("status %+v vs delta %+v", filtered.Statistics, d.Statistics)
	}
	if filtered.Daemon.Version != d.Daemon.Version {
		t.Fatalf("status daemon %q vs delta daemon %q", filtered.Daemon.Version, d.Daemon.Version)
	}
	if filtered.SitesTotal != d.SitesTotal || filtered.SitesReachable != d.SitesReachable {
		t.Fatalf("status coverage %d/%d vs delta %d/%d",
			filtered.SitesReachable, filtered.SitesTotal, d.SitesReachable, d.SitesTotal)
	}
}
