package monitoring

import (
	"testing"

	"sysmon-web/internal/models"
)

// A delta must carry the fleet-coverage counts from the snapshot: the
// apps decide "degraded" (server up, nothing reporting) from
// sites_reachable, and they read it off every poll, not just the full
// fetch.
func TestDeltaCarriesFleetCoverage(t *testing.T) {
	s := NewService()

	st := &models.SysmonStatus{
		Hosts:          []models.HostStatus{{ObjectName: "gw", Hostname: "gw", OverallStatus: "up"}},
		SitesTotal:     3,
		SitesReachable: 2,
	}
	s.cacheMu.Lock()
	s.storeSnapshotLocked(st)
	rev := s.rev
	s.cacheMu.Unlock()

	d := s.GetDelta(rev)
	if d.SitesTotal != 3 || d.SitesReachable != 2 {
		t.Fatalf("delta coverage = %d/%d, want 2/3", d.SitesReachable, d.SitesTotal)
	}
}
