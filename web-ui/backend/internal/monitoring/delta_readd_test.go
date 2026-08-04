package monitoring

import (
	"testing"

	"sysmon-web/internal/models"
)

// A host that goes away and comes back must not be reported as both
// changed and removed in one delta.
//
// The tombstone in removedAt used to outlive the host: nothing cleared
// it when the name reappeared. A client whose "since" predates both
// events then got the name in Changed AND in Removed, and whichever list
// it applied second won. The dashboard applied removed second, so the
// host was inserted and immediately deleted - gone from the page, with
// its rev already advanced, so no later delta mentioned it again until
// its signature happened to change.
//
// The window is as long as a browser throttles a background tab, which
// is minutes.
func TestReAddedHostIsNotAlsoReportedRemoved(t *testing.T) {
	s := NewService("")

	snapshot := func(names ...string) {
		st := &models.SysmonStatus{}
		for _, n := range names {
			st.Hosts = append(st.Hosts, models.HostStatus{ObjectName: n, Hostname: n, OverallStatus: "up"})
		}
		s.cacheMu.Lock()
		s.storeSnapshotLocked(st)
		s.cacheMu.Unlock()
	}

	snapshot("gw", "leaf")
	s.cacheMu.Lock()
	before := s.rev // what a client that is about to fall behind holds
	s.cacheMu.Unlock()

	snapshot("gw")         // leaf is removed
	snapshot("gw", "leaf") // and comes straight back

	d := s.GetDelta(before)

	inChanged := false
	for _, h := range d.Changed {
		if h.ObjectName == "leaf" {
			inChanged = true
		}
	}
	inRemoved := false
	for _, n := range d.Removed {
		if n == "leaf" {
			inRemoved = true
		}
	}

	if !inChanged {
		t.Errorf("leaf is present now, so a client behind both events must be sent it: Changed=%v", d.Changed)
	}
	if inRemoved {
		t.Errorf("leaf is present now, but the delta still calls it removed: Removed=%v", d.Removed)
	}
}

// The ordinary removal must still be reported, or the fix above would
// just be "never report removals".
func TestRemovedHostIsStillReportedRemoved(t *testing.T) {
	s := NewService("")

	snapshot := func(names ...string) {
		st := &models.SysmonStatus{}
		for _, n := range names {
			st.Hosts = append(st.Hosts, models.HostStatus{ObjectName: n, Hostname: n, OverallStatus: "up"})
		}
		s.cacheMu.Lock()
		s.storeSnapshotLocked(st)
		s.cacheMu.Unlock()
	}

	snapshot("gw", "leaf")
	s.cacheMu.Lock()
	before := s.rev
	s.cacheMu.Unlock()
	snapshot("gw")

	d := s.GetDelta(before)

	found := false
	for _, n := range d.Removed {
		if n == "leaf" {
			found = true
		}
	}
	if !found {
		t.Errorf("leaf was removed and the delta does not say so: Removed=%v", d.Removed)
	}
	for _, h := range d.Changed {
		if h.ObjectName == "leaf" {
			t.Errorf("leaf was removed but is in Changed too: %v", d.Changed)
		}
	}
}
