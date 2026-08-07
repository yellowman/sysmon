package push

import (
	"testing"
	"time"
)

// The loud fleet-dark push: fires once after the dwell, not per poll,
// not for a blip, and the recovery is a single quiet send.
func TestFleetCoverageChange(t *testing.T) {
	s := &Service{}
	t0 := time.Date(2026, 8, 7, 12, 0, 0, 0, time.UTC)

	// Healthy fleet: nothing to say.
	if _, _, _, send := s.fleetCoverageChange(3, 3, t0); send {
		t.Fatal("healthy fleet sent something")
	}

	// Goes dark: silent until the dwell has passed.
	if _, _, _, send := s.fleetCoverageChange(3, 0, t0); send {
		t.Fatal("sent immediately on going dark")
	}
	if _, _, _, send := s.fleetCoverageChange(3, 0, t0.Add(fleetDarkDwell-time.Second)); send {
		t.Fatal("sent before the dwell elapsed")
	}

	// Dwell elapsed: one loud send.
	title, _, critical, send := s.fleetCoverageChange(3, 0, t0.Add(fleetDarkDwell))
	if !send || !critical {
		t.Fatalf("want a critical send after the dwell, got send=%v critical=%v", send, critical)
	}
	if title != "MONITORING DEGRADED" {
		t.Fatalf("title = %q", title)
	}

	// Still dark: no repeat.
	if _, _, _, send := s.fleetCoverageChange(3, 0, t0.Add(fleetDarkDwell+time.Minute)); send {
		t.Fatal("repeated the dark notification")
	}

	// Recovery: one quiet send.
	title, _, critical, send = s.fleetCoverageChange(3, 2, t0.Add(2*time.Minute))
	if !send || critical {
		t.Fatalf("want a non-critical recovery send, got send=%v critical=%v", send, critical)
	}
	if title != "MONITORING RESTORED" {
		t.Fatalf("recovery title = %q", title)
	}

	// And only once.
	if _, _, _, send := s.fleetCoverageChange(3, 3, t0.Add(3*time.Minute)); send {
		t.Fatal("repeated the recovery")
	}
}

// A blip shorter than the dwell - a daemon reconnecting after a config
// delivery - must send nothing in either direction.
func TestFleetCoverageBlipIsSilent(t *testing.T) {
	s := &Service{}
	t0 := time.Date(2026, 8, 7, 12, 0, 0, 0, time.UTC)

	s.fleetCoverageChange(1, 1, t0)
	if _, _, _, send := s.fleetCoverageChange(1, 0, t0.Add(time.Second)); send {
		t.Fatal("sent on going dark")
	}
	if _, _, _, send := s.fleetCoverageChange(1, 1, t0.Add(5*time.Second)); send {
		t.Fatal("sent a recovery for a blip nobody was told about")
	}
	// The blip must also have reset the clock: going dark again starts
	// a fresh dwell rather than inheriting the earlier start.
	if _, _, _, send := s.fleetCoverageChange(1, 0, t0.Add(6*time.Second)); send {
		t.Fatal("sent on re-darkening")
	}
	if _, _, _, send := s.fleetCoverageChange(1, 0, t0.Add(6*time.Second+fleetDarkDwell-time.Second)); send {
		t.Fatal("dwell clock was not reset by the blip")
	}
	if _, _, _, send := s.fleetCoverageChange(1, 0, t0.Add(6*time.Second+fleetDarkDwell)); !send {
		t.Fatal("no send after a full dwell of real darkness")
	}
}

// An empty fleet - a fresh install nothing has ever dialed - never pages.
func TestFleetCoverageEmptyFleetIsSilent(t *testing.T) {
	s := &Service{}
	t0 := time.Date(2026, 8, 7, 12, 0, 0, 0, time.UTC)
	for i := 0; i < 100; i++ {
		if _, _, _, send := s.fleetCoverageChange(0, 0, t0.Add(time.Duration(i)*time.Minute)); send {
			t.Fatal("empty fleet paged someone")
		}
	}
}
