package monitoring

import (
	"path/filepath"
	"testing"
	"time"
)

// A site filter has to be applied inside the walk, before the limit is
// counted. Filtering a fleet-wide page afterwards returns however few of
// the newest N events happened to belong to that site - and presents
// that as the site's history.
func TestHistoryRecentFiltersBySiteBeforeLimiting(t *testing.T) {
	h, err := OpenHistory(filepath.Join(t.TempDir(), "h.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer h.Close()

	// 50 noisy events from one site, then 3 from the site we want. A
	// limit of 10 applied before filtering would find none of the 3.
	var events []HistoryEvent
	now := time.Now().UTC()
	for i := 0; i < 3; i++ {
		events = append(events, HistoryEvent{
			Timestamp: now.Add(time.Duration(i) * time.Second).Format(time.RFC3339),
			Site:      "bend", LocalName: "router1", ObjectName: "bend:router1",
			NewStatus: "CRITICAL",
		})
	}
	for i := 0; i < 50; i++ {
		events = append(events, HistoryEvent{
			Timestamp: now.Add(time.Duration(10+i) * time.Second).Format(time.RFC3339),
			Site:      "redmond", LocalName: "ap1", ObjectName: "redmond:ap1",
			NewStatus: "CRITICAL",
		})
	}
	if err := h.Append(events); err != nil {
		t.Fatal(err)
	}

	got, err := h.Recent(10, time.Hour, "bend")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 3 {
		t.Fatalf("want bend's 3 events despite 50 newer ones elsewhere, got %d", len(got))
	}
	for _, ev := range got {
		if ev.Site != "bend" {
			t.Fatalf("leaked another site's event: %+v", ev)
		}
	}

	// No site means the whole fleet, still capped by the limit.
	all, err := h.Recent(10, time.Hour, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(all) != 10 {
		t.Fatalf("fleet-wide should fill the limit, got %d", len(all))
	}
}
