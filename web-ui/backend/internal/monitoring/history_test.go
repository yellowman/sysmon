package monitoring

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"testing"
	"time"

	bolt "go.etcd.io/bbolt"
)

func TestHistoryWindowAndRetention(t *testing.T) {
	h, err := OpenHistory(filepath.Join(t.TempDir(), "history.db"))
	if err != nil {
		t.Fatalf("OpenHistory: %v", err)
	}
	defer h.Close()

	// Plant an event older than the 30-day retention directly (Append
	// always stamps "now").
	old := HistoryEvent{
		Timestamp:  time.Now().UTC().Add(-31 * 24 * time.Hour).Format(time.RFC3339),
		ObjectName: "ancient-host",
		PrevStatus: "OK",
		NewStatus:  "CRITICAL",
	}
	data, _ := json.Marshal(old)
	h.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketHistoryEvents)
		id, _ := b.NextSequence()
		return b.Put([]byte(fmt.Sprintf("%012d", id)), data)
	})

	// Recent must not serve it even before any prune runs.
	if got, _ := h.Recent(10, 0); len(got) != 0 {
		t.Fatalf("expected stale event filtered from Recent, got %d events", len(got))
	}

	// A fresh append triggers prune, which must delete the stale row and
	// keep the new one.
	h.Append([]HistoryEvent{{
		ObjectName: "fresh-host",
		PrevStatus: "OK",
		NewStatus:  "WARNING",
	}})

	got, _ := h.Recent(10, 0)
	if len(got) != 1 || got[0].ObjectName != "fresh-host" {
		t.Fatalf("expected only the fresh event, got %+v", got)
	}
	var keys int
	h.db.View(func(tx *bolt.Tx) error {
		keys = tx.Bucket(bucketHistoryEvents).Stats().KeyN
		return nil
	})
	if keys != 1 {
		t.Fatalf("expected stale row pruned from disk, bucket has %d keys", keys)
	}
}

// The 30-day window serves what the 48-hour default cuts off.
func TestRecentWindow(t *testing.T) {
	h, err := OpenHistory(filepath.Join(t.TempDir(), "history.db"))
	if err != nil {
		t.Fatalf("OpenHistory: %v", err)
	}
	defer h.Close()

	old := HistoryEvent{ObjectName: "gw", Hostname: "gw", PrevStatus: "OK", NewStatus: "CRITICAL"}
	h.Append([]HistoryEvent{old})
	// Backdate it past the default window but inside retention.
	h.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketHistoryEvents)
		c := b.Cursor()
		k, v := c.First()
		var ev HistoryEvent
		json.Unmarshal(v, &ev)
		ev.Timestamp = time.Now().UTC().Add(-72 * time.Hour).Format(time.RFC3339)
		nv, _ := json.Marshal(ev)
		return b.Put(k, nv)
	})

	if got, _ := h.Recent(10, 0); len(got) != 0 {
		t.Fatalf("default window served a 72h-old event: %d rows", len(got))
	}
	if got, _ := h.Recent(10, 30*24*time.Hour); len(got) != 1 {
		t.Fatalf("30d window missed the 72h-old event: %d rows", len(got))
	}
}

// Rows written before Site/LocalName existed carry only the qualified
// "site:object" key; Recent must split it on the way out so old and new
// rows serve the same shape. New rows keep what Append stored.
func TestRecentBackfillsSiteAndLocalName(t *testing.T) {
	h, err := OpenHistory(filepath.Join(t.TempDir(), "history.db"))
	if err != nil {
		t.Fatalf("OpenHistory: %v", err)
	}
	defer h.Close()

	// A pre-split row, planted directly the way an old release wrote it.
	old := HistoryEvent{
		Timestamp:  time.Now().UTC().Format(time.RFC3339),
		ObjectName: "branch2:coreswitch",
		PrevStatus: "OK",
		NewStatus:  "CRITICAL",
	}
	data, _ := json.Marshal(old)
	h.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketHistoryEvents)
		id, _ := b.NextSequence()
		return b.Put([]byte(fmt.Sprintf("%012d", id)), data)
	})
	// A pre-split local row: no colon, so there is no site to find.
	h.Append([]HistoryEvent{{
		ObjectName: "mailhost",
		PrevStatus: "OK",
		NewStatus:  "WARNING",
	}})
	// A current row, with the halves carried explicitly.
	h.Append([]HistoryEvent{{
		ObjectName: "branch3:fw",
		Site:       "branch3",
		LocalName:  "fw",
		PrevStatus: "WARNING",
		NewStatus:  "OK",
	}})

	got, _ := h.Recent(10, 0)
	if len(got) != 3 {
		t.Fatalf("Recent returned %d events, want 3: %+v", len(got), got)
	}
	// Newest first.
	if got[0].Site != "branch3" || got[0].LocalName != "fw" {
		t.Errorf("current row = site %q local %q, want branch3/fw", got[0].Site, got[0].LocalName)
	}
	if got[1].Site != "" || got[1].LocalName != "mailhost" {
		t.Errorf("old local row = site %q local %q, want \"\"/mailhost", got[1].Site, got[1].LocalName)
	}
	if got[2].Site != "branch2" || got[2].LocalName != "coreswitch" {
		t.Errorf("old fleet row = site %q local %q, want branch2/coreswitch", got[2].Site, got[2].LocalName)
	}
}
