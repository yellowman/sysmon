package monitoring

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"testing"
	"time"

	bolt "go.etcd.io/bbolt"
)

func TestHistoryExpiresAfter48Hours(t *testing.T) {
	h, err := OpenHistory(filepath.Join(t.TempDir(), "history.db"))
	if err != nil {
		t.Fatalf("OpenHistory: %v", err)
	}
	defer h.Close()

	// Plant a stale event directly (Append always stamps "now").
	old := HistoryEvent{
		Timestamp:  time.Now().UTC().Add(-72 * time.Hour).Format(time.RFC3339),
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
	if got := h.Recent(10); len(got) != 0 {
		t.Fatalf("expected stale event filtered from Recent, got %d events", len(got))
	}

	// A fresh append triggers prune, which must delete the stale row and
	// keep the new one.
	h.Append([]HistoryEvent{{
		ObjectName: "fresh-host",
		PrevStatus: "OK",
		NewStatus:  "WARNING",
	}})

	got := h.Recent(10)
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
