package monitoring

import (
	"encoding/json"
	"fmt"
	"sync"
	"time"

	bolt "go.etcd.io/bbolt"
)

var bucketHistoryEvents = []byte("events")

// historyMax bounds the event log; the oldest entries are pruned once it
// overflows. At a few transitions per host per day this is months of
// history.
const historyMax = 5000

// HistoryEvent is one observed host state transition - the raw material
// of "what has been going up and down".
type HistoryEvent struct {
	Timestamp   string `json:"timestamp"` // RFC3339
	ObjectName  string `json:"object_name"`
	Hostname    string `json:"hostname"`
	Description string `json:"description,omitempty"`
	PrevStatus  string `json:"prev_status"`
	NewStatus   string `json:"new_status"`
	// Seconds the host had spent in PrevStatus, when known. 0 means
	// unknown (first transition observed after a sysmon-web restart).
	PrevDuration int64 `json:"prev_duration_seconds,omitempty"`
}

// HistoryStore persists host transitions to bbolt so the record survives
// restarts. Fed by the monitoring poller's snapshot diff, so it works
// regardless of whether push notifications are enabled.
type HistoryStore struct {
	mu         sync.Mutex
	db         *bolt.DB
	lastChange map[string]time.Time // per object; in-memory, so durations reset on restart
	appends    int
}

func OpenHistory(path string) (*HistoryStore, error) {
	db, err := bolt.Open(path, 0600, &bolt.Options{Timeout: time.Second})
	if err != nil {
		return nil, fmt.Errorf("open history database: %w", err)
	}
	if err := db.Update(func(tx *bolt.Tx) error {
		_, err := tx.CreateBucketIfNotExists(bucketHistoryEvents)
		return err
	}); err != nil {
		db.Close()
		return nil, fmt.Errorf("init history database: %w", err)
	}
	return &HistoryStore{db: db, lastChange: make(map[string]time.Time)}, nil
}

func (h *HistoryStore) Close() error {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.db.Close()
}

// Append records a batch of transitions, filling in how long each host
// had been in its previous state where we know it.
func (h *HistoryStore) Append(events []HistoryEvent) {
	if len(events) == 0 {
		return
	}
	h.mu.Lock()
	defer h.mu.Unlock()

	now := time.Now().UTC()
	h.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketHistoryEvents)
		for i := range events {
			ev := &events[i]
			ev.Timestamp = now.Format(time.RFC3339)
			if last, ok := h.lastChange[ev.ObjectName]; ok {
				ev.PrevDuration = int64(now.Sub(last).Seconds())
			}
			h.lastChange[ev.ObjectName] = now
			data, err := json.Marshal(ev)
			if err != nil {
				continue
			}
			id, _ := b.NextSequence()
			if err := b.Put([]byte(fmt.Sprintf("%012d", id)), data); err != nil {
				return err
			}
		}
		return nil
	})

	// Prune occasionally rather than on every write.
	h.appends += len(events)
	if h.appends >= 200 {
		h.appends = 0
		h.prune()
	}
}

// prune drops the oldest entries beyond historyMax. Caller holds mu.
func (h *HistoryStore) prune() {
	h.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketHistoryEvents)
		excess := b.Stats().KeyN - historyMax
		if excess <= 0 {
			return nil
		}
		c := b.Cursor()
		for k, _ := c.First(); k != nil && excess > 0; k, _ = c.Next() {
			if err := b.Delete(k); err != nil {
				return err
			}
			excess--
		}
		return nil
	})
}

// Recent returns up to limit events, newest first.
func (h *HistoryStore) Recent(limit int) []HistoryEvent {
	h.mu.Lock()
	defer h.mu.Unlock()

	out := make([]HistoryEvent, 0, limit)
	h.db.View(func(tx *bolt.Tx) error {
		c := tx.Bucket(bucketHistoryEvents).Cursor()
		for k, v := c.Last(); k != nil && len(out) < limit; k, v = c.Prev() {
			var ev HistoryEvent
			if json.Unmarshal(v, &ev) == nil {
				out = append(out, ev)
			}
		}
		return nil
	})
	return out
}
