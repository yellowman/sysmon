package monitoring

import (
	"encoding/json"
	"fmt"
	"sync"
	"time"

	bolt "go.etcd.io/bbolt"
)

var bucketHistoryEvents = []byte("events")

// History is kept for historyRetention and served over a caller-chosen
// window no larger than that; the default window stays 48 hours.
// historyMax is a safety backstop against event storms (flapping hosts)
// within that window.
const (
	historyRetention     = 30 * 24 * time.Hour
	HistoryDefaultWindow = 48 * time.Hour
	historyMax           = 20000
)

// HistoryEvent is one observed host state transition - the raw material
// of "what has been going up and down" over the last 48 hours.
type HistoryEvent struct {
	Timestamp  string `json:"timestamp"` // RFC3339
	ObjectName string `json:"object_name"`
	// Site and LocalName are ObjectName's two halves, carried separately
	// so no display ever has to render the "site:object" key itself -
	// the UIs show the bare name with the site as its own minimized
	// element. ObjectName stays the identity everywhere.
	Site        string `json:"site,omitempty"`
	LocalName   string `json:"local_name,omitempty"`
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

	// Transitions are rare, so pruning on every append is cheap.
	h.prune(now)
}

// PruneNow ages the store on a clock. Append prunes too, but a system
// with no new transitions - a dead daemon being the obvious case -
// would otherwise never prune at all, and the page would show the same
// rows forever.
func (h *HistoryStore) PruneNow() {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.prune(time.Now().UTC())
}

// prune drops entries older than historyRetention, plus the oldest entries
// beyond the historyMax backstop. Keys are chronological, so both walks
// stop at the first survivor. Caller holds mu.
func (h *HistoryStore) prune(now time.Time) {
	cutoff := now.Add(-historyRetention)
	h.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketHistoryEvents)
		c := b.Cursor()
		excess := b.Stats().KeyN - historyMax
		for k, v := c.First(); k != nil; k, v = c.Next() {
			expired := false
			var ev HistoryEvent
			if json.Unmarshal(v, &ev) == nil {
				if t, err := time.Parse(time.RFC3339, ev.Timestamp); err == nil {
					expired = t.Before(cutoff)
				}
			} else {
				expired = true // unparseable rows are dead weight
			}
			if !expired && excess <= 0 {
				break
			}
			if err := b.Delete(k); err != nil {
				return err
			}
			excess--
		}
		return nil
	})
}

// Recent returns up to limit events from the last window, newest
// first. The age check happens here too, not just in prune, so a quiet
// system never serves stale events between prunes. A window outside
// (0, retention] is clamped to the default.
func (h *HistoryStore) Recent(limit int, window time.Duration) []HistoryEvent {
	h.mu.Lock()
	defer h.mu.Unlock()

	if window <= 0 || window > historyRetention {
		window = HistoryDefaultWindow
	}
	cutoff := time.Now().UTC().Add(-window)
	out := make([]HistoryEvent, 0, limit)
	h.db.View(func(tx *bolt.Tx) error {
		c := tx.Bucket(bucketHistoryEvents).Cursor()
		for k, v := c.Last(); k != nil && len(out) < limit; k, v = c.Prev() {
			var ev HistoryEvent
			if json.Unmarshal(v, &ev) != nil {
				continue
			}
			// Rows written before Site/LocalName existed carry only the
			// qualified key; split it on the way out so every consumer
			// sees the same shape regardless of the row's age.
			if ev.LocalName == "" {
				ev.Site, ev.LocalName = SplitQualified(ev.ObjectName)
			}
			t, err := time.Parse(time.RFC3339, ev.Timestamp)
			if err != nil {
				// A row whose timestamp cannot be read has no age, so it
				// can never be cut by one. Skipping beats serving it as
				// if it were current, which is how frozen entries end up
				// on the page.
				continue
			}
			if t.Before(cutoff) {
				break // keys are chronological: everything further back is older
			}
			out = append(out, ev)
		}
		return nil
	})
	return out
}
