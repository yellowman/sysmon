package traps

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	bolt "go.etcd.io/bbolt"
)

var bucketTraps = []byte("traps")

// Trap history is kept far longer than host up/down history: an operator
// chasing an intermittent fault wants to ask "has this radio been sending
// linkDowns all month?", and the answer has to still be there. Traps only
// arrive from configured devices (see Service.handle), so the volume is
// bounded by the size of the network rather than by the internet.
const (
	MaxAge  = 31 * 24 * time.Hour
	MaxKeep = 20000 // backstop against a device stuck in a trap loop
)

// Record is one received trap as stored.
type Record struct {
	Source       string    `json:"source_ip"`
	When         time.Time `json:"timestamp"`
	Bytes        int       `json:"bytes"`
	Matched      string    `json:"matched_host,omitempty"` // object the source maps to
	AlertEnabled bool      `json:"trap_alert_enabled"`
	AlertSent    bool      `json:"alert_sent"`
	Content      Content   `json:"content"`
}

// Store persists traps to bbolt so they survive a restart. Keys are
// big-endian nanosecond timestamps plus a sequence byte, which keeps
// bbolt's natural key order the same as arrival order.
type Store struct {
	mu  sync.Mutex
	db  *bolt.DB
	seq uint16
}

func OpenStore(path string) (*Store, error) {
	db, err := bolt.Open(path, 0600, &bolt.Options{Timeout: time.Second})
	if err != nil {
		return nil, fmt.Errorf("open trap database: %w", err)
	}
	if err := db.Update(func(tx *bolt.Tx) error {
		_, err := tx.CreateBucketIfNotExists(bucketTraps)
		return err
	}); err != nil {
		db.Close()
		return nil, fmt.Errorf("init trap database: %w", err)
	}
	return &Store{db: db}, nil
}

func (s *Store) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.db.Close()
}

func (s *Store) key(t time.Time) []byte {
	k := make([]byte, 10)
	binary.BigEndian.PutUint64(k[0:8], uint64(t.UTC().UnixNano()))
	s.seq++
	binary.BigEndian.PutUint16(k[8:10], s.seq)
	return k
}

// Append stores one trap and prunes anything past the retention window.
func (s *Store) Append(r Record) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	blob, err := json.Marshal(r)
	if err != nil {
		return err
	}
	return s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketTraps)
		if b == nil {
			return fmt.Errorf("trap bucket missing")
		}
		if err := b.Put(s.key(r.When), blob); err != nil {
			return err
		}
		return pruneLocked(b, time.Now())
	})
}

// pruneLocked drops records older than MaxAge, then trims the oldest until
// the bucket is back under MaxKeep. Both walks go forward from the oldest
// key, which is the cheap direction in bbolt.
func pruneLocked(b *bolt.Bucket, now time.Time) error {
	cutoff := uint64(now.Add(-MaxAge).UTC().UnixNano())

	c := b.Cursor()
	var doomed [][]byte
	for k, _ := c.First(); k != nil; k, _ = c.Next() {
		if len(k) < 8 || binary.BigEndian.Uint64(k[0:8]) >= cutoff {
			break // keys are time-ordered, so the rest are newer
		}
		doomed = append(doomed, append([]byte(nil), k...))
	}

	if excess := b.Stats().KeyN - len(doomed) - MaxKeep; excess > 0 {
		k, _ := c.First()
		for i := 0; i < len(doomed); i++ {
			k, _ = c.Next() // skip what we are already deleting
		}
		for ; excess > 0 && k != nil; excess-- {
			doomed = append(doomed, append([]byte(nil), k...))
			k, _ = c.Next()
		}
	}

	for _, k := range doomed {
		if err := b.Delete(k); err != nil {
			return err
		}
	}
	return nil
}

// Recent returns up to limit traps, newest first. limit <= 0 means all of
// them (bounded by MaxKeep).
func (s *Store) Recent(limit int) []Record {
	s.mu.Lock()
	defer s.mu.Unlock()

	if limit <= 0 || limit > MaxKeep {
		limit = MaxKeep
	}
	out := make([]Record, 0, 64)
	cutoff := time.Now().Add(-MaxAge)

	_ = s.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketTraps)
		if b == nil {
			return nil
		}
		c := b.Cursor()
		for k, v := c.Last(); k != nil && len(out) < limit; k, v = c.Prev() {
			var r Record
			if err := json.Unmarshal(v, &r); err != nil {
				continue // a record we cannot read is not worth failing over
			}
			// Expired records may still be on disk between prunes; never
			// show something older than the window we advertise.
			if r.When.Before(cutoff) {
				break
			}
			out = append(out, r)
		}
		return nil
	})
	return out
}

// Count reports how many traps are held.
func (s *Store) Count() int {
	s.mu.Lock()
	defer s.mu.Unlock()

	n := 0
	_ = s.db.View(func(tx *bolt.Tx) error {
		if b := tx.Bucket(bucketTraps); b != nil {
			n = b.Stats().KeyN
		}
		return nil
	})
	return n
}
