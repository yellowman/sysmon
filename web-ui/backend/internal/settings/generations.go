package settings

import (
	"encoding/json"
	"fmt"
	"sort"
	"time"

	bolt "go.etcd.io/bbolt"
)

// Config generations: what each site is *supposed* to be running.
//
// The daemon holds actual state and answers CONFIG-GEN with it. This holds
// desired state - a numbered, immutable snapshot of every config file,
// with the same content hash the daemon computes - so the two can be
// compared without transferring anything.
//
// Generations are kept, not overwritten. Rollback needs the previous one,
// a diff needs both, and "who changed this box and when" is a question
// that gets asked at 3am.

var (
	bucketGenDesired = []byte("gen_desired") // site -> Desired
	bucketGenFiles   = []byte("gen_files")   // site\x00gen -> []GenFile
)

// GenFile is one config file of a generation, with the path it lives at on
// the target box. The path is part of the hash, so it is part of the
// identity of the generation - not a delivery detail.
type GenFile struct {
	Path    string `json:"path"`
	Content []byte `json:"content"`
}

// Desired is what a site should be running.
//
// Adopted is the state that decides whether anything is ever delivered.
// A box that has not been adopted is shown read-only and is never written
// to, so no amount of misclicking can blank a daemon whose config this
// process has never seen.
type Desired struct {
	Site       string    `json:"site"`
	Generation uint64    `json:"generation"`
	Hash       string    `json:"hash"`
	Adopted    bool      `json:"adopted"`
	Created    time.Time `json:"created"`
	CreatedBy  string    `json:"created_by,omitempty"`
	Note       string    `json:"note,omitempty"`

	// HighWater is the highest generation number ever issued for this
	// site. Generation is what should be running and can move backwards -
	// a rollback points it at an older one - but the number handed to a
	// new generation must never be re-used, or "the box is running
	// generation 9" stops naming one set of bytes.
	HighWater uint64 `json:"high_water,omitempty"`

	// Poisoned generations are ones a canary rejected. They are recorded
	// rather than deleted: the remaining waves must not go out, and the
	// operator has to be able to see what was refused and why.
	Poisoned map[uint64]string `json:"poisoned,omitempty"`
}

func genKey(site string, gen uint64) []byte {
	return []byte(fmt.Sprintf("%s\x00%020d", site, gen))
}

// PutGeneration records a new desired generation and its files.
//
// The generation number always moves forward, including past a poisoned
// one: re-using a number would make "the box is running generation 9"
// ambiguous, and the box's own state file is keyed on nothing but that
// number.
func (s *Store) PutGeneration(site string, files []GenFile, hash, by, note string) (uint64, error) {
	var gen uint64

	err := s.db.Update(func(tx *bolt.Tx) error {
		db, err := tx.CreateBucketIfNotExists(bucketGenDesired)
		if err != nil {
			return err
		}
		fb, err := tx.CreateBucketIfNotExists(bucketGenFiles)
		if err != nil {
			return err
		}

		cur := Desired{Site: site}
		if blob := db.Get([]byte(site)); blob != nil {
			if e := json.Unmarshal(blob, &cur); e != nil {
				return e
			}
		}

		gen = cur.HighWater
		if cur.Generation > gen {
			gen = cur.Generation
		}
		gen++

		next := Desired{
			Site:       site,
			Generation: gen,
			Hash:       hash,
			Adopted:    true,
			Created:    time.Now().UTC(),
			CreatedBy:  by,
			Note:       note,
			Poisoned:   cur.Poisoned,
			HighWater:  gen,
		}

		blob, err := json.Marshal(next)
		if err != nil {
			return err
		}
		if err := db.Put([]byte(site), blob); err != nil {
			return err
		}

		fblob, err := json.Marshal(files)
		if err != nil {
			return err
		}
		return fb.Put(genKey(site, gen), fblob)
	})
	return gen, err
}

// GetDesired returns what a site should be running. ok is false for a site
// nobody has adopted, which is a real state and not a missing value.
func (s *Store) GetDesired(site string) (Desired, bool) {
	var d Desired
	found := false

	s.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketGenDesired)
		if b == nil {
			return nil
		}
		blob := b.Get([]byte(site))
		if blob == nil {
			return nil
		}
		if json.Unmarshal(blob, &d) == nil {
			found = true
		}
		return nil
	})
	return d, found
}

// GetGenerationFiles returns the files of one generation.
func (s *Store) GetGenerationFiles(site string, gen uint64) ([]GenFile, bool) {
	var files []GenFile
	found := false

	s.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketGenFiles)
		if b == nil {
			return nil
		}
		blob := b.Get(genKey(site, gen))
		if blob == nil {
			return nil
		}
		if json.Unmarshal(blob, &files) == nil {
			found = true
		}
		return nil
	})
	return files, found
}

// ListGenerations returns the generation numbers held for a site, newest
// first.
func (s *Store) ListGenerations(site string) []uint64 {
	var out []uint64

	s.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketGenFiles)
		if b == nil {
			return nil
		}
		c := b.Cursor()
		prefix := []byte(site + "\x00")
		for k, _ := c.Seek(prefix); k != nil && len(k) > len(prefix) &&
			string(k[:len(prefix)]) == string(prefix); k, _ = c.Next() {
			var gen uint64
			fmt.Sscanf(string(k[len(prefix):]), "%020d", &gen)
			out = append(out, gen)
		}
		return nil
	})
	sort.Slice(out, func(i, j int) bool { return out[i] > out[j] })
	return out
}

// SetDesiredGeneration points a site at a generation it already holds.
// This is how a rollback becomes the desired state rather than a thing
// the box did on its own and will be "corrected" out of on the next poll.
func (s *Store) SetDesiredGeneration(site string, gen uint64, hash string) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		b, err := tx.CreateBucketIfNotExists(bucketGenDesired)
		if err != nil {
			return err
		}
		var d Desired
		if blob := b.Get([]byte(site)); blob != nil {
			if e := json.Unmarshal(blob, &d); e != nil {
				return e
			}
		}
		d.Site = site
		d.Generation = gen
		d.Hash = hash
		d.Adopted = true
		if gen > d.HighWater {
			d.HighWater = gen
		}
		blob, err := json.Marshal(d)
		if err != nil {
			return err
		}
		return b.Put([]byte(site), blob)
	})
}

// PoisonGeneration marks a generation as one that must not go out again.
func (s *Store) PoisonGeneration(site string, gen uint64, why string) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		b, err := tx.CreateBucketIfNotExists(bucketGenDesired)
		if err != nil {
			return err
		}
		var d Desired
		if blob := b.Get([]byte(site)); blob != nil {
			if e := json.Unmarshal(blob, &d); e != nil {
				return e
			}
		}
		d.Site = site
		if d.Poisoned == nil {
			d.Poisoned = map[uint64]string{}
		}
		d.Poisoned[gen] = why
		blob, err := json.Marshal(d)
		if err != nil {
			return err
		}
		return b.Put([]byte(site), blob)
	})
}

// Sites lists every site with a recorded desired state.
func (s *Store) GenerationSites() []string {
	var out []string

	s.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketGenDesired)
		if b == nil {
			return nil
		}
		return b.ForEach(func(k, _ []byte) error {
			out = append(out, string(k))
			return nil
		})
	})
	sort.Strings(out)
	return out
}
