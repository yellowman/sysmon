package settings

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	bolt "go.etcd.io/bbolt"
)

var bucketAgents = []byte("agents")

// hashToken is what actually gets stored. SHA-256 is right here and
// bcrypt is not: this is a 256-bit random value, not a password, so there
// is no dictionary to slow an attacker down against - only length.
func hashToken(t string) string {
	sum := sha256.Sum256([]byte(t))
	return hex.EncodeToString(sum[:])
}

// AgentToken is one monitoring box's credential.
//
// One per box, revocable here, is the whole reason daemons dial out rather
// than being dialled: the alternative has this process holding a key to
// every box in the fleet, so compromising the UI compromises the lot.
type AgentToken struct {
	Site     string    `json:"site"`
	Token    string    `json:"-"` // never leaves this process after creation
	Label    string    `json:"label,omitempty"`
	Created  time.Time `json:"created"`
	LastSeen time.Time `json:"last_seen,omitempty"`
	LastAddr string    `json:"last_addr,omitempty"`
	Revoked  bool      `json:"revoked,omitempty"`
}

// GetAgentToken returns the record for a site, without the secret.
// Used to tell "this site has no token yet" from "this site has a live
// token that something in the field is using".
func (s *Store) GetAgentToken(site string) (AgentToken, bool) {
	var stored struct {
		AgentToken
		Hash string `json:"hash"`
	}
	found := false

	s.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketAgents)
		if b == nil {
			return nil
		}
		blob := b.Get([]byte(site))
		if blob == nil {
			return nil
		}
		if json.Unmarshal(blob, &stored) == nil {
			found = true
		}
		return nil
	})
	return stored.AgentToken, found
}

// NewAgentToken mints a credential for a site. The token is returned once
// and only once - it is stored hashed, so a leaked database does not leak
// the fleet's credentials, and "show me the token again" is deliberately
// impossible rather than merely discouraged.
func (s *Store) NewAgentToken(site, label string) (string, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	token := hex.EncodeToString(raw)

	rec := AgentToken{
		Site:    site,
		Label:   label,
		Created: time.Now().UTC(),
	}
	blob, err := json.Marshal(struct {
		AgentToken
		Hash string `json:"hash"`
	}{rec, hashToken(token)})
	if err != nil {
		return "", err
	}

	if err := s.db.Update(func(tx *bolt.Tx) error {
		b, err := tx.CreateBucketIfNotExists(bucketAgents)
		if err != nil {
			return err
		}
		return b.Put([]byte(site), blob)
	}); err != nil {
		return "", err
	}
	return token, nil
}

// CheckAgentToken reports whether a token may claim a site, and records
// the sighting when it may.
func (s *Store) CheckAgentToken(site, token, addr string) bool {
	var stored struct {
		AgentToken
		Hash string `json:"hash"`
	}

	ok := false
	_ = s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketAgents)
		if b == nil {
			return nil
		}
		blob := b.Get([]byte(site))
		if blob == nil {
			return nil
		}
		if err := json.Unmarshal(blob, &stored); err != nil {
			return nil
		}
		if stored.Revoked {
			return nil
		}
		// Constant time: a token check that leaks its answer through
		// timing is not a token check.
		if subtle.ConstantTimeCompare([]byte(stored.Hash), []byte(hashToken(token))) != 1 {
			return nil
		}

		ok = true
		stored.LastSeen = time.Now().UTC()
		stored.LastAddr = addr
		updated, err := json.Marshal(stored)
		if err != nil {
			return nil
		}
		return b.Put([]byte(site), updated)
	})
	return ok
}

// ListAgentTokens returns what is known about each box, without the
// credential itself.
func (s *Store) ListAgentTokens() ([]AgentToken, error) {
	var out []AgentToken
	err := s.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketAgents)
		if b == nil {
			return nil
		}
		return b.ForEach(func(k, v []byte) error {
			var rec struct {
				AgentToken
				Hash string `json:"hash"`
			}
			if err := json.Unmarshal(v, &rec); err != nil {
				return nil
			}
			out = append(out, rec.AgentToken)
			return nil
		})
	})
	return out, err
}

// RevokeAgentToken stops a box connecting, immediately for the next
// attempt and within one reconnect for a link already up.
func (s *Store) RevokeAgentToken(site string) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketAgents)
		if b == nil {
			return fmt.Errorf("no agents registered")
		}
		blob := b.Get([]byte(site))
		if blob == nil {
			return fmt.Errorf("site %s is not registered", site)
		}
		var rec map[string]interface{}
		if err := json.Unmarshal(blob, &rec); err != nil {
			return err
		}
		rec["revoked"] = true
		updated, err := json.Marshal(rec)
		if err != nil {
			return err
		}
		return b.Put([]byte(site), updated)
	})
}
