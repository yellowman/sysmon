package settings

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
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

// What a token's peer is. Recorded at mint time (MintAgentToken) - the
// admin chooses whether a credential belongs to a monitoring box or an
// alert-only peer, and the greeting verb must match. Only records
// minted before kinds existed are empty, and those take the kind of
// their first successful greeting (ClaimAgentKind).
const (
	KindSysmond = "sysmond"
	KindAlerter = "alerter"
)

// AgentToken is one monitoring box's credential.
//
// One per box, revocable here, is the whole reason daemons dial out rather
// than being dialled: the alternative has this process holding a key to
// every box in the fleet, so compromising the UI compromises the lot.
type AgentToken struct {
	Site  string `json:"site"`
	Token string `json:"-"` // never leaves this process after creation
	Label string `json:"label,omitempty"`
	Kind  string `json:"kind,omitempty"` // KindSysmond/KindAlerter; "" only on pre-kind records
	// CredentialID is this mint's epoch: a random value regenerated
	// every time the site's token is minted. A connection remembers the
	// ID it authenticated under and re-checks it after registering, so
	// a revoke or re-mint that lands mid-handshake still catches the
	// connection - whichever side finishes second sees the other.
	// Empty on records minted before the field existed.
	CredentialID string    `json:"credential_id,omitempty"`
	Created      time.Time `json:"created"`
	LastSeen     time.Time `json:"last_seen,omitempty"`
	LastAddr     string    `json:"last_addr,omitempty"`
	Revoked      bool      `json:"revoked,omitempty"`
}

// ErrTokenExists is MintAgentToken's refusal to silently invalidate a
// live credential: the site already has one and replace was not asked.
var ErrTokenExists = errors.New("site already has a live token")

// SetAgentLabel renames a token's human label - for alerters this is
// the nickname alerts display. Missing records are left missing; a
// storage failure is the caller's to report, not to swallow - the UI
// must never confirm a rename the disk refused.
func (s *Store) SetAgentLabel(site, label string) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketAgents)
		if b == nil {
			return nil
		}
		blob := b.Get([]byte(site))
		if blob == nil {
			return nil
		}
		var stored map[string]json.RawMessage
		if err := json.Unmarshal(blob, &stored); err != nil {
			return fmt.Errorf("agent record %s is unreadable: %w", site, err)
		}
		enc, err := json.Marshal(label)
		if err != nil {
			return err
		}
		if label == "" {
			delete(stored, "label")
		} else {
			stored["label"] = enc
		}
		updated, err := json.Marshal(stored)
		if err != nil {
			return err
		}
		return b.Put([]byte(site), updated)
	})
}

// SetAgentKind overwrites a record's kind. Minting sets the kind
// atomically (NewAgentToken) and the handshake claims it for legacy
// records (ClaimAgentKind); this raw setter exists for migrations and
// tests - simulating a pre-kind record takes writing an empty kind.
// Missing records are left missing.
func (s *Store) SetAgentKind(site, kind string) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketAgents)
		if b == nil {
			return nil
		}
		blob := b.Get([]byte(site))
		if blob == nil {
			return nil
		}
		var stored map[string]json.RawMessage
		if err := json.Unmarshal(blob, &stored); err != nil {
			return fmt.Errorf("agent record %s is unreadable: %w", site, err)
		}
		enc, err := json.Marshal(kind)
		if err != nil {
			return err
		}
		stored["kind"] = enc
		updated, err := json.Marshal(stored)
		if err != nil {
			return err
		}
		return b.Put([]byte(site), updated)
	})
}

// ClaimAgentKind records what a token's peer identified as, first
// claim wins forever: read, check and write happen inside one bolt
// transaction, so two concurrent first handshakes with the same fresh
// token cannot both succeed as different kinds. Returns ("", nil) when
// the claim stands (recorded now, already recorded, or no record to
// claim against - the handshake already authenticated, so a missing
// record only races a concurrent revoke), the owning kind when the
// token already belongs to the other class, and a non-nil error when
// storage failed - in which case the claim did NOT stick and the
// caller must fail closed rather than admit an unbound peer.
func (s *Store) ClaimAgentKind(site, kind string) (string, error) {
	owner := ""
	err := s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketAgents)
		if b == nil {
			return nil
		}
		blob := b.Get([]byte(site))
		if blob == nil {
			return nil
		}
		var stored map[string]json.RawMessage
		if err := json.Unmarshal(blob, &stored); err != nil {
			return fmt.Errorf("agent record %s is unreadable: %w", site, err)
		}
		existing := ""
		if raw, ok := stored["kind"]; ok {
			_ = json.Unmarshal(raw, &existing)
		}
		if existing == kind {
			return nil // steady state: no write, no refusal
		}
		if existing != "" {
			owner = existing
			return nil
		}
		enc, err := json.Marshal(kind)
		if err != nil {
			return err
		}
		stored["kind"] = enc
		updated, err := json.Marshal(stored)
		if err != nil {
			return err
		}
		return b.Put([]byte(site), updated)
	})
	if err != nil {
		return "", err
	}
	return owner, nil
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

// MintAgentToken mints a credential for a site. The token is returned
// once and only once - it is stored hashed, so a leaked database does
// not leak the fleet's credentials, and "show me the token again" is
// deliberately impossible rather than merely discouraged.
//
// The whole mint is one transaction: the does-a-live-token-exist check
// and the write of hash, label, kind and credential epoch commit
// together, so two racing first mints cannot both hand out a token
// (exactly one wins; the other gets ErrTokenExists), and the caller
// never holds a plaintext token whose stored type failed to stick.
func (s *Store) MintAgentToken(site, label, kind string, replace bool) (string, error) {
	switch kind {
	case KindSysmond, KindAlerter:
	default:
		return "", fmt.Errorf("kind must be %q or %q", KindSysmond, KindAlerter)
	}

	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	token := hex.EncodeToString(raw)
	epoch := make([]byte, 8)
	if _, err := rand.Read(epoch); err != nil {
		return "", err
	}

	rec := AgentToken{
		Site:         site,
		Label:        label,
		Kind:         kind,
		CredentialID: hex.EncodeToString(epoch),
		Created:      time.Now().UTC(),
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
		if existing := b.Get([]byte(site)); existing != nil && !replace {
			var old AgentToken
			// An unreadable record blocks a silent overwrite too: the
			// caller asked to create, not to destroy whatever this is.
			if json.Unmarshal(existing, &old) != nil || !old.Revoked {
				return ErrTokenExists
			}
		}
		return b.Put([]byte(site), blob)
	}); err != nil {
		return "", err
	}
	return token, nil
}

// CheckAgentToken reports whether a token may claim a site, and records
// the sighting when it may. On success it also returns the credential
// epoch the token authenticated under, which the connection re-checks
// after registering (see AgentToken.CredentialID). A storage failure
// fails closed: an authenticator that cannot read or update its own
// store must refuse, not guess.
func (s *Store) CheckAgentToken(site, token, addr string) (bool, string, error) {
	var stored struct {
		AgentToken
		Hash string `json:"hash"`
	}

	ok := false
	err := s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketAgents)
		if b == nil {
			return nil
		}
		blob := b.Get([]byte(site))
		if blob == nil {
			return nil
		}
		if err := json.Unmarshal(blob, &stored); err != nil {
			return fmt.Errorf("agent record %s is unreadable: %w", site, err)
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
			return err
		}
		return b.Put([]byte(site), updated)
	})
	if err != nil {
		return false, "", err
	}
	if !ok {
		return false, "", nil
	}
	return true, stored.CredentialID, nil
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
