// Package settings stores web-only configuration in bbolt — the same
// storage class as auth.db and push.db. These are settings for sysmon-web
// (the Go process), not for sysmond (the C daemon), so they have no
// business in sysmon.conf. Credentials (the FCM service-account JSON, the
// APNs cert/key) are uploaded through the admin UI and held here as blobs,
// so operators never have to coordinate file paths or chmod secrets into
// place.
package settings

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	bolt "go.etcd.io/bbolt"
)

var bucketPush = []byte("push")

// Keys within the push bucket.
const (
	kEnabled        = "enabled"
	kFCMCredentials = "fcm_credentials" // service-account JSON (secret)
	kAPNsCert       = "apns_cert"       // PEM (secret)
	kAPNsKey        = "apns_key"        // PEM (secret)
	kAPNsBundleID   = "apns_bundle_id"
	kAPNsProduction = "apns_production"
)

// PushConfig is the runtime view, including the secret blobs. Empty
// []byte / "" means "not configured".
type PushConfig struct {
	Enabled        bool
	FCMCredentials []byte
	APNsCertPEM    []byte
	APNsKeyPEM     []byte
	APNsBundleID   string
	APNsProduction bool
}

type Store struct {
	db *bolt.DB
}

// NewStore opens (creating if needed) a bbolt database at path. The file
// is forced to 0600 since it holds push credentials.
func NewStore(path string) (*Store, error) {
	if dir := filepath.Dir(path); dir != "." && dir != "" {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return nil, err
		}
	}
	db, err := bolt.Open(path, 0o600, &bolt.Options{Timeout: 1 * time.Second})
	if err != nil {
		return nil, fmt.Errorf("settings: open %q: %w", path, err)
	}
	if err := db.Update(func(tx *bolt.Tx) error {
		_, e := tx.CreateBucketIfNotExists(bucketPush)
		return e
	}); err != nil {
		db.Close()
		return nil, err
	}
	// Belt-and-suspenders: bbolt's Open mode is masked by umask, so
	// re-assert 0600 on the existing file.
	_ = os.Chmod(path, 0o600)
	return &Store{db: db}, nil
}

func (s *Store) Close() error { return s.db.Close() }

// GetPush returns the full push configuration including secret blobs.
func (s *Store) GetPush() (PushConfig, error) {
	var c PushConfig
	err := s.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketPush)
		if b == nil {
			return nil
		}
		c.Enabled = string(b.Get([]byte(kEnabled))) == "1"
		c.FCMCredentials = cloneBytes(b.Get([]byte(kFCMCredentials)))
		c.APNsCertPEM = cloneBytes(b.Get([]byte(kAPNsCert)))
		c.APNsKeyPEM = cloneBytes(b.Get([]byte(kAPNsKey)))
		c.APNsBundleID = string(b.Get([]byte(kAPNsBundleID)))
		c.APNsProduction = string(b.Get([]byte(kAPNsProduction))) == "1"
		return nil
	})
	return c, err
}

func (s *Store) SetPushEnabled(enabled bool) error {
	return s.put(kEnabled, boolBytes(enabled))
}

// SetFCMCredentials stores the service-account JSON. Validation is the
// caller's job (see push.FCMCredentialMeta) — this just persists bytes.
func (s *Store) SetFCMCredentials(jsonBytes []byte) error {
	return s.put(kFCMCredentials, jsonBytes)
}

func (s *Store) ClearFCMCredentials() error { return s.del(kFCMCredentials) }

func (s *Store) SetAPNs(certPEM, keyPEM []byte, bundleID string, production bool) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketPush)
		if err := b.Put([]byte(kAPNsCert), certPEM); err != nil {
			return err
		}
		if err := b.Put([]byte(kAPNsKey), keyPEM); err != nil {
			return err
		}
		if err := b.Put([]byte(kAPNsBundleID), []byte(bundleID)); err != nil {
			return err
		}
		return b.Put([]byte(kAPNsProduction), boolBytes(production))
	})
}

func (s *Store) ClearAPNs() error {
	return s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketPush)
		for _, k := range []string{kAPNsCert, kAPNsKey, kAPNsBundleID, kAPNsProduction} {
			if err := b.Delete([]byte(k)); err != nil {
				return err
			}
		}
		return nil
	})
}

func (s *Store) put(key string, val []byte) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket(bucketPush).Put([]byte(key), val)
	})
}

func (s *Store) del(key string) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket(bucketPush).Delete([]byte(key))
	})
}

func boolBytes(b bool) []byte {
	if b {
		return []byte("1")
	}
	return []byte("0")
}

// cloneBytes copies a bolt-owned slice, which is only valid for the life
// of the transaction.
func cloneBytes(b []byte) []byte {
	if b == nil {
		return nil
	}
	out := make([]byte, len(b))
	copy(out, b)
	return out
}
