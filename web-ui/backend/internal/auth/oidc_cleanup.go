package auth

import (
	"context"
	"encoding/json"
	"log"
	"sync"
	"time"

	bolt "go.etcd.io/bbolt"
)

type oidcSessionLock struct {
	mu    sync.Mutex
	users int
}

func (s *Service) lockOIDCSession(token string) func() {
	s.refreshLocksMu.Lock()
	if s.refreshLocks == nil {
		s.refreshLocks = make(map[string]*oidcSessionLock)
	}
	lock := s.refreshLocks[token]
	if lock == nil {
		lock = &oidcSessionLock{}
		s.refreshLocks[token] = lock
	}
	lock.users++
	s.refreshLocksMu.Unlock()
	lock.mu.Lock()
	return func() {
		lock.mu.Unlock()
		s.refreshLocksMu.Lock()
		lock.users--
		if lock.users == 0 {
			delete(s.refreshLocks, token)
		}
		s.refreshLocksMu.Unlock()
	}
}

func (s *Service) revokeGrant(ctx context.Context, grant *OIDCIdentity) {
	client := s.oidc
	// A changed provider or client needs its original credentials to revoke.
	// Never send an old provider's token to the replacement provider.
	if client == nil || grant == nil || grant.RefreshToken == "" || grant.Issuer != client.issuer || grant.ClientID != client.clientID {
		return
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if err := client.Revoke(ctx, grant.RefreshToken); err != nil {
		log.Printf("OIDC grant revocation failed: %v", err)
	}
}

// StartSessionCleanup runs after OIDC initialization. Close cancels and
// joins the worker before closing the database.
func (s *Service) StartSessionCleanup() {
	s.cleanupMu.Lock()
	defer s.cleanupMu.Unlock()
	if s.cleanupCancel != nil {
		return
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	s.cleanupCancel, s.cleanupDone = cancel, done
	go func() {
		defer close(done)
		ticker := time.NewTicker(time.Minute)
		defer ticker.Stop()
		for {
			if err := s.SweepExpiredSessions(ctx); err != nil && ctx.Err() == nil {
				log.Printf("auth: session cleanup failed: %v", err)
			}
			s.sweepExpiredMobileHandoffs(ctx)
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
			}
		}
	}()
}

func sessionExpired(session Session, now time.Time) bool {
	if session.ExpiresAt == "" && session.OIDCGrant == nil {
		return false
	}
	expires, err := time.Parse(time.RFC3339, session.ExpiresAt)
	return err != nil || !now.Before(expires)
}

// SweepExpiredSessions rechecks each candidate under its refresh lock;
// local sliding sessions can have been extended since the initial scan.
func (s *Service) SweepExpiredSessions(ctx context.Context) error {
	var tokens []string
	if err := s.db.View(func(tx *bolt.Tx) error {
		now := time.Now()
		return tx.Bucket(bucketSessions).ForEach(func(k, v []byte) error {
			var session Session
			if json.Unmarshal(v, &session) != nil || sessionExpired(session, now) {
				tokens = append(tokens, string(k))
			}
			return nil
		})
	}); err != nil {
		return err
	}
	for _, token := range tokens {
		if err := ctx.Err(); err != nil {
			return err
		}
		unlock := s.lockOIDCSession(token)
		var grant *OIDCIdentity
		err := s.db.Update(func(tx *bolt.Tx) error {
			b := tx.Bucket(bucketSessions)
			raw := b.Get([]byte(token))
			if raw == nil {
				return nil
			}
			var session Session
			if json.Unmarshal(raw, &session) == nil {
				if !sessionExpired(session, time.Now()) {
					return nil
				}
				grant = session.OIDCGrant
			}
			return b.Delete([]byte(token))
		})
		unlock()
		if err != nil {
			return err
		}
		s.revokeGrant(ctx, grant)
	}
	return nil
}

func (s *Service) sweepExpiredMobileHandoffs(ctx context.Context) {
	var grants []OIDCIdentity
	err := s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketMobileHandoffs)
		var keys [][]byte
		now := time.Now()
		if err := b.ForEach(func(k, v []byte) error {
			var entry mobileHandoff
			if json.Unmarshal(v, &entry) != nil || !now.Before(entry.ExpiresAt) {
				keys = append(keys, append([]byte(nil), k...))
				grants = append(grants, entry.Identity)
			}
			return nil
		}); err != nil {
			return err
		}
		for _, key := range keys {
			if err := b.Delete(key); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		log.Printf("auth: mobile handoff cleanup failed: %v", err)
		return
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	for i := range grants {
		s.revokeGrant(ctx, &grants[i])
	}
}
