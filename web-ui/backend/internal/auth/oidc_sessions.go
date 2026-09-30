package auth

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"time"

	bolt "go.etcd.io/bbolt"
	"golang.org/x/oauth2"
)

var bucketOIDCFlows = []byte("oidc_flows")
var bucketMobileHandoffs = []byte("oidc_mobile")

type OIDCFlow struct {
	State, Nonce, Verifier, MobileChallenge string
	ExpiresAt                               time.Time
}

type mobileHandoff struct {
	Identity  OIDCIdentity
	Challenge string
	ExpiresAt time.Time
}

func (s *Service) SetOIDCClient(client *OIDCClient) { s.oidc = client }
func (s *Service) OIDC() *OIDCClient                { return s.oidc }

func randomOIDCToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func validMobileChallenge(raw string) bool {
	decoded, err := base64.RawURLEncoding.DecodeString(raw)
	return err == nil && len(decoded) == 32 && base64.RawURLEncoding.EncodeToString(decoded) == raw
}

func (s *Service) StartOIDCFlow(challenge string) (string, OIDCFlow, error) {
	if challenge != "" && !validMobileChallenge(challenge) {
		return "", OIDCFlow{}, errors.New("invalid mobile challenge")
	}
	id, err := randomOIDCToken()
	if err != nil {
		return "", OIDCFlow{}, err
	}
	state, err := randomOIDCToken()
	if err != nil {
		return "", OIDCFlow{}, err
	}
	nonce, err := randomOIDCToken()
	if err != nil {
		return "", OIDCFlow{}, err
	}
	flow := OIDCFlow{State: state, Nonce: nonce, Verifier: oauth2.GenerateVerifier(), MobileChallenge: challenge, ExpiresAt: time.Now().Add(10 * time.Minute)}
	raw, err := json.Marshal(flow)
	if err != nil {
		return "", OIDCFlow{}, err
	}
	err = s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketOIDCFlows)
		var stale [][]byte
		_ = b.ForEach(func(k, v []byte) error {
			var old OIDCFlow
			if json.Unmarshal(v, &old) != nil || time.Now().After(old.ExpiresAt) {
				stale = append(stale, append([]byte(nil), k...))
			}
			return nil
		})
		for _, key := range stale {
			if err := b.Delete(key); err != nil {
				return err
			}
		}
		return b.Put([]byte(id), raw)
	})
	return id, flow, err
}

func (s *Service) ConsumeOIDCFlow(id string) (OIDCFlow, error) {
	var flow OIDCFlow
	err := s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketOIDCFlows)
		raw := b.Get([]byte(id))
		if raw == nil {
			return errors.New("OIDC flow missing or already used")
		}
		if err := json.Unmarshal(raw, &flow); err != nil {
			return err
		}
		return b.Delete([]byte(id))
	})
	if err != nil {
		return flow, err
	}
	if time.Now().After(flow.ExpiresAt) {
		return flow, errors.New("OIDC flow expired")
	}
	return flow, nil
}

func (s *Service) CreateOIDCSession(identity OIDCIdentity) (*Session, error) {
	if s.oidc == nil || identity.Issuer != s.oidc.issuer || identity.ClientID != s.oidc.clientID || identity.Subject == "" || identity.RefreshToken == "" || !time.Now().Before(identity.ExpiresAt) || (identity.Role != RoleUser && identity.Role != RoleAdmin) {
		return nil, errors.New("incomplete OIDC identity or grant")
	}
	token, err := randomOIDCToken()
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	session := &Session{Token: token, Username: oidcUsername(identity), Role: identity.Role, CreatedAt: now.Format(time.RFC3339), ExpiresAt: now.Add(sessionIdleTTL).Format(time.RFC3339), OIDCGrant: &identity}
	raw, err := json.Marshal(session)
	if err != nil {
		return nil, err
	}
	err = s.db.Update(func(tx *bolt.Tx) error { return tx.Bucket(bucketSessions).Put([]byte(token), raw) })
	return session, err
}

func (s *Service) validateOIDCSession(session Session) *Session {
	expires, err := time.Parse(time.RFC3339, session.ExpiresAt)
	grant := session.OIDCGrant
	if s.oidc == nil || grant == nil || grant.Issuer != s.oidc.issuer || grant.ClientID != s.oidc.clientID || err != nil || !time.Now().Before(expires) {
		s.Logout(session.Token)
		return nil
	}
	if !session.RefreshInFlight && time.Now().Add(15*time.Second).Before(grant.ExpiresAt) {
		return &session
	}
	s.refreshMu.Lock()
	defer s.refreshMu.Unlock()
	// Re-read after waiting: another request may have refreshed or logged out.
	if err := s.db.View(func(tx *bolt.Tx) error {
		raw := tx.Bucket(bucketSessions).Get([]byte(session.Token))
		if raw == nil {
			return errors.New("session ended")
		}
		return json.Unmarshal(raw, &session)
	}); err != nil {
		return nil
	}
	expires, err = time.Parse(time.RFC3339, session.ExpiresAt)
	if session.RefreshInFlight || err != nil || !time.Now().Before(expires) {
		s.Logout(session.Token)
		return nil
	}
	if time.Now().Add(15 * time.Second).Before(session.OIDCGrant.ExpiresAt) {
		return &session
	}
	session.RefreshInFlight = true
	raw, _ := json.Marshal(session)
	if err := s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketSessions)
		if b.Get([]byte(session.Token)) == nil {
			return errors.New("session ended")
		}
		return b.Put([]byte(session.Token), raw)
	}); err != nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	identity, err := s.oidc.Refresh(ctx, *session.OIDCGrant)
	if err != nil {
		s.Logout(session.Token)
		return nil
	}
	session.OIDCGrant, session.Role, session.RefreshInFlight = &identity, identity.Role, false
	raw, _ = json.Marshal(session)
	if err := s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketSessions)
		if b.Get([]byte(session.Token)) == nil {
			return errors.New("session ended during refresh")
		}
		return b.Put([]byte(session.Token), raw)
	}); err != nil {
		s.Logout(session.Token)
		_ = s.oidc.Revoke(ctx, identity.RefreshToken)
		return nil
	}
	return &session
}

func (s *Service) StartMobileHandoff(identity OIDCIdentity, challenge string) (string, error) {
	if !validMobileChallenge(challenge) {
		return "", errors.New("invalid mobile challenge")
	}
	code, err := randomOIDCToken()
	if err != nil {
		return "", err
	}
	raw, err := json.Marshal(mobileHandoff{Identity: identity, Challenge: challenge, ExpiresAt: time.Now().Add(time.Minute)})
	if err != nil {
		return "", err
	}
	err = s.db.Update(func(tx *bolt.Tx) error { return tx.Bucket(bucketMobileHandoffs).Put([]byte(code), raw) })
	return code, err
}

func (s *Service) ConsumeMobileHandoff(code, verifier string) (OIDCIdentity, error) {
	var entry mobileHandoff
	if len(code) != 43 || len(verifier) < 43 || len(verifier) > 128 {
		return entry.Identity, errors.New("invalid mobile handoff")
	}
	err := s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketMobileHandoffs)
		raw := b.Get([]byte(code))
		if raw == nil {
			return errors.New("mobile handoff missing or already used")
		}
		if err := json.Unmarshal(raw, &entry); err != nil {
			return err
		}
		return b.Delete([]byte(code))
	})
	if err != nil {
		return OIDCIdentity{}, err
	}
	sum := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(sum[:])
	if time.Now().After(entry.ExpiresAt) || !hmac.Equal([]byte(challenge), []byte(entry.Challenge)) {
		if s.oidc != nil {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			_ = s.oidc.Revoke(ctx, entry.Identity.RefreshToken)
		}
		return OIDCIdentity{}, errors.New("invalid or expired mobile handoff")
	}
	return entry.Identity, nil
}
