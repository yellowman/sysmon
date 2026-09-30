package auth

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	bolt "go.etcd.io/bbolt"
	"golang.org/x/crypto/bcrypt"
)

const (
	RoleAdmin = "admin"
	RoleUser  = "user"
)

var (
	bucketUsers    = []byte("users")
	bucketSessions = []byte("sessions")
)

type User struct {
	Username  string `json:"username"`
	PassHash  string `json:"pass_hash"`
	Role      string `json:"role"`
	CreatedAt string `json:"created_at"`
	LastLogin string `json:"last_login,omitempty"`
}

type Session struct {
	Token           string        `json:"token"`
	Username        string        `json:"username"`
	Role            string        `json:"role"`
	CreatedAt       string        `json:"created_at"`
	ExpiresAt       string        `json:"expires_at"` // sliding for local sessions; absolute for OIDC
	OIDCGrant       *OIDCIdentity `json:"oidc_grant,omitempty"`
	RefreshInFlight bool          `json:"refresh_in_flight,omitempty"`
	RefreshRetryAt  string        `json:"refresh_retry_at,omitempty"`
}

const (
	// Sessions are valid as long as the app has been opened in the
	// last 30 days. Any authenticated request bumps this forward.
	sessionIdleTTL = 30 * 24 * time.Hour
	// Throttle bolt writes - only extend the session once per day of
	// activity, not on every API call.
	sessionExtendStep = 24 * time.Hour
)

type Service struct {
	db             *bolt.DB
	oidc           *OIDCClient
	refreshLocksMu sync.Mutex
	refreshLocks   map[string]*oidcSessionLock
	cleanupMu      sync.Mutex
	cleanupCancel  context.CancelFunc
	cleanupDone    chan struct{}
}

func NewService(dbPath string) (*Service, error) {
	return NewServiceWithBootstrap(dbPath, true)
}

func NewServiceWithBootstrap(dbPath string, bootstrap bool) (*Service, error) {
	if dir := filepath.Dir(dbPath); dir != "." && dir != "" {
		os.MkdirAll(dir, 0755)
	}

	db, err := bolt.Open(dbPath, 0600, &bolt.Options{Timeout: 1 * time.Second})
	if err != nil {
		return nil, fmt.Errorf("open auth database: %w", err)
	}

	err = db.Update(func(tx *bolt.Tx) error {
		if _, err := tx.CreateBucketIfNotExists(bucketUsers); err != nil {
			return err
		}
		for _, bucket := range [][]byte{bucketSessions, bucketOIDCFlows, bucketMobileHandoffs} {
			if _, err := tx.CreateBucketIfNotExists(bucket); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		db.Close()
		return nil, fmt.Errorf("init auth database: %w", err)
	}

	s := &Service{db: db}

	if bootstrap && s.UserCount() == 0 {
		log.Printf("auth: no users exist, creating default admin (admin/sysmon)")
		s.CreateUser("admin", "sysmon", RoleAdmin)
	}

	log.Printf("auth: initialized (%d users)", s.UserCount())
	return s, nil
}

func (s *Service) Close() {
	s.cleanupMu.Lock()
	cancel, done := s.cleanupCancel, s.cleanupDone
	s.cleanupMu.Unlock()
	if cancel != nil {
		cancel()
		<-done
	}
	if s.db != nil {
		s.db.Close()
	}
}

func (s *Service) CreateUser(username, password, role string) error {
	if username == "" || password == "" {
		return fmt.Errorf("username and password required")
	}
	if role != RoleAdmin && role != RoleUser {
		return fmt.Errorf("role must be 'admin' or 'user'")
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return fmt.Errorf("hash password: %w", err)
	}

	return s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketUsers)
		if b.Get([]byte(username)) != nil {
			return fmt.Errorf("user %s already exists", username)
		}
		user := User{
			Username:  username,
			PassHash:  string(hash),
			Role:      role,
			CreatedAt: time.Now().UTC().Format(time.RFC3339),
		}
		data, _ := json.Marshal(user)
		return b.Put([]byte(username), data)
	})
}

func (s *Service) DeleteUser(username string) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketUsers)
		if b.Get([]byte(username)) == nil {
			return fmt.Errorf("user %s not found", username)
		}
		b.Delete([]byte(username))

		// Revoke all sessions for this user
		sb := tx.Bucket(bucketSessions)
		var toDelete [][]byte
		sb.ForEach(func(k, v []byte) error {
			var sess Session
			if json.Unmarshal(v, &sess) == nil && sess.Username == username {
				toDelete = append(toDelete, k)
			}
			return nil
		})
		for _, k := range toDelete {
			sb.Delete(k)
		}
		return nil
	})
}

func (s *Service) ListUsers() []User {
	var users []User
	s.db.View(func(tx *bolt.Tx) error {
		return tx.Bucket(bucketUsers).ForEach(func(k, v []byte) error {
			var u User
			if json.Unmarshal(v, &u) == nil {
				u.PassHash = ""
				users = append(users, u)
			}
			return nil
		})
	})
	return users
}

func (s *Service) UserCount() int {
	count := 0
	s.db.View(func(tx *bolt.Tx) error {
		count = tx.Bucket(bucketUsers).Stats().KeyN
		return nil
	})
	return count
}

func (s *Service) ChangePassword(username, newPassword string) error {
	hash, err := bcrypt.GenerateFromPassword([]byte(newPassword), bcrypt.DefaultCost)
	if err != nil {
		return err
	}
	return s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketUsers)
		v := b.Get([]byte(username))
		if v == nil {
			return fmt.Errorf("user %s not found", username)
		}
		var u User
		json.Unmarshal(v, &u)
		u.PassHash = string(hash)
		data, _ := json.Marshal(u)
		b.Put([]byte(username), data)

		// Revoke all sessions so user must re-login with new password
		sb := tx.Bucket(bucketSessions)
		var toDelete [][]byte
		sb.ForEach(func(k, v []byte) error {
			var sess Session
			if json.Unmarshal(v, &sess) == nil && sess.Username == username {
				toDelete = append(toDelete, k)
			}
			return nil
		})
		for _, k := range toDelete {
			sb.Delete(k)
		}
		return nil
	})
}

func (s *Service) ChangeRole(username, newRole string) error {
	if newRole != RoleAdmin && newRole != RoleUser {
		return fmt.Errorf("role must be 'admin' or 'user'")
	}
	return s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketUsers)
		v := b.Get([]byte(username))
		if v == nil {
			return fmt.Errorf("user %s not found", username)
		}
		var u User
		json.Unmarshal(v, &u)
		u.Role = newRole
		data, _ := json.Marshal(u)
		b.Put([]byte(username), data)

		// Revoke sessions so user must re-login with new role
		sb := tx.Bucket(bucketSessions)
		var toDelete [][]byte
		sb.ForEach(func(k, sv []byte) error {
			var sess Session
			if json.Unmarshal(sv, &sess) == nil && sess.Username == username {
				toDelete = append(toDelete, k)
			}
			return nil
		})
		for _, k := range toDelete {
			sb.Delete(k)
		}
		return nil
	})
}

func (s *Service) Login(username, password string) (*Session, error) {
	if s.oidc != nil {
		return nil, fmt.Errorf("local accounts are disabled in OIDC mode")
	}
	var user User
	err := s.db.View(func(tx *bolt.Tx) error {
		v := tx.Bucket(bucketUsers).Get([]byte(username))
		if v == nil {
			return fmt.Errorf("invalid credentials")
		}
		return json.Unmarshal(v, &user)
	})
	if err != nil {
		return nil, err
	}

	if bcrypt.CompareHashAndPassword([]byte(user.PassHash), []byte(password)) != nil {
		return nil, fmt.Errorf("invalid credentials")
	}

	// Update last login
	s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketUsers)
		v := b.Get([]byte(username))
		if v == nil {
			return nil
		}
		var u User
		json.Unmarshal(v, &u)
		u.LastLogin = time.Now().UTC().Format(time.RFC3339)
		data, _ := json.Marshal(u)
		return b.Put([]byte(username), data)
	})

	token := generateToken()
	now := time.Now().UTC()
	session := &Session{
		Token:     token,
		Username:  username,
		Role:      user.Role,
		CreatedAt: now.Format(time.RFC3339),
		ExpiresAt: now.Add(sessionIdleTTL).Format(time.RFC3339),
	}

	s.db.Update(func(tx *bolt.Tx) error {
		data, _ := json.Marshal(session)
		return tx.Bucket(bucketSessions).Put([]byte(token), data)
	})

	return session, nil
}

func (s *Service) Logout(token string) {
	var grant *OIDCIdentity
	if err := s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketSessions)
		var session Session
		if raw := b.Get([]byte(token)); raw != nil && json.Unmarshal(raw, &session) == nil {
			grant = session.OIDCGrant
		}
		return b.Delete([]byte(token))
	}); err != nil {
		log.Printf("auth: could not remove session: %v", err)
		return
	}
	s.revokeGrant(context.Background(), grant)
}

// ValidateSession returns the session if it's still valid. Any successful
// authenticated request extends ExpiresAt to now + sessionIdleTTL, so the
// session only expires once the app has been off the phone (or unopened)
// for a full sessionIdleTTL - currently 30 days. Sessions stored before
// this field existed are treated as having an empty ExpiresAt and never
// expire on their own; they pick up sliding behaviour on first use.
func (s *Service) ValidateSession(token string) *Session {
	session, _ := s.validateSession(token)
	return session
}

func (s *Service) validateSession(token string) (*Session, error) {
	if token == "" {
		return nil, nil
	}
	var session Session
	s.db.View(func(tx *bolt.Tx) error {
		v := tx.Bucket(bucketSessions).Get([]byte(token))
		if v == nil {
			return fmt.Errorf("not found")
		}
		return json.Unmarshal(v, &session)
	})
	if session.Token == "" {
		return nil, nil
	}
	if session.OIDCGrant != nil {
		return s.validateOIDCSessionResult(session)
	}
	if s.oidc != nil {
		s.Logout(token)
		return nil, nil
	}

	now := time.Now().UTC()
	target := now.Add(sessionIdleTTL)

	if session.ExpiresAt != "" {
		expires, err := time.Parse(time.RFC3339, session.ExpiresAt)
		if err == nil && now.After(expires) {
			s.Logout(token)
			return nil, nil
		}
		// Skip the bolt write if the window has barely moved.
		if err == nil && target.Sub(expires) < sessionExtendStep {
			return &session, nil
		}
	}

	session.ExpiresAt = target.Format(time.RFC3339)
	s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketSessions)
		// Between our View above and this Update, a concurrent Logout,
		// ChangePassword, DeleteUser or ChangeRole may have deleted the
		// session. Don't resurrect it.
		if b.Get([]byte(token)) == nil {
			return nil
		}
		data, _ := json.Marshal(session)
		return b.Put([]byte(token), data)
	})

	return &session, nil
}

// GetSessionFromRequest extracts and validates the session from a request.
// Checks Authorization header (Bearer token) and sysmon_session cookie.
func (s *Service) GetSessionFromRequest(r *http.Request) *Session {
	session, _ := s.AuthenticateRequest(r)
	return session
}

// AuthenticateRequest distinguishes a temporary provider outage from an
// invalid session so clients can retain their session on a 503 response.
func (s *Service) AuthenticateRequest(r *http.Request) (*Session, error) {
	if cookie, err := r.Cookie("sysmon_session"); err == nil {
		if session, err := s.validateSession(cookie.Value); session != nil || err != nil {
			return session, err
		}
	}
	header := r.Header.Get("Authorization")
	if strings.HasPrefix(header, "Bearer ") {
		return s.validateSession(header[7:])
	}
	return nil, nil
}

func generateToken() string {
	b := make([]byte, 32)
	rand.Read(b)
	return hex.EncodeToString(b)
}
