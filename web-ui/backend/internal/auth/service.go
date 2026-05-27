package auth

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
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
	Token     string `json:"token"`
	Username  string `json:"username"`
	Role      string `json:"role"`
	CreatedAt string `json:"created_at"`
	ExpiresAt string `json:"expires_at"`
}

type Service struct {
	db *bolt.DB
}

func NewService(dbPath string) (*Service, error) {
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
		_, err := tx.CreateBucketIfNotExists(bucketSessions)
		return err
	})
	if err != nil {
		db.Close()
		return nil, fmt.Errorf("init auth database: %w", err)
	}

	s := &Service{db: db}

	if s.UserCount() == 0 {
		log.Printf("auth: no users exist, creating default admin (admin/sysmon)")
		s.CreateUser("admin", "sysmon", RoleAdmin)
	}

	log.Printf("auth: initialized (%d users)", s.UserCount())
	return s, nil
}

func (s *Service) Close() {
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
		ExpiresAt: now.Add(24 * time.Hour).Format(time.RFC3339),
	}

	s.db.Update(func(tx *bolt.Tx) error {
		data, _ := json.Marshal(session)
		return tx.Bucket(bucketSessions).Put([]byte(token), data)
	})

	return session, nil
}

func (s *Service) Logout(token string) {
	s.db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket(bucketSessions).Delete([]byte(token))
	})
}

func (s *Service) ValidateSession(token string) *Session {
	if token == "" {
		return nil
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
		return nil
	}
	expires, err := time.Parse(time.RFC3339, session.ExpiresAt)
	if err != nil || time.Now().UTC().After(expires) {
		s.Logout(token)
		return nil
	}
	return &session
}

// GetSessionFromRequest extracts and validates the session from a request.
// Checks Authorization header (Bearer token) and sysmon_session cookie.
func (s *Service) GetSessionFromRequest(r *http.Request) *Session {
	// Check Authorization header
	auth := r.Header.Get("Authorization")
	if strings.HasPrefix(auth, "Bearer ") {
		if sess := s.ValidateSession(auth[7:]); sess != nil {
			return sess
		}
	}

	// Check cookie
	if cookie, err := r.Cookie("sysmon_session"); err == nil {
		if sess := s.ValidateSession(cookie.Value); sess != nil {
			return sess
		}
	}

	return nil
}

func generateToken() string {
	b := make([]byte, 32)
	rand.Read(b)
	return hex.EncodeToString(b)
}
