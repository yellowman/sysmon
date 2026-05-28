package push

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	bolt "go.etcd.io/bbolt"

	"sysmon-web/internal/models"
	"sysmon-web/internal/monitoring"
)

type Platform string

const (
	PlatformIOS     Platform = "ios"
	PlatformAndroid Platform = "android"
)

var (
	bucketSubscriptions = []byte("subscriptions")
	bucketPushLog       = []byte("push_log")
)

type Subscription struct {
	DeviceToken    string   `json:"device_token"`
	Platform       Platform `json:"platform"`
	Label          string   `json:"label,omitempty"`
	APIKey         string   `json:"api_key"`
	Owner          string   `json:"owner,omitempty"`
	CreatedAt      string   `json:"created_at"`
	LastSeen       string   `json:"last_seen"`
	LastPushAt     string   `json:"last_push_at,omitempty"`
	LastPushStatus string   `json:"last_push_status,omitempty"`
	PushCount      int64    `json:"push_count"`
	FailCount      int64    `json:"fail_count"`
	IPAddress      string   `json:"ip_address,omitempty"`
	UserAgent      string   `json:"user_agent,omitempty"`
}

func generateAPIKey() string {
	b := make([]byte, 16)
	rand.Read(b)
	return hex.EncodeToString(b)
}

type pushLogEntry struct {
	Timestamp  string `json:"timestamp"`
	Hostname   string `json:"hostname"`
	Status     string `json:"status"`
	PrevStatus string `json:"prev_status"`
	Recipients int    `json:"recipients"`
}

type Config struct {
	Enabled        bool
	FCMServerKey   string
	APNsCertFile   string
	APNsKeyFile    string
	APNsBundleID   string
	APNsProduction bool
}

type Service struct {
	mu     sync.RWMutex
	config Config
	db     *bolt.DB

	apns *APNsClient
	fcm  *FCMClient

	monitoring *monitoring.Service
	prevHosts  map[string]string
	stopCh     chan struct{}
	wg         sync.WaitGroup
}

func NewService(cfg Config, dbPath string, mon *monitoring.Service) (*Service, error) {
	if dir := filepath.Dir(dbPath); dir != "." && dir != "" {
		os.MkdirAll(dir, 0755)
	}

	db, err := bolt.Open(dbPath, 0600, &bolt.Options{Timeout: 1 * time.Second})
	if err != nil {
		return nil, fmt.Errorf("open push database: %w", err)
	}

	err = db.Update(func(tx *bolt.Tx) error {
		if _, err := tx.CreateBucketIfNotExists(bucketSubscriptions); err != nil {
			return err
		}
		_, err := tx.CreateBucketIfNotExists(bucketPushLog)
		return err
	})
	if err != nil {
		db.Close()
		return nil, fmt.Errorf("init push database: %w", err)
	}

	s := &Service{
		config:     cfg,
		db:         db,
		monitoring: mon,
		prevHosts:  make(map[string]string),
		stopCh:     make(chan struct{}),
	}

	if cfg.FCMServerKey != "" {
		s.fcm = NewFCMClient(cfg.FCMServerKey)
		log.Printf("push: FCM client initialized")
	}

	if cfg.APNsCertFile != "" && cfg.APNsKeyFile != "" && cfg.APNsBundleID != "" {
		client, err := NewAPNsClient(cfg.APNsCertFile, cfg.APNsKeyFile, cfg.APNsBundleID, cfg.APNsProduction)
		if err != nil {
			log.Printf("push: WARNING: APNs client init failed: %v", err)
		} else {
			s.apns = client
			env := "sandbox"
			if cfg.APNsProduction {
				env = "production"
			}
			log.Printf("push: APNs client initialized (%s, bundle: %s)", env, cfg.APNsBundleID)
		}
	}

	count := s.subscriberCount()
	log.Printf("push: database opened at %s (%d subscriptions)", dbPath, count)

	return s, nil
}

func (s *Service) Start() {
	if !s.config.Enabled {
		log.Printf("push: notifications disabled in config")
		return
	}
	if s.fcm == nil && s.apns == nil {
		log.Printf("push: no FCM or APNs credentials configured, watcher not started")
		return
	}
	s.wg.Add(1)
	go s.watchLoop()
	log.Printf("push: state change watcher started (1s poll interval)")
}

func (s *Service) Stop() {
	close(s.stopCh)
	s.wg.Wait()
	if s.db != nil {
		s.db.Close()
	}
}

func (s *Service) Subscribe(token string, platform Platform, label, owner, ipAddr, userAgent string) (string, error) {
	if platform != PlatformIOS && platform != PlatformAndroid {
		return "", fmt.Errorf("platform must be 'ios' or 'android'")
	}
	if token == "" {
		return "", fmt.Errorf("device_token is required")
	}

	now := time.Now().UTC().Format(time.RFC3339)
	apiKey := ""

	err := s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketSubscriptions)

		var sub Subscription

		// Preserve existing data on re-subscribe
		if existing := b.Get([]byte(token)); existing != nil {
			json.Unmarshal(existing, &sub)
			// Don't let one user hijack another user's device token
			if sub.Owner != "" && sub.Owner != owner {
				return fmt.Errorf("device_token already registered to another account")
			}
		}

		if sub.APIKey != "" {
			apiKey = sub.APIKey
		} else {
			apiKey = generateAPIKey()
		}
		if sub.CreatedAt == "" {
			sub.CreatedAt = now
		}

		sub.DeviceToken = token
		sub.Platform = platform
		sub.Label = label
		sub.APIKey = apiKey
		sub.Owner = owner
		sub.LastSeen = now
		sub.IPAddress = ipAddr
		sub.UserAgent = userAgent

		data, err := json.Marshal(sub)
		if err != nil {
			return err
		}
		return b.Put([]byte(token), data)
	})
	return apiKey, err
}

// TouchLastSeen updates the last_seen timestamp for a device.
func (s *Service) TouchLastSeen(token, ipAddr string) {
	s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketSubscriptions)
		v := b.Get([]byte(token))
		if v == nil {
			return nil
		}
		var sub Subscription
		if err := json.Unmarshal(v, &sub); err != nil {
			return nil
		}
		sub.LastSeen = time.Now().UTC().Format(time.RFC3339)
		if ipAddr != "" {
			sub.IPAddress = ipAddr
		}
		data, _ := json.Marshal(sub)
		return b.Put([]byte(token), data)
	})
}

// RecordPush updates push delivery stats for a device.
func (s *Service) RecordPush(token string, success bool) {
	s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketSubscriptions)
		v := b.Get([]byte(token))
		if v == nil {
			return nil
		}
		var sub Subscription
		if err := json.Unmarshal(v, &sub); err != nil {
			return nil
		}
		sub.LastPushAt = time.Now().UTC().Format(time.RFC3339)
		if success {
			sub.PushCount++
			sub.LastPushStatus = "ok"
		} else {
			sub.FailCount++
			sub.LastPushStatus = "failed"
		}
		data, _ := json.Marshal(sub)
		return b.Put([]byte(token), data)
	})
}

// AdminRemove removes a subscription by device token (admin operation).
func (s *Service) AdminRemove(token string) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketSubscriptions)
		if b.Get([]byte(token)) == nil {
			return fmt.Errorf("device token not found")
		}
		return b.Delete([]byte(token))
	})
}

// GetPushLog returns the N most recent push log entries.
func (s *Service) GetPushLog(limit int) []pushLogEntry {
	var entries []pushLogEntry
	s.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketPushLog)
		c := b.Cursor()
		// Iterate in reverse (newest first)
		for k, v := c.Last(); k != nil; k, v = c.Prev() {
			var entry pushLogEntry
			if json.Unmarshal(v, &entry) == nil {
				entries = append(entries, entry)
			}
			if len(entries) >= limit {
				break
			}
		}
		return nil
	})
	return entries
}

func (s *Service) Unsubscribe(token string) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketSubscriptions)
		if b.Get([]byte(token)) == nil {
			return fmt.Errorf("device token not found")
		}
		return b.Delete([]byte(token))
	})
}

func (s *Service) ListSubscriptions() []Subscription {
	var subs []Subscription
	s.db.View(func(tx *bolt.Tx) error {
		return tx.Bucket(bucketSubscriptions).ForEach(func(k, v []byte) error {
			var sub Subscription
			if err := json.Unmarshal(v, &sub); err == nil {
				subs = append(subs, sub)
			}
			return nil
		})
	})
	return subs
}

// ListSubscriptionsByOwner returns only subscriptions owned by the given user.
func (s *Service) ListSubscriptionsByOwner(owner string) []Subscription {
	var subs []Subscription
	s.db.View(func(tx *bolt.Tx) error {
		return tx.Bucket(bucketSubscriptions).ForEach(func(k, v []byte) error {
			var sub Subscription
			if err := json.Unmarshal(v, &sub); err == nil && sub.Owner == owner {
				subs = append(subs, sub)
			}
			return nil
		})
	})
	return subs
}

// GetPlatform returns the platform of the subscription with the given token,
// or empty string if not found.
func (s *Service) GetPlatform(token string) Platform {
	var platform Platform
	s.db.View(func(tx *bolt.Tx) error {
		v := tx.Bucket(bucketSubscriptions).Get([]byte(token))
		if v == nil {
			return nil
		}
		var sub Subscription
		if err := json.Unmarshal(v, &sub); err == nil {
			platform = sub.Platform
		}
		return nil
	})
	return platform
}

// IsOwner checks if the given user owns the subscription with the given token.
func (s *Service) IsOwner(token, owner string) bool {
	owned := false
	s.db.View(func(tx *bolt.Tx) error {
		v := tx.Bucket(bucketSubscriptions).Get([]byte(token))
		if v == nil {
			return nil
		}
		var sub Subscription
		if err := json.Unmarshal(v, &sub); err == nil && sub.Owner == owner {
			owned = true
		}
		return nil
	})
	return owned
}

func (s *Service) SendTest(token string, platform Platform) error {
	return s.sendToDevice(token, platform, "sysmon test", "", "push notifications are working")
}

func (s *Service) subscriberCount() int {
	count := 0
	s.db.View(func(tx *bolt.Tx) error {
		count = tx.Bucket(bucketSubscriptions).Stats().KeyN
		return nil
	})
	return count
}

func (s *Service) sendToDevice(token string, platform Platform, title, subtitle, body string) error {
	switch platform {
	case PlatformIOS:
		if s.apns == nil {
			return fmt.Errorf("APNs not configured")
		}
		return s.apns.Send(token, title, subtitle, body, nil)
	case PlatformAndroid:
		if s.fcm == nil {
			return fmt.Errorf("FCM not configured")
		}
		return s.fcm.Send(token, title, body, fcmData{})
	default:
		return fmt.Errorf("unknown platform: %s", platform)
	}
}

func (s *Service) notifyAll(title, subtitle, body, hostname, status, prevStatus, checkType string, badge int) {
	subs := s.ListSubscriptions()
	sent := 0
	badgePtr := &badge

	for _, sub := range subs {
		var err error
		skipped := false
		switch sub.Platform {
		case PlatformIOS:
			if s.apns != nil {
				err = s.apns.Send(sub.DeviceToken, title, subtitle, body, badgePtr)
			} else {
				skipped = true
			}
		case PlatformAndroid:
			if s.fcm != nil {
				data := fcmData{
					Hostname: hostname,
					Status:   status,
					Type:     checkType,
				}
				err = s.fcm.Send(sub.DeviceToken, title, body, data)
			} else {
				skipped = true
			}
		default:
			skipped = true
		}
		if skipped {
			continue
		}
		s.RecordPush(sub.DeviceToken, err == nil)
		if err != nil {
			log.Printf("push: send to %s/%s failed: %v", sub.Platform, sub.Label, err)
		} else {
			sent++
		}
	}

	entry := pushLogEntry{
		Timestamp:  time.Now().UTC().Format(time.RFC3339),
		Hostname:   hostname,
		Status:     status,
		PrevStatus: prevStatus,
		Recipients: sent,
	}
	if data, err := json.Marshal(entry); err == nil {
		s.db.Update(func(tx *bolt.Tx) error {
			b := tx.Bucket(bucketPushLog)
			id, _ := b.NextSequence()
			return b.Put([]byte(fmt.Sprintf("%010d", id)), data)
		})
	}
}

func (s *Service) watchLoop() {
	defer s.wg.Done()
	defer func() {
		if r := recover(); r != nil {
			log.Printf("push: watchLoop panic recovered: %v", r)
		}
	}()

	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	s.pollAndNotify(true)

	for {
		select {
		case <-ticker.C:
			s.safePoll()
		case <-s.stopCh:
			return
		}
	}
}

func (s *Service) safePoll() {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("push: pollAndNotify panic: %v", r)
		}
	}()
	s.pollAndNotify(false)
}

func (s *Service) pollAndNotify(initialSeed bool) {
	status, err := s.monitoring.GetStatus()
	if err != nil {
		return
	}

	// Badge count = currently non-OK hosts (what an attentive user would
	// want to act on). Sent on every push so iOS app icon stays accurate.
	badge := 0
	for _, h := range status.Hosts {
		if strings.ToUpper(h.OverallStatus) != "OK" {
			badge++
		}
	}

	s.mu.Lock()
	var changes []struct {
		host       models.HostStatus
		prevStatus string
	}

	for _, host := range status.Hosts {
		key := host.ObjectName
		if key == "" {
			key = host.Hostname
		}
		prevStatus, known := s.prevHosts[key]
		s.prevHosts[key] = host.OverallStatus

		if initialSeed || !known || prevStatus == host.OverallStatus {
			continue
		}

		changes = append(changes, struct {
			host       models.HostStatus
			prevStatus string
		}{host, prevStatus})
	}
	s.mu.Unlock()

	for _, c := range changes {
		s.sendStateChange(c.host, c.prevStatus, badge)
	}
}

func (s *Service) sendStateChange(host models.HostStatus, prevStatus string, badge int) {
	var title, subtitle, body string

	checkType := ""
	if len(host.Checks) > 0 {
		checkType = host.Checks[0].Type
	}

	switch strings.ToUpper(host.OverallStatus) {
	case "CRITICAL", "WARNING":
		title = fmt.Sprintf("%s DOWN", host.Hostname)
		if host.Description != "" {
			subtitle = host.Description
		}
		body = fmt.Sprintf("%s is unreachable", host.Hostname)
		if checkType != "" {
			body = fmt.Sprintf("%s %s check failed", host.Hostname, checkType)
		}
	case "OK":
		title = fmt.Sprintf("%s RECOVERED", host.Hostname)
		if host.Description != "" {
			subtitle = host.Description
		}
		body = fmt.Sprintf("%s is back up (was %s)", host.Hostname, prevStatus)
	default:
		title = fmt.Sprintf("%s %s", host.Hostname, host.OverallStatus)
		body = fmt.Sprintf("status changed from %s to %s", prevStatus, host.OverallStatus)
	}

	log.Printf("push: %s status %s -> %s, notifying subscribers",
		host.Hostname, prevStatus, host.OverallStatus)

	s.notifyAll(title, subtitle, body, host.Hostname, host.OverallStatus, prevStatus, checkType, badge)
}
