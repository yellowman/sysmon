package push

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
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
	FCMCredentials []byte // Google service-account JSON
	APNsCertPEM    []byte
	APNsKeyPEM     []byte
	APNsBundleID   string
	APNsProduction bool
}

type Service struct {
	mu      sync.RWMutex
	config  Config
	db      *bolt.DB
	started bool // watchLoop running?

	// opsMu serializes the public API (Subscribe, ListSubscriptions,
	// SendTest, …) against Stop. Public methods take RLock and check
	// stopped; Stop takes Lock to drain in-flight ops, sets stopped,
	// then closes channels and the bolt DB. The DB is therefore only
	// ever closed once no RLocker can be holding it.
	opsMu   sync.RWMutex
	stopped bool

	apns *APNsClient
	fcm  *FCMClient

	// fcmKey is the latest result of the live key check (see
	// keyCheckLoop). Guarded by mu. kickKeyCh forces an immediate
	// re-check (buffered 1; extra kicks coalesce).
	fcmKey    FCMKeyStatus
	kickKeyCh chan struct{}

	// Pipeline telemetry (guarded by mu): what the watcher last did, so
	// "notifications aren't arriving" is diagnosable at a glance instead
	// of by log archaeology. See Health().
	lastPollAt   time.Time
	lastPollErr  string
	lastChangeAt time.Time
	lastChange   string // "host: OLD → NEW"
	lastPushAt   time.Time
	lastPushInfo string // "host (OLD → NEW): N recipient(s)"

	monitoring *monitoring.Service
	prevHosts  map[string]string
	stopCh     chan struct{}
	stopOnce   sync.Once
	wg         sync.WaitGroup
}

// FCMKeyStatus reports whether Google currently accepts the stored FCM
// service-account key. The offline metadata check can't see revocation,
// so this is maintained by actually minting OAuth tokens: hourly, on
// credential changes, and whenever a send fails with an auth error.
type FCMKeyStatus struct {
	Checked   bool   `json:"checked"`              // at least one check has completed
	CheckedAt string `json:"checked_at,omitempty"` // RFC3339
	Valid     bool   `json:"valid"`
	Rejected  bool   `json:"rejected"` // Google definitively refused (vs network trouble)
	Error     string `json:"error,omitempty"`
}

// ErrServiceStopped is returned by public Service methods after Stop has
// run. Callers should treat this as "push is unavailable" — typically a
// 503 — not as a permanent failure of the request itself.
var ErrServiceStopped = errors.New("push service is stopped")

// buildClients constructs FCM and APNs clients from a Config, logging
// (but not failing) on bad credentials so the service still runs for the
// other platform. Network-free: it only parses creds/certs.
func buildClients(cfg Config) (fcm *FCMClient, apns *APNsClient) {
	if len(cfg.FCMCredentials) > 0 {
		c, err := NewFCMClient(cfg.FCMCredentials)
		if err != nil {
			log.Printf("push: WARNING: FCM client init failed: %v", err)
		} else {
			fcm = c
			log.Printf("push: FCM client initialized for project %s", c.projectID)
		}
	}
	if len(cfg.APNsCertPEM) > 0 && len(cfg.APNsKeyPEM) > 0 && cfg.APNsBundleID != "" {
		c, err := NewAPNsClient(cfg.APNsCertPEM, cfg.APNsKeyPEM, cfg.APNsBundleID, cfg.APNsProduction)
		if err != nil {
			log.Printf("push: WARNING: APNs client init failed: %v", err)
		} else {
			apns = c
			env := "sandbox"
			if cfg.APNsProduction {
				env = "production"
			}
			log.Printf("push: APNs client initialized (%s, bundle: %s)", env, cfg.APNsBundleID)
		}
	}
	return fcm, apns
}

// clients snapshots the current client pointers and enable flag under a
// brief read lock so the send path never races a Reconfigure swap.
func (s *Service) clients() (fcm *FCMClient, apns *APNsClient, enabled bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.fcm, s.apns, s.config.Enabled
}

// Reconfigure hot-swaps the push credentials/flags (e.g. after an admin
// uploads new FCM creds). Safe to call while the watcher is running; it
// starts the watcher if push just became enabled+configured. Becomes a
// no-op after Stop so a late call can't relaunch the watcher against a
// closed bolt DB.
func (s *Service) Reconfigure(cfg Config) {
	s.opsMu.RLock()
	if s.stopped {
		s.opsMu.RUnlock()
		return
	}
	s.opsMu.RUnlock()
	fcm, apns := buildClients(cfg)
	s.mu.Lock()
	s.config = cfg
	s.fcm = fcm
	s.apns = apns
	s.mu.Unlock()
	s.maybeStartLoop()
	// Revalidate the (possibly new) key right away so the settings
	// panel reflects reality without waiting for the hourly tick.
	s.kickKeyCheck()
}

// maybeStartLoop starts the watcher once, if push is enabled and at least
// one platform is configured. Idempotent.
func (s *Service) maybeStartLoop() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.started || !s.config.Enabled || (s.fcm == nil && s.apns == nil) {
		return
	}
	s.started = true
	s.wg.Add(1)
	go s.watchLoop()
	log.Printf("push: state change watcher started (1s poll interval)")
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
		if _, err := tx.CreateBucketIfNotExists(bucketPushLog); err != nil {
			return err
		}
		// Hard-migrate legacy rows. Early Android builds subscribed with
		// platform "fcm" — rewrite those to "android" (notifyAll fans out
		// by platform, so they were silently undeliverable). Anything
		// else unrecognized (or unparseable) is unroutable garbage with
		// no upgrade path: delete it — the app re-subscribes on every
		// launch, so a legitimate device comes right back.
		b := tx.Bucket(bucketSubscriptions)
		type fix struct {
			key  []byte
			data []byte
		}
		var rewrites []fix
		var deletes [][]byte
		b.ForEach(func(k, v []byte) error {
			var sub Subscription
			if json.Unmarshal(v, &sub) != nil {
				deletes = append(deletes, append([]byte(nil), k...))
				return nil
			}
			switch sub.Platform {
			case PlatformIOS, PlatformAndroid:
			case "fcm":
				sub.Platform = PlatformAndroid
				if data, err := json.Marshal(sub); err == nil {
					rewrites = append(rewrites, fix{append([]byte(nil), k...), data})
				}
			default:
				deletes = append(deletes, append([]byte(nil), k...))
			}
			return nil
		})
		for _, f := range rewrites {
			if err := b.Put(f.key, f.data); err != nil {
				return err
			}
		}
		for _, k := range deletes {
			if err := b.Delete(k); err != nil {
				return err
			}
		}
		if len(rewrites) > 0 || len(deletes) > 0 {
			log.Printf("push: migrated subscriptions: %d platform=fcm rewritten to android, %d unroutable row(s) deleted",
				len(rewrites), len(deletes))
		}
		return nil
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
		kickKeyCh:  make(chan struct{}, 1),
	}

	s.fcm, s.apns = buildClients(cfg)

	count := s.subscriberCount()
	log.Printf("push: database opened at %s (%d subscriptions)", dbPath, count)

	// The key-health checker runs for the service's whole lifetime,
	// independent of the enabled flag — a stored-but-disabled key still
	// deserves a truthful status on the settings panel.
	s.wg.Add(1)
	go s.keyCheckLoop()

	return s, nil
}

// keyCheckLoop revalidates the FCM key hourly, plus immediately on
// kickKeyCheck (credential change or an auth failure during a send).
func (s *Service) keyCheckLoop() {
	defer s.wg.Done()
	defer func() {
		if r := recover(); r != nil {
			log.Printf("push: keyCheckLoop panic recovered: %v", r)
		}
	}()

	ticker := time.NewTicker(1 * time.Hour)
	defer ticker.Stop()

	s.runKeyCheck()
	for {
		select {
		case <-ticker.C:
			s.runKeyCheck()
		case <-s.kickKeyCh:
			s.runKeyCheck()
		case <-s.stopCh:
			return
		}
	}
}

// kickKeyCheck requests an immediate key re-check. Non-blocking;
// concurrent kicks coalesce into one.
func (s *Service) kickKeyCheck() {
	select {
	case s.kickKeyCh <- struct{}{}:
	default:
	}
}

func (s *Service) runKeyCheck() {
	s.mu.RLock()
	creds := s.config.FCMCredentials
	prev := s.fcmKey
	s.mu.RUnlock()

	if len(creds) == 0 {
		s.mu.Lock()
		s.fcmKey = FCMKeyStatus{}
		s.mu.Unlock()
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	err := FCMCredentialLiveCheck(ctx, creds)

	st := FCMKeyStatus{
		Checked:   true,
		CheckedAt: time.Now().UTC().Format(time.RFC3339),
		Valid:     err == nil,
	}
	if err != nil {
		st.Error = err.Error()
		var rej *KeyRejectedError
		if errors.As(err, &rej) {
			st.Rejected = true
		}
		log.Printf("push: WARNING: FCM service-account key check failed: %v", err)
	} else if prev.Checked && !prev.Valid {
		log.Printf("push: FCM service-account key check passing again")
	}

	s.mu.Lock()
	s.fcmKey = st
	s.mu.Unlock()
}

// FCMKeyHealth returns the latest live key-check result.
func (s *Service) FCMKeyHealth() FCMKeyStatus {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.fcmKey
}

// Enabled reports the current master enable flag. Used by handlers to
// warn when a test push succeeds while real alert delivery is off.
func (s *Service) Enabled() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.config.Enabled
}

// PipelineHealth is a one-glance answer to "why aren't alerts arriving?"
// — every link in the chain from the enable switch to the last actual
// send. Times are RFC3339, empty when the event has never happened.
type PipelineHealth struct {
	Enabled        bool         `json:"enabled"`
	WatcherRunning bool         `json:"watcher_running"`
	FCMConfigured  bool         `json:"fcm_configured"`
	APNsConfigured bool         `json:"apns_configured"`
	Subscribers    int          `json:"subscribers"`
	FCMKey         FCMKeyStatus `json:"fcm_key"`
	LastPollAt     string       `json:"last_poll_at,omitempty"`
	LastPollError  string       `json:"last_poll_error,omitempty"`
	LastChangeAt   string       `json:"last_change_at,omitempty"`
	LastChange     string       `json:"last_change,omitempty"`
	LastPushAt     string       `json:"last_push_at,omitempty"`
	LastPush       string       `json:"last_push,omitempty"`
}

// Health snapshots the delivery pipeline state.
func (s *Service) Health() PipelineHealth {
	s.opsMu.RLock()
	defer s.opsMu.RUnlock()
	if s.stopped {
		return PipelineHealth{}
	}
	subs := s.subscriberCount()

	s.mu.RLock()
	defer s.mu.RUnlock()
	ts := func(t time.Time) string {
		if t.IsZero() {
			return ""
		}
		return t.Format(time.RFC3339)
	}
	return PipelineHealth{
		Enabled:        s.config.Enabled,
		WatcherRunning: s.started,
		FCMConfigured:  s.fcm != nil,
		APNsConfigured: s.apns != nil,
		Subscribers:    subs,
		FCMKey:         s.fcmKey,
		LastPollAt:     ts(s.lastPollAt),
		LastPollError:  s.lastPollErr,
		LastChangeAt:   ts(s.lastChangeAt),
		LastChange:     s.lastChange,
		LastPushAt:     ts(s.lastPushAt),
		LastPush:       s.lastPushInfo,
	}
}

// Start begins the state-change watcher if push is enabled and at least
// one platform is configured. If not, it stays dormant until an admin
// configures push via Reconfigure.
func (s *Service) Start() {
	s.maybeStartLoop()
}

// Stop tears the service down with proper draining:
//  1. Close stopCh so the watcher exits at the next select.
//  2. Wait for the watcher goroutine to finish — the watcher's bolt
//     ops are wrapped in the same public API as handler requests, so
//     they take opsMu.RLock per op; we must not hold the W lock yet
//     or they'd deadlock.
//  3. Take opsMu.Lock. This blocks until every concurrent handler
//     that already had RLock has released. Once we own it, no new
//     RLocker can advance, and no current RLocker is in flight.
//  4. Set stopped = true. Releasing the W lock lets queued handlers
//     run; they observe stopped and return ErrServiceStopped without
//     touching the bolt DB.
//  5. Close the bolt DB.
//
// Idempotent via stopOnce: safe to call from a defer plus an explicit
// graceful shutdown path.
func (s *Service) Stop() {
	s.stopOnce.Do(func() {
		close(s.stopCh)
		s.wg.Wait()
		s.opsMu.Lock()
		s.stopped = true
		s.opsMu.Unlock()
		if s.db != nil {
			s.db.Close()
		}
	})
}

func (s *Service) Subscribe(token string, platform Platform, label, owner, ipAddr, userAgent string) (string, error) {
	s.opsMu.RLock()
	defer s.opsMu.RUnlock()
	if s.stopped {
		return "", ErrServiceStopped
	}
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

		// Preserve existing data on re-subscribe.
		ownerChanged := false
		if existing := b.Get([]byte(token)); existing != nil {
			json.Unmarshal(existing, &sub)
			// A device token is a per-install secret held by whoever
			// physically has the app. When a different account signs in
			// on the same device it legitimately takes the token over —
			// the previous owner logged out. (There's no hijack risk: the
			// push providers only deliver to the device that actually
			// holds the token, so re-registering someone else's token
			// can't redirect their notifications.) Reassign ownership
			// instead of rejecting, but rotate the API key so the prior
			// owner's key can no longer target this device.
			if sub.Owner != "" && sub.Owner != owner {
				ownerChanged = true
			}
		}

		if sub.APIKey != "" && !ownerChanged {
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
	s.opsMu.RLock()
	defer s.opsMu.RUnlock()
	if s.stopped {
		return
	}
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

// RecordPush updates push delivery stats for a device. On failure,
// status carries a short classified reason (e.g. "failed: project
// mismatch") that the subscribers admin page surfaces per device.
func (s *Service) RecordPush(token string, success bool, status string) {
	s.opsMu.RLock()
	defer s.opsMu.RUnlock()
	if s.stopped {
		return
	}
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
		} else {
			sub.FailCount++
		}
		sub.LastPushStatus = status
		data, _ := json.Marshal(sub)
		return b.Put([]byte(token), data)
	})
}

// pushFailStatus compresses a send error into a short per-device status
// for the subscribers page. The full error still goes to the log.
func pushFailStatus(err error) string {
	var se *FCMSendError
	if errors.As(err, &se) {
		switch se.Reason {
		case "UNREGISTERED":
			return "failed: token dead"
		case "SENDER_ID_MISMATCH":
			return "failed: project mismatch"
		}
		if se.Reason != "" {
			return "failed: " + strings.ToLower(se.Reason)
		}
	}
	var kr *KeyRejectedError
	if errors.As(err, &kr) {
		return "failed: key rejected"
	}
	return "failed"
}

// AdminRemove removes a subscription by device token (admin operation).
func (s *Service) AdminRemove(token string) error {
	s.opsMu.RLock()
	defer s.opsMu.RUnlock()
	if s.stopped {
		return ErrServiceStopped
	}
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
	s.opsMu.RLock()
	defer s.opsMu.RUnlock()
	if s.stopped {
		return nil
	}
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
	s.opsMu.RLock()
	defer s.opsMu.RUnlock()
	if s.stopped {
		return ErrServiceStopped
	}
	return s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketSubscriptions)
		if b.Get([]byte(token)) == nil {
			return fmt.Errorf("device token not found")
		}
		return b.Delete([]byte(token))
	})
}

func (s *Service) ListSubscriptions() []Subscription {
	s.opsMu.RLock()
	defer s.opsMu.RUnlock()
	if s.stopped {
		return nil
	}
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
	s.opsMu.RLock()
	defer s.opsMu.RUnlock()
	if s.stopped {
		return nil
	}
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
	s.opsMu.RLock()
	defer s.opsMu.RUnlock()
	if s.stopped {
		return ""
	}
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
	s.opsMu.RLock()
	defer s.opsMu.RUnlock()
	if s.stopped {
		return false
	}
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
	s.opsMu.RLock()
	defer s.opsMu.RUnlock()
	if s.stopped {
		return ErrServiceStopped
	}
	err := s.sendToDevice(token, platform, "sysmon test", "", "push notifications are working")
	if err != nil {
		var kr *KeyRejectedError
		if errors.As(err, &kr) {
			s.kickKeyCheck()
		}
	}
	return err
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
	fcm, apns, _ := s.clients()
	switch platform {
	case PlatformIOS:
		if apns == nil {
			return fmt.Errorf("APNs not configured")
		}
		return apns.Send(token, title, subtitle, body, nil)
	case PlatformAndroid:
		if fcm == nil {
			return fmt.Errorf("FCM not configured")
		}
		return fcm.Send(token, title, body, fcmData{})
	default:
		return fmt.Errorf("unknown platform: %s", platform)
	}
}

func (s *Service) notifyAll(title, subtitle, body, hostname, status, prevStatus, checkType string, badge int) {
	// Snapshot the clients once so a concurrent Reconfigure can't swap
	// them mid-fan-out, and so we don't hold a lock across slow sends.
	fcm, apns, _ := s.clients()
	subs := s.ListSubscriptions()
	sent := 0
	badgePtr := &badge

	for _, sub := range subs {
		var err error
		skipped := false
		switch sub.Platform {
		case PlatformIOS:
			if apns != nil {
				err = apns.Send(sub.DeviceToken, title, subtitle, body, badgePtr)
			} else {
				skipped = true
			}
		case PlatformAndroid:
			if fcm != nil {
				data := fcmData{
					Hostname: hostname,
					Status:   status,
					Type:     checkType,
				}
				err = fcm.Send(sub.DeviceToken, title, body, data)
			} else {
				skipped = true
			}
		default:
			// Can't happen after the boot-time migration (Subscribe
			// rejects anything but ios/android) — but never fail silent.
			log.Printf("push: WARNING: subscription %q has unknown platform %q — not delivered", sub.Label, sub.Platform)
			continue
		}
		if skipped {
			continue
		}
		if err != nil {
			s.RecordPush(sub.DeviceToken, false, pushFailStatus(err))
			log.Printf("push: send to %s/%s failed: %v", sub.Platform, sub.Label, err)
			// An auth-level refusal means the key itself died — flip the
			// settings-panel key status now instead of at the next hourly
			// check.
			var kr *KeyRejectedError
			if errors.As(err, &kr) {
				s.kickKeyCheck()
			}
		} else {
			s.RecordPush(sub.DeviceToken, true, "ok")
			sent++
		}
	}

	s.mu.Lock()
	s.lastPushAt = time.Now().UTC()
	s.lastPushInfo = fmt.Sprintf("%s (%s → %s): %d recipient(s)", hostname, prevStatus, status, sent)
	s.mu.Unlock()

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

	// Seed poll through safePoll so a panic here doesn't kill the watcher
	// (the seed just records baseline state; it shouldn't notify).
	s.safeSeed()

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

func (s *Service) safeSeed() {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("push: seed poll panic: %v", r)
		}
	}()
	s.pollAndNotify(true)
}

func (s *Service) pollAndNotify(initialSeed bool) {
	status, err := s.monitoring.GetStatus()
	s.mu.Lock()
	s.lastPollAt = time.Now().UTC()
	if err != nil {
		s.lastPollErr = err.Error()
	} else {
		s.lastPollErr = ""
	}
	s.mu.Unlock()
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
	if len(changes) > 0 {
		last := changes[len(changes)-1]
		s.lastChangeAt = time.Now().UTC()
		s.lastChange = fmt.Sprintf("%s: %s → %s",
			last.host.Hostname, last.prevStatus, last.host.OverallStatus)
	}
	s.mu.Unlock()

	// If push is disabled or unconfigured we still updated prevHosts
	// above, so the baseline stays current and re-enabling later doesn't
	// replay a backlog of stale state changes — we just don't send.
	_, _, enabled := s.clients()
	if !enabled {
		return
	}
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
