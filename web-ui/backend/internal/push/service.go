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
	// Unregistered is FCM's authoritative "this token no longer exists"
	// verdict (UNREGISTERED on a send): app uninstalled, data cleared,
	// restored to a new device, or purged after 270 days of device
	// inactivity. It is permanent for this token string - only the app
	// minting a fresh token (deleteToken + getToken) recovers, so the
	// row is kept as the signal that tells the app to do exactly that
	// on its next subscribe. Cleared if a send ever succeeds again.
	Unregistered   bool   `json:"unregistered,omitempty"`
	UnregisteredAt string `json:"unregistered_at,omitempty"`
	IPAddress      string `json:"ip_address,omitempty"`
	UserAgent      string `json:"user_agent,omitempty"`
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

	// Fleet coverage: when the whole fleet goes dark, nothing at all is
	// being monitored, and the phones must hear about it even though no
	// individual host transitions (they all just go stale).
	fleetDarkSince    time.Time
	fleetDarkNotified bool
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
// run. Callers should treat this as "push is unavailable" - typically a
// 503 - not as a permanent failure of the request itself.
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
		// platform "fcm" - rewrite those to "android" (notifyAll fans out
		// by platform, so they were silently undeliverable). Anything
		// else unrecognized (or unparseable) is unroutable garbage with
		// no upgrade path: delete it - the app re-subscribes on every
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
	// independent of the enabled flag - a stored-but-disabled key still
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
// - every link in the chain from the enable switch to the last actual
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
//  2. Wait for the watcher goroutine to finish - the watcher's bolt
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

// Subscribe registers (or refreshes) a device subscription. tokenDead
// reports whether FCM has already refused this exact token with
// UNREGISTERED: re-storing the same string doesn't resurrect it, so the
// caller must relay that verdict to the app - the phone's Firebase SDK
// is the one party that doesn't know its cached token is dead, and only
// the app can mint a fresh one.
func (s *Service) Subscribe(token string, platform Platform, label, owner, ipAddr, userAgent string) (apiKey string, tokenDead bool, err error) {
	s.opsMu.RLock()
	defer s.opsMu.RUnlock()
	if s.stopped {
		return "", false, ErrServiceStopped
	}
	if platform != PlatformIOS && platform != PlatformAndroid {
		return "", false, fmt.Errorf("platform must be 'ios' or 'android'")
	}
	if token == "" {
		return "", false, fmt.Errorf("device_token is required")
	}

	now := time.Now().UTC().Format(time.RFC3339)

	err = s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketSubscriptions)

		var sub Subscription

		// Preserve existing data on re-subscribe.
		ownerChanged := false
		if existing := b.Get([]byte(token)); existing != nil {
			json.Unmarshal(existing, &sub)
			// A device token is a per-install secret held by whoever
			// physically has the app. When a different account signs in
			// on the same device it legitimately takes the token over -
			// the previous owner logged out. (There's no hijack risk: the
			// push providers only deliver to the device that actually
			// holds the token, so re-registering someone else's token
			// can't redirect their notifications.) Reassign ownership
			// instead of rejecting, but rotate the API key so the prior
			// owner's key can no longer target this device.
			if sub.Owner != "" && sub.Owner != owner {
				ownerChanged = true
			}
			// The dead-token flag survives a re-subscribe of the same
			// token on purpose: UNREGISTERED is permanent for this
			// string, and reporting it back is what triggers the app's
			// renewal. A genuinely fresh token arrives under a new key
			// and starts clean.
			tokenDead = sub.Unregistered
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
	return apiKey, tokenDead, err
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
// mismatch") that the subscribers admin page surfaces per device, and
// unregistered marks FCM's permanent "token no longer exists" verdict
// (see Subscription.Unregistered). A success clears the flag - a
// delivered push is proof the token lives.
func (s *Service) RecordPush(token string, success bool, status string, unregistered bool) {
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
		now := time.Now().UTC().Format(time.RFC3339)
		sub.LastPushAt = now
		if success {
			sub.PushCount++
			sub.Unregistered = false
			sub.UnregisteredAt = ""
		} else {
			sub.FailCount++
			if unregistered && !sub.Unregistered {
				sub.Unregistered = true
				sub.UnregisteredAt = now
			}
		}
		sub.LastPushStatus = status
		data, _ := json.Marshal(sub)
		return b.Put([]byte(token), data)
	})
}

// isUnregistered reports whether a send failure was the transport's
// authoritative "this token no longer exists" verdict - FCM's
// UNREGISTERED or APNs' 410 Unregistered - the one failure that never
// heals on its own and needs the app to re-register.
func isUnregistered(err error) bool {
	var se *FCMSendError
	if errors.As(err, &se) && se.Reason == "UNREGISTERED" {
		return true
	}
	var ae *APNsSendError
	return errors.As(err, &ae) && ae.Reason == "Unregistered"
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
	var ae *APNsSendError
	if errors.As(err, &ae) {
		switch ae.Reason {
		case "Unregistered":
			return "failed: token dead"
		case "BadDeviceToken":
			return "failed: bad device token (env mismatch?)"
		}
		if ae.Reason != "" {
			return "failed: " + strings.ToLower(ae.Reason)
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

// getSubscription looks up one subscription row by device token.
func (s *Service) getSubscription(token string) (sub Subscription, ok bool) {
	s.opsMu.RLock()
	defer s.opsMu.RUnlock()
	if s.stopped {
		return Subscription{}, false
	}
	s.db.View(func(tx *bolt.Tx) error {
		if v := tx.Bucket(bucketSubscriptions).Get([]byte(token)); v != nil {
			ok = json.Unmarshal(v, &sub) == nil
		}
		return nil
	})
	return sub, ok
}

// GetPlatform returns the platform of the subscription with the given token,
// or empty string if not found.
func (s *Service) GetPlatform(token string) Platform {
	sub, _ := s.getSubscription(token)
	return sub.Platform
}

// IsOwner checks if the given user owns the subscription with the given token.
func (s *Service) IsOwner(token, owner string) bool {
	sub, ok := s.getSubscription(token)
	return ok && sub.Owner == owner
}

func (s *Service) SendTest(token string, platform Platform) error {
	err := func() error {
		s.opsMu.RLock()
		defer s.opsMu.RUnlock()
		if s.stopped {
			return ErrServiceStopped
		}
		return s.sendToDevice(token, platform, "sysmon test", "", "push notifications are working")
	}()
	if errors.Is(err, ErrServiceStopped) {
		return err
	}
	if err != nil {
		var kr *KeyRejectedError
		if errors.As(err, &kr) {
			s.kickKeyCheck()
		}
	}

	// Tests used to be invisible - they bypassed both the per-device
	// stats and the push log, so "the log never shows the test button"
	// read as "tests don't reach the server". Record them like any
	// other send, marked as tests. (Outside the RLock above: RecordPush
	// and appendPushLog take their own, and recursive RLock can
	// deadlock against a queued Stop.)
	status := "ok (test)"
	sent := 1
	if err != nil {
		status = pushFailStatus(err) + " (test)"
		sent = 0
	}
	s.RecordPush(token, err == nil, status, isUnregistered(err))
	target := token
	if len(target) > 12 {
		target = target[:12] + "…"
	}
	// "Who was this sent to" is the question the log answers, and a
	// person is a better answer than a token prefix - the prefix stays
	// for telling one of their devices from another.
	if sub, ok := s.getSubscription(token); ok && sub.Owner != "" {
		target = sub.Owner + " (" + target + ")"
	}
	s.appendPushLog(pushLogEntry{
		Timestamp:  time.Now().UTC().Format(time.RFC3339),
		Hostname:   "Test push → " + target,
		Status:     "TEST",
		Recipients: sent,
	})
	return err
}

// appendPushLog writes an entry to the push log bucket, guarded against
// a concurrent Stop.
func (s *Service) appendPushLog(entry pushLogEntry) {
	s.opsMu.RLock()
	defer s.opsMu.RUnlock()
	if s.stopped {
		return
	}
	if data, err := json.Marshal(entry); err == nil {
		s.db.Update(func(tx *bolt.Tx) error {
			b := tx.Bucket(bucketPushLog)
			id, _ := b.NextSequence()
			return b.Put([]byte(fmt.Sprintf("%010d", id)), data)
		})
	}
}

func (s *Service) subscriberCount() int {
	count := 0
	s.db.View(func(tx *bolt.Tx) error {
		count = tx.Bucket(bucketSubscriptions).Stats().KeyN
		return nil
	})
	return count
}

// looksLikeAPNsToken distinguishes a raw APNs device token (hex-encoded
// bytes, as registered by Firebase-less iOS builds) from an FCM
// registration token. One deployment can hold both kinds at once - some
// installs built with a GoogleService-Info.plist, some without - so the
// send path routes each token to the transport that can actually
// deliver to it instead of assuming every iOS token is whatever the
// server has configured.
//
// The test is shape, not size: Apple explicitly documents the token
// length as variable (it has grown before), so hardcoding today's 32
// bytes would silently misroute every raw-APNs device the day it grows
// again. FCM registration tokens always carry non-hex structure (a ':'
// separator at minimum), so pure hex of plausible byte-encoded length
// can only be an APNs token.
func looksLikeAPNsToken(token string) bool {
	if len(token) < 32 || len(token)%2 != 0 {
		return false
	}
	for _, c := range token {
		switch {
		case c >= '0' && c <= '9', c >= 'a' && c <= 'f', c >= 'A' && c <= 'F':
		default:
			return false
		}
	}
	return true
}

func (s *Service) sendToDevice(token string, platform Platform, title, subtitle, body string) error {
	fcm, apns, _ := s.clients()
	// Test pushes present as critical so the full sound/heads-up path is
	// what gets verified.
	const critical = true
	const collapse = "sysmon-test"
	switch platform {
	case PlatformIOS:
		// Firebase-first: with FCM configured, iOS devices register FCM
		// tokens and Firebase relays to APNs (auth key uploaded once in
		// the Firebase console, never expires). Direct cert-based APNs
		// serves Firebase-less deployments - and, by token shape, the
		// individual devices running a Firebase-less build even when FCM
		// is configured (see looksLikeAPNsToken).
		if apns != nil && (fcm == nil || looksLikeAPNsToken(token)) {
			return apns.Send(token, title, subtitle, body, nil, critical, collapse)
		}
		if fcm != nil {
			return fcm.Send(token, title, subtitle, body, nil, fcmData{}, critical, collapse)
		}
		return fmt.Errorf("no iOS push transport configured (FCM or APNs)")
	case PlatformAndroid:
		if fcm == nil {
			return fmt.Errorf("FCM not configured")
		}
		return fcm.Send(token, title, "", body, nil, fcmData{}, critical, collapse)
	default:
		return fmt.Errorf("unknown platform: %s", platform)
	}
}

// critical drives sound/heads-up vs silent delivery; data.Object (the
// object name) doubles as the collapse key, making newer notifications
// for a host replace older ones, so a WARN vanishes when the CRIT or
// the recovery arrives. data's Details/Related figures are already part
// of body; they repeat as data fields for the apps.
func (s *Service) notifyAll(title, subtitle, body string, data fcmData, prevStatus string, badge int, critical bool) {
	// Snapshot the clients once so a concurrent Reconfigure can't swap
	// them mid-fan-out, and so we don't hold a lock across slow sends.
	fcm, apns, _ := s.clients()
	subs := s.ListSubscriptions()
	sent := 0
	badgePtr := &badge

	hostname, status, collapseKey := data.Hostname, data.Status, data.Object
	for _, sub := range subs {
		// FCM already refused this token with UNREGISTERED - permanent
		// for this string, so every further send is a guaranteed
		// failure (and, per Google, exactly the traffic a sender is
		// supposed to stop). The row stays: the admin page shows it,
		// and the app's next subscribe of this token gets told to mint
		// a fresh one - test pushes still go through, so a wrongly
		// flagged token clears itself on the first success.
		if sub.Unregistered {
			log.Printf("push: skipping %s/%s - token unregistered since %s, awaiting app renewal",
				sub.Platform, sub.Label, sub.UnregisteredAt)
			continue
		}
		var err error
		skipped := false
		switch sub.Platform {
		case PlatformIOS:
			// Firebase-first, direct APNs for Firebase-less deployments
			// and for individual raw-APNs tokens - see sendToDevice.
			if apns != nil && (fcm == nil || looksLikeAPNsToken(sub.DeviceToken)) {
				err = apns.Send(sub.DeviceToken, title, subtitle, body, badgePtr, critical, collapseKey)
			} else if fcm != nil {
				err = fcm.Send(sub.DeviceToken, title, subtitle, body, badgePtr, data, critical, collapseKey)
			} else {
				skipped = true
			}
		case PlatformAndroid:
			if fcm != nil {
				err = fcm.Send(sub.DeviceToken, title, "", body, nil, data, critical, collapseKey)
			} else {
				skipped = true
			}
		default:
			// Can't happen after the boot-time migration (Subscribe
			// rejects anything but ios/android) - but never fail silent.
			log.Printf("push: WARNING: subscription %q has unknown platform %q - not delivered", sub.Label, sub.Platform)
			continue
		}
		if skipped {
			continue
		}
		if err != nil {
			s.RecordPush(sub.DeviceToken, false, pushFailStatus(err), isUnregistered(err))
			log.Printf("push: send to %s/%s failed: %v", sub.Platform, sub.Label, err)
			// An auth-level refusal means the key itself died - flip the
			// settings-panel key status now instead of at the next hourly
			// check.
			var kr *KeyRejectedError
			if errors.As(err, &kr) {
				s.kickKeyCheck()
			}
		} else {
			s.RecordPush(sub.DeviceToken, true, "ok", false)
			sent++
		}
	}

	s.mu.Lock()
	s.lastPushAt = time.Now().UTC()
	s.lastPushInfo = fmt.Sprintf("%s (%s → %s): %d recipient(s)", hostname, prevStatus, status, sent)
	s.mu.Unlock()

	s.appendPushLog(pushLogEntry{
		Timestamp:  time.Now().UTC().Format(time.RFC3339),
		Hostname:   hostname,
		Status:     status,
		PrevStatus: prevStatus,
		Recipients: sent,
	})
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

// fleetDarkDwell is how long the fleet must stay entirely dark before
// the loud push goes out. A daemon restarting after a config delivery
// drops its agent link for a moment; paging for that would teach
// everyone to ignore the page that matters.
const fleetDarkDwell = 30 * time.Second

// fleetCoverageChange updates the dark-fleet state for one poll and
// returns what, if anything, should be pushed. Callers hold s.mu.
func (s *Service) fleetCoverageChange(total, reachable int, now time.Time) (title, body string, critical, send bool) {
	dark := total > 0 && reachable == 0
	if dark {
		if s.fleetDarkSince.IsZero() {
			s.fleetDarkSince = now
		}
		if !s.fleetDarkNotified && now.Sub(s.fleetDarkSince) >= fleetDarkDwell {
			s.fleetDarkNotified = true
			plural := ""
			if total != 1 {
				plural = "s"
			}
			return "MONITORING DEGRADED",
				fmt.Sprintf("No monitoring daemon is reporting to sysmon-web - %d site%s dark. Hosts are not being watched.", total, plural),
				true, true
		}
		return "", "", false, false
	}
	wasNotified := s.fleetDarkNotified
	s.fleetDarkSince = time.Time{}
	s.fleetDarkNotified = false
	if wasNotified {
		return "MONITORING RESTORED",
			fmt.Sprintf("%d of %d site(s) reporting again.", reachable, total),
			false, true
	}
	return "", "", false, false
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
		if strings.ToUpper(h.OverallStatus) != "OK" && !h.Acked {
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

	// Fleet coverage is its own signal: hosts keep their last state
	// (flagged stale) when the fleet goes dark, so the per-host loop
	// above sees no transitions. The state tracking runs even when push
	// is disabled, like prevHosts, so enabling later starts from now
	// rather than replaying the past.
	s.mu.Lock()
	fleetTitle, fleetBody, fleetCritical, fleetSend := s.fleetCoverageChange(
		status.SitesTotal, status.SitesReachable, time.Now())
	s.mu.Unlock()

	// If push is disabled or unconfigured we still updated prevHosts
	// above, so the baseline stays current and re-enabling later doesn't
	// replay a backlog of stale state changes - we just don't send.
	_, _, enabled := s.clients()
	if !enabled {
		return
	}
	for _, c := range changes {
		s.sendStateChange(c.host, c.prevStatus, badge, relatedDetail(status.Hosts, c.host))
	}
	if fleetSend {
		st := "DEGRADED"
		if !fleetCritical {
			st = "OK"
		}
		log.Printf("push: fleet coverage %s - notifying subscribers", st)
		s.notifyAll(fleetTitle, "", fleetBody, fcmData{
			Hostname: "sysmon-web",
			Object:   "fleet-coverage",
			Status:   st,
		}, "", badge, fleetCritical)
	}
}

// ticksToUptime renders SNMP TimeTicks (1/100s) as a short human
// duration ("37d 4h", "12m").
func ticksToUptime(ticks int64) string {
	secs := ticks / 100
	d := secs / 86400
	h := (secs % 86400) / 3600
	m := (secs % 3600) / 60
	switch {
	case d > 0:
		return fmt.Sprintf("%dd %dh", d, h)
	case h > 0:
		return fmt.Sprintf("%dh %dm", h, m)
	default:
		return fmt.Sprintf("%dm", m)
	}
}

// checkDetail renders the measured figures behind a state change - "rtt
// avg 143.2ms (limit 80ms)", "loss 12.5% (8/64 lost)", "reading 52 (max
// 45)" - so the page itself says how bad it is, not just that it is.
// Empty for objects that measure nothing (plain ping/tcp checks). Sent
// on recoveries too: the current reading is the proof of health.
func checkDetail(host models.HostStatus) string {
	var parts []string
	if r := host.RTT; r != nil {
		p := fmt.Sprintf("rtt avg %.1fms", r.Avg)
		if r.Threshold > 0 {
			p += fmt.Sprintf(" (limit %dms)", r.Threshold)
		}
		parts = append(parts, p)
		if r.JitterThreshold > 0 {
			parts = append(parts, fmt.Sprintf("jitter %.1fms (limit %dms)", r.Jitter, r.JitterThreshold))
		}
		if r.Replies < r.Probes {
			parts = append(parts, fmt.Sprintf("%d/%d replies", r.Replies, r.Probes))
		}
	}
	if pl := host.PacketLoss; pl != nil {
		p := fmt.Sprintf("loss %.1f%% (%d/%d lost", pl.LossPct, pl.Lost, pl.Sent)
		if pl.Tolerance > 0 {
			p += fmt.Sprintf(", tolerance %d", pl.Tolerance)
		}
		parts = append(parts, p+")")
	}
	if sn := host.SNMP; sn != nil {
		switch sn.CheckType {
		case "reboot":
			// A reboot alert's uptime is how long ago the device came
			// back - the figure that turns "it rebooted" into "it
			// rebooted 4 minutes ago".
			if sn.SysUpTime > 0 {
				parts = append(parts, "device uptime "+ticksToUptime(sn.SysUpTime))
			}
		case "high", "low", "range", "exact":
			// "rate" is deliberately absent: its stashed value is the
			// raw counter sample, not the rate, and quoting it would
			// mislead.
			if sn.LastValue != nil {
				p := fmt.Sprintf("reading %d", *sn.LastValue)
				switch {
				case sn.CheckType == "high" && sn.High != 0:
					p += fmt.Sprintf(" (max %d)", sn.High)
				case sn.CheckType == "low" && sn.Low != 0:
					p += fmt.Sprintf(" (min %d)", sn.Low)
				case sn.CheckType == "range" && (sn.Low != 0 || sn.High != 0):
					p += fmt.Sprintf(" (range %d-%d)", sn.Low, sn.High)
				case sn.CheckType == "exact":
					p += fmt.Sprintf(" (expected %d)", sn.Exact)
				}
				parts = append(parts, p)
			}
		}
	}
	return strings.Join(parts, ", ")
}

// maxRelated caps how many sibling objects a notification quotes, so a
// heavily instrumented box doesn't overflow the payload.
const maxRelated = 3

// relatedDetail summarizes what the OTHER objects watching the same box
// last measured. A ping object can only say down/up, but its siblings -
// the rtt object, the temperature check - hold the last readings the
// fleet has for that machine, which is exactly the context a page
// should carry: "ping died, and the last rtt we saw was 44ms". Matched
// by hostname or address within the same site (private addresses reused
// across sites are different boxes). Siblings that measure nothing
// (other ping/tcp objects) are skipped; a sibling that is itself
// failing says so.
func relatedDetail(all []models.HostStatus, h models.HostStatus) string {
	selfKey := h.ObjectName
	if selfKey == "" {
		selfKey = h.Hostname
	}
	var parts []string
	extra := 0
	for i := range all {
		o := &all[i]
		key := o.ObjectName
		if key == "" {
			key = o.Hostname
		}
		if key == selfKey || o.Site != h.Site {
			continue
		}
		sameBox := (h.Hostname != "" && strings.EqualFold(o.Hostname, h.Hostname)) ||
			(h.IPv4Address != "" && o.IPv4Address == h.IPv4Address) ||
			(h.IPv6Address != "" && o.IPv6Address == h.IPv6Address)
		if !sameBox {
			continue
		}
		d := checkDetail(*o)
		if d == "" {
			continue
		}
		if len(parts) >= maxRelated {
			extra++
			continue
		}
		if st := strings.ToUpper(o.OverallStatus); st != "" && st != "OK" {
			d += " [" + st + "]"
		}
		name := o.LocalName
		if name == "" {
			name = key
		}
		parts = append(parts, name+" "+d)
	}
	if extra > 0 {
		parts = append(parts, fmt.Sprintf("+%d more", extra))
	}
	return strings.Join(parts, "; ")
}

func (s *Service) sendStateChange(host models.HostStatus, prevStatus string, badge int, related string) {
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

	// The measurements behind the transition ride in the visible body -
	// the alert should say HOW down, not just that it is - and again as
	// data fields for the apps to use programmatically. The sibling
	// objects' last readings follow the host's own.
	detail := checkDetail(host)
	if detail != "" {
		body += " - " + detail
	}
	if related != "" {
		body += " - also: " + related
	}

	log.Printf("push: %s status %s -> %s, notifying subscribers",
		host.Hostname, prevStatus, host.OverallStatus)

	critical := strings.ToUpper(host.OverallStatus) == "CRITICAL"
	collapseKey := host.ObjectName
	if collapseKey == "" {
		collapseKey = host.Hostname
	}
	s.notifyAll(title, subtitle, body, fcmData{
		Hostname: host.Hostname,
		Object:   collapseKey,
		Status:   host.OverallStatus,
		Type:     checkType,
		Details:  detail,
		Related:  related,
	}, prevStatus, badge, critical)
}
