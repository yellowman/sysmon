package push

import (
	"database/sql"
	"fmt"
	"log"
	"strings"
	"sync"
	"time"

	_ "modernc.org/sqlite"

	"sysmon-web/internal/models"
	"sysmon-web/internal/monitoring"
)

type Platform string

const (
	PlatformIOS     Platform = "ios"
	PlatformAndroid Platform = "android"
)

type Subscription struct {
	DeviceToken string   `json:"device_token"`
	Platform    Platform `json:"platform"`
	Label       string   `json:"label,omitempty"`
	CreatedAt   string   `json:"created_at"`
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
	db     *sql.DB

	apns *APNsClient
	fcm  *FCMClient

	monitoring *monitoring.Service
	prevHosts  map[string]string
	stopCh     chan struct{}
}

func NewService(cfg Config, dbPath string, mon *monitoring.Service) (*Service, error) {
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return nil, fmt.Errorf("open push database: %w", err)
	}

	if _, err := db.Exec(`
		CREATE TABLE IF NOT EXISTS subscriptions (
			device_token TEXT PRIMARY KEY,
			platform     TEXT NOT NULL CHECK(platform IN ('ios','android')),
			label        TEXT NOT NULL DEFAULT '',
			created_at   TEXT NOT NULL DEFAULT (datetime('now'))
		);
		CREATE TABLE IF NOT EXISTS push_log (
			id         INTEGER PRIMARY KEY AUTOINCREMENT,
			timestamp  TEXT NOT NULL DEFAULT (datetime('now')),
			hostname   TEXT NOT NULL,
			status     TEXT NOT NULL,
			prev_status TEXT NOT NULL,
			recipients INTEGER NOT NULL DEFAULT 0,
			error      TEXT
		);
	`); err != nil {
		db.Close()
		return nil, fmt.Errorf("init push database: %w", err)
	}

	s := &Service{
		config:    cfg,
		db:        db,
		monitoring: mon,
		prevHosts: make(map[string]string),
		stopCh:    make(chan struct{}),
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
	go s.watchLoop()
	log.Printf("push: state change watcher started (1s poll interval)")
}

func (s *Service) Stop() {
	close(s.stopCh)
	if s.db != nil {
		s.db.Close()
	}
}

func (s *Service) Subscribe(token string, platform Platform, label string) error {
	if platform != PlatformIOS && platform != PlatformAndroid {
		return fmt.Errorf("platform must be 'ios' or 'android'")
	}
	if token == "" {
		return fmt.Errorf("device_token is required")
	}

	_, err := s.db.Exec(
		`INSERT INTO subscriptions (device_token, platform, label) VALUES (?, ?, ?)
		 ON CONFLICT(device_token) DO UPDATE SET platform=excluded.platform, label=excluded.label`,
		token, string(platform), label,
	)
	if err != nil {
		return fmt.Errorf("subscribe: %w", err)
	}
	return nil
}

func (s *Service) Unsubscribe(token string) error {
	res, err := s.db.Exec(`DELETE FROM subscriptions WHERE device_token = ?`, token)
	if err != nil {
		return fmt.Errorf("unsubscribe: %w", err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return fmt.Errorf("device token not found")
	}
	return nil
}

func (s *Service) ListSubscriptions() []Subscription {
	rows, err := s.db.Query(`SELECT device_token, platform, label, created_at FROM subscriptions ORDER BY created_at`)
	if err != nil {
		log.Printf("push: list subscriptions: %v", err)
		return nil
	}
	defer rows.Close()

	var subs []Subscription
	for rows.Next() {
		var sub Subscription
		if err := rows.Scan(&sub.DeviceToken, &sub.Platform, &sub.Label, &sub.CreatedAt); err != nil {
			continue
		}
		subs = append(subs, sub)
	}
	return subs
}

func (s *Service) SendTest(token string, platform Platform) error {
	return s.sendToDevice(token, platform, "sysmon test", "", "push notifications are working")
}

func (s *Service) subscriberCount() int {
	var count int
	s.db.QueryRow(`SELECT COUNT(*) FROM subscriptions`).Scan(&count)
	return count
}

func (s *Service) sendToDevice(token string, platform Platform, title, subtitle, body string) error {
	switch platform {
	case PlatformIOS:
		if s.apns == nil {
			return fmt.Errorf("APNs not configured")
		}
		return s.apns.Send(token, title, subtitle, body)
	case PlatformAndroid:
		if s.fcm == nil {
			return fmt.Errorf("FCM not configured")
		}
		return s.fcm.Send(token, title, body, fcmData{})
	default:
		return fmt.Errorf("unknown platform: %s", platform)
	}
}

func (s *Service) notifyAll(title, subtitle, body, hostname, status, checkType string) {
	subs := s.ListSubscriptions()
	sent := 0

	for _, sub := range subs {
		var err error
		switch sub.Platform {
		case PlatformIOS:
			if s.apns != nil {
				err = s.apns.Send(sub.DeviceToken, title, subtitle, body)
			}
		case PlatformAndroid:
			if s.fcm != nil {
				data := fcmData{
					Hostname: hostname,
					Status:   status,
					Type:     checkType,
				}
				err = s.fcm.Send(sub.DeviceToken, title, body, data)
			}
		}
		if err != nil {
			log.Printf("push: send to %s/%s failed: %v", sub.Platform, sub.Label, err)
		} else {
			sent++
		}
	}

	s.db.Exec(
		`INSERT INTO push_log (hostname, status, prev_status, recipients) VALUES (?, ?, ?, ?)`,
		hostname, status, "", sent,
	)
}

func (s *Service) watchLoop() {
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	s.pollAndNotify(true)

	for {
		select {
		case <-ticker.C:
			s.pollAndNotify(false)
		case <-s.stopCh:
			return
		}
	}
}

func (s *Service) pollAndNotify(initialSeed bool) {
	status, err := s.monitoring.GetStatus()
	if err != nil {
		return
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
		s.sendStateChange(c.host, c.prevStatus)
	}
}

func (s *Service) sendStateChange(host models.HostStatus, prevStatus string) {
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

	s.notifyAll(title, subtitle, body, host.Hostname, host.OverallStatus, checkType)
}
