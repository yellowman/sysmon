package push

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"sync"
	"time"

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
	CreatedAt   time.Time `json:"created_at"`
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
	mu            sync.RWMutex
	config        Config
	subscriptions []Subscription
	storeFile     string

	apns *APNsClient
	fcm  *FCMClient

	monitoring *monitoring.Service
	prevHosts  map[string]string // hostname -> last known status
	stopCh     chan struct{}
}

func NewService(cfg Config, storeFile string, mon *monitoring.Service) (*Service, error) {
	s := &Service{
		config:     cfg,
		storeFile:  storeFile,
		monitoring: mon,
		prevHosts:  make(map[string]string),
		stopCh:     make(chan struct{}),
	}

	if err := s.loadSubscriptions(); err != nil {
		log.Printf("push: no existing subscriptions file (%s), starting fresh", err)
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
	log.Printf("push: state change watcher started")
}

func (s *Service) Stop() {
	close(s.stopCh)
}

func (s *Service) Subscribe(token string, platform Platform, label string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	for _, sub := range s.subscriptions {
		if sub.DeviceToken == token {
			return fmt.Errorf("device already subscribed")
		}
	}

	if platform != PlatformIOS && platform != PlatformAndroid {
		return fmt.Errorf("platform must be 'ios' or 'android'")
	}

	s.subscriptions = append(s.subscriptions, Subscription{
		DeviceToken: token,
		Platform:    platform,
		Label:       label,
		CreatedAt:   time.Now(),
	})

	return s.saveSubscriptions()
}

func (s *Service) Unsubscribe(token string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	for i, sub := range s.subscriptions {
		if sub.DeviceToken == token {
			s.subscriptions = append(s.subscriptions[:i], s.subscriptions[i+1:]...)
			return s.saveSubscriptions()
		}
	}
	return fmt.Errorf("device token not found")
}

func (s *Service) ListSubscriptions() []Subscription {
	s.mu.RLock()
	defer s.mu.RUnlock()

	result := make([]Subscription, len(s.subscriptions))
	copy(result, s.subscriptions)
	return result
}

func (s *Service) SendTest(token string, platform Platform) error {
	return s.sendToDevice(token, platform, "sysmon test", "", "push notifications are working")
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
	s.mu.RLock()
	subs := make([]Subscription, len(s.subscriptions))
	copy(subs, s.subscriptions)
	s.mu.RUnlock()

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
		}
	}
}

func (s *Service) watchLoop() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	// Seed initial state
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
		prevStatus, known := s.prevHosts[host.Hostname]
		s.prevHosts[host.Hostname] = host.OverallStatus

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

	switch host.OverallStatus {
	case "critical", "down":
		title = fmt.Sprintf("%s DOWN", host.Hostname)
		if host.Description != "" {
			subtitle = host.Description
		}
		body = fmt.Sprintf("%s is unreachable", host.Hostname)
		if checkType != "" {
			body = fmt.Sprintf("%s %s check failed", host.Hostname, checkType)
		}
	case "healthy", "up", "ok":
		title = fmt.Sprintf("%s RECOVERED", host.Hostname)
		if host.Description != "" {
			subtitle = host.Description
		}
		body = fmt.Sprintf("%s is back up (was %s)", host.Hostname, prevStatus)
	default:
		title = fmt.Sprintf("%s %s", host.Hostname, host.OverallStatus)
		body = fmt.Sprintf("status changed from %s to %s", prevStatus, host.OverallStatus)
	}

	log.Printf("push: %s status %s -> %s, notifying %d subscribers",
		host.Hostname, prevStatus, host.OverallStatus, len(s.subscriptions))

	s.notifyAll(title, subtitle, body, host.Hostname, host.OverallStatus, checkType)
}

func (s *Service) loadSubscriptions() error {
	data, err := os.ReadFile(s.storeFile)
	if err != nil {
		return err
	}
	return json.Unmarshal(data, &s.subscriptions)
}

func (s *Service) saveSubscriptions() error {
	data, err := json.MarshalIndent(s.subscriptions, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(s.storeFile, data, 0600)
}
