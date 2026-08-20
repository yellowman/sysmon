package monitoring

import (
	"bufio"
	"fmt"
	"log"
	"net"
	"strings"
	"sync"
	"time"
)

// Alerters: peers that are not sysmond.
//
// A backup job, a UPS script, a cron watchdog - things with something to
// say and no fleet of hosts behind them. They authenticate exactly like a
// monitoring box (one minted token, same TLS listener) but greet with
// ALERTER instead of HELLO, and from then on the conversation is inverted:
// nothing is polled, the peer just sends alerts and they ride the same
// push pipeline with the same priorities a sysmond's transitions do.
// They are never part of the fleet - no config, no hosts, no generations -
// just alerters that share the web UI's delivery machinery.
//
// The protocol is documented for implementors in docs/ALERTERS.md; the
// two files must agree.

// maxAlertText bounds what one line can put into a push notification and
// the logs. Anything longer is truncated, not refused - the alert still
// matters even when its author was verbose.
const maxAlertText = 512

// AlerterInfo is one alert-only peer, as the UI shows it.
type AlerterInfo struct {
	Name string `json:"name"`
	// Application is what the peer says it is - free text from its
	// handshake ("Bacula 15.0 nightly backups"). The name identifies;
	// this describes.
	Application string `json:"application,omitempty"`
	// Nickname is the operator's optional label for this alerter, from
	// the minted token's record. Filled in by the API layer; alerts
	// prefer it over Application when both exist.
	Nickname    string    `json:"nickname,omitempty"`
	Addr        string    `json:"addr"`
	Connected   bool      `json:"connected"`
	ConnectedAt time.Time `json:"connected_at"`
	LastSeen    time.Time `json:"last_seen,omitempty"`
	LastAlertAt time.Time `json:"last_alert_at,omitempty"`
	LastAlert   string    `json:"last_alert,omitempty"` // "CRITICAL tape: jam in drive 2"
	Alerts      uint64    `json:"alerts"`
}

type alerter struct {
	mu   sync.Mutex
	info AlerterInfo
	conn net.Conn
}

// alerterDisplayName is what an alert shows as its sender: the
// operator's nickname (the minted token's label) when one is set, else
// what the application calls itself, else the token name. The token
// name stays the identity everywhere - collapse keys, logs, the
// registry - a rename must never re-key anything.
func (s *Service) alerterDisplayName(a *alerter) string {
	a.mu.Lock()
	name, app := a.info.Name, a.info.Application
	a.mu.Unlock()
	if st := s.Generations(); st != nil {
		if tok, ok := st.GetAgentToken(name); ok && tok.Label != "" {
			return tok.Label
		}
	}
	if app != "" {
		return app
	}
	return name
}

// SetAlertSink names the function alerter traffic is delivered to -
// in practice push.Service.ExternalAlert, re-pointed whenever the push
// service is hot-swapped. Nil means alerts are acknowledged and dropped,
// which is correct for a deployment that has not configured push.
func (s *Service) SetAlertSink(fn func(source, display, object, status, text string)) {
	s.alertSinkMu.Lock()
	s.alertSink = fn
	s.alertSinkMu.Unlock()
}

func (s *Service) alertSinkFn() func(source, display, object, status, text string) {
	s.alertSinkMu.Lock()
	defer s.alertSinkMu.Unlock()
	return s.alertSink
}

// Alerters lists every alerter seen since this process started, newest
// connection first. Disconnected ones stay listed: "it was here and
// left" is information, and the record is only memory.
func (s *Service) Alerters() []AlerterInfo {
	s.alertersMu.Lock()
	defer s.alertersMu.Unlock()
	out := make([]AlerterInfo, 0, len(s.alerters))
	for _, a := range s.alerters {
		a.mu.Lock()
		out = append(out, a.info)
		a.mu.Unlock()
	}
	// Stable order for the page: by name.
	for i := 1; i < len(out); i++ {
		for j := i; j > 0 && out[j].Name < out[j-1].Name; j-- {
			out[j], out[j-1] = out[j-1], out[j]
		}
	}
	return out
}

// runAlerter owns an authenticated alerter connection until it drops.
// Called from the listener's handshake goroutine; blocks for the life
// of the connection.
//
// The wire protocol, one CRLF (or LF) line per exchange:
//
//	-> ALERT <CRITICAL|WARNING|OK> <object> <text...>
//	<- 333 ok
//	-> PING
//	<- 333 pong
//	-> QUIT
//	<- 333 bye
//
// Anything else answers 444 without closing the connection - one bad
// line should not cost an alerter its link.
func (s *Service) runAlerter(name, application, remote string, conn net.Conn, reader *bufio.Reader) {
	a := s.registerAlerter(name, application, remote, conn)
	defer func() {
		conn.Close()
		a.mu.Lock()
		a.info.Connected = false
		a.mu.Unlock()
		log.Printf("agents: alerter %s (%s) disconnected", name, remote)
	}()

	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			return
		}
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		a.mu.Lock()
		a.info.LastSeen = time.Now().UTC()
		a.mu.Unlock()

		verb := line
		if i := strings.IndexByte(line, ' '); i >= 0 {
			verb = line[:i]
		}
		switch strings.ToUpper(verb) {
		case "PING":
			fmt.Fprintf(conn, "333 pong\r\n")
		case "QUIT":
			fmt.Fprintf(conn, "333 bye\r\n")
			return
		case "ALERT":
			if msg := s.handleAlertLine(a, name, line); msg == "" {
				fmt.Fprintf(conn, "333 ok\r\n")
			} else {
				fmt.Fprintf(conn, "444 %s\r\n", msg)
			}
		default:
			fmt.Fprintf(conn, "444 unknown command (ALERT/PING/QUIT)\r\n")
		}
	}
}

// handleAlertLine parses "ALERT <status> <object> <text...>" and hands it
// to the sink. Returns "" on success, else the complaint for the 444.
func (s *Service) handleAlertLine(a *alerter, name, line string) string {
	fields := strings.SplitN(line, " ", 4)
	if len(fields) < 3 {
		return "usage: ALERT <CRITICAL|WARNING|OK> <object> <text>"
	}
	status := strings.ToUpper(fields[1])
	switch status {
	case "CRITICAL", "WARNING", "OK":
	default:
		return "status must be CRITICAL, WARNING or OK"
	}
	object := fields[2]
	if !ValidSiteName(object) {
		return "object name: letters, digits, - and _ only, max 64"
	}
	text := ""
	if len(fields) == 4 {
		text = strings.TrimSpace(fields[3])
	}
	if len(text) > maxAlertText {
		text = text[:maxAlertText] + "…"
	}
	if text == "" {
		text = fmt.Sprintf("%s reports %s %s", name, object, status)
	}

	a.mu.Lock()
	a.info.Alerts++
	a.info.LastAlertAt = time.Now().UTC()
	a.info.LastAlert = fmt.Sprintf("%s %s: %s", status, object, text)
	a.mu.Unlock()

	if sink := s.alertSinkFn(); sink != nil {
		sink(name, s.alerterDisplayName(a), object, status, text)
	} else {
		log.Printf("agents: alerter %s sent %s %s with no push service configured - dropped", name, status, object)
	}
	return ""
}

// registerAlerter puts a connection into the registry. A name
// reconnecting replaces its old link rather than adding a second, the
// same rule adoptAgent applies to daemons.
func (s *Service) registerAlerter(name, application, remote string, conn net.Conn) *alerter {
	s.alertersMu.Lock()
	defer s.alertersMu.Unlock()
	if s.alerters == nil {
		s.alerters = make(map[string]*alerter)
	}
	if old, ok := s.alerters[name]; ok {
		old.mu.Lock()
		if old.conn != nil && old.info.Connected {
			old.conn.Close()
		}
		old.conn = conn
		old.info.Application = application
		old.info.Addr = remote
		old.info.Connected = true
		old.info.ConnectedAt = time.Now().UTC()
		old.mu.Unlock()
		return old
	}
	a := &alerter{
		conn: conn,
		info: AlerterInfo{
			Name:        name,
			Application: application,
			Addr:        remote,
			Connected:   true,
			ConnectedAt: time.Now().UTC(),
		},
	}
	s.alerters[name] = a
	return a
}
