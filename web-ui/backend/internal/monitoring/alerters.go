package monitoring

import (
	"bufio"
	"fmt"
	"log"
	"net"
	"sort"
	"strings"
	"sync"
	"time"
	"unicode/utf8"
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

// maxAlertText bounds what one alert can put into a push notification
// and the logs, in runes. Anything longer is truncated, not refused -
// the alert still matters even when its author was verbose.
const maxAlertText = 512

// maxLineBytes bounds one protocol line. An alerter is deliberately the
// lower-trust peer class, and a line is read before it is parsed - so
// the read itself must not be a way to spend this server's memory.
const maxLineBytes = 4096

// alertQueueDepth is how many alerts may wait on the push pipeline
// before new ones are dropped (loudly). Alerts are rare and the queue
// exists only to keep the protocol reply from waiting on FCM/APNs.
const alertQueueDepth = 64

// TruncateRunes cuts s to at most n runes, never splitting one - a cut
// at a byte offset turns multi-byte text into U+FFFD garbage downstream.
func TruncateRunes(s string, n int) string {
	if utf8.RuneCountInString(s) <= n {
		return s
	}
	return string([]rune(s)[:n])
}

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
	// Pointers, not values: omitempty never omits a struct, and a
	// year-1 timestamp on an alerter that has not alerted yet is worse
	// than no field.
	LastSeen    *time.Time `json:"last_seen,omitempty"`
	LastAlertAt *time.Time `json:"last_alert_at,omitempty"`
	LastAlert   string     `json:"last_alert,omitempty"` // "CRITICAL tape: jam in drive 2"
	Alerts      uint64     `json:"alerts"`
}

type alerter struct {
	mu   sync.Mutex
	info AlerterInfo
	conn net.Conn
}

// pendingAlert is one parsed alert waiting on the push pipeline.
type pendingAlert struct {
	source, display, object, status, text string
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

// Alerters lists every alerter seen since this process started, by
// name. Disconnected ones stay listed: "it was here and left" is
// information, and the record is only memory.
func (s *Service) Alerters() []AlerterInfo {
	s.alertersMu.Lock()
	defer s.alertersMu.Unlock()
	out := make([]AlerterInfo, 0, len(s.alerters))
	for _, a := range s.alerters {
		a.mu.Lock()
		out = append(out, a.info)
		a.mu.Unlock()
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// readLineBounded returns the next line, holding at most maxLineBytes
// of it in memory - the rest of an overlong line is read and discarded,
// never buffered. One hostile line costs at most its own truncation,
// not the server's memory.
func readLineBounded(r *bufio.Reader) (string, error) {
	var buf []byte
	for {
		chunk, isPrefix, err := r.ReadLine()
		if err != nil {
			return "", err
		}
		if len(buf) < maxLineBytes {
			take := maxLineBytes - len(buf)
			if take > len(chunk) {
				take = len(chunk)
			}
			buf = append(buf, chunk[:take]...)
		}
		if !isPrefix {
			return string(buf), nil
		}
	}
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
//
// Delivery is decoupled from the reply: a push fan-out can take tens of
// seconds against a slow provider, and holding the 333 back that long
// makes a well-behaved client time out, reconnect, and resend the same
// page. One dispatcher goroutine per connection keeps alerts in order;
// it drains what is queued even after the connection drops.
func (s *Service) runAlerter(name, application, remote string, conn net.Conn, reader *bufio.Reader) {
	a := s.registerAlerter(name, application, remote, conn)

	pending := make(chan pendingAlert, alertQueueDepth)
	go func() {
		for p := range pending {
			if sink := s.alertSinkFn(); sink != nil {
				sink(p.source, p.display, p.object, p.status, p.text)
			} else {
				log.Printf("agents: alerter %s sent %s %s with no push service configured - dropped",
					p.source, p.status, p.object)
			}
		}
	}()

	defer func() {
		conn.Close()
		close(pending)
		// A reconnect replaces this connection on the shared record
		// before this goroutine notices its read failing - only the
		// record's CURRENT connection may declare it disconnected, or
		// the replacement is immediately (and permanently) shown gone.
		a.mu.Lock()
		mine := a.conn == conn
		if mine {
			a.info.Connected = false
		}
		a.mu.Unlock()
		if mine {
			log.Printf("agents: alerter %s (%s) disconnected", name, remote)
		}
	}()

	for {
		line, err := readLineBounded(reader)
		if err != nil {
			return
		}
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		now := time.Now().UTC()
		a.mu.Lock()
		a.info.LastSeen = &now
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
			if msg := s.handleAlertLine(a, name, line, pending); msg == "" {
				fmt.Fprintf(conn, "333 ok\r\n")
			} else {
				fmt.Fprintf(conn, "444 %s\r\n", msg)
			}
		default:
			fmt.Fprintf(conn, "444 unknown command (ALERT/PING/QUIT)\r\n")
		}
	}
}

// handleAlertLine parses "ALERT <status> <object> <text...>" and queues
// it for delivery. Returns "" on success, else the complaint for the 444.
func (s *Service) handleAlertLine(a *alerter, name, line string, pending chan<- pendingAlert) string {
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
		text = TruncateRunes(strings.TrimSpace(fields[3]), maxAlertText)
	}
	if text == "" {
		text = fmt.Sprintf("%s reports %s %s", name, object, status)
	}

	now := time.Now().UTC()
	a.mu.Lock()
	a.info.Alerts++
	a.info.LastAlertAt = &now
	a.info.LastAlert = fmt.Sprintf("%s %s: %s", status, object, text)
	a.mu.Unlock()

	p := pendingAlert{
		source:  name,
		display: s.alerterDisplayName(a),
		object:  object,
		status:  status,
		text:    text,
	}
	select {
	case pending <- p:
	default:
		// The push pipeline is badly backed up. Dropping the newest
		// (loudly) beats blocking the protocol - the client's resend
		// on reconnect would duplicate everything anyway.
		log.Printf("agents: alerter %s: delivery queue full - dropping %s %s", name, status, object)
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
