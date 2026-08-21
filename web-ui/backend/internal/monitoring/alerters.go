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

// alertQueueDepth is how many alerts may wait on the push pipeline.
// Once an alert is committed to history it is accepted - so a full
// queue skips the phone delivery (logged) rather than refusing.
// Alerts are rare and the queue exists only to keep the protocol reply
// from waiting on FCM/APNs.
const alertQueueDepth = 64

// The ingestion rate limit: a token bucket per alerter identity. The
// history store is shared with the hosts' transitions and bounded, so
// one broken cron script looping "ALERT CRITICAL backup failed" must
// not be able to churn the whole fleet's history out of it. The burst
// covers any honest storm (a UPS narrating an outage); the refill is
// far above what a well-behaved alerter sends.
var (
	alertRateBurst  = 30.0
	alertRatePerSec = 1.0
)

// Test barriers. Nil in production; a test sets one to pin an
// interleaving that scheduling luck (and -race) cannot force - each is
// called with the alerter's name at the boundary it names. Set before
// the connection goroutine starts and cleared after it is joined.
var (
	testHookAfterParse    func(name string) // parsed + validated, before acceptance
	testHookAfterRegister func(name string) // registered, before the epoch recheck
)

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
	// acceptMu serializes alert acceptance against connection
	// replacement. An old connection that has already read a line could
	// otherwise commit its (stale) alert after the replacement's newer
	// one: acceptance takes this lock, checks its connection is still
	// the record's current one, and only then commits - and a reconnect
	// swaps the connection under the same lock, so there are exactly
	// two outcomes: the old alert commits first, or it is refused.
	acceptMu sync.Mutex
	// pending is this identity's one delivery queue, drained by one
	// goroutine for the life of the process. It belongs to the NAME,
	// not the socket: when the alerter reconnects, the replacement
	// connection feeds the same queue, so an OK sent after a reconnect
	// can never overtake a CRITICAL accepted before it - with one
	// queue and one dispatcher per socket, two dispatchers raced and
	// the collapse key could leave the phone stuck on the stale state.
	// It also caps the identity at one queue's worth of backlog, where
	// per-connection queues let every reconnect abandon another 64.
	pending chan pendingAlert
	// lastStatus remembers each object's previous status, so the
	// history row for an alert can say what it changed FROM - the same
	// transition shape host history has. Guarded by mu.
	lastStatus map[string]string
	// credID is the credential epoch the current connection
	// authenticated under; kept so registration can refuse a stale
	// epoch before touching the connection. Guarded by mu.
	credID string
	// The ingestion token bucket (see alertRateBurst). Guarded by mu.
	rateTokens float64
	rateStamp  time.Time
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
// service is hot-swapped.
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
// never buffered, and the caller is told it happened. One hostile line
// costs at most its own truncation, not the server's memory; and a
// protocol line the server did not read in full must be refused, not
// silently processed as something shorter than what was sent.
func readLineBounded(r *bufio.Reader) (line string, truncated bool, err error) {
	var buf []byte
	for {
		chunk, isPrefix, rerr := r.ReadLine()
		if rerr != nil {
			return "", false, rerr
		}
		if len(buf) < maxLineBytes {
			take := maxLineBytes - len(buf)
			if take > len(chunk) {
				take = len(chunk)
			}
			buf = append(buf, chunk[:take]...)
			if take < len(chunk) {
				truncated = true
			}
		} else if len(chunk) > 0 {
			truncated = true
		}
		if !isPrefix {
			return string(buf), truncated, nil
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
// page. The queue and its dispatcher belong to the alerter's identity
// (see registerAlerter), so a reconnect keeps one ordered stream.
//
// credID is the credential epoch this connection authenticated under;
// after registering, the credential is checked again (register first,
// re-check second - see credentialCurrent for why that order closes
// the revoke-during-handshake race).
func (s *Service) runAlerter(name, application, remote, credID string, conn net.Conn, reader *bufio.Reader) {
	a, ok := s.registerAlerter(name, application, remote, credID, conn)
	if !ok {
		// Stale epoch: refused before the registry was touched, so the
		// legitimate current connection (if any) was never disturbed.
		conn.Close()
		log.Printf("agents: alerter %s (%s): credential revoked or replaced during handshake - dropping", name, remote)
		return
	}

	defer func() {
		conn.Close()
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

	// Registered; re-check the credential for a store write that landed
	// between the in-lock check and here. The defer detaches only if
	// this connection is still the record's current one, so a stale
	// handshake failing here can never tear down a later connection.
	if hook := testHookAfterRegister; hook != nil {
		hook(name)
	}
	if !s.credentialCurrent(name, credID) {
		log.Printf("agents: alerter %s (%s): credential revoked or replaced during handshake - dropping", name, remote)
		return
	}

	for {
		line, truncated, err := readLineBounded(reader)
		if err != nil {
			return
		}
		if truncated {
			// The server did not read what the peer sent; processing
			// the readable prefix would silently accept a different
			// message. Refuse it and keep the connection.
			fmt.Fprintf(conn, "444 line too long - maximum %d bytes\r\n", maxLineBytes)
			continue
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
			if msg := s.handleAlertLine(a, name, line, conn); msg == "" {
				fmt.Fprintf(conn, "333 ok\r\n")
			} else {
				fmt.Fprintf(conn, "444 %s\r\n", msg)
			}
		default:
			fmt.Fprintf(conn, "444 unknown command (ALERT/PING/QUIT)\r\n")
		}
	}
}

// handleAlertLine parses "ALERT <status> <object> <text...>" and
// accepts it: the history write IS the acceptance boundary - it must
// commit before the 333, and push is attempted only afterwards, as the
// optional extra channel it is. conn is the connection the line arrived
// on; acceptance re-checks it is still the identity's current one, so a
// replaced connection cannot commit a stale event after its
// replacement's newer one. Returns "" on success, else the 444 text.
func (s *Service) handleAlertLine(a *alerter, name, line string, conn net.Conn) string {
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

	// The history store is the acceptance boundary: 333 means, exactly,
	// "committed to alert history". A server without one refuses -
	// push alone cannot honor the promise, and an ack that a crash can
	// erase is not an ack.
	hist := s.History()
	if hist == nil {
		return "alert history unavailable on this server - alert not accepted"
	}

	if hook := testHookAfterParse; hook != nil {
		hook(name)
	}

	// Acceptance is serialized against connection replacement AND
	// administrative disconnection (revoke/re-mint), both of which take
	// the same lock and invalidate a.conn: a connection that already
	// parsed a line either commits it here before it was replaced or
	// cut off, or finds itself no longer current and is refused - never
	// commits after a revocation has returned or after a replacement's
	// newer event.
	a.acceptMu.Lock()
	defer a.acceptMu.Unlock()
	a.mu.Lock()
	current := a.conn == conn
	prev := a.lastStatus[object]
	// The ingestion bucket refills continuously up to the burst; an
	// empty bucket refuses BEFORE anything commits, so a flooding
	// alerter cannot churn the fleet's shared history out of the store.
	now := time.Now()
	a.rateTokens += now.Sub(a.rateStamp).Seconds() * alertRatePerSec
	if a.rateTokens > alertRateBurst {
		a.rateTokens = alertRateBurst
	}
	a.rateStamp = now
	allowed := a.rateTokens >= 1
	if allowed && current {
		a.rateTokens--
	}
	a.mu.Unlock()
	if !current {
		return "connection superseded by a newer one - alert not accepted"
	}
	if !allowed {
		return "rate limited - too many alerts, slow down"
	}

	if err := hist.Append([]HistoryEvent{{
		ObjectName:  name + ":" + object,
		Site:        name,
		LocalName:   object,
		Description: text,
		PrevStatus:  prev,
		NewStatus:   status,
	}}); err != nil {
		// Nothing was accepted, so nothing else may advance: the retry
		// this 444 asks for must see the same prev status and must not
		// duplicate anything.
		log.Printf("agents: alerter %s: recording %s %s to history failed: %v", name, status, object, err)
		return "could not record the alert - try again"
	}

	// Committed: everything after this honors the 333 rather than
	// gating it. Bookkeeping counts accepted alerts only.
	acceptedAt := time.Now().UTC()
	a.mu.Lock()
	a.lastStatus[object] = status
	a.info.Alerts++
	a.info.LastAlertAt = &acceptedAt
	a.info.LastAlert = fmt.Sprintf("%s %s: %s", status, object, text)
	a.mu.Unlock()

	// Push is the optional extra channel, attempted only after the
	// commit. A saturated queue cannot refuse an accepted alert - the
	// retry would duplicate the history row - so the skipped phone
	// delivery is a logged delivery failure instead.
	if sink := s.alertSinkFn(); sink != nil {
		p := pendingAlert{
			source:  name,
			display: s.alerterDisplayName(a),
			object:  object,
			status:  status,
			text:    text,
		}
		select {
		case a.pending <- p:
		default:
			log.Printf("agents: alerter %s: push queue full - %s %s is recorded in history but phone delivery was skipped",
				name, status, object)
		}
	}
	return ""
}

// registerAlerter puts a connection into the registry. A name
// reconnecting replaces its old link rather than adding a second, the
// same rule adoptAgent applies to daemons. The first sight of a name
// also starts its dispatcher: one goroutine per identity, for the life
// of the process, so every connection that ever speaks for this name
// feeds one ordered queue.
//
// The credential epoch is checked INSIDE the registry lock, before the
// current connection is touched: a handshake that authenticated under
// an old epoch and then slept through a re-mint must not get to evict
// the legitimate new-epoch connection on its way to being refused.
// Registrations are serialized by alertersMu, so the check and the
// install are one step relative to any competing registration.
func (s *Service) registerAlerter(name, application, remote, credID string, conn net.Conn) (*alerter, bool) {
	s.alertersMu.Lock()
	defer s.alertersMu.Unlock()
	if !s.credentialCurrent(name, credID) {
		return nil, false
	}
	if s.alerters == nil {
		s.alerters = make(map[string]*alerter)
	}
	if old, ok := s.alerters[name]; ok {
		// The swap holds the acceptance lock: an alert the old
		// connection already parsed either commits before this point
		// or sees itself superseded after it - see alerter.acceptMu.
		old.acceptMu.Lock()
		old.mu.Lock()
		if old.conn != nil && old.info.Connected {
			old.conn.Close()
		}
		old.conn = conn
		old.credID = credID
		old.info.Application = application
		old.info.Addr = remote
		old.info.Connected = true
		old.info.ConnectedAt = time.Now().UTC()
		old.mu.Unlock()
		old.acceptMu.Unlock()
		return old, true
	}
	a := &alerter{
		conn:       conn,
		credID:     credID,
		pending:    make(chan pendingAlert, alertQueueDepth),
		lastStatus: make(map[string]string),
		rateTokens: alertRateBurst,
		rateStamp:  time.Now(),
		info: AlerterInfo{
			Name:        name,
			Application: application,
			Addr:        remote,
			Connected:   true,
			ConnectedAt: time.Now().UTC(),
		},
	}
	s.alerters[name] = a
	go s.dispatchAlerts(a)
	return a, true
}

// dispatchAlerts is an alerter identity's one delivery worker. It never
// exits: the registry keeps the record (and this goroutine) for the
// life of the process, and the count of identities is bounded by the
// count of minted tokens.
func (s *Service) dispatchAlerts(a *alerter) {
	for p := range a.pending {
		if sink := s.alertSinkFn(); sink != nil {
			sink(p.source, p.display, p.object, p.status, p.text)
		} else {
			// The alert is already committed to history; only its
			// phone delivery is lost, because the sink was unset
			// between accept and dispatch.
			log.Printf("agents: alerter %s sent %s %s with no push service configured - phone delivery skipped",
				p.source, p.status, p.object)
		}
	}
}
