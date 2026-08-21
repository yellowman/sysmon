package monitoring

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"log"
	"net"
	"strings"
	"sync"
	"time"

	"sysmon-web/internal/settings"
)

// Daemons that dial in.
//
// A monitoring box usually sits behind NAT, on a management VLAN, or at a
// customer site, so waiting to be dialled means an inbound firewall rule
// per site. Letting sysmond dial out means none - and it inverts the
// credential story too: one token per box, revocable here, instead of this
// process holding a key to every box in the fleet.
//
// Once a daemon has proved who it is, its connection is handed to the same
// poller that drives a dialled daemon. From there nothing downstream knows
// or cares which end opened the socket.

// AgentAuth decides whether a token may claim a site. Returning false
// closes the connection; the daemon backs off and tries again, so a
// revoked token costs the fleet nothing but that one box.
type AgentAuth func(site, token, remoteAddr string) bool

// AgentListener accepts daemons dialling in over TLS.
type AgentListener struct {
	ln   net.Listener
	svc  *Service
	auth AgentAuth

	mu     sync.Mutex
	closed bool
}

// ListenForAgents starts accepting daemon connections on addr.
//
// TLS is required and not negotiable: this carries a bearer token, and
// later the whole config of every box that connects.
func ListenForAgents(addr, certFile, keyFile string, svc *Service, auth AgentAuth) (*AgentListener, error) {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, fmt.Errorf("agent listener: certificate: %w", err)
	}

	cfg := &tls.Config{
		Certificates: []tls.Certificate{cert},
		// The daemons speak the OpenSSL 1.1.1 / LibreSSL dialect and are
		// pinned to a TLS 1.2 floor; match that rather than demanding 1.3
		// from an OpenBSD box that may not offer it.
		MinVersion: tls.VersionTLS12,
	}

	ln, err := tls.Listen("tcp", addr, cfg)
	if err != nil {
		return nil, fmt.Errorf("agent listener: listen %s: %w", addr, err)
	}

	al := &AgentListener{ln: ln, svc: svc, auth: auth}
	go al.accept()
	log.Printf("agents: listening for sysmond connections on %s", addr)
	return al, nil
}

func (a *AgentListener) Close() error {
	a.mu.Lock()
	a.closed = true
	a.mu.Unlock()
	return a.ln.Close()
}

func (a *AgentListener) isClosed() bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.closed
}

func (a *AgentListener) accept() {
	for {
		conn, err := a.ln.Accept()
		if err != nil {
			if a.isClosed() {
				return
			}
			log.Printf("agents: accept failed: %v", err)
			time.Sleep(time.Second)
			continue
		}
		go a.handshake(conn)
	}
}

// handshake reads the daemon's HELLO and, if it checks out, registers it.
//
// A bad token gets a plain refusal and a closed socket - not a hint about
// which half was wrong, and not a retry loop held open on our side.
func (a *AgentListener) handshake(conn net.Conn) {
	remote := conn.RemoteAddr().String()

	// The greeting is the only thing on a timer. After this the
	// connection is long-lived by design.
	conn.SetDeadline(time.Now().Add(20 * time.Second))
	reader := bufio.NewReader(conn)

	// Bounded, not ReadString: this line arrives BEFORE any token
	// check, so an unauthenticated peer streaming a newline-free flood
	// must cost at most maxLineBytes of memory, not everything it can
	// push before the deadline.
	line, truncated, err := readLineBounded(reader)
	if err != nil {
		conn.Close()
		return
	}
	if truncated {
		fmt.Fprintf(conn, "444 line too long - maximum %d bytes\r\n", maxLineBytes)
		conn.Close()
		log.Printf("agents: %s sent an overlong greeting", remote)
		return
	}

	fields := strings.Fields(strings.TrimSpace(line))
	if len(fields) < 2 || (fields[0] != "HELLO" && fields[0] != "ALERTER") {
		fmt.Fprintf(conn, "444 expected HELLO <site> <token> or ALERTER <name> <token>\r\n")
		conn.Close()
		log.Printf("agents: %s did not greet us properly", remote)
		return
	}

	site := fields[1]
	token := ""
	if len(fields) >= 3 {
		token = fields[2]
	}

	if !ValidSiteName(site) {
		fmt.Fprintf(conn, "444 bad site name\r\n")
		conn.Close()
		log.Printf("agents: %s claimed an unusable site name %q", remote, site)
		return
	}

	if a.auth == nil || !a.auth(site, token, remote) {
		fmt.Fprintf(conn, "444 rejected\r\n")
		conn.Close()
		log.Printf("agents: rejected %s claiming site %q", remote, site)
		return
	}

	// The verb the peer greeted with claims what kind of thing it is. A
	// token that already belongs to the other class is refused: letting
	// a sysmond's token greet as an alerter (or the reverse) would flip
	// how every page counts and treats the site, on the say-so of
	// whoever holds the token.
	kind := settings.KindSysmond
	if fields[0] == "ALERTER" {
		kind = settings.KindAlerter
	}
	if refusal := a.svc.claimKind(site, kind); refusal != "" {
		fmt.Fprintf(conn, "444 %s\r\n", refusal)
		conn.Close()
		log.Printf("agents: refused %s greeting as %s for site %q: %s", remote, kind, site, refusal)
		return
	}

	if _, err := fmt.Fprintf(conn, "333 welcome\r\n"); err != nil {
		conn.Close()
		return
	}
	conn.SetDeadline(time.Time{}) // long-lived from here

	// An alerter is not a monitoring box: nothing is polled, nothing is
	// adopted, it just sends alerts down this socket - see alerters.go.
	if fields[0] == "ALERTER" {
		// Anything after the token is what the application calls
		// itself - free text, shown beside the name on the Fleet page
		// and in the alerts it sends.
		app := ""
		if len(fields) >= 4 {
			app = TruncateRunes(strings.Join(fields[3:], " "), 128)
		}
		log.Printf("agents: alerter %s connected from %s", site, remote)
		a.svc.runAlerter(site, app, remote, conn, reader)
		return
	}

	a.svc.adoptAgent(site, remote, conn, reader)
	log.Printf("agents: site %s connected from %s", site, remote)

	// The operator who put this box's token in its sysmon.conf already
	// made the management decision; a first connection from a box this
	// server has never seen records its running config as generation 1
	// without a second ceremony in the UI. A site that was deliberately
	// unmanaged has a record with Adopted false and is left alone.
	go a.svc.autoAdoptIfNew(site)
}

// ValidSiteName mirrors the daemon's own rule. A colon would make
// "site:object" ambiguous to split, so it is refused everywhere a site
// name is accepted: here, at the daemon's config parser, and at the admin
// page that mints a token for one.
func ValidSiteName(s string) bool {
	if s == "" || len(s) > 64 {
		return false
	}
	for _, c := range s {
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z',
			c >= '0' && c <= '9', c == '-', c == '_':
		default:
			return false
		}
	}
	return true
}

// claimKind records what a token's peer identified as at handshake and
// refuses a token that already belongs to the other class. Returns ""
// to proceed, else the complaint for the 444. The check and the write
// happen in one store transaction (ClaimAgentKind), so two concurrent
// first handshakes cannot both claim a fresh token as different kinds;
// a reconnect whose kind already matches costs no write at all.
func (s *Service) claimKind(site, kind string) string {
	st := s.Generations()
	if st == nil {
		return ""
	}
	owner, err := st.ClaimAgentKind(site, kind)
	if err != nil {
		// Fail closed: a peer admitted while its kind claim silently
		// failed to stick is a peer of no recorded kind - the exact
		// state this check exists to prevent.
		log.Printf("agents: kind claim for %s failed: %v", site, err)
		return "temporary credential-store failure - try again"
	}
	if owner != "" {
		return "this token belongs to a " + owner
	}
	return ""
}

// DisconnectSite closes whatever live connection the named identity
// holds - daemon or alerter - and reports whether one was closed.
//
// Authentication happens once, at the greeting, and the connection is
// long-lived by design; without this, revoking or re-minting a token
// changes nothing for a peer that simply never hangs up. The revoke and
// re-mint paths call it after the store is updated, so the next
// connection attempt fails authentication and the current one dies now.
// (A CLI revoke runs in its own process and cannot reach in here; the
// running server still cuts the link at its next protocol exchange
// failure or restart.)
func (s *Service) DisconnectSite(site string) bool {
	closed := false

	s.fleetMu.Lock()
	for _, d := range s.daemons {
		d.mu.Lock()
		if d.site == site && d.conn != nil {
			d.conn.Close()
			closed = true
		}
		d.mu.Unlock()
	}
	s.fleetMu.Unlock()

	s.alertersMu.Lock()
	if a, ok := s.alerters[site]; ok {
		a.mu.Lock()
		if a.conn != nil && a.info.Connected {
			a.conn.Close()
			closed = true
		}
		a.mu.Unlock()
	}
	s.alertersMu.Unlock()

	if closed {
		log.Printf("agents: disconnected %s (token revoked or replaced)", site)
	}
	return closed
}

// adoptAgent puts a dialled-in daemon into the fleet.
//
// A site reconnecting replaces its old entry rather than adding a second:
// a daemon that restarted, or whose link dropped and came back, is the
// same site, and two entries would double every host it reports.
func (s *Service) adoptAgent(site, remote string, conn net.Conn, reader *bufio.Reader) {
	s.fleetMu.Lock()
	defer s.fleetMu.Unlock()

	for _, d := range s.daemons {
		d.mu.Lock()
		same := d.site == site
		d.mu.Unlock()
		if !same {
			continue
		}
		d.mu.Lock()
		if d.conn != nil {
			d.conn.Close()
		}
		d.conn, d.reader = conn, reader
		d.addr = remote
		d.lastErr = ""
		// Its sequence numbers belong to the old connection's daemon
		// process, which may have restarted. Start clean rather than
		// asking for a delta against a sequence that no longer means
		// anything.
		d.confSeq, d.trapSeq = 0, 0
		d.hostCache = nil
		d.mu.Unlock()
		return
	}

	s.daemons = append(s.daemons, &daemon{
		addr:   remote,
		site:   site,
		conn:   conn,
		reader: reader,
	})
}
