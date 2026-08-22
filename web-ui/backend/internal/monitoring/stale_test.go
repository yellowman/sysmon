package monitoring

import (
	"bufio"
	"fmt"
	"net"
	"strings"
	"sync"
	"testing"
)

// A site that stops answering must not have its hosts reported as removed.
// They are the operator's map, their alert list and their history; deleting
// them on a blip and re-adding them on recovery churns the delta revision
// for every client in the fleet and, worse, hides the one thing worth
// seeing - that a site has gone dark.

// fakeSysmond speaks just enough of the protocol for a poll cycle.
type fakeSysmond struct {
	ln      net.Listener
	site    string
	objects []string

	mu   sync.Mutex
	dark bool     // stop answering, as a daemon that fell off the network does
	live net.Conn // the connection it dialled in on
	vers int      // how many times VERS has been asked
}

func (f *fakeSysmond) versCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.vers
}

func startFakeSysmond(t *testing.T, site string, objects ...string) *fakeSysmond {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	f := &fakeSysmond{ln: ln, site: site, objects: objects}
	go f.serve()
	t.Cleanup(func() { ln.Close() })
	return f
}

func (f *fakeSysmond) addr() string { return f.ln.Addr().String() }

// goDark is what a box falling off the network looks like from here: the
// link it dialled in on stops being a link. sysmon-web finds out on its
// next poll and has nothing to redial - the box has to come back by
// itself.
func (f *fakeSysmond) goDark() {
	f.mu.Lock()
	f.dark = true
	c := f.live
	f.mu.Unlock()
	if c != nil {
		c.Close()
	}
}

func (f *fakeSysmond) isDark() bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.dark
}

func (f *fakeSysmond) serve() {
	for {
		conn, err := f.ln.Accept()
		if err != nil {
			return
		}
		if f.isDark() {
			conn.Close() // hangs up mid-conversation, like a box that died
			continue
		}
		go f.session(conn)
	}
}

// session answers on a connection that has already been adopted, so
// there is no welcome banner: the HELLO/token handshake is over by the
// time sysmon-web starts polling.
func (f *fakeSysmond) session(conn net.Conn) {
	defer conn.Close()
	r := bufio.NewReader(conn)

	for {
		line, err := r.ReadString('\n')
		if err != nil {
			return
		}
		cmd := strings.TrimSpace(line)
		switch {
		case cmd == "VERS":
			f.mu.Lock()
			f.vers++
			f.mu.Unlock()
			fmt.Fprintf(conn, "sysmond 0.99-test\r\n")
		case cmd == "UPTIME":
			fmt.Fprintf(conn, "Uptime = 3600 secs\r\n")
		case cmd == "MODE xml":
			fmt.Fprintf(conn, "333 xml enabled\r\n")
		case cmd == "SITE":
			fmt.Fprintf(conn, "<SiteName>%s</SiteName>\r\n", f.site)
			fmt.Fprintf(conn, "<SiteDescription>%s the site</SiteDescription>\r\n", f.site)
			fmt.Fprintf(conn, "333 ok\r\n")
		case cmd == "STATAL":
			for _, o := range f.objects {
				fmt.Fprintf(conn, "%s\r\n", o)
			}
			fmt.Fprintf(conn, "333 Not currently Paused\r\n")
		case strings.HasPrefix(cmd, "CONF"), strings.HasPrefix(cmd, "TRAPS"):
			fmt.Fprintf(conn, "403 not authorised\r\n")
		case strings.HasPrefix(cmd, "SHOWOBJ "):
			name := strings.TrimPrefix(cmd, "SHOWOBJ ")
			fmt.Fprintf(conn, "<ObjectStatus>\r\n")
			fmt.Fprintf(conn, "<Object>%s</Object>\r\n", name)
			fmt.Fprintf(conn, "<HostName>%s.example.net</HostName>\r\n", name)
			fmt.Fprintf(conn, "<ObjectType>ping</ObjectType>\r\n")
			fmt.Fprintf(conn, "<ObjectLastcheckState>0</ObjectLastcheckState>\r\n")
			fmt.Fprintf(conn, "</ObjectStatus>\r\n")
		case cmd == "QUIT":
			return
		}
	}
}

// connect dials the fake and adopts the socket into the fleet, which is
// exactly what AgentListener.handshake does once a box has proved itself.
// Daemons dial in; nothing here is ever dialled by sysmon-web.
func connect(t *testing.T, svc *Service, f *fakeSysmond) {
	t.Helper()
	c, err := net.Dial("tcp", f.addr())
	if err != nil {
		t.Fatalf("dialling the fake daemon: %v", err)
	}
	f.mu.Lock()
	f.live = c
	f.mu.Unlock()
	svc.adoptAgent(f.site, c.RemoteAddr().String(), "", c, bufio.NewReader(c))
}

func TestUnreachableSiteGoesStaleNotRemoved(t *testing.T) {
	a := startFakeSysmond(t, "site-a", "gw", "sw1")
	b := startFakeSysmond(t, "site-b", "gw", "edge")

	svc := NewService()
	connect(t, svc, a)
	connect(t, svc, b)

	first, err := svc.fetchFleet()
	if err != nil {
		t.Fatalf("first poll: %v", err)
	}
	if len(first.Hosts) != 4 {
		t.Fatalf("first poll saw %d hosts, want 4", len(first.Hosts))
	}
	svc.cacheMu.Lock()
	svc.storeSnapshotLocked(first)
	revBefore := svc.rev
	svc.cacheMu.Unlock()

	b.goDark()

	second, err := svc.fetchFleet()
	if err != nil {
		t.Fatalf("second poll: %v", err)
	}
	if len(second.Hosts) != 4 {
		t.Fatalf("with site-b dark the fleet shows %d hosts, want 4 (2 live, 2 stale)", len(second.Hosts))
	}

	byName := map[string]bool{}
	for _, h := range second.Hosts {
		byName[h.ObjectName] = h.Stale
	}
	for _, want := range []string{"site-a:gw", "site-a:sw1", "site-b:gw", "site-b:edge"} {
		if _, ok := byName[want]; !ok {
			t.Errorf("%s vanished when its site went dark", want)
		}
	}
	if byName["site-a:gw"] {
		t.Error("a reachable site's host was marked stale")
	}
	if !byName["site-b:gw"] || !byName["site-b:edge"] {
		t.Error("a dark site's hosts were not marked stale")
	}
	for _, h := range second.Hosts {
		if h.ObjectName == "site-b:gw" && h.StaleSince == nil {
			t.Error("a stale host does not say when it was last heard from")
		}
	}

	// The delta must report the change, not a deletion.
	svc.cacheMu.Lock()
	svc.storeSnapshotLocked(second)
	rev := svc.rev
	var wronglyRemoved []string
	for name := range svc.removedAt {
		wronglyRemoved = append(wronglyRemoved, name)
	}
	svc.cacheMu.Unlock()

	if len(wronglyRemoved) != 0 {
		t.Errorf("a site going dark reported its hosts as removed: %v", wronglyRemoved)
	}
	if rev <= revBefore {
		t.Error("going stale did not bump the revision, so clients would never see it")
	}
}

// The process on the far end of a connection cannot change while the
// connection lives, so its version is asked once per connection rather
// than once per poll - and asked again on a reconnect, which may well
// be a restarted (upgraded) daemon.
func TestVersAskedOncePerConnection(t *testing.T) {
	a := startFakeSysmond(t, "site-a", "gw")
	svc := NewService()
	connect(t, svc, a)

	for i := 0; i < 3; i++ {
		status, err := svc.fetchFleet()
		if err != nil {
			t.Fatalf("poll %d: %v", i+1, err)
		}
		if status.Daemon.Version != "sysmond 0.99-test" {
			t.Fatalf("poll %d reported version %q", i+1, status.Daemon.Version)
		}
	}
	if got := a.versCount(); got != 1 {
		t.Errorf("VERS asked %d times over 3 polls on one connection, want 1", got)
	}

	// The daemon reconnects - new socket, possibly a new binary.
	connect(t, svc, a)
	if _, err := svc.fetchFleet(); err != nil {
		t.Fatalf("poll after reconnect: %v", err)
	}
	if got := a.versCount(); got != 2 {
		t.Errorf("VERS asked %d times after a reconnect, want 2", got)
	}
}

// The other half: a site nobody has ever reached has nothing to keep, and
// must not invent hosts.
func TestNeverReachedSiteContributesNothing(t *testing.T) {
	a := startFakeSysmond(t, "site-a", "gw")
	dead := startFakeSysmond(t, "site-dead", "ghost")

	svc := NewService()
	connect(t, svc, a)
	connect(t, svc, dead)
	// It dropped its link before we ever completed a poll, so there is
	// nothing recorded for it and nothing to keep.
	dead.goDark()

	status, err := svc.fetchFleet()
	if err != nil {
		t.Fatalf("poll: %v", err)
	}
	if len(status.Hosts) != 1 {
		t.Errorf("saw %d hosts, want just the one reachable site's", len(status.Hosts))
	}
}
