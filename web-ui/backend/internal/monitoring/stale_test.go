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
	dark bool // stop answering, as a daemon that fell off the network does
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

func (f *fakeSysmond) goDark() {
	f.mu.Lock()
	f.dark = true
	f.mu.Unlock()
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

func (f *fakeSysmond) session(conn net.Conn) {
	defer conn.Close()
	r := bufio.NewReader(conn)
	fmt.Fprintf(conn, "111 sysmond ready\r\n")

	for {
		line, err := r.ReadString('\n')
		if err != nil {
			return
		}
		cmd := strings.TrimSpace(line)
		switch {
		case cmd == "VERS":
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

func TestUnreachableSiteGoesStaleNotRemoved(t *testing.T) {
	a := startFakeSysmond(t, "site-a", "gw", "sw1")
	b := startFakeSysmond(t, "site-b", "gw", "edge")

	svc := NewService(a.addr() + "," + b.addr())

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

// The other half: a site nobody has ever reached has nothing to keep, and
// must not invent hosts.
func TestNeverReachedSiteContributesNothing(t *testing.T) {
	a := startFakeSysmond(t, "site-a", "gw")

	dead, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	deadAddr := dead.Addr().String()
	dead.Close() // nothing is listening there now

	svc := NewService(a.addr() + "," + deadAddr)
	status, err := svc.fetchFleet()
	if err != nil {
		t.Fatalf("poll: %v", err)
	}
	if len(status.Hosts) != 1 {
		t.Errorf("saw %d hosts, want just the one reachable site's", len(status.Hosts))
	}
}
