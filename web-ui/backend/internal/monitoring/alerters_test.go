package monitoring

import (
	"bufio"
	"fmt"
	"net"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"sysmon-web/internal/settings"
)

// A captured sink call.
type sunkAlert struct {
	source, display, object, status, text string
}

// waitFor polls cond until it holds or the test gives up. Delivery to
// the sink is asynchronous by design - the 333 comes back before the
// push pipeline runs - so every assertion about the sink has to wait,
// not look.
func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(2 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

// The alerter protocol, driven end to end over a pipe: handshake is the
// listener's job, so this starts where it hands over - an authenticated
// connection - and exercises ALERT/PING/QUIT, the display-name
// preference, and the registry the Fleet page reads.
func TestAlerterSession(t *testing.T) {
	store, err := settings.NewStore(filepath.Join(t.TempDir(), "settings.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if _, err := store.NewAgentToken("backupd", "", settings.KindAlerter); err != nil {
		t.Fatal(err)
	}

	svc := NewService()
	svc.SetGenerations(store)

	var mu sync.Mutex
	var sunk []sunkAlert
	svc.SetAlertSink(func(source, display, object, status, text string) {
		mu.Lock()
		sunk = append(sunk, sunkAlert{source, display, object, status, text})
		mu.Unlock()
	})
	sunkLen := func() int {
		mu.Lock()
		defer mu.Unlock()
		return len(sunk)
	}

	server, client := net.Pipe()
	done := make(chan struct{})
	go func() {
		svc.runAlerter("backupd", "Bacula 15.0 nightly backups", "pipe", server, bufio.NewReader(server))
		close(done)
	}()

	r := bufio.NewReader(client)
	send := func(line string) string {
		t.Helper()
		if _, err := client.Write([]byte(line + "\n")); err != nil {
			t.Fatalf("write %q: %v", line, err)
		}
		reply, err := r.ReadString('\n')
		if err != nil {
			t.Fatalf("no reply to %q: %v", line, err)
		}
		return strings.TrimSpace(reply)
	}

	if got := send("PING"); got != "333 pong" {
		t.Errorf("PING answered %q", got)
	}
	if got := send("ALERT CRITICAL tape jam in drive 2"); got != "333 ok" {
		t.Errorf("ALERT answered %q", got)
	}
	if got := send("ALERT BOGUS tape whatever"); !strings.HasPrefix(got, "444") {
		t.Errorf("bad status answered %q, want a 444", got)
	}
	if got := send("ALERT CRITICAL bad:name text"); !strings.HasPrefix(got, "444") {
		t.Errorf("bad object answered %q, want a 444", got)
	}
	if got := send("NONSENSE"); !strings.HasPrefix(got, "444") {
		t.Errorf("unknown verb answered %q, want a 444", got)
	}
	// A 444 must not have cost the connection.
	if got := send("ALERT OK tape cleared"); got != "333 ok" {
		t.Errorf("ALERT after a 444 answered %q", got)
	}

	waitFor(t, "two alerts to reach the sink", func() bool { return sunkLen() == 2 })
	mu.Lock()
	first := sunk[0]
	mu.Unlock()
	if first.source != "backupd" || first.object != "tape" ||
		first.status != "CRITICAL" || first.text != "jam in drive 2" {
		t.Errorf("first alert = %+v", first)
	}
	// No nickname set: the display name is what the application calls
	// itself.
	if first.display != "Bacula 15.0 nightly backups" {
		t.Errorf("display = %q, want the application name", first.display)
	}

	// The registry the Fleet page reads.
	list := svc.Alerters()
	if len(list) != 1 || list[0].Name != "backupd" || !list[0].Connected ||
		list[0].Application != "Bacula 15.0 nightly backups" || list[0].Alerts != 2 {
		t.Errorf("Alerters() = %+v", list)
	}
	if !strings.Contains(list[0].LastAlert, "OK tape") {
		t.Errorf("LastAlert = %q", list[0].LastAlert)
	}
	if list[0].LastSeen == nil || list[0].LastAlertAt == nil {
		t.Errorf("LastSeen/LastAlertAt = %v/%v, want both set", list[0].LastSeen, list[0].LastAlertAt)
	}

	// An admin nickname beats the application name from the next alert on.
	store.SetAgentLabel("backupd", "Nightly Backups")
	if got := send("ALERT WARNING tape drive temperature high"); got != "333 ok" {
		t.Errorf("ALERT answered %q", got)
	}
	waitFor(t, "the third alert to reach the sink", func() bool { return sunkLen() == 3 })
	mu.Lock()
	last := sunk[len(sunk)-1]
	mu.Unlock()
	if last.display != "Nightly Backups" {
		t.Errorf("display after nickname = %q, want the nickname", last.display)
	}

	if got := send("QUIT"); got != "333 bye" {
		t.Errorf("QUIT answered %q", got)
	}
	<-done
	if list := svc.Alerters(); len(list) != 1 || list[0].Connected {
		t.Errorf("after QUIT, Alerters() = %+v, want the record kept but disconnected", list)
	}

	// The kind was minted into the record; the handshake's claim of the
	// same kind is the steady state - prove it stands and that labels
	// round-trip beside it.
	if got, err := store.ClaimAgentKind("backupd", settings.KindAlerter); got != "" || err != nil {
		t.Errorf("ClaimAgentKind refused the minted kind: %q, %v", got, err)
	}
	tokens, err := store.ListAgentTokens()
	if err != nil || len(tokens) != 1 {
		t.Fatalf("ListAgentTokens: %v, %d", err, len(tokens))
	}
	if tokens[0].Kind != settings.KindAlerter || tokens[0].Label != "Nightly Backups" {
		t.Errorf("token record = %+v", tokens[0])
	}
}

// A reconnect replaces the old connection on the shared record; when the
// replaced connection's goroutine finally notices its read failing, it
// must not mark the record disconnected - that would show the live
// replacement as gone until its next alert.
func TestAlerterReconnectKeepsNewConnection(t *testing.T) {
	svc := NewService()

	server1, _ := net.Pipe()
	done1 := make(chan struct{})
	go func() {
		svc.runAlerter("upsd", "apcupsd", "pipe-1", server1, bufio.NewReader(server1))
		close(done1)
	}()
	waitFor(t, "the first connection to register", func() bool {
		l := svc.Alerters()
		return len(l) == 1 && l[0].Connected
	})

	// Same name dials in again: the registry closes the old socket,
	// which is what makes the first goroutine exit.
	server2, client2 := net.Pipe()
	done2 := make(chan struct{})
	go func() {
		svc.runAlerter("upsd", "apcupsd", "pipe-2", server2, bufio.NewReader(server2))
		close(done2)
	}()

	select {
	case <-done1:
	case <-time.After(5 * time.Second):
		t.Fatal("replaced connection's goroutine never exited")
	}
	// The old goroutine has fully torn down; the record must still say
	// connected, because the connection it tore down was not the
	// record's current one.
	if l := svc.Alerters(); len(l) != 1 || !l[0].Connected || l[0].Addr != "pipe-2" {
		t.Errorf("after replacement, Alerters() = %+v, want connected via pipe-2", l)
	}

	// And the replacement really is live.
	r := bufio.NewReader(client2)
	if _, err := client2.Write([]byte("PING\n")); err != nil {
		t.Fatalf("write on replacement: %v", err)
	}
	if reply, err := r.ReadString('\n'); err != nil || strings.TrimSpace(reply) != "333 pong" {
		t.Fatalf("replacement PING = %q, %v", strings.TrimSpace(reply), err)
	}
	client2.Close()
	<-done2
	if l := svc.Alerters(); len(l) != 1 || l[0].Connected {
		t.Errorf("after the replacement dropped, Alerters() = %+v, want disconnected", l)
	}
}

// One hostile line must cost at most its own truncation: the reader
// holds no more than maxLineBytes of it, the alert text is cut to
// maxAlertText runes, and the connection survives to serve the next
// line.
func TestAlerterOverlongLine(t *testing.T) {
	svc := NewService()

	var mu sync.Mutex
	var texts []string
	svc.SetAlertSink(func(_, _, _, _ string, text string) {
		mu.Lock()
		texts = append(texts, text)
		mu.Unlock()
	})

	server, client := net.Pipe()
	done := make(chan struct{})
	go func() {
		svc.runAlerter("chatty", "", "pipe", server, bufio.NewReader(server))
		close(done)
	}()

	// Four times the line bound, no newline until the end.
	long := "ALERT CRITICAL disk " + strings.Repeat("x", 4*maxLineBytes) + "\n"
	go func() {
		// net.Pipe writes block until read; feed it from the side.
		client.Write([]byte(long))
	}()
	r := bufio.NewReader(client)
	reply, err := r.ReadString('\n')
	if err != nil || !strings.HasPrefix(strings.TrimSpace(reply), "444 line too long") {
		t.Fatalf("overlong ALERT = %q, %v, want a 444 line too long refusal", strings.TrimSpace(reply), err)
	}

	// The line after the flood still parses - nothing of the overflow
	// leaked into the next read, and the refusal did not cost the
	// connection.
	if _, err := client.Write([]byte("PING\n")); err != nil {
		t.Fatalf("write after flood: %v", err)
	}
	if reply, err := r.ReadString('\n'); err != nil || strings.TrimSpace(reply) != "333 pong" {
		t.Fatalf("PING after flood = %q, %v", strings.TrimSpace(reply), err)
	}
	// Nothing of the refused line reached delivery: the server must not
	// silently accept a different message than the sender transmitted.
	mu.Lock()
	if len(texts) != 0 {
		t.Errorf("sink saw %d alerts from a refused line, want 0", len(texts))
	}
	mu.Unlock()
	client.Close()
	<-done
}

// TruncateRunes must never split a multi-byte rune - that is its whole
// reason to exist over a byte slice.
func TestTruncateRunes(t *testing.T) {
	if got := TruncateRunes("hello", 10); got != "hello" {
		t.Errorf("short string changed: %q", got)
	}
	if got := TruncateRunes("hello", 3); got != "hel" {
		t.Errorf("ASCII cut = %q", got)
	}
	// Each of these is one rune, several bytes.
	s := strings.Repeat("é世\U0001f600", 4) // é 世 😀
	got := TruncateRunes(s, 5)
	if n := len([]rune(got)); n != 5 {
		t.Errorf("cut to %d runes, want 5", n)
	}
	if !strings.HasPrefix(s, got) {
		t.Errorf("cut %q is not a prefix of the input", got)
	}
}

// claimKind: the greeting verb claims what a token's peer is, first
// claim wins forever, and the other class is refused - a sysmond's
// token cannot quietly become an alerter or the reverse.
func TestClaimKind(t *testing.T) {
	store, err := settings.NewStore(filepath.Join(t.TempDir(), "settings.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if _, err := store.NewAgentToken("box1", "", settings.KindSysmond); err != nil {
		t.Fatal(err)
	}
	// Minting records the kind now; blank it to simulate a record from
	// before kinds existed, whose first greeting claims it.
	if err := store.SetAgentKind("box1", ""); err != nil {
		t.Fatal(err)
	}

	svc := NewService()
	svc.SetGenerations(store)

	if got := svc.claimKind("box1", settings.KindSysmond); got != "" {
		t.Errorf("first claim refused: %q", got)
	}
	if tok, _ := store.GetAgentToken("box1"); tok.Kind != settings.KindSysmond {
		t.Errorf("kind after first claim = %q", tok.Kind)
	}
	if got := svc.claimKind("box1", settings.KindSysmond); got != "" {
		t.Errorf("reclaim of the same kind refused: %q", got)
	}
	if got := svc.claimKind("box1", settings.KindAlerter); !strings.Contains(got, "sysmond") {
		t.Errorf("cross-kind claim answered %q, want a refusal naming the owner", got)
	}
	if tok, _ := store.GetAgentToken("box1"); tok.Kind != settings.KindSysmond {
		t.Errorf("kind after refused claim = %q, must be unchanged", tok.Kind)
	}

	// No record: not claimKind's problem (the handshake authenticated
	// already; only a concurrent revoke gets here).
	if got := svc.claimKind("ghost", settings.KindAlerter); got != "" {
		t.Errorf("claim without a record refused: %q", got)
	}
	// No store at all: same.
	if got := NewService().claimKind("box1", settings.KindAlerter); got != "" {
		t.Errorf("claim without a store refused: %q", got)
	}
}

// A full delivery queue must refuse the alert, not acknowledge it:
// "333 ok" is a delivery promise, and a compliant client only resends
// what was refused. Refused alerts also must not count as sent.
func TestAlerterQueueFullRefuses(t *testing.T) {
	svc := NewService()

	release := make(chan struct{})
	starts := make(chan struct{}, alertQueueDepth+8)
	svc.SetAlertSink(func(_, _, _, _, _ string) {
		starts <- struct{}{}
		<-release // hold the dispatcher so the queue backs up
	})

	server, client := net.Pipe()
	done := make(chan struct{})
	go func() {
		svc.runAlerter("floody", "", "pipe", server, bufio.NewReader(server))
		close(done)
	}()

	r := bufio.NewReader(client)
	send := func(line string) string {
		t.Helper()
		if _, err := client.Write([]byte(line + "\n")); err != nil {
			t.Fatalf("write %q: %v", line, err)
		}
		reply, err := r.ReadString('\n')
		if err != nil {
			t.Fatalf("no reply to %q: %v", line, err)
		}
		return strings.TrimSpace(reply)
	}

	// The first alert occupies the dispatcher (wait until it is held in
	// the sink, so the queue is empty again)...
	if got := send("ALERT OK disk zero"); got != "333 ok" {
		t.Fatalf("first alert answered %q", got)
	}
	<-starts
	// ...then exactly alertQueueDepth more fill the buffer.
	for i := 0; i < alertQueueDepth; i++ {
		if got := send("ALERT OK disk filler"); got != "333 ok" {
			t.Fatalf("filler %d answered %q", i, got)
		}
	}
	// The next one has nowhere to go: it must be a 444, not a false ok.
	if got := send("ALERT CRITICAL disk the one that matters"); !strings.HasPrefix(got, "444 busy") {
		t.Fatalf("overflow alert answered %q, want a 444 busy refusal", got)
	}

	// Unblock delivery, let the backlog drain, and the same line is
	// accepted on retry - the connection survived the refusal.
	close(release)
	for i := 0; i < alertQueueDepth; i++ {
		<-starts
	}
	if got := send("ALERT CRITICAL disk the one that matters"); got != "333 ok" {
		t.Fatalf("retry after drain answered %q", got)
	}

	// Only accepted alerts counted: 1 + depth + 1, not the refusal.
	want := uint64(alertQueueDepth + 2)
	if list := svc.Alerters(); len(list) != 1 || list[0].Alerts != want {
		t.Errorf("Alerts = %d, want %d (refused alerts must not count)", list[0].Alerts, want)
	}

	client.Close()
	<-done
}

// Two first-use handshakes racing with the same fresh token must not
// both win: the claim is one store transaction, so exactly one side
// records its kind and the other is refused.
func TestClaimKindConcurrentFirstUse(t *testing.T) {
	store, err := settings.NewStore(filepath.Join(t.TempDir(), "settings.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	svc := NewService()
	svc.SetGenerations(store)

	for i := 0; i < 10; i++ {
		site := fmt.Sprintf("box%d", i)
		if _, err := store.NewAgentToken(site, "", settings.KindSysmond); err != nil {
			t.Fatal(err)
		}
		// The race only exists for records without a kind - which since
		// mint-time kinds means legacy records; simulate one.
		if err := store.SetAgentKind(site, ""); err != nil {
			t.Fatal(err)
		}
		results := make(chan string, 2)
		go func() { results <- svc.claimKind(site, settings.KindSysmond) }()
		go func() { results <- svc.claimKind(site, settings.KindAlerter) }()
		a, b := <-results, <-results
		refused := 0
		if a != "" {
			refused++
		}
		if b != "" {
			refused++
		}
		if refused != 1 {
			t.Fatalf("site %s: %d refusals (%q / %q), want exactly one winner", site, refused, a, b)
		}
	}
}

// The queue and dispatcher belong to the alerter's identity, not the
// socket: an OK accepted after a reconnect must never reach the sink
// before a CRITICAL accepted earlier on the old connection - two
// per-connection dispatchers raced exactly that way, and the shared
// collapse key then left the phones stuck on the stale CRITICAL.
func TestAlerterReconnectPreservesOrder(t *testing.T) {
	svc := NewService()

	release := make(chan struct{})
	starts := make(chan struct{}, 8)
	var mu sync.Mutex
	var order []string
	svc.SetAlertSink(func(_, _, _, status, _ string) {
		starts <- struct{}{}
		<-release // delivery is stuck (slow provider) until released
		mu.Lock()
		order = append(order, status)
		mu.Unlock()
	})

	// Connection one accepts two alerts: the first occupies the
	// dispatcher (stuck in the sink), the second waits in the queue.
	server1, client1 := net.Pipe()
	done1 := make(chan struct{})
	go func() {
		svc.runAlerter("upsd", "apcupsd", "pipe-1", server1, bufio.NewReader(server1))
		close(done1)
	}()
	r1 := bufio.NewReader(client1)
	send := func(c net.Conn, r *bufio.Reader, line string) string {
		t.Helper()
		if _, err := c.Write([]byte(line + "\n")); err != nil {
			t.Fatalf("write %q: %v", line, err)
		}
		reply, err := r.ReadString('\n')
		if err != nil {
			t.Fatalf("no reply to %q: %v", line, err)
		}
		return strings.TrimSpace(reply)
	}
	if got := send(client1, r1, "ALERT WARNING battery on battery power"); got != "333 ok" {
		t.Fatalf("first alert answered %q", got)
	}
	<-starts // dispatcher is now holding WARNING inside the sink
	if got := send(client1, r1, "ALERT CRITICAL battery battery low"); got != "333 ok" {
		t.Fatalf("second alert answered %q", got)
	}

	// The alerter reconnects and reports the recovery on the new link.
	server2, client2 := net.Pipe()
	done2 := make(chan struct{})
	go func() {
		svc.runAlerter("upsd", "apcupsd", "pipe-2", server2, bufio.NewReader(server2))
		close(done2)
	}()
	<-done1 // old connection fully torn down
	r2 := bufio.NewReader(client2)
	if got := send(client2, r2, "ALERT OK battery mains power restored"); got != "333 ok" {
		t.Fatalf("post-reconnect alert answered %q", got)
	}

	close(release)
	waitFor(t, "all three alerts to be delivered", func() bool {
		mu.Lock()
		defer mu.Unlock()
		return len(order) == 3
	})
	mu.Lock()
	got := strings.Join(order, ",")
	mu.Unlock()
	if got != "WARNING,CRITICAL,OK" {
		t.Fatalf("delivery order = %s, want WARNING,CRITICAL,OK", got)
	}

	client2.Close()
	<-done2
}

// The 333 is honored by either delivery path: the alert history alone
// is enough (push off or absent - the alert still shows in the web UI),
// and only a server with neither history nor push refuses.
func TestAlerterHistoryIsADeliveryPath(t *testing.T) {
	svc := NewService()

	server, client := net.Pipe()
	done := make(chan struct{})
	go func() {
		svc.runAlerter("backupd", "", "pipe", server, bufio.NewReader(server))
		close(done)
	}()
	r := bufio.NewReader(client)
	send := func(line string) string {
		t.Helper()
		if _, err := client.Write([]byte(line + "\n")); err != nil {
			t.Fatalf("write %q: %v", line, err)
		}
		reply, err := r.ReadString('\n')
		if err != nil {
			t.Fatalf("no reply to %q: %v", line, err)
		}
		return strings.TrimSpace(reply)
	}

	// Neither history nor push: genuinely nowhere to go, so refuse.
	if got := send("ALERT CRITICAL disk full"); !strings.HasPrefix(got, "444") {
		t.Fatalf("ALERT with nowhere to go answered %q, want a 444", got)
	}

	// A history store alone (no push at all) accepts and records.
	hist, err := OpenHistory(filepath.Join(t.TempDir(), "history.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer hist.Close()
	svc.SetHistory(hist)

	if got := send("ALERT CRITICAL tape jam in drive 2"); got != "333 ok" {
		t.Fatalf("ALERT with history only answered %q", got)
	}
	if got := send("ALERT OK tape cleared by operator"); got != "333 ok" {
		t.Fatalf("second ALERT answered %q", got)
	}

	// Recorded like host transitions: keyed source:object with the
	// halves split out, the text as the description, and the second
	// row knowing what the object changed from.
	events := hist.Recent(10, 0)
	if len(events) != 2 {
		t.Fatalf("history holds %d events, want 2: %+v", len(events), events)
	}
	newest, oldest := events[0], events[1]
	if oldest.ObjectName != "backupd:tape" || oldest.Site != "backupd" ||
		oldest.LocalName != "tape" || oldest.NewStatus != "CRITICAL" ||
		oldest.PrevStatus != "" || oldest.Description != "jam in drive 2" {
		t.Errorf("first recorded alert = %+v", oldest)
	}
	if newest.NewStatus != "OK" || newest.PrevStatus != "CRITICAL" {
		t.Errorf("second recorded alert = %+v, want OK from CRITICAL", newest)
	}
	// The transition duration machinery applies to alerter objects too.
	if newest.PrevDuration < 0 {
		t.Errorf("PrevDuration = %d", newest.PrevDuration)
	}

	if list := svc.Alerters(); len(list) != 1 || list[0].Alerts != 2 {
		t.Errorf("Alerts = %d, want 2 (the refused alert must not count)", list[0].Alerts)
	}

	client.Close()
	<-done
}

// Revoking or re-minting a token must cut the live connection, not just
// the next one: both registries - daemons and alerters - answer to
// DisconnectSite.
func TestDisconnectSiteCutsLiveConnections(t *testing.T) {
	svc := NewService()

	// An alerter with its socket up.
	aServer, aClient := net.Pipe()
	aDone := make(chan struct{})
	go func() {
		svc.runAlerter("backupd", "", "pipe-a", aServer, bufio.NewReader(aServer))
		close(aDone)
	}()
	waitFor(t, "the alerter to register", func() bool {
		l := svc.Alerters()
		return len(l) == 1 && l[0].Connected
	})

	// A daemon with its socket up.
	dServer, dClient := net.Pipe()
	svc.adoptAgent("branch2", "pipe-d", dServer, bufio.NewReader(dServer))

	if !svc.DisconnectSite("backupd") {
		t.Error("DisconnectSite(backupd) found nothing to close")
	}
	select {
	case <-aDone: // read loop died with the closed socket
	case <-time.After(5 * time.Second):
		t.Fatal("alerter connection survived DisconnectSite")
	}
	if l := svc.Alerters(); len(l) != 1 || l[0].Connected {
		t.Errorf("after DisconnectSite, Alerters() = %+v, want disconnected", l)
	}

	if !svc.DisconnectSite("branch2") {
		t.Error("DisconnectSite(branch2) found nothing to close")
	}
	// The daemon's socket really is dead: its far end reads EOF.
	dClient.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := dClient.Read(make([]byte, 1)); err == nil {
		t.Error("daemon connection still readable after DisconnectSite")
	}

	if svc.DisconnectSite("ghost") {
		t.Error("DisconnectSite(ghost) claimed to close something")
	}
	aClient.Close()
	dClient.Close()
}

// A broken credential store must fail closed: a kind claim that cannot
// be read or written refuses the handshake instead of admitting a peer
// whose kind never stuck, and label writes report their failure.
func TestStorageFailureFailsClosed(t *testing.T) {
	store, err := settings.NewStore(filepath.Join(t.TempDir(), "settings.db"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.NewAgentToken("box1", "", settings.KindSysmond); err != nil {
		t.Fatal(err)
	}

	svc := NewService()
	svc.SetGenerations(store)

	// Sanity: works while the store is healthy.
	if got := svc.claimKind("box1", settings.KindSysmond); got != "" {
		t.Fatalf("healthy claim refused: %q", got)
	}

	store.Close() // the "disk failure": every transaction now errors

	if got := svc.claimKind("box1", settings.KindAlerter); got == "" {
		t.Error("claimKind admitted a peer over a dead store")
	}
	if err := store.SetAgentLabel("box1", "new name"); err == nil {
		t.Error("SetAgentLabel reported success against a dead store")
	}
	if _, err := store.CheckAgentToken("box1", "whatever", "addr"); err == nil {
		t.Error("CheckAgentToken reported a verdict without an error against a dead store")
	}
}
