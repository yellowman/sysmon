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
	if _, err := store.NewAgentToken("backupd", ""); err != nil {
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

	// The token record learns its kind at handshake time in the real
	// path (claimKind -> ClaimAgentKind) - prove the recorded kind
	// sticks and that labels round-trip beside it.
	if got := store.ClaimAgentKind("backupd", settings.KindAlerter); got != "" {
		t.Errorf("ClaimAgentKind refused a fresh token: %q", got)
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
	if err != nil || strings.TrimSpace(reply) != "333 ok" {
		t.Fatalf("overlong ALERT = %q, %v, want 333 ok", strings.TrimSpace(reply), err)
	}

	waitFor(t, "the truncated alert to reach the sink", func() bool {
		mu.Lock()
		defer mu.Unlock()
		return len(texts) == 1
	})
	mu.Lock()
	text := texts[0]
	mu.Unlock()
	if got := len([]rune(text)); got > maxAlertText {
		t.Errorf("alert text is %d runes, want at most %d", got, maxAlertText)
	}

	// The line after the flood still parses - nothing of the overflow
	// leaked into the next read.
	if _, err := client.Write([]byte("PING\n")); err != nil {
		t.Fatalf("write after flood: %v", err)
	}
	if reply, err := r.ReadString('\n'); err != nil || strings.TrimSpace(reply) != "333 pong" {
		t.Fatalf("PING after flood = %q, %v", strings.TrimSpace(reply), err)
	}
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
	if _, err := store.NewAgentToken("box1", ""); err != nil {
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
		if _, err := store.NewAgentToken(site, ""); err != nil {
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
