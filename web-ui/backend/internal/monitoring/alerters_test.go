package monitoring

import (
	"bufio"
	"net"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"sysmon-web/internal/settings"
)

// A captured sink call.
type sunkAlert struct {
	source, display, object, status, text string
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

	mu.Lock()
	if len(sunk) != 2 {
		t.Fatalf("sink saw %d alerts, want 2: %+v", len(sunk), sunk)
	}
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

	// An admin nickname beats the application name from the next alert on.
	store.SetAgentLabel("backupd", "Nightly Backups")
	if got := send("ALERT WARNING tape drive temperature high"); got != "333 ok" {
		t.Errorf("ALERT answered %q", got)
	}
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

	// The token record learned its kind at handshake time in the real
	// path; SetAgentKind is what the listener calls - prove it sticks
	// and that labels round-trip beside it.
	store.SetAgentKind("backupd", settings.KindAlerter)
	tokens, err := store.ListAgentTokens()
	if err != nil || len(tokens) != 1 {
		t.Fatalf("ListAgentTokens: %v, %d", err, len(tokens))
	}
	if tokens[0].Kind != settings.KindAlerter || tokens[0].Label != "Nightly Backups" {
		t.Errorf("token record = %+v", tokens[0])
	}
}
