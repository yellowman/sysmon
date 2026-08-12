package push

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync"
	"testing"

	bolt "go.etcd.io/bbolt"
	"golang.org/x/oauth2"
)

// seedSubscription writes a raw subscription row straight into the db,
// bypassing Subscribe's validation - simulating rows created by old
// builds before platform names were locked down.
func seedRow(t *testing.T, dbPath, token string, raw []byte) {
	t.Helper()
	db, err := bolt.Open(dbPath, 0600, nil)
	if err != nil {
		t.Fatalf("open seed db: %v", err)
	}
	defer db.Close()
	err = db.Update(func(tx *bolt.Tx) error {
		b, err := tx.CreateBucketIfNotExists(bucketSubscriptions)
		if err != nil {
			return err
		}
		return b.Put([]byte(token), raw)
	})
	if err != nil {
		t.Fatalf("seed row: %v", err)
	}
}

func mustJSON(t *testing.T, sub Subscription) []byte {
	t.Helper()
	data, err := json.Marshal(sub)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return data
}

func TestNewServiceHardMigratesLegacyPlatforms(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "push.db")

	seedRow(t, dbPath, "tok-legacy-fcm", mustJSON(t, Subscription{
		DeviceToken: "tok-legacy-fcm", Platform: "fcm", Label: "old android build",
	}))
	seedRow(t, dbPath, "tok-android", mustJSON(t, Subscription{
		DeviceToken: "tok-android", Platform: PlatformAndroid, Label: "current android",
	}))
	seedRow(t, dbPath, "tok-ios", mustJSON(t, Subscription{
		DeviceToken: "tok-ios", Platform: PlatformIOS, Label: "iphone",
	}))
	seedRow(t, dbPath, "tok-junk-platform", mustJSON(t, Subscription{
		DeviceToken: "tok-junk-platform", Platform: "web", Label: "unroutable",
	}))
	seedRow(t, dbPath, "tok-corrupt", []byte("{not json"))

	svc, err := NewService(Config{}, dbPath, nil)
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	defer svc.Stop()

	subs := svc.ListSubscriptions()
	got := map[string]Platform{}
	for _, s := range subs {
		got[s.DeviceToken] = s.Platform
	}

	if len(subs) != 3 {
		t.Fatalf("expected 3 surviving subscriptions, got %d: %v", len(subs), got)
	}
	if got["tok-legacy-fcm"] != PlatformAndroid {
		t.Errorf("legacy fcm row not rewritten to android: %q", got["tok-legacy-fcm"])
	}
	if got["tok-android"] != PlatformAndroid || got["tok-ios"] != PlatformIOS {
		t.Errorf("valid rows disturbed: %v", got)
	}
	if _, ok := got["tok-junk-platform"]; ok {
		t.Errorf("unroutable platform row survived migration")
	}
	if _, ok := got["tok-corrupt"]; ok {
		t.Errorf("corrupt row survived migration")
	}
}

func TestSendTestIsRecorded(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "push.db")
	svc, err := NewService(Config{}, dbPath, nil)
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	defer svc.Stop()

	if _, _, err := svc.Subscribe("tok-test-device", PlatformAndroid, "pixel", "chris", "", ""); err != nil {
		t.Fatalf("Subscribe: %v", err)
	}

	// No FCM client configured → the send fails, but the attempt must
	// still show up in the per-device stats and the push log so tests
	// are never invisible.
	if err := svc.SendTest("tok-test-device", PlatformAndroid); err == nil {
		t.Fatalf("expected send error with no FCM client")
	}

	subs := svc.ListSubscriptions()
	if len(subs) != 1 {
		t.Fatalf("expected 1 subscription, got %d", len(subs))
	}
	if subs[0].LastPushStatus != "failed (test)" {
		t.Errorf("LastPushStatus = %q, want %q", subs[0].LastPushStatus, "failed (test)")
	}
	if subs[0].FailCount != 1 {
		t.Errorf("FailCount = %d, want 1", subs[0].FailCount)
	}

	log := svc.GetPushLog(10)
	if len(log) != 1 {
		t.Fatalf("expected 1 push log entry, got %d", len(log))
	}
	if log[0].Status != "TEST" || log[0].Recipients != 0 {
		t.Errorf("log entry = %+v, want Status TEST with 0 recipients", log[0])
	}
}

func TestPushFailStatusClassification(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want string
	}{
		{"unregistered", &FCMSendError{StatusCode: http.StatusNotFound, Reason: "UNREGISTERED"}, "failed: token dead"},
		{"mismatch", &FCMSendError{StatusCode: http.StatusForbidden, Reason: "SENDER_ID_MISMATCH"}, "failed: project mismatch"},
		{"other fcm", &FCMSendError{StatusCode: 500, Reason: "INTERNAL"}, "failed: internal"},
		{"key rejected", &KeyRejectedError{Detail: "revoked"}, "failed: key rejected"},
		{"generic", errRandom, "failed"},
	}
	for _, tc := range cases {
		if got := pushFailStatus(tc.err); got != tc.want {
			t.Errorf("%s: pushFailStatus = %q, want %q", tc.name, got, tc.want)
		}
	}
}

var errRandom = json.Unmarshal([]byte("x"), &struct{}{})

// fakeFCM stands in for the FCM v1 endpoint: it answers UNREGISTERED
// for tokens in dead, 200 for everything else, and counts the sends it
// saw per token.
type fakeFCM struct {
	mu    sync.Mutex
	dead  map[string]bool
	sends map[string]int
}

func newFakeFCM(deadTokens ...string) *fakeFCM {
	f := &fakeFCM{dead: map[string]bool{}, sends: map[string]int{}}
	for _, tok := range deadTokens {
		f.dead[tok] = true
	}
	return f
}

func (f *fakeFCM) sendCount(token string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.sends[token]
}

func (f *fakeFCM) handler(w http.ResponseWriter, req *http.Request) {
	var body struct {
		Message struct {
			Token string `json:"token"`
		} `json:"message"`
	}
	json.NewDecoder(req.Body).Decode(&body)
	f.mu.Lock()
	f.sends[body.Message.Token]++
	dead := f.dead[body.Message.Token]
	f.mu.Unlock()
	if dead {
		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte(`{"error":{"code":404,"message":"Requested entity was not found.","status":"NOT_FOUND","details":[{"@type":"type.googleapis.com/google.firebase.fcm.v1.FcmError","errorCode":"UNREGISTERED"}]}}`))
		return
	}
	w.Write([]byte(`{"name":"projects/test/messages/1"}`))
}

// fcmClientFor wires an FCMClient at a fake endpoint - no OAuth, no
// network beyond the test server.
func fcmClientFor(t *testing.T, f *fakeFCM) *FCMClient {
	t.Helper()
	ts := httptest.NewServer(http.HandlerFunc(f.handler))
	t.Cleanup(ts.Close)
	return &FCMClient{
		httpClient:  ts.Client(),
		tokenSource: oauth2.StaticTokenSource(&oauth2.Token{AccessToken: "test"}),
		projectID:   "test",
		endpoint:    ts.URL,
	}
}

// TestUnregisteredTokenLifecycle walks the whole renewal handshake:
// UNREGISTERED flags the token, fan-outs skip it, re-subscribing the
// same token reports it dead (the app's cue to mint a fresh one), the
// fresh token starts clean, and a later successful send clears a flag.
func TestUnregisteredTokenLifecycle(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "push.db")
	svc, err := NewService(Config{Enabled: true}, dbPath, nil)
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	defer svc.Stop()

	fake := newFakeFCM("tok-dead")
	svc.fcm = fcmClientFor(t, fake)

	for _, tok := range []string{"tok-dead", "tok-alive"} {
		if _, dead, err := svc.Subscribe(tok, PlatformAndroid, tok, "chris", "", ""); err != nil || dead {
			t.Fatalf("Subscribe(%s) = dead %v, err %v", tok, dead, err)
		}
	}

	// First fan-out: both tokens are tried; FCM refuses the dead one.
	svc.notifyAll("host DOWN", "", "host is unreachable", "host", "CRITICAL", "OK", "", 1, true, "host")
	if got := fake.sendCount("tok-dead"); got != 1 {
		t.Fatalf("dead token sends after first fan-out = %d, want 1", got)
	}

	byToken := func() map[string]Subscription {
		m := map[string]Subscription{}
		for _, s := range svc.ListSubscriptions() {
			m[s.DeviceToken] = s
		}
		return m
	}
	subs := byToken()
	if !subs["tok-dead"].Unregistered || subs["tok-dead"].UnregisteredAt == "" {
		t.Errorf("dead token not flagged unregistered: %+v", subs["tok-dead"])
	}
	if subs["tok-dead"].LastPushStatus != "failed: token dead" {
		t.Errorf("dead token LastPushStatus = %q", subs["tok-dead"].LastPushStatus)
	}
	if subs["tok-alive"].Unregistered || subs["tok-alive"].LastPushStatus != "ok" {
		t.Errorf("live token disturbed: %+v", subs["tok-alive"])
	}

	// Second fan-out: the flagged token is skipped, the live one isn't.
	svc.notifyAll("host RECOVERED", "", "host is back up", "host", "OK", "CRITICAL", "", 0, false, "host")
	if got := fake.sendCount("tok-dead"); got != 1 {
		t.Errorf("dead token sends after second fan-out = %d, want still 1 (skipped)", got)
	}
	if got := fake.sendCount("tok-alive"); got != 2 {
		t.Errorf("live token sends = %d, want 2", got)
	}

	// The app re-subscribes the same dead token at launch: it must be
	// told, and the flag must survive the re-subscribe.
	if _, dead, err := svc.Subscribe("tok-dead", PlatformAndroid, "tok-dead", "chris", "", ""); err != nil || !dead {
		t.Errorf("re-subscribe of dead token: dead = %v, err = %v, want dead = true", dead, err)
	}
	// A genuinely fresh token starts clean.
	if _, dead, err := svc.Subscribe("tok-fresh", PlatformAndroid, "tok-fresh", "chris", "", ""); err != nil || dead {
		t.Errorf("fresh token reported dead = %v, err = %v", dead, err)
	}

	// A successful send (e.g. an admin test push to a wrongly flagged
	// token) clears the flag - test sends bypass the fan-out skip.
	fake.mu.Lock()
	fake.dead["tok-dead"] = false
	fake.mu.Unlock()
	if err := svc.SendTest("tok-dead", PlatformAndroid); err != nil {
		t.Fatalf("SendTest after revival: %v", err)
	}
	if sub := byToken()["tok-dead"]; sub.Unregistered || sub.UnregisteredAt != "" {
		t.Errorf("flag not cleared by successful send: %+v", sub)
	}
}
