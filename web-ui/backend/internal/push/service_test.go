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

	"sysmon-web/internal/models"
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
	// The log names the owner, with the token prefix to tell one of
	// their devices from another.
	if want := "Test push → chris (tok-test-dev…)"; log[0].Hostname != want {
		t.Errorf("log entry hostname = %q, want %q", log[0].Hostname, want)
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
		{"apns unregistered", &APNsSendError{StatusCode: http.StatusGone, Reason: "Unregistered"}, "failed: token dead"},
		{"apns bad token", &APNsSendError{StatusCode: http.StatusBadRequest, Reason: "BadDeviceToken"}, "failed: bad device token (env mismatch?)"},
		{"apns other", &APNsSendError{StatusCode: 429, Reason: "TooManyRequests"}, "failed: toomanyrequests"},
		{"key rejected", &KeyRejectedError{Detail: "revoked"}, "failed: key rejected"},
		{"generic", errRandom, "failed"},
	}
	for _, tc := range cases {
		if got := pushFailStatus(tc.err); got != tc.want {
			t.Errorf("%s: pushFailStatus = %q, want %q", tc.name, got, tc.want)
		}
	}
}

// Both transports' dead-token verdicts - and only those - count as
// unregistered.
func TestIsUnregistered(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want bool
	}{
		{"fcm unregistered", &FCMSendError{StatusCode: 404, Reason: "UNREGISTERED"}, true},
		{"apns unregistered", &APNsSendError{StatusCode: 410, Reason: "Unregistered"}, true},
		{"fcm mismatch", &FCMSendError{StatusCode: 403, Reason: "SENDER_ID_MISMATCH"}, false},
		{"apns bad token", &APNsSendError{StatusCode: 400, Reason: "BadDeviceToken"}, false},
		{"nil", nil, false},
		{"generic", errRandom, false},
	}
	for _, tc := range cases {
		if got := isUnregistered(tc.err); got != tc.want {
			t.Errorf("%s: isUnregistered = %v, want %v", tc.name, got, tc.want)
		}
	}
}

func TestLooksLikeAPNsToken(t *testing.T) {
	apnsToken := "0123456789abcdef0123456789abcdef0123456789ABCDEF0123456789abcdef"
	if !looksLikeAPNsToken(apnsToken) {
		t.Errorf("64 hex chars not recognized as an APNs token")
	}
	fcmish := "dGVzdA:APA91bFoo-Bar_Baz0123456789abcdefghijklmnopqrstuvwxyz0123"
	for name, tok := range map[string]string{
		"fcm-shaped (colon)": fcmish,
		"too short":          apnsToken[:63],
		"too long":           apnsToken + "0",
		"non-hex":            apnsToken[:63] + "g",
		"empty":              "",
	} {
		if looksLikeAPNsToken(tok) {
			t.Errorf("%s: %q misrecognized as an APNs token", name, tok)
		}
	}
}

func TestRelatedDetail(t *testing.T) {
	ping := models.HostStatus{
		ObjectName: "site1:core-ping", LocalName: "core-ping",
		Site: "site1", Hostname: "core.example.net", OverallStatus: "CRITICAL",
	}
	all := []models.HostStatus{
		ping, // self - excluded
		{ // sibling by hostname, measures rtt
			ObjectName: "site1:core-rtt", LocalName: "core-rtt",
			Site: "site1", Hostname: "CORE.example.net", OverallStatus: "OK",
			RTT: &models.RTTStats{Avg: 44.0, Threshold: 80, Replies: 5, Probes: 5},
		},
		{ // sibling by hostname, snmp temperature, itself failing
			ObjectName: "site1:core-temp", LocalName: "core-temp",
			Site: "site1", Hostname: "core.example.net", OverallStatus: "WARNING",
			SNMP: &models.SNMPStats{CheckType: "high", LastValue: i64(52), High: 45},
		},
		{ // sibling but measures nothing - skipped
			ObjectName: "site1:core-tcp", LocalName: "core-tcp",
			Site: "site1", Hostname: "core.example.net", OverallStatus: "OK",
		},
		{ // same hostname, different site - a different box
			ObjectName: "site2:core-rtt", LocalName: "core-rtt",
			Site: "site2", Hostname: "core.example.net", OverallStatus: "OK",
			RTT: &models.RTTStats{Avg: 9.0, Replies: 5, Probes: 5},
		},
		{ // unrelated host
			ObjectName: "site1:edge-rtt", LocalName: "edge-rtt",
			Site: "site1", Hostname: "edge.example.net", OverallStatus: "OK",
			RTT: &models.RTTStats{Avg: 12.0, Replies: 5, Probes: 5},
		},
	}
	want := "core-rtt rtt avg 44.0ms (limit 80ms); core-temp reading 52 (max 45) [WARNING]"
	if got := relatedDetail(all, ping); got != want {
		t.Errorf("relatedDetail = %q, want %q", got, want)
	}

	// No siblings → empty.
	if got := relatedDetail(all, all[5]); got != "" {
		t.Errorf("relatedDetail for lone host = %q, want empty", got)
	}
}

var errRandom = json.Unmarshal([]byte("x"), &struct{}{})

func i64(v int64) *int64 { return &v }

func TestCheckDetail(t *testing.T) {
	cases := []struct {
		name string
		host models.HostStatus
		want string
	}{
		{"plain ping - nothing measured", models.HostStatus{}, ""},
		{"rtt over limit with loss", models.HostStatus{
			RTT: &models.RTTStats{Avg: 143.25, Threshold: 80, Jitter: 12.1, JitterThreshold: 20, Replies: 3, Probes: 5},
		}, "rtt avg 143.2ms (limit 80ms), jitter 12.1ms (limit 20ms), 3/5 replies"},
		{"rtt no thresholds, all replies", models.HostStatus{
			RTT: &models.RTTStats{Avg: 12.0, Replies: 5, Probes: 5},
		}, "rtt avg 12.0ms"},
		{"packet loss", models.HostStatus{
			PacketLoss: &models.PacketLossStats{Sent: 64, Received: 56, Lost: 8, LossPct: 12.5, Tolerance: 4},
		}, "loss 12.5% (8/64 lost, tolerance 4)"},
		{"snmp temperature over max", models.HostStatus{
			SNMP: &models.SNMPStats{CheckType: "high", LastValue: i64(52), High: 45},
		}, "reading 52 (max 45)"},
		{"snmp range", models.HostStatus{
			SNMP: &models.SNMPStats{CheckType: "range", LastValue: i64(3), Low: 10, High: 45},
		}, "reading 3 (range 10-45)"},
		{"snmp zero reading is still a reading", models.HostStatus{
			SNMP: &models.SNMPStats{CheckType: "low", LastValue: i64(0), Low: 10},
		}, "reading 0 (min 10)"},
		{"snmp rate value withheld (raw counter, not a rate)", models.HostStatus{
			SNMP: &models.SNMPStats{CheckType: "rate", LastValue: i64(981231231), Rate: 1000},
		}, ""},
		{"snmp reboot", models.HostStatus{
			SNMP: &models.SNMPStats{CheckType: "reboot", SysUpTime: 24 * 3600 * 100},
		}, "device uptime 1d 0h"},
	}
	for _, tc := range cases {
		if got := checkDetail(tc.host); got != tc.want {
			t.Errorf("%s: checkDetail = %q, want %q", tc.name, got, tc.want)
		}
	}
}

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
	svc.notifyAll("host DOWN", "", "host is unreachable",
		fcmData{Hostname: "host", Object: "host", Status: "CRITICAL"}, "OK", 1, true)
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
	svc.notifyAll("host RECOVERED", "", "host is back up",
		fcmData{Hostname: "host", Object: "host", Status: "OK"}, "CRITICAL", 0, false)
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
