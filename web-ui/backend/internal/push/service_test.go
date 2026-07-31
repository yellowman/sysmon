package push

import (
	"encoding/json"
	"net/http"
	"path/filepath"
	"testing"

	bolt "go.etcd.io/bbolt"
)

// seedSubscription writes a raw subscription row straight into the db,
// bypassing Subscribe's validation — simulating rows created by old
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

	if _, err := svc.Subscribe("tok-test-device", PlatformAndroid, "pixel", "chris", "", ""); err != nil {
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
