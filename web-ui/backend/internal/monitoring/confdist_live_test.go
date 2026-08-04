package monitoring

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"sysmon-web/internal/config"
	"sysmon-web/internal/settings"
)

// The one test that proves config distribution works, because it is the
// only one where both implementations are present: a real sysmond binary
// on one side and this package on the other.
//
// Everything else here can agree with itself and still be wrong. The
// content hash in particular is only useful if two separate programs, in
// two languages, compute the same 64 hex digits over the same bytes -
// and there is no way to check that without running the daemon.
//
// It also checks the property that shapes the whole design: the seed
// config is never written. Every delivery lands in the daemon's own
// directory, so managing a box does not mean making /etc writable by the
// user the daemon drops to.
//
// Skipped, not failed, when there is no sysmond to run: this has to stay
// runnable on a machine that has not built the C half.

func sysmondPath(t *testing.T) string {
	t.Helper()
	if p := os.Getenv("SYSMOND"); p != "" {
		return p
	}
	// ../../../../src/sysmond from internal/monitoring
	p, err := filepath.Abs(filepath.Join("..", "..", "..", "..", "src", "sysmond"))
	if err != nil {
		t.Skip("cannot resolve the sysmond path")
	}
	if _, err := os.Stat(p); err != nil {
		t.Skipf("no sysmond built at %s - run make in src/", p)
	}
	return p
}

const liveMainTmpl = `root = "core";
config authkey "livetestkey";
config sitename "livebox";
config sitedesc "Live test box";
config generation-dir "%s";

include "hosts.conf";

# This comment has to survive a round trip through the fleet.
object core {
	ip "127.0.0.1";
	type ping;
	desc "core";
};
`

const liveInc = `# hosts.conf
object leaf {
	ip "127.0.0.2";
	type ping;
	desc "leaf";
	dep "core";
};
`

// liveBox is a running daemon plus the two directories that matter: the
// seed, which must stay untouched, and the state directory, which is the
// only place a managed config may land.
type liveBox struct {
	seedDir  string
	genDir   string
	mainPath string
	incPath  string
	mainBody string
}

func (b *liveBox) live(name string) string {
	return filepath.Join(b.genDir, "current", name)
}

func startLiveDaemon(t *testing.T, port int) *liveBox {
	t.Helper()
	bin := sysmondPath(t)

	// The daemon drops privileges and then has to write the state
	// directory, so neither of these can live under a root-owned
	// t.TempDir(). A real deployment gives the state directory to the
	// daemon's user; here it is world-writable, which exercises the same
	// property.
	root, err := os.MkdirTemp("/tmp", "sysmon-live-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(root) })

	b := &liveBox{
		seedDir: filepath.Join(root, "etc"),
		genDir:  filepath.Join(root, "state"),
	}
	if err := os.MkdirAll(b.seedDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(b.genDir, 0o777); err != nil {
		t.Fatal(err)
	}
	os.Chmod(root, 0o755)
	os.Chmod(b.genDir, 0o777)

	b.mainPath = filepath.Join(b.seedDir, "sysmon.conf")
	b.incPath = filepath.Join(b.seedDir, "hosts.conf")
	b.mainBody = fmt.Sprintf(liveMainTmpl, b.genDir)

	// The seed is deliberately not writable by anyone but its owner: if
	// the daemon ever tries, the test fails rather than quietly succeeding
	// on a machine where the test happens to run as root.
	if err := os.WriteFile(b.mainPath, []byte(b.mainBody), 0o444); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(b.incPath, []byte(liveInc), 0o444); err != nil {
		t.Fatal(err)
	}

	cmd := exec.Command(bin, "-f", b.mainPath, "-p", fmt.Sprint(port), "-d")
	cmd.Dir = b.seedDir
	if err := cmd.Start(); err != nil {
		t.Skipf("cannot run sysmond: %v", err)
	}
	t.Cleanup(func() {
		exec.Command("pkill", "-f", "sysmond -f "+b.mainPath).Run()
	})

	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		c, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), time.Second)
		if err == nil {
			c.Close()
			return b
		}
		time.Sleep(200 * time.Millisecond)
	}
	t.Skip("sysmond never started listening")
	return b
}

// seedIntact is asserted after anything that could have written it.
func (b *liveBox) seedIntact(t *testing.T, when string) {
	t.Helper()
	if got, _ := os.ReadFile(b.mainPath); string(got) != b.mainBody {
		t.Errorf("%s: the seed config was written", when)
	}
	if got, _ := os.ReadFile(b.incPath); string(got) != liveInc {
		t.Errorf("%s: the seed include was written", when)
	}
}

func liveConn(t *testing.T, port int) (net.Conn, *bufio.Reader) {
	t.Helper()
	c, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	c.SetDeadline(time.Now().Add(60 * time.Second))
	r := bufio.NewReader(c)
	if err := readWelcomeBanner(r); err != nil {
		t.Fatal(err)
	}
	if err := authenticate(c, r, "livetestkey"); err != nil {
		t.Fatal(err)
	}
	return c, r
}

func names(files []settings.GenFile) []string {
	out := make([]string, len(files))
	for i, f := range files {
		out[i] = f.Name
	}
	return out
}

func contents(files []settings.GenFile) [][]byte {
	out := make([][]byte, len(files))
	for i, f := range files {
		out[i] = f.Content
	}
	return out
}

func TestLiveConfigRoundTrip(t *testing.T) {
	const port = 13460
	b := startLiveDaemon(t, port)
	conn, reader := liveConn(t, port)

	files, gen, hash, err := fetchConfigFiles(conn, reader)
	if err != nil {
		t.Fatalf("CONFIG-GET: %v", err)
	}
	if gen != 0 {
		t.Errorf("an unmanaged box reports generation %d, want 0", gen)
	}
	if len(files) != 2 {
		t.Fatalf("got %d files, want the main config and its include", len(files))
	}

	// Names, not paths: what comes back has to mean the same thing on a
	// box whose seed lives somewhere else.
	if got := names(files); got[0] != "sysmon.conf" || got[1] != "hosts.conf" {
		t.Errorf("files came back as %v, want plain names in load order", got)
	}
	if string(files[0].Content) != b.mainBody {
		t.Error("the main config did not come back byte-identical")
	}
	if string(files[1].Content) != liveInc {
		t.Error("the include did not come back byte-identical")
	}
	if !strings.Contains(string(files[0].Content), "# This comment has to survive") {
		t.Error("comments did not survive the transfer")
	}

	// The point of the whole exercise: two programs, two languages, the
	// same 64 hex digits over the same bytes.
	if mine := config.HashFileSet(names(files), contents(files)); mine != hash {
		t.Errorf("hash disagreement\n sysmond: %s\n     Go: %s", hash, mine)
	}
}

func TestLiveDeliveryAndRollback(t *testing.T) {
	const port = 13461
	b := startLiveDaemon(t, port)
	conn, reader := liveConn(t, port)

	original, _, originalHash, err := fetchConfigFiles(conn, reader)
	if err != nil {
		t.Fatalf("CONFIG-GET: %v", err)
	}

	// A config sysmond itself refuses: the named root does not exist. It
	// parses; it also makes every object unreachable from the root, and
	// the daemon is the only thing that knows.
	bad := []settings.GenFile{
		{Name: "sysmon.conf",
			Content: []byte(strings.Replace(b.mainBody, `root = "core";`, `root = "nope";`, 1))},
		{Name: "hosts.conf", Content: original[1].Content},
	}
	if _, _, _, complaints, err := putConfigFiles(conn, reader, 5, bad); err == nil {
		t.Error("the daemon accepted a config with an undefined root")
	} else if len(complaints) == 0 {
		t.Error("a rejection came back with no explanation from the parser")
	}
	b.seedIntact(t, "after a rejected delivery")
	if _, err := os.Stat(b.live("sysmon.conf")); err == nil {
		t.Error("a rejected delivery left something live")
	}
	if _, _, hash, err := fetchConfigFiles(conn, reader); err != nil {
		t.Fatal(err)
	} else if hash != originalHash {
		t.Error("the box's hash changed after a rejected delivery")
	}

	// A real change.
	changed := []settings.GenFile{
		{Name: "sysmon.conf", Content: original[0].Content},
		{Name: "hosts.conf",
			Content: []byte(strings.Replace(liveInc, "127.0.0.2", "127.0.0.9", 1))},
	}
	gen, hash, objects, _, err := putConfigFiles(conn, reader, 5, changed)
	if err != nil {
		t.Fatalf("delivering a valid config: %v", err)
	}
	if gen != 5 {
		t.Errorf("the box reports generation %d, want the 5 we delivered", gen)
	}
	if objects != 2 {
		t.Errorf("the box counted %d objects, want 2", objects)
	}
	if want := config.HashFileSet(names(changed), contents(changed)); hash != want {
		t.Errorf("the box hashes the delivered config as %s, we compute %s", hash, want)
	}

	// It landed in the daemon's own directory, and nowhere near the seed.
	b.seedIntact(t, "after a delivery")
	got, rerr := os.ReadFile(b.live("hosts.conf"))
	if rerr != nil {
		t.Fatalf("the delivery is not in the state directory: %v", rerr)
	}
	if !strings.Contains(string(got), "127.0.0.9") {
		t.Error("the change did not land")
	}
	if !strings.Contains(string(got), "# hosts.conf") {
		t.Error("the include's comment did not survive delivery")
	}

	// One generation is not enough to roll back to.
	if _, _, _, err := rollbackConfig(conn, reader); err == nil {
		t.Error("rolled back with no previous generation to roll back to")
	}

	// Two are.
	again := []settings.GenFile{
		{Name: "sysmon.conf", Content: original[0].Content},
		{Name: "hosts.conf",
			Content: []byte(strings.Replace(liveInc, "127.0.0.2", "127.0.0.77", 1))},
	}
	if _, _, _, _, err := putConfigFiles(conn, reader, 6, again); err != nil {
		t.Fatalf("delivering generation 6: %v", err)
	}
	rgen, rhash, _, err := rollbackConfig(conn, reader)
	if err != nil {
		t.Fatalf("rollback: %v", err)
	}
	if rgen != 5 {
		t.Errorf("generation after rollback is %d, want 5", rgen)
	}
	if want := config.HashFileSet(names(changed), contents(changed)); rhash != want {
		t.Error("rollback did not restore generation 5's bytes")
	}
	b.seedIntact(t, "after a rollback")

	// And the way out: stop being managed, go back to the seed.
	code, _, err := revertConfig(conn, reader)
	if err != nil {
		t.Fatalf("revert: %v", err)
	}
	if code != 0 {
		t.Errorf("generation after revert is %d, want 0", code)
	}
	// The reload happens at the top of the daemon's next main-loop pass,
	// so what it reports is only the seed's once that has run.
	deadline := time.Now().Add(10 * time.Second)
	for {
		_, gen, hash, err = fetchConfigFiles(conn, reader)
		if err != nil {
			t.Fatal(err)
		}
		if gen == 0 && hash == originalHash {
			break
		}
		if time.Now().After(deadline) {
			t.Errorf("after revert the box reports generation %d hash %s, want 0 and the seed's",
				gen, hash)
			break
		}
		time.Sleep(250 * time.Millisecond)
	}
	b.seedIntact(t, "after a revert")
}

// Whatever the other end asks for, the daemon writes only its own state
// directory. It is trusted with the monitoring config; it is not trusted
// with the filesystem.
func TestLiveContainment(t *testing.T) {
	const port = 13462
	b := startLiveDaemon(t, port)
	conn, reader := liveConn(t, port)

	original, _, _, err := fetchConfigFiles(conn, reader)
	if err != nil {
		t.Fatalf("CONFIG-GET: %v", err)
	}

	outside := "/tmp/sysmond-must-never-write-this"
	os.Remove(outside)

	for _, bad := range []string{outside, "../escape.conf", "sub/x.conf", ".."} {
		attempt := []settings.GenFile{
			{Name: "sysmon.conf", Content: original[0].Content},
			{Name: bad, Content: []byte("nope\n")},
		}
		if _, _, _, _, err := putConfigFiles(conn, reader, 6, attempt); err == nil {
			t.Errorf("the daemon accepted %q as a file name", bad)
		}
	}
	if _, err := os.Stat(outside); err == nil {
		os.Remove(outside)
		t.Fatalf("sysmond wrote %s", outside)
	}
	b.seedIntact(t, "after refused deliveries")

	// A delivery that leaves out the main config would be validating a
	// set that does not include the file the daemon actually reads.
	justInc := []settings.GenFile{{Name: "hosts.conf", Content: original[1].Content}}
	if _, _, _, _, err := putConfigFiles(conn, reader, 6, justInc); err == nil {
		t.Error("the daemon accepted a delivery without the main config file")
	}
}
