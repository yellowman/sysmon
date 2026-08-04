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

const liveMain = `root = "core";
config authkey "livetestkey";
config sitename "livebox";
config sitedesc "Live test box";

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

// startLiveDaemon writes a config, runs sysmond on it, and returns the
// directory and port.
func startLiveDaemon(t *testing.T, port int) string {
	t.Helper()
	bin := sysmondPath(t)

	// The daemon drops privileges and then has to write this directory,
	// so it cannot live under a root-owned t.TempDir(). Using /tmp
	// directly and making it world-writable is what a real deployment
	// does differently (it gives the directory to the daemon's user), but
	// the property under test is the same.
	dir, err := os.MkdirTemp("/tmp", "sysmon-live-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })

	main := filepath.Join(dir, "sysmon.conf")
	if err := os.WriteFile(main, []byte(liveMain), 0666); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "hosts.conf"), []byte(liveInc), 0666); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0777); err != nil {
		t.Fatal(err)
	}

	cmd := exec.Command(bin, "-f", main, "-p", fmt.Sprint(port), "-d")
	cmd.Dir = dir
	if err := cmd.Start(); err != nil {
		t.Skipf("cannot run sysmond: %v", err)
	}
	t.Cleanup(func() {
		exec.Command("pkill", "-f", "sysmond -f "+main).Run()
	})

	// Wait for it to listen.
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		c, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), time.Second)
		if err == nil {
			c.Close()
			return dir
		}
		time.Sleep(200 * time.Millisecond)
	}
	t.Skip("sysmond never started listening")
	return dir
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

func TestLiveConfigRoundTrip(t *testing.T) {
	const port = 13460
	dir := startLiveDaemon(t, port)
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

	main := filepath.Join(dir, "sysmon.conf")
	inc := filepath.Join(dir, "hosts.conf")
	if files[0].Path != main || files[1].Path != inc {
		t.Errorf("files came back as %s, %s", files[0].Path, files[1].Path)
	}
	if string(files[0].Content) != liveMain {
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
	paths := []string{files[0].Path, files[1].Path}
	contents := [][]byte{files[0].Content, files[1].Content}
	if mine := config.HashFileSet(paths, contents); mine != hash {
		t.Errorf("hash disagreement\n sysmond: %s\n     Go: %s", hash, mine)
	}
}

func TestLiveDeliveryAndRollback(t *testing.T) {
	const port = 13461
	dir := startLiveDaemon(t, port)
	conn, reader := liveConn(t, port)

	original, _, originalHash, err := fetchConfigFiles(conn, reader)
	if err != nil {
		t.Fatalf("CONFIG-GET: %v", err)
	}
	inc := filepath.Join(dir, "hosts.conf")

	// A config sysmond itself refuses: the named root does not exist. It
	// parses; it also makes every object unreachable from the root, and
	// the daemon is the only thing that knows.
	bad := []settings.GenFile{
		{Path: original[0].Path,
			Content: []byte(strings.Replace(liveMain, `root = "core";`, `root = "nope";`, 1))},
		{Path: original[1].Path, Content: original[1].Content},
	}
	if _, _, _, complaints, err := putConfigFiles(conn, reader, 5, bad); err == nil {
		t.Error("the daemon accepted a config with an undefined root")
	} else if len(complaints) == 0 {
		t.Error("a rejection came back with no explanation from the parser")
	}

	// And it put the files back before answering.
	if got, _ := os.ReadFile(original[0].Path); string(got) != liveMain {
		t.Error("a rejected delivery was left on disk")
	}
	if _, _, hash, err := fetchConfigFiles(conn, reader); err != nil {
		t.Fatal(err)
	} else if hash != originalHash {
		t.Error("the box's hash changed after a rejected delivery")
	}

	// A real change.
	changed := []settings.GenFile{
		{Path: original[0].Path, Content: original[0].Content},
		{Path: original[1].Path,
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
	want := config.HashFileSet(
		[]string{changed[0].Path, changed[1].Path},
		[][]byte{changed[0].Content, changed[1].Content})
	if hash != want {
		t.Errorf("the box hashes the delivered config as %s, we compute %s", hash, want)
	}
	if got, _ := os.ReadFile(inc); !strings.Contains(string(got), "127.0.0.9") {
		t.Error("the change did not land on disk")
	}
	if got, _ := os.ReadFile(inc); !strings.Contains(string(got), "# hosts.conf") {
		t.Error("the include's comment did not survive delivery")
	}

	// Rollback restores the bytes without needing anything from here -
	// the previous generation is kept on the box precisely so that a
	// config which broke the link can still be undone.
	rgen, rhash, _, err := rollbackConfig(conn, reader)
	if err != nil {
		t.Fatalf("rollback: %v", err)
	}
	if rgen != 4 {
		t.Errorf("generation after rollback is %d, want 4", rgen)
	}
	if rhash != originalHash {
		t.Error("rollback did not restore the original bytes")
	}
	if got, _ := os.ReadFile(inc); string(got) != liveInc {
		t.Error("the include was not restored")
	}
}

// Whatever the other end asks for, the daemon writes only its own config
// directory. An aggregator is trusted with the monitoring config; it is
// not trusted with the filesystem.
func TestLiveContainment(t *testing.T) {
	const port = 13462
	dir := startLiveDaemon(t, port)
	conn, reader := liveConn(t, port)

	original, _, _, err := fetchConfigFiles(conn, reader)
	if err != nil {
		t.Fatalf("CONFIG-GET: %v", err)
	}

	outside := "/tmp/sysmond-must-never-write-this"
	os.Remove(outside)

	attempt := []settings.GenFile{
		{Path: original[0].Path, Content: original[0].Content},
		{Path: outside, Content: []byte("nope\n")},
	}
	if _, _, _, _, err := putConfigFiles(conn, reader, 6, attempt); err == nil {
		t.Error("the daemon accepted a write outside its config directory")
	}
	if _, err := os.Stat(outside); err == nil {
		os.Remove(outside)
		t.Fatalf("sysmond wrote %s", outside)
	}

	// A delivery that leaves out the main config would be validating a
	// set that does not include the file the daemon actually reads.
	justInc := []settings.GenFile{{Path: original[1].Path, Content: original[1].Content}}
	if _, _, _, _, err := putConfigFiles(conn, reader, 6, justInc); err == nil {
		t.Error("the daemon accepted a delivery without the main config file")
	}

	_ = dir
}
