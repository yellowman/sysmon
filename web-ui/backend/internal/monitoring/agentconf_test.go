package monitoring

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// The block goes to a person who pastes it into a config file. So the
// test is not "does it contain the word aggregator" - it is "does sysmond
// accept it". sysmond -t reads a config and reports what is wrong with
// it.
func TestAgentConfigBlockParses(t *testing.T) {
	daemon := findSysmond()
	if daemon == "" {
		t.Skip("sysmond is not built; run make in src/ first")
	}

	block := AgentConfigBlock("metro", "Metro Station - rack 4",
		"sysmon-web.example.net:1347", "s3cr3t-token")

	// A config with no object is not a config, so the block gets the
	// smallest one that stands on its own.
	full := block + "\nroot = \"gw\";\n\nobject gw {\n" +
		"\tip \"127.0.0.1\";\n\ttype ping;\n\tdesc \"gateway\";\n" +
		"\tcontact \"nobody@example.net\";\n};\n"

	path := filepath.Join(t.TempDir(), "sysmon.conf")
	if err := os.WriteFile(path, []byte(full), 0o600); err != nil {
		t.Fatal(err)
	}

	out, err := exec.Command(daemon, "-t", "-f", path).CombinedOutput()
	if err != nil {
		t.Fatalf("cannot run %s -t: %v\n%s", daemon, err, out)
	}
	// sysmond -t exits 0 whatever it finds, and says nothing about a
	// config it accepts. So silence is the pass, and any line at all -
	// "Unknown information c", "spawn definition outside" - is a
	// complaint about the block this package generated.
	if got := strings.TrimSpace(string(out)); got != "" {
		t.Fatalf("sysmond complained about the generated block:\n%s\n---\n%s",
			got, full)
	}
}

// The token is the one thing here that cannot be looked up again, so it
// has to be in the text a person copies.
func TestAgentConfigBlockHoldsTheToken(t *testing.T) {
	block := AgentConfigBlock("metro", "", "web.example.net:9999", "tok-123")

	for _, want := range []string{
		`config sitename  "metro";`,
		`config sitedesc  "metro";`, // no label, so the site name stands in
		`config aggregator "web.example.net:9999";`,
		`config aggregator-token "tok-123";`,
	} {
		if !strings.Contains(block, want) {
			t.Errorf("the block is missing %q:\n%s", want, block)
		}
	}
}

func TestDialTarget(t *testing.T) {
	cases := []struct{ names, listen, want string }{
		{"sysmon-web.example.net", ":1347", "sysmon-web.example.net:1347"},
		{"a.example.net, b.example.net", ":9999", "a.example.net:9999"},
		{"192.0.2.7", "0.0.0.0:1347", "192.0.2.7:1347"},
		// No listen address to read a port from: say 1347 rather than
		// printing a line with no port in it.
		{"web.example.net", "", "web.example.net:1347"},
	}
	for _, c := range cases {
		if got := DialTarget(c.names, c.listen); got != c.want {
			t.Errorf("DialTarget(%q, %q) = %q, want %q",
				c.names, c.listen, got, c.want)
		}
	}
}

func findSysmond() string {
	// The test runs in web-ui/backend/internal/monitoring.
	for _, p := range []string{
		"../../../../src/sysmond",
		"../../../../src/syswatch",
	} {
		if st, err := os.Stat(p); err == nil && st.Mode()&0o111 != 0 {
			abs, err := filepath.Abs(p)
			if err == nil {
				return abs
			}
		}
	}
	return ""
}
