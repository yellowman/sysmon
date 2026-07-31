package config

import (
	"strings"
	"testing"
)

// sysmond supports multiple "dep" lines per object (it builds a
// dependency list). Parsing must keep them all, and generating must
// write one line each - otherwise saving from the web UI quietly
// destroys every dependency but the last.
func TestMultipleDependenciesRoundTrip(t *testing.T) {
	src := `root = "core";

object core {
	ip "10.0.0.1";
	type ping;
};

object leaf {
	ip "10.0.0.9";
	type ping;
	dep "core";
	dep "dist-a";
	dep "dist-b";
};
`
	cfg, err := Parse([]byte(src))
	if err != nil {
		t.Fatalf("ParseConfig: %v", err)
	}
	var leaf *struct{ deps string }
	for i := range cfg.Hosts {
		if cfg.Hosts[i].ID == "leaf" {
			leaf = &struct{ deps string }{cfg.Hosts[i].Dependencies}
		}
	}
	if leaf == nil {
		t.Fatalf("leaf host not parsed; got %d hosts", len(cfg.Hosts))
	}
	for _, want := range []string{"core", "dist-a", "dist-b"} {
		if !strings.Contains(leaf.deps, want) {
			t.Errorf("dependency %q lost during parse (got %q)", want, leaf.deps)
		}
	}

	out, err := Generate(cfg)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	for _, want := range []string{`dep "core";`, `dep "dist-a";`, `dep "dist-b";`} {
		if !strings.Contains(out, want) {
			t.Errorf("generated config missing %s\n---\n%s", want, out)
		}
	}
	if strings.Contains(out, `dep "core, dist-a`) {
		t.Errorf("dependencies emitted as one comma-joined name:\n%s", out)
	}
}
