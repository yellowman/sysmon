package config

import (
	"strings"
	"testing"
)

// A version an operator set must survive a load/save cycle, and a default
// one must not sprout a directive nobody asked for.
func TestSNMPVersionRoundTrip(t *testing.T) {
	src := `root = "a";
object a {
	ip "10.0.0.1";
	type snmp;
	snmp-version "1";
	snmp-type "high";
	oid ".1.3.6.1.2.1.1.3.0";
	community "public";
};
object b {
	ip "10.0.0.2";
	type snmp;
	snmp-type "high";
	oid ".1.3.6.1.2.1.1.3.0";
	community "public";
	dep "a";
};
`
	cfg, err := Parse([]byte(src))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	for _, h := range cfg.Hosts {
		switch h.ID {
		case "a":
			if h.SNMPVersion != "1" {
				t.Errorf("a: snmp-version = %q, want 1", h.SNMPVersion)
			}
		case "b":
			if h.SNMPVersion != "" {
				t.Errorf("b: snmp-version = %q, want empty (default)", h.SNMPVersion)
			}
		}
	}

	out, err := Generate(cfg)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	if strings.Count(out, `snmp-version "1";`) != 1 {
		t.Errorf("generated config should carry exactly one snmp-version:\n%s", out)
	}

	again, err := Parse([]byte(out))
	if err != nil {
		t.Fatalf("reparse: %v", err)
	}
	for _, h := range again.Hosts {
		if h.ID == "a" && h.SNMPVersion != "1" {
			t.Errorf("after a save/load cycle a lost its version: %q", h.SNMPVersion)
		}
		if h.ID == "b" && h.SNMPVersion != "" {
			t.Errorf("b gained a version it never had: %q", h.SNMPVersion)
		}
	}
}
