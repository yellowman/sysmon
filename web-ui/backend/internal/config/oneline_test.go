package config

import "testing"

// sysmond's lexer reads tokens, not lines, so an object written on one
// line is ordinary config. This parser read a line at a time and lost
// every such object: it took the name, dropped the fields that shared
// the line, and never saw a closing brace alone - so nothing was ever
// appended, and a working config showed up in the editor as no hosts.
func TestSingleLineObjectIsParsed(t *testing.T) {
	cfg, err := Parse([]byte(`root = "gw";
object gw { ip "127.0.0.1"; type ping; desc "gateway"; contact "a@b"; };
object lat { ip "10.0.0.1"; type rtt; rtt_threshold 150; rtt_interval 50; };
`))
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Hosts) != 2 {
		t.Fatalf("got %d hosts, want 2", len(cfg.Hosts))
	}

	byName := map[string]int{}
	for i, h := range cfg.Hosts {
		byName[h.Hostname] = i
	}

	gw := cfg.Hosts[byName["gw"]]
	if gw.IP != "127.0.0.1" || gw.Type != "ping" || gw.Notes != "gateway" {
		t.Errorf("gw fields lost: ip=%q type=%q desc=%q", gw.IP, gw.Type, gw.Notes)
	}

	lat := cfg.Hosts[byName["lat"]]
	if lat.Type != "rtt" || lat.RTTThreshold != 150 || lat.RTTInterval != 50 {
		t.Errorf("lat fields lost: type=%q thr=%d interval=%d",
			lat.Type, lat.RTTThreshold, lat.RTTInterval)
	}
}

// The two things normalisation must not cut through.
func TestSplitStatementsRespectsQuotesAndComments(t *testing.T) {
	// A semicolon inside a quoted value is part of the value, and a
	// semicolon at the start of a line is a comment marker - which is
	// why ";" alone cannot be treated as a terminator.
	cfg, err := Parse([]byte(`; this leading-semicolon comment must stay a comment
;; so must this
object x {
	ip "127.0.0.1";
	type ping;
	desc "restart; then check";	# trailing comment; with a semicolon
	contact "a@b";
};
`))
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Hosts) != 1 {
		t.Fatalf("got %d hosts, want 1", len(cfg.Hosts))
	}
	if got := cfg.Hosts[0].Notes; got != "restart; then check" {
		t.Errorf("a semicolon inside a quoted value was treated as a terminator: desc=%q", got)
	}
}

// Multi-line configs parsed before this change and must be unaffected.
func TestMultiLineObjectStillParses(t *testing.T) {
	cfg, err := Parse([]byte(`root = "gw";

object gw {
	ip "127.0.0.1";
	type ping;
	desc "gateway";
	contact "a@b";
};
`))
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Hosts) != 1 || cfg.Hosts[0].Hostname != "gw" ||
		cfg.Hosts[0].Notes != "gateway" {
		t.Fatalf("multi-line parse regressed: %+v", cfg.Hosts)
	}
}
