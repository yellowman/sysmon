package monitoring

import (
	"strings"
	"testing"

	"sysmon-web/internal/settings"
)

func conf(body string) []settings.GenFile {
	return []settings.GenFile{{Name: "sysmon.conf", Content: []byte(body)}}
}

const uplinkBase = `root = "core";
config sitename "metro";
config aggregator "web.example.net:1347";
config aggregator-token "abc123";

object core {
	ip "10.0.0.1";
	type ping;
};
`

// The edits an operator actually makes must go through untouched. A guard
// that blocks ordinary work gets removed, and then it guards nothing.
func TestOrdinaryEditsAreAllowed(t *testing.T) {
	cases := []struct {
		name string
		body string
	}{
		{"adding an object", uplinkBase + "\nobject leaf {\n\tip \"10.0.0.2\";\n\ttype ping;\n};\n"},
		{"changing an address", strings.Replace(uplinkBase, "10.0.0.1", "10.0.0.9", 1)},
		{"changing the site description", uplinkBase + "config sitedesc \"Metro\";\n"},
		{"adding a comment", "# a note\n" + uplinkBase},
		{"re-indenting the uplink line", strings.Replace(uplinkBase,
			`config aggregator "web.example.net:1347";`,
			`  config    aggregator   "web.example.net:1347";`, 1)},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := checkUplinkUnchanged(conf(uplinkBase), conf(tc.body)); err != nil {
				t.Errorf("refused an ordinary edit: %v", err)
			}
		})
	}
}

// Every way of moving the box has to be caught, including the quiet ones.
func TestMovingTheBoxIsRefused(t *testing.T) {
	cases := []struct {
		name string
		body string
	}{
		{"pointing it at another sysmon-web", strings.Replace(uplinkBase,
			"web.example.net:1347", "elsewhere.example.net:1347", 1)},
		{"changing only the port", strings.Replace(uplinkBase,
			"web.example.net:1347", "web.example.net:9999", 1)},
		{"changing the token", strings.Replace(uplinkBase, "abc123", "def456", 1)},
		{"removing the aggregator line", strings.Replace(uplinkBase,
			"config aggregator \"web.example.net:1347\";\n", "", 1)},
		{"commenting the aggregator line out", strings.Replace(uplinkBase,
			"config aggregator \"web.example.net:1347\";",
			"# config aggregator \"web.example.net:1347\";", 1)},
		{"adding a second one", uplinkBase + "config aggregator \"other:1347\";\n"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := checkUplinkUnchanged(conf(uplinkBase), conf(tc.body))
			if err == nil {
				t.Error("allowed an edit that moves the box")
			}
		})
	}
}

// A token proves a box to this process. It must not travel in an error,
// because errors reach logs, screens and tickets.
func TestTheTokenIsNotPutInTheError(t *testing.T) {
	err := checkUplinkUnchanged(conf(uplinkBase),
		conf(strings.Replace(uplinkBase, "abc123", "def456", 1)))
	if err == nil {
		t.Fatal("expected a refusal")
	}
	if strings.Contains(err.Error(), "abc123") || strings.Contains(err.Error(), "def456") {
		t.Errorf("the token is in the error text: %v", err)
	}
	if !strings.Contains(err.Error(), "hidden") {
		t.Errorf("the message does not say a value was withheld: %v", err)
	}
}

// "config aggregator-token" starts with "config aggregator". Matching the
// shorter one loosely would make the two indistinguishable.
func TestTheTwoDirectivesAreToldApart(t *testing.T) {
	lines := uplinkLines(conf(uplinkBase))
	if len(lines) != 2 {
		t.Fatalf("found %d uplink lines, want 2: %v", len(lines), lines)
	}

	// A directive that merely starts with the same letters is not one.
	other := uplinkLines(conf("config aggregatorfoo \"x\";\n"))
	if len(other) != 0 {
		t.Errorf("matched an unrelated directive: %v", other)
	}
}

// The uplink lives in one file, but an operator may edit any of them.
func TestAnIncludeCannotSmuggleItIn(t *testing.T) {
	was := []settings.GenFile{
		{Name: "sysmon.conf", Content: []byte(uplinkBase)},
		{Name: "hosts.conf", Content: []byte("object leaf { ip \"10.0.0.2\"; type ping; };\n")},
	}
	now := []settings.GenFile{
		{Name: "sysmon.conf", Content: []byte(uplinkBase)},
		{Name: "hosts.conf", Content: []byte(
			"config aggregator \"elsewhere:1347\";\nobject leaf { ip \"10.0.0.2\"; type ping; };\n")},
	}
	if err := checkUplinkUnchanged(was, now); err == nil {
		t.Error("an include was allowed to add an aggregator directive")
	}
}
