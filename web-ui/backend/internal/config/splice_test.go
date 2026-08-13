package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"sysmon-web/internal/models"
)

const mainConf = `# Site: bend-noc
# This comment must survive everything.

root = "core";

config queuetime 60;      # inline comment
include "hosts.conf";

# The core router. Do not delete without telling Dave.
object core {
	ip "10.0.0.1";
	type ping;
	desc "core router";
};

object leaf {
	ip "10.0.0.2";
	type ping;
	desc "a leaf";
	dep "core";
};
`

const incConf = `# hosts.conf - the access layer
object accessw {
	ip "10.0.1.1";
	type ping;
	desc "access switch";
	dep "core";
};
`

func writeConf(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	main := filepath.Join(dir, "sysmon.conf")
	if err := os.WriteFile(main, []byte(mainConf), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "hosts.conf"), []byte(incConf), 0644); err != nil {
		t.Fatal(err)
	}
	return main
}

func TestDocumentFindsObjectsAcrossIncludes(t *testing.T) {
	d, err := LoadDocument(writeConf(t))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"core", "leaf", "accessw"} {
		if _, ok := d.Objects[want]; !ok {
			t.Errorf("object %q not found", want)
		}
	}
	if d.Objects["accessw"].File == d.MainPath {
		t.Error("accessw should be recorded in the included file, not the main one")
	}
}

// The point of the whole exercise: an edit that changes nothing must
// change nothing.
func TestUnchangedApplyRewritesNothing(t *testing.T) {
	main := writeConf(t)
	d, err := LoadDocument(main)
	if err != nil {
		t.Fatal(err)
	}
	before := d.Hash()

	cfg, err := ParseFile(main)
	if err != nil {
		t.Fatal(err)
	}
	added, changed, removed := d.Apply(cfg)
	if added+changed+removed != 0 {
		t.Errorf("a no-op save touched objects: +%d ~%d -%d", added, changed, removed)
	}
	if got := d.Hash(); got != before {
		t.Error("a no-op save changed the config hash")
	}
	if len(d.Dirty()) != 0 {
		t.Errorf("a no-op save marked files dirty: %v", d.Dirty())
	}
}

func TestEditPreservesCommentsAndIncludes(t *testing.T) {
	main := writeConf(t)
	d, err := LoadDocument(main)
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := ParseFile(main)
	if err != nil {
		t.Fatal(err)
	}

	for i := range cfg.Hosts {
		if cfg.Hosts[i].Hostname == "leaf" {
			cfg.Hosts[i].IP = "10.9.9.9"
		}
	}
	if _, changed, _ := d.Apply(cfg); changed != 1 {
		t.Fatalf("expected exactly one changed object, got %d", changed)
	}

	out := string(d.Files[main])
	for _, want := range []string{
		"# Site: bend-noc",
		"# This comment must survive everything.",
		"# The core router. Do not delete without telling Dave.",
		`include "hosts.conf";`,
		"# inline comment",
		`ip "10.9.9.9";`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("edit destroyed %q", want)
		}
	}
	// the untouched include must not have been rewritten at all
	for _, f := range d.Dirty() {
		if f != main {
			t.Errorf("editing the main file dirtied %s", f)
		}
	}
}

func TestEditInsideAnIncludeStaysThere(t *testing.T) {
	main := writeConf(t)
	d, err := LoadDocument(main)
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := ParseFile(main)
	if err != nil {
		t.Fatal(err)
	}
	for i := range cfg.Hosts {
		if cfg.Hosts[i].Hostname == "accessw" {
			cfg.Hosts[i].Notes = "access switch, rack 4"
		}
	}
	d.Apply(cfg)

	inc := filepath.Join(filepath.Dir(main), "hosts.conf")
	if !strings.Contains(string(d.Files[inc]), "rack 4") {
		t.Error("the edit did not land in the file the object lives in")
	}
	if strings.Contains(string(d.Files[main]), "accessw") {
		t.Error("an included object leaked into the main file")
	}
	if !strings.Contains(string(d.Files[inc]), "# hosts.conf - the access layer") {
		t.Error("the include's own comment was destroyed")
	}
}

func TestAddAndDelete(t *testing.T) {
	main := writeConf(t)
	d, err := LoadDocument(main)
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := ParseFile(main)
	if err != nil {
		t.Fatal(err)
	}

	kept := cfg.Hosts[:0]
	for _, h := range cfg.Hosts {
		if h.Hostname != "leaf" {
			kept = append(kept, h)
		}
	}
	cfg.Hosts = append(kept, models.Host{
		ID: "newthing", Hostname: "newthing", IP: "10.5.5.5", Type: "ping",
	})

	added, _, removed := d.Apply(cfg)
	if added != 1 || removed != 1 {
		t.Errorf("expected +1/-1, got +%d/-%d", added, removed)
	}
	out := string(d.Files[main])
	if strings.Contains(out, "object leaf {") {
		t.Error("deleted object is still there")
	}
	if !strings.Contains(out, "object newthing {") {
		t.Error("added object is missing")
	}
	if !strings.Contains(out, "# The core router. Do not delete without telling Dave.") {
		t.Error("a delete took a neighbouring comment with it")
	}
}

// Deleting several objects from one file at once. Each delete reindexes
// that file, so a delete pass that walks the live object map is walking a
// map that is being rewritten underneath it - and quietly leaves objects
// behind. One-at-a-time deletes never showed it.
func TestDeleteManyAtOnce(t *testing.T) {
	dir := t.TempDir()
	main := filepath.Join(dir, "sysmon.conf")

	var src strings.Builder
	src.WriteString("root = \"keep0\";\n\n")
	for i := 0; i < 8; i++ {
		fmt.Fprintf(&src, "object keep%d {\n\tip \"10.0.0.%d\";\n\ttype ping;\n};\n\n", i, i)
		fmt.Fprintf(&src, "object drop%d {\n\tip \"10.1.0.%d\";\n\ttype ping;\n};\n\n", i, i)
	}
	if err := os.WriteFile(main, []byte(src.String()), 0644); err != nil {
		t.Fatal(err)
	}

	d, err := LoadDocument(main)
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := ParseFile(main)
	if err != nil {
		t.Fatal(err)
	}

	kept := cfg.Hosts[:0]
	for _, h := range cfg.Hosts {
		if !strings.HasPrefix(h.Hostname, "drop") {
			kept = append(kept, h)
		}
	}
	cfg.Hosts = kept

	_, _, removed := d.Apply(cfg)
	if removed != 8 {
		t.Errorf("removed %d objects, want 8", removed)
	}
	out := string(d.Files[main])
	for i := 0; i < 8; i++ {
		if strings.Contains(out, fmt.Sprintf("object drop%d {", i)) {
			t.Errorf("drop%d survived the delete", i)
		}
		if !strings.Contains(out, fmt.Sprintf("object keep%d {", i)) {
			t.Errorf("keep%d was deleted by mistake", i)
		}
	}
	if _, still := d.Objects["drop3"]; still {
		t.Error("a deleted object is still indexed")
	}
}

// Two identical saves must produce identical bytes. Appending new objects
// in map order would not: the fleet compares config hashes, so a config
// that hashes differently every save reads as "somebody edited this box"
// forever.
func TestApplyIsDeterministic(t *testing.T) {
	var first string
	for run := 0; run < 8; run++ {
		main := writeConf(t)
		d, err := LoadDocument(main)
		if err != nil {
			t.Fatal(err)
		}
		cfg, err := ParseFile(main)
		if err != nil {
			t.Fatal(err)
		}
		for i := 0; i < 12; i++ {
			name := fmt.Sprintf("added%02d", i)
			cfg.Hosts = append(cfg.Hosts, models.Host{
				ID: name, Hostname: name,
				IP: fmt.Sprintf("10.7.0.%d", i), Type: "ping",
			})
		}
		if added, _, _ := d.Apply(cfg); added != 12 {
			t.Fatalf("added %d objects, want 12", added)
		}

		out := string(d.Files[main])
		if run == 0 {
			first = out
			continue
		}
		if out != first {
			t.Fatal("the same save produced different bytes on a second run")
		}
	}
	// and the order is the caller's, not a shuffle
	pos := -1
	for i := 0; i < 12; i++ {
		at := strings.Index(first, fmt.Sprintf("object added%02d {", i))
		if at < 0 {
			t.Fatalf("added%02d is missing", i)
		}
		if at < pos {
			t.Errorf("added%02d was written out of order", i)
		}
		pos = at
	}
}

// Braces and hashes inside quoted strings must not confuse the scanner.
func TestScannerIsNotFooledByStrings(t *testing.T) {
	src := []byte(`object weird {
	ip "10.0.0.1";
	type ping;
	desc "a } brace and a # hash walk into a bar";
	spawn "echo {} # not a comment";
};

object after {
	ip "10.0.0.2";
	type ping;
};
`)
	objs := scanObjects(src)
	if len(objs) != 2 {
		t.Fatalf("found %d objects, want 2", len(objs))
	}
	if got := objectName(src[objs[0].Start:objs[0].End]); got != "weird" {
		t.Errorf("first object is %q", got)
	}
	if got := objectName(src[objs[1].Start:objs[1].End]); got != "after" {
		t.Errorf("second object is %q", got)
	}
}

// The fleet save path splices the box's file set for two reasons that
// are invisible until they bite: the model has no fields for the box's
// `config aggregator` lines, so regenerating dropped them and the
// uplink guard then refused every save; and the model's defaults are
// not the daemon's, so regeneration injected `config queuetime 300;`
// into configs that never set one, silently slowing every check 5x.
// This is the round trip a structured fleet save performs.
func TestApplyPreservesUplinkAndInjectsNothing(t *testing.T) {
	const boxConf = `# managed box - this comment must survive
root = "gw";
config sitename "second";
config aggregator "sysmon-web.example.net:1347";
config aggregator-token "tok-abc123";

object gw {
	ip "10.9.0.1";
	type ping;
	desc "gateway";
};
`
	dir := t.TempDir()
	main := filepath.Join(dir, "sysmon.conf")
	if err := os.WriteFile(main, []byte(boxConf), 0644); err != nil {
		t.Fatal(err)
	}

	// What the structured editor does: parse into the model, edit the
	// model, apply the model back.
	cfg, err := ParseFile(main)
	if err != nil {
		t.Fatal(err)
	}
	cfg.Hosts = append(cfg.Hosts, models.Host{
		ID: "traphost", Hostname: "traphost", IP: "10.9.0.7", Type: "ping",
	})

	d, err := LoadDocument(main)
	if err != nil {
		t.Fatal(err)
	}
	added, changed, removed := d.Apply(cfg)
	if added != 1 || changed != 0 || removed != 0 {
		t.Fatalf("Apply = %d added, %d changed, %d removed; want 1,0,0",
			added, changed, removed)
	}
	if err := d.Save(); err != nil {
		t.Fatal(err)
	}

	out, err := os.ReadFile(main)
	if err != nil {
		t.Fatal(err)
	}
	text := string(out)
	for _, keep := range []string{
		`config aggregator "sysmon-web.example.net:1347";`,
		`config aggregator-token "tok-abc123";`,
		`config sitename "second";`,
		"# managed box - this comment must survive",
	} {
		if !strings.Contains(text, keep) {
			t.Errorf("splice lost %q:\n%s", keep, text)
		}
	}
	if strings.Contains(text, "queuetime") {
		t.Errorf("splice invented a queuetime the operator never wrote:\n%s", text)
	}
	if !strings.Contains(text, "traphost") {
		t.Errorf("the added host is missing:\n%s", text)
	}
	if _, err := ParseFile(main); err != nil {
		t.Errorf("spliced config no longer parses: %v", err)
	}
}
