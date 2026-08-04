package settings

import (
	"path/filepath"
	"testing"
)

func testStore(t *testing.T) *Store {
	t.Helper()
	s, err := NewStore(filepath.Join(t.TempDir(), "settings.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

// A site nobody has adopted is a real state, not a missing value. Nothing
// is ever delivered to one, so getting this wrong means an unadopted box
// could be written to.
func TestUnadoptedSiteHasNoDesiredState(t *testing.T) {
	s := testStore(t)
	if _, ok := s.GetDesired("nobody"); ok {
		t.Error("a site nobody adopted reports desired state")
	}
}

func TestGenerationsAreKept(t *testing.T) {
	s := testStore(t)

	g1, err := s.PutGeneration("metro",
		[]GenFile{{Path: "/etc/sysmon.conf", Content: []byte("one\n")}}, "h1", "alice", "first")
	if err != nil {
		t.Fatal(err)
	}
	g2, err := s.PutGeneration("metro",
		[]GenFile{{Path: "/etc/sysmon.conf", Content: []byte("two\n")}}, "h2", "bob", "second")
	if err != nil {
		t.Fatal(err)
	}
	if g1 != 1 || g2 != 2 {
		t.Fatalf("generations numbered %d and %d, want 1 and 2", g1, g2)
	}

	// The older one is still there: rollback needs it, and so does a diff.
	files, ok := s.GetGenerationFiles("metro", g1)
	if !ok || string(files[0].Content) != "one\n" {
		t.Error("the previous generation was overwritten")
	}

	d, ok := s.GetDesired("metro")
	if !ok || d.Generation != 2 || d.Hash != "h2" || !d.Adopted {
		t.Errorf("desired state is %+v", d)
	}
	if got := s.ListGenerations("metro"); len(got) != 2 || got[0] != 2 || got[1] != 1 {
		t.Errorf("ListGenerations returned %v, want newest first", got)
	}
}

// A rollback points desired state at an older generation. The next new
// generation must not re-use a number that already names different bytes -
// otherwise "the box is running generation 2" stops meaning one thing, and
// the stored files for that number get silently overwritten.
func TestRollbackDoesNotRecycleGenerationNumbers(t *testing.T) {
	s := testStore(t)

	s.PutGeneration("metro", []GenFile{{Path: "/c", Content: []byte("one")}}, "h1", "", "")
	s.PutGeneration("metro", []GenFile{{Path: "/c", Content: []byte("two")}}, "h2", "", "")

	// Roll back to 1.
	if err := s.SetDesiredGeneration("metro", 1, "h1"); err != nil {
		t.Fatal(err)
	}
	if d, _ := s.GetDesired("metro"); d.Generation != 1 {
		t.Fatalf("desired generation is %d after rollback, want 1", d.Generation)
	}

	// The next edit must be 3, not another 2.
	g, err := s.PutGeneration("metro", []GenFile{{Path: "/c", Content: []byte("three")}}, "h3", "", "")
	if err != nil {
		t.Fatal(err)
	}
	if g != 3 {
		t.Errorf("the generation after a rollback is %d, want 3", g)
	}
	if files, ok := s.GetGenerationFiles("metro", 2); !ok || string(files[0].Content) != "two" {
		t.Error("generation 2's files were overwritten by a later edit")
	}
}

// A poisoned generation must stay recorded across later edits: the whole
// point is that the remaining waves do not go out.
func TestPoisonSurvivesLaterGenerations(t *testing.T) {
	s := testStore(t)

	g, _ := s.PutGeneration("metro", []GenFile{{Path: "/c", Content: []byte("x")}}, "h", "", "")
	if err := s.PoisonGeneration("metro", g, "object count fell off a cliff"); err != nil {
		t.Fatal(err)
	}
	s.PutGeneration("metro", []GenFile{{Path: "/c", Content: []byte("y")}}, "h2", "", "")

	d, _ := s.GetDesired("metro")
	if why, ok := d.Poisoned[g]; !ok || why == "" {
		t.Errorf("the poison record was lost: %+v", d.Poisoned)
	}
}

func TestGenerationsAreScopedPerSite(t *testing.T) {
	s := testStore(t)

	s.PutGeneration("metro", []GenFile{{Path: "/c", Content: []byte("m")}}, "hm", "", "")
	s.PutGeneration("depot", []GenFile{{Path: "/c", Content: []byte("d")}}, "hd", "", "")

	if got := s.ListGenerations("metro"); len(got) != 1 {
		t.Errorf("metro sees %v", got)
	}
	m, _ := s.GetGenerationFiles("metro", 1)
	d, _ := s.GetGenerationFiles("depot", 1)
	if string(m[0].Content) != "m" || string(d[0].Content) != "d" {
		t.Error("two sites' generation 1 got mixed up")
	}
	if sites := s.GenerationSites(); len(sites) != 2 {
		t.Errorf("GenerationSites returned %v", sites)
	}
}
