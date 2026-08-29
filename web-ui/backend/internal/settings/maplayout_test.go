package settings

import (
	"path/filepath"
	"testing"
)

// The map is drawn per sysmond, so its hand-placed positions are per
// sysmond. One shared key meant two boxes that both contain a "core" -
// normal, object names are only unique within a box - overwrote each
// other's arrangement on every save.
func TestMapLayoutIsPerSite(t *testing.T) {
	s, err := NewStore(filepath.Join(t.TempDir(), "s.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	if err := s.SetMapLayout("bend", []byte(`{"core":{"x":10,"y":20}}`)); err != nil {
		t.Fatal(err)
	}
	if err := s.SetMapLayout("redmond", []byte(`{"core":{"x":900,"y":900}}`)); err != nil {
		t.Fatal(err)
	}

	bend, err := s.GetMapLayout("bend")
	if err != nil {
		t.Fatal(err)
	}
	if string(bend) != `{"core":{"x":10,"y":20}}` {
		t.Fatalf("redmond's save moved bend's nodes: %s", bend)
	}

	// A site nobody has arranged yet starts empty rather than inheriting
	// somebody else's coordinates.
	fresh, err := s.GetMapLayout("lapine")
	if err != nil {
		t.Fatal(err)
	}
	if string(fresh) != "{}" {
		t.Fatalf("unset site should be empty, got %s", fresh)
	}
}

// Layouts saved before the per-site split are the LOCAL map's layout,
// not orphaned rows: the empty site keeps the original key.
func TestMapLayoutLegacyKeyIsTheLocalMap(t *testing.T) {
	s, err := NewStore(filepath.Join(t.TempDir(), "s.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	if err := s.SetMapLayout("", []byte(`{"router1":{"x":1,"y":2}}`)); err != nil {
		t.Fatal(err)
	}
	got, err := s.GetMapLayout("")
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != `{"router1":{"x":1,"y":2}}` {
		t.Fatalf("local layout lost: %s", got)
	}
	if bend, _ := s.GetMapLayout("bend"); string(bend) != "{}" {
		t.Fatalf("the local layout must not become every site's layout: %s", bend)
	}
}
