package monitoring

import "testing"

// The limit arrives straight from ?limit= on the admin API, so it must
// be clamped to what exists before it becomes an allocation size - an
// unclamped make() capacity was a one-request crash of the whole UI.
func TestSessionLogTailClampsCallerLimit(t *testing.T) {
	sl := NewSessionLogger(10, 5)
	sl.Log("site-a", "CONF", "ok", false, "")
	sl.Log("site-b", "VERS", "v", false, "")
	sl.Log("site-a", "TRAPS", "", true, "boom")

	all := sl.GetRecentEntries(1<<40, "")
	if len(all) != 3 {
		t.Fatalf("huge limit returned %d entries, want all 3", len(all))
	}
	if all[0].Command != "CONF" || all[2].Command != "TRAPS" {
		t.Errorf("entries not oldest-first: %+v", all)
	}

	onlyA := sl.GetRecentEntries(1<<40, "site-a")
	if len(onlyA) != 2 || onlyA[0].Site != "site-a" || onlyA[1].Site != "site-a" {
		t.Errorf("site filter returned %+v, want site-a's two entries", onlyA)
	}

	if errs := sl.GetRecentErrors(1<<40, "site-b"); len(errs) != 0 {
		t.Errorf("site-b has no errors but got %+v", errs)
	}
	if errs := sl.GetRecentErrors(1<<40, "site-a"); len(errs) != 1 || errs[0].ErrorMsg != "boom" {
		t.Errorf("site-a errors = %+v, want the one TRAPS failure", errs)
	}
}
