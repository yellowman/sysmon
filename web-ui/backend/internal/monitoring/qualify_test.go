package monitoring

import "testing"

func TestQualifyAndSplit(t *testing.T) {
	cases := []struct{ site, object, want string }{
		{"sysmon-metro", "corerouter", "sysmon-metro:corerouter"},
		{"local", "corerouter", "corerouter"}, // single-box installs unchanged
		{"", "corerouter", "corerouter"},
	}
	for _, c := range cases {
		if got := Qualify(c.site, c.object); got != c.want {
			t.Errorf("Qualify(%q,%q) = %q, want %q", c.site, c.object, got, c.want)
		}
	}

	// Splitting must return the bare name a daemon knows, whether or not
	// the key was ever qualified - an unqualified key is what a single-box
	// install and every pre-namespace stored row look like.
	for _, c := range []struct{ in, site, object string }{
		{"sysmon-metro:corerouter", "sysmon-metro", "corerouter"},
		{"corerouter", "", "corerouter"},
	} {
		site, object := SplitQualified(c.in)
		if site != c.site || object != c.object {
			t.Errorf("SplitQualified(%q) = %q,%q want %q,%q", c.in, site, object, c.site, c.object)
		}
	}
}

// A round trip must survive: whatever we store, splitting it has to give
// back a name the owning daemon will recognise.
func TestQualifyRoundTrip(t *testing.T) {
	for _, site := range []string{"sysmon-metro", "a", "local", ""} {
		for _, obj := range []string{"corerouter", "a-b_c", "host.with.dots"} {
			_, back := SplitQualified(Qualify(site, obj))
			if back != obj {
				t.Errorf("site %q object %q round-tripped to %q", site, obj, back)
			}
		}
	}
}
