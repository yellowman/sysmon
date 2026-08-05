package monitoring

import (
	"testing"
)

// classify is the whole conflict model in one function, so it gets tested
// as one: every combination an operator can actually be in, including the
// two that are easy to get backwards.

func TestClassify(t *testing.T) {
	cases := []struct {
		name         string
		row          SiteConfigStatus
		haveDesired  bool
		heardFromBox bool
		want         ConfigState
	}{
		{
			name:         "a box nobody adopted",
			row:          SiteConfigStatus{Reachable: true},
			haveDesired:  false,
			heardFromBox: true,
			want:         StateUnmanaged,
		},
		{
			name: "adopted and running what it should",
			row: SiteConfigStatus{
				Reachable: true, Adopted: true,
				RunningGeneration: 4, DesiredGeneration: 4,
				RunningHash: "aa", DesiredHash: "aa",
			},
			haveDesired: true, heardFromBox: true,
			want: StateInSync,
		},
		{
			// Adoption records what the box already runs as generation 1
			// while the box still calls it 0. Same bytes, different
			// bookkeeping - and a box running the right bytes is in sync.
			name: "just adopted: hashes agree, numbers do not",
			row: SiteConfigStatus{
				Reachable: true, Adopted: true,
				RunningGeneration: 0, DesiredGeneration: 1,
				RunningHash: "aa", DesiredHash: "aa",
			},
			haveDesired: true, heardFromBox: true,
			want: StateInSync,
		},
		{
			name: "a newer generation exists that it has not taken",
			row: SiteConfigStatus{
				Reachable: true, Adopted: true,
				RunningGeneration: 3, DesiredGeneration: 4,
				RunningHash: "aa", DesiredHash: "bb",
			},
			haveDesired: true, heardFromBox: true,
			want: StatePending,
		},
		{
			// The one that matters most: same generation number, different
			// bytes. Somebody edited the box directly, and it must never
			// be silently overwritten.
			name: "somebody edited the box",
			row: SiteConfigStatus{
				Reachable: true, Adopted: true,
				RunningGeneration: 4, DesiredGeneration: 4,
				RunningHash: "aa", DesiredHash: "bb",
			},
			haveDesired: true, heardFromBox: true,
			want: StateModified,
		},
		{
			name: "the box claims a generation we never issued",
			row: SiteConfigStatus{
				Reachable: true, Adopted: true,
				RunningGeneration: 9, DesiredGeneration: 4,
				RunningHash: "aa", DesiredHash: "bb",
			},
			haveDesired: true, heardFromBox: true,
			want: StateRejected,
		},
		{
			// "We cannot tell" has to beat every other answer. Reporting
			// a box as in sync when it has not answered is the failure
			// that costs someone their weekend.
			name: "site is not answering",
			row: SiteConfigStatus{
				Reachable: false, Adopted: true,
				RunningGeneration: 4, DesiredGeneration: 4,
				RunningHash: "aa", DesiredHash: "aa",
			},
			haveDesired: true, heardFromBox: true,
			want: StateUnknown,
		},
		{
			name: "reachable but this daemon has no CONFIG-GEN",
			row: SiteConfigStatus{
				Reachable: true, Adopted: true,
				DesiredGeneration: 4, DesiredHash: "aa",
			},
			haveDesired: true, heardFromBox: false,
			want: StateUnknown,
		},
		{
			name: "desired state exists but adoption was never completed",
			row: SiteConfigStatus{
				Reachable: true, Adopted: false,
				RunningGeneration: 1, DesiredGeneration: 1,
			},
			haveDesired: true, heardFromBox: true,
			want: StateUnmanaged,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := classify(tc.row, tc.haveDesired, tc.heardFromBox); got != tc.want {
				t.Errorf("got %s, want %s", got, tc.want)
			}
		})
	}
}
