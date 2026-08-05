package config

import (
	"strings"
	"testing"

	"sysmon-web/internal/models"
)

// A template stamps out objects; the generator writes them; sysmond has
// to accept them and the parser has to read them back. Any link that
// drops a field makes the template a lie.
func TestNewCheckFieldsRoundTrip(t *testing.T) {
	cfg := &models.Config{Hosts: []models.Host{
		{ID: "gw", Hostname: "gw", IP: "127.0.0.1", Type: "ping", Contact: "a@b"},
		{ID: "gw-rtt", Hostname: "gw-rtt", IP: "127.0.0.1", Type: "rtt", Contact: "a@b",
			Dependencies: "gw", RTTThreshold: 20, JitterThreshold: 5,
			RTTSamples: 5, RTTInterval: 100},
		{ID: "gw-loss", Hostname: "gw-loss", IP: "127.0.0.1", Type: "pktloss", Contact: "a@b",
			Dependencies: "gw", PktLossTolerance: 3},
	}}
	out, err := Generate(cfg)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"type rtt", "rtt_threshold 20", "jitter_threshold 5",
		"rtt_samples 5", "rtt_interval 100", "type pktloss", "pktloss_tolerance 3"} {
		if !strings.Contains(out, want) {
			t.Errorf("generator dropped %q\n%s", want, out)
		}
	}

	back, perr := Parse([]byte(out))
	if perr != nil {
		t.Fatal(perr)
	}
	byName := map[string]models.Host{}
	for _, h := range back.Hosts {
		byName[h.Hostname] = h
	}
	if r := byName["gw-rtt"]; r.RTTThreshold != 20 || r.JitterThreshold != 5 ||
		r.RTTSamples != 5 || r.RTTInterval != 100 {
		t.Errorf("rtt fields lost on read-back: %+v", r)
	}
	if l := byName["gw-loss"]; l.PktLossTolerance != 3 {
		t.Errorf("pktloss tolerance lost on read-back: got %d", l.PktLossTolerance)
	}
}
