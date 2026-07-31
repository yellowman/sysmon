package config

import (
	"strings"
	"testing"
)

// A real-world SNMP object (voltage alarm on a Mikrotik-style OID) must
// survive parse -> generate unchanged. Anything dropped here is silently
// destroyed the first time an operator saves from the web editor.
func TestSNMPObjectRoundTrip(t *testing.T) {
	src := `root = "elkrouter";

object elkrouter {
	ip "172.20.254.6";
	type ping;
};

object elktpdin {
	ip "172.20.54.3";
	type snmp;
	snmp-type "low";
	oid ".1.3.6.1.4.1.45621.2.2.5.0";
	desc "Elk VOLTAGE ALERT below 47.0V";
	snmp-low "47";
	dep "elkrouter";
	community "godaddy";
	spawn "sendalert %I %U %s %w %t";
};
`
	cfg, err := Parse([]byte(src))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	var h *string
	for i := range cfg.Hosts {
		if cfg.Hosts[i].ID == "elktpdin" {
			got := cfg.Hosts[i]
			for field, val := range map[string]string{
				"type": got.Type, "snmp-type": got.SNMPType,
				"oid": got.SNMPOID, "community": got.SNMPCommunity,
				"spawn": got.Spawn, "desc": got.Notes,
			} {
				if val == "" {
					t.Errorf("field %s lost during parse", field)
				}
			}
			if got.SNMPLow != 47 {
				t.Errorf("snmp-low = %d, want 47", got.SNMPLow)
			}
			s := got.ID
			h = &s
		}
	}
	if h == nil {
		t.Fatalf("snmp object not parsed")
	}

	out, err := Generate(cfg)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	for _, want := range []string{
		`type snmp;`, `snmp-type "low";`, `.1.3.6.1.4.1.45621.2.2.5.0`,
		`snmp-low "47";`, `godaddy`, `sendalert`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("generated config lost %q\n---\n%s", want, out)
		}
	}
}
