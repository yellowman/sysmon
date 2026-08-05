package templates

import "testing"

func find(id string) *Template {
	for _, t := range Builtins() {
		if t.ID == id {
			tt := t
			return &tt
		}
	}
	return nil
}

func TestExpandMikrotikSwitch(t *testing.T) {
	tpl := find("mikrotik-switch")
	if tpl == nil {
		t.Fatal("builtin mikrotik-switch missing")
	}
	hosts, err := Expand(tpl, Params{
		TemplateID: tpl.ID,
		Name:       "lbmtk5",
		IP:         "172.20.8.244",
		Parent:     "longrouter",
		Desc:       "Long Mikrotik netPower 16P",
		Community:  "public",
		Contact:    "ops@example.com",
		Spawn:      "sendalert %I %U %s %w %t",
	})
	if err != nil {
		t.Fatalf("Expand: %v", err)
	}
	if len(hosts) != 3 {
		t.Fatalf("expected 3 objects (ping, voltage, temp), got %d", len(hosts))
	}

	dev := hosts[0]
	if dev.Hostname != "lbmtk5" {
		t.Errorf("hostname must be set or the config validator rejects the save: %q", dev.Hostname)
	}
	if dev.ID != "lbmtk5" || dev.Type != "ping" {
		t.Errorf("device object wrong: %+v", dev)
	}
	// The device hangs off the parent the operator chose...
	if dev.Dependencies != "longrouter" {
		t.Errorf("device should depend on longrouter, got %q", dev.Dependencies)
	}

	volt := hosts[1]
	if volt.ID != "lbmtk5-volt" {
		t.Errorf("voltage object name = %q", volt.ID)
	}
	// ...but its sensors hang off the device, so one dead switch is one
	// alert instead of three.
	if volt.Dependencies != "lbmtk5" {
		t.Errorf("sensor should depend on the device, got %q", volt.Dependencies)
	}
	if volt.Type != "snmp" || volt.SNMPType != "low" || volt.SNMPLow != 47 {
		t.Errorf("voltage check wrong: %+v", volt)
	}
	if volt.SNMPCommunity != "public" || volt.SNMPOID == "" {
		t.Errorf("snmp credentials/oid not applied: %+v", volt)
	}
	if volt.Notes != "lbmtk5 PSU voltage below 47V" {
		t.Errorf("placeholder not substituted: %q", volt.Notes)
	}
	if volt.Spawn != "sendalert %I %U %s %w %t" {
		t.Errorf("spawn not propagated: %q", volt.Spawn)
	}
}

func TestExpandValidatesInput(t *testing.T) {
	tpl := find("generic-ping")
	if _, err := Expand(tpl, Params{Name: "", IP: "10.0.0.1"}); err == nil {
		t.Error("expected error for missing name")
	}
	if _, err := Expand(tpl, Params{Name: "x", IP: ""}); err == nil {
		t.Error("expected error for missing address")
	}
}

func TestMergeOverridesBuiltinByID(t *testing.T) {
	custom := []Template{{
		ID: "mikrotik-switch", Name: "Mikrotik switch (our thresholds)",
		Checks: []Check{{Suffix: "", Type: "ping"}},
	}}
	merged := Merge(custom)
	for _, tpl := range merged {
		if tpl.ID == "mikrotik-switch" {
			if len(tpl.Checks) != 1 || tpl.Builtin {
				t.Errorf("custom template did not replace builtin: %+v", tpl)
			}
			return
		}
	}
	t.Error("merged set lost the overridden template")
}
