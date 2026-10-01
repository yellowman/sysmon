package templates

import (
	"strings"
	"testing"

	"sysmon-web/internal/models"
)

const sysUpTime = ".1.3.6.1.2.1.1.3.0"

// sysUpTime is a reboot watch and nothing else. Six builtins once used it
// as a stand-in for a sensor reading, because every device answers it:
// a "temperature above 60C" compared a weeks-long uptime and was always
// red, and a "voltage below 46V" was always green whatever the battery
// was doing. A check whose OID the template cannot know ships without
// one now, and applying the template asks for it.
func TestNoBuiltinReadsUptimeAsAMeasurement(t *testing.T) {
	for _, tpl := range Builtins() {
		for _, c := range tpl.Checks {
			if c.Type == "snmp" && c.OID == sysUpTime && c.SNMPType != "reboot" {
				t.Errorf("%s: check %q compares sysUpTime as a %s reading (%q)",
					tpl.ID, c.Suffix, c.SNMPType, c.Desc)
			}
		}
	}
}

func findTemplate(t *testing.T, id string) *Template {
	t.Helper()
	for _, tpl := range Builtins() {
		if tpl.ID == id {
			tt := tpl
			return &tt
		}
	}
	t.Fatalf("no builtin %q", id)
	return nil
}

func byID(hosts []models.Host) map[string]models.Host {
	m := map[string]models.Host{}
	for _, h := range hosts {
		m[h.ID] = h
	}
	return m
}

func TestExpandAsksForTheOIDsATemplateCannotKnow(t *testing.T) {
	env := findTemplate(t, "environment")
	base := Params{TemplateID: env.ID, Name: "hut", IP: "10.0.0.5", Community: "public"}

	// Nothing supplied: refused, naming the check and where to look -
	// not written with a stand-in.
	_, err := Expand(env, base)
	if err == nil {
		t.Fatal("environment expanded with no OIDs for its sensors")
	}
	if !strings.Contains(err.Error(), "hut-temp needs an OID") || !strings.Contains(err.Error(), "degrees C") {
		t.Errorf("refusal should name the check and carry its hint, got: %v", err)
	}

	// One of three is not enough either.
	partial := base
	partial.OIDs = map[string]string{"-temp": ".1.3.6.1.4.1.3854.1.2.2.1.16.1.3.0"}
	if _, err := Expand(env, partial); err == nil || !strings.Contains(err.Error(), "hut-humidity") {
		t.Errorf("expanded with the humidity OID missing: %v", err)
	}

	// All three: each object carries the OID it was given. A leading dot
	// is added, as sysmond writes them.
	full := base
	full.OIDs = map[string]string{
		"-temp":     ".1.3.6.1.4.1.3854.1.2.2.1.16.1.3.0",
		"-humidity": "1.3.6.1.4.1.3854.1.2.2.1.17.1.3.0",
		"-door":     ".1.3.6.1.4.1.3854.1.2.2.1.18.1.3.1",
	}
	hosts, err := Expand(env, full)
	if err != nil {
		t.Fatal(err)
	}
	got := byID(hosts)
	for suffix, want := range map[string]string{
		"-temp":     ".1.3.6.1.4.1.3854.1.2.2.1.16.1.3.0",
		"-humidity": ".1.3.6.1.4.1.3854.1.2.2.1.17.1.3.0",
		"-door":     ".1.3.6.1.4.1.3854.1.2.2.1.18.1.3.1",
	} {
		if h := got["hut"+suffix]; h.SNMPOID != want {
			t.Errorf("hut%s: OID %q, want %q", suffix, h.SNMPOID, want)
		}
	}
}

func TestSuppliedOIDsAreNumericAndCanOverride(t *testing.T) {
	sw := findTemplate(t, "netonix-switch")
	p := Params{TemplateID: sw.ID, Name: "sw", IP: "10.0.0.3", Community: "public",
		OIDs: map[string]string{"-volt": ".1.3.6.1.4.1.46242.4.1.3.4"}}

	// The shipped OID is used when none is given...
	hosts, err := Expand(sw, p)
	if err != nil {
		t.Fatal(err)
	}
	if h := byID(hosts)["sw-temp"]; h.SNMPOID != ".1.3.6.1.4.1.46242.3.1.3.1" {
		t.Errorf("sw-temp: OID %q, want the shipped tempTable row 1", h.SNMPOID)
	}

	// ...and the operator's replaces it: another row of the same table.
	p.OIDs["-temp"] = ".1.3.6.1.4.1.46242.3.1.3.2"
	hosts, err = Expand(sw, p)
	if err != nil {
		t.Fatal(err)
	}
	if h := byID(hosts)["sw-temp"]; h.SNMPOID != ".1.3.6.1.4.1.46242.3.1.3.2" {
		t.Errorf("sw-temp: override ignored, OID %q", h.SNMPOID)
	}

	// The OID is written into sysmon.conf, so it has to be one.
	for _, bad := range []string{`.1.3.6"; dep "x`, "sysUpTime.0", ".1.3.", "1"} {
		p.OIDs["-temp"] = bad
		if _, err := Expand(sw, p); err == nil {
			t.Errorf("accepted %q as an OID", bad)
		}
	}
}

// The Netonix voltage column is VoltageTC: two implied decimals, so the
// switch reports 48.00V as 4800. A threshold of 46 against it would
// never fire.
func TestNetonixVoltageThresholdIsInHundredths(t *testing.T) {
	for _, c := range findTemplate(t, "netonix-switch").Checks {
		if c.Suffix == "-volt" && c.SNMPLow != 4600 {
			t.Errorf("-volt threshold %d; the switch reports hundredths of a volt, so 46V is 4600", c.SNMPLow)
		}
	}
}
