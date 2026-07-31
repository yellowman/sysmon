// Package templates turns a device type into the set of sysmon objects
// that monitor it. A "Mikrotik netPower 16P" is not one check - it is a
// ping, a voltage alarm, a temperature alarm - and typing that out for
// every unit is how an 800-host config becomes unmaintainable.
//
// Expansion happens entirely in sysmon-web: templates produce ordinary
// objects that are written into sysmon.conf, so sysmond never learns
// what a template is.
package templates

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"sysmon-web/internal/models"
)

// Check is one monitored object within a template.
type Check struct {
	// Suffix appended to the device name for this check's object name.
	// Empty means the device object itself (the one children depend on).
	Suffix string `json:"suffix"`
	Type   string `json:"type"`             // ping, tcp, snmp, http, ...
	Port   int    `json:"port,omitempty"`
	// Desc supports {name}, {ip} and {desc} placeholders.
	Desc string `json:"desc,omitempty"`

	// SNMP specifics
	SNMPType   string `json:"snmp_type,omitempty"` // low, high, range, exact, rate, reboot, compare
	OID        string `json:"oid,omitempty"`
	OIDSec     string `json:"oid_sec,omitempty"`
	SNMPHigh   int64  `json:"snmp_high,omitempty"`
	SNMPLow    int64  `json:"snmp_low,omitempty"`
	SNMPRate   int64  `json:"snmp_rate,omitempty"`
	SNMPExact  int64  `json:"snmp_exact,omitempty"`
	SNMPOctets bool   `json:"snmp_octets,omitempty"`

	// DependsOnDevice ties this check to the device's own object rather
	// than to the device's parent, so a voltage alarm doesn't page when
	// the whole unit is unreachable - the ping already said that.
	DependsOnDevice bool `json:"depends_on_device,omitempty"`
}

// Template is a device type: what it is, and every check it deserves.
type Template struct {
	ID          string  `json:"id"`
	Name        string  `json:"name"`
	Vendor      string  `json:"vendor,omitempty"`
	Description string  `json:"description,omitempty"`
	Builtin     bool    `json:"builtin,omitempty"`
	Checks      []Check `json:"checks"`
}

// Params are the per-device values an operator supplies when applying a
// template.
type Params struct {
	TemplateID string `json:"template_id"`
	Name       string `json:"name"`      // object name for the device
	IP         string `json:"ip"`
	Parent     string `json:"parent,omitempty"`    // dependency for the device object
	Desc       string `json:"desc,omitempty"`      // human description
	Community  string `json:"community,omitempty"` // SNMP community for snmp checks
	Contact    string `json:"contact,omitempty"`
	Spawn      string `json:"spawn,omitempty"`
}

// Expand turns a template plus params into the objects to add to the
// config. The first returned host is the device itself; SNMP sub-checks
// depend on it, so an unreachable device produces one alert instead of a
// storm from every sensor on it.
func Expand(t *Template, p Params) ([]models.Host, error) {
	if t == nil {
		return nil, fmt.Errorf("no template")
	}
	name := strings.TrimSpace(p.Name)
	if name == "" {
		return nil, fmt.Errorf("device name is required")
	}
	if strings.TrimSpace(p.IP) == "" {
		return nil, fmt.Errorf("device address is required")
	}

	subst := func(s string) string {
		r := strings.NewReplacer("{name}", name, "{ip}", p.IP, "{desc}", p.Desc)
		return r.Replace(s)
	}

	out := make([]models.Host, 0, len(t.Checks))
	for _, c := range t.Checks {
		id := name + c.Suffix
		desc := subst(c.Desc)
		if desc == "" {
			desc = p.Desc
		}
		h := models.Host{
			ID: id,
			// The parser sets Hostname to the object name; expansion must
			// do the same or the config validator rejects the save.
			Hostname: id,
			IP:       p.IP,
			Type:    c.Type,
			Port:    c.Port,
			Notes:   desc,
			Contact: p.Contact,
			Spawn:   p.Spawn,
		}
		if c.DependsOnDevice && c.Suffix != "" {
			h.Dependencies = name
		} else if p.Parent != "" {
			h.Dependencies = p.Parent
		}
		if c.Type == "snmp" {
			h.SNMPType = c.SNMPType
			h.SNMPOID = c.OID
			h.SNMPOIDSec = c.OIDSec
			h.SNMPHigh = c.SNMPHigh
			h.SNMPLow = c.SNMPLow
			h.SNMPRate = c.SNMPRate
			h.SNMPExact = c.SNMPExact
			h.SNMPOctets = c.SNMPOctets
			h.SNMPCommunity = p.Community
		}
		out = append(out, h)
	}
	return out, nil
}

// Builtins ship with sysmon: the device types a wireless ISP actually
// racks. OIDs are the vendors' documented ones; thresholds are sane
// starting points meant to be edited, not gospel.
func Builtins() []Template {
	return []Template{
		{
			ID: "generic-ping", Name: "Generic device (ping only)", Builtin: true,
			Description: "Reachability only. The baseline for anything with an address.",
			Checks: []Check{{Suffix: "", Type: "ping", Desc: "{desc}"}},
		},
		{
			ID: "router-juniper", Name: "Juniper router", Vendor: "Juniper", Builtin: true,
			Description: "Ping plus a reboot watch, so an unnoticed restart is not mistaken for a healthy device.",
			Checks: []Check{
				{Suffix: "", Type: "ping", Desc: "{desc}"},
				{Suffix: "-uptime", Type: "snmp", SNMPType: "reboot",
					OID: ".1.3.6.1.2.1.1.3.0", Desc: "{name} reboot watch", DependsOnDevice: true},
			},
		},
		{
			ID: "mikrotik-switch", Name: "Mikrotik switch (netPower / CRS)", Vendor: "Mikrotik", Builtin: true,
			Description: "Ping, PSU voltage and board temperature - the two things that kill a pole-mounted switch.",
			Checks: []Check{
				{Suffix: "", Type: "ping", Desc: "{desc}"},
				{Suffix: "-volt", Type: "snmp", SNMPType: "low", SNMPLow: 47,
					OID: ".1.3.6.1.4.1.14988.1.1.3.8.0", Desc: "{name} PSU voltage below 47V", DependsOnDevice: true},
				{Suffix: "-temp", Type: "snmp", SNMPType: "high", SNMPHigh: 70,
					OID: ".1.3.6.1.4.1.14988.1.1.3.10.0", Desc: "{name} board temperature above 70C", DependsOnDevice: true},
			},
		},
		{
			ID: "ubnt-ap", Name: "Ubiquiti AP (Rocket / Prism / LTU)", Vendor: "Ubiquiti", Builtin: true,
			Description: "Ping plus a reboot watch. Add a signal-strength check per link where it matters.",
			Checks: []Check{
				{Suffix: "", Type: "ping", Desc: "{desc}"},
				{Suffix: "-uptime", Type: "snmp", SNMPType: "reboot",
					OID: ".1.3.6.1.2.1.1.3.0", Desc: "{name} reboot watch", DependsOnDevice: true},
			},
		},
		{
			ID: "ubnt-wave", Name: "Ubiquiti Wave AP (60GHz)", Vendor: "Ubiquiti", Builtin: true,
			Description: "60GHz links are weather-sensitive; watch reachability and restarts closely.",
			Checks: []Check{
				{Suffix: "", Type: "ping", Desc: "{desc}"},
				{Suffix: "-uptime", Type: "snmp", SNMPType: "reboot",
					OID: ".1.3.6.1.2.1.1.3.0", Desc: "{name} reboot watch", DependsOnDevice: true},
			},
		},
		{
			ID: "siklu-ptp", Name: "Siklu PTP radio (EH-8010 / EH-5500)", Vendor: "Siklu", Builtin: true,
			Description: "Backhaul radio: reachability and a reboot watch on each end.",
			Checks: []Check{
				{Suffix: "", Type: "ping", Desc: "{desc}"},
				{Suffix: "-uptime", Type: "snmp", SNMPType: "reboot",
					OID: ".1.3.6.1.2.1.1.3.0", Desc: "{name} reboot watch", DependsOnDevice: true},
			},
		},
		{
			ID: "cambium-ptp", Name: "Cambium PTP (820S / AF)", Vendor: "Cambium", Builtin: true,
			Description: "Licensed backhaul: reachability plus reboot watch.",
			Checks: []Check{
				{Suffix: "", Type: "ping", Desc: "{desc}"},
				{Suffix: "-uptime", Type: "snmp", SNMPType: "reboot",
					OID: ".1.3.6.1.2.1.1.3.0", Desc: "{name} reboot watch", DependsOnDevice: true},
			},
		},
		{
			ID: "server-web", Name: "Server (ping + HTTP)", Builtin: true,
			Description: "A host that must both answer pings and serve a page.",
			Checks: []Check{
				{Suffix: "", Type: "ping", Desc: "{desc}"},
				{Suffix: "-http", Type: "http", Port: 80, Desc: "{name} web service", DependsOnDevice: true},
			},
		},
		{
			ID: "ups-voltage", Name: "UPS / power plant (voltage + temp)", Builtin: true,
			Description: "Site power: DC voltage floor and cabinet temperature ceiling.",
			Checks: []Check{
				{Suffix: "", Type: "ping", Desc: "{desc}"},
				{Suffix: "-volt", Type: "snmp", SNMPType: "low", SNMPLow: 47,
					OID: ".1.3.6.1.4.1.45621.2.2.5.0", Desc: "{name} voltage below 47.0V", DependsOnDevice: true},
			},
		},
	}
}

// Merge combines the builtins with any custom/overridden templates.
// A stored template with the same ID as a builtin replaces it, so an
// operator can retune thresholds without losing the shipped set.
func Merge(stored []Template) []Template {
	byID := map[string]Template{}
	for _, t := range Builtins() {
		byID[t.ID] = t
	}
	for _, t := range stored {
		t.Builtin = false
		byID[t.ID] = t
	}
	out := make([]Template, 0, len(byID))
	for _, t := range byID {
		out = append(out, t)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// Decode parses a stored template list, tolerating an empty store.
func Decode(data []byte) ([]Template, error) {
	if len(data) == 0 {
		return nil, nil
	}
	var out []Template
	if err := json.Unmarshal(data, &out); err != nil {
		return nil, err
	}
	return out, nil
}
