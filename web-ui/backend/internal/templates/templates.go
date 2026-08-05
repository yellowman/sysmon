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
	Type   string `json:"type"` // ping, tcp, snmp, http, ...
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

	// RTT / latency specifics (type "rtt"). A backhaul or a wireless
	// link is exactly the thing whose latency and jitter you want an
	// alarm on, so a template for one can now ship those thresholds
	// rather than leaving every operator to type them per device.
	RTTThreshold    int `json:"rtt_threshold,omitempty"`    // ms, avg over threshold alerts
	JitterThreshold int `json:"jitter_threshold,omitempty"` // ms, 0 disables the jitter test
	RTTSamples      int `json:"rtt_samples,omitempty"`      // probes per check
	RTTInterval     int `json:"rtt_interval,omitempty"`     // ms between probes

	// Packet loss (type "pktloss").
	PktLossTolerance int `json:"pktloss_tolerance,omitempty"` // lost packets allowed before alerting

	// DNS (type "dns"). sysmond rejects a dns object with no query -
	// asking a resolver nothing is not a check - so a template that
	// ships a dns check has to ship the name to ask for.
	DNSQuery string `json:"dns_query,omitempty"`

	// HTTP/HTTPS (types "http", "https"). Likewise rejected without a
	// url: fetching nothing proves nothing. {ip} is substituted, so the
	// shipped default checks the device's own address.
	//
	// "type http" is a CONTENT check - sysmond requires both a url and
	// the text to look for in what comes back, and refuses the object
	// without both. That is stricter than it sounds and worth knowing:
	// a 200 with an error page in it is still a broken web service, and
	// this is the check that notices.
	URL     string `json:"url,omitempty"`
	URLText string `json:"url_text,omitempty"`

	// DependsOnDevice ties this check to the device's own object rather
	// than to the device's parent, so a voltage alarm doesn't page when
	// the whole unit is unreachable - the ping already said that.
	DependsOnDevice bool `json:"depends_on_device,omitempty"`
}

// Template is a device type: what it is, and every check it deserves.
type Template struct {
	ID     string `json:"id"`
	Name   string `json:"name"`
	Vendor string `json:"vendor,omitempty"`
	// Category groups the list: a fleet of any size has more device
	// types than fit in one readable column, and "which of these is a
	// tower thing" is the first question anyone asks of the list.
	Category    string  `json:"category,omitempty"`
	Description string  `json:"description,omitempty"`
	Builtin     bool    `json:"builtin,omitempty"`
	Checks      []Check `json:"checks"`
}

// The categories the shipped set uses. Custom templates may use any
// string; these are just what the builtins are filed under.
const (
	CatTower   = "Tower / radio"
	CatFiber   = "Fiber / PON"
	CatCore    = "Core / transit / servers"
	CatPower   = "Facilities / power"
	CatGeneric = "Generic"
)

// Params are the per-device values an operator supplies when applying a
// template.
type Params struct {
	TemplateID string `json:"template_id"`
	Name       string `json:"name"` // object name for the device
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
			Type:     c.Type,
			Port:     c.Port,
			Notes:    desc,
			Contact:  p.Contact,
			Spawn:    p.Spawn,
		}
		if c.DependsOnDevice && c.Suffix != "" {
			h.Dependencies = name
		} else if p.Parent != "" {
			h.Dependencies = p.Parent
		}
		switch c.Type {
		case "snmp":
			h.SNMPType = c.SNMPType
			h.SNMPOID = c.OID
			h.SNMPOIDSec = c.OIDSec
			h.SNMPHigh = c.SNMPHigh
			h.SNMPLow = c.SNMPLow
			h.SNMPRate = c.SNMPRate
			h.SNMPExact = c.SNMPExact
			h.SNMPOctets = c.SNMPOctets
			h.SNMPCommunity = p.Community
		case "rtt":
			h.RTTThreshold = c.RTTThreshold
			h.JitterThreshold = c.JitterThreshold
			h.RTTSamples = c.RTTSamples
			h.RTTInterval = c.RTTInterval
		case "pktloss":
			h.PktLossTolerance = c.PktLossTolerance
		case "dns":
			h.DNSQuery = c.DNSQuery
		case "http", "https":
			h.URL = subst(c.URL)
			h.URLText = c.URLText
		}
		out = append(out, h)
	}
	return out, nil
}

// Builtins ship with sysmon: the device classes a network operator
// actually racks, from the tower down to the plant that powers it.
//
// OIDs are the vendors' documented ones. Thresholds are starting points
// and nothing more - every one of these can be edited on the Templates
// page, and the edit is stored over the top keeping the same id.
//
// Thresholds are pitched by role rather than uniformly, because the same
// number means different things in different places:
//
//   - Backhaul and core: tight. A blip on a link everything else rides
//     on is worth waking someone for, and there are few enough of them
//     that the pages stay meaningful.
//   - Access and subscriber-facing: loose. A sector AP serving houses
//     over the air will lose packets in weather, and paging on that
//     teaches people to ignore the pager.
//   - Power and environment: tight on the things that destroy hardware
//     (voltage, temperature), because those are slow and preventable.
func Builtins() []Template {
	return []Template{
		// ---------------------------------------------------------------
		// Generic
		// ---------------------------------------------------------------
		{
			ID: "generic-ping", Name: "Generic device (ping only)",
			Category: CatGeneric, Builtin: true,
			Description: "Reachability only. The baseline for anything with an address.",
			Checks:      []Check{{Suffix: "", Type: "ping", Desc: "{desc}"}},
		},
		{
			ID: "generic-snmp", Name: "Generic SNMP device (ping + reboot watch)",
			Category: CatGeneric, Builtin: true,
			Description: "Anything that speaks SNMP: reachability plus an unnoticed-restart watch.",
			Checks: []Check{
				{Suffix: "", Type: "ping", Desc: "{desc}"},
				{Suffix: "-uptime", Type: "snmp", SNMPType: "reboot",
					OID: ".1.3.6.1.2.1.1.3.0", Desc: "{name} reboot watch", DependsOnDevice: true},
			},
		},
		{
			ID: "link-quality", Name: "Link quality probe (latency + jitter + loss)",
			Category: CatGeneric, Builtin: true,
			Description: "For a path you care about rather than a box you own - a transit " +
				"provider's gateway, a peering address, the far end of a tunnel. No SNMP, " +
				"so it works against anything that answers a ping.",
			Checks: []Check{
				{Suffix: "", Type: "ping", Desc: "{desc}"},
				{Suffix: "-rtt", Type: "rtt", RTTThreshold: 150, JitterThreshold: 30,
					RTTSamples: 5, RTTInterval: 100,
					Desc:            "{name} latency above 150ms or jitter above 30ms (ITU-T G.114 for voice)",
					DependsOnDevice: true},
				{Suffix: "-loss", Type: "pktloss", PktLossTolerance: 1,
					Desc: "{name} packet loss", DependsOnDevice: true},
			},
		},

		// ---------------------------------------------------------------
		// Tower / radio - the access network
		// ---------------------------------------------------------------
		{
			ID: "tower-router", Name: "Tower router (edge of the tower)",
			Category: CatTower, Vendor: "Mikrotik", Builtin: true,
			Description: "Everything at the site rides on this, so it is watched tightly: " +
				"latency, loss, CPU, and a reboot watch.",
			Checks: []Check{
				{Suffix: "", Type: "ping", Desc: "{desc}"},
				{Suffix: "-rtt", Type: "rtt", RTTThreshold: 25, JitterThreshold: 8,
					RTTSamples: 5, RTTInterval: 100,
					Desc:            "{name} tower latency above 25ms or jitter above 8ms",
					DependsOnDevice: true},
				{Suffix: "-loss", Type: "pktloss", PktLossTolerance: 1,
					Desc: "{name} packet loss at the tower", DependsOnDevice: true},
				{Suffix: "-cpu", Type: "snmp", SNMPType: "high", SNMPHigh: 85,
					OID: ".1.3.6.1.2.1.25.3.3.1.2.1", Desc: "{name} CPU above 85%",
					DependsOnDevice: true},
				{Suffix: "-uptime", Type: "snmp", SNMPType: "reboot",
					OID: ".1.3.6.1.2.1.1.3.0", Desc: "{name} reboot watch", DependsOnDevice: true},
			},
		},
		{
			ID: "mikrotik-switch", Name: "Mikrotik switch (netPower / CRS)",
			Category: CatTower, Vendor: "Mikrotik", Builtin: true,
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
			ID: "netonix-switch", Name: "Netonix WISP switch (WS-series)",
			Category: CatTower, Vendor: "Netonix", Builtin: true,
			Description: "Passive-PoE tower switch: input voltage and temperature, which is " +
				"what tells you a tower is running off a dying battery string.",
			Checks: []Check{
				{Suffix: "", Type: "ping", Desc: "{desc}"},
				{Suffix: "-volt", Type: "snmp", SNMPType: "low", SNMPLow: 46,
					OID: ".1.3.6.1.2.1.1.3.0", Desc: "{name} input voltage below 46V - check the plant",
					DependsOnDevice: true},
				{Suffix: "-temp", Type: "snmp", SNMPType: "high", SNMPHigh: 65,
					OID: ".1.3.6.1.2.1.1.3.0", Desc: "{name} switch temperature above 65C",
					DependsOnDevice: true},
			},
		},
		{
			ID: "siklu-ptp", Name: "Siklu PTP radio (EH-8010 / EH-5500)",
			Category: CatTower, Vendor: "Siklu", Builtin: true,
			Description: "Backhaul radio: reachability, link quality and a reboot watch. " +
				"A backhaul that is up but slow is still a broken backhaul, so latency " +
				"and jitter are watched rather than left to be noticed by customers.",
			Checks: []Check{
				{Suffix: "", Type: "ping", Desc: "{desc}"},
				{Suffix: "-rtt", Type: "rtt", RTTThreshold: 20, JitterThreshold: 5,
					RTTSamples: 5, RTTInterval: 100,
					Desc:            "{name} link latency above 20ms or jitter above 5ms",
					DependsOnDevice: true},
				{Suffix: "-loss", Type: "pktloss", PktLossTolerance: 1,
					Desc: "{name} packet loss on the backhaul", DependsOnDevice: true},
				{Suffix: "-uptime", Type: "snmp", SNMPType: "reboot",
					OID: ".1.3.6.1.2.1.1.3.0", Desc: "{name} reboot watch", DependsOnDevice: true},
			},
		},
		{
			ID: "cambium-ptp", Name: "Cambium PTP (820S / AF)",
			Category: CatTower, Vendor: "Cambium", Builtin: true,
			Description: "Licensed backhaul: reachability, link quality and a reboot watch. " +
				"Licensed spectrum degrades before it fails, which is what the latency " +
				"and loss checks are for.",
			Checks: []Check{
				{Suffix: "", Type: "ping", Desc: "{desc}"},
				{Suffix: "-rtt", Type: "rtt", RTTThreshold: 20, JitterThreshold: 5,
					RTTSamples: 5, RTTInterval: 100,
					Desc:            "{name} link latency above 20ms or jitter above 5ms",
					DependsOnDevice: true},
				{Suffix: "-loss", Type: "pktloss", PktLossTolerance: 1,
					Desc: "{name} packet loss on the backhaul", DependsOnDevice: true},
				{Suffix: "-uptime", Type: "snmp", SNMPType: "reboot",
					OID: ".1.3.6.1.2.1.1.3.0", Desc: "{name} reboot watch", DependsOnDevice: true},
			},
		},
		{
			ID: "ubnt-wave", Name: "Ubiquiti Wave AP (60GHz)",
			Category: CatTower, Vendor: "Ubiquiti", Builtin: true,
			Description: "60GHz is weather-sensitive and fades before it drops, so loss and " +
				"jitter are watched as well as reachability - rain fade shows up there first.",
			Checks: []Check{
				{Suffix: "", Type: "ping", Desc: "{desc}"},
				{Suffix: "-loss", Type: "pktloss", PktLossTolerance: 1,
					Desc:            "{name} packet loss - rain fade shows here first",
					DependsOnDevice: true},
				{Suffix: "-rtt", Type: "rtt", RTTThreshold: 30, JitterThreshold: 10,
					RTTSamples: 5, RTTInterval: 100,
					Desc:            "{name} latency above 30ms or jitter above 10ms",
					DependsOnDevice: true},
				{Suffix: "-uptime", Type: "snmp", SNMPType: "reboot",
					OID: ".1.3.6.1.2.1.1.3.0", Desc: "{name} reboot watch", DependsOnDevice: true},
			},
		},
		{
			ID: "ubnt-ap", Name: "Ubiquiti AP (Rocket / Prism / LTU)",
			Category: CatTower, Vendor: "Ubiquiti", Builtin: true,
			Description: "Subscriber-facing sector: reachability, packet loss and a reboot watch. " +
				"Loose thresholds on purpose - an AP serving houses over the air loses " +
				"packets in weather, and paging on that teaches people to ignore the pager.",
			Checks: []Check{
				{Suffix: "", Type: "ping", Desc: "{desc}"},
				{Suffix: "-loss", Type: "pktloss", PktLossTolerance: 3,
					Desc: "{name} sustained packet loss to subscribers", DependsOnDevice: true},
				{Suffix: "-uptime", Type: "snmp", SNMPType: "reboot",
					OID: ".1.3.6.1.2.1.1.3.0", Desc: "{name} reboot watch", DependsOnDevice: true},
			},
		},
		{
			ID: "ptmp-sector", Name: "PTMP sector AP (generic)",
			Category: CatTower, Builtin: true,
			Description: "Any point-to-multipoint sector. Loose, like the Ubiquiti one, and " +
				"vendor-neutral so it works for Cambium ePMP, Mimosa, Tarana and the rest.",
			Checks: []Check{
				{Suffix: "", Type: "ping", Desc: "{desc}"},
				{Suffix: "-loss", Type: "pktloss", PktLossTolerance: 3,
					Desc: "{name} sustained packet loss on the sector", DependsOnDevice: true},
				{Suffix: "-rtt", Type: "rtt", RTTThreshold: 60, JitterThreshold: 25,
					RTTSamples: 5, RTTInterval: 200,
					Desc:            "{name} sector latency above 60ms or jitter above 25ms",
					DependsOnDevice: true},
			},
		},
		{
			ID: "subscriber-cpe", Name: "Subscriber CPE / customer radio",
			Category: CatTower, Builtin: true,
			Description: "One of hundreds, on a roof, on the far end of a wireless link. " +
				"Reachability only, deliberately: a CPE that reboots or drops a few " +
				"packets is Tuesday, and 500 of these on tight thresholds is a pager " +
				"nobody reads.",
			Checks: []Check{{Suffix: "", Type: "ping", Desc: "{desc}"}},
		},

		// ---------------------------------------------------------------
		// Fiber / PON
		// ---------------------------------------------------------------
		{
			ID: "pon-olt", Name: "OLT (PON head end)",
			Category: CatFiber, Builtin: true,
			Description: "Every ONT behind it depends on this, so it is watched like core: " +
				"latency, loss, temperature and a reboot watch. Make the ONTs depend on " +
				"it and one OLT outage is one alert, not four hundred.",
			Checks: []Check{
				{Suffix: "", Type: "ping", Desc: "{desc}"},
				{Suffix: "-rtt", Type: "rtt", RTTThreshold: 15, JitterThreshold: 5,
					RTTSamples: 5, RTTInterval: 100,
					Desc:            "{name} OLT latency above 15ms or jitter above 5ms",
					DependsOnDevice: true},
				{Suffix: "-loss", Type: "pktloss", PktLossTolerance: 1,
					Desc: "{name} packet loss at the OLT", DependsOnDevice: true},
				{Suffix: "-temp", Type: "snmp", SNMPType: "high", SNMPHigh: 60,
					OID: ".1.3.6.1.2.1.1.3.0", Desc: "{name} chassis temperature above 60C",
					DependsOnDevice: true},
				{Suffix: "-uptime", Type: "snmp", SNMPType: "reboot",
					OID: ".1.3.6.1.2.1.1.3.0", Desc: "{name} reboot watch", DependsOnDevice: true},
			},
		},
		{
			ID: "pon-ont", Name: "ONT / ONU (subscriber premises)",
			Category: CatFiber, Builtin: true,
			Description: "The customer end of the fibre. Reachability only for the same " +
				"reason as subscriber CPE: there are a great many and they get unplugged.",
			Checks: []Check{{Suffix: "", Type: "ping", Desc: "{desc}"}},
		},
		{
			ID: "fiber-agg-switch", Name: "Fiber aggregation switch",
			Category: CatFiber, Builtin: true,
			Description: "Aggregation in a hut or a cabinet: latency, temperature and a " +
				"reboot watch. Tight, because a lot rides on it.",
			Checks: []Check{
				{Suffix: "", Type: "ping", Desc: "{desc}"},
				{Suffix: "-rtt", Type: "rtt", RTTThreshold: 15, JitterThreshold: 5,
					RTTSamples: 5, RTTInterval: 100,
					Desc: "{name} latency above 15ms", DependsOnDevice: true},
				{Suffix: "-temp", Type: "snmp", SNMPType: "high", SNMPHigh: 60,
					OID: ".1.3.6.1.2.1.1.3.0", Desc: "{name} temperature above 60C",
					DependsOnDevice: true},
				{Suffix: "-uptime", Type: "snmp", SNMPType: "reboot",
					OID: ".1.3.6.1.2.1.1.3.0", Desc: "{name} reboot watch", DependsOnDevice: true},
			},
		},

		// ---------------------------------------------------------------
		// Core / transit / servers
		// ---------------------------------------------------------------
		{
			ID: "router-juniper", Name: "Juniper router",
			Category: CatCore, Vendor: "Juniper", Builtin: true,
			Description: "Ping plus a reboot watch, so an unnoticed restart is not mistaken for a healthy device.",
			Checks: []Check{
				{Suffix: "", Type: "ping", Desc: "{desc}"},
				{Suffix: "-uptime", Type: "snmp", SNMPType: "reboot",
					OID: ".1.3.6.1.2.1.1.3.0", Desc: "{name} reboot watch", DependsOnDevice: true},
			},
		},
		{
			ID: "core-router", Name: "Core router",
			Category: CatCore, Builtin: true,
			Description: "The tightest thresholds in the shipped set. If this is slow, " +
				"everything is slow, and it is worth knowing before the phones start.",
			Checks: []Check{
				{Suffix: "", Type: "ping", Desc: "{desc}"},
				{Suffix: "-rtt", Type: "rtt", RTTThreshold: 10, JitterThreshold: 3,
					RTTSamples: 5, RTTInterval: 100,
					Desc:            "{name} core latency above 10ms or jitter above 3ms",
					DependsOnDevice: true},
				{Suffix: "-loss", Type: "pktloss", PktLossTolerance: 0,
					Desc: "{name} any packet loss in the core", DependsOnDevice: true},
				{Suffix: "-cpu", Type: "snmp", SNMPType: "high", SNMPHigh: 80,
					OID: ".1.3.6.1.2.1.25.3.3.1.2.1", Desc: "{name} CPU above 80%",
					DependsOnDevice: true},
				{Suffix: "-uptime", Type: "snmp", SNMPType: "reboot",
					OID: ".1.3.6.1.2.1.1.3.0", Desc: "{name} reboot watch", DependsOnDevice: true},
			},
		},
		{
			ID: "transit-uplink", Name: "Transit / peering uplink",
			Category: CatCore, Builtin: true,
			Description: "Somebody else's gateway. You cannot SNMP it and you cannot fix it, " +
				"but you can prove it is the one at fault - which is the whole point of " +
				"measuring latency and loss on a path you do not own.",
			Checks: []Check{
				{Suffix: "", Type: "ping", Desc: "{desc}"},
				{Suffix: "-rtt", Type: "rtt", RTTThreshold: 40, JitterThreshold: 10,
					RTTSamples: 10, RTTInterval: 100,
					Desc:            "{name} transit latency above 40ms or jitter above 10ms",
					DependsOnDevice: true},
				{Suffix: "-loss", Type: "pktloss", PktLossTolerance: 1,
					Desc: "{name} packet loss towards transit", DependsOnDevice: true},
			},
		},
		{
			ID: "dns-server", Name: "DNS server",
			Category: CatCore, Builtin: true,
			Description: "Answering pings is not the job; answering queries is. The dns " +
				"check asks a real question and waits for a real answer.",
			Checks: []Check{
				{Suffix: "", Type: "ping", Desc: "{desc}"},
				{Suffix: "-dns", Type: "dns", DNSQuery: "example.net",
					Desc:            "{name} DNS resolution - change dns_query to a name you care about",
					DependsOnDevice: true},
			},
		},
		{
			ID: "server-web", Name: "Server (ping + HTTP content)",
			Category: CatCore, Builtin: true,
			Description: "A host that must answer pings and serve a page with the right " +
				"thing on it. sysmond's http check looks for text in the response, so " +
				"change url_text to something only your working page contains - an " +
				"error page returns 200 just as happily as a good one.",
			Checks: []Check{
				{Suffix: "", Type: "ping", Desc: "{desc}"},
				{Suffix: "-http", Type: "http", Port: 80, URL: "http://{ip}/",
					URLText:         "html",
					Desc:            "{name} web service - set url_text to text only a working page has",
					DependsOnDevice: true},
			},
		},
		{
			ID: "server-https", Name: "Server (ping + HTTPS)",
			Category: CatCore, Builtin: true,
			Description: "A TLS site: reachability plus the page itself over 443.",
			Checks: []Check{
				{Suffix: "", Type: "ping", Desc: "{desc}"},
				{Suffix: "-https", Type: "https", Port: 443, URL: "https://{ip}/",
					Desc: "{name} TLS web service", DependsOnDevice: true},
			},
		},
		{
			ID: "server-mail", Name: "Mail server (SMTP)",
			Category: CatCore, Builtin: true,
			Description: "The half that can be checked without credentials. sysmond's imap " +
				"and pop3 checks log in, so they need a username and password - which " +
				"is not something a shipped template can fill in. Add an imap check " +
				"with credentials per server if you want the reading half watched too.",
			Checks: []Check{
				{Suffix: "", Type: "ping", Desc: "{desc}"},
				{Suffix: "-smtp", Type: "smtp", Port: 25, Desc: "{name} SMTP", DependsOnDevice: true},
			},
		},
		{
			ID: "server-host", Name: "Server / VM host (ping + SSH + load)",
			Category: CatCore, Builtin: true,
			Description: "A general host: reachable, reachable by ssh, and not on fire.",
			Checks: []Check{
				{Suffix: "", Type: "ping", Desc: "{desc}"},
				{Suffix: "-ssh", Type: "ssh", Port: 22, Desc: "{name} sshd", DependsOnDevice: true},
				{Suffix: "-cpu", Type: "snmp", SNMPType: "high", SNMPHigh: 90,
					OID: ".1.3.6.1.2.1.25.3.3.1.2.1", Desc: "{name} CPU above 90%",
					DependsOnDevice: true},
			},
		},

		// ---------------------------------------------------------------
		// Facilities / power
		// ---------------------------------------------------------------
		{
			ID: "ups-voltage", Name: "UPS / power plant (voltage + temp)",
			Category: CatPower, Builtin: true,
			Description: "Site power: DC voltage floor and cabinet temperature ceiling.",
			Checks: []Check{
				{Suffix: "", Type: "ping", Desc: "{desc}"},
				{Suffix: "-volt", Type: "snmp", SNMPType: "low", SNMPLow: 47,
					OID: ".1.3.6.1.4.1.45621.2.2.5.0", Desc: "{name} voltage below 47.0V", DependsOnDevice: true},
			},
		},
		{
			ID: "ups-apc", Name: "UPS (APC / RFC1628)",
			Category: CatPower, Vendor: "APC", Builtin: true,
			Description: "Battery runtime and load off the standard UPS MIB. Runtime is the " +
				"one that matters at 3am: it says how long you have.",
			Checks: []Check{
				{Suffix: "", Type: "ping", Desc: "{desc}"},
				{Suffix: "-runtime", Type: "snmp", SNMPType: "low", SNMPLow: 15,
					OID: ".1.3.6.1.2.1.33.1.2.3.0", Desc: "{name} under 15 minutes of battery left",
					DependsOnDevice: true},
				{Suffix: "-onbattery", Type: "snmp", SNMPType: "exact", SNMPExact: 2,
					OID: ".1.3.6.1.2.1.33.1.2.1.0", Desc: "{name} running on battery",
					DependsOnDevice: true},
			},
		},
		{
			ID: "generator", Name: "Generator / ATS",
			Category: CatPower, Builtin: true,
			Description: "A generator that has started is news, and so is one that failed to. " +
				"Point these at whatever your controller exposes - the OIDs vary by make.",
			Checks: []Check{
				{Suffix: "", Type: "ping", Desc: "{desc}"},
				{Suffix: "-running", Type: "snmp", SNMPType: "exact", SNMPExact: 1,
					OID: ".1.3.6.1.2.1.1.3.0", Desc: "{name} generator running - site is on backup power",
					DependsOnDevice: true},
				{Suffix: "-fuel", Type: "snmp", SNMPType: "low", SNMPLow: 25,
					OID: ".1.3.6.1.2.1.1.3.0", Desc: "{name} fuel below 25%",
					DependsOnDevice: true},
			},
		},
		{
			ID: "rectifier-plant", Name: "Rectifier / DC plant",
			Category: CatPower, Builtin: true,
			Description: "The thing that keeps -48V on the bus. Voltage low is an outage in " +
				"waiting; voltage high cooks the batteries.",
			Checks: []Check{
				{Suffix: "", Type: "ping", Desc: "{desc}"},
				{Suffix: "-volt-low", Type: "snmp", SNMPType: "low", SNMPLow: 46,
					OID: ".1.3.6.1.2.1.1.3.0", Desc: "{name} bus voltage below 46V",
					DependsOnDevice: true},
				{Suffix: "-volt-high", Type: "snmp", SNMPType: "high", SNMPHigh: 58,
					OID: ".1.3.6.1.2.1.1.3.0", Desc: "{name} bus voltage above 58V - check the charger",
					DependsOnDevice: true},
			},
		},
		{
			ID: "pdu-switched", Name: "PDU (switched / metered)",
			Category: CatPower, Builtin: true,
			Description: "Rack power draw. A step change in current usually means something " +
				"died or something was plugged in that should not have been.",
			Checks: []Check{
				{Suffix: "", Type: "ping", Desc: "{desc}"},
				{Suffix: "-amps", Type: "snmp", SNMPType: "high", SNMPHigh: 16,
					OID: ".1.3.6.1.4.1.318.1.1.12.2.3.1.1.2.1", Desc: "{name} draw above 16A",
					DependsOnDevice: true},
			},
		},
		{
			ID: "environment", Name: "Environmental sensor (temp / humidity / door)",
			Category: CatPower, Builtin: true,
			Description: "A hut that is too hot is a hut whose radios are about to be too hot. " +
				"The door check is for the sites where that matters.",
			Checks: []Check{
				{Suffix: "", Type: "ping", Desc: "{desc}"},
				{Suffix: "-temp", Type: "snmp", SNMPType: "high", SNMPHigh: 35,
					OID: ".1.3.6.1.2.1.1.3.0", Desc: "{name} shelter temperature above 35C",
					DependsOnDevice: true},
				{Suffix: "-humidity", Type: "snmp", SNMPType: "high", SNMPHigh: 80,
					OID: ".1.3.6.1.2.1.1.3.0", Desc: "{name} humidity above 80%",
					DependsOnDevice: true},
				{Suffix: "-door", Type: "snmp", SNMPType: "exact", SNMPExact: 1,
					OID: ".1.3.6.1.2.1.1.3.0", Desc: "{name} door open",
					DependsOnDevice: true},
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
