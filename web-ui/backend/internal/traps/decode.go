// Package traps receives and decodes SNMP traps.
//
// This used to live in sysmond, which meant a hand-written BER parser in C
// reading hostile UDP packets inside the process that does the monitoring.
// It lives here now: sysmon-web owns the trap port, decodes the packet,
// matches it against the configured objects, and dispatches the alert.
// sysmond knows nothing about traps at all.
//
// The decoder still treats every packet as hostile - Go bounds-checks for
// us, but a malicious sender can still ask for unbounded work, so varbind
// count, OID length and string sizes are all capped.
package traps

import (
	"fmt"
	"strconv"
	"strings"
)

// ASN.1 / BER tags used by SNMP.
const (
	berInteger        = 0x02
	berOctetStr       = 0x04
	berNull           = 0x05
	berOID            = 0x06
	berSequence       = 0x30
	berIPAddress      = 0x40
	berCounter32      = 0x41
	berGauge32        = 0x42
	berTimeTicks      = 0x43
	berOpaque         = 0x44
	berCounter64      = 0x46
	berNoSuchObject   = 0x80
	berNoSuchInstance = 0x81
	berEndOfMibView   = 0x82

	pduTrapV1 = 0xa4
	pduInform = 0xa6
	pduTrapV2 = 0xa7
)

// Caps. A packet is at most 64KB, but nothing says its contents have to be
// sane, and none of this is worth unbounded memory or CPU.
const (
	maxVarbinds = 16
	maxSubIDs   = 64
	maxOIDLen   = 192
	maxValueLen = 160
)

// Varbind is one variable binding from the trap.
type Varbind struct {
	OID   string `json:"oid"`
	Name  string `json:"name,omitempty"` // friendly name, when we know the OID
	Type  string `json:"type"`           // INTEGER, STRING, TimeTicks, ...
	Value string `json:"value"`
	Note  string `json:"note,omitempty"` // decoded meaning, eg "down" for a 2
}

// Content is everything we could learn from one trap packet.
type Content struct {
	Version int  `json:"version"` // 0 = v1, 1 = v2c, 3 = v3
	Decoded bool `json:"decoded"` // false => we could not read the packet
	// Alertable is true when the packet really was an SNMP trap. Junk
	// aimed at the trap port must never page anyone.
	Alertable   bool      `json:"alertable"`
	Inform      bool      `json:"inform,omitempty"` // InformRequest, not a trap
	Community   string    `json:"community,omitempty"`
	TrapOID     string    `json:"trap_oid,omitempty"`
	Enterprise  string    `json:"enterprise,omitempty"`
	Agent       string    `json:"agent,omitempty"` // v1 agent-addr
	Name        string    `json:"name"`
	Description string    `json:"description"`
	Severity    string    `json:"severity"`
	Category    string    `json:"category"`
	Vendor      string    `json:"vendor,omitempty"`
	Interface   string    `json:"interface,omitempty"`
	IfIndex     int       `json:"ifindex,omitempty"`
	Generic     int       `json:"generic,omitempty"`
	Specific    int       `json:"specific,omitempty"`
	Uptime      uint64    `json:"uptime,omitempty"` // hundredths of a second
	Varbinds    []Varbind `json:"varbinds,omitempty"`
}

// VersionString renders the version the way an operator writes it.
func (c Content) VersionString() string {
	switch c.Version {
	case 0:
		return "v1"
	case 1:
		return "v2c"
	case 3:
		return "v3"
	default:
		return "unknown"
	}
}

// Well-known OIDs we name outright.
var oidExact = map[string]string{
	".1.3.6.1.2.1.1.3.0":     "sysUpTime",
	".1.3.6.1.6.3.1.1.4.1.0": "snmpTrapOID",
	".1.3.6.1.6.3.1.1.4.3.0": "snmpTrapEnterprise",
	".1.3.6.1.2.1.1.1.0":     "sysDescr",
	".1.3.6.1.2.1.1.5.0":     "sysName",
	".1.3.6.1.2.1.1.6.0":     "sysLocation",
}

// Table columns: the instance index follows, so match on the prefix.
var oidPrefix = []struct{ prefix, name string }{
	{".1.3.6.1.2.1.2.2.1.1.", "ifIndex"},
	{".1.3.6.1.2.1.2.2.1.2.", "ifDescr"},
	{".1.3.6.1.2.1.2.2.1.3.", "ifType"},
	{".1.3.6.1.2.1.2.2.1.7.", "ifAdminStatus"},
	{".1.3.6.1.2.1.2.2.1.8.", "ifOperStatus"},
	{".1.3.6.1.2.1.31.1.1.1.1.", "ifName"},
	{".1.3.6.1.2.1.31.1.1.1.18.", "ifAlias"},
	{".1.3.6.1.6.3.18.1.3.", "snmpTrapAddress"},
	{".1.3.6.1.6.3.18.1.4.", "snmpTrapCommunity"},
}

// The six standard traps, keyed both ways: v2c sends an OID, v1 sends a
// generic number, and they mean the same thing.
var standardTraps = []struct {
	oid      string
	generic  int
	name     string
	severity string
	category string
	desc     string
}{
	{".1.3.6.1.6.3.1.1.5.1", 0, "coldStart", "warning", "restart",
		"Device cold started - it was power cycled or reloaded"},
	{".1.3.6.1.6.3.1.1.5.2", 1, "warmStart", "warning", "restart",
		"Device warm started - its agent reinitialised"},
	{".1.3.6.1.6.3.1.1.5.3", 2, "linkDown", "critical", "link",
		"An interface went down"},
	{".1.3.6.1.6.3.1.1.5.4", 3, "linkUp", "informational", "link",
		"An interface came back up"},
	{".1.3.6.1.6.3.1.1.5.5", 4, "authenticationFailure", "warning", "security",
		"SNMP authentication failure - wrong community, or a poller that should not be there"},
	{".1.3.6.1.6.3.1.1.5.6", 5, "egpNeighborLoss", "warning", "routing",
		"An EGP neighbour was lost"},
}

// Enterprise numbers under .1.3.6.1.4.1 worth naming on sight.
var vendors = map[uint64]string{
	9:     "Cisco",
	11:    "Hewlett-Packard",
	674:   "Dell",
	1916:  "Extreme Networks",
	2011:  "Huawei",
	2636:  "Juniper",
	3375:  "F5",
	4526:  "NETGEAR",
	6027:  "Dell Force10",
	8072:  "Net-SNMP",
	14988: "MikroTik",
	25506: "H3C",
	30065: "Arista",
	41112: "Ubiquiti",
}

// ifOperStatus / ifAdminStatus values, so a bare "2" reads as "down".
func ifStatusName(v int64) string {
	switch v {
	case 1:
		return "up"
	case 2:
		return "down"
	case 3:
		return "testing"
	case 4:
		return "unknown"
	case 5:
		return "dormant"
	case 6:
		return "notPresent"
	case 7:
		return "lowerLayerDown"
	}
	return ""
}

// cursor walks a BER buffer. Every read is checked; nothing here can run
// off the end of the slice.
type cursor struct {
	buf []byte
	pos int
}

// next reads one tag-length-value. It refuses anything we will not
// tolerate: truncation, multi-byte tags, indefinite lengths, or a length
// that runs past the end of the buffer.
func (c *cursor) next() (tag byte, val []byte, ok bool) {
	if c.pos >= len(c.buf) {
		return 0, nil, false
	}
	t := c.buf[c.pos]
	c.pos++
	if t&0x1f == 0x1f {
		return 0, nil, false // multi-byte tag: never valid in SNMP
	}
	if c.pos >= len(c.buf) {
		return 0, nil, false
	}
	l := int(c.buf[c.pos])
	c.pos++
	if l&0x80 != 0 {
		n := l & 0x7f
		if n == 0 || n > 4 {
			return 0, nil, false // indefinite length, or absurd
		}
		if c.pos+n > len(c.buf) {
			return 0, nil, false
		}
		l = 0
		for ; n > 0; n-- {
			l = l<<8 | int(c.buf[c.pos])
			c.pos++
		}
	}
	if l < 0 || l > len(c.buf)-c.pos {
		return 0, nil, false // claims more data than we received
	}
	val = c.buf[c.pos : c.pos+l]
	c.pos += l
	return t, val, true
}

func berInt(v []byte) int64 {
	if len(v) == 0 || len(v) > 8 {
		return 0
	}
	var acc uint64
	if v[0]&0x80 != 0 {
		acc = ^uint64(0) // sign extend
	}
	for _, b := range v {
		acc = acc<<8 | uint64(b)
	}
	return int64(acc)
}

func berUint(v []byte) uint64 {
	if len(v) == 0 || len(v) > 8 {
		return 0
	}
	var acc uint64
	for _, b := range v {
		acc = acc<<8 | uint64(b)
	}
	return acc
}

// oidString renders an OID as ".1.3.6.1...", truncating rather than
// growing without bound.
func oidString(v []byte) string {
	if len(v) == 0 {
		return ""
	}
	var sb strings.Builder
	if v[0] >= 80 {
		fmt.Fprintf(&sb, ".2.%d", int(v[0])-80)
	} else {
		fmt.Fprintf(&sb, ".%d.%d", int(v[0])/40, int(v[0])%40)
	}

	var sub uint64
	shifted := 0
	subids := 0
	for _, b := range v[1:] {
		if shifted > 4 { // > 35 bits: not a real OID
			sub, shifted = 0, 0
			continue
		}
		sub = sub<<7 | uint64(b&0x7f)
		shifted++
		if b&0x80 != 0 {
			continue // more bytes to come
		}
		subids++
		if subids > maxSubIDs || sb.Len() > maxOIDLen {
			break // truncate: enough is enough
		}
		fmt.Fprintf(&sb, ".%d", sub)
		sub, shifted = 0, 0
	}
	return sb.String()
}

// octetString renders an octet string. Printable text comes through as
// text; anything else is hex, because trap payloads are attacker
// controlled and must never be pasted raw into a log line or a page.
func octetString(v []byte) string {
	printable := true
	for _, b := range v {
		if b == '\t' || b == '\n' || b == '\r' {
			continue
		}
		if b < 0x20 || b > 0x7e {
			printable = false
			break
		}
	}
	if !printable {
		var sb strings.Builder
		for _, b := range v {
			if sb.Len() >= maxValueLen {
				break
			}
			fmt.Fprintf(&sb, "%02x", b)
		}
		return sb.String()
	}
	var sb strings.Builder
	for _, b := range v {
		if sb.Len() >= maxValueLen {
			break
		}
		if b < 0x20 {
			sb.WriteByte(' ')
		} else {
			sb.WriteByte(b)
		}
	}
	return sb.String()
}

// valueString formats one varbind value and names its type.
func valueString(tag byte, v []byte) (typ, value, note string) {
	switch tag {
	case berInteger:
		return "INTEGER", strconv.FormatInt(berInt(v), 10), ""
	case berOctetStr:
		return "STRING", octetString(v), ""
	case berNull:
		return "NULL", "", ""
	case berOID:
		return "OID", oidString(v), ""
	case berIPAddress:
		if len(v) == 4 {
			return "IpAddress", fmt.Sprintf("%d.%d.%d.%d", v[0], v[1], v[2], v[3]), ""
		}
		return "IpAddress", octetString(v), ""
	case berCounter32:
		return "Counter32", strconv.FormatUint(berUint(v), 10), ""
	case berGauge32:
		return "Gauge32", strconv.FormatUint(berUint(v), 10), ""
	case berTimeTicks:
		ticks := berUint(v)
		return "TimeTicks", strconv.FormatUint(ticks, 10), fmt.Sprintf("%dd %dh %dm %ds",
			ticks/8640000, (ticks/360000)%24, (ticks/6000)%60, (ticks/100)%60)
	case berCounter64:
		return "Counter64", strconv.FormatUint(berUint(v), 10), ""
	case berOpaque:
		return "Opaque", octetString(v), ""
	case berNoSuchObject:
		return "noSuchObject", "", ""
	case berNoSuchInstance:
		return "noSuchInstance", "", ""
	case berEndOfMibView:
		return "endOfMibView", "", ""
	}
	return fmt.Sprintf("tag 0x%02x", tag), octetString(v), ""
}

func nameOID(oid string) string {
	if n, ok := oidExact[oid]; ok {
		return n
	}
	for _, p := range oidPrefix {
		if strings.HasPrefix(oid, p.prefix) {
			return p.name
		}
	}
	return ""
}

// nameVendor pulls the enterprise number out of .1.3.6.1.4.1.<n>... and
// names it if we know it.
func nameVendor(oid string) string {
	const ent = ".1.3.6.1.4.1."
	if !strings.HasPrefix(oid, ent) {
		return ""
	}
	rest := oid[len(ent):]
	if i := strings.IndexByte(rest, '.'); i >= 0 {
		rest = rest[:i]
	}
	n, err := strconv.ParseUint(rest, 10, 64)
	if err != nil {
		return ""
	}
	return vendors[n]
}

// Decode parses a trap packet. It always returns something printable,
// whether or not the packet made sense; Decoded says whether the contents
// are trustworthy, and Alertable whether it was a trap at all.
func Decode(pkt []byte) Content {
	out := Content{
		Version:     -1,
		Generic:     -1,
		IfIndex:     -1,
		Severity:    "warning",
		Category:    "trap",
		Name:        "undecoded",
		Description: "Trap could not be decoded (malformed or unsupported packet)",
	}
	if len(pkt) == 0 {
		return out
	}

	msg := &cursor{buf: pkt}
	tag, seqBytes, ok := msg.next()
	if !ok || tag != berSequence {
		return out
	}
	seq := &cursor{buf: seqBytes}

	tag, v, ok := seq.next()
	if !ok || tag != berInteger {
		return out
	}
	out.Version = int(berInt(v))

	if out.Version == 3 {
		// v3 hides the PDU behind USM keys we were never given. Be honest
		// about it rather than reporting a decode failure - and still
		// alert, because the device did mean to tell us something.
		out.Name = "snmpv3Trap"
		out.Description = "SNMPv3 trap received - sysmon-web does not hold the v3 keys to decode it"
		out.Alertable = true
		return out
	}
	if out.Version != 0 && out.Version != 1 {
		return out
	}

	tag, v, ok = seq.next()
	if !ok || tag != berOctetStr {
		return out
	}
	out.Community = octetString(v)

	tag, pduBytes, ok := seq.next()
	if !ok {
		return out
	}
	pdu := &cursor{buf: pduBytes}

	switch tag {
	case pduTrapV1:
		// enterprise
		t, v, ok := pdu.next()
		if !ok || t != berOID {
			return out
		}
		out.Enterprise = oidString(v)

		// agent-addr: the device's own idea of its address, which differs
		// from the packet source when a proxy forwards the trap.
		t, v, ok = pdu.next()
		if !ok {
			return out
		}
		if t == berIPAddress && len(v) == 4 {
			out.Agent = fmt.Sprintf("%d.%d.%d.%d", v[0], v[1], v[2], v[3])
		}

		if t, v, ok = pdu.next(); !ok || t != berInteger {
			return out
		}
		out.Generic = int(berInt(v))

		if t, v, ok = pdu.next(); !ok || t != berInteger {
			return out
		}
		out.Specific = int(berInt(v))

		if t, v, ok = pdu.next(); !ok {
			return out
		}
		if t == berTimeTicks {
			out.Uptime = berUint(v)
		}

		// v1 has no snmpTrapOID; build the equivalent so v1 and v2c
		// records can be compared like for like.
		switch {
		case out.Generic == 6:
			out.TrapOID = fmt.Sprintf("%s.0.%d", out.Enterprise, out.Specific)
		case out.Generic >= 0 && out.Generic <= 5:
			out.TrapOID = fmt.Sprintf(".1.3.6.1.6.3.1.1.5.%d", out.Generic+1)
		}

	case pduTrapV2, pduInform:
		out.Inform = tag == pduInform
		// request-id, error-status, error-index
		for i := 0; i < 3; i++ {
			if t, _, ok := pdu.next(); !ok || t != berInteger {
				return out
			}
		}

	default:
		// Something aimed at the trap port that is not a trap - a GET, a
		// response, a scanner. Not our business.
		out.Name = "non-trap"
		out.Description = fmt.Sprintf("SNMP PDU type 0x%02x on the trap port - not a trap", tag)
		return out
	}

	decodeVarbinds(pdu, &out)
	classify(&out)
	out.Decoded = true
	out.Alertable = true
	return out
}

func decodeVarbinds(pdu *cursor, out *Content) {
	tag, listBytes, ok := pdu.next()
	if !ok || tag != berSequence {
		return
	}
	list := &cursor{buf: listBytes}

	for len(out.Varbinds) < maxVarbinds {
		tag, vbBytes, ok := list.next()
		if !ok || tag != berSequence {
			return
		}
		vb := &cursor{buf: vbBytes}

		t, v, ok := vb.next()
		if !ok || t != berOID {
			return
		}
		b := Varbind{OID: oidString(v)}
		b.Name = nameOID(b.OID)

		t, v, ok = vb.next()
		if !ok {
			return
		}
		b.Type, b.Value, b.Note = valueString(t, v)

		// Turn the varbinds we understand into facts about the trap.
		switch b.Name {
		case "snmpTrapOID":
			if b.Value != "" {
				out.TrapOID = b.Value
			}
		case "sysUpTime":
			out.Uptime, _ = strconv.ParseUint(b.Value, 10, 64)
		case "snmpTrapEnterprise":
			if out.Enterprise == "" {
				out.Enterprise = b.Value
			}
		case "ifIndex":
			if n, err := strconv.Atoi(b.Value); err == nil {
				out.IfIndex = n
			}
		case "ifName", "ifDescr", "ifAlias":
			// ifName wins over ifDescr wins over ifAlias, but any name at
			// all beats an index.
			if out.Interface == "" || b.Name == "ifName" {
				out.Interface = b.Value
			}
		case "ifOperStatus", "ifAdminStatus":
			if n, err := strconv.ParseInt(b.Value, 10, 64); err == nil {
				if s := ifStatusName(n); s != "" {
					b.Note = s
				}
			}
		}

		out.Varbinds = append(out.Varbinds, b)
	}
}

// classify decides what the trap means: name, severity, category, vendor.
func classify(out *Content) {
	known := false
	for _, st := range standardTraps {
		hit := (out.TrapOID != "" && out.TrapOID == st.oid) ||
			(out.Version == 0 && out.Generic == st.generic)
		if hit {
			out.Name, out.Severity = st.name, st.severity
			out.Category, out.Description = st.category, st.desc
			known = true
			break
		}
	}

	if !known {
		// Enterprise-specific. We cannot know what it means without the
		// vendor MIB, so say exactly that instead of guessing a severity
		// that would be wrong half the time.
		switch {
		case out.Version == 0 && out.Generic == 6:
			out.Name = fmt.Sprintf("enterpriseSpecific(%d)", out.Specific)
		case out.TrapOID != "":
			out.Name = "enterpriseSpecific"
		default:
			out.Name = "trap"
		}
		out.Severity = "warning"
		out.Category = "vendor"
		id := out.TrapOID
		if id == "" {
			id = out.Enterprise
		}
		out.Description = fmt.Sprintf(
			"Vendor-specific trap %s - see the vendor MIB for its meaning", id)
	}

	if out.Enterprise != "" {
		out.Vendor = nameVendor(out.Enterprise)
	}
	if out.Vendor == "" && out.TrapOID != "" {
		out.Vendor = nameVendor(out.TrapOID)
	}

	// An interface name makes a link trap actionable; without one an
	// ifIndex at least says which port to look at.
	if out.Interface == "" && out.IfIndex >= 0 {
		out.Interface = fmt.Sprintf("ifIndex %d", out.IfIndex)
	}
	if out.Interface != "" && out.Category == "link" {
		out.Description = out.Description + ": " + out.Interface
	}
}
