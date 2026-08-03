package traps

import (
	"fmt"
	"strings"
	"testing"
)

// Minimal BER writer, only enough to build test packets. Lengths are
// always written in the two-byte long form, which keeps containers
// unbounded and exercises the decoder's long-form path on every packet.
type pkt struct{ b []byte }

func (p *pkt) open(tag byte) int {
	p.b = append(p.b, tag, 0x82, 0, 0)
	return len(p.b)
}

func (p *pkt) close(start int) {
	n := len(p.b) - start
	p.b[start-2] = byte(n >> 8)
	p.b[start-1] = byte(n)
}

func (p *pkt) int(tag byte, v int64) {
	s := p.open(tag)
	if v == 0 {
		p.b = append(p.b, 0)
	} else {
		var tmp []byte
		for x := v; x > 0; x >>= 8 {
			tmp = append(tmp, byte(x&0xff))
		}
		if tmp[len(tmp)-1]&0x80 != 0 {
			p.b = append(p.b, 0) // keep it positive
		}
		for i := len(tmp) - 1; i >= 0; i-- {
			p.b = append(p.b, tmp[i])
		}
	}
	p.close(s)
}

func (p *pkt) str(v string) {
	s := p.open(0x04)
	p.b = append(p.b, v...)
	p.close(s)
}

func (p *pkt) oid(dotted string) {
	s := p.open(0x06)
	var subs []uint64
	for _, part := range strings.Split(dotted, ".") {
		var n uint64
		fmt.Sscanf(part, "%d", &n)
		subs = append(subs, n)
	}
	p.b = append(p.b, byte(subs[0]*40+subs[1]))
	for _, v := range subs[2:] {
		var tmp []byte
		for {
			tmp = append(tmp, byte(v&0x7f))
			v >>= 7
			if v == 0 {
				break
			}
		}
		for i := len(tmp) - 1; i >= 0; i-- {
			b := tmp[i]
			if i > 0 {
				b |= 0x80
			}
			p.b = append(p.b, b)
		}
	}
	p.close(s)
}

func (p *pkt) ip(a, b, c, d byte) {
	s := p.open(0x40)
	p.b = append(p.b, a, b, c, d)
	p.close(s)
}

// A v2c linkDown naming interface Gi0/1.
func buildV2LinkDown() []byte {
	p := &pkt{}
	msg := p.open(0x30)
	p.int(0x02, 1) // v2c
	p.str("public")
	pdu := p.open(0xa7)
	p.int(0x02, 12345) // request-id
	p.int(0x02, 0)     // error-status
	p.int(0x02, 0)     // error-index
	vbl := p.open(0x30)

	vb := p.open(0x30)
	p.oid("1.3.6.1.2.1.1.3.0")
	p.int(0x43, 123456) // sysUpTime
	p.close(vb)

	vb = p.open(0x30)
	p.oid("1.3.6.1.6.3.1.1.4.1.0") // snmpTrapOID
	p.oid("1.3.6.1.6.3.1.1.5.3")   // linkDown
	p.close(vb)

	vb = p.open(0x30)
	p.oid("1.3.6.1.2.1.2.2.1.1.3") // ifIndex.3
	p.int(0x02, 3)
	p.close(vb)

	vb = p.open(0x30)
	p.oid("1.3.6.1.2.1.2.2.1.2.3") // ifDescr.3
	p.str("Gi0/1")
	p.close(vb)

	vb = p.open(0x30)
	p.oid("1.3.6.1.2.1.2.2.1.8.3") // ifOperStatus.3
	p.int(0x02, 2)                 // down
	p.close(vb)

	p.close(vbl)
	p.close(pdu)
	p.close(msg)
	return p.b
}

// A v1 trap. generic 0 is coldStart; generic 6 is enterprise-specific.
func buildV1(enterprise string, generic, specific int64) []byte {
	p := &pkt{}
	msg := p.open(0x30)
	p.int(0x02, 0) // v1
	p.str("public")
	pdu := p.open(0xa4)
	p.oid(enterprise)
	p.ip(10, 1, 2, 3) // agent-addr
	p.int(0x02, generic)
	p.int(0x02, specific)
	p.int(0x43, 42) // timestamp
	vbl := p.open(0x30)
	p.close(vbl)
	p.close(pdu)
	p.close(msg)
	return p.b
}

func buildV3() []byte {
	p := &pkt{}
	msg := p.open(0x30)
	p.int(0x02, 3)
	p.str("junk") // not what v3 really carries
	p.close(msg)
	return p.b
}

// A packet designed to be obnoxious: XML/HTML metacharacters in a string,
// an OID longer than the field meant to hold it, and far more varbinds
// than we keep.
func buildNasty() []byte {
	longoid := "1.3" + strings.Repeat(".4294967295", 60)

	p := &pkt{}
	msg := p.open(0x30)
	p.int(0x02, 1)
	p.str("<&\"'>")
	pdu := p.open(0xa7)
	p.int(0x02, 1)
	p.int(0x02, 0)
	p.int(0x02, 0)
	vbl := p.open(0x30)

	vb := p.open(0x30)
	p.oid("1.3.6.1.6.3.1.1.4.1.0")
	p.oid("1.3.6.1.4.1.9.9.41.2.0.1") // Cisco enterprise trap
	p.close(vb)

	vb = p.open(0x30)
	p.oid("1.3.6.1.2.1.2.2.1.2.1")
	p.str("</TrapDescription><script>alert(1)</script>")
	p.close(vb)

	vb = p.open(0x30)
	p.oid(longoid)
	p.str("over-long oid")
	p.close(vb)

	for i := int64(0); i < 40; i++ { // more varbinds than maxVarbinds
		vb = p.open(0x30)
		p.oid("1.3.6.1.4.1.9.9.9.1")
		p.int(0x02, i)
		p.close(vb)
	}

	p.close(vbl)
	p.close(pdu)
	p.close(msg)
	return p.b
}

// checkBounds asserts the invariants every decode must hold, whatever the
// input was.
func checkBounds(t *testing.T, c Content) {
	t.Helper()
	if len(c.Varbinds) > maxVarbinds {
		t.Fatalf("varbind count %d exceeds cap %d", len(c.Varbinds), maxVarbinds)
	}
	if c.Name == "" || c.Severity == "" || c.Category == "" {
		t.Fatalf("decode left a required field empty: %+v", c)
	}
	if c.Decoded && !c.Alertable {
		t.Fatalf("a decoded trap must be alertable: %+v", c)
	}
	for _, v := range c.Varbinds {
		if len(v.OID) > maxOIDLen+16 {
			t.Fatalf("oid string too long: %d", len(v.OID))
		}
		if len(v.Value) > maxValueLen+16 {
			t.Fatalf("value string too long: %d", len(v.Value))
		}
	}
}

func TestV2LinkDown(t *testing.T) {
	c := Decode(buildV2LinkDown())
	checkBounds(t, c)

	if !c.Decoded || !c.Alertable {
		t.Fatalf("linkDown should decode: %+v", c)
	}
	if c.Version != 1 {
		t.Errorf("version = %d, want 1 (v2c)", c.Version)
	}
	if c.Community != "public" {
		t.Errorf("community = %q", c.Community)
	}
	if c.Name != "linkDown" || c.Severity != "critical" || c.Category != "link" {
		t.Errorf("classified as %s/%s/%s", c.Name, c.Severity, c.Category)
	}
	if c.TrapOID != ".1.3.6.1.6.3.1.1.5.3" {
		t.Errorf("trap OID = %q", c.TrapOID)
	}
	if c.Interface != "Gi0/1" || c.IfIndex != 3 {
		t.Errorf("interface = %q index = %d", c.Interface, c.IfIndex)
	}
	if c.Uptime != 123456 {
		t.Errorf("uptime = %d", c.Uptime)
	}
	if !strings.Contains(c.Description, "Gi0/1") {
		t.Errorf("description should name the interface: %q", c.Description)
	}
	if len(c.Varbinds) != 5 {
		t.Fatalf("varbinds = %d, want 5", len(c.Varbinds))
	}

	var found bool
	for _, v := range c.Varbinds {
		if v.Name == "ifOperStatus" {
			found = true
			if v.Note != "down" {
				t.Errorf("ifOperStatus note = %q, want down", v.Note)
			}
		}
	}
	if !found {
		t.Error("ifOperStatus varbind missing")
	}
}

func TestV1ColdStart(t *testing.T) {
	c := Decode(buildV1("1.3.6.1.4.1.14988", 0, 0))
	checkBounds(t, c)

	if c.Version != 0 {
		t.Errorf("version = %d, want 0 (v1)", c.Version)
	}
	if c.Name != "coldStart" || c.Severity != "warning" || c.Category != "restart" {
		t.Errorf("classified as %s/%s/%s", c.Name, c.Severity, c.Category)
	}
	if c.Agent != "10.1.2.3" {
		t.Errorf("agent-addr = %q", c.Agent)
	}
	if c.Vendor != "MikroTik" {
		t.Errorf("vendor = %q, want MikroTik", c.Vendor)
	}
	if c.TrapOID != ".1.3.6.1.6.3.1.1.5.1" {
		t.Errorf("v1 should map to the v2 trap OID, got %q", c.TrapOID)
	}
}

func TestV1EnterpriseSpecific(t *testing.T) {
	c := Decode(buildV1("1.3.6.1.4.1.9", 6, 17))
	checkBounds(t, c)

	if c.Name != "enterpriseSpecific(17)" {
		t.Errorf("name = %q, want enterpriseSpecific(17)", c.Name)
	}
	if c.Vendor != "Cisco" {
		t.Errorf("vendor = %q, want Cisco", c.Vendor)
	}
	if c.TrapOID != ".1.3.6.1.4.1.9.0.17" {
		t.Errorf("trap OID = %q", c.TrapOID)
	}
}

func TestV3IsNotDecodedButStillAlerts(t *testing.T) {
	c := Decode(buildV3())
	checkBounds(t, c)

	if c.Decoded {
		t.Error("v3 must not claim to be decoded")
	}
	if !c.Alertable {
		t.Error("v3 is a real trap and must still alert")
	}
	if c.Name != "snmpv3Trap" {
		t.Errorf("name = %q", c.Name)
	}
}

func TestNastyPacket(t *testing.T) {
	c := Decode(buildNasty())
	checkBounds(t, c)

	if !c.Decoded {
		t.Fatal("the nasty packet is still valid BER and should decode")
	}
	if c.Vendor != "Cisco" {
		t.Errorf("vendor = %q, want Cisco (from the trap OID)", c.Vendor)
	}
	if len(c.Varbinds) != maxVarbinds {
		t.Errorf("varbinds = %d, want them capped at %d", len(c.Varbinds), maxVarbinds)
	}
}

// Junk on the trap port must never be alertable - that is what keeps a
// spoofed packet from paging somebody.
func TestGarbageIsNotAlertable(t *testing.T) {
	cases := map[string][]byte{
		"empty":     {},
		"truncated": {0x30, 0x0f, 0x02, 0x01},
		"bad tag":   {0xff, 0x01, 0x00},
		"huge len":  {0x30, 0x84, 0xff, 0xff, 0xff, 0xff, 0x02, 0x01, 0x01},
		"all bytes": func() []byte {
			b := make([]byte, 256)
			for i := range b {
				b[i] = byte(i)
			}
			return b
		}(),
		"snmp get": func() []byte {
			p := &pkt{}
			m := p.open(0x30)
			p.int(0x02, 1)
			p.str("public")
			g := p.open(0xa0)
			p.int(0x02, 1)
			p.close(g)
			p.close(m)
			return p.b
		}(),
	}
	for name, b := range cases {
		c := Decode(b)
		checkBounds(t, c)
		if c.Alertable {
			t.Errorf("%s: must not be alertable", name)
		}
		if c.Decoded {
			t.Errorf("%s: must not claim to be decoded", name)
		}
	}
}

// Every prefix of a valid packet must be handled without misbehaving.
func TestTruncation(t *testing.T) {
	for _, full := range [][]byte{buildV2LinkDown(), buildV1("1.3.6.1.4.1.9", 6, 17), buildNasty()} {
		for n := 0; n <= len(full); n++ {
			c := Decode(full[:n])
			checkBounds(t, c)
		}
	}
}

// FuzzDecode is the real safety net: go test -fuzz=FuzzDecode
func FuzzDecode(f *testing.F) {
	f.Add(buildV2LinkDown())
	f.Add(buildV1("1.3.6.1.4.1.14988", 0, 0))
	f.Add(buildV1("1.3.6.1.4.1.9", 6, 17))
	f.Add(buildV3())
	f.Add(buildNasty())
	f.Add([]byte{0x30, 0x00})

	f.Fuzz(func(t *testing.T, data []byte) {
		c := Decode(data)
		if len(c.Varbinds) > maxVarbinds {
			t.Fatalf("varbind cap broken: %d", len(c.Varbinds))
		}
		if c.Name == "" || c.Severity == "" || c.Category == "" {
			t.Fatalf("required field empty for input %x", data)
		}
		if c.Decoded && !c.Alertable {
			t.Fatalf("decoded but not alertable: %x", data)
		}
	})
}
