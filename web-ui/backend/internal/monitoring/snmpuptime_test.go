package monitoring

import (
	"testing"
	"time"
)

// ObjectSNMPObjectSysUpTime is only an uptime on a reboot check.
//
// The daemon's struct field is called system_uptime, but every SNMP
// check type stashes its own last reading in it - a "high" check on a
// board-temperature OID leaves 38 there. Reading that as TimeTicks put
// "up 0m" on the card of a switch that had been up for weeks, next to a
// genuine "up 37d 0h" from the reboot check on the same device, which
// is the kind of wrong that makes a reader distrust the rest of it.
func TestSysUpTimeOnlyFromRebootChecks(t *testing.T) {
	cases := []struct {
		name     string
		snmpType string
		raw      int64
		want     int64 // 0 means "must not be presented as an uptime"
	}{
		{"reboot check carries a real sysUpTime", "reboot", 319680000, 319680000},
		{"a temperature reading is not an uptime", "high", 38, 0},
		{"a voltage reading is not an uptime", "low", 53, 0},
		{"a battery status is not an uptime", "exact", 2, 0},
		{"a rate is not an uptime", "rate", 1200, 0},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			host, _ := hostFromXML(XMLObjectStatus{
				Object:        "sw-" + c.snmpType,
				HostName:      "10.0.0.1",
				ObjectType:    "snmp",
				SNMPType:      c.snmpType,
				SNMPSysUpTime: c.raw,
			}, time.Now(), "site")
			var got int64
			if host.SNMP != nil {
				got = host.SNMP.SysUpTime
			}
			if got != c.want {
				t.Errorf("snmp-type %q with value %d: uptime reported as %d, want %d",
					c.snmpType, c.raw, got, c.want)
			}
		})
	}
}
