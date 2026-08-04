package monitoring

import (
	"bufio"
	"encoding/xml"
	"fmt"
	"net"
	"sort"
	"strings"
	"time"

	"sysmon-web/internal/models"
)

// SNMP traps are received by sysmond, not by this process: it is the thing
// holding a socket on UDP 162, and it decodes each packet as it arrives.
// This file asks it for what it has - the TRAPS command - and turns the
// daemon's XML into the model the trap page renders.

// Retention. sysmond's ring holds the last few dozen traps in memory so
// it can hand them over; keeping a month of them is this side's job,
// because this is the side with somewhere to put them and a page that
// shows them.
const (
	trapMaxAge = 31 * 24 * time.Hour
	trapsKept  = 20000 // backstop against a device stuck in a trap loop
)

// Wire format produced by send_traps() in src/srvclient.c.
type xmlTrapList struct {
	XMLName xml.Name  `xml:"SysmonTraps"`
	Traps   []xmlTrap `xml:"Trap"`
}

type xmlTrap struct {
	Seq          uint64       `xml:"TrapSeq"`
	Source       string       `xml:"TrapSource"`
	Time         int64        `xml:"TrapTime"`
	Bytes        int          `xml:"TrapBytes"`
	Version      string       `xml:"TrapVersion"`
	Community    string       `xml:"TrapCommunity"`
	OID          string       `xml:"TrapOID"`
	Enterprise   string       `xml:"TrapEnterprise"`
	Agent        string       `xml:"TrapAgentAddress"`
	Name         string       `xml:"TrapName"`
	Description  string       `xml:"TrapDescription"`
	Severity     string       `xml:"TrapSeverity"`
	Category     string       `xml:"TrapCategory"`
	Vendor       string       `xml:"TrapVendor"`
	Interface    string       `xml:"TrapInterface"`
	IfIndex      int          `xml:"TrapIfIndex"`
	Uptime       uint64       `xml:"TrapUptime"`
	Decoded      int          `xml:"TrapDecoded"`
	MatchedHost  string       `xml:"TrapMatchedHost"`
	AlertEnabled int          `xml:"TrapAlertEnabled"`
	AlertSent    int          `xml:"TrapAlertSent"`
	Varbinds     []xmlVarbind `xml:"Varbind"`
}

type xmlVarbind struct {
	OID   string `xml:"VarbindOID"`
	Name  string `xml:"VarbindName"`
	Type  string `xml:"VarbindType"`
	Value string `xml:"VarbindValue"`
	Note  string `xml:"VarbindNote"`
}

// GetTraps returns the traps the poller has collected, newest first.
//
// It does not talk to sysmond: the poller already asked, on the same
// connection it uses for object status, and kept what came back. Traps
// are held far longer than the daemon's ring holds them, so this is also
// the only place a month of history exists.
func (s *Service) GetTraps(authKey string) (*models.TrapInfo, error) {
	s.cacheMu.Lock()
	held := make([]xmlTrap, len(s.trapHistory))
	copy(held, s.trapHistory)
	lost := s.trapsLost
	s.cacheMu.Unlock()

	info := buildTrapInfo(held)
	info.Summary.Lost = lost
	return info, nil
}

func emptyTrapInfo() *models.TrapInfo {
	return &models.TrapInfo{
		RecentTraps: []models.Trap{},
		TrapSources: []models.TrapSource{},
		Summary: models.TrapSummary{
			TrapsByType:     make(map[string]int),
			TrapsBySeverity: make(map[string]int),
		},
	}
}

// fetchTraps asks for the traps that arrived since the last cycle, on the
// connection the caller already has open and authenticated.
//
// The daemon answers "333 <current-seq> <oldest-held> <sent>". Comparing
// <oldest-held> against what we asked for is how we know the ring
// overwrote traps before we managed to collect them - which is worth
// saying out loud rather than quietly under-reporting.
func (s *Service) fetchTraps(conn net.Conn, reader *bufio.Reader) {
	s.cacheMu.Lock()
	since := s.trapSeq
	s.cacheMu.Unlock()

	cmd := "TRAPS\n"
	if since > 0 {
		cmd = fmt.Sprintf("TRAPS %d\n", since)
	}
	if _, err := conn.Write([]byte(cmd)); err != nil {
		s.sessionLog.Log("TRAPS", "", true, "write failed: "+err.Error())
		return
	}

	var (
		block   strings.Builder
		fresh   []xmlTrap
		current uint64
		oldest  uint64
	)
	for {
		line, err := reader.ReadString('\n')
		trimmed := strings.TrimSpace(line)

		if strings.HasPrefix(trimmed, "444") || strings.HasPrefix(trimmed, "403") {
			s.sessionLog.Log("TRAPS", trimmed, true, "daemon refused the trap query")
			return // daemon too old to know TRAPS, or not in xml mode
		}
		if strings.HasPrefix(trimmed, "333") {
			current = parseSeqField(trimmed, 1)
			oldest = parseSeqField(trimmed, 2)
			break
		}

		// Start clean at each <Trap>: the first block would otherwise
		// carry the <SysmonTraps> wrapper line with it and fail to
		// unmarshal, quietly losing one trap per fetch.
		if strings.Contains(line, "<Trap>") {
			block.Reset()
		}
		block.WriteString(line)
		if strings.Contains(line, "</Trap>") {
			var t xmlTrap
			if perr := xml.Unmarshal([]byte(block.String()), &t); perr == nil {
				fresh = append(fresh, t)
			} else {
				s.sessionLog.Log("TRAPS", block.String(), true, perr.Error())
			}
			block.Reset()
		}
		if err != nil {
			s.sessionLog.Log("TRAPS", "", true, "read failed: "+err.Error())
			return
		}
	}

	s.cacheMu.Lock()
	defer s.cacheMu.Unlock()

	if current < s.trapSeq {
		// Daemon restarted; its ring and its counter start over.
		s.trapSeq = 0
		since = 0
	}
	// A gap means traps aged out of the daemon's ring before we asked.
	if since > 0 && oldest > since+1 {
		missed := int(oldest - since - 1)
		s.trapsLost += missed
		s.sessionLog.Log(fmt.Sprintf("TRAPS %d", since), "", true,
			fmt.Sprintf("%d trap(s) aged out of sysmond's ring before we collected them", missed))
	}

	// The daemon sends newest first; keep the store oldest-last so the
	// page renders the same order it always did.
	if len(fresh) > 0 {
		s.trapHistory = append(fresh, s.trapHistory...)
		if len(s.trapHistory) > trapsKept {
			s.trapHistory = s.trapHistory[:trapsKept]
		}
		s.sessionLog.Log(fmt.Sprintf("TRAPS %d", since),
			fmt.Sprintf("%d new (seq %d, %d held)", len(fresh), current, len(s.trapHistory)), false, "")
	}
	if current > 0 {
		s.trapSeq = current
	}

	// Age out anything past the retention window.
	cutoff := time.Now().Add(-trapMaxAge).Unix()
	kept := s.trapHistory[:0]
	for _, t := range s.trapHistory {
		if t.Time >= cutoff {
			kept = append(kept, t)
		}
	}
	s.trapHistory = kept
}

// buildTrapInfo turns the daemon's records into the page model, including
// the per-source and summary rollups the UI shows above the list.
func buildTrapInfo(traps []xmlTrap) *models.TrapInfo {
	info := emptyTrapInfo()
	sources := map[string]*models.TrapSource{}
	hourAgo := time.Now().Add(-time.Hour)

	for _, t := range traps {
		when := time.Unix(t.Time, 0)

		trap := models.Trap{
			SourceIP:     t.Source,
			Timestamp:    when,
			TrapType:     t.Name,
			Varbinds:     []models.Varbind{},
			MatchedHost:  t.MatchedHost,
			AlertEnabled: t.AlertEnabled == 1,
			AlertSent:    t.AlertSent == 1,
		}

		// A trap we could not decode has no decoded block; say what it
		// was instead of showing a blank row.
		if t.Decoded == 1 {
			trap.Decoded = &models.TrapDecode{
				TrapName:       t.Name,
				Description:    t.Description,
				Severity:       t.Severity,
				Category:       t.Category,
				Vendor:         t.Vendor,
				Interface:      t.Interface,
				InterfaceIndex: t.IfIndex,
			}
		} else if t.Description != "" {
			trap.TrapType = fmt.Sprintf("%s - %s", t.Name, t.Description)
		}

		for _, v := range t.Varbinds {
			desc := v.Note
			if v.Name != "" {
				if desc != "" {
					desc = fmt.Sprintf("%s (%s)", v.Name, desc)
				} else {
					desc = v.Name
				}
			}
			trap.Varbinds = append(trap.Varbinds, models.Varbind{
				OID:         v.OID,
				Type:        v.Type,
				Value:       v.Value,
				Description: desc,
			})
		}

		info.RecentTraps = append(info.RecentTraps, trap)

		if when.After(hourAgo) {
			info.Summary.TotalTraps++
		}
		info.Summary.TrapsByType[t.Name]++
		severity := t.Severity
		if severity == "" {
			severity = "unknown"
		}
		info.Summary.TrapsBySeverity[severity]++

		src, ok := sources[t.Source]
		if !ok {
			src = &models.TrapSource{SourceIP: t.Source, Hostname: t.MatchedHost}
			sources[t.Source] = src
		}
		src.TrapCount++
		if when.After(src.LastTrap) {
			src.LastTrap = when
		}
		if src.Hostname == "" {
			src.Hostname = t.MatchedHost
		}
	}

	for _, src := range sources {
		info.TrapSources = append(info.TrapSources, *src)
	}
	sort.Slice(info.TrapSources, func(i, j int) bool {
		return info.TrapSources[i].LastTrap.After(info.TrapSources[j].LastTrap)
	})

	return info
}
