package monitoring

import (
	"bufio"
	"encoding/xml"
	"fmt"
	"net"
	"sort"
	"strings"
	"sync"
	"time"

	"sysmon-web/internal/models"
)

// SNMP traps are received by sysmond, not by this process: it is the thing
// holding a socket on UDP 162, and it decodes each packet as it arrives.
// This file asks it for what it has - the TRAPS command - and turns the
// daemon's XML into the model the trap page renders.

// trapCacheTTL keeps a burst of page loads from opening a connection each.
// Traps are already history by the time they get here; a few seconds of
// staleness costs nothing.
const trapCacheTTL = 5 * time.Second

var (
	trapMu      sync.Mutex
	trapCache   *models.TrapInfo
	trapCacheAt time.Time
)

// Wire format produced by send_traps() in src/srvclient.c.
type xmlTrapList struct {
	XMLName xml.Name  `xml:"SysmonTraps"`
	Traps   []xmlTrap `xml:"Trap"`
}

type xmlTrap struct {
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

// GetTraps returns the traps sysmond has caught, newest first.
//
// An older daemon that does not know the TRAPS command answers "444 - Unk";
// that is reported as an empty list rather than an error, because "no traps"
// and "this daemon predates trap decoding" look identical to a user staring
// at an empty page, and only one of them is worth a red banner.
func (s *Service) GetTraps(authKey string) (*models.TrapInfo, error) {
	trapMu.Lock()
	if trapCache != nil && time.Since(trapCacheAt) < trapCacheTTL {
		cached := trapCache
		trapMu.Unlock()
		return cached, nil
	}
	trapMu.Unlock()

	info, err := s.fetchTraps(authKey)
	if err != nil {
		return nil, err
	}

	trapMu.Lock()
	trapCache = info
	trapCacheAt = time.Now()
	trapMu.Unlock()

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

func (s *Service) fetchTraps(authKey string) (*models.TrapInfo, error) {
	conn, err := net.DialTimeout("tcp", s.sysmonAddr, 5*time.Second)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to sysmon at %s: %w (is sysmond running?)", s.sysmonAddr, err)
	}
	defer conn.Close()

	conn.SetDeadline(time.Now().Add(10 * time.Second))
	reader := bufio.NewReader(conn)

	if err := readWelcomeBanner(reader); err != nil {
		return nil, err
	}

	// Authenticating is what earns the community string in the reply;
	// sysmond withholds it from anonymous clients because it is a
	// credential.
	if err := authenticate(conn, reader, authKey); err != nil {
		return nil, err
	}

	if _, err := conn.Write([]byte("MODE xml\n")); err != nil {
		return nil, fmt.Errorf("failed to send MODE xml command: %w", err)
	}
	resp, err := readSysmonResponse(reader)
	if err != nil {
		return nil, fmt.Errorf("failed to read MODE xml response: %w", err)
	}
	if resp.IsError || resp.Code != "333" {
		return nil, fmt.Errorf("MODE xml failed: %s", resp.Message)
	}

	if _, err := conn.Write([]byte("TRAPS\n")); err != nil {
		return nil, fmt.Errorf("failed to send TRAPS command: %w", err)
	}

	var sb strings.Builder
	for {
		line, err := reader.ReadString('\n')
		trimmed := strings.TrimSpace(line)

		if strings.HasPrefix(trimmed, "444") {
			// Daemon does not implement TRAPS.
			s.sessionLog.Log("TRAPS", "daemon does not support TRAPS", false, "")
			return emptyTrapInfo(), nil
		}
		if strings.HasPrefix(trimmed, "333") {
			s.sessionLog.Log("TRAPS", trimmed, false, "")
			break
		}
		if trimmed != "" {
			sb.WriteString(trimmed)
		}

		if err != nil {
			return nil, fmt.Errorf("error reading TRAPS response: %w", err)
		}
	}

	raw := sb.String()
	if raw == "" {
		return emptyTrapInfo(), nil
	}

	var parsed xmlTrapList
	if err := xml.Unmarshal([]byte(raw), &parsed); err != nil {
		s.sessionLog.Log("TRAPS", raw, true, err.Error())
		return nil, fmt.Errorf("could not parse trap list from sysmond: %w", err)
	}

	return buildTrapInfo(parsed.Traps), nil
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
