package traps

import (
	"log"
	"net"
	"sort"
	"strings"
	"sync"
	"time"

	"sysmon-web/internal/models"
)

// readBuffer is one UDP datagram. Traps are small; anything bigger than
// this is not a trap we can use, and the kernel truncates it for us.
const readBuffer = 8192

// unknownSourcesKept bounds what we remember about packets we refused, so
// a flood cannot grow memory through the very path that exists to ignore
// it. Source addresses only - a refused packet's contents are never
// decoded, stored, or shown.
const unknownSourcesKept = 32

// target is a configured object a trap can belong to.
type target struct {
	object      string // sysmon object name
	hostname    string
	description string
	alert       bool // object has trap_alert set
	contact     string
}

// UnknownSource is a device sending traps that no object claims.
type UnknownSource struct {
	SourceIP string    `json:"source_ip"`
	Count    int64     `json:"count"`
	LastSeen time.Time `json:"last_seen"`
}

// AlertFunc is called for a trap that a configured object wants alerts
// for. It runs on the listener goroutine, so it should not block for long.
type AlertFunc func(Record)

// Service owns the trap socket: it reads packets, drops anything from an
// address no object claims, decodes the rest, stores them, and dispatches
// alerts.
type Service struct {
	conn  *net.UDPConn
	store *Store

	mu       sync.RWMutex
	targets  map[string]target // source IP -> object
	unknown  map[string]*UnknownSource
	dropped  int64 // packets refused because nobody claims the source
	received int64
	lastErr  string

	alert AlertFunc

	stop     chan struct{}
	stopOnce sync.Once
	wg       sync.WaitGroup
}

func NewService(conn *net.UDPConn, store *Store) *Service {
	return &Service{
		conn:    conn,
		store:   store,
		targets: make(map[string]target),
		unknown: make(map[string]*UnknownSource),
		stop:    make(chan struct{}),
	}
}

// OnAlert registers the alert dispatcher. Must be called before Start.
func (s *Service) OnAlert(fn AlertFunc) { s.alert = fn }

// SetHosts rebuilds the allow-list from the parsed sysmon.conf.
//
// Only literal addresses can match: a source IP is compared against what
// the config says, and an object addressed by DNS name would need a lookup
// per packet to match - which is exactly the work a flood would want us to
// do. Objects with non-literal addresses are reported once so the
// operator knows their traps will not be accepted.
func (s *Service) SetHosts(hosts []models.Host) {
	next := make(map[string]target, len(hosts))
	unresolvable := 0

	for _, h := range hosts {
		addr := strings.TrimSpace(h.IP)
		if addr == "" {
			addr = strings.TrimSpace(h.Hostname)
		}
		if net.ParseIP(addr) == nil {
			if addr != "" {
				unresolvable++
			}
			continue
		}
		t := target{
			object:      h.ID,
			hostname:    h.Hostname,
			description: h.Notes,
			alert:       h.TrapAlert,
			contact:     h.Contact,
		}
		// Several objects can share an address (a device plus its SNMP
		// sub-checks). Prefer whichever one actually wants trap alerts;
		// otherwise the first is fine, it only supplies a display name.
		if prev, ok := next[addr]; ok && prev.alert && !t.alert {
			continue
		}
		next[addr] = t
	}

	s.mu.Lock()
	prevCount := len(s.targets)
	s.targets = next
	s.mu.Unlock()

	if prevCount != len(next) {
		log.Printf("traps: accepting traps from %d configured address(es)", len(next))
	}
	if unresolvable > 0 {
		log.Printf("traps: %d object(s) are addressed by name, not by IP - "+
			"traps from those devices cannot be matched and will be ignored", unresolvable)
	}
}

func (s *Service) Start() {
	if s.conn == nil {
		return
	}
	s.wg.Add(1)
	go s.loop()
}

func (s *Service) Stop() {
	s.stopOnce.Do(func() {
		close(s.stop)
		if s.conn != nil {
			s.conn.Close() // unblocks the pending ReadFromUDP
		}
	})
	s.wg.Wait()
}

func (s *Service) loop() {
	defer s.wg.Done()
	buf := make([]byte, readBuffer)

	log.Printf("traps: listening on %s", s.conn.LocalAddr())
	for {
		n, addr, err := s.conn.ReadFromUDP(buf)
		select {
		case <-s.stop:
			return
		default:
		}
		if err != nil {
			// A read error on a UDP socket is usually transient (ICMP port
			// unreachable from a previous send). Record it and keep going;
			// a closed socket exits via the stop channel above.
			s.mu.Lock()
			s.lastErr = err.Error()
			s.mu.Unlock()
			if strings.Contains(err.Error(), "use of closed") {
				return
			}
			continue
		}
		s.handle(append([]byte(nil), buf[:n]...), addr)
	}
}

// handle processes one datagram. A panic here would take the whole daemon
// with it, and this is the one code path fed directly by the network, so
// it is contained.
func (s *Service) handle(pkt []byte, addr *net.UDPAddr) {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("traps: recovered while handling a packet from %s: %v", addr, r)
		}
	}()

	src := addr.IP.String()

	// Refuse anything from an address no configured object claims, before
	// decoding it. Random internet noise costs one map lookup, and nothing
	// an unconfigured sender puts in a packet is ever parsed or stored.
	s.mu.RLock()
	t, known := s.targets[src]
	s.mu.RUnlock()
	if !known {
		s.noteUnknown(src)
		return
	}

	content := Decode(pkt)

	s.mu.Lock()
	s.received++
	s.mu.Unlock()

	rec := Record{
		Source:       src,
		When:         time.Now().UTC(),
		Bytes:        len(pkt),
		Matched:      t.object,
		AlertEnabled: t.alert,
		Content:      content,
	}

	// A v1 trap carries the agent's own address, which is what matters
	// when a proxy forwards it: the packet comes from the relay, but the
	// event belongs to the device named inside. The relay still has to be
	// a configured object to get this far.
	if content.Agent != "" && content.Agent != src {
		s.mu.RLock()
		relayed, ok := s.targets[content.Agent]
		s.mu.RUnlock()
		if ok {
			rec.Matched = relayed.object
			rec.AlertEnabled = relayed.alert
			t = relayed
		}
	}

	// Only something that really is a trap can page anyone. Junk aimed at
	// the trap port is recorded and shown, never alerted on.
	if rec.AlertEnabled && content.Alertable && s.alert != nil {
		rec.AlertSent = true
	}

	if content.Decoded {
		log.Printf("traps: %s from %s (%s): %s", content.Name, src, content.Severity, content.Description)
	} else {
		log.Printf("traps: from %s: %s", src, content.Description)
	}

	if err := s.store.Append(rec); err != nil {
		log.Printf("traps: could not store trap from %s: %v", src, err)
	}
	if rec.AlertSent {
		s.alert(rec)
	}
}

// noteUnknown counts a refused packet. Bounded on purpose - see
// unknownSourcesKept.
func (s *Service) noteUnknown(src string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.dropped++
	if u, ok := s.unknown[src]; ok {
		u.Count++
		u.LastSeen = time.Now().UTC()
		return
	}
	if len(s.unknown) >= unknownSourcesKept {
		// Evict the least recently seen so a scanner cycling addresses
		// cannot grow the map, but a persistent misconfigured device still
		// stays visible.
		var oldest string
		var oldestAt time.Time
		for ip, u := range s.unknown {
			if oldest == "" || u.LastSeen.Before(oldestAt) {
				oldest, oldestAt = ip, u.LastSeen
			}
		}
		delete(s.unknown, oldest)
	}
	s.unknown[src] = &UnknownSource{SourceIP: src, Count: 1, LastSeen: time.Now().UTC()}
}

// Stats describes the listener for the admin/trap pages.
type Stats struct {
	Listening      bool            `json:"listening"`
	Address        string          `json:"address,omitempty"`
	Received       int64           `json:"received"`
	Dropped        int64           `json:"dropped_unconfigured"`
	ConfiguredIPs  int             `json:"configured_addresses"`
	UnknownSources []UnknownSource `json:"unknown_sources,omitempty"`
	RetentionDays  int             `json:"retention_days"`
	LastError      string          `json:"last_error,omitempty"`
}

func (s *Service) Stats() Stats {
	s.mu.RLock()
	defer s.mu.RUnlock()

	st := Stats{
		Listening:     s.conn != nil,
		Received:      s.received,
		Dropped:       s.dropped,
		ConfiguredIPs: len(s.targets),
		RetentionDays: int(MaxAge / (24 * time.Hour)),
		LastError:     s.lastErr,
	}
	if s.conn != nil {
		st.Address = s.conn.LocalAddr().String()
	}
	for _, u := range s.unknown {
		st.UnknownSources = append(st.UnknownSources, *u)
	}
	sort.Slice(st.UnknownSources, func(i, j int) bool {
		return st.UnknownSources[i].LastSeen.After(st.UnknownSources[j].LastSeen)
	})
	return st
}

// Info builds the model the trap page renders: the records plus the
// per-source and summary rollups shown above the list.
func (s *Service) Info(limit int) *models.TrapInfo {
	info := &models.TrapInfo{
		RecentTraps: []models.Trap{},
		TrapSources: []models.TrapSource{},
		Summary: models.TrapSummary{
			TrapsByType:     make(map[string]int),
			TrapsBySeverity: make(map[string]int),
		},
	}
	if s.store == nil {
		return info
	}

	sources := map[string]*models.TrapSource{}
	hourAgo := time.Now().Add(-time.Hour)

	for _, r := range s.store.Recent(limit) {
		c := r.Content
		trap := models.Trap{
			SourceIP:     r.Source,
			Timestamp:    r.When,
			TrapType:     c.Name,
			Varbinds:     []models.Varbind{},
			MatchedHost:  r.Matched,
			AlertEnabled: r.AlertEnabled,
			AlertSent:    r.AlertSent,
		}

		// A trap we could not decode has no decoded block; say what it was
		// instead of showing a blank row.
		if c.Decoded {
			trap.Decoded = &models.TrapDecode{
				TrapName:       c.Name,
				Description:    c.Description,
				Severity:       c.Severity,
				Category:       c.Category,
				Vendor:         c.Vendor,
				Interface:      c.Interface,
				InterfaceIndex: c.IfIndex,
			}
		} else if c.Description != "" {
			trap.TrapType = c.Name + " - " + c.Description
		}

		for _, v := range c.Varbinds {
			desc := v.Note
			if v.Name != "" {
				if desc != "" {
					desc = v.Name + " (" + desc + ")"
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

		if r.When.After(hourAgo) {
			info.Summary.TotalTraps++
		}
		info.Summary.TrapsByType[c.Name]++
		severity := c.Severity
		if severity == "" {
			severity = "unknown"
		}
		info.Summary.TrapsBySeverity[severity]++

		src, ok := sources[r.Source]
		if !ok {
			src = &models.TrapSource{SourceIP: r.Source, Hostname: r.Matched}
			sources[r.Source] = src
		}
		src.TrapCount++
		if r.When.After(src.LastTrap) {
			src.LastTrap = r.When
		}
		if src.Hostname == "" {
			src.Hostname = r.Matched
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
