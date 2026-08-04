package monitoring

import (
	"bufio"
	"encoding/xml"
	"fmt"
	"hash/fnv"
	"net"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"sysmon-web/internal/models"
	"sysmon-web/internal/settings"
)

// sanitizeCmd removes newlines and control characters from user input
// before it's sent as part of a sysmond TCP command. Prevents injection
// of additional protocol commands via crafted hostnames or notes.
func sanitizeCmd(s string) string {
	clean := strings.Map(func(r rune) rune {
		if r == '\n' || r == '\r' || r < 32 {
			return -1
		}
		return r
	}, s)
	return strings.TrimSpace(clean)
}

// Service handles monitoring queries to sysmon daemon
// daemon is one sysmond and everything we track about it. A fleet is a
// list of these; a single-box install is a list of one, which is why the
// aggregation adds no special case to the single-box path.
type daemon struct {
	addr string

	// inbound daemons dialled us: their connection is long-lived and
	// reused every cycle rather than redialled, because a TLS handshake
	// per second per site is waste and the box may not be reachable from
	// here at all.
	inbound bool
	conn    net.Conn
	reader  *bufio.Reader

	mu       sync.Mutex
	site     string // "local" until the daemon says otherwise
	siteDesc string
	info     models.DaemonInfo
	lastErr  string
	lastOK   time.Time

	// Incremental fetch state.
	//
	// confSeq is the highest object sequence this daemon has reported. It
	// goes back as CONF's argument, so a cycle where nothing changed
	// transfers two lines. hostCache keeps the objects we already know,
	// since the daemon will not resend them.
	//
	// fullResyncAt forces a whole dump periodically: counters like
	// total_checked tick without being a "change", so an object that never
	// changes state would otherwise show numbers frozen at whenever we
	// last saw it.
	confSeq      uint64
	hostCache    map[string]XMLObjectStatus
	fullResyncAt time.Time

	// Config distribution state, and the lock that keeps a delivery from
	// interleaving with a status poll on a shared inbound socket.
	conf   confState
	confMu sync.Mutex

	// lastHosts is the last thing this site actually said, kept so a site
	// that stops answering can be shown as stale rather than deleted.
	// It is the built model, not the XML, because the bulk path and the
	// object-by-object fallback both end up here - and because freezing
	// the derived "up for 3d" at the moment contact was lost is the
	// honest thing to show.
	lastHosts []models.HostStatus

	// Traps collected from this daemon, newest first. trapSeq is the
	// highest trap sequence it has reported; trapsLost counts the ones its
	// ring overwrote before we asked for them.
	trapSeq     uint64
	trapHistory []xmlTrap
	trapsLost   int
}

type Service struct {
	// daemons is the fleet, in the order they were configured. The first
	// is the primary: it is what a single-daemon API field reports, so a
	// one-box install sees exactly what it always did.
	// fleetMu guards the daemons slice itself; each daemon guards its own
	// state. A dialled-in site can join or reconnect at any moment.
	fleetMu    sync.Mutex
	daemons    []*daemon
	sysmonAddr string // the primary's address, kept for error messages
	sessionLog *SessionLogger

	cacheMu sync.Mutex
	// history, when set, receives every observed host status transition.
	history *HistoryStore
	// generations is the desired-state store for config distribution.
	// Nil means this process is not managing anyone's config, which is
	// the correct state for a single-box install that never asked for it.
	generations  *settings.Store
	cachedStatus *models.SysmonStatus
	cacheTime    time.Time
	fetching     bool
	fetchDone    chan struct{}

	// Delta bookkeeping (guarded by cacheMu). rev bumps only when host
	// state actually changes. hostRev[name] is the rev a host last changed
	// at; hostSig[name] is its content signature (volatile timers
	// excluded) used to detect change. removedAt[name] records the rev a
	// host was removed, so delta clients learn about deletions.
	// minDeltaRev is the oldest rev we can still produce a correct delta
	// from; a client older than that gets a full resync.
	rev         int64
	hostRev     map[string]int64
	hostSig     map[string]uint64
	removedAt   map[string]int64
	minDeltaRev int64

	pollOnce sync.Once
	pollStop chan struct{}

	// authKeyFn supplies sysmond's configured authkey. CONF - the bulk
	// object dump - is privileged; without a key we fall back to asking
	// for each object separately.
	authKeyFn func() string
}

// fullResyncEvery bounds how stale a quiet object's counters can get.
const fullResyncEvery = 60 * time.Second

// SetAuthKeyProvider tells the service how to find sysmond's authkey.
func (s *Service) SetAuthKeyProvider(fn func() string) { s.authKeyFn = fn }

func (s *Service) authKey() string {
	if s.authKeyFn == nil {
		return ""
	}
	return s.authKeyFn()
}

// maxRemovedTracked caps the removal log; removals are rare in a
// monitoring tool, so this is effectively never hit, but it bounds memory.
const maxRemovedTracked = 256

// SessionLogEntry represents a single logged operation
type SessionLogEntry struct {
	Timestamp time.Time `json:"timestamp"`
	Command   string    `json:"command"`
	Response  string    `json:"response"`
	IsError   bool      `json:"is_error"`
	ErrorMsg  string    `json:"error_msg,omitempty"`
}

// SessionLogger captures all sysmon protocol operations
type SessionLogger struct {
	mu         sync.RWMutex
	entries    []SessionLogEntry
	errors     []SessionLogEntry
	maxEntries int
	maxErrors  int
}

// NewSessionLogger creates a new session logger
func NewSessionLogger(maxEntries, maxErrors int) *SessionLogger {
	return &SessionLogger{
		entries:    make([]SessionLogEntry, 0, maxEntries),
		errors:     make([]SessionLogEntry, 0, maxErrors),
		maxEntries: maxEntries,
		maxErrors:  maxErrors,
	}
}

// Log adds an entry to the session log
func (sl *SessionLogger) Log(command, response string, isError bool, errorMsg string) {
	sl.mu.Lock()
	defer sl.mu.Unlock()

	entry := SessionLogEntry{
		Timestamp: time.Now(),
		Command:   command,
		Response:  response,
		IsError:   isError,
		ErrorMsg:  errorMsg,
	}

	// Add to main log (circular buffer)
	sl.entries = append(sl.entries, entry)
	if len(sl.entries) >= sl.maxEntries {
		sl.entries = sl.entries[len(sl.entries)-sl.maxEntries:]
	}

	// Add to errors log if it's an error (circular buffer)
	if isError {
		sl.errors = append(sl.errors, entry)
		if len(sl.errors) >= sl.maxErrors {
			sl.errors = sl.errors[len(sl.errors)-sl.maxErrors:]
		}
	}
}

// GetRecentEntries returns the N most recent log entries
func (sl *SessionLogger) GetRecentEntries(n int) []SessionLogEntry {
	sl.mu.RLock()
	defer sl.mu.RUnlock()

	if n <= 0 || n > len(sl.entries) {
		n = len(sl.entries)
	}

	// Return last N entries
	result := make([]SessionLogEntry, n)
	copy(result, sl.entries[len(sl.entries)-n:])
	return result
}

// GetRecentErrors returns the N most recent error entries
func (sl *SessionLogger) GetRecentErrors(n int) []SessionLogEntry {
	sl.mu.RLock()
	defer sl.mu.RUnlock()

	if n <= 0 || n > len(sl.errors) {
		n = len(sl.errors)
	}

	// Return last N errors
	result := make([]SessionLogEntry, n)
	copy(result, sl.errors[len(sl.errors)-n:])
	return result
}

// XMLParseError represents an XML parsing error with debug data
type XMLParseError struct {
	Message      string
	ObjectName   string
	RawXML       string
	AllSamples   []map[string]string
	AllResponses []ResponseCapture // Capture ALL protocol responses
}

func (e *XMLParseError) Error() string {
	return e.Message
}

// ResponseCapture captures a single protocol response
type ResponseCapture struct {
	Command  string `json:"command"`
	Response string `json:"response"`
	Parsed   bool   `json:"parsed"`
	Error    string `json:"error,omitempty"`
}

// NewService creates a new monitoring service
// SetHistory attaches a transition-history store; every status change
// observed by the snapshot differ is appended to it.
func (s *Service) SetHistory(h *HistoryStore) {
	s.cacheMu.Lock()
	s.history = h
	s.cacheMu.Unlock()
}

// History returns the attached store, or nil.
func (s *Service) History() *HistoryStore {
	s.cacheMu.Lock()
	defer s.cacheMu.Unlock()
	return s.history
}

// SetGenerations attaches the desired-state store. Without one, every site
// reads as unmanaged and nothing is ever delivered - which is the right
// behaviour, not a degraded one.
func (s *Service) SetGenerations(st *settings.Store) {
	s.cacheMu.Lock()
	s.generations = st
	s.cacheMu.Unlock()
}

// Generations returns the desired-state store, or nil.
func (s *Service) Generations() *settings.Store {
	s.cacheMu.Lock()
	defer s.cacheMu.Unlock()
	return s.generations
}

// NewService takes one or more sysmond addresses, comma-separated. One
// address is the ordinary single-box case and behaves exactly as it always
// has; several make this the front end for a fleet.
func NewService(sysmonAddr string) *Service {
	s := &Service{
		sysmonAddr: sysmonAddr,
		sessionLog: NewSessionLogger(500, 100), // Keep last 500 entries, 100 errors
		hostRev:    make(map[string]int64),
		hostSig:    make(map[string]uint64),
		removedAt:  make(map[string]int64),
	}
	for _, addr := range strings.Split(sysmonAddr, ",") {
		addr = strings.TrimSpace(addr)
		if addr == "" {
			continue
		}
		s.daemons = append(s.daemons, &daemon{addr: addr, site: "local"})
	}
	// No address is a real configuration, not a mistake: sysmon-web waits
	// to be dialled by default, and the fleet is empty until the first
	// daemon connects and is adopted into it.
	if len(s.daemons) > 0 {
		s.sysmonAddr = s.daemons[0].addr
	}
	return s
}

// Sites reports the fleet: who is configured, what they call themselves,
// and whether the last poll reached them.
// fleet is a snapshot of the daemon list, safe to range over while a site
// dials in or reconnects.
func (s *Service) fleet() []*daemon {
	s.fleetMu.Lock()
	defer s.fleetMu.Unlock()
	out := make([]*daemon, len(s.daemons))
	copy(out, s.daemons)
	return out
}

func (s *Service) Sites() []models.SiteInfo {
	var out []models.SiteInfo
	for _, d := range s.fleet() {
		d.mu.Lock()
		out = append(out, models.SiteInfo{
			Site:        d.site,
			Description: d.siteDesc,
			Address:     d.addr,
			Inbound:     d.inbound,
			Reachable:   d.lastErr == "",
			LastError:   d.lastErr,
			LastSeen:    d.lastOK,
			Hosts:       len(d.lastHosts),
		})
		d.mu.Unlock()
	}
	return out
}

// hostKey is the stable identity for a host across snapshots.
func hostKey(h *models.HostStatus) string {
	if h.ObjectName != "" {
		return h.ObjectName
	}
	return h.Hostname
}

// hostSignature hashes the fields that represent a host's *state*,
// deliberately excluding everything that ticks without a real change -
// TimeUp/TimeFailed (computed from now()), the per-check timestamps and
// response times, and ALL check counters (down/up/total): sysmond bumps
// them on every single check run (TotalDown counts failed checks, not
// outages), which would mark every host "changed" on every poll and
// void the delta system. Actual transitions are fully captured by
// OverallStatus/StatusColor/LastChangeTime. A steady host thus produces
// an identical signature poll-over-poll and no delta; clients render
// live "up/down for X" locally from LastChangeTime.
func hostSignature(h *models.HostStatus) uint64 {
	w := fnv.New64a()
	fmt.Fprintf(w, "%s\x00%s\x00%s\x00%s\x00%s\x00%t\x00%s\x00%s\x00%t",
		h.ObjectName, h.Hostname, h.OverallStatus, h.StatusColor, h.Contact,
		h.Paused, h.Description, h.IPv4Address, h.Stale)
	if h.LastChangeTime != nil {
		fmt.Fprintf(w, "\x00%d", h.LastChangeTime.Unix())
	}
	for i := range h.Checks {
		c := &h.Checks[i]
		fmt.Fprintf(w, "\x01%s\x00%d\x00%s\x00%s", c.Type, c.Port, c.Status, c.StatusMessage)
	}
	return w.Sum64()
}

// GetSessionLog returns recent session log entries
func (s *Service) GetSessionLog(limit int) []SessionLogEntry {
	return s.sessionLog.GetRecentEntries(limit)
}

// GetSessionErrors returns recent error entries
func (s *Service) GetSessionErrors(limit int) []SessionLogEntry {
	return s.sessionLog.GetRecentErrors(limit)
}

// SysmonResponse represents a parsed response from sysmon daemon
type SysmonResponse struct {
	Code    string // e.g., "333", "403", "444"
	Message string // Full response line
	IsError bool   // true if 403 or 444
}

// readSysmonResponse reads and parses a sysmon response line
// Returns the parsed response and any read error
func readSysmonResponse(reader *bufio.Reader) (*SysmonResponse, error) {
	line, err := reader.ReadString('\n')
	if err != nil {
		return nil, err
	}

	trimmed := strings.TrimSpace(line)

	// Check if it's a numbered response code (3 digits at start)
	if len(trimmed) >= 3 {
		code := trimmed[0:3]
		// All valid sysmon codes are numeric
		if code[0] >= '0' && code[0] <= '9' &&
			code[1] >= '0' && code[1] <= '9' &&
			code[2] >= '0' && code[2] <= '9' {
			return &SysmonResponse{
				Code:    code,
				Message: trimmed,
				IsError: code == "403" || code == "444",
			}, nil
		}
	}

	// Not a numbered code - it's data (like XML)
	return &SysmonResponse{
		Code:    "",
		Message: line, // Keep full line with newline for XML parsing
		IsError: false,
	}, nil
}

// XMLObjectStatus represents the XML structure from SHOWOBJ command
// Maps to send_object_xml() output in srvclient.c
type XMLObjectStatus struct {
	XMLName xml.Name `xml:"ObjectStatus"`
	// ChangeSeq is sysmond's monotonic "this object moved" counter. The
	// highest one seen goes back as CONF's argument next cycle.
	ChangeSeq         uint64 `xml:"ObjectChangeSeq"`
	Object            string `xml:"Object"`
	HostName          string `xml:"HostName"`
	ObjectPort        int    `xml:"ObjectPort"`
	ObjectType        string `xml:"ObjectType"`
	ObjectMessage     string `xml:"ObjectMessage"`
	ObjectNotes       string `xml:"ObjectNotes"`
	ObjectContact     string `xml:"ObjectContact"`
	ObjectGroup       string `xml:"ObjectGroup"`
	ObjectState       int    `xml:"ObjectLastcheckState"`
	ObjectContacted   int    `xml:"ObjectContacted"`
	ObjectContactedAt int64  `xml:"ObjectContactedAt"`
	ObjectContactOnUp int    `xml:"ObjectContactOnUp"`
	TotalChecked      int64  `xml:"ObjectTotalChecked"`
	TotalDown         int64  `xml:"ObjectTotalDown"`
	DownCt            int64  `xml:"ObjectDownCt"`
	UpCt              int64  `xml:"ObjectUpCt"`
	MaxDown           int64  `xml:"ObjectMaxDown"`
	QueueInterval     int64  `xml:"ObjectQueueInterval"`
	SendPings         int    `xml:"ObjectSendPings"`
	MinPings          int    `xml:"ObjectMinPings"`
	Reversed          int    `xml:"ObjectReversed"`
	Queued            int    `xml:"ObjectQueued"`
	LastChecked       int64  `xml:"ObjectLastChecked"`
	CheckStarted      int64  `xml:"ObjectCheckStarted"`
	DeathTime         int64  `xml:"ObjectOutageTime"`
	LastTimeUp        int64  `xml:"ObjectLastTimeUp"`
	UniqueID          string `xml:"ObjectUniqueID"`
	URL               string `xml:"ObjectURL"`
	URLText           string `xml:"ObjectURLText"`
	ExecCmd           string `xml:"ObjectExecCmd"`
	PageMessage       string `xml:"ObjectPageMessage"`

	// Thresholds
	PacketLossThreshold int `xml:"ObjectPacketLossThreshold"`
	RTTThreshold        int `xml:"ObjectRTTThreshold"`
	JitterThreshold     int `xml:"ObjectJitterThreshold"`
	WakeupRetries       int `xml:"ObjectWakeupRetries"`

	// Debug/diagnostic
	TraceEnabled int `xml:"ObjectTraceEnabled"`
	Acked        int `xml:"ObjectAcked"`

	// Next queue time
	NextQueueTime int64 `xml:"ObjectNextQueueTime"`

	// Auth
	AuthUsername string `xml:"ObjectAuthUsername"`
	AuthPassword string `xml:"ObjectAuthPassword"`
	RadiusSecret string `xml:"ObjectRadiusSecret"`
	Header       string `xml:"ObjectHeader"`
	HeaderValue  string `xml:"ObjectHeaderValue"`

	// SNMP
	SNMPCommunity string `xml:"ObjectSNMPCommunity"`
	SNMPOID       string `xml:"ObjectSNMPoid"`
	SNMPType      string `xml:"ObjectSNMPType"`
	SNMPLow       int64  `xml:"ObjectSNMPLowThresh"`
	SNMPHigh      int64  `xml:"ObjectSNMPHighThresh"`
	SNMPExact     int64  `xml:"ObjectSNMPExactThresh"`
	SNMPSysUpTime int64  `xml:"ObjectSNMPObjectSysUpTime"`
	SNMPRate      int64  `xml:"ObjectSNMPRate"`
	SNMPOctets    int    `xml:"ObjectSNMPOctets"`
	SNMPLastResp  int64  `xml:"ObjectSNMPLastResponseTime"`

	// DNS
	DNSQuery     string `xml:"ObjectDNSQuery"`
	DNSRequireAA int    `xml:"ObjectDNSRequireAA"`
	DNSRecursion int    `xml:"ObjectDNSRecursion"`

	// Runtime check state (from queue entry)
	CheckQueuedAt     string `xml:"CheckQueuedAt"`
	CheckLastServiced string `xml:"CheckLastServiced"`
	CheckFD           int    `xml:"CheckFileDescriptor"`
	CheckStartedFlag  int    `xml:"CheckStarted"`
	CheckReturnValue  int    `xml:"CheckReturnValue"`
	CheckWakeupCount  int    `xml:"CheckWakeupCount"`
	CheckWakeupTime   int64  `xml:"CheckLastWakeupTime"`
}

// GetStatus gets the complete sysmon status via TCP protocol
// statusCacheTTL is how long a cached status snapshot is served before a
// request would refetch. The background poller (StartPoller) refreshes
// well within this window, so user/app requests are served from a warm
// cache and never block on the expensive per-host sysmond fetch. The TTL
// is the fallback if the poller stalls or sysmond goes away - after it,
// requests refetch and surface the real error.
const statusCacheTTL = 10 * time.Second

func (s *Service) GetStatus() (*models.SysmonStatus, error) {
	for {
		s.cacheMu.Lock()

		// Cache hit
		if s.cachedStatus != nil && time.Since(s.cacheTime) < statusCacheTTL {
			cached := s.cachedStatus
			s.cacheMu.Unlock()
			return cached, nil
		}

		// Another goroutine is already fetching - wait for it
		if s.fetching {
			done := s.fetchDone
			s.cacheMu.Unlock()
			<-done
			continue // re-check cache
		}

		// We're the one who fetches
		s.fetching = true
		s.fetchDone = make(chan struct{})
		s.cacheMu.Unlock()

		status, err := s.fetchFleet()

		s.cacheMu.Lock()
		var events []HistoryEvent
		if err == nil {
			events = s.storeSnapshotLocked(status)
		}
		hist := s.history
		s.fetching = false
		close(s.fetchDone)
		s.cacheMu.Unlock()

		if hist != nil {
			hist.Append(events)
		}
		if err != nil {
			return nil, err
		}
		return status, nil
	}
}

// Refresh forces a fresh fetch from sysmond and updates the cache,
// regardless of cache age. Single-flighted against GetStatus via the same
// fetching/fetchDone state, so a concurrent caller never triggers a second
// fetch. Used by the background poller to keep the cache warm; a failed
// fetch leaves the previous snapshot in place (the TTL is the backstop).
func (s *Service) Refresh() {
	s.cacheMu.Lock()
	if s.fetching {
		// A fetch is already in progress - that's enough.
		s.cacheMu.Unlock()
		return
	}
	s.fetching = true
	s.fetchDone = make(chan struct{})
	s.cacheMu.Unlock()

	status, err := s.fetchFleet()

	s.cacheMu.Lock()
	var events []HistoryEvent
	if err == nil {
		events = s.storeSnapshotLocked(status)
	}
	hist := s.history
	s.fetching = false
	close(s.fetchDone)
	s.cacheMu.Unlock()

	if hist != nil {
		hist.Append(events)
	}
}

// storeSnapshotLocked installs a freshly fetched snapshot and updates the
// delta bookkeeping. Caller must hold cacheMu. It bumps rev only if some
// host's state signature changed or a host was added/removed, stamping
// each changed host with the new rev, so GetDelta can answer "what
// changed since rev N". It also sets status.Rev.
func (s *Service) storeSnapshotLocked(status *models.SysmonStatus) []HistoryEvent {
	// Diff overall status against the previous snapshot for the history
	// log. Baseline (first snapshot) records nothing.
	var transitions []HistoryEvent
	if s.cachedStatus != nil {
		prev := make(map[string]string, len(s.cachedStatus.Hosts))
		for i := range s.cachedStatus.Hosts {
			h := &s.cachedStatus.Hosts[i]
			prev[hostKey(h)] = h.OverallStatus
		}
		for i := range status.Hosts {
			h := &status.Hosts[i]
			if old, ok := prev[hostKey(h)]; ok && old != h.OverallStatus {
				transitions = append(transitions, HistoryEvent{
					ObjectName:  h.ObjectName,
					Hostname:    h.Hostname,
					Description: h.Description,
					PrevStatus:  old,
					NewStatus:   h.OverallStatus,
				})
			}
		}
	}

	newSig := make(map[string]uint64, len(status.Hosts))
	changed := false
	for i := range status.Hosts {
		name := hostKey(&status.Hosts[i])
		sig := hostSignature(&status.Hosts[i])
		newSig[name] = sig
		if old, ok := s.hostSig[name]; !ok || old != sig {
			changed = true
		}
	}
	var removed []string
	for name := range s.hostSig {
		if _, ok := newSig[name]; !ok {
			removed = append(removed, name)
			changed = true
		}
	}

	if changed {
		s.rev++
		for name, sig := range newSig {
			if old, ok := s.hostSig[name]; !ok || old != sig {
				s.hostRev[name] = s.rev
			}
		}
		for _, name := range removed {
			delete(s.hostRev, name)
			s.removedAt[name] = s.rev
		}
		s.hostSig = newSig
		s.pruneRemovedLocked()
	}

	status.Rev = s.rev
	s.cachedStatus = status
	s.cacheTime = time.Now()
	return transitions
}

// pruneRemovedLocked bounds the removal log. When it overflows we drop the
// oldest entries and raise minDeltaRev so any client older than the
// dropped point is correctly forced into a full resync (we can no longer
// prove we'd report every deletion they missed). Caller holds cacheMu.
func (s *Service) pruneRemovedLocked() {
	if len(s.removedAt) <= maxRemovedTracked {
		return
	}
	// Find the cutoff rev: keep the newest maxRemovedTracked entries.
	revs := make([]int64, 0, len(s.removedAt))
	for _, r := range s.removedAt {
		revs = append(revs, r)
	}
	sort.Slice(revs, func(i, j int) bool { return revs[i] < revs[j] })
	cutoff := revs[len(revs)-maxRemovedTracked]
	for name, r := range s.removedAt {
		if r < cutoff {
			delete(s.removedAt, name)
		}
	}
	if cutoff > s.minDeltaRev {
		s.minDeltaRev = cutoff
	}
}

// FilterSite narrows a status to one site. Used to serve ?site= without
// making the client download the rest of the fleet.
func FilterSite(status *models.SysmonStatus, site string) *models.SysmonStatus {
	if status == nil || site == "" {
		return status
	}
	out := *status
	out.Hosts = make([]models.HostStatus, 0, len(status.Hosts))
	out.Statistics = models.Stats{
		ChecksByType:   make(map[string]int),
		ChecksByStatus: make(map[string]int),
	}
	for _, h := range status.Hosts {
		if h.Site != site {
			continue
		}
		out.Hosts = append(out.Hosts, h)
		out.Statistics.TotalHosts++
		switch h.OverallStatus {
		case "CRITICAL":
			out.Statistics.CriticalHosts++
		case "WARNING":
			out.Statistics.WarningHosts++
		default:
			out.Statistics.HealthyHosts++
		}
		out.Statistics.ChecksByStatus[h.OverallStatus]++
		if len(h.Checks) > 0 && h.Checks[0].Type != "" {
			out.Statistics.ChecksByType[h.Checks[0].Type]++
		}
	}
	for _, di := range status.Daemons {
		if di.Site == site {
			out.Daemon = di
			out.Daemons = []models.DaemonInfo{di}
			break
		}
	}
	return &out
}

// FilterDeltaSite narrows a delta the same way.
//
// The revision stays global and monotonic: a client whose delta comes back
// empty because the change was in a site it does not watch just stores the
// new rev and moves on. Widening the filter is the case that needs care -
// the client has never seen the sites it was excluding - and is handled by
// the caller forcing a full resync.
func FilterDeltaSite(d *models.StatusDelta, site string) *models.StatusDelta {
	if d == nil || site == "" {
		return d
	}
	out := *d
	out.Changed = make([]models.HostStatus, 0, len(d.Changed))
	for _, h := range d.Changed {
		if h.Site == site {
			out.Changed = append(out.Changed, h)
		}
	}
	out.Removed = nil
	for _, name := range d.Removed {
		if s, _ := SplitQualified(name); s == site {
			out.Removed = append(out.Removed, name)
		}
	}
	return &out
}

// GetDelta returns the changes since the client's revision. If the client
// is fresh (since<=0), too far behind (since<minDeltaRev), or somehow
// ahead, it returns a full resync (Full=true, Changed=all hosts). Daemon
// and Statistics are always included (they're small). If nothing changed
// since `since`, Changed/Removed are empty and Rev==since.
func (s *Service) GetDelta(since int64) *models.StatusDelta {
	s.cacheMu.Lock()
	defer s.cacheMu.Unlock()

	// Changed must never marshal as JSON null - strictly-typed clients
	// (kotlinx.serialization, Swift Codable) reject null for a list, which
	// turned every idle delta poll into a decode error on the apps.
	d := &models.StatusDelta{Rev: s.rev, Changed: []models.HostStatus{}}
	cur := s.cachedStatus
	if cur == nil {
		d.Full = true
		return d
	}
	d.Daemon = cur.Daemon
	d.Statistics = cur.Statistics

	if since <= 0 || since < s.minDeltaRev || since > s.rev {
		d.Full = true
		if cur.Hosts != nil {
			d.Changed = cur.Hosts
		}
		return d
	}
	if since == s.rev {
		return d // up to date - nothing changed
	}
	for i := range cur.Hosts {
		if s.hostRev[hostKey(&cur.Hosts[i])] > since {
			d.Changed = append(d.Changed, cur.Hosts[i])
		}
	}
	for name, r := range s.removedAt {
		if r > since {
			d.Removed = append(d.Removed, name)
		}
	}
	return d
}

// StartPoller runs a background goroutine that refreshes the status cache
// every interval, so the expensive per-host sysmond fetch happens off the
// request path and UI/app requests always hit a warm cache. Idempotent -
// only the first call starts a poller. Primes the cache once immediately.
func (s *Service) StartPoller(interval time.Duration) {
	s.pollOnce.Do(func() {
		s.pollStop = make(chan struct{})
		go func() {
			s.Refresh() // prime so the first request is warm
			t := time.NewTicker(interval)
			defer t.Stop()
			for {
				select {
				case <-t.C:
					s.Refresh()
				case <-s.pollStop:
					return
				}
			}
		}()
	})
}

// StopPoller stops the background poller (best-effort; safe to call once).
func (s *Service) StopPoller() {
	if s.pollStop != nil {
		select {
		case <-s.pollStop: // already closed
		default:
			close(s.pollStop)
		}
	}
}

// hostFromXML converts one <ObjectStatus> block into the API model. Shared
// by the bulk CONF path and the per-object SHOWOBJ fallback so the two can
// never drift apart.
func hostFromXML(xmlObj XMLObjectStatus, daemonStart time.Time, site string) (models.HostStatus, string) {
	// Create host status entry
	host := models.HostStatus{
		// One place qualifies, so every store downstream - history,
		// push, delta revisions, layout - inherits the namespace
		// without knowing it exists.
		ObjectName:    Qualify(site, xmlObj.Object),
		LocalName:     xmlObj.Object,
		Site:          site,
		Hostname:      xmlObj.HostName,
		Description:   xmlObj.ObjectMessage,
		IPv4Address:   "",
		OverallStatus: "OK",
		StatusColor:   "green",
		Contact:       xmlObj.ObjectContact,
		DownCount:     xmlObj.DownCt,
		UpCount:       xmlObj.UpCt,
		TotalDown:     xmlObj.TotalDown,
		TotalChecked:  xmlObj.TotalChecked,
		Checks:        []models.CheckResult{},
	}

	// If HostName is an IP address, populate IPv4Address field
	// Otherwise leave it empty (it's a DNS name or hostname)
	if net.ParseIP(xmlObj.HostName) != nil {
		host.IPv4Address = xmlObj.HostName
	}

	// Calculate timing information and last change time
	currentTime := time.Now()

	if xmlObj.ObjectState != 0 {
		// Currently DOWN
		if xmlObj.DeathTime > 0 {
			deathTime := time.Unix(xmlObj.DeathTime, 0)
			host.LastChangeTime = &deathTime
			host.LastOutage = &deathTime
			host.TimeFailed = int64(currentTime.Sub(deathTime).Seconds())
			host.TimeUp = 0
		}
	} else {
		// Currently UP
		if xmlObj.LastTimeUp > 0 {
			lastTimeUp := time.Unix(xmlObj.LastTimeUp, 0)
			host.LastChangeTime = &lastTimeUp
			host.TimeUp = int64(currentTime.Sub(lastTimeUp).Seconds())
			host.TimeFailed = 0
		} else if !daemonStart.IsZero() {
			// sysmond only sets ObjectLastTimeUp after a recovery; a
			// host that has been up since the daemon started reports 0.
			// Fall back to the daemon start time so "up for X" isn't
			// blank for perfectly healthy hosts.
			host.TimeUp = int64(currentTime.Sub(daemonStart).Seconds())
			host.TimeFailed = 0
		}
		// LastOutage is when it last went down (before coming back up)
		if xmlObj.DeathTime > 0 {
			lastOutage := time.Unix(xmlObj.DeathTime, 0)
			host.LastOutage = &lastOutage
		}
	}

	// Status logic:
	// - ObjectState == 0: UP/OK (green)
	// - ObjectState != 0 && ObjectContacted == 0: DOWN but not alerted yet (yellow/WARNING)
	// - ObjectState != 0 && ObjectContacted == 1: DOWN and alerted (red/CRITICAL)
	if xmlObj.ObjectState != 0 {
		if xmlObj.ObjectContacted == 0 {
			// Down but not alerted yet - WARNING (yellow)
			host.OverallStatus = "WARNING"
			host.StatusColor = "yellow"
		} else {
			// Down and already alerted - CRITICAL (red)
			host.OverallStatus = "CRITICAL"
			host.StatusColor = "red"
		}
	}

	// Add check details
	// Set last check time to current time since XML doesn't provide per-check timestamps
	// The actual last check is very recent (within checkinterval seconds)
	check := models.CheckResult{
		Type:          xmlObj.ObjectType,
		Port:          xmlObj.ObjectPort,
		Status:        host.OverallStatus,
		LastCheckTime: time.Now(),
		StatusMessage: xmlObj.ObjectMessage,
	}
	host.Checks = append(host.Checks, check)

	if xmlObj.ObjectContact != "" {
		host.Contact = xmlObj.ObjectContact
	}

	return host, xmlObj.ObjectType
}

// accumulateHost folds one host into the run's statistics.
func accumulateHost(status *models.SysmonStatus, host models.HostStatus, checkType string, hostsUp, hostsDown *int) {
	switch host.OverallStatus {
	case "WARNING":
		status.Statistics.WarningHosts++
	case "CRITICAL":
		*hostsDown++
	default:
		*hostsUp++
	}
	if checkType != "" {
		status.Statistics.ChecksByType[checkType]++
	}
	status.Statistics.ChecksByStatus[host.OverallStatus]++
	status.Hosts = append(status.Hosts, host)
}

// fetchAllObjectsXML pulls every object's status in one command.
//
// CONF is a bulk send_object_xml() walk - byte for byte what SHOWOBJ
// returns, just for all of them - so this is one round trip instead of
// one per object. On an 800-object config that is the difference between
// a poll taking half a minute and taking a second.
//
// It is privileged, so it needs sysmond's authkey. Returns ok=false (not
// an error) whenever the bulk path is unavailable - no key, a daemon that
// refuses, a daemon too old to know the command - and the caller falls
// back to asking object by object.
func (s *Service) fetchAllObjectsXML(d *daemon, conn net.Conn, reader *bufio.Reader) (objs []XMLObjectStatus, ok bool) {
	// A daemon that dialled in is already authenticated, and by something
	// stronger than a shared key: it verified our certificate before
	// sending a byte, and we verified its per-box token before answering.
	// Asking it to AUTH would prove less, and would put the shared authkey
	// back in the middle of an arrangement built to retire it.
	d.mu.Lock()
	inbound := d.inbound
	d.mu.Unlock()

	if !inbound {
		key := s.authKey()
		if key == "" {
			// Worth saying out loud: without it every poll walks the
			// objects one at a time, which is the difference between 0.1s
			// and 36s on a large config, and the silence made that hard to
			// notice.
			s.sessionLog.Log("CONF", "", true,
				"no sysmond authkey available - falling back to per-object fetch")
			return nil, false
		}
		if err := authenticate(conn, reader, key); err != nil {
			s.sessionLog.Log("AUTH", "bulk fetch unavailable", true, err.Error())
			return nil, false
		}
	}

	// Ask only for what moved since last time. Periodically - and on the
	// first cycle - ask for everything anyway, so counters that tick
	// without counting as a change do not drift.
	d.mu.Lock()
	since := d.confSeq
	if d.hostCache == nil || time.Since(d.fullResyncAt) > fullResyncEvery {
		since = 0
	}
	d.mu.Unlock()

	cmd := "CONF\n"
	if since > 0 {
		cmd = fmt.Sprintf("CONF %d\n", since)
	}
	if _, err := conn.Write([]byte(cmd)); err != nil {
		return nil, false
	}

	var block strings.Builder
	var daemonSeq, daemonTotal uint64
	for {
		line, err := reader.ReadString('\n')
		trimmed := strings.TrimSpace(line)

		// "444 Permission Denied" / "444 - Unk": no bulk path here.
		if strings.HasPrefix(trimmed, "444") || strings.HasPrefix(trimmed, "403") {
			s.sessionLog.Log("CONF", trimmed, true, "falling back to per-object fetch")
			return nil, false
		}
		if strings.HasPrefix(trimmed, "333") {
			daemonSeq = parseSeqField(trimmed, 1)
			daemonTotal = parseSeqField(trimmed, 3)
			break // end of dump
		}

		block.WriteString(line)
		if strings.Contains(line, "</ObjectStatus>") {
			var xmlObj XMLObjectStatus
			if perr := xml.Unmarshal([]byte(block.String()), &xmlObj); perr != nil {
				// One unreadable object should not cost us the whole
				// poll - the per-object path would have skipped it too.
				s.sessionLog.Log("CONF", block.String(), true, perr.Error())
			} else {
				objs = append(objs, xmlObj)
			}
			block.Reset()
			// Keep the clock honest against a slow dump rather than
			// holding one deadline over the whole transfer.
			conn.SetDeadline(time.Now().Add(30 * time.Second))
		}

		if err != nil {
			s.sessionLog.Log("CONF", "", true, fmt.Sprintf("read error after %d objects: %v", len(objs), err))
			return nil, false
		}
	}

	// Merge into what we already hold. An incremental reply carrying
	// nothing is the normal case on a quiet network, and is a success.
	d.mu.Lock()
	if since == 0 || d.hostCache == nil {
		d.hostCache = make(map[string]XMLObjectStatus, len(objs))
		d.fullResyncAt = time.Now()
	}
	if daemonSeq < d.confSeq {
		// The daemon restarted: its counter went backwards, so everything
		// we hold is from a previous life.
		s.sessionLog.Log("CONF", "sysmond sequence went backwards - resyncing", false, "")
		d.hostCache = make(map[string]XMLObjectStatus, len(objs))
		d.fullResyncAt = time.Time{}
	}
	for _, o := range objs {
		d.hostCache[o.Object] = o
	}

	// An incremental reply can say what changed but not what is gone: a
	// deleted object simply stops being sent, so a merge keeps it forever.
	// The daemon's own count is what catches that - if it does not match
	// what we hold, the cache has ghosts in it and the next cycle asks for
	// everything. (Older daemons send no count; 0 means "did not say".)
	if daemonTotal > 0 && uint64(len(d.hostCache)) != daemonTotal {
		s.sessionLog.Log("CONF",
			fmt.Sprintf("holding %d objects, daemon has %d - resyncing",
				len(d.hostCache), daemonTotal), false, "")
		d.fullResyncAt = time.Time{}
	}
	d.confSeq = daemonSeq
	merged := make([]XMLObjectStatus, 0, len(d.hostCache))
	for _, o := range d.hostCache {
		merged = append(merged, o)
	}
	d.mu.Unlock()

	if len(merged) == 0 {
		return nil, false
	}
	if since > 0 {
		s.sessionLog.Log(fmt.Sprintf("CONF %d", since),
			fmt.Sprintf("%d changed of %d held (seq %d)", len(objs), len(merged), daemonSeq), false, "")
	} else {
		s.sessionLog.Log("CONF", fmt.Sprintf("Retrieved %d objects in one command", len(objs)), false, "")
	}
	return merged, true
}

// parseSeqField pulls field n out of a "333 a b c" terminator.
func parseSeqField(line string, n int) uint64 {
	fields := strings.Fields(line)
	if n >= len(fields) {
		return 0
	}
	v, err := strconv.ParseUint(fields[n], 10, 64)
	if err != nil {
		return 0
	}
	return v
}

// sortHostsByUrgency puts what is broken at the top: CRITICAL, then
// WARNING, then OK, alphabetical within each.
func sortHostsByUrgency(hosts []models.HostStatus) {
	sort.SliceStable(hosts, func(i, j int) bool {
		hostI := hosts[i]
		hostJ := hosts[j]

		// Define priority: CRITICAL=0, WARNING=1, OK=2
		priorityI := 2 // OK
		if hostI.OverallStatus == "CRITICAL" {
			priorityI = 0
		} else if hostI.OverallStatus == "WARNING" {
			priorityI = 1
		}

		priorityJ := 2 // OK
		if hostJ.OverallStatus == "CRITICAL" {
			priorityJ = 0
		} else if hostJ.OverallStatus == "WARNING" {
			priorityJ = 1
		}

		// Sort by priority first
		if priorityI != priorityJ {
			return priorityI < priorityJ
		}

		// Within same priority, sort alphabetically by hostname
		return hostI.Hostname < hostJ.Hostname
	})
}

// fetchFleet polls every daemon and merges them into one view.
//
// Boxes are polled concurrently, because a fleet's poll cycle should be as
// slow as its slowest member rather than the sum of all of them. One
// unreachable daemon is recorded against that daemon and does not fail the
// cycle - the rest of the fleet is still worth showing, and a site that
// has gone dark is exactly what the operator needs to see.
func (s *Service) fetchFleet() (*models.SysmonStatus, error) {
	type result struct {
		status *models.SysmonStatus
		err    error
	}

	fleet := s.fleet()
	results := make([]result, len(fleet))
	var wg sync.WaitGroup
	for i, d := range fleet {
		wg.Add(1)
		go func(i int, d *daemon) {
			defer wg.Done()
			st, err := s.fetchStatus(d)
			results[i] = result{st, err}

			d.mu.Lock()
			if err != nil {
				d.lastErr = err.Error()
			} else {
				d.lastErr = ""
				d.lastOK = time.Now()
				d.info = st.Daemon
				d.lastHosts = st.Hosts
			}
			d.mu.Unlock()
		}(i, d)
	}
	wg.Wait()

	merged := &models.SysmonStatus{
		Hosts: []models.HostStatus{},
		Statistics: models.Stats{
			ChecksByType:   make(map[string]int),
			ChecksByStatus: make(map[string]int),
		},
	}

	reached := 0
	var firstErr error
	var dark []*daemon
	for i, r := range results {
		if r.err != nil {
			if firstErr == nil {
				firstErr = r.err
			}
			dark = append(dark, fleet[i])
			continue
		}
		reached++
		merged.Daemons = append(merged.Daemons, r.status.Daemon)
		merged.Hosts = append(merged.Hosts, r.status.Hosts...)
		merged.Statistics.TotalHosts += r.status.Statistics.TotalHosts
		merged.Statistics.HealthyHosts += r.status.Statistics.HealthyHosts
		merged.Statistics.WarningHosts += r.status.Statistics.WarningHosts
		merged.Statistics.CriticalHosts += r.status.Statistics.CriticalHosts
		merged.Statistics.TotalChecks += r.status.Statistics.TotalChecks
		for k, v := range r.status.Statistics.ChecksByType {
			merged.Statistics.ChecksByType[k] += v
		}
		for k, v := range r.status.Statistics.ChecksByStatus {
			merged.Statistics.ChecksByStatus[k] += v
		}
	}

	// An empty fleet is not a failure. Daemons dial in, so a freshly
	// installed sysmon-web has none until the first box is given a token
	// and started - and reporting that as a service error puts a red
	// banner on every page of a system that is working exactly as
	// intended. There are no hosts because there are no boxes yet.
	if len(fleet) == 0 {
		merged.Rev = 0
		return merged, nil
	}

	// Daemons are configured and not one answered: that is a real failure,
	// and the caller's error handling should see it.
	if reached == 0 {
		if firstErr == nil {
			firstErr = fmt.Errorf("no sysmond answered")
		}
		return nil, firstErr
	}

	// A site that did not answer keeps its hosts, flagged stale.
	//
	// Dropping them instead would report them as *removed* in the delta:
	// every client deletes them, the map loses a whole region, and when
	// the site comes back they are all re-added - a rev bump per host in
	// both directions, fleet-wide, for a link that blipped. Worse, the
	// operator would see a site disappear rather than see that it has
	// gone dark, which is the one thing they need to know.
	for _, d := range dark {
		hosts := d.staleHosts()
		for _, h := range hosts {
			merged.Statistics.TotalHosts++
			merged.Statistics.TotalChecks += len(h.Checks)
			for _, c := range h.Checks {
				merged.Statistics.ChecksByType[c.Type]++
			}
			merged.Statistics.ChecksByStatus[h.OverallStatus]++
			switch h.OverallStatus {
			case "WARNING":
				merged.Statistics.WarningHosts++
			case "CRITICAL":
				merged.Statistics.CriticalHosts++
			default:
				merged.Statistics.HealthyHosts++
			}
			merged.Hosts = append(merged.Hosts, h)
		}
	}

	// The primary's daemon info is what a single-box client reads.
	if len(merged.Daemons) > 0 {
		merged.Daemon = merged.Daemons[0]
	}
	sortHostsByUrgency(merged.Hosts)
	return merged, nil
}

// staleHosts rebuilds this daemon's last known hosts, marked stale.
//
// It is the last thing the site said before it stopped answering. Nothing
// here is current - which is exactly what the flag says - but it is far
// more useful than an empty space where a site used to be.
func (d *daemon) staleHosts() []models.HostStatus {
	d.mu.Lock()
	defer d.mu.Unlock()

	if len(d.lastHosts) == 0 {
		return nil // never heard from it; there is nothing to keep
	}

	since := d.lastOK
	out := make([]models.HostStatus, len(d.lastHosts))
	copy(out, d.lastHosts)
	for i := range out {
		out[i].Stale = true
		if !since.IsZero() {
			when := since
			out[i].StaleSince = &when
		}
	}
	return out
}

// fetchSite asks the daemon for its identity. Failure is not an error:
// "local" is the right answer for a daemon that has never been told it is
// part of a fleet.
func fetchSite(conn net.Conn, reader *bufio.Reader) (name, desc string) {
	name = "local"

	if _, err := conn.Write([]byte("SITE\n")); err != nil {
		return name, ""
	}
	for {
		line, err := reader.ReadString('\n')
		trimmed := strings.TrimSpace(line)

		if strings.HasPrefix(trimmed, "444") || strings.HasPrefix(trimmed, "403") {
			return name, ""
		}
		if strings.HasPrefix(trimmed, "333") {
			return name, desc
		}
		if v, ok := xmlField(trimmed, "SiteName"); ok && v != "" {
			name = v
		}
		if v, ok := xmlField(trimmed, "SiteDescription"); ok {
			desc = v
		}
		if err != nil {
			return name, desc
		}
	}
}

// xmlField pulls the text out of a one-line <Tag>text</Tag>.
func xmlField(line, tag string) (string, bool) {
	open, close := "<"+tag+">", "</"+tag+">"
	if !strings.HasPrefix(line, open) || !strings.HasSuffix(line, close) {
		return "", false
	}
	return line[len(open) : len(line)-len(close)], true
}

// Qualify builds the fleet-wide key for an object.
func Qualify(site, object string) string {
	if site == "" || site == "local" {
		return object
	}
	return site + ":" + object
}

// SplitQualified separates a fleet-wide key back into its parts. A name
// with no site is returned as-is, which is what a single-box install and
// every pre-namespace stored key look like.
func SplitQualified(name string) (site, object string) {
	if i := strings.IndexByte(name, ':'); i >= 0 {
		return name[:i], name[i+1:]
	}
	return "", name
}

// connection returns the socket to talk to this daemon on: the live one it
// dialled in with, or a fresh dial.
func (d *daemon) connection() (net.Conn, *bufio.Reader, bool, error) {
	d.mu.Lock()
	inbound, conn, reader, addr := d.inbound, d.conn, d.reader, d.addr
	d.mu.Unlock()

	if inbound {
		if conn == nil {
			return nil, nil, true, fmt.Errorf("site %s is not connected", d.site)
		}
		return conn, reader, true, nil
	}

	c, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		return nil, nil, false, fmt.Errorf("failed to connect to sysmon at %s: %w (is sysmond running?)", addr, err)
	}
	return c, nil, false, nil
}

// dropConnection closes a dialled-in link so the daemon reconnects.
func (d *daemon) dropConnection() {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.conn != nil {
		d.conn.Close()
		d.conn = nil
		d.reader = nil
	}
}

func (s *Service) fetchStatus(d *daemon) (status *models.SysmonStatus, err error) {
	// Connect to sysmon daemon
	// A daemon that dialled us keeps its connection open; one we dial gets
	// a fresh socket per cycle. Either way what follows is the same
	// conversation.
	conn, reader, inbound, err := d.connection()
	if err != nil {
		return nil, err
	}

	// Per-chunk, not per-fetch: a hung daemon is still caught in seconds,
	// but a big config walking object by object is not cut off halfway.
	// (30s was less than an 800-object walk takes, so the fetch used to
	// time out on exactly the configs that most needed it.)
	conn.SetDeadline(time.Now().Add(30 * time.Second))

	if inbound {
		// One socket, two users. A config delivery on a dialled-in
		// daemon has to have the connection to itself - interleaving a
		// multi-megabyte CONFIG-PUT with a status poll on the same
		// socket would put both halves' replies in the wrong reader.
		d.confMu.Lock()
		defer d.confMu.Unlock()

		// A conversation that breaks means the link is broken: drop it
		// and let the daemon dial back in with clean sequence numbers.
		defer func() {
			if err != nil {
				d.dropConnection()
			}
		}()
	} else {
		defer conn.Close()
		reader = bufio.NewReader(conn)

		// Read welcome banner first
		if err = readWelcomeBanner(reader); err != nil {
			return nil, err
		}
	}

	// Get daemon information before entering XML mode
	daemonInfo := models.DaemonInfo{
		CurrentTime: time.Now(),
	}

	// Get version with VERS command
	_, err = conn.Write([]byte("VERS\n"))
	if err != nil {
		return nil, fmt.Errorf("failed to send VERS command: %w", err)
	}
	versResp, err := reader.ReadString('\n')
	if err != nil {
		return nil, fmt.Errorf("failed to read VERS response: %w", err)
	}
	daemonInfo.Version = strings.TrimSpace(versResp)
	s.sessionLog.Log("VERS", daemonInfo.Version, false, "")

	// Get uptime with UPTIME command
	_, err = conn.Write([]byte("UPTIME\n"))
	if err != nil {
		return nil, fmt.Errorf("failed to send UPTIME command: %w", err)
	}
	uptimeResp, err := reader.ReadString('\n')
	if err != nil {
		return nil, fmt.Errorf("failed to read UPTIME response: %w", err)
	}
	uptimeStr := strings.TrimSpace(uptimeResp)
	s.sessionLog.Log("UPTIME", uptimeStr, false, "")

	// Parse uptime string like "Uptime = 2d 5h 30m 15s" or similar
	// Extract seconds from the uptime string
	uptime, startTime := parseUptimeString(uptimeStr, daemonInfo.CurrentTime)
	daemonInfo.Uptime = uptime
	daemonInfo.StartTime = startTime

	// Step 1: Enable XML mode
	_, err = conn.Write([]byte("MODE xml\n"))
	if err != nil {
		return nil, fmt.Errorf("failed to send MODE xml command: %w", err)
	}

	// Read response: expect "333 xml enabled"
	resp, err := readSysmonResponse(reader)
	if err != nil {
		return nil, fmt.Errorf("failed to read MODE xml response: %w", err)
	}
	if resp.IsError || resp.Code != "333" {
		return nil, fmt.Errorf("MODE xml failed: %s", resp.Message)
	}
	s.sessionLog.Log("MODE xml", resp.Message, false, "")

	// Who is this daemon? The answer becomes the first half of every
	// object name we store, so it has to be known before any object is
	// built. An older daemon that does not know SITE reports "local",
	// which is exactly what a single-box install wants anyway.
	daemonInfo.Site, daemonInfo.SiteDesc = fetchSite(conn, reader)
	d.mu.Lock()
	d.site, d.siteDesc = daemonInfo.Site, daemonInfo.SiteDesc
	d.mu.Unlock()

	// Step 2: Get list of ALL objects with STATAL command
	// CRITICAL: Use STATAL (not STATO or STAT) because:
	// - STATAL returns ALL hosts (both up and down)
	// - STATO only returns hosts with errors (lastcheck != 0)
	// - STATAL returns unique_name (the object identifier) like STATO
	// - STAT returns hostname:type:port:... where hostname != unique_name
	// - SHOWOBJ searches by unique_name, so using STAT causes 403 errors
	_, err = conn.Write([]byte("STATAL\n"))
	if err != nil {
		return nil, fmt.Errorf("failed to send STATAL command: %w", err)
	}

	// Read object names from STATAL response
	objectNames := []string{}
	daemonPaused := false
	for {
		resp, err := readSysmonResponse(reader)
		if err != nil {
			return nil, fmt.Errorf("error reading STATAL response: %w", err)
		}

		if resp.Code != "" {
			if resp.IsError {
				return nil, fmt.Errorf("STATAL command failed: %s", resp.Message)
			}
			if resp.Code == "333" {
				// "333 Paused Currently" or "333 Not currently Paused"
				if strings.Contains(resp.Message, "Paused Currently") {
					daemonPaused = true
				}
				break
			}
		}

		objectName := strings.TrimSpace(resp.Message)
		if objectName != "" {
			objectNames = append(objectNames, objectName)
		}
	}
	s.sessionLog.Log("STATAL", fmt.Sprintf("Retrieved %d objects (all hosts)", len(objectNames)), false, "")

	// Step 3: Get detailed XML for each object with SHOWOBJ
	daemonInfo.Paused = daemonPaused
	status = &models.SysmonStatus{
		Daemon: daemonInfo,
		Hosts:  []models.HostStatus{},
		Statistics: models.Stats{
			ChecksByType:   make(map[string]int),
			ChecksByStatus: make(map[string]int),
		},
	}

	hostsUp := 0
	hostsDown := 0
	debugXMLSamples := []map[string]string{} // Collect first few XML samples for debugging
	allResponses := []ResponseCapture{}      // Capture ALL protocol responses

	// Capture MODE xml response
	allResponses = append(allResponses, ResponseCapture{
		Command:  "MODE xml",
		Response: resp.Message,
		Parsed:   resp.Code == "333",
	})

	// One command for everything, when the daemon will give it to us.
	bulkObjs, bulkOK := s.fetchAllObjectsXML(d, conn, reader)
	if bulkOK {
		// Same connection, already authenticated: ask for the traps that
		// arrived since last cycle, and what config the box is running,
		// while we are here. Both are one line when nothing changed, and
		// asking every cycle is what makes "somebody edited this box"
		// visible in seconds rather than whenever someone looks.
		s.fetchTraps(d, conn, reader)
		s.fetchConfigGen(d, conn, reader)
	}
	if bulkOK {
		objectNames = objectNames[:0]
		for _, xmlObj := range bulkObjs {
			host, checkType := hostFromXML(xmlObj, daemonInfo.StartTime, daemonInfo.Site)
			accumulateHost(status, host, checkType, &hostsUp, &hostsDown)
			objectNames = append(objectNames, xmlObj.Object)
		}
	}

	for _, objName := range objectNames {
		if bulkOK {
			break // already have every object from the one command
		}
		// Each object gets its own slice of time. One deadline for the
		// whole walk would fire on any config big enough to need it.
		conn.SetDeadline(time.Now().Add(30 * time.Second))
		// Send SHOWOBJ command
		_, err = conn.Write([]byte(fmt.Sprintf("SHOWOBJ %s\n", objName)))
		if err != nil {
			continue // Skip this object
		}

		// Read first line using helper to check if it's an error or XML
		resp, err := readSysmonResponse(reader)
		if err != nil {
			errMsg := fmt.Sprintf("Error reading first line for %s: %v", objName, err)
			s.sessionLog.Log(fmt.Sprintf("SHOWOBJ %s", objName), "", true, errMsg)

			// Capture the failed response
			capture := ResponseCapture{
				Command:  fmt.Sprintf("SHOWOBJ %s", objName),
				Response: "",
				Parsed:   false,
				Error:    err.Error(),
			}
			allResponses = append(allResponses, capture)

			return nil, &XMLParseError{
				Message:      fmt.Sprintf("Timeout reading response for %s: %v", objName, err),
				ObjectName:   objName,
				RawXML:       "",
				AllSamples:   debugXMLSamples,
				AllResponses: allResponses,
			}
		}

		// Check if response is an error code (403, 444)
		if resp.IsError {
			// Daemon returned an error (object not found, permission denied, etc.)
			s.sessionLog.Log(fmt.Sprintf("SHOWOBJ %s", objName), resp.Message, true, resp.Message)

			// Capture the error response
			capture := ResponseCapture{
				Command:  fmt.Sprintf("SHOWOBJ %s", objName),
				Response: resp.Message,
				Parsed:   false,
				Error:    resp.Message,
			}
			allResponses = append(allResponses, capture)

			// Skip this object and continue with others
			continue
		}

		// It's XML - read remaining lines until </ObjectStatus>
		xmlData := resp.Message
		readErr := error(nil)
		for {
			line, err := reader.ReadString('\n')

			// IMPORTANT: Process line FIRST, even if err != nil
			// ReadString() can return both data AND error (e.g., EOF) on same call
			xmlData += line

			// Check for terminator
			if strings.Contains(line, "</ObjectStatus>") {
				break // Success! Complete XML received
			}

			// THEN check for error (after processing line)
			if err != nil {
				// Save error for reporting
				readErr = err
				s.sessionLog.Log(fmt.Sprintf("SHOWOBJ %s", objName), xmlData, true, fmt.Sprintf("Error reading line: %v", err))
				break
			}
		}

		// If read error (timeout, connection closed), return immediately with partial data
		if readErr != nil {
			// Capture the failed response
			capture := ResponseCapture{
				Command:  fmt.Sprintf("SHOWOBJ %s", objName),
				Response: xmlData,
				Parsed:   false,
				Error:    readErr.Error(),
			}
			allResponses = append(allResponses, capture)

			return nil, &XMLParseError{
				Message:      fmt.Sprintf("Timeout or connection error reading XML for %s: %v", objName, readErr),
				ObjectName:   objName,
				RawXML:       xmlData,
				AllSamples:   debugXMLSamples,
				AllResponses: allResponses,
			}
		}

		// Collect XML samples for debugging (first 3 objects)
		if len(debugXMLSamples) < 3 {
			debugXMLSamples = append(debugXMLSamples, map[string]string{
				"object": objName,
				"xml":    xmlData,
			})
		}

		// Parse XML
		var xmlObj XMLObjectStatus
		parseErr := xml.Unmarshal([]byte(xmlData), &xmlObj)

		// Capture this response
		capture := ResponseCapture{
			Command:  fmt.Sprintf("SHOWOBJ %s", objName),
			Response: xmlData,
			Parsed:   parseErr == nil,
		}
		if parseErr != nil {
			capture.Error = parseErr.Error()
		}
		allResponses = append(allResponses, capture)

		// If parse failed, return error with ALL captured data
		if parseErr != nil {
			return nil, &XMLParseError{
				Message:      fmt.Sprintf("Failed to parse XML for object %s: %v", objName, parseErr),
				ObjectName:   objName,
				RawXML:       xmlData,
				AllSamples:   debugXMLSamples,
				AllResponses: allResponses,
			}
		}

		host, checkType := hostFromXML(xmlObj, daemonInfo.StartTime, daemonInfo.Site)
		accumulateHost(status, host, checkType, &hostsUp, &hostsDown)
	}

	// Sort hosts: CRITICAL first, then WARNING, then OK
	// Within each status level, sort alphabetically by hostname
	sortHostsByUrgency(status.Hosts)

	// Fill in statistics
	status.Statistics.TotalHosts = len(objectNames)
	status.Statistics.HealthyHosts = hostsUp
	status.Statistics.CriticalHosts = hostsDown
	// WarningHosts and ChecksByType/ChecksByStatus are incremented in the loop above

	// Send QUIT to close connection cleanly - but only on a socket we
	// dialled. A daemon that dialled us keeps this connection for its
	// whole life, and QUIT would make it hang up and reconnect on every
	// single cycle.
	if !inbound {
		if _, werr := conn.Write([]byte("QUIT\n")); werr != nil {
			// Log but don't fail - connection is closing anyway
			s.sessionLog.Log("QUIT", "", true, fmt.Sprintf("Error sending QUIT: %v", werr))
		}
	}

	// Log successful completion
	s.sessionLog.Log("GetStatus", fmt.Sprintf("Complete: %d total, %d up, %d down, %d warnings",
		len(objectNames), hostsUp, hostsDown, status.Statistics.WarningHosts), false, "")

	return status, nil
}

// GetHostStatus gets status for a specific host
func (s *Service) GetHostStatus(name string) (*models.HostStatus, error) {
	status, err := s.GetStatus()
	if err != nil {
		return nil, err
	}

	for _, host := range status.Hosts {
		if host.ObjectName == name || host.Hostname == name {
			return &host, nil
		}
	}

	return nil, fmt.Errorf("host %s not found", name)
}

// GetTrapsBySource gets traps from a specific source
func (s *Service) GetTrapsBySource(sourceIP string, authKey string) ([]models.Trap, error) {
	traps, err := s.GetTraps(authKey)
	if err != nil {
		return nil, err
	}

	filtered := []models.Trap{}
	for _, trap := range traps.RecentTraps {
		if trap.SourceIP == sourceIP {
			filtered = append(filtered, trap)
		}
	}

	return filtered, nil
}

// GetStatistics gets monitoring statistics
func (s *Service) GetStatistics() (*models.Stats, error) {
	status, err := s.GetStatus()
	if err != nil {
		return nil, err
	}

	return &status.Statistics, nil
}

// GetAlerts gets active alerts (hosts/checks in WARNING or CRITICAL state)
func (s *Service) GetAlerts() ([]models.HostStatus, error) {
	status, err := s.GetStatus()
	if err != nil {
		return nil, err
	}

	alerts := []models.HostStatus{}
	for _, host := range status.Hosts {
		if host.OverallStatus == "WARNING" || host.OverallStatus == "CRITICAL" {
			alerts = append(alerts, host)
		}
	}

	return alerts, nil
}

// readWelcomeBanner reads and validates the daemon's welcome banner
// Sysmon sends "111 - v1.0 Ready - Welcome" on connection
func readWelcomeBanner(reader *bufio.Reader) error {
	welcome, err := reader.ReadString('\n')
	if err != nil {
		return fmt.Errorf("failed to read welcome banner: %w", err)
	}

	welcome = strings.TrimSpace(welcome)
	if !strings.HasPrefix(welcome, "111") {
		return fmt.Errorf("unexpected welcome banner: %s", welcome)
	}

	return nil
}

// parseUptimeString parses the UPTIME response and returns uptime in seconds and start time
// Expected format: "Uptime = 123456 secs" or similar time format
func parseUptimeString(uptimeStr string, currentTime time.Time) (int64, time.Time) {
	// Remove "Uptime = " prefix if present
	uptimeStr = strings.TrimPrefix(uptimeStr, "Uptime = ")
	uptimeStr = strings.TrimSpace(uptimeStr)

	// Try to parse various formats
	// Format 1: "123456 secs" or "123456"
	if strings.Contains(uptimeStr, "sec") {
		parts := strings.Fields(uptimeStr)
		if len(parts) > 0 {
			if secs, err := strconv.ParseInt(parts[0], 10, 64); err == nil {
				startTime := currentTime.Add(-time.Duration(secs) * time.Second)
				return secs, startTime
			}
		}
	}

	// Format 2: Try parsing as duration string like "2d 5h 30m"
	// This is more complex, let's try a simple regex-based approach
	var totalSeconds int64

	// Parse days
	if matches := regexp.MustCompile(`(\d+)d`).FindStringSubmatch(uptimeStr); len(matches) > 1 {
		if days, err := strconv.ParseInt(matches[1], 10, 64); err == nil {
			totalSeconds += days * 86400
		}
	}

	// Parse hours
	if matches := regexp.MustCompile(`(\d+)h`).FindStringSubmatch(uptimeStr); len(matches) > 1 {
		if hours, err := strconv.ParseInt(matches[1], 10, 64); err == nil {
			totalSeconds += hours * 3600
		}
	}

	// Parse minutes
	if matches := regexp.MustCompile(`(\d+)m`).FindStringSubmatch(uptimeStr); len(matches) > 1 {
		if mins, err := strconv.ParseInt(matches[1], 10, 64); err == nil {
			totalSeconds += mins * 60
		}
	}

	// Parse seconds
	if matches := regexp.MustCompile(`(\d+)s`).FindStringSubmatch(uptimeStr); len(matches) > 1 {
		if secs, err := strconv.ParseInt(matches[1], 10, 64); err == nil {
			totalSeconds += secs
		}
	}

	if totalSeconds > 0 {
		startTime := currentTime.Add(-time.Duration(totalSeconds) * time.Second)
		return totalSeconds, startTime
	}

	// Fallback: return 0 if we couldn't parse
	return 0, currentTime
}

// authenticate sends AUTH command to sysmon if authKey is provided
// Returns error if authentication fails
func authenticate(conn net.Conn, reader *bufio.Reader, authKey string) error {
	if authKey == "" {
		return nil // No auth key provided, continue without auth
	}

	// Send AUTH command
	_, err := conn.Write([]byte(fmt.Sprintf("AUTH %s\n", authKey)))
	if err != nil {
		return fmt.Errorf("failed to send AUTH command: %w", err)
	}

	response, err := reader.ReadString('\n')
	if err != nil {
		return fmt.Errorf("failed to read AUTH response: %w", err)
	}

	if strings.Contains(response, "333") {
		return nil // Authentication successful
	}

	return fmt.Errorf("authentication failed - invalid auth key")
}

// AckHost acknowledges an alert for a specific host
func (s *Service) AckHost(hostname string, authKey string) error {
	// The caller holds a fleet-wide "site:object" key; the daemon that
	// owns it has never heard of the site half.
	_, hostname = SplitQualified(hostname)
	hostname = sanitizeCmd(hostname)
	// Connect to sysmon daemon
	conn, err := net.DialTimeout("tcp", s.sysmonAddr, 5*time.Second)
	if err != nil {
		return fmt.Errorf("failed to connect to sysmon: %w", err)
	}
	defer conn.Close()

	conn.SetDeadline(time.Now().Add(5 * time.Second))
	reader := bufio.NewReader(conn)

	// Read welcome banner first
	if err := readWelcomeBanner(reader); err != nil {
		return err
	}

	// Authenticate if auth key provided
	if err := authenticate(conn, reader, authKey); err != nil {
		return err
	}

	// Enable XML mode
	_, err = conn.Write([]byte("MODE xml\n"))
	if err != nil {
		return fmt.Errorf("failed to send MODE xml: %w", err)
	}

	response, err := reader.ReadString('\n')
	if err != nil {
		return fmt.Errorf("failed to read MODE xml response: %w", err)
	}
	if !strings.Contains(response, "333") {
		return fmt.Errorf("MODE xml failed: %s", response)
	}

	// Send ACK command
	_, err = conn.Write([]byte(fmt.Sprintf("ACK %s\n", hostname)))
	if err != nil {
		return fmt.Errorf("failed to send ACK command: %w", err)
	}

	response, err = reader.ReadString('\n')
	if err != nil {
		return fmt.Errorf("failed to read ACK response: %w", err)
	}

	if strings.Contains(response, "333") {
		return nil
	} else if strings.Contains(response, "403") {
		return fmt.Errorf("host not found or permission denied")
	} else if strings.Contains(response, "444") {
		return fmt.Errorf("permission denied - authentication required")
	}

	return fmt.Errorf("ACK failed: %s", response)
}

// UpdateHostStatus updates a host with a status note
func (s *Service) UpdateHostStatus(hostname string, note string, authKey string) error {
	// The caller holds a fleet-wide "site:object" key; the daemon that
	// owns it has never heard of the site half.
	_, hostname = SplitQualified(hostname)
	hostname = sanitizeCmd(hostname)
	note = sanitizeCmd(note)
	// Connect to sysmon daemon
	conn, err := net.DialTimeout("tcp", s.sysmonAddr, 5*time.Second)
	if err != nil {
		return fmt.Errorf("failed to connect to sysmon: %w", err)
	}
	defer conn.Close()

	conn.SetDeadline(time.Now().Add(5 * time.Second))
	reader := bufio.NewReader(conn)

	// Read welcome banner first
	if err := readWelcomeBanner(reader); err != nil {
		return err
	}

	// Authenticate if auth key provided
	if err := authenticate(conn, reader, authKey); err != nil {
		return err
	}

	// Enable XML mode
	_, err = conn.Write([]byte("MODE xml\n"))
	if err != nil {
		return fmt.Errorf("failed to send MODE xml: %w", err)
	}

	response, err := reader.ReadString('\n')
	if err != nil {
		return fmt.Errorf("failed to read MODE xml response: %w", err)
	}
	if !strings.Contains(response, "333") {
		return fmt.Errorf("MODE xml failed: %s", response)
	}

	// Send UPD command with note
	_, err = conn.Write([]byte(fmt.Sprintf("UPD %s %s\n", hostname, note)))
	if err != nil {
		return fmt.Errorf("failed to send UPD command: %w", err)
	}

	response, err = reader.ReadString('\n')
	if err != nil {
		return fmt.Errorf("failed to read UPD response: %w", err)
	}

	if strings.Contains(response, "333") {
		return nil
	} else if strings.Contains(response, "403") {
		return fmt.Errorf("host not found, update error, or permission denied")
	} else if strings.Contains(response, "444") {
		return fmt.Errorf("permission denied - authentication required")
	}

	return fmt.Errorf("UPD failed: %s", response)
}

// ToggleTrace toggles debug tracing for a specific host
func (s *Service) ToggleTrace(hostname string, authKey string) (bool, error) {
	// The caller holds a fleet-wide "site:object" key; the daemon that
	// owns it has never heard of the site half.
	_, hostname = SplitQualified(hostname)
	hostname = sanitizeCmd(hostname)
	// Connect to sysmon daemon
	conn, err := net.DialTimeout("tcp", s.sysmonAddr, 5*time.Second)
	if err != nil {
		return false, fmt.Errorf("failed to connect to sysmon: %w", err)
	}
	defer conn.Close()

	conn.SetDeadline(time.Now().Add(5 * time.Second))
	reader := bufio.NewReader(conn)

	// Read welcome banner first
	if err := readWelcomeBanner(reader); err != nil {
		return false, err
	}

	// Authenticate if auth key provided (TRACE doesn't require auth, but accept it)
	if err := authenticate(conn, reader, authKey); err != nil {
		return false, err
	}

	// Send TRACE command
	_, err = conn.Write([]byte(fmt.Sprintf("TRACE %s\n", hostname)))
	if err != nil {
		return false, fmt.Errorf("failed to send TRACE command: %w", err)
	}

	response, err := reader.ReadString('\n')
	if err != nil {
		return false, fmt.Errorf("failed to read TRACE response: %w", err)
	}

	response = strings.TrimSpace(response)

	if strings.Contains(response, "333 tracing enabled") {
		return true, nil
	} else if strings.Contains(response, "333 tracing disabled") {
		return false, nil
	} else if strings.Contains(response, "403") {
		return false, fmt.Errorf("host not found")
	}

	return false, fmt.Errorf("TRACE failed: %s", response)
}

// TestAuth tests if an auth key is valid
func (s *Service) TestAuth(authKey string) (bool, error) {
	if authKey == "" {
		return false, fmt.Errorf("auth key is required")
	}

	// Connect to sysmon daemon
	conn, err := net.DialTimeout("tcp", s.sysmonAddr, 5*time.Second)
	if err != nil {
		return false, fmt.Errorf("failed to connect to sysmon: %w", err)
	}
	defer conn.Close()

	conn.SetDeadline(time.Now().Add(5 * time.Second))
	reader := bufio.NewReader(conn)

	// Read welcome banner first
	if err := readWelcomeBanner(reader); err != nil {
		return false, err
	}

	// Try to authenticate
	err = authenticate(conn, reader, authKey)
	if err != nil {
		return false, nil // Auth failed but connection worked
	}

	return true, nil // Auth succeeded
}

// GetVersion gets the sysmon daemon version
func (s *Service) GetVersion(authKey string) (string, error) {
	// From what the poller already recorded, not from a connection of its
	// own. This used to dial s.sysmonAddr, which predates the fleet: it
	// could only ever see a daemon this process dials, and daemons dial
	// *in* by default now. On a normal install it was reaching for an
	// address that is not set and reporting the result as a fault.
	//
	// An empty answer is not an error. A sysmon-web with no boxes yet is
	// a sysmon-web that has just been installed.
	for _, d := range s.fleet() {
		d.mu.Lock()
		v := d.info.Version
		d.mu.Unlock()
		if v != "" {
			return v, nil
		}
	}
	return "", nil
}

// ToggleDebug toggles general debug logging
func (s *Service) ToggleDebug(authKey string) (string, error) {
	return s.sendSimpleCommand("DEBUG", authKey)
}

// ToggleSNMPDebug toggles SNMP debug logging
func (s *Service) ToggleSNMPDebug(authKey string) (string, error) {
	return s.sendSimpleCommand("SNMPD", authKey)
}

// ExpireDNS expires the DNS cache
// ExpireDNS expires the daemon's DNS cache.
// sysmond calls expire_dns() and sends no response.
func (s *Service) ExpireDNS(authKey string) (string, error) {
	return s.sendFireAndForget("EXPIREDNS", authKey)
}

// PrintQueue prints the internal queue status
func (s *Service) PrintQueue(authKey string) (string, error) {
	conn, err := net.DialTimeout("tcp", s.sysmonAddr, 5*time.Second)
	if err != nil {
		return "", fmt.Errorf("failed to connect to sysmon: %w", err)
	}
	defer conn.Close()

	conn.SetDeadline(time.Now().Add(5 * time.Second))
	reader := bufio.NewReader(conn)

	if err := readWelcomeBanner(reader); err != nil {
		return "", err
	}

	if err := authenticate(conn, reader, authKey); err != nil {
		return "", err
	}

	// Send PRINTQ command
	_, err = conn.Write([]byte("PRINTQ\n"))
	if err != nil {
		return "", fmt.Errorf("failed to send PRINTQ command: %w", err)
	}

	// sysmond sends queue lines then closes with no terminator code,
	// so we read until EOF or the connection deadline fires.
	conn.SetDeadline(time.Now().Add(2 * time.Second))
	var output strings.Builder
	for {
		line, err := reader.ReadString('\n')
		if line != "" {
			output.WriteString(line)
		}
		if err != nil {
			break
		}
	}

	return output.String(), nil
}

// GetNextFD gets next file descriptor info
func (s *Service) GetNextFD(authKey string) (string, error) {
	conn, err := net.DialTimeout("tcp", s.sysmonAddr, 5*time.Second)
	if err != nil {
		return "", fmt.Errorf("failed to connect to sysmon: %w", err)
	}
	defer conn.Close()

	conn.SetDeadline(time.Now().Add(5 * time.Second))
	reader := bufio.NewReader(conn)

	if err := readWelcomeBanner(reader); err != nil {
		return "", err
	}

	if err := authenticate(conn, reader, authKey); err != nil {
		return "", err
	}

	// Send NFD command
	_, err = conn.Write([]byte("NFD\n"))
	if err != nil {
		return "", fmt.Errorf("failed to send NFD command: %w", err)
	}

	// Read two-line response
	line1, err := reader.ReadString('\n')
	if err != nil {
		return "", fmt.Errorf("failed to read NFD response: %w", err)
	}
	line2, _ := reader.ReadString('\n')

	return strings.TrimSpace(line1) + "\n" + strings.TrimSpace(line2), nil
}

// KillDaemon gracefully shuts down the daemon.
// sysmond sets stop_daemon=TRUE and sends no response, so we
// send the command and return immediately.
func (s *Service) KillDaemon(authKey string) (string, error) {
	return s.sendFireAndForget("KILLIT", authKey)
}

// sendFireAndForget sends a command that produces no response from sysmond.
func (s *Service) sendFireAndForget(command string, authKey string) (string, error) {
	conn, err := net.DialTimeout("tcp", s.sysmonAddr, 5*time.Second)
	if err != nil {
		return "", fmt.Errorf("failed to connect to sysmon: %w", err)
	}
	defer conn.Close()

	conn.SetDeadline(time.Now().Add(5 * time.Second))
	reader := bufio.NewReader(conn)

	if err := readWelcomeBanner(reader); err != nil {
		return "", err
	}

	if err := authenticate(conn, reader, authKey); err != nil {
		return "", err
	}

	_, err = conn.Write([]byte(command + "\n"))
	if err != nil {
		return "", fmt.Errorf("failed to send %s command: %w", command, err)
	}

	return fmt.Sprintf("%s command sent", command), nil
}

// sendSimpleCommand sends a command that returns a single line response
func (s *Service) sendSimpleCommand(command string, authKey string) (string, error) {
	conn, err := net.DialTimeout("tcp", s.sysmonAddr, 5*time.Second)
	if err != nil {
		return "", fmt.Errorf("failed to connect to sysmon: %w", err)
	}
	defer conn.Close()

	conn.SetDeadline(time.Now().Add(5 * time.Second))
	reader := bufio.NewReader(conn)

	if err := readWelcomeBanner(reader); err != nil {
		return "", err
	}

	if err := authenticate(conn, reader, authKey); err != nil {
		return "", err
	}

	// Send command
	_, err = conn.Write([]byte(command + "\n"))
	if err != nil {
		return "", fmt.Errorf("failed to send %s command: %w", command, err)
	}

	// Read response
	response, err := reader.ReadString('\n')
	if err != nil {
		return "", fmt.Errorf("failed to read %s response: %w", command, err)
	}

	response = strings.TrimSpace(response)

	// Check for error response codes
	if strings.Contains(response, "444") {
		return "", fmt.Errorf("authentication failed - auth key required for %s command", command)
	} else if strings.Contains(response, "403") {
		return "", fmt.Errorf("command failed or permission denied")
	}

	// Success - return the response
	return response, nil
}

// GetObjectsXML returns raw XML for all monitored objects
// This returns the comprehensive XML output from enhanced send_object_xml()
func (s *Service) GetObjectsXML() (string, error) {
	conn, err := net.DialTimeout("tcp", s.sysmonAddr, 5*time.Second)
	if err != nil {
		return "", fmt.Errorf("failed to connect to sysmon at %s: %w (is sysmond running?)", s.sysmonAddr, err)
	}
	defer conn.Close()

	conn.SetDeadline(time.Now().Add(5 * time.Second))
	reader := bufio.NewReader(conn)

	// Read welcome banner
	if err := readWelcomeBanner(reader); err != nil {
		return "", err
	}

	// Enable XML mode
	_, err = conn.Write([]byte("MODE xml\n"))
	if err != nil {
		return "", fmt.Errorf("failed to send MODE xml command: %w", err)
	}

	response, err := reader.ReadString('\n')
	if err != nil {
		return "", fmt.Errorf("failed to read MODE xml response: %w", err)
	}
	if !strings.Contains(response, "333") {
		return "", fmt.Errorf("MODE xml failed: %s", response)
	}

	// Get list of ALL objects with STATAL command
	// CRITICAL: Use STATAL (not STATO or STAT) because:
	// - STATAL returns ALL hosts (both up and down)
	// - STATO only returns hosts with errors (lastcheck != 0)
	// - STATAL returns unique_name (the object identifier) like STATO
	// - STAT returns hostname:type:port:... where hostname != unique_name
	// - SHOWOBJ searches by unique_name, so using STAT causes 403 errors
	_, err = conn.Write([]byte("STATAL\n"))
	if err != nil {
		return "", fmt.Errorf("failed to send STATAL command: %w", err)
	}
	s.sessionLog.Log("STATAL", "getting object list (all hosts)", false, "")

	// Read object names from STATAL response
	// STATAL returns just unique_name, one per line (like STATO but for all hosts)
	objectNames := []string{}
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			return "", fmt.Errorf("error reading STATAL response: %w", err)
		}

		line = strings.TrimSpace(line)

		if strings.HasPrefix(line, "333") {
			break
		}

		// STATAL returns unique_name directly (no parsing needed)
		// This is exactly what SHOWOBJ expects
		if line != "" {
			objectNames = append(objectNames, line)
		}
	}

	// Build complete XML document with all objects
	var xmlOutput strings.Builder
	xmlOutput.WriteString("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n")
	xmlOutput.WriteString("<SysmonStatus>\n")

	// Get XML for each object
	for _, objName := range objectNames {
		// Send SHOWOBJ command
		_, err = conn.Write([]byte(fmt.Sprintf("SHOWOBJ %s\n", objName)))
		if err != nil {
			return "", fmt.Errorf("failed to send SHOWOBJ command: %w", err)
		}

		// Read multi-line XML response until we see </ObjectStatus>
		for {
			line, err := reader.ReadString('\n')

			// Process line first (ReadString can return data + error)
			xmlOutput.WriteString(line)

			// Check for terminator
			if strings.Contains(line, "</ObjectStatus>") {
				break
			}

			// Then check error
			if err != nil {
				return "", fmt.Errorf("error reading SHOWOBJ response: %w", err)
			}
		}
	}

	xmlOutput.WriteString("</SysmonStatus>\n")

	// Send QUIT to close connection cleanly (ignore error - connection closing)
	conn.Write([]byte("QUIT\n"))

	return xmlOutput.String(), nil
}

// GetObjectXML returns raw XML for a single monitored object
func (s *Service) GetObjectXML(hostname string) (string, error) {
	// The caller holds a fleet-wide "site:object" key; the daemon that
	// owns it has never heard of the site half.
	_, hostname = SplitQualified(hostname)
	hostname = sanitizeCmd(hostname)
	conn, err := net.DialTimeout("tcp", s.sysmonAddr, 5*time.Second)
	if err != nil {
		return "", fmt.Errorf("failed to connect to sysmon: %w", err)
	}
	defer conn.Close()

	conn.SetDeadline(time.Now().Add(5 * time.Second))
	reader := bufio.NewReader(conn)

	// Read welcome banner
	if err := readWelcomeBanner(reader); err != nil {
		return "", err
	}

	// Enable XML mode
	_, err = conn.Write([]byte("MODE xml\n"))
	if err != nil {
		return "", fmt.Errorf("failed to send MODE xml command: %w", err)
	}

	response, err := reader.ReadString('\n')
	if err != nil {
		return "", fmt.Errorf("failed to read MODE xml response: %w", err)
	}
	if !strings.Contains(response, "333") {
		return "", fmt.Errorf("MODE xml failed: %s", response)
	}

	// Send SHOWOBJ command
	_, err = conn.Write([]byte(fmt.Sprintf("SHOWOBJ %s\n", hostname)))
	if err != nil {
		return "", fmt.Errorf("failed to send SHOWOBJ command: %w", err)
	}

	// Read multi-line XML response
	var xmlOutput strings.Builder
	for {
		line, err := reader.ReadString('\n')

		// Process line first (ReadString can return data + error)
		xmlOutput.WriteString(line)

		// Check for terminator
		if strings.Contains(line, "</ObjectStatus>") {
			break
		}

		// Check for error responses (match at line start to avoid false positives on XML content)
		trimmedLine := strings.TrimSpace(line)
		if strings.HasPrefix(trimmedLine, "403") || strings.HasPrefix(trimmedLine, "444") {
			return "", fmt.Errorf("object not found or MODE xml not enabled")
		}

		// Then check error
		if err != nil {
			return "", fmt.Errorf("error reading SHOWOBJ response: %w", err)
		}
	}

	// Send QUIT to close connection cleanly (ignore error - connection closing)
	conn.Write([]byte("QUIT\n"))

	return xmlOutput.String(), nil
}

// BulkOperationResult represents the result of a single operation in a bulk request
type BulkOperationResult struct {
	Hostname string `json:"hostname"`
	Success  bool   `json:"success"`
	Error    string `json:"error,omitempty"`
}

// BulkAckHosts acknowledges multiple hosts in a single connection
func (s *Service) BulkAckHosts(hostnames []string, authKey string) []BulkOperationResult {
	results := make([]BulkOperationResult, len(hostnames))

	// Validate input
	if len(hostnames) == 0 {
		return results
	}

	// Connect to sysmon daemon once
	conn, err := net.DialTimeout("tcp", s.sysmonAddr, 10*time.Second)
	if err != nil {
		// If connection fails, mark all as failed
		for i, hostname := range hostnames {
			results[i] = BulkOperationResult{
				Hostname: hostname,
				Success:  false,
				Error:    fmt.Sprintf("failed to connect to sysmon: %v", err),
			}
		}
		return results
	}
	defer conn.Close()

	conn.SetDeadline(time.Now().Add(30 * time.Second)) // Longer timeout for bulk
	reader := bufio.NewReader(conn)

	// Read welcome banner
	if err := readWelcomeBanner(reader); err != nil {
		for i, hostname := range hostnames {
			results[i] = BulkOperationResult{
				Hostname: hostname,
				Success:  false,
				Error:    fmt.Sprintf("failed to read welcome banner: %v", err),
			}
		}
		return results
	}

	// Authenticate once
	if err := authenticate(conn, reader, authKey); err != nil {
		for i, hostname := range hostnames {
			results[i] = BulkOperationResult{
				Hostname: hostname,
				Success:  false,
				Error:    fmt.Sprintf("authentication failed: %v", err),
			}
		}
		return results
	}

	// Process each hostname
	for i, hostname := range hostnames {
		// The caller holds a fleet-wide "site:object" key; the daemon that
		// owns it has never heard of the site half.
		_, hostname = SplitQualified(hostname)
		hostname = sanitizeCmd(hostname)
		cmd := fmt.Sprintf("ACK %s\n", hostname)
		_, err := conn.Write([]byte(cmd))
		if err != nil {
			results[i] = BulkOperationResult{
				Hostname: hostname,
				Success:  false,
				Error:    fmt.Sprintf("failed to send command: %v", err),
			}
			continue
		}

		s.sessionLog.Log(fmt.Sprintf("ACK %s", hostname), "", false, "")

		// Read response
		response, err := reader.ReadString('\n')
		if err != nil {
			results[i] = BulkOperationResult{
				Hostname: hostname,
				Success:  false,
				Error:    fmt.Sprintf("failed to read response: %v", err),
			}
			continue
		}

		response = strings.TrimSpace(response)
		s.sessionLog.Log(fmt.Sprintf("ACK %s", hostname), response, false, "")

		// sysmond responds with "333 ..." on success
		if strings.HasPrefix(response, "333") {
			results[i] = BulkOperationResult{
				Hostname: hostname,
				Success:  true,
			}
		} else {
			results[i] = BulkOperationResult{
				Hostname: hostname,
				Success:  false,
				Error:    response,
			}
		}
	}

	// Send QUIT
	conn.Write([]byte("QUIT\n"))

	return results
}

// BulkUpdateHosts updates multiple hosts with the same note in a single connection
func (s *Service) BulkUpdateHosts(hostnames []string, note string, authKey string) []BulkOperationResult {
	results := make([]BulkOperationResult, len(hostnames))

	// Validate input
	if len(hostnames) == 0 {
		return results
	}
	if note == "" {
		for i, hostname := range hostnames {
			results[i] = BulkOperationResult{
				Hostname: hostname,
				Success:  false,
				Error:    "note is required",
			}
		}
		return results
	}

	// Connect to sysmon daemon once
	conn, err := net.DialTimeout("tcp", s.sysmonAddr, 10*time.Second)
	if err != nil {
		for i, hostname := range hostnames {
			results[i] = BulkOperationResult{
				Hostname: hostname,
				Success:  false,
				Error:    fmt.Sprintf("failed to connect to sysmon: %v", err),
			}
		}
		return results
	}
	defer conn.Close()

	conn.SetDeadline(time.Now().Add(30 * time.Second))
	reader := bufio.NewReader(conn)

	// Read welcome banner
	if err := readWelcomeBanner(reader); err != nil {
		for i, hostname := range hostnames {
			results[i] = BulkOperationResult{
				Hostname: hostname,
				Success:  false,
				Error:    fmt.Sprintf("failed to read welcome banner: %v", err),
			}
		}
		return results
	}

	// Authenticate once
	if err := authenticate(conn, reader, authKey); err != nil {
		for i, hostname := range hostnames {
			results[i] = BulkOperationResult{
				Hostname: hostname,
				Success:  false,
				Error:    fmt.Sprintf("authentication failed: %v", err),
			}
		}
		return results
	}

	// Process each hostname
	note = sanitizeCmd(note)
	for i, hostname := range hostnames {
		// The caller holds a fleet-wide "site:object" key; the daemon that
		// owns it has never heard of the site half.
		_, hostname = SplitQualified(hostname)
		hostname = sanitizeCmd(hostname)
		cmd := fmt.Sprintf("UPD %s %s\n", hostname, note)
		_, err := conn.Write([]byte(cmd))
		if err != nil {
			results[i] = BulkOperationResult{
				Hostname: hostname,
				Success:  false,
				Error:    fmt.Sprintf("failed to send command: %v", err),
			}
			continue
		}

		s.sessionLog.Log(fmt.Sprintf("UPD %s %s", hostname, note), "", false, "")

		// Read response
		response, err := reader.ReadString('\n')
		if err != nil {
			results[i] = BulkOperationResult{
				Hostname: hostname,
				Success:  false,
				Error:    fmt.Sprintf("failed to read response: %v", err),
			}
			continue
		}

		response = strings.TrimSpace(response)
		s.sessionLog.Log(fmt.Sprintf("UPD %s", hostname), response, false, "")

		// sysmond responds with "333 ..." on success
		if strings.HasPrefix(response, "333") {
			results[i] = BulkOperationResult{
				Hostname: hostname,
				Success:  true,
			}
		} else {
			results[i] = BulkOperationResult{
				Hostname: hostname,
				Success:  false,
				Error:    response,
			}
		}
	}

	// Send QUIT
	conn.Write([]byte("QUIT\n"))

	return results
}

// BulkToggleTrace toggles trace for multiple hosts in a single connection
func (s *Service) BulkToggleTrace(hostnames []string, enable bool, authKey string) []BulkOperationResult {
	results := make([]BulkOperationResult, len(hostnames))

	// Validate input
	if len(hostnames) == 0 {
		return results
	}

	// Connect to sysmon daemon once
	conn, err := net.DialTimeout("tcp", s.sysmonAddr, 10*time.Second)
	if err != nil {
		for i, hostname := range hostnames {
			results[i] = BulkOperationResult{
				Hostname: hostname,
				Success:  false,
				Error:    fmt.Sprintf("failed to connect to sysmon: %v", err),
			}
		}
		return results
	}
	defer conn.Close()

	conn.SetDeadline(time.Now().Add(30 * time.Second))
	reader := bufio.NewReader(conn)

	// Read welcome banner
	if err := readWelcomeBanner(reader); err != nil {
		for i, hostname := range hostnames {
			results[i] = BulkOperationResult{
				Hostname: hostname,
				Success:  false,
				Error:    fmt.Sprintf("failed to read welcome banner: %v", err),
			}
		}
		return results
	}

	// Authenticate once (trace doesn't require auth but accept it)
	if authKey != "" {
		if err := authenticate(conn, reader, authKey); err != nil {
			for i, hostname := range hostnames {
				results[i] = BulkOperationResult{
					Hostname: hostname,
					Success:  false,
					Error:    fmt.Sprintf("authentication failed: %v", err),
				}
			}
			return results
		}
	}

	// Process each hostname
	for i, hostname := range hostnames {
		// The caller holds a fleet-wide "site:object" key; the daemon that
		// owns it has never heard of the site half.
		_, hostname = SplitQualified(hostname)
		hostname = sanitizeCmd(hostname)
		cmd := fmt.Sprintf("TRACE %s\n", hostname)
		_, err := conn.Write([]byte(cmd))
		if err != nil {
			results[i] = BulkOperationResult{
				Hostname: hostname,
				Success:  false,
				Error:    fmt.Sprintf("failed to send command: %v", err),
			}
			continue
		}

		s.sessionLog.Log(fmt.Sprintf("TRACE %s", hostname), "", false, "")

		// Read response
		response, err := reader.ReadString('\n')
		if err != nil {
			results[i] = BulkOperationResult{
				Hostname: hostname,
				Success:  false,
				Error:    fmt.Sprintf("failed to read response: %v", err),
			}
			continue
		}

		response = strings.TrimSpace(response)
		s.sessionLog.Log(fmt.Sprintf("TRACE %s", hostname), response, false, "")

		// sysmond responds with "333 ..." on success
		if strings.HasPrefix(response, "333") {
			results[i] = BulkOperationResult{
				Hostname: hostname,
				Success:  true,
			}
		} else {
			results[i] = BulkOperationResult{
				Hostname: hostname,
				Success:  false,
				Error:    response,
			}
		}
	}

	// Send QUIT
	conn.Write([]byte("QUIT\n"))

	return results
}
