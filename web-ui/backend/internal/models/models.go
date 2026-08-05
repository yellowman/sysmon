package models

import "time"

// Config represents the complete sysmon configuration
type Config struct {
	Root     string         `json:"root,omitempty"` // Root object name for dependency tree
	Global   GlobalSettings `json:"global"`
	Hosts    []Host         `json:"hosts"`
	Contacts []Contact      `json:"contacts"`
	Spawns   []SpawnCommand `json:"spawns"` // Named spawn commands
}

// GlobalSettings represents global sysmon settings
type GlobalSettings struct {
	// Core settings
	CheckInterval int `json:"checkinterval,omitempty"` // queuetime - seconds between checks (default 60)
	NumFailures   int `json:"numfailures,omitempty"`   // number of failures before alert (default 4)

	// Wishlist features
	MinNumFailures int `json:"minnumfailures,omitempty"` // minimum failures threshold
	FlapTime       int `json:"flaptime,omitempty"`       // flap detection time in seconds

	// Ports
	ClientPort int `json:"clientport,omitempty"` // TCP port for sysmon client (default 1345)

	// Alert settings
	PageInterval int    `json:"pageinterval,omitempty"` // reminder interval in minutes
	Sender       string `json:"sender,omitempty"`       // email sender address
	From         string `json:"from,omitempty"`         // email from address
	Subject      string `json:"subject,omitempty"`      // email subject line
	ReplyTo      string `json:"replyto,omitempty"`      // reply-to header
	ErrorsTo     string `json:"errorsto,omitempty"`     // errors-to header
	NoSubject    bool   `json:"nosubject,omitempty"`    // disable subject line
	PMsg         string `json:"pmesg,omitempty"`        // page message format

	// HTML/Display settings
	UpColor     string `json:"upcolor,omitempty"`     // color for up status
	DownColor   string `json:"downcolor,omitempty"`   // color for down status
	RecentColor string `json:"recentcolor,omitempty"` // color for recent changes
	HTMLRefresh int    `json:"htmlrefresh,omitempty"` // HTML refresh interval in seconds
	DateFormat  string `json:"dateformat,omitempty"`  // date format string
	ShowUpAlso  bool   `json:"showupalso,omitempty"`  // show up hosts in status

	// Files and logging
	StatusFile     string `json:"statusfile,omitempty"`     // path to status file
	StatusFileType string `json:"statusfiletype,omitempty"` // "html" or "text"
	StatusTempDir  string `json:"statustempdir,omitempty"`  // temp directory for status files
	CSSFile        string `json:"cssfile,omitempty"`        // path to custom CSS file for HTML output
	PidFile        string `json:"pidfile,omitempty"`        // PID file path
	Logging        string `json:"logging,omitempty"`        // syslog facility
	OutputJSON     string `json:"outputjson,omitempty"`     // JSON output file path

	// DNS settings
	DNSLog    int `json:"dnslog,omitempty"`    // DNS logging interval in seconds
	DNSExpire int `json:"dnsexpire,omitempty"` // DNS cache TTL in seconds

	// System settings
	MaxQueued     int    `json:"maxqueued,omitempty"`     // max simultaneous checks
	NoHeartbeat   bool   `json:"noheartbeat,omitempty"`   // disable registration packet
	NoLogConnects bool   `json:"nologconnects,omitempty"` // don't log client connections
	SNMPTrap      bool   `json:"snmptrap,omitempty"`      // enable SNMP trap monitoring
	AuthKey       string `json:"authkey,omitempty"`       // authentication key for clients
	SaveState     string `json:"savestate,omitempty"`     // path to save state XML file

	// Push notification settings live in the web-ui settings store
	// (bbolt), not here - sysmond doesn't care about them.

	// Include paths
	Includes []string `json:"includes,omitempty"` // included config files
}

// SpawnCommand represents a named spawn command definition
type SpawnCommand struct {
	Name    string `json:"name"`    // e.g., "pagechris"
	Command string `json:"command"` // e.g., "blah %s %s %i blah"
}

// Host represents a monitored host (object in sysmon.conf)
type Host struct {
	ID       string `json:"id"`
	Hostname string `json:"hostname"`
	IP       string `json:"ip"`                // IP address
	Contact  string `json:"contact,omitempty"` // contact email
	Notes    string `json:"notes,omitempty"`   // Description/notes
	Paused   bool   `json:"paused"`            // pause monitoring

	// Alert settings
	Spawn        string `json:"spawn,omitempty"`
	PageInterval int    `json:"pageinterval,omitempty"`
	ContactOn    string `json:"contacton,omitempty"`

	// Check configuration
	Type string `json:"type,omitempty"`
	Port int    `json:"port,omitempty"`

	// Ping status, read from sysmond and NOT configurable via sysmon.conf:
	// the daemon hardcodes how many probes a plain ping check sends.
	MinPings            int     `json:"minpings,omitempty"`
	SendPings           int     `json:"sendpings,omitempty"`
	PacketLossThreshold float64 `json:"packetlossthreshold,omitempty"`

	// RTT / latency check (type rtt) - all four are real per-object
	// directives. RTTInterval is the ms between probes; the rest set the
	// alert thresholds and how many probes make up the average.
	RTTThreshold    int `json:"rttthreshold,omitempty"`
	JitterThreshold int `json:"jitterthreshold,omitempty"`
	RTTSamples      int `json:"rttsamples,omitempty"`
	RTTInterval     int `json:"rttinterval,omitempty"`

	// SNMP trap settings
	TrapAlert bool `json:"trapalert,omitempty"`

	// SNMP monitoring settings
	SNMPCommunity string `json:"snmpcommunity,omitempty"` // SNMP community string (e.g., "public")
	SNMPOID       string `json:"snmpoid,omitempty"`       // OID to query (e.g., ".1.3.6.1.2.1.1.3.0")
	SNMPOIDSec    string `json:"snmpoidsec,omitempty"`    // Secondary OID for comparison
	SNMPUpMsg     string `json:"snmpupmsg,omitempty"`     // Custom message when SNMP check passes
	SNMPDownMsg   string `json:"snmpdownmsg,omitempty"`   // Custom message when SNMP check fails
	SNMPType      string `json:"snmptype,omitempty"`      // SNMP check type (high/low/range/exact/rate/uptime)
	// SNMPVersion is "1" or "2c"; empty means the daemon default (2c).
	SNMPVersion string `json:"snmpversion,omitempty"`
	SNMPHigh    int64  `json:"snmphigh,omitempty"`   // upper threshold
	SNMPLow     int64  `json:"snmplow,omitempty"`    // lower threshold
	SNMPExact   int64  `json:"snmpexact,omitempty"`  // exact value to match
	SNMPRate    int64  `json:"snmprate,omitempty"`   // rate per second threshold
	SNMPOctets  bool   `json:"snmpoctets,omitempty"` // convert bytes to bits for rate

	// DNS check settings
	DNSQuery     string `json:"dnsquery,omitempty"`     // DNS hostname to query
	DNSAA        bool   `json:"dnsaa,omitempty"`        // Require authoritative answer
	DNSRecursion bool   `json:"dnsrecursion,omitempty"` // Perform recursive query

	// Protocol authentication (POP3, IMAP, RADIUS, etc.)
	Username string `json:"username,omitempty"` // Authentication username
	Password string `json:"password,omitempty"` // Authentication password
	Secret   string `json:"secret,omitempty"`   // RADIUS shared secret

	// HTTP/HTTPS check settings
	URL       string `json:"url,omitempty"`       // URL path to check (e.g., "/health")
	URLText   string `json:"urltext,omitempty"`   // Text to find in HTTP response
	Header    string `json:"header,omitempty"`    // HTTP header name to check
	HeaderVal string `json:"headerval,omitempty"` // Expected HTTP header value

	// Per-object overrides and customization
	QueueTime           int    `json:"queuetime,omitempty"`           // per-object check interval in seconds
	NumFailures         int    `json:"numfailures,omitempty"`         // per-object failures before alert (overrides global)
	PMsg                string `json:"pmsg,omitempty"`                // custom page message format
	Command             string `json:"command,omitempty"`             // command to execute on failure
	Group               string `json:"group,omitempty"`               // group/category for organization
	PktLossTolerance    int    `json:"pktlosstolerance,omitempty"`    // packet count threshold (not percentage)
	PktLossHistoryHours int    `json:"pktlosshistoryhours,omitempty"` // hours of packet loss history

	// Advanced settings
	Reverse      bool   `json:"reverse,omitempty"`      // reverse logic (alert when UP)
	Dependencies string `json:"dependencies,omitempty"` // dependency string

	Checks []Check `json:"checks,omitempty"` // Multiple check types
}

// Check represents a monitoring check
type Check struct {
	ID       string                 `json:"id"`
	Type     string                 `json:"type"`
	Port     int                    `json:"port,omitempty"`
	Interval int                    `json:"interval,omitempty"`
	Options  map[string]interface{} `json:"options,omitempty"`
}

// Contact represents an alert contact
type Contact struct {
	ID    string `json:"id"`
	Email string `json:"email"`
	Name  string `json:"name,omitempty"`
}

// ConfigSnapshot represents a versioned config snapshot
type ConfigSnapshot struct {
	Version string    `json:"version"`
	Config  Config    `json:"config"`
	ModTime time.Time `json:"modified_time"`
}

// ConfigUpdate represents a config update request
type ConfigUpdate struct {
	Version string `json:"version"`
	Config  Config `json:"config"`
	Comment string `json:"comment,omitempty"`
}

// SysmonStatus represents the live sysmon daemon status
type SysmonStatus struct {
	// Daemon is the primary daemon, so a single-box client sees what it
	// always did; Daemons is the whole fleet.
	Daemon     DaemonInfo   `json:"daemon"`
	Daemons    []DaemonInfo `json:"daemons,omitempty"`
	Hosts      []HostStatus `json:"hosts"`
	Statistics Stats        `json:"statistics"`
	SNMPTraps  *TrapInfo    `json:"snmp_traps,omitempty"`
	// Rev is a monotonic revision that bumps only when host state
	// actually changes (not when timers/uptime merely tick). Clients
	// pass it back as ?since= to fetch a StatusDelta of just what changed.
	Rev int64 `json:"rev"`
}

// StatusDelta is the response to GET /api/monitoring/status?since=<rev>.
// It carries only the hosts that changed since the client's last revision,
// so a live client can poll cheaply (or stream) instead of pulling the
// whole host list every time.
type StatusDelta struct {
	Rev        int64        `json:"rev"`               // current server revision
	Full       bool         `json:"full"`              // true => Changed is the complete host set (resync)
	Daemon     DaemonInfo   `json:"daemon"`            // always included (small); uptime/pid/paused
	Statistics Stats        `json:"statistics"`        // always included (small)
	Changed    []HostStatus `json:"changed"`           // hosts new-or-changed since `since`
	Removed    []string     `json:"removed,omitempty"` // object names removed since `since`
}

// SiteInfo is one sysmond in the fleet, as the site picker sees it.
type SiteInfo struct {
	Site        string `json:"site"`
	Description string `json:"description,omitempty"`
	Address     string `json:"address"`
	// Inbound means the daemon dialled us rather than us dialling it.
	Inbound   bool      `json:"inbound,omitempty"`
	Reachable bool      `json:"reachable"`
	LastError string    `json:"last_error,omitempty"`
	LastSeen  time.Time `json:"last_seen,omitempty"`
	Hosts     int       `json:"hosts"`
}

// DaemonInfo represents sysmon daemon information
type DaemonInfo struct {
	Version     string    `json:"version"`
	Uptime      int64     `json:"uptime_seconds"`
	StartTime   time.Time `json:"start_time"`
	CurrentTime time.Time `json:"current_time"`
	PID         int       `json:"pid"`
	// Site is this daemon's key half of "site:object"; SiteDesc is the
	// label a person reads. An unconfigured daemon reports "local".
	Site           string    `json:"site"`
	SiteDesc       string    `json:"site_desc,omitempty"`
	ConfigFile     string    `json:"config_file"`
	ConfigLoadTime time.Time `json:"config_load_time"`
	Paused         bool      `json:"paused"`
}

// HostStatus represents the status of a monitored host
type HostStatus struct {
	// ObjectName is the fleet-wide key: "site:object". It is what every
	// store is keyed on - history, push collapse, map layout, delta
	// revisions - so two sites' coreswitch can never collide.
	ObjectName string `json:"object_name"`
	// LocalName is the bare name the owning daemon knows it by, which is
	// what goes back over the wire in ACK/UPD/TRACE, and what the UI shows
	// when only one site is in view.
	LocalName      string        `json:"local_name,omitempty"`
	Site           string        `json:"site,omitempty"`
	Hostname       string        `json:"hostname"`
	Description    string        `json:"description,omitempty"` // Notes/description from config
	IPv4Address    string        `json:"ipv4_address,omitempty"`
	IPv6Address    string        `json:"ipv6_address,omitempty"`
	OverallStatus  string        `json:"overall_status"`
	StatusColor    string        `json:"status_color"`
	Contact        string        `json:"contact,omitempty"`
	Paused         bool          `json:"paused"`
	DownCount      int64         `json:"down_count"`                 // Consecutive down count
	UpCount        int64         `json:"up_count"`                   // Consecutive up count
	TotalDown      int64         `json:"total_down"`                 // Total times down
	TotalChecked   int64         `json:"total_checked"`              // Total checks performed
	LastChangeTime *time.Time    `json:"last_change_time,omitempty"` // When status last changed
	TimeUp         int64         `json:"time_up,omitempty"`          // Seconds host has been up (0 if down)
	TimeFailed     int64         `json:"time_failed,omitempty"`      // Seconds host has been down (0 if up)
	LastOutage     *time.Time    `json:"last_outage,omitempty"`      // When last outage occurred
	Checks         []CheckResult `json:"checks"`
	// Stale means the site that owns this host is not answering, so what
	// is shown is the last thing it said rather than current truth. The
	// host is deliberately still here: a site going dark is a fact about
	// the site, not a reason to make its hosts vanish from every map and
	// alert list and then reappear minutes later.
	Stale      bool       `json:"stale,omitempty"`
	StaleSince *time.Time `json:"stale_since,omitempty"`

	// RTT is what a "type rtt" check last measured, in milliseconds,
	// and is nil for every other kind of object. A pointer rather than
	// a zero value: 0.00ms is a real reading on loopback, so "no
	// measurement" and "very fast" have to be distinguishable.
	RTT *RTTStats `json:"rtt,omitempty"`

	// PacketLoss is what a "type pktloss" check last counted, and is
	// nil for every other kind of object.
	PacketLoss *PacketLossStats `json:"packet_loss,omitempty"`
}

// PacketLossStats is one pktloss cycle's counts.
type PacketLossStats struct {
	Sent     int     `json:"sent"`
	Received int     `json:"received"`
	Lost     int     `json:"lost"`
	LossPct  float64 `json:"loss_pct"`
}

// RTTStats is one rtt check's latency and jitter figures.
type RTTStats struct {
	Min    float64 `json:"min_ms"`
	Avg    float64 `json:"avg_ms"`
	Max    float64 `json:"max_ms"`
	Jitter float64 `json:"jitter_ms"` // RFC 3550 delay variation
	// Replies out of Probes: the loss the average is hiding. A check
	// that got 3 of 5 back still reports an average, and the ratio is
	// how a reader knows to distrust it.
	Replies int `json:"replies"`
	Probes  int `json:"probes"`
}

// CheckResult represents a check result
type CheckResult struct {
	Type          string                 `json:"type"`
	Port          int                    `json:"port,omitempty"`
	Status        string                 `json:"status"`
	LastCheckTime time.Time              `json:"last_check_time"`
	NextCheckTime time.Time              `json:"next_check_time"`
	CheckInterval int                    `json:"check_interval_seconds"`
	ResponseTime  float64                `json:"response_time_ms,omitempty"`
	StatusMessage string                 `json:"status_message,omitempty"`
	Result        map[string]interface{} `json:"result,omitempty"`
}

// Stats represents monitoring statistics
type Stats struct {
	TotalHosts     int            `json:"total_hosts"`
	HealthyHosts   int            `json:"healthy_hosts"`
	WarningHosts   int            `json:"warning_hosts"`
	CriticalHosts  int            `json:"critical_hosts"`
	TotalChecks    int            `json:"total_checks"`
	ChecksByType   map[string]int `json:"checks_by_type"`
	ChecksByStatus map[string]int `json:"checks_by_status"`
}

// TrapInfo represents SNMP trap information
type TrapInfo struct {
	RecentTraps []Trap       `json:"recent_traps"`
	TrapSources []TrapSource `json:"trap_sources"`
	Summary     TrapSummary  `json:"summary"`
}

// Trap represents an SNMP trap
type Trap struct {
	SourceIP       string      `json:"source_ip"`
	SourceHostname string      `json:"source_hostname,omitempty"`
	Timestamp      time.Time   `json:"timestamp"`
	TrapType       string      `json:"trap_type"`
	Varbinds       []Varbind   `json:"varbinds"`
	Decoded        *TrapDecode `json:"decoded,omitempty"`
	MatchedHost    string      `json:"matched_host,omitempty"`
	AlertEnabled   bool        `json:"trap_alert_enabled"`
	AlertSent      bool        `json:"alert_sent"`
}

// Varbind represents an SNMP varbind
type Varbind struct {
	OID         string `json:"oid"`
	Type        string `json:"type"`
	Value       string `json:"value"`
	Description string `json:"description,omitempty"`
}

// TrapDecode represents decoded trap information
type TrapDecode struct {
	TrapName       string `json:"trap_name"`
	Description    string `json:"description"`
	Severity       string `json:"severity"`
	Category       string `json:"category"`
	Vendor         string `json:"vendor,omitempty"`
	Interface      string `json:"interface,omitempty"`
	InterfaceIndex int    `json:"interface_index,omitempty"`
}

// TrapSource represents a trap source summary
type TrapSource struct {
	SourceIP  string    `json:"source_ip"`
	Hostname  string    `json:"hostname,omitempty"`
	TrapCount int       `json:"trap_count"`
	LastTrap  time.Time `json:"last_trap"`
}

// TrapSummary represents trap statistics
type TrapSummary struct {
	TotalTraps int `json:"total_traps_hour"`
	// Lost counts traps sysmond's ring overwrote before sysmon-web
	// collected them - visible rather than silently missing.
	Lost            int            `json:"traps_lost,omitempty"`
	TrapsByType     map[string]int `json:"traps_by_type"`
	TrapsBySeverity map[string]int `json:"traps_by_severity"`
}

// Backup represents a config backup
type Backup struct {
	Timestamp time.Time `json:"timestamp"`
	Filename  string    `json:"filename"`
	Size      int64     `json:"size"`
	Comment   string    `json:"comment,omitempty"`
}

// APIError represents an API error response
type APIError struct {
	Error   string      `json:"error"`
	Message string      `json:"message"`
	Details interface{} `json:"details,omitempty"`
}

// VersionConflictError represents a version conflict
type VersionConflictError struct {
	Expected string          `json:"expected_version"`
	Actual   string          `json:"actual_version"`
	Current  *ConfigSnapshot `json:"current_config"`
	Message  string          `json:"message"`
}

func (e *VersionConflictError) Error() string {
	return e.Message
}
