package models

import "time"

// Config represents the complete sysmon configuration
type Config struct {
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
	ClientPort   int `json:"clientport,omitempty"`   // TCP port for sysmon client (default 1345)
	SNMPTrapPort int `json:"trapport,omitempty"`     // UDP port for SNMP traps (default 162)

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
	UpColor      string `json:"upcolor,omitempty"`      // color for up status
	DownColor    string `json:"downcolor,omitempty"`    // color for down status
	RecentColor  string `json:"recentcolor,omitempty"`  // color for recent changes
	HTMLRefresh  int    `json:"htmlrefresh,omitempty"`  // HTML refresh interval in seconds
	DateFormat   string `json:"dateformat,omitempty"`   // date format string
	ShowUpAlso   bool   `json:"showupalso,omitempty"`   // show up hosts in status

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
	MaxQueued       int    `json:"maxqueued,omitempty"`       // max simultaneous checks
	DropPrivileges  bool   `json:"dropprivileges,omitempty"`  // drop privileges after init
	DisableICMP     bool   `json:"disableicmp,omitempty"`     // disable all ICMP checks
	NoHeartbeat     bool   `json:"noheartbeat,omitempty"`     // disable registration packet
	NoLogConnects   bool   `json:"nologconnects,omitempty"`   // don't log client connections
	SNMPTrap        bool   `json:"snmptrap,omitempty"`        // enable SNMP trap monitoring
	AuthKey         string `json:"authkey,omitempty"`         // authentication key for clients
	SaveState       string `json:"savestate,omitempty"`       // path to save state XML file

	// Push notification settings
	PushNotifications bool   `json:"pushnotifications,omitempty"` // enable push notifications
	PushFCMServerKey  string `json:"push_fcm_serverkey,omitempty"`
	PushAPNsCertFile  string `json:"push_apns_certfile,omitempty"`
	PushAPNsKeyFile   string `json:"push_apns_keyfile,omitempty"`
	PushAPNsBundleID  string `json:"push_apns_bundleid,omitempty"`
	PushAPNsProduction bool  `json:"push_apns_production,omitempty"`

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
	IP       string `json:"ip"`                      // IP address
	Contact  string `json:"contact,omitempty"`       // contact email
	Notes    string `json:"notes,omitempty"`         // Description/notes
	Paused   bool   `json:"paused"`                  // pause monitoring

	// Alert settings
	Spawn         string `json:"spawn,omitempty"`          // Named spawn command to use
	CustomSpawn   string `json:"customspawn,omitempty"`    // Direct spawn command (for backward compat)
	PageInterval  int    `json:"pageinterval,omitempty"`   // per-host page interval override
	ContactOn     string `json:"contacton,omitempty"`      // when to contact (up/down/both)

	// Check configuration
	Type string `json:"type,omitempty"`           // Main check type (icmp, tcp, http, etc.)
	Port int    `json:"port,omitempty"`           // Port for TCP/UDP checks

	// Packet loss and ping settings
	MinPings             int     `json:"minpings,omitempty"`             // min successful pings required
	SendPings            int     `json:"sendpings,omitempty"`            // number of pings to send
	PacketLossThreshold  float64 `json:"packetlossthreshold,omitempty"`  // packet loss % threshold
	RTTThreshold         int     `json:"rttthreshold,omitempty"`         // RTT threshold in ms
	JitterThreshold      int     `json:"jitterthreshold,omitempty"`      // jitter threshold in ms
	RTTSamples           int     `json:"rttsamples,omitempty"`           // number of RTT samples

	// Wake-on-LAN settings
	WakeupCheck         bool `json:"wakeupcheck,omitempty"`         // enable wakeup monitoring
	WakeupRetries       int  `json:"wakeupretries,omitempty"`       // number of wakeup attempts
	WakeupCheckInterval int  `json:"wakeupcheckinterval,omitempty"` // time between wakeup attempts

	// SNMP trap settings
	TrapAlert   bool   `json:"trapalert,omitempty"`   // enable SNMP trap monitoring
	MatchedHost string `json:"matchedhost,omitempty"` // associated host for trap matching

	// SNMP monitoring settings
	SNMPCommunity string  `json:"snmpcommunity,omitempty"` // SNMP community string (e.g., "public")
	SNMPOID       string  `json:"snmpoid,omitempty"`       // OID to query (e.g., ".1.3.6.1.2.1.1.3.0")
	SNMPOIDSec    string  `json:"snmpoidsec,omitempty"`    // Secondary OID for comparison
	SNMPUpMsg     string  `json:"snmpupmsg,omitempty"`     // Custom message when SNMP check passes
	SNMPDownMsg   string  `json:"snmpdownmsg,omitempty"`   // Custom message when SNMP check fails
	SNMPType      string  `json:"snmptype,omitempty"`      // SNMP check type (high/low/range/exact/rate/uptime)
	SNMPHigh      int64   `json:"snmphigh,omitempty"`      // upper threshold
	SNMPLow       int64   `json:"snmplow,omitempty"`       // lower threshold
	SNMPExact     int64   `json:"snmpexact,omitempty"`     // exact value to match
	SNMPRate      int64   `json:"snmprate,omitempty"`      // rate per second threshold
	SNMPOctets    bool    `json:"snmpoctets,omitempty"`    // convert bytes to bits for rate

	// DNS check settings
	DNSQuery      string `json:"dnsquery,omitempty"`      // DNS hostname to query
	DNSAA         bool   `json:"dnsaa,omitempty"`         // Require authoritative answer
	DNSRecursion  bool   `json:"dnsrecursion,omitempty"`  // Perform recursive query

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
	QueueTime            int    `json:"queuetime,omitempty"`            // per-object check interval in seconds
	NumFailures          int    `json:"numfailures,omitempty"`          // per-object failures before alert (overrides global)
	PMsg                 string `json:"pmsg,omitempty"`                 // custom page message format
	Command              string `json:"command,omitempty"`              // command to execute on failure
	Group                string `json:"group,omitempty"`                // group/category for organization
	PktLossTolerance     int    `json:"pktlosstolerance,omitempty"`     // packet count threshold (not percentage)
	PktLossHistoryHours  int    `json:"pktlosshistoryhours,omitempty"`  // hours of packet loss history

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
	Daemon     DaemonInfo   `json:"daemon"`
	Hosts      []HostStatus `json:"hosts"`
	Statistics Stats        `json:"statistics"`
	SNMPTraps  *TrapInfo    `json:"snmp_traps,omitempty"`
}

// DaemonInfo represents sysmon daemon information
type DaemonInfo struct {
	Version        string    `json:"version"`
	Uptime         int64     `json:"uptime_seconds"`
	StartTime      time.Time `json:"start_time"`
	CurrentTime    time.Time `json:"current_time"`
	PID            int       `json:"pid"`
	ConfigFile     string    `json:"config_file"`
	ConfigLoadTime time.Time `json:"config_load_time"`
}

// HostStatus represents the status of a monitored host
type HostStatus struct {
	Hostname       string        `json:"hostname"`
	Description    string        `json:"description,omitempty"` // Notes/description from config
	IPv4Address    string        `json:"ipv4_address,omitempty"`
	IPv6Address    string        `json:"ipv6_address,omitempty"`
	OverallStatus  string        `json:"overall_status"`
	StatusColor    string        `json:"status_color"`
	Contact        string        `json:"contact,omitempty"`
	Paused         bool          `json:"paused"`
	DownCount      int64         `json:"down_count"`          // Consecutive down count
	UpCount        int64         `json:"up_count"`            // Consecutive up count
	TotalDown      int64         `json:"total_down"`          // Total times down
	TotalChecked   int64         `json:"total_checked"`       // Total checks performed
	LastChangeTime *time.Time    `json:"last_change_time,omitempty"` // When status last changed
	TimeUp         int64         `json:"time_up,omitempty"`          // Seconds host has been up (0 if down)
	TimeFailed     int64         `json:"time_failed,omitempty"`      // Seconds host has been down (0 if up)
	LastOutage     *time.Time    `json:"last_outage,omitempty"`      // When last outage occurred
	Checks         []CheckResult `json:"checks"`
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
	TotalTraps      int            `json:"total_traps_hour"`
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
