package monitoring

import (
	"bufio"
	"encoding/xml"
	"fmt"
	"net"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"sysmon-web/internal/models"
)

// Service handles monitoring queries to sysmon daemon
type Service struct {
	sysmonAddr string
	sessionLog *SessionLogger
}

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
	mu           sync.RWMutex
	entries      []SessionLogEntry
	errors       []SessionLogEntry
	maxEntries   int
	maxErrors    int
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
	if len(sl.entries) > sl.maxEntries {
		sl.entries = sl.entries[len(sl.entries)-sl.maxEntries:]
	}

	// Add to errors log if it's an error (circular buffer)
	if isError {
		sl.errors = append(sl.errors, entry)
		if len(sl.errors) > sl.maxErrors {
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
func NewService(sysmonAddr string) *Service {
	return &Service{
		sysmonAddr: sysmonAddr,
		sessionLog: NewSessionLogger(500, 100), // Keep last 500 entries, 100 errors
	}
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
	XMLName         xml.Name `xml:"ObjectStatus"`
	Object          string   `xml:"Object"`
	HostName        string   `xml:"HostName"`
	ObjectPort      int      `xml:"ObjectPort"`
	ObjectType      string   `xml:"ObjectType"`
	ObjectMessage   string   `xml:"ObjectMessage"`
	ObjectNotes     string   `xml:"ObjectNotes"`          // Description/notes for the object
	ObjectContact   string   `xml:"ObjectContact"`
	ObjectState     int      `xml:"ObjectLastcheckState"` // 0=OK, non-zero=problem
	ObjectContacted int      `xml:"ObjectContacted"`      // 0=not alerted, 1=alerted
	TotalChecked    int64    `xml:"ObjectTotalChecked"`
	TotalDown       int64    `xml:"ObjectTotalDown"`
	DownCt          int64    `xml:"ObjectDownCt"`          // Current consecutive down count
	UpCt            int64    `xml:"ObjectUpCt"`            // Current consecutive up count
	SendPings       int      `xml:"ObjectSendPings"`
	MinPings        int      `xml:"ObjectMinPings"`
	DeathTime       int64    `xml:"ObjectOutageTime"`      // When it went down (Unix timestamp)
	LastTimeUp      int64    `xml:"ObjectLastTimeUp"`      // When it last came back up (Unix timestamp)
}

// GetStatus gets the complete sysmon status via TCP protocol
func (s *Service) GetStatus() (*models.SysmonStatus, error) {
	// Connect to sysmon daemon
	conn, err := net.DialTimeout("tcp", s.sysmonAddr, 5*time.Second)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to sysmon at %s: %w (is sysmond running?)", s.sysmonAddr, err)
	}
	defer conn.Close()

	// Set connection timeout - keep it short for responsive monitoring UI
	conn.SetDeadline(time.Now().Add(5 * time.Second))
	reader := bufio.NewReader(conn)

	// Read welcome banner first
	if err := readWelcomeBanner(reader); err != nil {
		return nil, err
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
	for {
		resp, err := readSysmonResponse(reader)
		if err != nil {
			return nil, fmt.Errorf("error reading STATAL response: %w", err)
		}

		// Check for response codes
		if resp.Code != "" {
			if resp.IsError {
				return nil, fmt.Errorf("STATAL command failed: %s", resp.Message)
			}
			// Code 333 = end of output
			if resp.Code == "333" {
				break
			}
		}

		// It's a data line (no response code)
		// STATAL returns just the unique_name (object identifier), one per line
		objectName := strings.TrimSpace(resp.Message)
		if objectName != "" {
			objectNames = append(objectNames, objectName)
		}
	}
	s.sessionLog.Log("STATAL", fmt.Sprintf("Retrieved %d objects (all hosts)", len(objectNames)), false, "")

	// Step 3: Get detailed XML for each object with SHOWOBJ
	status := &models.SysmonStatus{
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
	allResponses := []ResponseCapture{}       // Capture ALL protocol responses

	// Capture MODE xml response
	allResponses = append(allResponses, ResponseCapture{
		Command:  "MODE xml",
		Response: resp.Message,
		Parsed:   resp.Code == "333",
	})

	for _, objName := range objectNames {
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

		// Create host status entry
		host := models.HostStatus{
			Hostname:      xmlObj.HostName,
			Description:   xmlObj.ObjectNotes,
			IPv4Address:   "", // Will be set below if hostname is an IP
			OverallStatus: "OK",
			StatusColor:   "green",
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

		// Calculate last change time from DeathTime (when went down) or LastTimeUp (when came back up)
		// Use the most recent of the two as the last change time
		if xmlObj.ObjectState != 0 && xmlObj.DeathTime > 0 {
			// Currently down, so DeathTime is the last change
			changeTime := time.Unix(xmlObj.DeathTime, 0)
			host.LastChangeTime = &changeTime
		} else if xmlObj.ObjectState == 0 && xmlObj.LastTimeUp > 0 {
			// Currently up, so LastTimeUp is the last change
			changeTime := time.Unix(xmlObj.LastTimeUp, 0)
			host.LastChangeTime = &changeTime
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
				status.Statistics.WarningHosts++
			} else {
				// Down and already alerted - CRITICAL (red)
				host.OverallStatus = "CRITICAL"
				host.StatusColor = "red"
				hostsDown++
			}
		} else {
			hostsUp++
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

		// Increment statistics counters for dashboard charts
		if xmlObj.ObjectType != "" {
			status.Statistics.ChecksByType[xmlObj.ObjectType]++
		}
		status.Statistics.ChecksByStatus[host.OverallStatus]++

		if xmlObj.ObjectContact != "" {
			host.Contact = xmlObj.ObjectContact
		}

		status.Hosts = append(status.Hosts, host)
	}

	// Sort hosts: CRITICAL first, then WARNING, then OK
	// Within each status level, sort alphabetically by hostname
	sort.SliceStable(status.Hosts, func(i, j int) bool {
		hostI := status.Hosts[i]
		hostJ := status.Hosts[j]

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

	// Fill in statistics
	status.Statistics.TotalHosts = len(objectNames)
	status.Statistics.HealthyHosts = hostsUp
	status.Statistics.CriticalHosts = hostsDown
	// WarningHosts and ChecksByType/ChecksByStatus are incremented in the loop above

	// Send QUIT to close connection cleanly
	conn.Write([]byte("QUIT\n"))

	// Log successful completion
	s.sessionLog.Log("GetStatus", fmt.Sprintf("Complete: %d total, %d up, %d down, %d warnings",
		len(objectNames), hostsUp, hostsDown, status.Statistics.WarningHosts), false, "")

	return status, nil
}

// GetHostStatus gets status for a specific host
func (s *Service) GetHostStatus(hostname string) (*models.HostStatus, error) {
	status, err := s.GetStatus()
	if err != nil {
		return nil, err
	}

	for _, host := range status.Hosts {
		if host.Hostname == hostname {
			return &host, nil
		}
	}

	return nil, fmt.Errorf("host %s not found", hostname)
}

// GetTraps gets all SNMP traps
func (s *Service) GetTraps() (*models.TrapInfo, error) {
	status, err := s.GetStatus()
	if err != nil {
		return nil, err
	}

	if status.SNMPTraps == nil {
		return &models.TrapInfo{
			RecentTraps: []models.Trap{},
			TrapSources: []models.TrapSource{},
			Summary: models.TrapSummary{
				TrapsByType:     make(map[string]int),
				TrapsBySeverity: make(map[string]int),
			},
		}, nil
	}

	return status.SNMPTraps, nil
}

// GetTrapsBySource gets traps from a specific source
func (s *Service) GetTrapsBySource(sourceIP string) ([]models.Trap, error) {
	traps, err := s.GetTraps()
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

	// Send VERS command
	_, err = conn.Write([]byte("VERS\n"))
	if err != nil {
		return "", fmt.Errorf("failed to send VERS command: %w", err)
	}

	// Read version response
	response, err := reader.ReadString('\n')
	if err != nil {
		return "", fmt.Errorf("failed to read VERS response: %w", err)
	}

	return strings.TrimSpace(response), nil
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
func (s *Service) ExpireDNS(authKey string) (string, error) {
	return s.sendSimpleCommand("EXPIREDNS", authKey)
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

	// Read multi-line response until we get a prompt or timeout
	var output strings.Builder
	for {
		line, err := reader.ReadString('\n')

		// Process line first (ReadString can return data + error)
		output.WriteString(line)

		// Stop if we see end marker
		if strings.Contains(line, "333") || strings.Contains(line, "444") {
			break
		}

		// Then check error
		if err != nil {
			break // End of output
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
	line1, _ := reader.ReadString('\n')
	line2, _ := reader.ReadString('\n')

	return strings.TrimSpace(line1) + "\n" + strings.TrimSpace(line2), nil
}

// KillDaemon gracefully shuts down the daemon
func (s *Service) KillDaemon(authKey string) (string, error) {
	return s.sendSimpleCommand("KILLIT", authKey)
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

	// Send QUIT to close connection cleanly
	conn.Write([]byte("QUIT\n"))

	return xmlOutput.String(), nil
}

// GetObjectXML returns raw XML for a single monitored object
func (s *Service) GetObjectXML(hostname string) (string, error) {
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

		// Check for error responses
		if strings.Contains(line, "403") {
			return "", fmt.Errorf("object not found or MODE xml not enabled")
		}

		// Then check error
		if err != nil {
			return "", fmt.Errorf("error reading SHOWOBJ response: %w", err)
		}
	}

	// Send QUIT to close connection cleanly
	conn.Write([]byte("QUIT\n"))

	return xmlOutput.String(), nil
}
