package monitoring

import (
	"bufio"
	"encoding/xml"
	"fmt"
	"net"
	"strings"
	"time"

	"sysmon-web/internal/models"
)

// Service handles monitoring queries to sysmon daemon
type Service struct {
	sysmonAddr string
}

// NewService creates a new monitoring service
func NewService(sysmonAddr string) *Service {
	return &Service{
		sysmonAddr: sysmonAddr,
	}
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
	ObjectContact   string   `xml:"ObjectContact"`
	ObjectState     int      `xml:"ObjectLastcheckState"` // 0=OK, non-zero=problem
	ObjectContacted int      `xml:"ObjectContacted"`      // 0=not alerted, 1=alerted
	TotalChecked    int64    `xml:"ObjectTotalChecked"`
	TotalDown       int64    `xml:"ObjectTotalDown"`
	DownCt          int64    `xml:"ObjectDownCt"`
	SendPings       int      `xml:"ObjectSendPings"`
	MinPings        int      `xml:"ObjectMinPings"`
}

// GetStatus gets the complete sysmon status via TCP protocol
func (s *Service) GetStatus() (*models.SysmonStatus, error) {
	// Connect to sysmon daemon
	conn, err := net.DialTimeout("tcp", s.sysmonAddr, 5*time.Second)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to sysmon at %s: %w (is sysmond running?)", s.sysmonAddr, err)
	}
	defer conn.Close()

	// Set connection timeout
	conn.SetDeadline(time.Now().Add(30 * time.Second))
	reader := bufio.NewReader(conn)

	// Step 1: Enable XML mode
	_, err = conn.Write([]byte("MODE xml\n"))
	if err != nil {
		return nil, fmt.Errorf("failed to send MODE xml command: %w", err)
	}

	// Read response: "333 xml enabled"
	response, err := reader.ReadString('\n')
	if err != nil {
		return nil, fmt.Errorf("failed to read MODE xml response: %w", err)
	}
	if !strings.Contains(response, "333") {
		return nil, fmt.Errorf("MODE xml failed: %s", response)
	}

	// Step 2: Get list of objects with STAT command
	_, err = conn.Write([]byte("STAT\n"))
	if err != nil {
		return nil, fmt.Errorf("failed to send STAT command: %w", err)
	}

	// Read object names from STAT response
	objectNames := []string{}
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			return nil, fmt.Errorf("error reading STAT response: %w", err)
		}

		line = strings.TrimSpace(line)

		// End of status output
		if strings.HasPrefix(line, "333") {
			break
		}

		// Parse plain text format from STAT (even in XML mode)
		// Format: hostname:type:port:lastcheck:downct:contacted:deathtime
		// OR just: objectname (for STATO command)
		fields := strings.Split(line, ":")
		if len(fields) > 0 && fields[0] != "" {
			objectNames = append(objectNames, fields[0])
		}
	}

	// Step 3: Get detailed XML for each object with SHOWOBJ
	status := &models.SysmonStatus{
		Hosts:      []models.HostStatus{},
		Statistics: models.Stats{},
	}

	hostsUp := 0
	hostsDown := 0

	for _, objName := range objectNames {
		// Send SHOWOBJ command
		_, err = conn.Write([]byte(fmt.Sprintf("SHOWOBJ %s\n", objName)))
		if err != nil {
			continue // Skip this object
		}

		// Read XML response (multi-line)
		xmlData := ""
		for {
			line, err := reader.ReadString('\n')
			if err != nil {
				break
			}
			xmlData += line

			// XML ends with </ObjectStatus>
			if strings.Contains(line, "</ObjectStatus>") {
				break
			}
		}

		// Parse XML
		var xmlObj XMLObjectStatus
		if err := xml.Unmarshal([]byte(xmlData), &xmlObj); err != nil {
			continue // Skip objects with parse errors
		}

		// Create host status entry
		host := models.HostStatus{
			Hostname:      xmlObj.HostName,
			OverallStatus: "OK",
			StatusColor:   "green",
			Checks:        []models.CheckResult{},
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
		check := models.CheckResult{
			Type:          xmlObj.ObjectType,
			Port:          xmlObj.ObjectPort,
			Status:        host.OverallStatus,
			StatusMessage: xmlObj.ObjectMessage,
		}
		host.Checks = append(host.Checks, check)

		if xmlObj.ObjectContact != "" {
			host.Contact = xmlObj.ObjectContact
		}

		status.Hosts = append(status.Hosts, host)
	}

	// Fill in statistics
	status.Statistics.TotalHosts = len(objectNames)
	status.Statistics.HealthyHosts = hostsUp
	status.Statistics.CriticalHosts = hostsDown
	// WarningHosts is incremented in the loop above
	status.Statistics.ChecksByType = make(map[string]int)
	status.Statistics.ChecksByStatus = make(map[string]int)

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

	conn.SetDeadline(time.Now().Add(10 * time.Second))
	reader := bufio.NewReader(conn)

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

	conn.SetDeadline(time.Now().Add(10 * time.Second))
	reader := bufio.NewReader(conn)

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

	conn.SetDeadline(time.Now().Add(10 * time.Second))
	reader := bufio.NewReader(conn)

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

	conn.SetDeadline(time.Now().Add(10 * time.Second))
	reader := bufio.NewReader(conn)

	// Try to authenticate
	err = authenticate(conn, reader, authKey)
	if err != nil {
		return false, nil // Auth failed but connection worked
	}

	return true, nil // Auth succeeded
}
