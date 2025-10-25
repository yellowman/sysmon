package monitoring

import (
	"bufio"
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

// GetStatus gets the complete sysmon status via TCP protocol
func (s *Service) GetStatus() (*models.SysmonStatus, error) {
	// Connect to sysmon daemon
	conn, err := net.DialTimeout("tcp", s.sysmonAddr, 5*time.Second)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to sysmon at %s: %w (is sysmond running?)", s.sysmonAddr, err)
	}
	defer conn.Close()

	// Set connection timeout
	conn.SetDeadline(time.Now().Add(10 * time.Second))

	// Request status (STAT command returns status of all objects)
	_, err = conn.Write([]byte("STAT\n"))
	if err != nil {
		return nil, fmt.Errorf("failed to send STAT command: %w", err)
	}

	// Read response line by line
	scanner := bufio.NewScanner(conn)
	status := &models.SysmonStatus{
		Hosts:      []models.HostStatus{},
		Statistics: models.Stats{},
	}

	hostsUp := 0
	hostsDown := 0
	hostsTotal := 0

	for scanner.Scan() {
		line := scanner.Text()

		// End of status output
		if strings.Contains(line, "333") {
			break
		}

		// Parse status line format: hostname:type:port:lastcheck:downct:contacted:deathtime
		// Example: router1.example.com:3:0:0:0:0:0
		fields := strings.Split(line, ":")
		if len(fields) < 7 {
			continue
		}

		hostname := fields[0]
		if hostname == "" {
			continue
		}

		hostsTotal++

		// lastcheck field: 0 = OK, anything else = problem
		lastcheck := fields[3]
		isUp := (lastcheck == "0")

		if isUp {
			hostsUp++
		} else {
			hostsDown++
		}

		// Create host status entry
		host := models.HostStatus{
			Hostname:      hostname,
			OverallStatus: "OK",
			StatusColor:   "green",
			Checks:        []models.CheckResult{},
		}

		if !isUp {
			host.OverallStatus = "CRITICAL"
			host.StatusColor = "red"
		}

		status.Hosts = append(status.Hosts, host)
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error reading from sysmon: %w", err)
	}

	// Fill in statistics
	status.Statistics.TotalHosts = hostsTotal
	status.Statistics.HealthyHosts = hostsUp
	status.Statistics.CriticalHosts = hostsDown
	status.Statistics.WarningHosts = 0
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
