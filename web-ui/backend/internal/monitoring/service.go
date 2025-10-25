package monitoring

import (
	"encoding/json"
	"fmt"
	"net"
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

// GetStatus gets the complete sysmon status via JSON
func (s *Service) GetStatus() (*models.SysmonStatus, error) {
	// Connect to sysmon
	conn, err := net.DialTimeout("tcp", s.sysmonAddr, 5*time.Second)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to sysmon: %w", err)
	}
	defer conn.Close()

	// Request JSON output
	_, err = conn.Write([]byte("json\n"))
	if err != nil {
		return nil, fmt.Errorf("failed to send command: %w", err)
	}

	// Read and parse JSON response
	var status models.SysmonStatus
	decoder := json.NewDecoder(conn)
	if err := decoder.Decode(&status); err != nil {
		return nil, fmt.Errorf("failed to parse JSON from sysmon: %w", err)
	}

	return &status, nil
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
