package config

import (
	"bufio"
	"bytes"
	"fmt"
	"strconv"
	"strings"

	"sysmon-web/internal/models"
)

// Parse parses sysmon.conf format
func Parse(content []byte) (*models.Config, error) {
	config := &models.Config{
		Global: models.GlobalSettings{
			ClientPort:    1345, // sysmon default TCP port (SYSMON_PORTNUM)
			SNMPTrapPort:  162,  // SNMP trap default
			CheckInterval: 300,  // 5 minutes default
		},
		Hosts:    []models.Host{},
		Contacts: []models.Contact{},
	}

	scanner := bufio.NewScanner(bytes.NewReader(content))
	var currentHost *models.Host

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		// Skip comments and empty lines
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Parse global settings
		if strings.HasPrefix(line, "clientport ") {
			port, _ := strconv.Atoi(strings.TrimPrefix(line, "clientport "))
			config.Global.ClientPort = port
		} else if strings.HasPrefix(line, "snmptrapport ") {
			port, _ := strconv.Atoi(strings.TrimPrefix(line, "snmptrapport "))
			config.Global.SNMPTrapPort = port
		} else if strings.HasPrefix(line, "checkinterval ") {
			interval, _ := strconv.Atoi(strings.TrimPrefix(line, "checkinterval "))
			config.Global.CheckInterval = interval
		} else if line == "disableicmp" {
			config.Global.DisableICMP = true

		// Parse host definitions
		} else if strings.HasPrefix(line, "monitor ") {
			hostname := strings.TrimPrefix(line, "monitor ")
			currentHost = &models.Host{
				ID:       generateID(hostname),
				Hostname: hostname,
				Checks:   []models.Check{},
			}
			config.Hosts = append(config.Hosts, *currentHost)

		// Parse host attributes
		} else if currentHost != nil {
			if strings.HasPrefix(line, "contact ") {
				email := strings.TrimPrefix(line, "contact ")
				currentHost.Contact = email
				// Add to contacts if not exists
				addContactIfNew(config, email)

			} else if line == "pause" {
				currentHost.Paused = true

			} else if strings.HasPrefix(line, "ping") {
				currentHost.Checks = append(currentHost.Checks, models.Check{
					ID:   generateID("ping"),
					Type: "ping",
				})

			} else if strings.HasPrefix(line, "tcp ") {
				port, _ := strconv.Atoi(strings.TrimPrefix(line, "tcp "))
				currentHost.Checks = append(currentHost.Checks, models.Check{
					ID:   generateID(fmt.Sprintf("tcp-%d", port)),
					Type: "tcp",
					Port: port,
				})

			} else if strings.HasPrefix(line, "http ") || strings.HasPrefix(line, "https ") {
				var checkType string
				var port int
				if strings.HasPrefix(line, "https ") {
					checkType = "https"
					port = 443
					portStr := strings.TrimPrefix(line, "https ")
					if portStr != "" {
						port, _ = strconv.Atoi(portStr)
					}
				} else {
					checkType = "http"
					port = 80
					portStr := strings.TrimPrefix(line, "http ")
					if portStr != "" {
						port, _ = strconv.Atoi(portStr)
					}
				}
				currentHost.Checks = append(currentHost.Checks, models.Check{
					ID:   generateID(fmt.Sprintf("%s-%d", checkType, port)),
					Type: checkType,
					Port: port,
				})

			} else if strings.HasPrefix(line, "smtp") || strings.HasPrefix(line, "pop3") ||
				strings.HasPrefix(line, "imap") || strings.HasPrefix(line, "dns") {
				checkType := strings.Fields(line)[0]
				currentHost.Checks = append(currentHost.Checks, models.Check{
					ID:   generateID(checkType),
					Type: checkType,
				})

			} else if strings.HasPrefix(line, "snmp ") {
				parts := strings.Fields(line)
				if len(parts) >= 2 {
					oid := parts[1]
					currentHost.Checks = append(currentHost.Checks, models.Check{
						ID:   generateID("snmp"),
						Type: "snmp",
						Options: map[string]interface{}{
							"oid": oid,
						},
					})
				}

			} else if strings.HasPrefix(line, "rtt") {
				currentHost.Checks = append(currentHost.Checks, models.Check{
					ID:   generateID("rtt"),
					Type: "rtt",
				})

			} else if strings.HasPrefix(line, "pktloss ") {
				parts := strings.Fields(line)
				threshold := 5.0
				if len(parts) >= 2 {
					threshold, _ = strconv.ParseFloat(parts[1], 64)
				}
				currentHost.Checks = append(currentHost.Checks, models.Check{
					ID:   generateID("pktloss"),
					Type: "pktloss",
					Options: map[string]interface{}{
						"threshold": threshold,
					},
				})
			}
		}
	}

	return config, scanner.Err()
}

// addContactIfNew adds a contact if it doesn't exist
func addContactIfNew(config *models.Config, email string) {
	for _, c := range config.Contacts {
		if c.Email == email {
			return
		}
	}
	config.Contacts = append(config.Contacts, models.Contact{
		ID:    generateID(email),
		Email: email,
	})
}

// generateID generates a simple ID from a string
func generateID(s string) string {
	return strings.ReplaceAll(strings.ToLower(s), " ", "-")
}
