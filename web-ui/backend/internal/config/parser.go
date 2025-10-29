package config

import (
	"bufio"
	"bytes"
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
		Spawns:   []models.SpawnCommand{},
	}

	scanner := bufio.NewScanner(bytes.NewReader(content))
	var currentHost *models.Host
	var inObject bool
	var inSpawns bool
	var currentSpawn *models.SpawnCommand
	var inSpawnDef bool

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		// Skip comments and empty lines
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}

		// Remove trailing semicolon
		line = strings.TrimSuffix(line, ";")

		// Check for spawns block
		if strings.HasPrefix(line, "spawns") && strings.Contains(line, "{") {
			inSpawns = true
			continue
		}

		// Inside spawns block
		if inSpawns {
			if line == "}" {
				inSpawns = false
				continue
			}

			// Start of spawn definition: name "spawnname" {
			if strings.HasPrefix(line, "name") && strings.Contains(line, "{") {
				parts := strings.SplitN(line, "\"", 3)
				if len(parts) >= 2 {
					spawnName := parts[1]
					currentSpawn = &models.SpawnCommand{
						Name: spawnName,
					}
					inSpawnDef = true
				}
				continue
			}

			// Inside spawn definition
			if inSpawnDef {
				if line == "}" {
					if currentSpawn != nil {
						config.Spawns = append(config.Spawns, *currentSpawn)
						currentSpawn = nil
					}
					inSpawnDef = false
					continue
				}

				// command "..."
				if strings.HasPrefix(line, "command") && currentSpawn != nil {
					parts := strings.SplitN(line, "\"", 3)
					if len(parts) >= 2 {
						currentSpawn.Command = parts[1]
					}
				}
			}
			continue
		}

		// Parse global config directives
		if strings.HasPrefix(line, "config ") {
			line = strings.TrimPrefix(line, "config ")

			// Boolean flags
			if line == "drop_privileges" || line == "dropprivileges" {
				config.Global.DropPrivileges = true
			} else if line == "disable_icmp" || line == "disableicmp" {
				config.Global.DisableICMP = true
			} else if line == "noheartbeat" {
				config.Global.NoHeartbeat = true
			} else if line == "nologconnects" {
				config.Global.NoLogConnects = true
			} else if line == "showupalso" {
				config.Global.ShowUpAlso = true
			} else if line == "snmp-trap" {
				config.Global.SNMPTrap = true
			} else if line == "nosubject" {
				config.Global.NoSubject = true
			} else if strings.HasPrefix(line, "queuetime ") || strings.HasPrefix(line, "checkinterval ") {
				// Parse integer value
				parts := strings.Fields(line)
				if len(parts) >= 2 {
					if val, err := strconv.Atoi(parts[1]); err == nil {
						config.Global.CheckInterval = val
					}
				}
			} else if strings.HasPrefix(line, "numfailures ") {
				parts := strings.Fields(line)
				if len(parts) >= 2 {
					if val, err := strconv.Atoi(parts[1]); err == nil {
						config.Global.NumFailures = val
					}
				}
			} else if strings.HasPrefix(line, "minnumfailures ") {
				parts := strings.Fields(line)
				if len(parts) >= 2 {
					if val, err := strconv.Atoi(parts[1]); err == nil {
						config.Global.MinNumFailures = val
					}
				}
			} else if strings.HasPrefix(line, "flaptime ") {
				parts := strings.Fields(line)
				if len(parts) >= 2 {
					if val, err := strconv.Atoi(parts[1]); err == nil {
						config.Global.FlapTime = val
					}
				}
			} else if strings.HasPrefix(line, "clientport ") {
				parts := strings.Fields(line)
				if len(parts) >= 2 {
					if val, err := strconv.Atoi(parts[1]); err == nil {
						config.Global.ClientPort = val
					}
				}
			} else if strings.HasPrefix(line, "trap_port ") {
				parts := strings.Fields(line)
				if len(parts) >= 2 {
					if val, err := strconv.Atoi(parts[1]); err == nil {
						config.Global.SNMPTrapPort = val
					}
				}
			} else if strings.HasPrefix(line, "maxqueued ") {
				parts := strings.Fields(line)
				if len(parts) >= 2 {
					if val, err := strconv.Atoi(parts[1]); err == nil {
						config.Global.MaxQueued = val
					}
				}
			} else if strings.HasPrefix(line, "pageinterval ") {
				parts := strings.Fields(line)
				if len(parts) >= 2 {
					if val, err := strconv.Atoi(parts[1]); err == nil {
						config.Global.PageInterval = val
					}
				}
			} else if strings.HasPrefix(line, "dnsexpire ") {
				parts := strings.Fields(line)
				if len(parts) >= 2 {
					if val, err := strconv.Atoi(parts[1]); err == nil {
						config.Global.DNSExpire = val
					}
				}
			} else if strings.HasPrefix(line, "dnslog ") {
				parts := strings.Fields(line)
				if len(parts) >= 2 {
					if val, err := strconv.Atoi(parts[1]); err == nil {
						config.Global.DNSLog = val
					}
				}
			} else if strings.HasPrefix(line, "htmlrefresh ") || strings.HasPrefix(line, "html refresh ") {
				parts := strings.Fields(line)
				if len(parts) >= 2 {
					if val, err := strconv.Atoi(parts[len(parts)-1]); err == nil {
						config.Global.HTMLRefresh = val
					}
				}
			} else if strings.HasPrefix(line, "statusfile ") {
				parts := strings.Fields(line)
				if len(parts) >= 3 {
					config.Global.StatusFileType = parts[1] // html or text
					config.Global.StatusFile = extractQuoted(strings.Join(parts[2:], " "))
				}
			} else if strings.HasPrefix(line, "statustempdir ") {
				config.Global.StatusTempDir = extractQuoted(strings.TrimPrefix(line, "statustempdir "))
			} else if strings.HasPrefix(line, "sender ") {
				config.Global.Sender = extractQuoted(strings.TrimPrefix(line, "sender "))
			} else if strings.HasPrefix(line, "from ") {
				config.Global.From = extractQuoted(strings.TrimPrefix(line, "from "))
			} else if strings.HasPrefix(line, "subject ") {
				config.Global.Subject = extractQuoted(strings.TrimPrefix(line, "subject "))
			} else if strings.HasPrefix(line, "replyto ") {
				config.Global.ReplyTo = extractQuoted(strings.TrimPrefix(line, "replyto "))
			} else if strings.HasPrefix(line, "errorsto ") {
				config.Global.ErrorsTo = extractQuoted(strings.TrimPrefix(line, "errorsto "))
			} else if strings.HasPrefix(line, "authkey ") {
				config.Global.AuthKey = extractQuoted(strings.TrimPrefix(line, "authkey "))
			} else if strings.HasPrefix(line, "savestate ") {
				config.Global.SaveState = extractQuoted(strings.TrimPrefix(line, "savestate "))
			} else if strings.HasPrefix(line, "pidfile ") {
				config.Global.PidFile = extractQuoted(strings.TrimPrefix(line, "pidfile "))
			} else if strings.HasPrefix(line, "cssfile ") {
				config.Global.CSSFile = extractQuoted(strings.TrimPrefix(line, "cssfile "))
			} else if strings.HasPrefix(line, "outputjson ") {
				config.Global.OutputJSON = extractQuoted(strings.TrimPrefix(line, "outputjson "))
			} else if strings.HasPrefix(line, "logging ") {
				config.Global.Logging = strings.TrimSpace(strings.TrimPrefix(line, "logging "))
			} else if strings.HasPrefix(line, "dateformat ") {
				config.Global.DateFormat = extractQuoted(strings.TrimPrefix(line, "dateformat "))
			} else if strings.HasPrefix(line, "pmesg ") || strings.HasPrefix(line, "pmesg=") {
				config.Global.PMsg = extractQuoted(strings.TrimPrefix(strings.TrimPrefix(line, "pmesg "), "pmesg="))
			} else if strings.HasPrefix(line, "upcolor ") {
				config.Global.UpColor = extractQuoted(strings.TrimPrefix(line, "upcolor "))
			} else if strings.HasPrefix(line, "downcolor ") {
				config.Global.DownColor = extractQuoted(strings.TrimPrefix(line, "downcolor "))
			} else if strings.HasPrefix(line, "recentcolor ") {
				config.Global.RecentColor = extractQuoted(strings.TrimPrefix(line, "recentcolor "))
			}
			continue
		}

		// Parse set directives
		if strings.HasPrefix(line, "set ") {
			// Skip for now - we don't process variable substitution
			continue
		}

		// Parse object definitions: object name {
		if strings.HasPrefix(line, "object ") && strings.Contains(line, "{") {
			// Extract object name
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				objectName := strings.TrimSuffix(parts[1], "{")
				objectName = strings.TrimSpace(objectName)

				currentHost = &models.Host{
					ID:       generateID(objectName),
					Hostname: objectName,
					Checks:   []models.Check{},
				}
				inObject = true
			}
			continue
		}

		// Inside object block
		if inObject {
			// End of object
			if line == "}" {
				if currentHost != nil {
					config.Hosts = append(config.Hosts, *currentHost)
					currentHost = nil
				}
				inObject = false
				continue
			}

			if currentHost == nil {
				continue
			}

			// Parse object fields
			if strings.HasPrefix(line, "ip ") {
				currentHost.IP = extractQuoted(strings.TrimPrefix(line, "ip "))
			} else if strings.HasPrefix(line, "type ") {
				currentHost.Type = extractQuoted(strings.TrimPrefix(line, "type "))
			} else if strings.HasPrefix(line, "desc ") {
				currentHost.Notes = extractQuoted(strings.TrimPrefix(line, "desc "))
			} else if strings.HasPrefix(line, "notes ") {
				currentHost.Notes = extractQuoted(strings.TrimPrefix(line, "notes "))
			} else if strings.HasPrefix(line, "contact ") {
				email := extractQuoted(strings.TrimPrefix(line, "contact "))
				currentHost.Contact = email
				addContactIfNew(config, email)
			} else if strings.HasPrefix(line, "dep ") {
				deps := extractQuoted(strings.TrimPrefix(line, "dep "))
				currentHost.Dependencies = deps
			} else if strings.HasPrefix(line, "spawn ") {
				currentHost.Spawn = extractQuoted(strings.TrimPrefix(line, "spawn "))
			} else if strings.HasPrefix(line, "port ") {
				parts := strings.Fields(line)
				if len(parts) >= 2 {
					if val, err := strconv.Atoi(parts[1]); err == nil {
						currentHost.Port = val
					}
				}
			} else if strings.HasPrefix(line, "group ") {
				currentHost.Group = extractQuoted(strings.TrimPrefix(line, "group "))
			} else if line == "pause" {
				currentHost.Paused = true
			} else if line == "reverse" {
				currentHost.Reverse = true
			} else if strings.HasPrefix(line, "pageinterval ") {
				parts := strings.Fields(line)
				if len(parts) >= 2 {
					if val, err := strconv.Atoi(parts[1]); err == nil {
						currentHost.PageInterval = val
					}
				}
			} else if strings.HasPrefix(line, "queuetime ") {
				parts := strings.Fields(line)
				if len(parts) >= 2 {
					if val, err := strconv.Atoi(parts[1]); err == nil {
						currentHost.QueueTime = val
					}
				}
			} else if strings.HasPrefix(line, "contact_on ") {
				currentHost.ContactOn = extractQuoted(strings.TrimPrefix(line, "contact_on "))
			} else if strings.HasPrefix(line, "command ") {
				currentHost.Command = extractQuoted(strings.TrimPrefix(line, "command "))
			} else if strings.HasPrefix(line, "customspawn ") {
				currentHost.CustomSpawn = extractQuoted(strings.TrimPrefix(line, "customspawn "))
			} else if strings.HasPrefix(line, "numfailures ") {
				parts := strings.Fields(line)
				if len(parts) >= 2 {
					if val, err := strconv.Atoi(parts[1]); err == nil {
						currentHost.NumFailures = val
					}
				}
			} else if line == "trap_alert" || line == "trapalert" {
				currentHost.TrapAlert = true
			} else if strings.HasPrefix(line, "matched_host ") {
				currentHost.MatchedHost = extractQuoted(strings.TrimPrefix(line, "matched_host "))
			} else if strings.HasPrefix(line, "send_pings ") {
				parts := strings.Fields(line)
				if len(parts) >= 2 {
					if val, err := strconv.Atoi(parts[1]); err == nil {
						currentHost.SendPings = val
					}
				}
			} else if strings.HasPrefix(line, "min_pings ") {
				parts := strings.Fields(line)
				if len(parts) >= 2 {
					if val, err := strconv.Atoi(parts[1]); err == nil {
						currentHost.MinPings = val
					}
				}
			} else if strings.HasPrefix(line, "packet_loss_threshold ") {
				parts := strings.Fields(line)
				if len(parts) >= 2 {
					if val, err := strconv.ParseFloat(parts[1], 64); err == nil {
						currentHost.PacketLossThreshold = val
					}
				}
			} else if strings.HasPrefix(line, "rtt_threshold ") {
				parts := strings.Fields(line)
				if len(parts) >= 2 {
					if val, err := strconv.Atoi(parts[1]); err == nil {
						currentHost.RTTThreshold = val
					}
				}
			} else if strings.HasPrefix(line, "jitter_threshold ") {
				parts := strings.Fields(line)
				if len(parts) >= 2 {
					if val, err := strconv.Atoi(parts[1]); err == nil {
						currentHost.JitterThreshold = val
					}
				}
			} else if line == "wakeup_check" {
				currentHost.WakeupCheck = true
			} else if strings.HasPrefix(line, "wakeup_retries ") {
				parts := strings.Fields(line)
				if len(parts) >= 2 {
					if val, err := strconv.Atoi(parts[1]); err == nil {
						currentHost.WakeupRetries = val
					}
				}
			} else if strings.HasPrefix(line, "wakeup_check_interval ") {
				parts := strings.Fields(line)
				if len(parts) >= 2 {
					if val, err := strconv.Atoi(parts[1]); err == nil {
						currentHost.WakeupCheckInterval = val
					}
				}
			} else if strings.HasPrefix(line, "snmp-community ") || strings.HasPrefix(line, "snmpcommunity ") {
				currentHost.SNMPCommunity = extractQuoted(strings.TrimPrefix(strings.TrimPrefix(line, "snmp-community "), "snmpcommunity "))
			} else if strings.HasPrefix(line, "snmp-oid ") || strings.HasPrefix(line, "snmpoid ") {
				currentHost.SNMPOID = extractQuoted(strings.TrimPrefix(strings.TrimPrefix(line, "snmp-oid "), "snmpoid "))
			} else if strings.HasPrefix(line, "snmp-oid-sec ") {
				currentHost.SNMPOIDSec = extractQuoted(strings.TrimPrefix(line, "snmp-oid-sec "))
			} else if strings.HasPrefix(line, "snmp-upmsg ") {
				currentHost.SNMPUpMsg = extractQuoted(strings.TrimPrefix(line, "snmp-upmsg "))
			} else if strings.HasPrefix(line, "snmp-downmsg ") {
				currentHost.SNMPDownMsg = extractQuoted(strings.TrimPrefix(line, "snmp-downmsg "))
			} else if strings.HasPrefix(line, "snmp-type ") {
				currentHost.SNMPType = extractQuoted(strings.TrimPrefix(line, "snmp-type "))
			} else if strings.HasPrefix(line, "snmp-high ") {
				parts := strings.Fields(line)
				if len(parts) >= 2 {
					if val, err := strconv.ParseInt(parts[1], 10, 64); err == nil {
						currentHost.SNMPHigh = val
					}
				}
			} else if strings.HasPrefix(line, "snmp-low ") {
				parts := strings.Fields(line)
				if len(parts) >= 2 {
					if val, err := strconv.ParseInt(parts[1], 10, 64); err == nil {
						currentHost.SNMPLow = val
					}
				}
			} else if strings.HasPrefix(line, "snmp-exact ") {
				parts := strings.Fields(line)
				if len(parts) >= 2 {
					if val, err := strconv.ParseInt(parts[1], 10, 64); err == nil {
						currentHost.SNMPExact = val
					}
				}
			} else if strings.HasPrefix(line, "snmp-rate ") {
				parts := strings.Fields(line)
				if len(parts) >= 2 {
					if val, err := strconv.ParseInt(parts[1], 10, 64); err == nil {
						currentHost.SNMPRate = val
					}
				}
			} else if line == "snmp-octets" || line == "snmpoctets" {
				currentHost.SNMPOctets = true
			} else if strings.HasPrefix(line, "dns-query ") {
				currentHost.DNSQuery = extractQuoted(strings.TrimPrefix(line, "dns-query "))
			} else if line == "dns-aa" {
				currentHost.DNSAA = true
			} else if line == "dns-recursion" {
				currentHost.DNSRecursion = true
			} else if strings.HasPrefix(line, "username ") {
				currentHost.Username = extractQuoted(strings.TrimPrefix(line, "username "))
			} else if strings.HasPrefix(line, "password ") {
				currentHost.Password = extractQuoted(strings.TrimPrefix(line, "password "))
			} else if strings.HasPrefix(line, "secret ") {
				currentHost.Secret = extractQuoted(strings.TrimPrefix(line, "secret "))
			} else if strings.HasPrefix(line, "url ") {
				currentHost.URL = extractQuoted(strings.TrimPrefix(line, "url "))
			} else if strings.HasPrefix(line, "urltext ") {
				currentHost.URLText = extractQuoted(strings.TrimPrefix(line, "urltext "))
			} else if strings.HasPrefix(line, "header ") {
				currentHost.Header = extractQuoted(strings.TrimPrefix(line, "header "))
			} else if strings.HasPrefix(line, "headerval ") {
				currentHost.HeaderVal = extractQuoted(strings.TrimPrefix(line, "headerval "))
			}
		}
	}

	return config, scanner.Err()
}

// extractQuoted extracts a quoted string or returns the whole string if not quoted
func extractQuoted(s string) string {
	s = strings.TrimSpace(s)
	if strings.HasPrefix(s, "\"") && strings.HasSuffix(s, "\"") {
		return s[1 : len(s)-1]
	}
	return s
}

// addContactIfNew adds a contact if it doesn't exist
func addContactIfNew(config *models.Config, email string) {
	if email == "" {
		return
	}
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
