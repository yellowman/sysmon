package config

import (
	"bufio"
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"sysmon-web/internal/models"
)

// ParseFile parses a sysmon.conf file, resolving include directives
// relative to the file's directory.
func ParseFile(path string) (*models.Config, error) {
	content, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return parseWithIncludes(content, filepath.Dir(path), 0)
}

// CollectAllContent reads the main config file and all included files,
// returning their concatenated content for hashing.
func CollectAllContent(path string) ([]byte, error) {
	return collectIncludes(path, 0)
}

func collectIncludes(path string, depth int) ([]byte, error) {
	if depth > maxIncludeDepth {
		return nil, nil
	}

	content, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var all []byte
	all = append(all, content...)

	baseDir := filepath.Dir(path)
	scanner := bufio.NewScanner(bytes.NewReader(content))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		line = strings.TrimSuffix(line, ";")
		if strings.HasPrefix(line, "include ") {
			incPath := extractQuoted(strings.TrimPrefix(line, "include "))
			if incPath == "" {
				continue
			}
			if !filepath.IsAbs(incPath) {
				incPath = filepath.Join(baseDir, incPath)
			}
			incContent, err := collectIncludes(incPath, depth+1)
			if err != nil {
				continue
			}
			all = append(all, incContent...)
		}
	}

	return all, nil
}

const maxIncludeDepth = 10

func parseWithIncludes(content []byte, baseDir string, depth int) (*models.Config, error) {
	if depth > maxIncludeDepth {
		return nil, fmt.Errorf("include depth exceeded (max %d)", maxIncludeDepth)
	}

	config, err := Parse(content)
	if err != nil {
		return nil, err
	}

	// Scan for include directives and merge included configs
	scanner := bufio.NewScanner(bytes.NewReader(content))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		line = strings.TrimSuffix(line, ";")

		if strings.HasPrefix(line, "include ") {
			includePath := extractQuoted(strings.TrimPrefix(line, "include "))
			if includePath == "" {
				continue
			}

			if !filepath.IsAbs(includePath) {
				includePath = filepath.Join(baseDir, includePath)
			}

			includeContent, err := os.ReadFile(includePath)
			if err != nil {
				continue // skip missing includes like the C parser does
			}

			included, err := parseWithIncludes(includeContent, filepath.Dir(includePath), depth+1)
			if err != nil {
				continue
			}

			config.Hosts = append(config.Hosts, included.Hosts...)
			config.Spawns = append(config.Spawns, included.Spawns...)
			config.Contacts = append(config.Contacts, included.Contacts...)
		}
	}

	return config, nil
}

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

		// Skip empty lines and regular comments
		if line == "" || strings.HasPrefix(line, ";") {
			continue
		}

		// Parse structured comment: #@contact "email" "name"
		if strings.HasPrefix(line, "#@contact ") {
			parts := strings.SplitN(line, "\"", 5)
			if len(parts) >= 4 {
				email := parts[1]
				name := parts[3]
				found := false
				for i := range config.Contacts {
					if config.Contacts[i].Email == email {
						config.Contacts[i].Name = name
						found = true
						break
					}
				}
				if !found {
					config.Contacts = append(config.Contacts, models.Contact{
						ID: generateID(email), Email: email, Name: name,
					})
				}
			}
			continue
		}

		if strings.HasPrefix(line, "#") {
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

		// Parse root directive: root = "name";
		if strings.HasPrefix(line, "root") {
			val := strings.TrimPrefix(line, "root")
			val = strings.TrimLeft(val, " =")
			config.Root = extractQuoted(val)
			continue
		}

		// Parse global config directives
		if strings.HasPrefix(line, "config ") {
			line = strings.TrimPrefix(line, "config ")

			// Boolean flags
			if line == "noheartbeat" {
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
			} else if strings.HasPrefix(line, "sender ") || strings.HasPrefix(line, "from ") {
				val := strings.TrimPrefix(line, "sender ")
				val = strings.TrimPrefix(val, "from ")
				config.Global.Sender = extractQuoted(val)
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
				val := strings.TrimPrefix(line, "logging ")
				if strings.HasPrefix(val, "file ") {
					config.Global.Logging = "file " + extractQuoted(strings.TrimPrefix(val, "file "))
				} else if strings.HasPrefix(val, "syslog ") {
					config.Global.Logging = "syslog " + extractQuoted(strings.TrimPrefix(val, "syslog "))
				} else {
					config.Global.Logging = strings.TrimSpace(val)
				}
			} else if strings.HasPrefix(line, "date ") || strings.HasPrefix(line, "dateformat ") {
				val := line
				val = strings.TrimPrefix(val, "dateformat ")
				val = strings.TrimPrefix(val, "date ")
				config.Global.DateFormat = extractQuoted(val)
			} else if strings.HasPrefix(line, "pmesg ") || strings.HasPrefix(line, "pmesg=") {
				config.Global.PMsg = extractQuoted(strings.TrimPrefix(strings.TrimPrefix(line, "pmesg "), "pmesg="))
			} else if strings.HasPrefix(line, "upcolor ") {
				config.Global.UpColor = extractQuoted(strings.TrimPrefix(line, "upcolor "))
			} else if strings.HasPrefix(line, "downcolor ") {
				config.Global.DownColor = extractQuoted(strings.TrimPrefix(line, "downcolor "))
			} else if strings.HasPrefix(line, "recentcolor ") {
				config.Global.RecentColor = extractQuoted(strings.TrimPrefix(line, "recentcolor "))
			} else if line == "push-notifications" {
				config.Global.PushNotifications = true
			} else if strings.HasPrefix(line, "push-fcm-serverkey ") {
				config.Global.PushFCMServerKey = extractQuoted(strings.TrimPrefix(line, "push-fcm-serverkey "))
			} else if strings.HasPrefix(line, "push-apns-certfile ") {
				config.Global.PushAPNsCertFile = extractQuoted(strings.TrimPrefix(line, "push-apns-certfile "))
			} else if strings.HasPrefix(line, "push-apns-keyfile ") {
				config.Global.PushAPNsKeyFile = extractQuoted(strings.TrimPrefix(line, "push-apns-keyfile "))
			} else if strings.HasPrefix(line, "push-apns-bundleid ") {
				config.Global.PushAPNsBundleID = extractQuoted(strings.TrimPrefix(line, "push-apns-bundleid "))
			} else if line == "push-apns-production" {
				config.Global.PushAPNsProduction = true
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
			} else if strings.HasPrefix(line, "numfailures ") {
				parts := strings.Fields(line)
				if len(parts) >= 2 {
					if val, err := strconv.Atoi(parts[1]); err == nil {
						currentHost.NumFailures = val
					}
				}
			} else if line == "trap_alert" || line == "trapalert" {
				currentHost.TrapAlert = true
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
			} else if strings.HasPrefix(line, "community ") || strings.HasPrefix(line, "snmp-community ") || strings.HasPrefix(line, "snmpcommunity ") {
				val := line
				for _, p := range []string{"snmp-community ", "snmpcommunity ", "community "} {
					val = strings.TrimPrefix(val, p)
				}
				currentHost.SNMPCommunity = extractQuoted(val)
			} else if strings.HasPrefix(line, "oid ") || strings.HasPrefix(line, "snmp-oid ") || strings.HasPrefix(line, "snmpoid ") {
				val := line
				for _, p := range []string{"snmp-oid ", "snmpoid ", "oid "} {
					val = strings.TrimPrefix(val, p)
				}
				currentHost.SNMPOID = extractQuoted(val)
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
			} else if strings.HasPrefix(line, "page ") {
				currentHost.Contact = extractQuoted(strings.TrimPrefix(line, "page "))
			} else if strings.HasPrefix(line, "child ") {
				// child is inverse of dep — store as dependency for display
				currentHost.Dependencies = extractQuoted(strings.TrimPrefix(line, "child "))
			} else if strings.HasPrefix(line, "also-notify ") {
				// additional contact — append to existing contact
				extra := extractQuoted(strings.TrimPrefix(line, "also-notify "))
				if currentHost.Contact != "" && extra != "" {
					currentHost.Contact = currentHost.Contact + "," + extra
				} else if extra != "" {
					currentHost.Contact = extra
				}
			} else if strings.HasPrefix(line, "pmesg ") {
				currentHost.PMsg = extractQuoted(strings.TrimPrefix(line, "pmesg "))
			} else if strings.HasPrefix(line, "rtt_samples ") {
				if val, err := strconv.Atoi(strings.TrimSpace(strings.TrimPrefix(line, "rtt_samples "))); err == nil {
					currentHost.RTTSamples = val
				}
			} else if strings.HasPrefix(line, "pkt_loss_tolerance ") {
				if val, err := strconv.Atoi(strings.TrimSpace(strings.TrimPrefix(line, "pkt_loss_tolerance "))); err == nil {
					currentHost.PktLossTolerance = val
				}
			} else if strings.HasPrefix(line, "pkt_loss_history_hours ") {
				if val, err := strconv.Atoi(strings.TrimSpace(strings.TrimPrefix(line, "pkt_loss_history_hours "))); err == nil {
					currentHost.PktLossHistoryHours = val
				}
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
