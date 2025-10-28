package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"sysmon-web/internal/config"
	"sysmon-web/internal/models"
	"sysmon-web/internal/monitoring"
)

// Router holds the API handlers
type Router struct {
	config     *config.Service
	monitoring *monitoring.Service
	mux        *http.ServeMux
}

// NewRouter creates a new API router
func NewRouter(cfg *config.Service, mon *monitoring.Service) http.Handler {
	r := &Router{
		config:     cfg,
		monitoring: mon,
		mux:        http.NewServeMux(),
	}

	// Configuration endpoints (file-based)
	r.mux.HandleFunc("/api/config", r.handleConfig)
	r.mux.HandleFunc("/api/config/validate", r.handleConfigValidate)
	r.mux.HandleFunc("/api/config/reload", r.handleConfigReload)
	r.mux.HandleFunc("/api/config/raw", r.handleConfigRaw)

	// Visual config editor endpoints (structured data, not raw file)
	r.mux.HandleFunc("/api/config/editor/get", r.handleConfigEditorGet)
	r.mux.HandleFunc("/api/config/editor/save", r.handleConfigEditorSave)
	r.mux.HandleFunc("/api/config/editor/spawns", r.handleConfigEditorSpawns)

	// Hosts
	r.mux.HandleFunc("/api/hosts", r.handleHosts)
	r.mux.HandleFunc("/api/hosts/", r.handleHostDetail)

	// Checks
	r.mux.HandleFunc("/api/checks", r.handleChecks)
	r.mux.HandleFunc("/api/checks/", r.handleCheckDetail)

	// Contacts
	r.mux.HandleFunc("/api/contacts", r.handleContacts)
	r.mux.HandleFunc("/api/contacts/", r.handleContactDetail)

	// Backups
	r.mux.HandleFunc("/api/backups", r.handleBackups)
	r.mux.HandleFunc("/api/backups/", r.handleBackupDetail)

	// Live monitoring
	r.mux.HandleFunc("/api/monitoring/status", r.handleMonitoringStatus)
	r.mux.HandleFunc("/api/monitoring/hosts", r.handleMonitoringHosts)
	r.mux.HandleFunc("/api/monitoring/host/", r.handleMonitoringHost)
	r.mux.HandleFunc("/api/monitoring/alerts", r.handleMonitoringAlerts)
	r.mux.HandleFunc("/api/monitoring/traps", r.handleMonitoringTraps)
	r.mux.HandleFunc("/api/monitoring/traps/", r.handleMonitoringTrapsBySource)
	r.mux.HandleFunc("/api/monitoring/stats", r.handleMonitoringStats)
	r.mux.HandleFunc("/api/monitoring/ack/", r.handleMonitoringAck)
	r.mux.HandleFunc("/api/monitoring/update/", r.handleMonitoringUpdate)
	r.mux.HandleFunc("/api/monitoring/trace/", r.handleMonitoringTrace)
	r.mux.HandleFunc("/api/auth/test", r.handleAuthTest)

	// XML passthrough endpoints (comprehensive data)
	r.mux.HandleFunc("/api/xml/objects", r.handleXMLObjects)
	r.mux.HandleFunc("/api/xml/object/", r.handleXMLObject)

	// Admin/debug endpoints
	r.mux.HandleFunc("/api/admin/version", r.handleAdminVersion)
	r.mux.HandleFunc("/api/admin/debug", r.handleAdminDebug)
	r.mux.HandleFunc("/api/admin/snmpd", r.handleAdminSNMPDebug)
	r.mux.HandleFunc("/api/admin/expiredns", r.handleAdminExpireDNS)
	r.mux.HandleFunc("/api/admin/printq", r.handleAdminPrintQ)
	r.mux.HandleFunc("/api/admin/nfd", r.handleAdminNFD)
	r.mux.HandleFunc("/api/admin/killit", r.handleAdminKillit)
	r.mux.HandleFunc("/api/admin/session-log", r.handleAdminSessionLog)
	r.mux.HandleFunc("/api/admin/session-errors", r.handleAdminSessionErrors)

	// HTML pages
	r.mux.HandleFunc("/", r.handleDashboard)
	r.mux.HandleFunc("/hosts.html", r.handleHostsPage)
	r.mux.HandleFunc("/host-detail.html", r.handleHostDetailPage)
	r.mux.HandleFunc("/traps.html", r.handleTrapsPage)
	r.mux.HandleFunc("/config.html", r.handleConfigPage)
	r.mux.HandleFunc("/admin.html", r.handleAdminPage)

	// Serve static files (CSS, JS)
	r.mux.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.Dir("./static"))))

	return r.addCORS(r.mux)
}

// Config handlers
func (r *Router) handleConfig(w http.ResponseWriter, req *http.Request) {
	switch req.Method {
	case http.MethodGet:
		snapshot, err := r.config.GetConfig()
		if err != nil {
			r.sendError(w, http.StatusInternalServerError, err.Error())
			return
		}
		r.sendJSON(w, snapshot)

	case http.MethodPut:
		var update models.ConfigUpdate
		if err := json.NewDecoder(req.Body).Decode(&update); err != nil {
			r.sendError(w, http.StatusBadRequest, "Invalid JSON")
			return
		}

		user, ip := r.getUserInfo(req)
		snapshot, err := r.config.UpdateConfig(&update, user, ip)
		if err != nil {
			if verr, ok := err.(*models.VersionConflictError); ok {
				w.WriteHeader(http.StatusConflict)
				r.sendJSON(w, verr)
				return
			}
			r.sendError(w, http.StatusBadRequest, err.Error())
			return
		}

		r.sendJSON(w, snapshot)

	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func (r *Router) handleConfigValidate(w http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var cfg models.Config
	if err := json.NewDecoder(req.Body).Decode(&cfg); err != nil {
		r.sendError(w, http.StatusBadRequest, "Invalid JSON")
		return
	}

	if err := r.config.ValidateConfig(&cfg); err != nil {
		r.sendJSON(w, map[string]interface{}{
			"valid": false,
			"error": err.Error(),
		})
		return
	}

	r.sendJSON(w, map[string]interface{}{
		"valid": true,
	})
}

func (r *Router) handleConfigReload(w http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Trigger sysmon reload (send SIGHUP)
	if err := r.config.ReloadSysmon(); err != nil {
		r.sendError(w, http.StatusInternalServerError, fmt.Sprintf("Failed to reload sysmon: %v", err))
		return
	}

	r.sendJSON(w, map[string]string{"status": "sysmon reloaded successfully"})
}

func (r *Router) handleConfigRaw(w http.ResponseWriter, req *http.Request) {
	switch req.Method {
	case http.MethodGet:
		content, version, err := r.config.GetRawConfig()
		if err != nil {
			r.sendError(w, http.StatusInternalServerError, err.Error())
			return
		}
		r.sendJSON(w, map[string]string{
			"content": content,
			"version": version,
		})

	case http.MethodPut:
		var data struct {
			Content string `json:"content"`
			Version string `json:"version"`
			Comment string `json:"comment"`
		}
		if err := json.NewDecoder(req.Body).Decode(&data); err != nil {
			r.sendError(w, http.StatusBadRequest, "Invalid JSON")
			return
		}

		user, ip := r.getUserInfo(req)
		newVersion, err := r.config.UpdateRawConfig(data.Content, data.Version, data.Comment, user, ip)
		if err != nil {
			if _, ok := err.(*models.VersionConflictError); ok {
				http.Error(w, "Version conflict", http.StatusConflict)
				return
			}
			r.sendError(w, http.StatusBadRequest, err.Error())
			return
		}

		r.sendJSON(w, map[string]string{"version": newVersion})

	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// Visual config editor handlers (structured data, not raw file)
func (r *Router) handleConfigEditorGet(w http.ResponseWriter, req *http.Request) {
	// TODO: Build config from monitoring data
	// For now, return stub data
	config := models.Config{
		Global: models.GlobalSettings{
			ClientPort:    1345,
			CheckInterval: 60,
		},
		Spawns: []models.SpawnCommand{},
		Hosts:  []models.Host{},
	}
	r.sendJSON(w, config)
}

func (r *Router) handleConfigEditorSave(w http.ResponseWriter, req *http.Request) {
	// TODO: Implement save logic
	r.sendJSON(w, map[string]interface{}{
		"success": true,
		"message": "Config editor save not yet implemented",
	})
}

func (r *Router) handleConfigEditorSpawns(w http.ResponseWriter, req *http.Request) {
	// TODO: Handle spawns CRUD operations
	r.sendJSON(w, []models.SpawnCommand{})
}

// Hosts handlers
func (r *Router) handleHosts(w http.ResponseWriter, req *http.Request) {
	snapshot, err := r.config.GetConfig()
	if err != nil {
		r.sendError(w, http.StatusInternalServerError, err.Error())
		return
	}

	r.sendJSON(w, snapshot.Config.Hosts)
}

func (r *Router) handleHostDetail(w http.ResponseWriter, req *http.Request) {
	// Extract hostname from path
	hostname := strings.TrimPrefix(req.URL.Path, "/api/hosts/")

	snapshot, err := r.config.GetConfig()
	if err != nil {
		r.sendError(w, http.StatusInternalServerError, err.Error())
		return
	}

	for _, host := range snapshot.Config.Hosts {
		if host.ID == hostname || host.Hostname == hostname {
			r.sendJSON(w, host)
			return
		}
	}

	http.Error(w, "Host not found", http.StatusNotFound)
}

// Checks handlers
func (r *Router) handleChecks(w http.ResponseWriter, req *http.Request) {
	snapshot, err := r.config.GetConfig()
	if err != nil {
		r.sendError(w, http.StatusInternalServerError, err.Error())
		return
	}

	// Collect all checks from all hosts
	var allChecks []models.Check
	for _, host := range snapshot.Config.Hosts {
		allChecks = append(allChecks, host.Checks...)
	}

	r.sendJSON(w, allChecks)
}

func (r *Router) handleCheckDetail(w http.ResponseWriter, req *http.Request) {
	http.Error(w, "Not implemented", http.StatusNotImplemented)
}

// Contacts handlers
func (r *Router) handleContacts(w http.ResponseWriter, req *http.Request) {
	snapshot, err := r.config.GetConfig()
	if err != nil {
		r.sendError(w, http.StatusInternalServerError, err.Error())
		return
	}

	r.sendJSON(w, snapshot.Config.Contacts)
}

func (r *Router) handleContactDetail(w http.ResponseWriter, req *http.Request) {
	http.Error(w, "Not implemented", http.StatusNotImplemented)
}

// Backups handlers
func (r *Router) handleBackups(w http.ResponseWriter, req *http.Request) {
	backups, err := r.config.ListBackups()
	if err != nil {
		r.sendError(w, http.StatusInternalServerError, err.Error())
		return
	}

	r.sendJSON(w, backups)
}

func (r *Router) handleBackupDetail(w http.ResponseWriter, req *http.Request) {
	filename := strings.TrimPrefix(req.URL.Path, "/api/backups/")

	if strings.HasSuffix(filename, "/restore") {
		// Restore backup
		filename = strings.TrimSuffix(filename, "/restore")
		user, ip := r.getUserInfo(req)

		if err := r.config.RestoreBackup(filename, user, ip); err != nil {
			r.sendError(w, http.StatusBadRequest, err.Error())
			return
		}

		r.sendJSON(w, map[string]string{"status": "restored"})
		return
	}

	http.Error(w, "Not implemented", http.StatusNotImplemented)
}

// Monitoring handlers
func (r *Router) handleMonitoringStatus(w http.ResponseWriter, req *http.Request) {
	status, err := r.monitoring.GetStatus()
	if err != nil {
		// Check if it's an XML parse error with debug data
		if xmlErr, ok := err.(*monitoring.XMLParseError); ok {
			r.sendErrorWithDetails(w, http.StatusServiceUnavailable, xmlErr.Message, map[string]interface{}{
				"object_name":   xmlErr.ObjectName,
				"raw_xml":       xmlErr.RawXML,
				"samples":       xmlErr.AllSamples,
				"all_responses": xmlErr.AllResponses,
			})
			return
		}
		r.sendError(w, http.StatusServiceUnavailable, fmt.Sprintf("Failed to connect to sysmon: %v", err))
		return
	}

	r.sendJSON(w, status)
}

func (r *Router) handleMonitoringHosts(w http.ResponseWriter, req *http.Request) {
	status, err := r.monitoring.GetStatus()
	if err != nil {
		r.sendError(w, http.StatusServiceUnavailable, err.Error())
		return
	}

	r.sendJSON(w, status.Hosts)
}

func (r *Router) handleMonitoringHost(w http.ResponseWriter, req *http.Request) {
	hostname := strings.TrimPrefix(req.URL.Path, "/api/monitoring/host/")

	host, err := r.monitoring.GetHostStatus(hostname)
	if err != nil {
		r.sendError(w, http.StatusNotFound, err.Error())
		return
	}

	r.sendJSON(w, host)
}

func (r *Router) handleMonitoringAlerts(w http.ResponseWriter, req *http.Request) {
	alerts, err := r.monitoring.GetAlerts()
	if err != nil {
		r.sendError(w, http.StatusServiceUnavailable, err.Error())
		return
	}

	r.sendJSON(w, alerts)
}

func (r *Router) handleMonitoringTraps(w http.ResponseWriter, req *http.Request) {
	traps, err := r.monitoring.GetTraps()
	if err != nil {
		r.sendError(w, http.StatusServiceUnavailable, err.Error())
		return
	}

	r.sendJSON(w, traps)
}

func (r *Router) handleMonitoringTrapsBySource(w http.ResponseWriter, req *http.Request) {
	sourceIP := strings.TrimPrefix(req.URL.Path, "/api/monitoring/traps/")

	traps, err := r.monitoring.GetTrapsBySource(sourceIP)
	if err != nil {
		r.sendError(w, http.StatusServiceUnavailable, err.Error())
		return
	}

	r.sendJSON(w, traps)
}

func (r *Router) handleMonitoringStats(w http.ResponseWriter, req *http.Request) {
	stats, err := r.monitoring.GetStatistics()
	if err != nil {
		r.sendError(w, http.StatusServiceUnavailable, err.Error())
		return
	}

	r.sendJSON(w, stats)
}

func (r *Router) handleMonitoringAck(w http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodPost {
		r.sendError(w, http.StatusMethodNotAllowed, "Only POST allowed")
		return
	}

	hostname := strings.TrimPrefix(req.URL.Path, "/api/monitoring/ack/")
	if hostname == "" {
		r.sendError(w, http.StatusBadRequest, "Hostname required")
		return
	}

	// Get auth key from header or body
	authKey := r.getAuthKey(req)

	err := r.monitoring.AckHost(hostname, authKey)
	if err != nil {
		if strings.Contains(err.Error(), "authentication failed") {
			r.sendError(w, http.StatusUnauthorized, err.Error())
			return
		}
		r.sendError(w, http.StatusServiceUnavailable, fmt.Sprintf("Failed to acknowledge host: %v", err))
		return
	}

	r.sendJSON(w, map[string]string{
		"status":   "success",
		"message":  fmt.Sprintf("Host %s acknowledged", hostname),
		"hostname": hostname,
	})
}

func (r *Router) handleMonitoringUpdate(w http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodPost {
		r.sendError(w, http.StatusMethodNotAllowed, "Only POST allowed")
		return
	}

	hostname := strings.TrimPrefix(req.URL.Path, "/api/monitoring/update/")
	if hostname == "" {
		r.sendError(w, http.StatusBadRequest, "Hostname required")
		return
	}

	// Parse JSON body for note and optional auth key
	var body struct {
		Note    string `json:"note"`
		AuthKey string `json:"auth_key,omitempty"`
	}
	if err := json.NewDecoder(req.Body).Decode(&body); err != nil {
		r.sendError(w, http.StatusBadRequest, "Invalid JSON body")
		return
	}

	if body.Note == "" {
		r.sendError(w, http.StatusBadRequest, "Note is required")
		return
	}

	// Use auth key from body if provided, otherwise from header
	authKey := body.AuthKey
	if authKey == "" {
		authKey = req.Header.Get("X-Auth-Key")
	}

	err := r.monitoring.UpdateHostStatus(hostname, body.Note, authKey)
	if err != nil {
		if strings.Contains(err.Error(), "authentication failed") {
			r.sendError(w, http.StatusUnauthorized, err.Error())
			return
		}
		r.sendError(w, http.StatusServiceUnavailable, fmt.Sprintf("Failed to update host: %v", err))
		return
	}

	r.sendJSON(w, map[string]string{
		"status":   "success",
		"message":  fmt.Sprintf("Host %s updated", hostname),
		"hostname": hostname,
		"note":     body.Note,
	})
}

func (r *Router) handleMonitoringTrace(w http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodPost {
		r.sendError(w, http.StatusMethodNotAllowed, "Only POST allowed")
		return
	}

	hostname := strings.TrimPrefix(req.URL.Path, "/api/monitoring/trace/")
	if hostname == "" {
		r.sendError(w, http.StatusBadRequest, "Hostname required")
		return
	}

	// Get auth key from header
	authKey := r.getAuthKey(req)

	enabled, err := r.monitoring.ToggleTrace(hostname, authKey)
	if err != nil {
		if strings.Contains(err.Error(), "authentication failed") {
			r.sendError(w, http.StatusUnauthorized, err.Error())
			return
		}
		r.sendError(w, http.StatusServiceUnavailable, fmt.Sprintf("Failed to toggle trace: %v", err))
		return
	}

	r.sendJSON(w, map[string]interface{}{
		"status":   "success",
		"hostname": hostname,
		"tracing_enabled": enabled,
		"message":  fmt.Sprintf("Tracing %s for %s", map[bool]string{true: "enabled", false: "disabled"}[enabled], hostname),
	})
}

func (r *Router) handleAuthTest(w http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodPost {
		r.sendError(w, http.StatusMethodNotAllowed, "Only POST allowed")
		return
	}

	// Get auth key from header first
	authKey := req.Header.Get("X-Auth-Key")

	// If no header, try to parse from body (but don't fail if body is empty)
	if authKey == "" && req.Body != nil {
		var body struct {
			AuthKey string `json:"auth_key"`
		}
		// Ignore decode errors - body might be empty, which is OK if header is set
		json.NewDecoder(req.Body).Decode(&body)
		authKey = body.AuthKey
	}

	if authKey == "" {
		r.sendError(w, http.StatusBadRequest, "Auth key required in X-Auth-Key header or JSON body")
		return
	}

	valid, err := r.monitoring.TestAuth(authKey)
	if err != nil {
		r.sendError(w, http.StatusServiceUnavailable, fmt.Sprintf("Failed to test auth: %v", err))
		return
	}

	r.sendJSON(w, map[string]interface{}{
		"valid": valid,
		"message": map[bool]string{
			true:  "Authentication successful",
			false: "Invalid auth key",
		}[valid],
	})
}

// Admin handlers
func (r *Router) handleAdminVersion(w http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodGet {
		r.sendError(w, http.StatusMethodNotAllowed, "Only GET allowed")
		return
	}

	authKey := r.getAuthKey(req)
	version, err := r.monitoring.GetVersion(authKey)
	if err != nil {
		if strings.Contains(err.Error(), "authentication failed") {
			r.sendError(w, http.StatusUnauthorized, err.Error())
			return
		}
		r.sendError(w, http.StatusServiceUnavailable, fmt.Sprintf("Failed to get version: %v", err))
		return
	}

	r.sendJSON(w, map[string]string{
		"version": version,
	})
}

func (r *Router) handleAdminDebug(w http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodPost {
		r.sendError(w, http.StatusMethodNotAllowed, "Only POST allowed")
		return
	}

	authKey := r.getAuthKey(req)
	response, err := r.monitoring.ToggleDebug(authKey)
	if err != nil {
		if strings.Contains(err.Error(), "authentication failed") {
			r.sendError(w, http.StatusUnauthorized, err.Error())
			return
		}
		r.sendError(w, http.StatusServiceUnavailable, fmt.Sprintf("Failed to toggle debug: %v", err))
		return
	}

	r.sendJSON(w, map[string]string{
		"response": response,
	})
}

func (r *Router) handleAdminSNMPDebug(w http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodPost {
		r.sendError(w, http.StatusMethodNotAllowed, "Only POST allowed")
		return
	}

	authKey := r.getAuthKey(req)
	response, err := r.monitoring.ToggleSNMPDebug(authKey)
	if err != nil {
		if strings.Contains(err.Error(), "authentication failed") {
			r.sendError(w, http.StatusUnauthorized, err.Error())
			return
		}
		r.sendError(w, http.StatusServiceUnavailable, fmt.Sprintf("Failed to toggle SNMP debug: %v", err))
		return
	}

	r.sendJSON(w, map[string]string{
		"response": response,
	})
}

func (r *Router) handleAdminExpireDNS(w http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodPost {
		r.sendError(w, http.StatusMethodNotAllowed, "Only POST allowed")
		return
	}

	authKey := r.getAuthKey(req)
	response, err := r.monitoring.ExpireDNS(authKey)
	if err != nil {
		if strings.Contains(err.Error(), "authentication failed") {
			r.sendError(w, http.StatusUnauthorized, err.Error())
			return
		}
		r.sendError(w, http.StatusServiceUnavailable, fmt.Sprintf("Failed to expire DNS: %v", err))
		return
	}

	r.sendJSON(w, map[string]string{
		"response": response,
	})
}

func (r *Router) handleAdminPrintQ(w http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodGet {
		r.sendError(w, http.StatusMethodNotAllowed, "Only GET allowed")
		return
	}

	authKey := r.getAuthKey(req)
	response, err := r.monitoring.PrintQueue(authKey)
	if err != nil {
		if strings.Contains(err.Error(), "authentication failed") {
			r.sendError(w, http.StatusUnauthorized, err.Error())
			return
		}
		r.sendError(w, http.StatusServiceUnavailable, fmt.Sprintf("Failed to print queue: %v", err))
		return
	}

	r.sendJSON(w, map[string]string{
		"output": response,
	})
}

func (r *Router) handleAdminNFD(w http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodGet {
		r.sendError(w, http.StatusMethodNotAllowed, "Only GET allowed")
		return
	}

	authKey := r.getAuthKey(req)
	response, err := r.monitoring.GetNextFD(authKey)
	if err != nil {
		if strings.Contains(err.Error(), "authentication failed") {
			r.sendError(w, http.StatusUnauthorized, err.Error())
			return
		}
		r.sendError(w, http.StatusServiceUnavailable, fmt.Sprintf("Failed to get FD info: %v", err))
		return
	}

	r.sendJSON(w, map[string]string{
		"info": response,
	})
}

func (r *Router) handleAdminKillit(w http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodPost {
		r.sendError(w, http.StatusMethodNotAllowed, "Only POST allowed")
		return
	}

	authKey := r.getAuthKey(req)
	response, err := r.monitoring.KillDaemon(authKey)
	if err != nil {
		if strings.Contains(err.Error(), "authentication failed") {
			r.sendError(w, http.StatusUnauthorized, err.Error())
			return
		}
		r.sendError(w, http.StatusServiceUnavailable, fmt.Sprintf("Failed to shutdown daemon: %v", err))
		return
	}

	r.sendJSON(w, map[string]string{
		"response": response,
		"message":  "Daemon shutdown initiated",
	})
}

func (r *Router) handleAdminSessionLog(w http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodGet {
		r.sendError(w, http.StatusMethodNotAllowed, "Only GET allowed")
		return
	}

	// Get limit from query param, default to 100
	limitStr := req.URL.Query().Get("limit")
	limit := 100
	if limitStr != "" {
		if parsed, err := strconv.Atoi(limitStr); err == nil && parsed > 0 {
			limit = parsed
		}
	}

	entries := r.monitoring.GetSessionLog(limit)
	r.sendJSON(w, map[string]interface{}{
		"entries": entries,
		"count":   len(entries),
	})
}

func (r *Router) handleAdminSessionErrors(w http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodGet {
		r.sendError(w, http.StatusMethodNotAllowed, "Only GET allowed")
		return
	}

	// Get limit from query param, default to 10
	limitStr := req.URL.Query().Get("limit")
	limit := 10
	if limitStr != "" {
		if parsed, err := strconv.Atoi(limitStr); err == nil && parsed > 0 {
			limit = parsed
		}
	}

	errors := r.monitoring.GetSessionErrors(limit)
	r.sendJSON(w, map[string]interface{}{
		"errors": errors,
		"count":  len(errors),
	})
}

// XML Passthrough Handlers - Return raw XML with comprehensive data

func (r *Router) handleXMLObjects(w http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodGet {
		r.sendError(w, http.StatusMethodNotAllowed, "Only GET allowed")
		return
	}

	// Get raw XML from sysmon with all enhanced fields
	xmlData, err := r.monitoring.GetObjectsXML()
	if err != nil {
		r.sendError(w, http.StatusServiceUnavailable, fmt.Sprintf("Failed to get objects XML: %v", err))
		return
	}

	// Return raw XML with proper Content-Type
	w.Header().Set("Content-Type", "application/xml; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(xmlData))
}

func (r *Router) handleXMLObject(w http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodGet {
		r.sendError(w, http.StatusMethodNotAllowed, "Only GET allowed")
		return
	}

	// Extract hostname from URL path
	path := strings.TrimPrefix(req.URL.Path, "/api/xml/object/")
	hostname := strings.TrimSpace(path)

	if hostname == "" {
		r.sendError(w, http.StatusBadRequest, "Hostname required")
		return
	}

	// Get raw XML for single object
	xmlData, err := r.monitoring.GetObjectXML(hostname)
	if err != nil {
		if strings.Contains(err.Error(), "object not found") {
			r.sendError(w, http.StatusNotFound, err.Error())
			return
		}
		r.sendError(w, http.StatusServiceUnavailable, fmt.Sprintf("Failed to get object XML: %v", err))
		return
	}

	// Return raw XML with proper Content-Type
	w.Header().Set("Content-Type", "application/xml; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(xmlData))
}

// Helper functions
func (r *Router) sendJSON(w http.ResponseWriter, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(data)
}

func (r *Router) sendError(w http.ResponseWriter, status int, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(models.APIError{
		Error:   http.StatusText(status),
		Message: message,
	})
}

func (r *Router) sendErrorWithDetails(w http.ResponseWriter, status int, message string, details interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(models.APIError{
		Error:   http.StatusText(status),
		Message: message,
		Details: details,
	})
}

func (r *Router) getUserInfo(req *http.Request) (user, ip string) {
	// Try to get user from auth headers (if implemented)
	user = req.Header.Get("X-User")
	if user == "" {
		user = "anonymous"
	}

	// Get IP from X-Forwarded-For or RemoteAddr
	ip = req.Header.Get("X-Forwarded-For")
	if ip == "" {
		ip = req.Header.Get("X-Real-IP")
	}
	if ip == "" {
		ip = req.RemoteAddr
	}

	return user, ip
}

func (r *Router) getAuthKey(req *http.Request) string {
	// Get auth key from X-Auth-Key header
	return req.Header.Get("X-Auth-Key")
}

func (r *Router) addCORS(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, X-User, X-Auth-Key")

		if req.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}

		next.ServeHTTP(w, req)
	})
}
