package api

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"strconv"
	"strings"
	"time"

	"sysmon-web/internal/config"
	"sysmon-web/internal/middleware"
	"sysmon-web/internal/models"
	"sysmon-web/internal/monitoring"
)

// Router holds the API handlers
type Router struct {
	config     *config.Service
	monitoring *monitoring.Service
	mux        *http.ServeMux
	metrics    *middleware.MetricsCollector
}

// NewRouter creates a new API router
func NewRouter(cfg *config.Service, mon *monitoring.Service) http.Handler {
	metrics := middleware.NewMetricsCollector()

	r := &Router{
		config:     cfg,
		monitoring: mon,
		mux:        http.NewServeMux(),
		metrics:    metrics,
	}

	// Configuration endpoints (file-based)
	r.mux.HandleFunc("/api/config", r.handleConfig)
	r.mux.HandleFunc("/api/config/validate", r.handleConfigValidate)
	r.mux.HandleFunc("/api/config/reload", r.handleConfigReload)
	r.mux.HandleFunc("/api/config/raw", r.handleConfigRaw)

	// Backups
	r.mux.HandleFunc("/api/backups", r.handleBackups)
	r.mux.HandleFunc("/api/backups/", r.handleBackupDetail)

	// Live monitoring
	r.mux.HandleFunc("/api/monitoring/status", r.handleMonitoringStatus)
	r.mux.HandleFunc("/api/monitoring/hosts", r.handleMonitoringHosts)
	r.mux.HandleFunc("/api/monitoring/alerts", r.handleMonitoringAlerts)
	r.mux.HandleFunc("/api/monitoring/traps", r.handleMonitoringTraps)
	r.mux.HandleFunc("/api/monitoring/ack/", r.handleMonitoringAck)
	r.mux.HandleFunc("/api/monitoring/update/", r.handleMonitoringUpdate)
	r.mux.HandleFunc("/api/monitoring/trace/", r.handleMonitoringTrace)

	// Bulk operations
	r.mux.HandleFunc("/api/monitoring/bulk/ack", r.handleBulkAck)
	r.mux.HandleFunc("/api/monitoring/bulk/update", r.handleBulkUpdate)
	r.mux.HandleFunc("/api/monitoring/bulk/trace", r.handleBulkTrace)

	// API documentation
	r.mux.HandleFunc("/api/docs", r.handleAPIDocs)
	r.mux.HandleFunc("/api/openapi.yaml", r.handleOpenAPISpec)

	// Metrics
	r.mux.HandleFunc("/api/metrics", r.handleMetrics)

	// XML passthrough endpoint (for host detail - kept for compatibility)
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
	r.mux.HandleFunc("/metrics.html", r.handleMetricsPage)

	// Serve static files (CSS, JS)
	r.mux.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.Dir("./static"))))

	// Apply rate limiting (60 requests per minute for general API, configurable)
	rateLimiter := middleware.NewRateLimiter(60, 1*time.Minute)

	// Create cache middleware
	cache := middleware.NewCacheConfig()

	// Apply middleware chain: CORS -> Metrics -> Cache -> Rate Limiting -> Handler
	var handler http.Handler = r.mux
	handler = rateLimiter.Middleware(handler)
	handler = cache.Middleware(handler)
	handler = metrics.Middleware(handler)
	handler = r.addCORS(handler)

	return handler
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
			if versionErr, ok := err.(*models.VersionConflictError); ok {
				w.WriteHeader(http.StatusConflict)
				r.sendJSON(w, versionErr)
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

// Backups handlers
func (r *Router) handleBackups(w http.ResponseWriter, req *http.Request) {
	backups, err := r.config.ListBackups()
	if err != nil {
		r.sendError(w, http.StatusInternalServerError, err.Error())
		return
	}

	// Check if pagination is requested
	if req.URL.Query().Get("page") != "" || req.URL.Query().Get("limit") != "" {
		params := r.parsePaginationParams(req)

		total := len(backups)
		start := (params.Page - 1) * params.Limit
		end := start + params.Limit

		if start >= total {
			start = total
			end = total
		} else if end > total {
			end = total
		}

		paginatedBackups := backups[start:end]
		totalPages := (total + params.Limit - 1) / params.Limit
		if totalPages == 0 {
			totalPages = 1
		}

		response := map[string]interface{}{
			"data":        paginatedBackups,
			"total":       total,
			"page":        params.Page,
			"limit":       params.Limit,
			"total_pages": totalPages,
		}
		r.sendJSON(w, response)
	} else {
		// No pagination requested, return all backups (backward compatible)
		r.sendJSON(w, backups)
	}
}

func (r *Router) handleBackupDetail(w http.ResponseWriter, req *http.Request) {
	filename := strings.TrimPrefix(req.URL.Path, "/api/backups/")
	filename = strings.TrimSpace(filename)

	if filename == "" {
		r.sendError(w, http.StatusBadRequest, "backup filename required")
		return
	}

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

	// Check if pagination is requested
	if req.URL.Query().Get("page") != "" || req.URL.Query().Get("limit") != "" {
		params := r.parsePaginationParams(req)

		total := len(status.Hosts)
		start := (params.Page - 1) * params.Limit
		end := start + params.Limit

		if start >= total {
			start = total
			end = total
		} else if end > total {
			end = total
		}

		paginatedHosts := status.Hosts[start:end]
		totalPages := (total + params.Limit - 1) / params.Limit
		if totalPages == 0 {
			totalPages = 1
		}

		response := map[string]interface{}{
			"data":        paginatedHosts,
			"total":       total,
			"page":        params.Page,
			"limit":       params.Limit,
			"total_pages": totalPages,
		}
		r.sendJSON(w, response)
	} else {
		// No pagination requested, return all hosts (backward compatible)
		r.sendJSON(w, status.Hosts)
	}
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

	// Check if pagination is requested
	if req.URL.Query().Get("page") != "" || req.URL.Query().Get("limit") != "" {
		params := r.parsePaginationParams(req)

		total := len(traps.RecentTraps)
		start := (params.Page - 1) * params.Limit
		end := start + params.Limit

		if start >= total {
			start = total
			end = total
		} else if end > total {
			end = total
		}

		paginatedTraps := traps.RecentTraps[start:end]
		totalPages := (total + params.Limit - 1) / params.Limit
		if totalPages == 0 {
			totalPages = 1
		}

		response := map[string]interface{}{
			"data":        paginatedTraps,
			"total":       total,
			"page":        params.Page,
			"limit":       params.Limit,
			"total_pages": totalPages,
		}
		r.sendJSON(w, response)
	} else {
		// No pagination requested, return all traps (backward compatible)
		r.sendJSON(w, traps)
	}
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

// Bulk operation handlers

func (r *Router) handleBulkAck(w http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodPost {
		r.sendError(w, http.StatusMethodNotAllowed, "Only POST allowed")
		return
	}

	// Parse JSON body
	var body struct {
		Hostnames []string `json:"hostnames"`
		AuthKey   string   `json:"auth_key,omitempty"`
	}
	if err := json.NewDecoder(req.Body).Decode(&body); err != nil {
		r.sendError(w, http.StatusBadRequest, "Invalid JSON body")
		return
	}

	if len(body.Hostnames) == 0 {
		r.sendError(w, http.StatusBadRequest, "Hostnames array is required and cannot be empty")
		return
	}

	// Use auth key from body if provided, otherwise from header
	authKey := body.AuthKey
	if authKey == "" {
		authKey = req.Header.Get("X-Auth-Key")
	}

	// Call bulk acknowledge
	results := r.monitoring.BulkAckHosts(body.Hostnames, authKey)

	// Count successes and failures
	successCount := 0
	failureCount := 0
	for _, result := range results {
		if result.Success {
			successCount++
		} else {
			failureCount++
		}
	}

	r.sendJSON(w, map[string]interface{}{
		"status":        "completed",
		"total":         len(body.Hostnames),
		"success_count": successCount,
		"failure_count": failureCount,
		"results":       results,
	})
}

func (r *Router) handleBulkUpdate(w http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodPost {
		r.sendError(w, http.StatusMethodNotAllowed, "Only POST allowed")
		return
	}

	// Parse JSON body
	var body struct {
		Hostnames []string `json:"hostnames"`
		Note      string   `json:"note"`
		AuthKey   string   `json:"auth_key,omitempty"`
	}
	if err := json.NewDecoder(req.Body).Decode(&body); err != nil {
		r.sendError(w, http.StatusBadRequest, "Invalid JSON body")
		return
	}

	if len(body.Hostnames) == 0 {
		r.sendError(w, http.StatusBadRequest, "Hostnames array is required and cannot be empty")
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

	// Call bulk update
	results := r.monitoring.BulkUpdateHosts(body.Hostnames, body.Note, authKey)

	// Count successes and failures
	successCount := 0
	failureCount := 0
	for _, result := range results {
		if result.Success {
			successCount++
		} else {
			failureCount++
		}
	}

	r.sendJSON(w, map[string]interface{}{
		"status":        "completed",
		"total":         len(body.Hostnames),
		"success_count": successCount,
		"failure_count": failureCount,
		"results":       results,
		"note":          body.Note,
	})
}

func (r *Router) handleBulkTrace(w http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodPost {
		r.sendError(w, http.StatusMethodNotAllowed, "Only POST allowed")
		return
	}

	// Parse JSON body
	var body struct {
		Hostnames []string `json:"hostnames"`
		Enable    bool     `json:"enable"`
		AuthKey   string   `json:"auth_key,omitempty"`
	}
	if err := json.NewDecoder(req.Body).Decode(&body); err != nil {
		r.sendError(w, http.StatusBadRequest, "Invalid JSON body")
		return
	}

	if len(body.Hostnames) == 0 {
		r.sendError(w, http.StatusBadRequest, "Hostnames array is required and cannot be empty")
		return
	}

	// Use auth key from body if provided, otherwise from header
	authKey := body.AuthKey
	if authKey == "" {
		authKey = req.Header.Get("X-Auth-Key")
	}

	// Call bulk trace toggle
	results := r.monitoring.BulkToggleTrace(body.Hostnames, body.Enable, authKey)

	// Count successes and failures
	successCount := 0
	failureCount := 0
	for _, result := range results {
		if result.Success {
			successCount++
		} else {
			failureCount++
		}
	}

	r.sendJSON(w, map[string]interface{}{
		"status":        "completed",
		"total":         len(body.Hostnames),
		"success_count": successCount,
		"failure_count": failureCount,
		"results":       results,
		"enable":        body.Enable,
	})
}

// Metrics Handler

func (r *Router) handleMetrics(w http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodGet {
		r.sendError(w, http.StatusMethodNotAllowed, "Only GET allowed")
		return
	}

	metrics := r.metrics.GetMetrics()
	r.sendJSON(w, metrics)
}

// API Documentation Handlers

func (r *Router) handleOpenAPISpec(w http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodGet {
		r.sendError(w, http.StatusMethodNotAllowed, "Only GET allowed")
		return
	}

	// Read OpenAPI spec file
	specData, err := ioutil.ReadFile("./api/openapi.yaml")
	if err != nil {
		r.sendError(w, http.StatusInternalServerError, "Failed to load API specification")
		return
	}

	w.Header().Set("Content-Type", "application/yaml")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.WriteHeader(http.StatusOK)
	w.Write(specData)
}

func (r *Router) handleAPIDocs(w http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodGet {
		r.sendError(w, http.StatusMethodNotAllowed, "Only GET allowed")
		return
	}

	// Serve Swagger UI HTML
	html := `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Sysmon API Documentation</title>
    <link rel="stylesheet" type="text/css" href="https://unpkg.com/swagger-ui-dist@5.10.0/swagger-ui.css">
    <style>
        body {
            margin: 0;
            padding: 0;
        }
    </style>
</head>
<body>
    <div id="swagger-ui"></div>
    <script src="https://unpkg.com/swagger-ui-dist@5.10.0/swagger-ui-bundle.js"></script>
    <script src="https://unpkg.com/swagger-ui-dist@5.10.0/swagger-ui-standalone-preset.js"></script>
    <script>
        window.onload = function() {
            window.ui = SwaggerUIBundle({
                url: "/api/openapi.yaml",
                dom_id: '#swagger-ui',
                deepLinking: true,
                presets: [
                    SwaggerUIBundle.presets.apis,
                    SwaggerUIStandalonePreset
                ],
                plugins: [
                    SwaggerUIBundle.plugins.DownloadUrl
                ],
                layout: "StandaloneLayout",
                tryItOutEnabled: true,
                persistAuthorization: true
            });
        };
    </script>
</body>
</html>`

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(html))
}

// XML Passthrough Handler - Return raw XML for single object (used by host-detail.html)

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

// Pagination helpers
type PaginationParams struct {
	Page  int
	Limit int
	Sort  string
}

type PaginatedResponse struct {
	Data       interface{} `json:"data"`
	Total      int         `json:"total"`
	Page       int         `json:"page"`
	Limit      int         `json:"limit"`
	TotalPages int         `json:"total_pages"`
}

// parsePaginationParams extracts pagination parameters from query string
func (r *Router) parsePaginationParams(req *http.Request) PaginationParams {
	params := PaginationParams{
		Page:  1,
		Limit: 50, // Default limit
		Sort:  "",
	}

	// Parse page number
	if pageStr := req.URL.Query().Get("page"); pageStr != "" {
		if page, err := strconv.Atoi(pageStr); err == nil && page > 0 {
			params.Page = page
		}
	}

	// Parse limit
	if limitStr := req.URL.Query().Get("limit"); limitStr != "" {
		if limit, err := strconv.Atoi(limitStr); err == nil && limit > 0 && limit <= 1000 {
			params.Limit = limit
		}
	}

	// Parse sort field
	params.Sort = req.URL.Query().Get("sort")

	return params
}

// paginateSlice paginates a slice and returns pagination metadata
func (r *Router) paginateSlice(data interface{}, params PaginationParams) PaginatedResponse {
	// Use reflection to handle different slice types
	// For simplicity, we'll assume data is already a slice
	// In a real implementation, you might want to add type checking

	// Calculate pagination
	total := 0
	var paginatedData interface{}

	// For now, we'll handle the common case of []interface{}
	// and let the caller handle type conversion if needed
	switch v := data.(type) {
	case []interface{}:
		total = len(v)
		start := (params.Page - 1) * params.Limit
		end := start + params.Limit

		if start >= total {
			paginatedData = []interface{}{}
		} else {
			if end > total {
				end = total
			}
			paginatedData = v[start:end]
		}
	default:
		// If not a slice we recognize, return everything
		paginatedData = data
	}

	totalPages := (total + params.Limit - 1) / params.Limit
	if totalPages == 0 {
		totalPages = 1
	}

	return PaginatedResponse{
		Data:       paginatedData,
		Total:      total,
		Page:       params.Page,
		Limit:      params.Limit,
		TotalPages: totalPages,
	}
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
