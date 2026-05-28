package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"sysmon-web/internal/auth"
	"sysmon-web/internal/config"
	"sysmon-web/internal/middleware"
	"sysmon-web/internal/models"
	"sysmon-web/internal/monitoring"
	"sysmon-web/internal/push"
)

// Router holds the API handlers
type Router struct {
	config     *config.Service
	monitoring *monitoring.Service
	push       *push.Service
	auth       *auth.Service
	mux        *http.ServeMux
	metrics    *middleware.MetricsCollector
}

// NewRouter creates a new API router
func NewRouter(cfg *config.Service, mon *monitoring.Service, pushSvc *push.Service, authSvc *auth.Service) http.Handler {
	metrics := middleware.NewMetricsCollector()

	r := &Router{
		config:     cfg,
		monitoring: mon,
		push:       pushSvc,
		auth:       authSvc,
		mux:        http.NewServeMux(),
		metrics:    metrics,
	}

	// Configuration endpoints (admin only — config contains secrets)
	r.mux.HandleFunc("/api/config", auth.RequireAdmin(r.handleConfig))
	r.mux.HandleFunc("/api/config/validate", auth.RequireAdmin(r.handleConfigValidate))
	r.mux.HandleFunc("/api/config/reload", auth.RequireAdmin(r.handleConfigReload))
	r.mux.HandleFunc("/api/config/raw", auth.RequireAdmin(r.handleConfigRaw))

	// Backups (admin only)
	r.mux.HandleFunc("/api/backups", auth.RequireAdmin(r.handleBackups))
	r.mux.HandleFunc("/api/backups/", auth.RequireAdmin(r.handleBackupDetail))

	// Live monitoring
	r.mux.HandleFunc("/api/monitoring/status", r.handleMonitoringStatus)
	r.mux.HandleFunc("/api/monitoring/hosts", r.handleMonitoringHosts)
	r.mux.HandleFunc("/api/monitoring/host/", r.handleMonitoringHost)
	r.mux.HandleFunc("/api/monitoring/stats", r.handleMonitoringStats)
	r.mux.HandleFunc("/api/monitoring/alerts", r.handleMonitoringAlerts)
	r.mux.HandleFunc("/api/monitoring/traps", r.handleMonitoringTraps)
	r.mux.HandleFunc("/api/monitoring/ack/", auth.RequireAdmin(r.handleMonitoringAck))
	r.mux.HandleFunc("/api/monitoring/update/", auth.RequireAdmin(r.handleMonitoringUpdate))
	r.mux.HandleFunc("/api/monitoring/trace/", auth.RequireAdmin(r.handleMonitoringTrace))

	// Bulk operations (admin only)
	r.mux.HandleFunc("/api/monitoring/bulk/ack", auth.RequireAdmin(r.handleBulkAck))
	r.mux.HandleFunc("/api/monitoring/bulk/update", auth.RequireAdmin(r.handleBulkUpdate))
	r.mux.HandleFunc("/api/monitoring/bulk/trace", auth.RequireAdmin(r.handleBulkTrace))

	// Push notifications
	r.mux.HandleFunc("/api/push/subscribe", r.handlePushSubscribe)
	r.mux.HandleFunc("/api/push/me", r.handlePushMe)
	r.mux.HandleFunc("/api/push/subscriptions", auth.RequireAdmin(r.handlePushSubscriptions))
	r.mux.HandleFunc("/api/push/remove/", auth.RequireAdmin(r.handlePushAdminRemove))
	r.mux.HandleFunc("/api/push/log", auth.RequireAdmin(r.handlePushLog))
	r.mux.HandleFunc("/api/push/test", r.handlePushTest)

	// API documentation
	r.mux.HandleFunc("/api/docs", r.handleAPIDocs)
	r.mux.HandleFunc("/api/openapi.yaml", r.handleOpenAPISpec)

	// Metrics
	r.mux.HandleFunc("/api/metrics", r.handleMetrics)

	// XML passthrough endpoint (for host detail - kept for compatibility)
	r.mux.HandleFunc("/api/xml/object/", r.handleXMLObject)

	// Admin/debug endpoints (all require admin role)
	r.mux.HandleFunc("/api/admin/version", auth.RequireAdmin(r.handleAdminVersion))
	r.mux.HandleFunc("/api/admin/debug", auth.RequireAdmin(r.handleAdminDebug))
	r.mux.HandleFunc("/api/admin/snmpd", auth.RequireAdmin(r.handleAdminSNMPDebug))
	r.mux.HandleFunc("/api/admin/expiredns", auth.RequireAdmin(r.handleAdminExpireDNS))
	r.mux.HandleFunc("/api/admin/printq", auth.RequireAdmin(r.handleAdminPrintQ))
	r.mux.HandleFunc("/api/admin/nfd", auth.RequireAdmin(r.handleAdminNFD))
	r.mux.HandleFunc("/api/admin/killit", auth.RequireAdmin(r.handleAdminKillit))
	r.mux.HandleFunc("/api/admin/session-log", auth.RequireAdmin(r.handleAdminSessionLog))
	r.mux.HandleFunc("/api/admin/session-errors", auth.RequireAdmin(r.handleAdminSessionErrors))

	// Auth endpoints
	r.mux.HandleFunc("/api/auth/login", r.handleAuthLogin)
	r.mux.HandleFunc("/api/auth/logout", r.handleAuthLogout)
	r.mux.HandleFunc("/api/auth/me", r.handleAuthMe)
	r.mux.HandleFunc("/api/auth/users", auth.RequireAdmin(r.handleAuthUsers))
	r.mux.HandleFunc("/api/auth/users/", auth.RequireAdmin(r.handleAuthUserAction))

	// HTML pages
	r.mux.HandleFunc("/", r.handleDashboard)
	r.mux.HandleFunc("/login.html", r.handleLoginPage)
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

	// Apply middleware chain
	var handler http.Handler = r.mux
	handler = rateLimiter.Middleware(handler)
	handler = cache.Middleware(handler)
	handler = metrics.Middleware(handler)

	// Limit request body size to 1MB
	handler = http.MaxBytesHandler(handler, 1<<20)
	handler = auth.RequireAuth(authSvc, handler)
	handler = r.addCORS(handler)
	handler = middleware.Recovery(handler)

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
		if req.Method != http.MethodPost {
			r.sendError(w, http.StatusMethodNotAllowed, "Only POST allowed for restore")
			return
		}

		filename = strings.TrimSuffix(filename, "/restore")
		user, ip := r.getUserInfo(req)

		if err := r.config.RestoreBackup(filename, user, ip); err != nil {
			r.sendError(w, http.StatusBadRequest, err.Error())
			return
		}

		r.sendJSON(w, map[string]string{"status": "restored"})
		return
	}

	if req.Method != http.MethodGet {
		r.sendError(w, http.StatusMethodNotAllowed, "Only GET allowed")
		return
	}

	backups, err := r.config.ListBackups()
	if err != nil {
		r.sendError(w, http.StatusInternalServerError, err.Error())
		return
	}

	for _, backup := range backups {
		if backup.Filename == filename {
			r.sendJSON(w, backup)
			return
		}
	}

	r.sendError(w, http.StatusNotFound, fmt.Sprintf("Backup %s not found", filename))
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

func (r *Router) handleMonitoringHost(w http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodGet {
		r.sendError(w, http.StatusMethodNotAllowed, "Only GET allowed")
		return
	}

	hostname := strings.TrimPrefix(req.URL.Path, "/api/monitoring/host/")
	hostname = strings.TrimSpace(hostname)
	if hostname == "" {
		r.sendError(w, http.StatusBadRequest, "Hostname required")
		return
	}

	host, err := r.monitoring.GetHostStatus(hostname)
	if err != nil {
		if strings.Contains(err.Error(), "not found") {
			r.sendError(w, http.StatusNotFound, fmt.Sprintf("Host %s not found", hostname))
			return
		}
		r.sendError(w, http.StatusServiceUnavailable, fmt.Sprintf("Failed to get host status: %v", err))
		return
	}

	r.sendJSON(w, host)
}

func (r *Router) handleMonitoringStats(w http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodGet {
		r.sendError(w, http.StatusMethodNotAllowed, "Only GET allowed")
		return
	}

	stats, err := r.monitoring.GetStatistics()
	if err != nil {
		r.sendError(w, http.StatusServiceUnavailable, fmt.Sprintf("Failed to get statistics: %v", err))
		return
	}

	r.sendJSON(w, stats)
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

		// Return paginated traps with sources and summary (not paginated)
		// This maintains consistency with non-paginated response structure
		response := map[string]interface{}{
			"data":         paginatedTraps,
			"total":        total,
			"page":         params.Page,
			"limit":        params.Limit,
			"total_pages":  totalPages,
			"trap_sources": traps.TrapSources,
			"summary":      traps.Summary,
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
	authKey := r.getSysmonAuthKey()

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
		Note string `json:"note"`
	}
	if err := json.NewDecoder(req.Body).Decode(&body); err != nil {
		r.sendError(w, http.StatusBadRequest, "Invalid JSON body")
		return
	}

	if body.Note == "" {
		r.sendError(w, http.StatusBadRequest, "Note is required")
		return
	}

	authKey := r.getSysmonAuthKey()

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
	authKey := r.getSysmonAuthKey()

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

	authKey := r.getSysmonAuthKey()
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

	authKey := r.getSysmonAuthKey()
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

	authKey := r.getSysmonAuthKey()
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

	authKey := r.getSysmonAuthKey()
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

	authKey := r.getSysmonAuthKey()
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

	authKey := r.getSysmonAuthKey()
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

	authKey := r.getSysmonAuthKey()
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
	}
	if err := json.NewDecoder(req.Body).Decode(&body); err != nil {
		r.sendError(w, http.StatusBadRequest, "Invalid JSON body")
		return
	}

	if len(body.Hostnames) == 0 {
		r.sendError(w, http.StatusBadRequest, "Hostnames array is required and cannot be empty")
		return
	}

	authKey := r.getSysmonAuthKey()

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
		Note string `json:"note"`
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

	authKey := r.getSysmonAuthKey()

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
	}
	if err := json.NewDecoder(req.Body).Decode(&body); err != nil {
		r.sendError(w, http.StatusBadRequest, "Invalid JSON body")
		return
	}

	if len(body.Hostnames) == 0 {
		r.sendError(w, http.StatusBadRequest, "Hostnames array is required and cannot be empty")
		return
	}

	authKey := r.getSysmonAuthKey()
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
	specData, err := os.ReadFile("./api/openapi.yaml")
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

// Auth handlers

func (r *Router) handleAuthLogin(w http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var body struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(req.Body).Decode(&body); err != nil {
		r.sendError(w, http.StatusBadRequest, "Invalid JSON body")
		return
	}

	session, err := r.auth.Login(body.Username, body.Password)
	if err != nil {
		r.sendError(w, http.StatusUnauthorized, "Invalid credentials")
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name:     "sysmon_session",
		Value:    session.Token,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   86400,
	})

	r.sendJSON(w, map[string]string{
		"token":    session.Token,
		"username": session.Username,
		"role":     session.Role,
	})
}

func (r *Router) handleAuthLogout(w http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	sess := r.auth.GetSessionFromRequest(req)
	if sess != nil {
		r.auth.Logout(sess.Token)
	}

	http.SetCookie(w, &http.Cookie{
		Name:   "sysmon_session",
		Value:  "",
		Path:   "/",
		MaxAge: -1,
	})

	r.sendJSON(w, map[string]string{"status": "logged out"})
}

func (r *Router) handleAuthMe(w http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	r.sendJSON(w, map[string]string{
		"username": req.Header.Get("X-Session-User"),
		"role":     req.Header.Get("X-Session-Role"),
	})
}

func (r *Router) handleAuthUsers(w http.ResponseWriter, req *http.Request) {
	switch req.Method {
	case http.MethodGet:
		users := r.auth.ListUsers()
		r.sendJSON(w, map[string]interface{}{
			"users": users,
			"count": len(users),
		})

	case http.MethodPost:
		var body struct {
			Username string `json:"username"`
			Password string `json:"password"`
			Role     string `json:"role"`
		}
		if err := json.NewDecoder(req.Body).Decode(&body); err != nil {
			r.sendError(w, http.StatusBadRequest, "Invalid JSON body")
			return
		}
		if err := r.auth.CreateUser(body.Username, body.Password, body.Role); err != nil {
			r.sendError(w, http.StatusBadRequest, err.Error())
			return
		}
		r.sendJSON(w, map[string]string{"status": "created", "username": body.Username})

	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func (r *Router) handleAuthUserAction(w http.ResponseWriter, req *http.Request) {
	username := strings.TrimPrefix(req.URL.Path, "/api/auth/users/")
	if username == "" {
		r.sendError(w, http.StatusBadRequest, "Username required")
		return
	}

	switch req.Method {
	case http.MethodDelete:
		if username == req.Header.Get("X-Session-User") {
			r.sendError(w, http.StatusBadRequest, "Cannot delete your own account")
			return
		}
		if err := r.auth.DeleteUser(username); err != nil {
			r.sendError(w, http.StatusNotFound, err.Error())
			return
		}
		r.sendJSON(w, map[string]string{"status": "deleted", "username": username})

	case http.MethodPut:
		var body struct {
			Password string `json:"password,omitempty"`
			Role     string `json:"role,omitempty"`
		}
		if err := json.NewDecoder(req.Body).Decode(&body); err != nil {
			r.sendError(w, http.StatusBadRequest, "Invalid JSON body")
			return
		}
		if body.Role != "" && body.Role != "admin" && username == req.Header.Get("X-Session-User") {
			r.sendError(w, http.StatusBadRequest, "Cannot demote your own account")
			return
		}
		if body.Password != "" {
			if err := r.auth.ChangePassword(username, body.Password); err != nil {
				r.sendError(w, http.StatusBadRequest, err.Error())
				return
			}
		}
		if body.Role != "" {
			if err := r.auth.ChangeRole(username, body.Role); err != nil {
				r.sendError(w, http.StatusBadRequest, err.Error())
				return
			}
		}
		r.sendJSON(w, map[string]string{"status": "updated", "username": username})

	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// Push notification handlers


// handlePushMe returns the current user's own push subscriptions.
func (r *Router) handlePushMe(w http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodGet {
		r.sendError(w, http.StatusMethodNotAllowed, "Only GET allowed")
		return
	}
	if r.push == nil {
		r.sendError(w, http.StatusServiceUnavailable, "Push notifications not configured")
		return
	}

	owner := req.Header.Get("X-Session-User")
	subs := r.push.ListSubscriptionsByOwner(owner)

	// Strip api_keys — the app already has its own
	type safeSub struct {
		DeviceToken    string `json:"device_token"`
		Platform       string `json:"platform"`
		Label          string `json:"label,omitempty"`
		CreatedAt      string `json:"created_at"`
		LastSeen       string `json:"last_seen"`
		LastPushAt     string `json:"last_push_at,omitempty"`
		LastPushStatus string `json:"last_push_status,omitempty"`
		PushCount      int64  `json:"push_count"`
	}
	out := make([]safeSub, len(subs))
	for i, s := range subs {
		out[i] = safeSub{
			DeviceToken: s.DeviceToken, Platform: string(s.Platform), Label: s.Label,
			CreatedAt: s.CreatedAt, LastSeen: s.LastSeen,
			LastPushAt: s.LastPushAt, LastPushStatus: s.LastPushStatus,
			PushCount: s.PushCount,
		}
	}
	r.sendJSON(w, map[string]interface{}{
		"subscriptions": out,
		"count":         len(out),
	})
}

func (r *Router) handlePushSubscribe(w http.ResponseWriter, req *http.Request) {
	switch req.Method {
	case http.MethodPost:
		if r.push == nil {
			r.sendError(w, http.StatusServiceUnavailable, "Push notifications not configured")
			return
		}

		var body struct {
			DeviceToken string `json:"device_token"`
			Platform    string `json:"platform"`
			Label       string `json:"label"`
		}
		if err := json.NewDecoder(req.Body).Decode(&body); err != nil {
			r.sendError(w, http.StatusBadRequest, "Invalid JSON body")
			return
		}

		if body.DeviceToken == "" || body.Platform == "" {
			r.sendError(w, http.StatusBadRequest, "device_token and platform are required")
			return
		}

		_, clientIP := r.getUserInfo(req)
		userAgent := req.Header.Get("User-Agent")
		owner := req.Header.Get("X-Session-User")
		apiKey, err := r.push.Subscribe(body.DeviceToken, push.Platform(body.Platform), body.Label, owner, clientIP, userAgent)
		if err != nil {
			r.sendError(w, http.StatusBadRequest, err.Error())
			return
		}

		r.sendJSON(w, map[string]string{
			"status":  "subscribed",
			"api_key": apiKey,
		})

	case http.MethodDelete:
		if r.push == nil {
			r.sendError(w, http.StatusServiceUnavailable, "Push notifications not configured")
			return
		}

		var body struct {
			DeviceToken string `json:"device_token"`
			APIKey      string `json:"api_key,omitempty"`
		}
		if err := json.NewDecoder(req.Body).Decode(&body); err != nil {
			r.sendError(w, http.StatusBadRequest, "Invalid JSON body")
			return
		}

		if body.DeviceToken == "" {
			r.sendError(w, http.StatusBadRequest, "device_token is required")
			return
		}

		// Allow unsubscribe via api_key OR by being the owner of the subscription.
		// Admins can also unsubscribe any device.
		owner := req.Header.Get("X-Session-User")
		role := req.Header.Get("X-Session-Role")
		allowed := role == "admin" ||
			r.push.IsOwner(body.DeviceToken, owner) ||
			(body.APIKey != "" && r.push.ValidateAPIKey(body.DeviceToken, body.APIKey))
		if !allowed {
			r.sendError(w, http.StatusForbidden, "Not authorized to unsubscribe this device")
			return
		}

		if err := r.push.Unsubscribe(body.DeviceToken); err != nil {
			r.sendError(w, http.StatusNotFound, err.Error())
			return
		}

		r.sendJSON(w, map[string]string{"status": "unsubscribed"})

	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func (r *Router) handlePushSubscriptions(w http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodGet {
		r.sendError(w, http.StatusMethodNotAllowed, "Only GET allowed")
		return
	}

	if r.push == nil {
		r.sendError(w, http.StatusServiceUnavailable, "Push notifications not configured")
		return
	}

	subs := r.push.ListSubscriptions()

	// Return all metadata except api_keys
	type adminSubscription struct {
		DeviceToken    string `json:"device_token"`
		Platform       string `json:"platform"`
		Label          string `json:"label,omitempty"`
		CreatedAt      string `json:"created_at"`
		LastSeen       string `json:"last_seen"`
		LastPushAt     string `json:"last_push_at,omitempty"`
		LastPushStatus string `json:"last_push_status,omitempty"`
		PushCount      int64  `json:"push_count"`
		FailCount      int64  `json:"fail_count"`
		IPAddress      string `json:"ip_address,omitempty"`
		UserAgent      string `json:"user_agent,omitempty"`
	}
	out := make([]adminSubscription, len(subs))
	for i, s := range subs {
		out[i] = adminSubscription{
			DeviceToken:    s.DeviceToken,
			Platform:       string(s.Platform),
			Label:          s.Label,
			CreatedAt:      s.CreatedAt,
			LastSeen:       s.LastSeen,
			LastPushAt:     s.LastPushAt,
			LastPushStatus: s.LastPushStatus,
			PushCount:      s.PushCount,
			FailCount:      s.FailCount,
			IPAddress:      s.IPAddress,
			UserAgent:      s.UserAgent,
		}
	}

	r.sendJSON(w, map[string]interface{}{
		"subscriptions": out,
		"count":         len(out),
	})
}

func (r *Router) handlePushAdminRemove(w http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodDelete {
		r.sendError(w, http.StatusMethodNotAllowed, "Only DELETE allowed")
		return
	}

	if r.push == nil {
		r.sendError(w, http.StatusServiceUnavailable, "Push notifications not configured")
		return
	}

	token := strings.TrimPrefix(req.URL.Path, "/api/push/remove/")
	token = strings.TrimSpace(token)
	if token == "" {
		r.sendError(w, http.StatusBadRequest, "Device token required in URL path")
		return
	}

	if err := r.push.AdminRemove(token); err != nil {
		r.sendError(w, http.StatusNotFound, err.Error())
		return
	}

	r.sendJSON(w, map[string]string{
		"status":       "removed",
		"device_token": token,
	})
}

func (r *Router) handlePushLog(w http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodGet {
		r.sendError(w, http.StatusMethodNotAllowed, "Only GET allowed")
		return
	}

	if r.push == nil {
		r.sendError(w, http.StatusServiceUnavailable, "Push notifications not configured")
		return
	}

	limit := 100
	if limitStr := req.URL.Query().Get("limit"); limitStr != "" {
		if parsed, err := strconv.Atoi(limitStr); err == nil && parsed > 0 && parsed <= 1000 {
			limit = parsed
		}
	}

	entries := r.push.GetPushLog(limit)
	r.sendJSON(w, map[string]interface{}{
		"entries": entries,
		"count":   len(entries),
	})
}

func (r *Router) handlePushTest(w http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodPost {
		r.sendError(w, http.StatusMethodNotAllowed, "Only POST allowed")
		return
	}

	if r.push == nil {
		r.sendError(w, http.StatusServiceUnavailable, "Push notifications not configured")
		return
	}

	var body struct {
		APIKey string `json:"api_key"`
	}
	if err := json.NewDecoder(req.Body).Decode(&body); err != nil {
		r.sendError(w, http.StatusBadRequest, "Invalid JSON body")
		return
	}

	if body.APIKey == "" {
		r.sendError(w, http.StatusUnauthorized, "api_key is required")
		return
	}

	// Look up the device by its API key
	token, platform := r.push.FindTokenByAPIKey(body.APIKey)
	if token == "" {
		r.sendError(w, http.StatusForbidden, "Invalid api_key")
		return
	}

	if err := r.push.SendTest(token, platform); err != nil {
		r.sendError(w, http.StatusBadGateway, fmt.Sprintf("Push failed: %v", err))
		return
	}

	r.sendJSON(w, map[string]string{"status": "sent"})
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
	user = req.Header.Get("X-Session-User")
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

func (r *Router) getSysmonAuthKey() string {
	snapshot, err := r.config.GetConfig()
	if err != nil {
		return ""
	}
	return snapshot.Config.Global.AuthKey
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
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")

		if req.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}

		next.ServeHTTP(w, req)
	})
}
