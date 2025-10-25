package api

import (
	"encoding/json"
	"fmt"
	"net/http"
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

	// Configuration endpoints
	r.mux.HandleFunc("/api/config", r.handleConfig)
	r.mux.HandleFunc("/api/config/validate", r.handleConfigValidate)
	r.mux.HandleFunc("/api/config/reload", r.handleConfigReload)
	r.mux.HandleFunc("/api/config/raw", r.handleConfigRaw)

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

	// HTML pages
	r.mux.HandleFunc("/", r.handleDashboard)
	r.mux.HandleFunc("/hosts.html", r.handleHostsPage)
	r.mux.HandleFunc("/traps.html", r.handleTrapsPage)
	r.mux.HandleFunc("/config.html", r.handleConfigPage)

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

func (r *Router) addCORS(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, X-User")

		if req.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}

		next.ServeHTTP(w, req)
	})
}
