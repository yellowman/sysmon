package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"sysmon-web/internal/auth"
	"sysmon-web/internal/config"
	"sysmon-web/internal/middleware"
	"sysmon-web/internal/models"
	"sysmon-web/internal/monitoring"
	"sysmon-web/internal/push"
	"sysmon-web/internal/settings"
	"sysmon-web/internal/templates"
)

// Router holds the API handlers
// PushFactory rebuilds the push service from a Config. The router calls
// it on a settings change if the boot-time push service is nil (e.g.
// push.db was unwritable at boot but the operator has since fixed
// permissions), so configuration changes don't require a process
// restart to recover.
type PushFactory func(push.Config) (*push.Service, error)

type Router struct {
	config     *config.Service
	monitoring *monitoring.Service
	// push is an atomic pointer so handler reads are race-free without a
	// lock; per-call safety against Stop is handled inside the push
	// Service itself (opsMu + ErrServiceStopped). pushInitMu serializes
	// the few writers (lazy init, shutdown) so we never end up with two
	// live services or a torn pointer swap.
	push        atomic.Pointer[push.Service]
	pushInitMu  sync.Mutex
	pushFactory PushFactory
	auth        *auth.Service
	settings    *settings.Store
	mux         *http.ServeMux
	metrics     *middleware.MetricsCollector

	// Cached sysmond PID (the daemon doesn't report it; we read the
	// pidfile). Cached so delta polls don't hit config+disk every request.
	pidMu  sync.Mutex
	pidVal int
	pidAt  time.Time
}

// NewRouter creates a new API router and returns the wrapped handler
// plus a shutdown func. The shutdown func stops whichever push service
// the router currently owns - the boot instance OR one created later by
// a lazy reinit - so the watcher goroutine and push.db handle are
// always released by the same owner. Callers should defer it.
func NewRouter(cfg *config.Service, mon *monitoring.Service, pushSvc *push.Service, pushFactory PushFactory, authSvc *auth.Service, settingsStore *settings.Store) (http.Handler, func()) {
	metrics := middleware.NewMetricsCollector()

	r := &Router{
		config:      cfg,
		monitoring:  mon,
		pushFactory: pushFactory,
		auth:        authSvc,
		settings:    settingsStore,
		mux:         http.NewServeMux(),
		metrics:     metrics,
	}
	if pushSvc != nil {
		r.push.Store(pushSvc)
	}
	// Alerter traffic (alert-only peers on the agent listener) delivers
	// through whatever push service is current; re-pointed whenever the
	// service is hot-swapped (see reconfigurePush).
	if pushSvc != nil {
		mon.SetAlertSink(pushSvc.ExternalAlert)
	}

	// Configuration endpoints (admin only - config contains secrets)
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
	r.mux.HandleFunc("/api/sites", r.handleSites)
	r.mux.HandleFunc("/api/alerters", r.handleAlerters)
	r.mux.HandleFunc("/api/alerters/nickname", auth.RequireAdmin(r.handleAlerterNickname))

	// Config distribution. Everything that changes what a box runs is
	// admin-only and POST, so no stale tab or link prefetch can deliver a
	// config.
	//
	// Reading splits in two, and the line is content, not verb. Per-site
	// STATUS - which generation a box runs, whether it has drifted - is
	// open to anyone who can see the UI, because that belongs on a
	// wallboard. Config CONTENT is admin-only, because a config file
	// holds config authkey, aggregator-token, SNMP communities and
	// radius secrets. A GET that returns file bytes is as sensitive as
	// /api/config itself and is gated the same way.
	r.mux.HandleFunc("/api/config/fleet", r.handleConfigFleet)
	r.mux.HandleFunc("/api/config/site/", auth.RequireAdmin(r.handleConfigSite))
	r.mux.HandleFunc("/api/config/generations/", auth.RequireAdmin(r.handleConfigGenerations))
	r.mux.HandleFunc("/api/config/adopt/", auth.RequireAdmin(r.handleConfigAdopt))
	r.mux.HandleFunc("/api/config/stage/", auth.RequireAdmin(r.handleConfigStage))
	r.mux.HandleFunc("/api/config/deliver/", auth.RequireAdmin(r.handleConfigDeliver))
	r.mux.HandleFunc("/api/config/rollback/", auth.RequireAdmin(r.handleConfigRollback))
	r.mux.HandleFunc("/api/config/revert/", auth.RequireAdmin(r.handleConfigRevert))
	r.mux.HandleFunc("/api/settings/agents", auth.RequireAdmin(r.handleAgentTokens))
	r.mux.HandleFunc("/api/settings/agents/revoke/", auth.RequireAdmin(r.handleAgentRevoke))
	r.mux.HandleFunc("/api/settings/agents/ca", auth.RequireAdmin(r.handleAgentCA))
	r.mux.HandleFunc("/api/config/rollout", func(w http.ResponseWriter, req *http.Request) {
		if req.Method == http.MethodGet {
			r.handleConfigRolloutStatus(w, req)
			return
		}
		auth.RequireAdmin(r.handleConfigRollout)(w, req)
	})
	r.mux.HandleFunc("/api/monitoring/history", r.handleMonitoringHistory)
	r.mux.HandleFunc("/api/map/layout", r.handleMapLayout)
	// GET is open because the map's "add a device" modal needs it for
	// any logged-in user; PUT stores a custom set that becomes config,
	// so it is gated inside the handler.
	r.mux.HandleFunc("/api/templates", r.handleTemplates)
	r.mux.HandleFunc("/api/templates/expand", r.handleTemplateExpand)
	r.mux.HandleFunc("/api/monitoring/ack/", auth.RequireAdmin(r.handleMonitoringAck))
	r.mux.HandleFunc("/api/monitoring/unack/", auth.RequireAdmin(r.handleMonitoringUnack))
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
	r.mux.HandleFunc("/api/push/health", auth.RequireAdmin(r.handlePushHealth))
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

	// Web-only settings (stored in bbolt, not sysmon.conf) - admin only
	// because the push tab carries FCM credentials / APNs PEMs.
	r.mux.HandleFunc("/api/settings/push", auth.RequireAdmin(r.handleSettingsPush))
	r.mux.HandleFunc("/api/settings/push/fcm-credentials", auth.RequireAdmin(r.handleSettingsPushFCM))
	r.mux.HandleFunc("/api/settings/push/apns", auth.RequireAdmin(r.handleSettingsPushAPNs))

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
	r.mux.HandleFunc("/history.html", r.handleHistoryPage)
	r.mux.HandleFunc("/map.html", r.handleMapPage)
	r.mux.HandleFunc("/config.html", r.handleConfigPage)
	r.mux.HandleFunc("/fleet.html", r.handleFleetPage)
	r.mux.HandleFunc("/agents.html", r.handleAgentsPage)
	r.mux.HandleFunc("/templates.html", r.handleTemplatesPage)
	r.mux.HandleFunc("/admin.html", r.handleAdminPage)
	r.mux.HandleFunc("/metrics.html", r.handleMetricsPage)

	// The UI's assets - Tailwind build, Alpine, Chart.js, Font Awesome,
	// fonts - are self-hosted and served from here, so the console works
	// on a network with no route to the internet.
	r.mux.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.Dir(staticDir))))

	// Rate limiting, split by what each limit is protecting against.
	//
	// RequireAuth sits outside this in the chain, so almost everything
	// that reaches a limiter already carries a valid session - the
	// general bucket only has to bound runaway clients, and the UI's own
	// polling across a handful of open tabs is legitimate traffic.
	//
	// /api/auth/login is the exception: RequireAuth lets it through
	// unauthenticated, so it is the brute-force surface and gets its own
	// small bucket.
	//
	// /api/auth/logout is never limited. It needs a valid session and
	// only deletes it, and a 429 here leaves a session the browser
	// cannot end - the HttpOnly cookie only dies on the server's say-so.
	loginLimiter := middleware.NewRateLimiter(10, 1*time.Minute)
	generalLimiter := middleware.NewRateLimiter(300, 1*time.Minute)

	// Create cache middleware
	cache := middleware.NewCacheConfig()

	// Apply middleware chain
	unlimited := http.Handler(r.mux)
	limited := generalLimiter.Middleware(r.mux)
	loginLimited := loginLimiter.Middleware(r.mux)
	var handler http.Handler = http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		switch req.URL.Path {
		case "/api/auth/logout":
			unlimited.ServeHTTP(w, req)
		case "/api/auth/login":
			loginLimited.ServeHTTP(w, req)
		default:
			limited.ServeHTTP(w, req)
		}
	})
	handler = cache.Middleware(handler)
	handler = metrics.Middleware(handler)

	// Limit request body size to 1MB
	handler = http.MaxBytesHandler(handler, 1<<20)
	handler = auth.RequireAuth(authSvc, handler)
	handler = r.addCORS(handler)
	handler = middleware.Recovery(handler)

	return handler, r.stopPush
}

// stopPush stops whichever push service the router currently holds and
// clears the pointer. Idempotent (push.Service.Stop is guarded by a
// sync.Once, and the swap-to-nil short-circuits subsequent calls).
func (r *Router) stopPush() {
	r.pushInitMu.Lock()
	defer r.pushInitMu.Unlock()
	if svc := r.push.Swap(nil); svc != nil {
		svc.Stop()
	}
}

// Config handlers
func (r *Router) handleConfig(w http.ResponseWriter, req *http.Request) {
	if site := remoteSite(req); site != "" {
		switch req.Method {
		case http.MethodGet:
			r.handleConfigSiteGet(w, site)
		case http.MethodPut:
			r.handleConfigSitePut(w, req, site)
		default:
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		}
		return
	}

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
	if site := remoteSite(req); site != "" {
		switch req.Method {
		case http.MethodGet:
			r.handleConfigRawSiteGet(w, site)
		case http.MethodPut:
			r.handleConfigRawSitePut(w, req, site)
		default:
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		}
		return
	}

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
	// Make sure the cache is warm (the background poller normally keeps it
	// so, but on a cold start this primes it and surfaces a real error).
	status, err := r.monitoring.GetStatus()
	if err != nil {
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

	// ?site= narrows to one daemon, so a client watching one site never
	// downloads the rest of the fleet.
	site := req.URL.Query().Get("site")

	// Delta mode: ?since=<rev> returns only what changed, for cheap live
	// polling (and the basis for an SSE stream later).
	if sinceStr := req.URL.Query().Get("since"); sinceStr != "" {
		since, perr := strconv.ParseInt(sinceStr, 10, 64)
		if perr != nil {
			r.sendError(w, http.StatusBadRequest, "invalid 'since' parameter")
			return
		}
		delta := r.monitoring.GetDelta(since)
		if site != "" {
			delta = monitoring.FilterDeltaSite(delta, site)
		}
		if delta.Daemon.PID == 0 {
			delta.Daemon.PID = r.daemonPID()
		}
		r.sendJSON(w, delta)
		return
	}

	if site != "" {
		status = monitoring.FilterSite(status, site)
	}

	// sysmond's TCP protocol doesn't expose its PID; read it from the
	// pidfile configured in sysmon.conf so the dashboard isn't stuck
	// showing "PID 0".
	if status.Daemon.PID == 0 {
		status.Daemon.PID = r.daemonPID()
	}

	r.sendJSON(w, status)
}

// daemonPID returns the sysmond PID, cached for 30s so delta polls don't
// re-read config + the pidfile on every request. The PID only changes on
// a daemon restart, so 30s staleness is fine.
func (r *Router) daemonPID() int {
	r.pidMu.Lock()
	defer r.pidMu.Unlock()
	if time.Since(r.pidAt) < 30*time.Second && r.pidVal != 0 {
		return r.pidVal
	}
	r.pidVal = r.readDaemonPID()
	r.pidAt = time.Now()
	return r.pidVal
}

func (r *Router) readDaemonPID() int {
	snapshot, err := r.config.GetConfig()
	if err != nil || snapshot == nil {
		return 0
	}
	path := snapshot.Config.Global.PidFile
	if path == "" {
		return 0
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return 0
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(data)))
	if err != nil || pid <= 0 {
		// A POSIX PID is strictly positive; a stale or corrupted pidfile
		// with 0 or a negative value should not be surfaced as if it
		// were the live daemon. Fall back to "unknown".
		return 0
	}
	return pid
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

// handleSites lists the fleet, so a site picker can offer names rather
// than asking someone to type one. minted counts the boxes with tokens
// here at all - connected or not. The editors use it to decide whether
// an unselected page may take the only box for granted: one minted box
// is unambiguous, several are a question, even when just one happens
// to be online.
func (r *Router) handleSites(w http.ResponseWriter, req *http.Request) {
	minted := 0
	if r.settings != nil {
		if tokens, err := r.settings.ListAgentTokens(); err == nil {
			for _, t := range tokens {
				// Alerters have no config to edit, so they do not
				// count toward the pickers' ambiguity. A token nothing
				// has used yet has no kind and counts conservatively.
				if !t.Revoked && t.Kind != settings.KindAlerter {
					minted++
				}
			}
		}
	}
	r.sendJSON(w, map[string]interface{}{
		"sites":  r.monitoring.Sites(),
		"minted": minted,
	})
}

// handleAlerters lists the alert-only peers seen since this process
// started - connected or not. They are shown beside the fleet, never in
// it: an alerter has no hosts, no config, no generations, just alerts.
func (r *Router) handleAlerters(w http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodGet {
		r.sendError(w, http.StatusMethodNotAllowed, "Only GET allowed")
		return
	}
	list := r.monitoring.Alerters()
	// The nickname lives on the minted token's record, where the admin
	// edits it; joined in here so the card can show it.
	if r.settings != nil {
		for i := range list {
			if tok, ok := r.settings.GetAgentToken(list[i].Name); ok {
				list[i].Nickname = tok.Label
			}
		}
	}
	r.sendJSON(w, map[string]interface{}{
		"alerters": list,
		"count":    len(list),
	})
}

// handleAlerterNickname sets (or clears, with an empty label) the
// operator's nickname for an alerter - the name its alerts display in
// place of whatever the application calls itself.
func (r *Router) handleAlerterNickname(w http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodPut {
		r.sendError(w, http.StatusMethodNotAllowed, "Only PUT allowed")
		return
	}
	if r.settings == nil {
		r.sendError(w, http.StatusServiceUnavailable, "no settings store")
		return
	}
	var body struct {
		Name     string `json:"name"`
		Nickname string `json:"nickname"`
	}
	if err := json.NewDecoder(req.Body).Decode(&body); err != nil {
		r.sendError(w, http.StatusBadRequest, "Invalid JSON")
		return
	}
	// Only a token an alerter has actually claimed is renameable here.
	// A sysmond's token answering to this endpoint would let its Label
	// (which other pages use for other things) be edited under the
	// guise of an alerter nickname.
	tok, ok := r.settings.GetAgentToken(body.Name)
	if !ok || tok.Kind != settings.KindAlerter {
		r.sendError(w, http.StatusNotFound, "no such alerter")
		return
	}
	body.Nickname = monitoring.TruncateRunes(body.Nickname, 128)
	if err := r.settings.SetAgentLabel(body.Name, body.Nickname); err != nil {
		// Never confirm a rename the disk refused.
		r.sendError(w, http.StatusInternalServerError, "could not store the nickname: "+err.Error())
		return
	}
	r.sendJSON(w, map[string]string{"name": body.Name, "nickname": body.Nickname})
}

func (r *Router) handleMonitoringTraps(w http.ResponseWriter, req *http.Request) {
	// Authenticating to sysmond is what unlocks the community string in
	// the trap records; without it the daemon withholds that field.
	traps, err := r.monitoring.GetTraps(r.getSysmonAuthKey())
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

// handleTemplates lists device templates (shipped set merged with any
// stored customisations) and saves the custom set.
func (r *Router) handleTemplates(w http.ResponseWriter, req *http.Request) {
	switch req.Method {
	case http.MethodGet:
		var stored []templates.Template
		if r.settings != nil {
			if data, err := r.settings.GetTemplates(); err == nil {
				stored, _ = templates.Decode(data)
			}
		}
		r.sendJSON(w, map[string]interface{}{"templates": templates.Merge(stored)})

	case http.MethodPut:
		// Saving templates writes what later becomes sysmon.conf, so it
		// belongs on the same side of the line as config content.
		if req.Header.Get("X-Session-Role") != auth.RoleAdmin {
			r.sendError(w, http.StatusForbidden, "Admin access required")
			return
		}
		if r.settings == nil {
			r.sendError(w, http.StatusServiceUnavailable, "Settings store not configured")
			return
		}
		body, err := io.ReadAll(io.LimitReader(req.Body, 1<<20))
		if err != nil {
			r.sendError(w, http.StatusBadRequest, err.Error())
			return
		}
		if _, err := templates.Decode(body); err != nil {
			r.sendError(w, http.StatusBadRequest, "templates must be a JSON array: "+err.Error())
			return
		}
		if err := r.settings.SetTemplates(body); err != nil {
			r.sendError(w, http.StatusInternalServerError, err.Error())
			return
		}
		r.sendJSON(w, map[string]string{"status": "saved"})

	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// handleTemplateExpand turns a template plus device parameters into the
// objects to add. Expansion lives on the server so the same rules apply
// to every caller, and so it can be tested.
func (r *Router) handleTemplateExpand(w http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodPost {
		r.sendError(w, http.StatusMethodNotAllowed, "Only POST allowed")
		return
	}
	var p templates.Params
	if err := json.NewDecoder(req.Body).Decode(&p); err != nil {
		r.sendError(w, http.StatusBadRequest, "Invalid JSON body")
		return
	}
	var stored []templates.Template
	if r.settings != nil {
		if data, err := r.settings.GetTemplates(); err == nil {
			stored, _ = templates.Decode(data)
		}
	}
	var found *templates.Template
	for _, t := range templates.Merge(stored) {
		if t.ID == p.TemplateID {
			tt := t
			found = &tt
			break
		}
	}
	if found == nil {
		r.sendError(w, http.StatusNotFound, "Unknown template: "+p.TemplateID)
		return
	}
	hosts, err := templates.Expand(found, p)
	if err != nil {
		r.sendError(w, http.StatusBadRequest, err.Error())
		return
	}
	r.sendJSON(w, map[string]interface{}{"hosts": hosts, "count": len(hosts)})
}

// handleMapLayout stores hand-placed node positions for the dependency
// map. Kept server-side (not localStorage) so a layout an operator
// arranges is what everyone else sees too.
func (r *Router) handleMapLayout(w http.ResponseWriter, req *http.Request) {
	if r.settings == nil {
		r.sendError(w, http.StatusServiceUnavailable, "Settings store not configured")
		return
	}
	switch req.Method {
	case http.MethodGet:
		data, err := r.settings.GetMapLayout()
		if err != nil {
			r.sendError(w, http.StatusInternalServerError, err.Error())
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write(data)

	case http.MethodPut:
		body, err := io.ReadAll(io.LimitReader(req.Body, 1<<20))
		if err != nil {
			r.sendError(w, http.StatusBadRequest, err.Error())
			return
		}
		var probe map[string]struct{ X, Y float64 }
		if err := json.Unmarshal(body, &probe); err != nil {
			r.sendError(w, http.StatusBadRequest, "layout must be an object of {x,y} positions")
			return
		}
		if err := r.settings.SetMapLayout(body); err != nil {
			r.sendError(w, http.StatusInternalServerError, err.Error())
			return
		}
		r.sendJSON(w, map[string]string{"status": "saved"})

	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// handleMonitoringHistory returns recent host up/down transitions,
// newest first.
func (r *Router) handleMonitoringHistory(w http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodGet {
		r.sendError(w, http.StatusMethodNotAllowed, "Only GET allowed")
		return
	}
	hist := r.monitoring.History()
	if hist == nil {
		r.sendJSON(w, map[string]interface{}{"events": []interface{}{}, "count": 0, "available": false})
		return
	}
	limit := 200
	if v := req.URL.Query().Get("limit"); v != "" {
		if parsed, err := strconv.Atoi(v); err == nil && parsed > 0 && parsed <= 1000 {
			limit = parsed
		}
	}
	// Two windows only: the near-term default and the month the store
	// retains. Anything else is somebody probing, and gets the default.
	window := monitoring.HistoryDefaultWindow
	if req.URL.Query().Get("window") == "30d" {
		window = 30 * 24 * time.Hour
	}
	events := hist.Recent(limit, window)
	r.sendJSON(w, map[string]interface{}{"events": events, "count": len(events), "available": true, "window": req.URL.Query().Get("window")})
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

	// The note is the whole point of an ack: "seen, and here is what I
	// know". Anonymous acks are refused.
	var body struct {
		Note string `json:"note"`
	}
	_ = json.NewDecoder(req.Body).Decode(&body)
	body.Note = strings.TrimSpace(body.Note)
	if body.Note == "" {
		r.sendError(w, http.StatusBadRequest, "A note is required to acknowledge - say what you know")
		return
	}

	// Get auth key from header or body
	authKey := r.getSysmonAuthKey()

	err := r.monitoring.AckHost(hostname, body.Note, authKey)
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
		"status":          "success",
		"hostname":        hostname,
		"tracing_enabled": enabled,
		"message":         fmt.Sprintf("Tracing %s for %s", map[bool]string{true: "enabled", false: "disabled"}[enabled], hostname),
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

	// Which box. Empty is fine on a single-box install; with a
	// fleet the caller has to say, because these act on one daemon.
	site := req.URL.Query().Get("site")
	response, err := r.monitoring.ToggleDebug(site)
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

	// Which box. Empty is fine on a single-box install; with a
	// fleet the caller has to say, because these act on one daemon.
	site := req.URL.Query().Get("site")
	response, err := r.monitoring.ToggleSNMPDebug(site)
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

	// Which box. Empty is fine on a single-box install; with a
	// fleet the caller has to say, because these act on one daemon.
	site := req.URL.Query().Get("site")
	response, err := r.monitoring.ExpireDNS(site)
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

	// Which box. Empty is fine on a single-box install; with a
	// fleet the caller has to say, because these act on one daemon.
	site := req.URL.Query().Get("site")
	response, err := r.monitoring.PrintQueue(site)
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

	// Which box. Empty is fine on a single-box install; with a
	// fleet the caller has to say, because these act on one daemon.
	site := req.URL.Query().Get("site")
	response, err := r.monitoring.GetNextFD(site)
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

	// Which box. Empty is fine on a single-box install; with a
	// fleet the caller has to say, because these act on one daemon.
	site := req.URL.Query().Get("site")
	response, err := r.monitoring.KillDaemon(site)
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

	// ?site= narrows to one sysmond's exchanges; empty means the fleet.
	entries := r.monitoring.GetSessionLog(limit, req.URL.Query().Get("site"))
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

	errors := r.monitoring.GetSessionErrors(limit, req.URL.Query().Get("site"))
	r.sendJSON(w, map[string]interface{}{
		"errors": errors,
		"count":  len(errors),
	})
}

// Bulk operation handlers

func (r *Router) handleMonitoringUnack(w http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodPost {
		r.sendError(w, http.StatusMethodNotAllowed, "Only POST allowed")
		return
	}
	hostname := strings.TrimPrefix(req.URL.Path, "/api/monitoring/unack/")
	if hostname == "" {
		r.sendError(w, http.StatusBadRequest, "Hostname required")
		return
	}
	if err := r.monitoring.UnackHost(hostname, r.getSysmonAuthKey()); err != nil {
		r.sendError(w, http.StatusServiceUnavailable, fmt.Sprintf("Failed to un-acknowledge host: %v", err))
		return
	}
	r.sendJSON(w, map[string]string{
		"status":   "success",
		"message":  fmt.Sprintf("Host %s un-acknowledged", hostname),
		"hostname": hostname,
	})
}

func (r *Router) handleBulkAck(w http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodPost {
		r.sendError(w, http.StatusMethodNotAllowed, "Only POST allowed")
		return
	}

	// Parse JSON body
	var body struct {
		Hostnames []string `json:"hostnames"`
		Note      string   `json:"note"`
	}
	if err := json.NewDecoder(req.Body).Decode(&body); err != nil {
		r.sendError(w, http.StatusBadRequest, "Invalid JSON body")
		return
	}

	if len(body.Hostnames) == 0 {
		r.sendError(w, http.StatusBadRequest, "Hostnames array is required and cannot be empty")
		return
	}
	body.Note = strings.TrimSpace(body.Note)
	if body.Note == "" {
		r.sendError(w, http.StatusBadRequest, "A note is required to acknowledge - say what you know")
		return
	}

	authKey := r.getSysmonAuthKey()

	// Call bulk acknowledge
	results := r.monitoring.BulkAckHosts(body.Hostnames, body.Note, authKey)

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
		// 10 years - sessions don't expire on the backend; this cookie
		// lasts as long as the browser keeps it. Explicit logout, an
		// admin kick, or a password change still revokes the session.
		MaxAge: 10 * 365 * 86400,
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
	svc := r.push.Load()
	if svc == nil {
		r.sendError(w, http.StatusServiceUnavailable, "Push notifications not configured")
		return
	}

	owner := req.Header.Get("X-Session-User")
	subs := svc.ListSubscriptionsByOwner(owner)

	// Strip api_keys - the app already has its own
	type safeSub struct {
		DeviceToken    string `json:"device_token"`
		Platform       string `json:"platform"`
		Label          string `json:"label,omitempty"`
		CreatedAt      string `json:"created_at"`
		LastSeen       string `json:"last_seen"`
		LastPushAt     string `json:"last_push_at,omitempty"`
		LastPushStatus string `json:"last_push_status,omitempty"`
		PushCount      int64  `json:"push_count"`
		Unregistered   bool   `json:"unregistered,omitempty"`
	}
	out := make([]safeSub, len(subs))
	for i, s := range subs {
		out[i] = safeSub{
			DeviceToken: s.DeviceToken, Platform: string(s.Platform), Label: s.Label,
			CreatedAt: s.CreatedAt, LastSeen: s.LastSeen,
			LastPushAt: s.LastPushAt, LastPushStatus: s.LastPushStatus,
			PushCount: s.PushCount, Unregistered: s.Unregistered,
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
		svc := r.push.Load()
		if svc == nil {
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
		apiKey, tokenDead, err := svc.Subscribe(body.DeviceToken, push.Platform(body.Platform), body.Label, owner, clientIP, userAgent)
		if err != nil {
			r.sendError(w, http.StatusBadRequest, err.Error())
			return
		}

		resp := map[string]string{
			"status":  "subscribed",
			"api_key": apiKey,
		}
		if tokenDead {
			// FCM has already refused this exact token with UNREGISTERED.
			// The phone's own Firebase SDK doesn't know that - it keeps
			// re-registering the dead token from cache - so this response
			// is the app's only cue to deleteToken() and mint a fresh one.
			resp["token_status"] = "invalid"
			resp["message"] = "FCM reports this device token is no longer valid - delete the cached token, obtain a fresh one, and subscribe again"
		}
		r.sendJSON(w, resp)

	case http.MethodDelete:
		svc := r.push.Load()
		if svc == nil {
			r.sendError(w, http.StatusServiceUnavailable, "Push notifications not configured")
			return
		}

		var body struct {
			DeviceToken string `json:"device_token"`
		}
		if err := json.NewDecoder(req.Body).Decode(&body); err != nil {
			r.sendError(w, http.StatusBadRequest, "Invalid JSON body")
			return
		}

		if body.DeviceToken == "" {
			r.sendError(w, http.StatusBadRequest, "device_token is required")
			return
		}

		// Only owners or admins can unsubscribe. api_key alone is not
		// sufficient - it's just a per-device fingerprint, not an auth
		// credential that should grant ability to cancel subscriptions.
		owner := req.Header.Get("X-Session-User")
		role := req.Header.Get("X-Session-Role")
		if role != "admin" && !svc.IsOwner(body.DeviceToken, owner) {
			r.sendError(w, http.StatusForbidden, "Not authorized to unsubscribe this device")
			return
		}

		if err := svc.Unsubscribe(body.DeviceToken); err != nil {
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

	svc := r.push.Load()
	if svc == nil {
		r.sendError(w, http.StatusServiceUnavailable, "Push notifications not configured")
		return
	}

	subs := svc.ListSubscriptions()

	// Return all metadata except api_keys
	type adminSubscription struct {
		DeviceToken    string `json:"device_token"`
		Platform       string `json:"platform"`
		Label          string `json:"label,omitempty"`
		Owner          string `json:"owner,omitempty"`
		CreatedAt      string `json:"created_at"`
		LastSeen       string `json:"last_seen"`
		LastPushAt     string `json:"last_push_at,omitempty"`
		LastPushStatus string `json:"last_push_status,omitempty"`
		PushCount      int64  `json:"push_count"`
		FailCount      int64  `json:"fail_count"`
		Unregistered   bool   `json:"unregistered,omitempty"`
		UnregisteredAt string `json:"unregistered_at,omitempty"`
		IPAddress      string `json:"ip_address,omitempty"`
		UserAgent      string `json:"user_agent,omitempty"`
	}
	out := make([]adminSubscription, len(subs))
	for i, s := range subs {
		out[i] = adminSubscription{
			DeviceToken:    s.DeviceToken,
			Platform:       string(s.Platform),
			Label:          s.Label,
			Owner:          s.Owner,
			CreatedAt:      s.CreatedAt,
			LastSeen:       s.LastSeen,
			LastPushAt:     s.LastPushAt,
			LastPushStatus: s.LastPushStatus,
			PushCount:      s.PushCount,
			FailCount:      s.FailCount,
			Unregistered:   s.Unregistered,
			UnregisteredAt: s.UnregisteredAt,
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

	svc := r.push.Load()
	if svc == nil {
		r.sendError(w, http.StatusServiceUnavailable, "Push notifications not configured")
		return
	}

	token := strings.TrimPrefix(req.URL.Path, "/api/push/remove/")
	token = strings.TrimSpace(token)
	if token == "" {
		r.sendError(w, http.StatusBadRequest, "Device token required in URL path")
		return
	}

	if err := svc.AdminRemove(token); err != nil {
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

	svc := r.push.Load()
	if svc == nil {
		r.sendError(w, http.StatusServiceUnavailable, "Push notifications not configured")
		return
	}

	limit := 100
	if limitStr := req.URL.Query().Get("limit"); limitStr != "" {
		if parsed, err := strconv.Atoi(limitStr); err == nil && parsed > 0 && parsed <= 1000 {
			limit = parsed
		}
	}

	entries := svc.GetPushLog(limit)
	r.sendJSON(w, map[string]interface{}{
		"entries": entries,
		"count":   len(entries),
	})
}

// handlePushHealth answers "why aren't alerts arriving?" in one call:
// every link of the delivery pipeline from the enable switch to the
// last actual send.
func (r *Router) handlePushHealth(w http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodGet {
		r.sendError(w, http.StatusMethodNotAllowed, "Only GET allowed")
		return
	}
	svc := r.push.Load()
	if svc == nil {
		r.sendJSON(w, map[string]interface{}{"service_running": false})
		return
	}
	r.sendJSON(w, map[string]interface{}{
		"service_running": true,
		"health":          svc.Health(),
	})
}

func (r *Router) handlePushTest(w http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodPost {
		r.sendError(w, http.StatusMethodNotAllowed, "Only POST allowed")
		return
	}

	svc := r.push.Load()
	if svc == nil {
		r.sendError(w, http.StatusServiceUnavailable, "Push notifications not configured")
		return
	}

	var body struct {
		DeviceToken string `json:"device_token"`
	}
	if err := json.NewDecoder(req.Body).Decode(&body); err != nil {
		r.sendError(w, http.StatusBadRequest, "Invalid JSON body")
		return
	}

	if body.DeviceToken == "" {
		r.sendError(w, http.StatusBadRequest, "device_token is required")
		return
	}

	// Only owners or admins can send test pushes to a device
	owner := req.Header.Get("X-Session-User")
	role := req.Header.Get("X-Session-Role")
	if role != "admin" && !svc.IsOwner(body.DeviceToken, owner) {
		r.sendError(w, http.StatusForbidden, "Not authorized to test this device")
		return
	}

	platform := svc.GetPlatform(body.DeviceToken)
	if platform == "" {
		r.sendError(w, http.StatusNotFound, "Device not found")
		return
	}

	if err := svc.SendTest(body.DeviceToken, platform); err != nil {
		r.sendError(w, http.StatusBadGateway, fmt.Sprintf("Push failed: %v", err))
		return
	}

	// Test sends deliberately bypass the master enable flag (so an admin
	// can verify credentials before going live) - but that means a
	// working test proves nothing about real alerts. Say so explicitly
	// instead of letting a green test mask a disabled pipeline.
	resp := map[string]string{"status": "sent"}
	if !svc.Enabled() {
		resp["warning"] = "Push is DISABLED in settings - this test was delivered, but real alerts are NOT being sent. Enable push to receive alerts."
	}
	r.sendJSON(w, resp)
}

// -- Push settings (web-only, bbolt-backed) -------------------------------

// pushSettingsView is what the UI sees: never the raw secrets, just metadata
// (configured y/n + the bits that aren't secret) so the page can render
// "FCM: project yk-sysmon, firebase-adminsdk@... (key ...85020)" without
// re-leaking the private key.
type pushSettingsView struct {
	Enabled        bool                `json:"enabled"`
	FCM            *fcmConfiguredView  `json:"fcm,omitempty"`
	APNs           *apnsConfiguredView `json:"apns,omitempty"`
	APNsBundleID   string              `json:"apns_bundle_id,omitempty"`
	APNsProduction bool                `json:"apns_production"`
	// RuntimeAvailable is false when the push service didn't initialize
	// at startup (typically a bbolt open failure on push.db) - in that
	// case settings still persist to settings.db, but they won't be
	// hot-applied: a process restart is required after the underlying
	// problem is fixed. The admin UI surfaces this clearly so changes
	// don't appear to silently take effect when they haven't.
	RuntimeAvailable bool `json:"runtime_available"`
}

type fcmConfiguredView struct {
	ProjectID   string `json:"project_id,omitempty"`
	ClientEmail string `json:"client_email,omitempty"`
	KeyIDLast4  string `json:"key_id_last4,omitempty"`
	// Error is set when credentials ARE stored but couldn't be parsed.
	// This is distinct from the FCM block being absent (nothing stored)
	// - the UI must not show "not configured" while real bytes sit in
	// settings.db (and the running service may still be using them).
	Error string `json:"error,omitempty"`
	// Live key health from the background verifier (the offline parse
	// above can't see revocation). KeyValid is nil until the first
	// check completes. KeyRejected distinguishes "Google refused the
	// key" (revoked/deleted) from transient network failure reaching
	// Google, which is not evidence the key is bad.
	KeyValid     *bool  `json:"key_valid,omitempty"`
	KeyRejected  bool   `json:"key_rejected,omitempty"`
	KeyError     string `json:"key_error,omitempty"`
	KeyCheckedAt string `json:"key_checked_at,omitempty"`
}

type apnsConfiguredView struct {
	Subject  string `json:"subject,omitempty"`   // certificate Subject CN
	NotAfter string `json:"not_after,omitempty"` // RFC3339, for the expiry warning
	// Ready is true only when APNs is actually operational, which the
	// push service requires a bundle ID for (see buildClients). A cert
	// uploaded without a bundle ID is present-but-not-ready: we still
	// show its metadata, but Ready=false so the UI doesn't claim iOS
	// delivery works when it doesn't.
	Ready bool `json:"ready"`
	// Error is set when a cert+key ARE stored but couldn't be parsed.
	Error string `json:"error,omitempty"`
}

func (r *Router) viewPush(pc settings.PushConfig) pushSettingsView {
	v := pushSettingsView{
		Enabled:          pc.Enabled,
		APNsBundleID:     pc.APNsBundleID,
		APNsProduction:   pc.APNsProduction,
		RuntimeAvailable: r.pushRuntimeAvailable(),
	}
	if len(pc.FCMCredentials) > 0 {
		// Credentials are stored: always emit an FCM block so the panel
		// reflects that. If they no longer parse, report the error
		// instead of silently dropping to a "not configured" view.
		if proj, email, last4, err := push.FCMCredentialMeta(pc.FCMCredentials); err == nil {
			v.FCM = &fcmConfiguredView{ProjectID: proj, ClientEmail: email, KeyIDLast4: last4}
			if svc := r.push.Load(); svc != nil {
				if st := svc.FCMKeyHealth(); st.Checked {
					valid := st.Valid
					v.FCM.KeyValid = &valid
					v.FCM.KeyRejected = st.Rejected
					v.FCM.KeyError = st.Error
					v.FCM.KeyCheckedAt = st.CheckedAt
				}
			}
		} else {
			v.FCM = &fcmConfiguredView{Error: err.Error()}
		}
	}
	if len(pc.APNsCertPEM) > 0 && len(pc.APNsKeyPEM) > 0 {
		if subj, notAfter, err := push.APNsCertMeta(pc.APNsCertPEM, pc.APNsKeyPEM); err == nil {
			v.APNs = &apnsConfiguredView{
				Subject:  subj,
				NotAfter: notAfter.UTC().Format(time.RFC3339),
				Ready:    pc.APNsBundleID != "",
			}
		} else {
			v.APNs = &apnsConfiguredView{Error: err.Error()}
		}
	}
	return v
}

// handleSettingsPush: GET returns the metadata view; PUT updates the
// non-credential bits (enable flag, APNs bundle, APNs production).
// Credential uploads/deletes go through the dedicated endpoints below.
func (r *Router) handleSettingsPush(w http.ResponseWriter, req *http.Request) {
	if r.settings == nil {
		r.sendError(w, http.StatusServiceUnavailable, "Settings store not configured")
		return
	}
	switch req.Method {
	case http.MethodGet:
		pc, err := r.settings.GetPush()
		if err != nil {
			r.sendError(w, http.StatusInternalServerError, err.Error())
			return
		}
		r.sendJSON(w, r.viewPush(pc))

	case http.MethodPut:
		var body struct {
			Enabled        *bool   `json:"enabled"`
			APNsBundleID   *string `json:"apns_bundle_id"`
			APNsProduction *bool   `json:"apns_production"`
		}
		if err := json.NewDecoder(req.Body).Decode(&body); err != nil {
			r.sendError(w, http.StatusBadRequest, "Invalid JSON body")
			return
		}
		pc, err := r.settings.GetPush()
		if err != nil {
			r.sendError(w, http.StatusInternalServerError, err.Error())
			return
		}
		// failAfterWrite re-reads the actual on-disk state and pushes it
		// to the runtime before reporting the error, so a partial PUT
		// can never leave the push service tracking a stale view of
		// settings.db (e.g. Enabled persisted but Reconfigure skipped).
		failAfterWrite := func(status int, msg string) {
			if fresh, gerr := r.settings.GetPush(); gerr == nil {
				r.reconfigurePush(fresh)
			}
			r.sendError(w, status, msg)
		}
		if body.Enabled != nil {
			pc.Enabled = *body.Enabled
			if err := r.settings.SetPushEnabled(pc.Enabled); err != nil {
				failAfterWrite(http.StatusInternalServerError, err.Error())
				return
			}
		}
		if body.APNsBundleID != nil || body.APNsProduction != nil {
			if body.APNsBundleID != nil {
				pc.APNsBundleID = *body.APNsBundleID
			}
			if body.APNsProduction != nil {
				pc.APNsProduction = *body.APNsProduction
			}
			if err := r.settings.SetAPNs(pc.APNsCertPEM, pc.APNsKeyPEM, pc.APNsBundleID, pc.APNsProduction); err != nil {
				failAfterWrite(http.StatusInternalServerError, err.Error())
				return
			}
		}
		r.commitPushAndRespond(w)

	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// handleSettingsPushFCM: POST uploads a service-account JSON (validated
// before storage); DELETE removes the stored credentials.
func (r *Router) handleSettingsPushFCM(w http.ResponseWriter, req *http.Request) {
	if r.settings == nil {
		r.sendError(w, http.StatusServiceUnavailable, "Settings store not configured")
		return
	}
	switch req.Method {
	case http.MethodPost:
		// Accept either application/json (raw paste) or
		// multipart/form-data (file upload via the admin UI).
		body, err := readFCMBody(req)
		if err != nil {
			r.sendError(w, http.StatusBadRequest, err.Error())
			return
		}
		if _, _, _, err := push.FCMCredentialMeta(body); err != nil {
			r.sendError(w, http.StatusBadRequest, err.Error())
			return
		}
		// The metadata check above is offline-only - a revoked or deleted
		// key still parses fine. Prove Google actually accepts this key by
		// minting a real OAuth token before storing it. Network trouble
		// reaching Google is NOT evidence the key is bad, so only a
		// definitive refusal rejects the upload; the background checker
		// keeps verifying either way.
		ctx, cancel := context.WithTimeout(req.Context(), 15*time.Second)
		defer cancel()
		if err := push.FCMCredentialLiveCheck(ctx, body); err != nil {
			var rejected *push.KeyRejectedError
			if errors.As(err, &rejected) {
				r.sendError(w, http.StatusBadRequest, err.Error())
				return
			}
			log.Printf("settings: could not live-verify FCM key (accepting upload anyway): %v", err)
		}
		if err := r.settings.SetFCMCredentials(body); err != nil {
			r.sendError(w, http.StatusInternalServerError, err.Error())
			return
		}
		r.commitPushAndRespond(w)

	case http.MethodDelete:
		if err := r.settings.ClearFCMCredentials(); err != nil {
			r.sendError(w, http.StatusInternalServerError, err.Error())
			return
		}
		r.commitPushAndRespond(w)

	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// handleSettingsPushAPNs: POST uploads a cert + key (PEM, multipart);
// DELETE clears them. Bundle ID and production flag go through the
// /api/settings/push PUT.
func (r *Router) handleSettingsPushAPNs(w http.ResponseWriter, req *http.Request) {
	if r.settings == nil {
		r.sendError(w, http.StatusServiceUnavailable, "Settings store not configured")
		return
	}
	switch req.Method {
	case http.MethodPost:
		if err := req.ParseMultipartForm(2 << 20); err != nil { // 2 MiB ceiling for PEMs
			r.sendError(w, http.StatusBadRequest, "expected multipart/form-data with cert+key files")
			return
		}
		certPEM, err := readFormFile(req, "cert")
		if err != nil {
			r.sendError(w, http.StatusBadRequest, "cert: "+err.Error())
			return
		}
		keyPEM, err := readFormFile(req, "key")
		if err != nil {
			r.sendError(w, http.StatusBadRequest, "key: "+err.Error())
			return
		}
		if _, _, err := push.APNsCertMeta(certPEM, keyPEM); err != nil {
			r.sendError(w, http.StatusBadRequest, err.Error())
			return
		}
		// Carry forward the existing bundle id / production flag - but
		// fail loud if the read errors, otherwise a flaky GetPush would
		// silently zero them out as part of an APNs cert upload.
		pc, err := r.settings.GetPush()
		if err != nil {
			r.sendError(w, http.StatusInternalServerError, err.Error())
			return
		}
		if err := r.settings.SetAPNs(certPEM, keyPEM, pc.APNsBundleID, pc.APNsProduction); err != nil {
			r.sendError(w, http.StatusInternalServerError, err.Error())
			return
		}
		r.commitPushAndRespond(w)

	case http.MethodDelete:
		if err := r.settings.ClearAPNs(); err != nil {
			r.sendError(w, http.StatusInternalServerError, err.Error())
			return
		}
		r.commitPushAndRespond(w)

	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// pushConfigFrom translates a settings record into the push-service
// config shape, in one place so the two layouts can drift independently
// without spreading field-by-field copies around.
func pushConfigFrom(pc settings.PushConfig) push.Config {
	return push.Config{
		Enabled:        pc.Enabled,
		FCMCredentials: pc.FCMCredentials,
		APNsCertPEM:    pc.APNsCertPEM,
		APNsKeyPEM:     pc.APNsKeyPEM,
		APNsBundleID:   pc.APNsBundleID,
		APNsProduction: pc.APNsProduction,
	}
}

// reconfigurePush hot-swaps the running push service to match pc. If
// the push service is nil because its boot-time init failed (e.g.
// push.db unwritable) and we have a factory, retry NewService now - the
// operator may have fixed the underlying problem since startup. Returns
// true if the runtime is now in sync with pc.
func (r *Router) reconfigurePush(pc settings.PushConfig) bool {
	cfg := pushConfigFrom(pc)
	// Fast path: existing service → no init mutex needed; Reconfigure
	// has its own internal locking against Stop and concurrent calls.
	if svc := r.push.Load(); svc != nil {
		svc.Reconfigure(cfg)
		return true
	}
	if r.pushFactory == nil {
		return false
	}
	// Serialise lazy init so two simultaneous requests can't both spin
	// up a Service (one of which would then leak its watcher + DB
	// handle when overwritten).
	r.pushInitMu.Lock()
	defer r.pushInitMu.Unlock()
	if svc := r.push.Load(); svc != nil {
		// Lost the race; the other reinit won.
		svc.Reconfigure(cfg)
		return true
	}
	svc, err := r.pushFactory(cfg)
	if err != nil {
		return false
	}
	r.push.Store(svc)
	// The alerter sink must follow the swap or alerts keep flowing into
	// the dead service (harmlessly - a stopped service drops them - but
	// silently).
	r.monitoring.SetAlertSink(svc.ExternalAlert)
	return true
}

// pushRuntimeAvailable reports whether the push service is currently
// running. Cheap atomic Load; matches what handlers see.
func (r *Router) pushRuntimeAvailable() bool {
	return r.push.Load() != nil
}

// commitPushAndRespond reloads the push config from settings.db, pushes
// it to the runtime, and writes the metadata view to w. This is the only
// way a push-config handler should return success - runtime and on-disk
// state stay in lockstep, with no chance of returning a snapshot that
// differs from what just got persisted.
func (r *Router) commitPushAndRespond(w http.ResponseWriter) {
	pc, err := r.settings.GetPush()
	if err != nil {
		r.sendError(w, http.StatusInternalServerError, err.Error())
		return
	}
	r.reconfigurePush(pc)
	r.sendJSON(w, r.viewPush(pc))
}

// readFCMBody accepts the service-account JSON either as the raw request
// body (Content-Type: application/json) or as the "credentials" form
// field of a multipart upload (Content-Type: multipart/form-data). Caps
// at 64 KiB - real service-account JSONs are ~2.5 KiB.
func readFCMBody(req *http.Request) ([]byte, error) {
	const maxBytes = 64 * 1024
	ctype := req.Header.Get("Content-Type")
	if strings.HasPrefix(ctype, "multipart/form-data") {
		if err := req.ParseMultipartForm(maxBytes); err != nil {
			return nil, fmt.Errorf("multipart parse: %w", err)
		}
		return readFormFile(req, "credentials")
	}
	body, err := io.ReadAll(io.LimitReader(req.Body, maxBytes+1))
	if err != nil {
		return nil, err
	}
	if len(body) > maxBytes {
		return nil, fmt.Errorf("credentials too large (>%d bytes)", maxBytes)
	}
	if len(body) == 0 {
		return nil, fmt.Errorf("empty body")
	}
	return body, nil
}

func readFormFile(req *http.Request, field string) ([]byte, error) {
	f, _, err := req.FormFile(field)
	if err != nil {
		return nil, fmt.Errorf("missing form file %q", field)
	}
	defer f.Close()
	const maxBytes = 64 * 1024
	body, err := io.ReadAll(io.LimitReader(f, maxBytes+1))
	if err != nil {
		return nil, err
	}
	if len(body) > maxBytes {
		return nil, fmt.Errorf("file too large (>%d bytes)", maxBytes)
	}
	if len(body) == 0 {
		return nil, fmt.Errorf("empty file")
	}
	return body, nil
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
