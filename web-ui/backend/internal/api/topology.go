package api

import (
	"fmt"
	"net/http"

	"sysmon-web/internal/models"
)

// The dependency map needs the shape of the network: what the objects
// are and what they depend on. It used to get that from /api/config,
// which is admin-only for good reason - a config carries the daemon
// authkey, SNMP communities, RADIUS secrets, check passwords and spawn
// command lines. That made the whole map admin-only too, which is
// backwards: the map is the screen a read-only NOC operator most wants
// during an outage, and it needs none of those fields.
//
// So topology is its own endpoint with its own model. It is built by
// copying the handful of fields the map draws out of each object -
// allow-list, never redaction of a full record: a new secret-bearing
// field added to models.Host must not leak here just because nobody
// remembered to add it to a blocklist.

// TopologyHost is one object as the map needs it, and nothing else.
type TopologyHost struct {
	ID           string `json:"id"`
	IP           string `json:"ip,omitempty"`
	Type         string `json:"type,omitempty"`
	Notes        string `json:"notes,omitempty"`
	Group        string `json:"group,omitempty"`
	Dependencies string `json:"dependencies,omitempty"`
	Paused       bool   `json:"paused,omitempty"`
}

// topologyOf copies just the drawable fields out of a parsed config.
func topologyOf(cfg *models.Config) []TopologyHost {
	out := make([]TopologyHost, 0, len(cfg.Hosts))
	for _, h := range cfg.Hosts {
		out = append(out, TopologyHost{
			ID:           h.ID,
			IP:           h.IP,
			Type:         h.Type,
			Notes:        h.Notes,
			Group:        h.Group,
			Dependencies: h.Dependencies,
			Paused:       h.Paused,
		})
	}
	return out
}

// handleMonitoringTopology serves the dependency graph to any logged-in
// user: GET /api/monitoring/topology[?site=X].
//
// Read-only by construction - there is no PUT. Editing topology is still
// a config write through the admin-gated /api/config, so the map's edit
// mode remains admin-only while its view mode is available to everyone.
func (r *Router) handleMonitoringTopology(w http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodGet {
		r.sendError(w, http.StatusMethodNotAllowed, "Only GET allowed")
		return
	}

	var (
		cfg     *models.Config
		version string
	)

	if site := remoteSite(req); site != "" {
		files, _, hash, err := r.monitoring.SiteConfigFiles(site)
		if err != nil {
			r.sendError(w, http.StatusServiceUnavailable, err.Error())
			return
		}
		parsed, err := parseSiteFiles(files)
		if err != nil {
			r.sendError(w, http.StatusUnprocessableEntity,
				fmt.Sprintf("%s's config fetched but did not parse here: %v", site, err))
			return
		}
		cfg, version = parsed, hash
	} else {
		snapshot, err := r.config.GetConfig()
		if err != nil {
			r.sendError(w, http.StatusInternalServerError, err.Error())
			return
		}
		if snapshot == nil {
			r.sendError(w, http.StatusServiceUnavailable, "No configuration loaded")
			return
		}
		cfg, version = &snapshot.Config, snapshot.Version
	}

	r.sendJSON(w, map[string]interface{}{
		"hosts":   topologyOf(cfg),
		"version": version,
		"site":    req.URL.Query().Get("site"),
	})
}
