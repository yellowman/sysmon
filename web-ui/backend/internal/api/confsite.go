package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"

	"sysmon-web/internal/config"
	"sysmon-web/internal/models"
	"sysmon-web/internal/settings"
)

// The config editor and the map act on one daemon. With a fleet behind
// the aggregator they take ?site=<sitename>: reads fetch that box's
// running files over the agent link and go through the same Go parser
// the local file does; a raw save stages a new generation and delivers
// it, which the box validates with its own parser before swapping.
// An empty site (or "local") is the local sysmon.conf, exactly as
// before.

// remoteSite returns the site a request names, or "" for the local box.
func remoteSite(req *http.Request) string {
	site := req.URL.Query().Get("site")
	if site == "local" {
		return ""
	}
	return site
}

// parseSiteFiles runs a box's file set through the local Go parser. The
// set is written to a throwaway directory so include resolution sees the
// flat layout a generation directory has on the box. The daemon sends
// the entry file first (confset_record records the main config before
// its includes), so files[0] is the main file.
func parseSiteFiles(files []settings.GenFile) (*models.Config, error) {
	if len(files) == 0 {
		return nil, fmt.Errorf("the box sent no files")
	}
	dir, err := os.MkdirTemp("", "sysmon-remote-conf-*")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(dir)
	for _, f := range files {
		name := filepath.Base(f.Name)
		if err := os.WriteFile(filepath.Join(dir, name), f.Content, 0600); err != nil {
			return nil, err
		}
	}
	return config.ParseFile(filepath.Join(dir, filepath.Base(files[0].Name)))
}

// GET /api/config?site=X - that box's running config, parsed.
func (r *Router) handleConfigSiteGet(w http.ResponseWriter, site string) {
	files, gen, hash, err := r.monitoring.SiteConfigFiles(site)
	if err != nil {
		r.sendError(w, http.StatusServiceUnavailable, err.Error())
		return
	}
	cfg, err := parseSiteFiles(files)
	if err != nil {
		r.sendError(w, http.StatusUnprocessableEntity,
			fmt.Sprintf("%s's config fetched but did not parse here: %v", site, err))
		return
	}
	r.sendJSON(w, map[string]interface{}{
		"version":    hash,
		"config":     cfg,
		"site":       site,
		"generation": gen,
		"remote":     true,
	})
}

// GET /api/config/raw?site=X - the box's main file, byte for byte.
func (r *Router) handleConfigRawSiteGet(w http.ResponseWriter, site string) {
	files, gen, hash, err := r.monitoring.SiteConfigFiles(site)
	if err != nil {
		r.sendError(w, http.StatusServiceUnavailable, err.Error())
		return
	}
	if len(files) == 0 {
		r.sendError(w, http.StatusServiceUnavailable, "the box sent no files")
		return
	}
	names := make([]string, len(files))
	for i, f := range files {
		names[i] = f.Name
	}
	r.sendJSON(w, map[string]interface{}{
		"content":    string(files[0].Content),
		"version":    hash,
		"site":       site,
		"generation": gen,
		"remote":     true,
		"files":      names,
	})
}

// PUT /api/config/raw?site=X - stage the edited main file with the rest
// of the box's current set, then deliver. The box's own parser validates
// before anything running is touched, so a refusal comes back with its
// words and costs the box nothing.
func (r *Router) handleConfigRawSitePut(w http.ResponseWriter, req *http.Request, site string) {
	var data struct {
		Content string `json:"content"`
		Version string `json:"version"`
		Comment string `json:"comment"`
	}
	if err := json.NewDecoder(req.Body).Decode(&data); err != nil {
		r.sendError(w, http.StatusBadRequest, "Invalid JSON")
		return
	}

	files, _, hash, err := r.monitoring.SiteConfigFiles(site)
	if err != nil {
		r.sendError(w, http.StatusServiceUnavailable, err.Error())
		return
	}
	if len(files) == 0 {
		r.sendError(w, http.StatusServiceUnavailable, "the box sent no files")
		return
	}
	if data.Version != "" && data.Version != hash {
		w.WriteHeader(http.StatusConflict)
		r.sendJSON(w, &models.VersionConflictError{
			Expected: data.Version,
			Actual:   hash,
			Message:  "the box's config changed since this copy was loaded - reload and redo the edit",
		})
		return
	}

	files[0].Content = []byte(data.Content)

	user, _ := r.getUserInfo(req)
	note := data.Comment
	if note == "" {
		note = "raw edit from the config page"
	}
	if _, _, err := r.monitoring.StageGeneration(site, files, user, note); err != nil {
		r.sendError(w, http.StatusBadRequest, err.Error())
		return
	}

	res, err := r.monitoring.DeliverSite(site)
	if err != nil {
		msg := err.Error()
		if res != nil && len(res.Complaints) > 0 {
			msg = fmt.Sprintf("%s refused it: %v", site, res.Complaints)
		}
		r.sendError(w, http.StatusBadRequest, msg)
		return
	}

	out := map[string]interface{}{
		"version":    res.RunningHash,
		"generation": res.RunningGeneration,
		"objects":    res.Objects,
		"site":       site,
	}
	if res.Warning != "" {
		out["warning"] = res.Warning
	}
	r.sendJSON(w, out)
}
