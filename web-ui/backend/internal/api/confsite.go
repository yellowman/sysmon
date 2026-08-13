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

	files := r.siteFilesForEdit(w, site, data.Version)
	if files == nil {
		return
	}

	files[0].Content = []byte(data.Content)

	note := data.Comment
	if note == "" {
		note = "raw edit from the config page"
	}
	r.stageAndDeliver(w, req, site, files, note)
}

// siteFilesForEdit is the shared front half of every site save: fetch
// the box's current file set and check the caller's copy of it is still
// current. Answers the request and returns nil when anything
// disqualifies the save.
func (r *Router) siteFilesForEdit(w http.ResponseWriter, site, version string) []settings.GenFile {
	files, _, hash, err := r.monitoring.SiteConfigFiles(site)
	if err != nil {
		r.sendError(w, http.StatusServiceUnavailable, err.Error())
		return nil
	}
	if len(files) == 0 {
		r.sendError(w, http.StatusServiceUnavailable, "the box sent no files")
		return nil
	}
	if version != "" && version != hash {
		w.WriteHeader(http.StatusConflict)
		r.sendJSON(w, &models.VersionConflictError{
			Expected: version,
			Actual:   hash,
			Message:  "the box's config changed since this copy was loaded - reload and redo the edit",
		})
		return nil
	}
	return files
}

// stageAndDeliver is the shared back half of every site save: stage the
// file set as a new generation, deliver it, and answer with what the
// box is now running - or with its parser's own words when it refuses,
// which costs the box nothing.
func (r *Router) stageAndDeliver(w http.ResponseWriter, req *http.Request, site string, files []settings.GenFile, note string) {
	user, _ := r.getUserInfo(req)
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

// PUT /api/config?site=X - a structured save for a managed box.
//
// The box's file set is SPLICED, never regenerated. The model cannot
// carry comments, include structure, or directives it has no fields
// for - the box's own aggregator lines above all, which the uplink
// guard in StageGeneration would (rightly) refuse to see vanish. So
// the edit is applied the way the local path applies it: only the
// objects that actually changed are rewritten, in the file they live
// in, and every other byte of the set survives untouched. Then the
// same stage-and-deliver as a raw save - the box's own parser
// validates before anything running is touched.
func (r *Router) handleConfigSitePut(w http.ResponseWriter, req *http.Request, site string) {
	var update models.ConfigUpdate
	if err := json.NewDecoder(req.Body).Decode(&update); err != nil {
		r.sendError(w, http.StatusBadRequest, "Invalid JSON")
		return
	}

	// The site's reachability is judged before the payload: a save for
	// a box that cannot be reached is answered as such whatever the
	// body says.
	files := r.siteFilesForEdit(w, site, update.Version)
	if files == nil {
		return
	}
	if err := config.Validate(&update.Config); err != nil {
		r.sendError(w, http.StatusBadRequest, err.Error())
		return
	}

	// The splice machinery works on paths; give it the file set laid
	// out the way a generation directory lays it out - flat names in
	// one directory - exactly as parseSiteFiles does for reads.
	dir, err := os.MkdirTemp("", "sysmon-site-edit-*")
	if err != nil {
		r.sendError(w, http.StatusInternalServerError, err.Error())
		return
	}
	defer os.RemoveAll(dir)
	for _, f := range files {
		name := filepath.Base(f.Name)
		if err := os.WriteFile(filepath.Join(dir, name), f.Content, 0600); err != nil {
			r.sendError(w, http.StatusInternalServerError, err.Error())
			return
		}
	}

	doc, err := config.LoadDocument(filepath.Join(dir, filepath.Base(files[0].Name)))
	if err != nil {
		r.sendError(w, http.StatusUnprocessableEntity,
			fmt.Sprintf("%s's config fetched but did not load here: %v", site, err))
		return
	}
	doc.Apply(&update.Config)
	if err := doc.Save(); err != nil {
		r.sendError(w, http.StatusInternalServerError, err.Error())
		return
	}
	for i := range files {
		b, err := os.ReadFile(filepath.Join(dir, filepath.Base(files[i].Name)))
		if err != nil {
			r.sendError(w, http.StatusInternalServerError, err.Error())
			return
		}
		files[i].Content = b
	}

	note := update.Comment
	if note == "" {
		note = "structured edit from the config page"
	}
	r.stageAndDeliver(w, req, site, files, note)
}
