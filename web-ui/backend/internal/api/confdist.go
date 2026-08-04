package api

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"

	"sysmon-web/internal/settings"
)

// Config distribution endpoints.
//
// Everything that changes what a box runs is admin-only and is a POST -
// no amount of link-prefetching or a stale browser tab can deliver a
// config. Reading state is not: seeing that a site has drifted is the
// kind of thing you want on a wallboard.

// GET /api/config/fleet
// The per-site state table: what each box runs, what it should run, and
// which of the two the operator needs to do something about.
func (r *Router) handleConfigFleet(w http.ResponseWriter, req *http.Request) {
	r.sendJSON(w, map[string]interface{}{"sites": r.monitoring.ConfigStatus()})
}

// siteFromPath pulls the site name out of /api/config/site/<site>/<action>.
func siteFromPath(path, prefix string) (site, action string) {
	rest := strings.TrimPrefix(path, prefix)
	rest = strings.Trim(rest, "/")
	if rest == "" {
		return "", ""
	}
	parts := strings.SplitN(rest, "/", 2)
	if len(parts) == 1 {
		return parts[0], ""
	}
	return parts[0], parts[1]
}

// wireFile is how a config file crosses the HTTP boundary. Content is
// base64 for the same reason it is base64 on the daemon link: a config
// file is bytes, and JSON strings are not.
type wireFile struct {
	Path    string `json:"path"`
	Content string `json:"content"`
}

func toWire(files []settings.GenFile) []wireFile {
	out := make([]wireFile, len(files))
	for i, f := range files {
		out[i] = wireFile{Path: f.Path,
			Content: base64.StdEncoding.EncodeToString(f.Content)}
	}
	return out
}

func fromWire(files []wireFile) ([]settings.GenFile, error) {
	out := make([]settings.GenFile, len(files))
	for i, f := range files {
		body, err := base64.StdEncoding.DecodeString(f.Content)
		if err != nil {
			return nil, err
		}
		out[i] = settings.GenFile{Path: f.Path, Content: body}
	}
	return out, nil
}

// GET  /api/config/site/<site>            what the box is running now
// GET  /api/config/site/<site>/generation/<n>   a stored generation
func (r *Router) handleConfigSite(w http.ResponseWriter, req *http.Request) {
	site, action := siteFromPath(req.URL.Path, "/api/config/site/")
	if site == "" {
		r.sendError(w, http.StatusBadRequest, "which site?")
		return
	}

	if strings.HasPrefix(action, "generation/") {
		store := r.monitoring.Generations()
		if store == nil {
			r.sendError(w, http.StatusServiceUnavailable, "no settings store")
			return
		}
		gen, err := strconv.ParseUint(strings.TrimPrefix(action, "generation/"), 10, 64)
		if err != nil {
			r.sendError(w, http.StatusBadRequest, "not a generation number")
			return
		}
		files, ok := store.GetGenerationFiles(site, gen)
		if !ok {
			r.sendError(w, http.StatusNotFound, "that generation is not held here")
			return
		}
		r.sendJSON(w, map[string]interface{}{
			"site": site, "generation": gen, "files": toWire(files),
		})
		return
	}

	if action != "" {
		r.sendError(w, http.StatusNotFound, "no such config endpoint")
		return
	}

	files, gen, hash, err := r.monitoring.SiteConfigFiles(site)
	if err != nil {
		r.sendError(w, http.StatusServiceUnavailable, err.Error())
		return
	}
	r.sendJSON(w, map[string]interface{}{
		"site": site, "generation": gen, "hash": hash, "files": toWire(files),
	})
}

// GET /api/config/site/<site>/generations - the numbers we hold, newest
// first, so a rollback or a diff has something to name.
func (r *Router) handleConfigGenerations(w http.ResponseWriter, req *http.Request) {
	site, _ := siteFromPath(req.URL.Path, "/api/config/generations/")
	store := r.monitoring.Generations()
	if site == "" || store == nil {
		r.sendError(w, http.StatusBadRequest, "which site?")
		return
	}
	desired, _ := store.GetDesired(site)
	r.sendJSON(w, map[string]interface{}{
		"site":        site,
		"generations": store.ListGenerations(site),
		"desired":     desired,
	})
}

// POST /api/config/adopt/<site>
//
// Take what is really on the box and make it the first desired
// generation. Also the recovery path when somebody fixed something on the
// console: pull it up, and agree that it is what should be there.
func (r *Router) handleConfigAdopt(w http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodPost {
		r.sendError(w, http.StatusMethodNotAllowed, "POST only")
		return
	}
	site, _ := siteFromPath(req.URL.Path, "/api/config/adopt/")
	if site == "" {
		r.sendError(w, http.StatusBadRequest, "which site?")
		return
	}

	gen, err := r.monitoring.AdoptSite(site, req.Header.Get("X-Session-User"))
	if err != nil {
		r.sendError(w, http.StatusBadGateway, err.Error())
		return
	}
	r.sendJSON(w, map[string]interface{}{"site": site, "generation": gen, "adopted": true})
}

// POST /api/config/stage/<site>   {files:[{path,content}], note}
//
// Record a new desired generation without delivering it. Staging and
// delivering are deliberately two acts: the second one is the one that
// can take a site off the air.
func (r *Router) handleConfigStage(w http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodPost {
		r.sendError(w, http.StatusMethodNotAllowed, "POST only")
		return
	}
	site, _ := siteFromPath(req.URL.Path, "/api/config/stage/")
	if site == "" {
		r.sendError(w, http.StatusBadRequest, "which site?")
		return
	}

	var body struct {
		Files []wireFile `json:"files"`
		Note  string     `json:"note"`
	}
	if err := json.NewDecoder(req.Body).Decode(&body); err != nil {
		r.sendError(w, http.StatusBadRequest, err.Error())
		return
	}
	files, err := fromWire(body.Files)
	if err != nil {
		r.sendError(w, http.StatusBadRequest, "undecodable file content: "+err.Error())
		return
	}

	gen, hash, err := r.monitoring.StageGeneration(site, files,
		req.Header.Get("X-Session-User"), body.Note)
	if err != nil {
		r.sendError(w, http.StatusBadRequest, err.Error())
		return
	}
	r.sendJSON(w, map[string]interface{}{"site": site, "generation": gen, "hash": hash})
}

// POST /api/config/deliver/<site>
func (r *Router) handleConfigDeliver(w http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodPost {
		r.sendError(w, http.StatusMethodNotAllowed, "POST only")
		return
	}
	site, _ := siteFromPath(req.URL.Path, "/api/config/deliver/")
	if site == "" {
		r.sendError(w, http.StatusBadRequest, "which site?")
		return
	}

	res, err := r.monitoring.DeliverSite(site)
	if err != nil {
		// The daemon's own complaints are the useful part of a rejection,
		// so they travel with the error rather than being flattened into
		// it.
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadGateway)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"error": err.Error(), "result": res,
		})
		return
	}
	r.sendJSON(w, res)
}

// POST /api/config/rollback/<site>
func (r *Router) handleConfigRollback(w http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodPost {
		r.sendError(w, http.StatusMethodNotAllowed, "POST only")
		return
	}
	site, _ := siteFromPath(req.URL.Path, "/api/config/rollback/")
	if site == "" {
		r.sendError(w, http.StatusBadRequest, "which site?")
		return
	}

	res, err := r.monitoring.RollbackSite(site)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadGateway)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"error": err.Error(), "result": res,
		})
		return
	}
	r.sendJSON(w, res)
}

// POST /api/config/rollout   {generation-per-site is implied; body picks
// the sites and the watch window}
//
// Waves, canary first. See monitoring.StartRollout for why "it applied" is
// not the success criterion.
func (r *Router) handleConfigRollout(w http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodPost {
		r.sendError(w, http.StatusMethodNotAllowed, "POST only")
		return
	}

	var body struct {
		Sites       []string `json:"sites"`
		WatchWindow int      `json:"watch_seconds"`
		Tolerance   float64  `json:"object_tolerance"`
	}
	if err := json.NewDecoder(req.Body).Decode(&body); err != nil {
		r.sendError(w, http.StatusBadRequest, err.Error())
		return
	}
	if len(body.Sites) == 0 {
		r.sendError(w, http.StatusBadRequest, "no sites named")
		return
	}

	id, err := r.monitoring.StartRollout(body.Sites, body.WatchWindow, body.Tolerance,
		req.Header.Get("X-Session-User"))
	if err != nil {
		r.sendError(w, http.StatusBadRequest, err.Error())
		return
	}
	r.sendJSON(w, map[string]interface{}{"rollout": id})
}

// GET /api/config/rollout - live state of the rollouts this process has run.
func (r *Router) handleConfigRolloutStatus(w http.ResponseWriter, req *http.Request) {
	r.sendJSON(w, map[string]interface{}{"rollouts": r.monitoring.Rollouts()})
}
