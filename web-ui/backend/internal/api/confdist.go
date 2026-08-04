package api

import (
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"os"
	"strconv"
	"strings"

	"sysmon-web/internal/monitoring"
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
//
// Name, not path: this end never says where a file goes. The daemon owns
// one directory and puts them there.
type wireFile struct {
	Name    string `json:"name"`
	Content string `json:"content"`
}

func toWire(files []settings.GenFile) []wireFile {
	out := make([]wireFile, len(files))
	for i, f := range files {
		out[i] = wireFile{Name: f.Name,
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
		out[i] = settings.GenFile{Name: f.Name, Content: body}
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

// POST /api/config/revert/<site>
//
// Stop managing a box: it goes back to the config an operator wrote and
// this process has never touched.
func (r *Router) handleConfigRevert(w http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodPost {
		r.sendError(w, http.StatusMethodNotAllowed, "POST only")
		return
	}
	site, _ := siteFromPath(req.URL.Path, "/api/config/revert/")
	if site == "" {
		r.sendError(w, http.StatusBadRequest, "which site?")
		return
	}

	res, err := r.monitoring.RevertSite(site)
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

// ---------------------------------------------------------------------
// Agent tokens
// ---------------------------------------------------------------------
//
// One credential per box, minted here and revocable here. This is the
// whole reason daemons dial out rather than being dialled: the
// alternative has this process holding a key to every box in the fleet,
// so compromising the UI compromises the lot.
//
// The plaintext token is returned exactly once, at creation. It is stored
// hashed, so "show it to me again" is impossible rather than merely
// discouraged - and a leaked database does not leak the fleet.

// GET  /api/settings/agents          list sites and when they last connected
// POST /api/settings/agents          {site,label} -> mint, returns the token once
func (r *Router) handleAgentTokens(w http.ResponseWriter, req *http.Request) {
	if r.settings == nil {
		r.sendError(w, http.StatusServiceUnavailable, "no settings store")
		return
	}

	switch req.Method {
	case http.MethodGet:
		tokens, err := r.settings.ListAgentTokens()
		if err != nil {
			r.sendError(w, http.StatusInternalServerError, err.Error())
			return
		}
		if tokens == nil {
			tokens = []settings.AgentToken{}
		}
		r.sendJSON(w, map[string]interface{}{"agents": tokens})

	case http.MethodPost:
		var body struct {
			Site  string `json:"site"`
			Label string `json:"label"`
			// Replace has to be asked for. One token per site, so minting
			// again for a site that already has one silently stops the box
			// holding the old token - it keeps monitoring and paging, and
			// simply cannot report any more. That is not something to do
			// by accident while trying to make a spare.
			Replace bool `json:"replace"`
		}
		if err := json.NewDecoder(req.Body).Decode(&body); err != nil {
			r.sendError(w, http.StatusBadRequest, err.Error())
			return
		}
		// The same rule the daemon and the listener use. A site name that
		// cannot be split back out of "site:object" is worse than no site.
		if !monitoring.ValidSiteName(body.Site) {
			r.sendError(w, http.StatusBadRequest,
				"a site name is letters, digits, - and _ (no colon, which would make site:object ambiguous)")
			return
		}
		if existing, held := r.settings.GetAgentToken(body.Site); held &&
			!existing.Revoked && !body.Replace {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusConflict)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"error": "site already has a token",
				"message": "Site " + body.Site + " already has a live token. " +
					"Minting another one stops the box that holds the old one " +
					"from reporting. Send replace:true if that is what you want.",
				"site":      body.Site,
				"last_seen": existing.LastSeen,
				"last_addr": existing.LastAddr,
			})
			return
		}

		token, err := r.settings.NewAgentToken(body.Site, body.Label)
		if err != nil {
			r.sendError(w, http.StatusInternalServerError, err.Error())
			return
		}
		r.sendJSON(w, map[string]interface{}{
			"site":  body.Site,
			"token": token,
			"note":  "copy this now - it is stored hashed and cannot be shown again",
		})

	default:
		r.sendError(w, http.StatusMethodNotAllowed, "GET or POST")
	}
}

// POST /api/settings/agents/revoke/<site>
//
// The box keeps monitoring and paging; it just stops being able to report
// here. Revoking is the fleet-side action, and it costs that one box.
func (r *Router) handleAgentRevoke(w http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodPost {
		r.sendError(w, http.StatusMethodNotAllowed, "POST only")
		return
	}
	if r.settings == nil {
		r.sendError(w, http.StatusServiceUnavailable, "no settings store")
		return
	}
	site, _ := siteFromPath(req.URL.Path, "/api/settings/agents/revoke/")
	if site == "" {
		r.sendError(w, http.StatusBadRequest, "which site?")
		return
	}
	if err := r.settings.RevokeAgentToken(site); err != nil {
		r.sendError(w, http.StatusInternalServerError, err.Error())
		return
	}
	r.sendJSON(w, map[string]interface{}{"site": site, "revoked": true})
}

// GET /api/settings/agents/ca
//
// The certificate a box needs as aggregator-ca.pem. Without it the daemon
// cannot verify this server and refuses to connect, so handing it out is
// half of onboarding - and telling somebody to go and find a file on the
// server is how they end up copying the wrong one, or the key.
//
// Only ever the certificate. The key that goes with it is what lets
// something impersonate this server to the whole fleet, so this reads the
// cert file, parses it, and re-encodes only the CERTIFICATE blocks - a
// file that happened to hold both would still yield only the public half.
func (r *Router) handleAgentCA(w http.ResponseWriter, req *http.Request) {
	path := monitoring.AgentCertPath()
	if path == "" {
		r.sendError(w, http.StatusServiceUnavailable,
			"no agent listener is running, so there is no certificate to hand out")
		return
	}

	raw, err := os.ReadFile(path)
	if err != nil {
		r.sendError(w, http.StatusInternalServerError, "cannot read the certificate")
		return
	}

	var out []byte
	for rest := raw; len(rest) > 0; {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue // a key in this file is not ours to give away
		}
		out = append(out, pem.EncodeToMemory(block)...)
	}
	if len(out) == 0 {
		r.sendError(w, http.StatusInternalServerError,
			"the configured certificate file holds no certificate")
		return
	}

	w.Header().Set("Content-Type", "application/x-pem-file")
	w.Header().Set("Content-Disposition", `attachment; filename="aggregator-ca.pem"`)
	w.Write(out)
}
