package monitoring

import (
	"fmt"
	"log"
	"sort"
	"sync"
	"time"

	"sysmon-web/internal/models"
)

// Canary rollout.
//
// A generation goes out to one box first, and only spreads if that box
// keeps working. "It applied" is not the success criterion, because a
// config can parse perfectly and still be catastrophically wrong: delete
// one `dep` line and a single upstream failure turns into eight hundred
// pages. So a box that took a generation is watched, and the criteria are
// deliberately about consequences rather than syntax:
//
//   1. the daemon validated it and reloaded          (the delivery said so)
//   2. the object count is within tolerance          (did we lose hosts?)
//   3. no alert-rate spike inside the watch window   (did we break the tree?)
//
// Failing 2 or 3 rolls that box back on its own and poisons the
// generation, which stops the remaining waves. Rollback needs no network:
// the previous generation's files are already on the box.

const (
	defaultWatchWindow   = 120 * time.Second
	defaultObjectTolance = 0.10 // 10% of the object count
	// How much worse the alert rate may get during the watch window
	// before the generation is treated as the cause. Absolute, not
	// proportional: going from 0 alerts to 1 is not a spike, going from
	// 0 to 40 is.
	alertSpikeAllowance = 5
)

type RolloutSiteState string

const (
	RolloutPending    RolloutSiteState = "pending"
	RolloutDelivered  RolloutSiteState = "delivered"
	RolloutWatching   RolloutSiteState = "watching"
	RolloutOK         RolloutSiteState = "ok"
	RolloutFailed     RolloutSiteState = "failed"
	RolloutRolledBack RolloutSiteState = "rolled-back"
	RolloutSkipped    RolloutSiteState = "skipped"
)

// RolloutSite is one box's part in a rollout.
type RolloutSite struct {
	Site         string           `json:"site"`
	Generation   uint64           `json:"generation"`
	State        RolloutSiteState `json:"state"`
	Detail       string           `json:"detail,omitempty"`
	Objects      int              `json:"objects,omitempty"`
	Expected     int              `json:"expected_objects,omitempty"`
	AlertsBefore int              `json:"alerts_before,omitempty"`
	AlertsAfter  int              `json:"alerts_after,omitempty"`
	Started      time.Time        `json:"started,omitempty"`
	Finished     time.Time        `json:"finished,omitempty"`
}

// Rollout is one wave-by-wave delivery.
type Rollout struct {
	ID        string         `json:"id"`
	StartedBy string         `json:"started_by,omitempty"`
	Started   time.Time      `json:"started"`
	Finished  time.Time      `json:"finished,omitempty"`
	Watch     time.Duration  `json:"-"`
	WatchSecs int            `json:"watch_seconds"`
	Tolerance float64        `json:"object_tolerance"`
	Sites     []*RolloutSite `json:"sites"`
	Poisoned  bool           `json:"poisoned,omitempty"`
	Halted    string         `json:"halted,omitempty"`
}

type rolloutRegistry struct {
	mu   sync.Mutex
	list []*Rollout
}

var rollouts rolloutRegistry

// Rollouts returns what this process has run, newest first. It is
// deliberately in memory only: a rollout is a thing happening now, and a
// half-finished one recovered from disk after a restart would have nobody
// watching its watch window.
func (s *Service) Rollouts() []*Rollout {
	rollouts.mu.Lock()
	defer rollouts.mu.Unlock()

	out := make([]*Rollout, len(rollouts.list))
	copy(out, rollouts.list)
	sort.Slice(out, func(i, j int) bool { return out[i].Started.After(out[j].Started) })
	return out
}

// StartRollout delivers each site's desired generation, one box at a time,
// watching each before moving on.
//
// One at a time, not in waves of N: the whole value of a canary is that
// the first failure costs one box. With a fleet large enough for that to
// be slow, the operator can start several rollouts.
func (s *Service) StartRollout(sites []string, watchSecs int, tolerance float64, by string) (string, error) {
	store := s.Generations()
	if store == nil {
		return "", fmt.Errorf("no settings store is attached")
	}

	watch := defaultWatchWindow
	if watchSecs > 0 {
		watch = time.Duration(watchSecs) * time.Second
	}
	if tolerance <= 0 {
		tolerance = defaultObjectTolance
	}

	r := &Rollout{
		ID:        fmt.Sprintf("rollout-%d", time.Now().UnixNano()),
		StartedBy: by,
		Started:   time.Now(),
		Watch:     watch,
		WatchSecs: int(watch / time.Second),
		Tolerance: tolerance,
	}

	for _, site := range sites {
		desired, ok := store.GetDesired(site)
		if !ok || !desired.Adopted {
			r.Sites = append(r.Sites, &RolloutSite{
				Site: site, State: RolloutSkipped,
				Detail: "not adopted; nothing is delivered to a box whose config has never been seen here",
			})
			continue
		}
		r.Sites = append(r.Sites, &RolloutSite{
			Site: site, Generation: desired.Generation, State: RolloutPending,
		})
	}

	rollouts.mu.Lock()
	rollouts.list = append(rollouts.list, r)
	if len(rollouts.list) > 50 {
		rollouts.list = rollouts.list[len(rollouts.list)-50:]
	}
	rollouts.mu.Unlock()

	go s.runRollout(r)
	return r.ID, nil
}

func (s *Service) runRollout(r *Rollout) {
	defer func() {
		r.Finished = time.Now()
	}()

	for _, rs := range r.Sites {
		if rs.State == RolloutSkipped {
			continue
		}
		if r.Halted != "" {
			rs.State = RolloutSkipped
			rs.Detail = "a previous wave failed: " + r.Halted
			continue
		}

		rs.Started = time.Now()
		rs.Expected = s.objectCount(rs.Site)
		rs.AlertsBefore = s.alertCount(rs.Site)

		res, err := s.DeliverSite(rs.Site)
		if err != nil {
			rs.State = RolloutFailed
			rs.Detail = err.Error()
			if res != nil && len(res.Complaints) > 0 {
				rs.Detail += " - " + res.Complaints[len(res.Complaints)-1]
			}
			rs.Finished = time.Now()
			// The daemon refused it and is still running what it was.
			// Nothing to roll back, but the rest of the fleet must not
			// be handed the same config.
			s.poison(r, rs, "the daemon refused it: "+rs.Detail)
			continue
		}

		rs.State = RolloutDelivered
		rs.Objects = res.Objects

		// Criterion 2: did we lose hosts? The daemon counted the objects
		// in the config it just accepted, so this is checkable before the
		// watch window even starts.
		if rs.Expected > 0 && rs.Objects > 0 {
			drop := float64(rs.Expected-rs.Objects) / float64(rs.Expected)
			if drop > r.Tolerance {
				rs.State = RolloutRolledBack
				rs.Detail = fmt.Sprintf(
					"object count fell from %d to %d (%.0f%%, tolerance %.0f%%)",
					rs.Expected, rs.Objects, drop*100, r.Tolerance*100)
				s.rollbackAndPoison(r, rs)
				continue
			}
		}

		// Criterion 3: watch it.
		rs.State = RolloutWatching
		time.Sleep(r.Watch)
		rs.AlertsAfter = s.alertCount(rs.Site)

		if rs.AlertsAfter-rs.AlertsBefore > alertSpikeAllowance {
			rs.State = RolloutRolledBack
			rs.Detail = fmt.Sprintf("alerts went from %d to %d during the watch window",
				rs.AlertsBefore, rs.AlertsAfter)
			s.rollbackAndPoison(r, rs)
			continue
		}

		rs.State = RolloutOK
		rs.Finished = time.Now()
		log.Printf("rollout %s: %s took generation %d (%d objects)",
			r.ID, rs.Site, rs.Generation, rs.Objects)
	}
}

// rollbackAndPoison undoes one box and stops the rest of the rollout.
func (s *Service) rollbackAndPoison(r *Rollout, rs *RolloutSite) {
	if _, err := s.RollbackSite(rs.Site); err != nil {
		rs.Detail += fmt.Sprintf(" - and the rollback failed: %v", err)
		rs.State = RolloutFailed
	}
	rs.Finished = time.Now()
	s.poison(r, rs, rs.Detail)
}

func (s *Service) poison(r *Rollout, rs *RolloutSite, why string) {
	r.Poisoned = true
	r.Halted = fmt.Sprintf("%s: %s", rs.Site, why)
	if store := s.Generations(); store != nil {
		store.PoisonGeneration(rs.Site, rs.Generation, why)
	}
	log.Printf("rollout %s halted at %s: %s", r.ID, rs.Site, why)
}

// objectCount is how many objects a site currently reports, from the last
// snapshot. It is the number the delivered config has to stay near.
func (s *Service) objectCount(site string) int {
	status := s.cached()
	if status == nil {
		return 0
	}
	n := 0
	for i := range status.Hosts {
		if hostSiteOf(&status.Hosts[i]) == site {
			n++
		}
	}
	return n
}

// alertCount is how many of a site's hosts are not OK right now.
func (s *Service) alertCount(site string) int {
	status := s.cached()
	if status == nil {
		return 0
	}
	n := 0
	for i := range status.Hosts {
		h := &status.Hosts[i]
		if hostSiteOf(h) == site && h.OverallStatus != "OK" && !h.Stale {
			n++
		}
	}
	return n
}

func hostSiteOf(h *models.HostStatus) string {
	if h.Site != "" {
		return h.Site
	}
	site, _ := SplitQualified(h.ObjectName)
	return site
}

// cached is the last snapshot the poller stored. The rollout reads it
// rather than forcing a fetch: the numbers it compares are exactly what
// the operator is looking at.
func (s *Service) cached() *models.SysmonStatus {
	s.cacheMu.Lock()
	defer s.cacheMu.Unlock()
	return s.cachedStatus
}
