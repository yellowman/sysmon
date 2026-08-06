# Service SLOs: a sysmon-web feature

Status: design. Nothing here is built.

## What it is

A **service** is a named group of monitored objects with an availability
target. sysmon answers "is this host up"; a service answers "is the VPN
working, and did it stay inside 99.9% this month?"

- **Three states.** A service is UP, DEGRADED, or DOWN. DEGRADED is the
  tier the per-host model lacks: an RTT threshold breach pages with the
  same urgency as a dead router because there is nowhere else for it to
  go.
- **An error budget.** 99.9% over 30 days allows ~43 minutes of DOWN. The
  budget is what is left of that allowance.
- **Burn rate.** Consuming budget faster than the window sustains is an
  alert in its own right, and it fires while there is still budget left.

Services live in sysmon-web, not sysmond. One sysmond sees one site; only
sysmon-web sees a fleet, so only sysmon-web can say whether a cross-site
service is up. The C daemon needs no change.

Everything the feature needs already exists in sysmon-web:

- **The fleet view.** The poller refreshes every daemon's state every
  second (`StartPoller(1 * time.Second)`), so the component states a
  service aggregates are already in memory, fleet-wide.
- **Names that survive.** Components bind by qualified object name
  (`metro:vpn-gw`), the same key the delta protocol, history, push and
  acks use. Names are looked up against each snapshot, so there are no
  pointers into a config tree and no dangling references when a daemon
  reloads.
- **Persistence.** history.db already records 48 hours of host
  transitions in bbolt. Service state transitions are the same shape, and
  a 30-day SLO window is a retention setting.
- **Delivery.** The push service already grades severity per event and
  collapses per key. Service alerts reuse it.

## The model

Services are sysmon-web configuration, not sysmon.conf. They live in
settings.db and are edited on an admin page and API, like agent tokens. A
service spans sites, so no single box's config could hold it.

```json
{
  "name": "customer-a-vpn",
  "description": "VPN service for Customer A across 3 sites",
  "slo": { "availability": 99.9, "window_days": 30 },
  "components": [
    { "object": "metro:vpn-gw",  "critical": true  },
    { "object": "depot:vpn-gw",  "critical": true  },
    { "object": "metro:vpn-rtt", "critical": false }
  ],
  "burn_rate_alert": 10
}
```

A component is a reference and one flag. Thresholds stay on the object
(`rtt_threshold`, `snmp-high`, …). If a service needs a different
threshold than the object has, that is a second object.

## State

State is boolean:

- **DOWN** when any critical component is failing.
- **DEGRADED** when every critical component is fine and any non-critical
  one is failing.
- **UP** otherwise.

There are no weights and no health score. If a component matters enough
to weight up, mark it critical.

**A component is "failing" when its check fails, not when it has paged.**
The web UI's WARNING/CRITICAL split is paging bookkeeping - "has anyone
been told yet" - not severity. For SLO arithmetic WARNING and CRITICAL
both count as failing.

**A stale component is unknown, not down.** When a site drops its link,
its hosts are marked `Stale` and sysmon-web knows nothing about them.
Unknown time is excluded from the availability calculation and reported
separately as measurement coverage ("99.95% available, 97% measured").

**A component that names no known object** (deleted, renamed, site
unadopted) shows as a configuration error on the service, counts as
unknown, and is flagged in the UI.

## Measurement and storage

Record **state transitions, not samples**: `(service, state, since,
until)`, written to bbolt when the state changes, as history.db records
host transitions. Availability over a window is an integral over
intervals, and a service that never changes state writes nothing.

The evaluator runs off the same cadence as the poller, reading the
snapshot it already produced. Evaluating a service is a map lookup per
component; a hundred services is microseconds.

Retention is the longest configured window plus margin.

Transitions are in bbolt, so a sysmon-web restart loses nothing but the
seconds it was down, which are recorded as unknown.

## Alerts

Through the existing push service, per service, collapsed on the service
name:

- **DOWN** - critical severity (loud, like a host CRITICAL today)
- **DEGRADED** - warning severity (silent, shade-only)
- **Burn rate exceeded** - warning; fires when budget is being consumed
  at more than `burn_rate_alert` times the sustainable rate over the
  recent evaluation period
- **Budget exhausted** - critical, once per window

## API and UI

Same access rule as the rest of the API: status is open, configuration is
admin-only.

```
GET    /api/services                    all services with state, budget, coverage
GET    /api/services/<name>             detail: components, transitions, window math
POST   /api/services                    create/update (admin)
DELETE /api/services/<name>             remove (admin)
```

UI: a Services page listing each service with state, availability vs
target, budget remaining and a burn sparkline; a detail view showing
per-component state and the transition log. The dashboard gets a services
strip above the host cards.

## Phases

1. **Model + evaluator.** Store, bind-by-name, three states, unknown
   handling, transitions in bbolt. Tests drive the evaluator with
   synthetic snapshots, which the delta tests already show how to do.
2. **Windows + budget.** Availability integral, error budget, burn rate.
   Pure functions over transitions; test with fabricated histories.
3. **Alerts + UI.** Push wiring, the two pages, dashboard strip.

## Still open

- Multiple windows per service (30d and 7d at once). The transition store
  supports it; the config and UI cost is the question.
- Scheduled maintenance windows - planned downtime that should not burn
  budget. Not in the first version.
- Whether budget/coverage belong in the mobile apps' delta feed or stay
  web-only at first.
