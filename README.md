# sysmon

Network monitoring that pages you when things break - and now tells your
phone, your browser, and your history log too.

sysmon is a fast, no-nonsense network monitoring system built around a
small C daemon (`sysmond`) that has been watching networks since the
1990s. This repository is its modern era: the same battle-tested engine,
now with a live web dashboard, native Android and iOS apps, push
notifications, and CI that builds everything on every push.

## What's in the box

| Component | Language | What it does |
|---|---|---|
| `src/` - sysmond | C | The monitoring engine: ping/tcp/dns/http/smtp/imap/snmp checks, dependency trees, paging, SNMP traps |
| `web-ui/` - sysmon-web | Go | Web dashboard + JSON API, FastCGI (nginx/httpd) or standalone HTTP |
| `android/` | Kotlin / Compose | Native Android app |
| `ios/` | Swift / SwiftUI | Native iOS app |

## Features

### Monitoring engine (sysmond)
- Checks: ICMP ping (v4/v6, with packet-loss / RTT / jitter thresholds),
  TCP, DNS, HTTP, SMTP, IMAP, POP3, NNTP, SSH, Radius, SNMP, and more
- **No net-snmp**: sysmond speaks SNMP itself - v1/v2c GET for polling,
  v1/v2c trap decoding for what arrives on 162. That is the whole of the
  protocol it ever used, so there is no library to find, no OpenSSL on
  the link line, and no configure probe that can quietly leave you with a
  daemon that rejects every `type snmp` object. Counter64 values are read
  as 64-bit rather than guessed at, which the old net-snmp path got
  wrong. Both halves are fuzzed under ASan/UBSan, and `make check` runs a
  differential test against net-snmp's own client when you point it at an
  agent. Per-object `snmp-version "1";` for agents too old for v2c
- Dependency trees: when a router dies, its children don't page you
- Flap damping, ack/notification thresholds, per-contact schedules
- **SNMP trap reception, decoded**: v1 and v2c traps are parsed - trap
  identity, severity, vendor and every varbind - so an alert reads
  "linkDown on GigabitEthernet0/1" instead of "a trap arrived". Traps
  from unknown sources are logged too, because they are usually a device
  nobody got around to monitoring. Only packets that really are traps
  can page you; junk aimed at port 162 no longer wakes anyone
- Privilege dropping with a small setuid ping helper
- Echo replies verified by source address, not just ICMP ident - stray
  or reflected packets can't "revive" an unrelated down host
- Outage clocks survive failure-kind changes: WARNING escalating to
  CRITICAL is one outage with one start time

### Web UI (sysmon-web)
- Live dashboard: status cards, active alerts with one-click
  acknowledge, daemon state
- Hosts view: table and card layouts, search, sort, client-side
  pagination, per-host detail with check breakdown
- **Alert history**: every up/down transition from the last 48 hours,
  with how long each host spent in its previous state, filterable to
  downs-only
- **Delta protocol**: clients poll `?since=<rev>` and receive only what
  changed - a steady 300-host system transfers ~400 bytes per poll
  instead of ~150 KB
- Config editor: structured forms or raw text, with automatic backups
- Push administration: credential upload (stored in bbolt, never in
  sysmon.conf), live FCM key verification against Google, a per-device
  Test button, and a **Push Delivery Pipeline** panel that names the
  exact broken link when notifications aren't flowing
- **SNMP trap browser**: the decoded trap stream from sysmond - name,
  severity, interface, matched object, and every varbind with its MIB
  name and meaning (`ifOperStatus (down)`), filterable by source and
  severity
- Dependency map: the whole config as a graph, drag nodes into place
  (the layout is shared with every other session), right-click a host to
  add a dependent under it or stamp one out from a device template
- API metrics, session/error logs, user management with roles
- Runs as FastCGI behind nginx or OpenBSD httpd(8), or standalone with
  `-listen` for development; drops privileges after binding

### Mobile apps (Android + iOS)
- Live host list and alerts driven by the delta protocol - a shared
  poller keeps one warm host map per app, patching only what changed
- **Severity-aware push notifications**: CRITICAL is loud (sound,
  heads-up, breaks through Focus on iOS); WARNING and recoveries are
  silent, shade-only. Per-host collapse keys mean one notification per
  host showing its current truth - a WARN is replaced by the CRIT that
  follows it, and by the recovery after that
- History tab: last 48 hours of transitions with durations and
  ALL / DOWNS / RECOVERIES filtering
- Alert sorting (time down / name / IP, both directions), host detail
  with admin acknowledge, paused-host and paused-daemon indicators
- Self-diagnosing notifications: the app detects blocked channels or
  disabled permissions and deep-links to the exact settings page;
  Settings offers both a local display test and a full
  server-to-Firebase round-trip test
- Sessions last as long as the app is in use (30-day sliding renewal)

### Push notification pipeline
- Android via FCM HTTP v1 (OAuth service account, uploaded through the
  admin UI)
- iOS via the same Firebase pipeline (nested `apns` payload; upload an
  APNs auth key to the Firebase console once - never expires), or
  direct cert-based APNs for Firebase-less deployments
- The server live-verifies the FCM key with Google hourly and on every
  auth failure, so a revoked key shows up as a red badge instead of
  silence

### CI - no Mac, no local SDK required
- **Android**: every push builds an installable debug APK on Linux
  runners (`.github/workflows/android.yml`)
- **iOS**: every push generates the Xcode project from
  `ios/project.yml` (XcodeGen) on GitHub's macOS runners and uploads an
  unsigned IPA, sideloadable via AltStore/Sideloadly
  (`.github/workflows/ios.yml`)
- Both runs double as the compile gate for the app code

## Aggregating several sysmonds

One sysmon-web fronts a fleet. **Daemons dial in; sysmon-web listens.**
Neither side does the opposite by default:

```sh
# sysmon-web: listens on :1347, generates and logs a certificate on first run
sysmon-web ...

# each box, in its sysmon.conf:
config sitename  "metro";
config aggregator "sysmon-web.example.net:1347";
config aggregator-token "...";                 # minted on the admin page
config aggregator-ca "/etc/ssl/sysmon-web-agent.pem";
```

sysmond **no longer listens on 1345 unless asked**. That socket was open on
every sysmond for most of the daemon's life, unauthenticated until `AUTH`,
on a process that ran as root; it is now opt-in with `config listen 1345`
(or `-p`), which is what you want if you use the `sysmon(1)` client against
a box directly. sysmon-web likewise only dials out if given `-sysmon`:

```sh
sysmon-web -sysmon "metro.noc:1345,north.noc:1345" ...   # the old arrangement
```

The design is in [docs/sysmond-aggregation.md](docs/sysmond-aggregation.md);
the shape of it:

- **Objects are namespaced** `site:object`. Each daemon carries a short
  `sitename` (the key, appearing in every alert and stored row) and a
  `sitedesc` (the human label the site selector shows). That qualified name
  keys alerts, history, push collapse, map layout and acknowledgements, so
  two sites' `coreswitch` never collide.
- **Anything that acts on one daemon gets a site selector** - config
  editing, the map, backups, reload. Status views aggregate across sites
  and filter optionally.
- **sysmond dials out to sysmon-web**, over TLS with a per-box token, and
  status and config share the one connection. Monitoring boxes live behind
  NAT and on management VLANs; outbound-only means no inbound firewall
  rules and no per-site VPN. A daemon that cannot reach sysmon-web keeps
  running its last known-good config and keeps paging - the monitoring
  outlives its management plane.
- **Config is distributed whole-file and validated by the target daemon's
  own parser** before it is allowed to take effect - in a forked child, so
  a config bad enough to crash the parser cannot take down the daemon that
  is still paging people. sysmon-web holds desired state, the daemon
  reports what it is actually running (`CONFIG-GEN`, one line per poll),
  and the difference is a hash comparison rather than a merge: in sync,
  pending, locally modified, unmanaged, rejected or unknown. A rejected
  delivery costs nothing - the running config is untouched until validation
  passes, and the previous files are back on disk before the reply is sent.
  A box that was edited at the console is never silently overwritten: the
  operator is offered the diff, and adopting the local version is the
  default, because the person at the console usually had a reason.
- **`/etc/sysmon.conf` is never written.** A managed box keeps its running
  copy under a directory it owns (`/var/lib/sysmon`, or `config
  generation-dir`), created for it at startup while still root, and loads
  that instead. The seed file stays exactly as the operator wrote it, is
  what the box falls back to if that directory is emptied, and is what
  "Unmanage" returns it to. The alternative - writing `/etc` from a
  daemon that has dropped privileges - is a bad trade to ask for in
  exchange for remote config. Files are named rather than located: a
  delivery carries plain filenames, and the daemon decides where they go,
  so nothing an aggregator sends is ever used to build a path.
- **Rollouts are canaried.** A generation goes to one box first, and
  "applied" is not success on its own: object count and alert rate are
  watched, and a spike rolls that box back automatically and blocks the
  rest of the fleet.
- **The apps carry two independent site filters**, both defaulting to all:
  what to *show* and what to *notify about*. Someone on call for one region
  wants waking only for it, but wants to see every site when they open the
  app - whether the neighbour is also down is the first question at 3am.
  Show is a request parameter so a phone watching one site never downloads
  the rest; Notify lives on the push subscription, because that is the only
  place it can be enforced.
- **The dependency map is per site**, because `dep` cannot cross daemons.
  Several sites can share a canvas as separate clusters, but no cross-site
  edge is invented - the honest way to express one is a `type sysm` check
  against the upstream daemon.

## Quick start

### Daemon
```sh
./configure && make
cp examples/sysmon.conf.dist /usr/local/etc/sysmon.conf   # then edit
src/sysmond -f /usr/local/etc/sysmon.conf
```

### Web UI
```sh
cd web-ui/backend
go build ./cmd/sysmon-web
# development: standalone HTTP
./sysmon-web -listen 127.0.0.1:8180 -config /usr/local/etc/sysmon.conf -debug
# production: FastCGI socket for nginx/httpd - see web-ui/nginx.conf.example
```
First login is `admin` / `sysmon` - change it immediately (Admin page).
State lives in `/var/lib/sysmon` (auth, push credentials, settings,
alert history).

### Apps
Grab the latest APK / IPA from the repository's Actions artifacts, or
build locally:
- Android: drop your `google-services.json` into `android/app/`, then
  `gradle assembleDebug`
- iOS: `brew install xcodegen && cd ios && xcodegen generate`, open in
  Xcode (add `GoogleService-Info.plist` for push)

For push notifications end to end: upload your Firebase service-account
JSON on the Admin page, enable the push toggle, and check the Push
Delivery Pipeline panel - it will tell you what, if anything, is
missing.

## History

sysmon was written by Jared Mauch and has monitored real networks for
nearly three decades. The docs/ directory preserves the original
documentation; docs/CHANGES tracks the long arc. Same engine, new era.
