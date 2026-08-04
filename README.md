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
