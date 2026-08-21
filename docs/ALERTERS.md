# Alerters: sending alerts to sysmon-web without being a sysmond

An alerter is a daemon with something to say and no fleet of hosts
behind it - a backup job, a UPS script, a RAID monitor, a cron
watchdog. It connects to the same TLS listener the monitoring boxes
use, proves itself with the same kind of minted token, and then sends
alerts. Those alerts ride the exact push pipeline a sysmond's host
transitions ride, with the same priorities: CRITICAL is loud on the
phones, WARNING and OK are quiet.

An alerter is never part of the fleet. It has no config to manage, no
hosts to poll, no generations to roll out. The Fleet page lists it in
its own "Alerters" section; the config editor and the map never see it.

## Getting a token

**Admin -> Monitoring boxes -> Add a box**, with the credential type
set to **External alerter** - the panel then shows the greeting line
below instead of sysmond config. Mint the token under the name the
alerter will use (letters, digits, `-`, `_`; max 64 chars). The name
is the alerter's identity - it appears in notifications and on the
Fleet page - so name the thing, not the machine: `backupd`, not
`server3`.

The type is part of the credential: a token minted for an alerter is
refused if something greets with it as a sysmond, and the other way
around.

Revoking the token on the same page cuts the alerter off immediately -
the live connection is closed and the next attempt is refused.

## Connecting

- **Transport**: TLS to sysmon-web's agent port (default `1347`, the
  `-agent-listen` flag). TLS is required, not negotiable - the first
  line carries a bearer token.
- **Server certificate**: sysmon-web generates a self-signed
  certificate on first start (or uses `-agent-cert`/`-agent-key`).
  Verify against that certificate - the same `aggregator-ca.pem` a
  monitoring box pins. Skipping verification hands your token to
  whoever answers the port first.
- The connection is long-lived. Stay connected and send alerts as they
  happen; reconnect with backoff when the link drops. The server never
  polls an alerter, so a silent alerter costs nothing.

## Protocol

Text lines, terminated by `\n` (a trailing `\r` is tolerated). One
line may carry at most 4096 bytes; a longer line is refused with
`444 line too long` rather than processed as something shorter than
what was sent (the connection survives). Every reply is one line
starting `333 ` (success) or `444 ` (refusal).

### Handshake (first line, within 20 seconds of connecting)

    ALERTER <name> <token> [application name...]

- `333 welcome` - authenticated; send alerts from here on.
- `444 rejected` - bad name/token pair, or the token is revoked. The
  socket closes; back off before retrying.
- `444 this token belongs to a sysmond` - the token was minted for (and
  first used by) a monitoring box; a token keeps the kind of its first
  handshake forever. Mint a separate token for the alerter.

Everything after the token is what the application calls itself -
free text up to 128 characters, e.g. `Bacula 15.0 nightly backups`.
It shows on the Fleet page and in alerts. Optional but worth sending:
the token name identifies, this describes.

The greeting verb is what separates an alerter from a monitoring box:
a sysmond says `HELLO` and gets polled, an alerter says `ALERTER` and
does the talking.

### Sending an alert

    ALERT <CRITICAL|WARNING|OK> <object> <text...>

- `<object>` names the thing the alert is about (same character rules
  as the alerter name). One alerter can alert about many objects.
- `<text>` is free-form to end of line, up to 512 characters
  (anything longer is truncated, not refused). Optional - omitted, a
  plain "name reports object STATUS" is generated.
- Reply is `333 ok` once accepted, or `444 <reason>` for a malformed
  line. A `444` never closes the connection; fix the line and carry on.
- `444 busy - ...` means the server's delivery pipeline is backed up
  and the alert was **not** accepted. Retry the same line after a short
  delay; `333 ok` is the only reply that means the alert was taken.
What `333 ok` promises, exactly: the alert is recorded in the web
UI's **alert history** - written to disk before the reply, visible on
the History page, surviving server restarts - and, when push is
enabled, queued for immediate phone delivery in order with everything
else this alerter has sent. The history record is the delivery
guarantee; push is the extra channel on top. Phone-side delivery is
best-effort (a provider outage after acceptance shows in the server
log and the admin Push Log, not on the wire), so if an alert matters,
keep re-sending transitions as the condition changes rather than
treating one 333 as the end of the story.

Semantics, identical to a sysmond's transitions:

- **CRITICAL** delivers loud: sound, heads-up on Android, time-sensitive
  on iOS.
- **WARNING** and **OK** deliver quiet: they land in the notification
  shade without a sound. Send `OK` when the condition clears - it
  replaces the earlier alert on the phones rather than stacking a
  second notification, because `<alerter>:<object>` is the collapse
  key, exactly as host alerts collapse per host.
- The master push switch in the admin UI only governs the phones:
  alerts sent while push is disabled are still accepted, recorded, and
  shown in the web UI - they just page nobody, and the server log says
  so.

### Keepalive and goodbye

    PING            ->  333 pong
    QUIT            ->  333 bye (server closes)

Send `PING` every minute or so if your network kills idle
connections; the server does not require it.

## Names, nicknames, and what an alert shows

Three names are in play, in order of what alerts display:

1. **Nickname** - optional, set by an admin on the Fleet page's
   Alerters card (the pencil next to "Shows as"). Wins when set.
2. **Application name** - what the alerter declared at handshake.
3. **Token name** - the identity; the fallback when nothing else is set.

The token name is what keys everything internally - collapse keys,
logs, the registry - so renaming a nickname never re-keys anything.

## What the web UI does with alerts

- Records each alert in the **History** page's log, alongside host
  transitions, as `<alerter>:<object>` - with the status it changed
  from and how long the previous state lasted, once this server has
  seen the object before.
- Push notifications to every subscribed phone, with the priority
  routing above, when push is enabled.
- The admin **Push Log** records each fan-out like any other.
- The **Fleet page** shows the alerter: connected or gone, what it
  shows as (nickname or application name), its address, how many
  alerts it has sent, and the last one.

Alerts are events, not tracked state: they do not appear on the
dashboard's host board and are not replayed to phones that subscribe
later. If a thing needs its state *tracked* - polled, colored,
acknowledged - it wants to be a monitored host on a sysmond, not an
alerter.

## Example: shell

```sh
# One-shot alert via openssl s_client (BSD echo; adjust for your shell).
{
  echo 'ALERTER backupd tok-abc123... Bacula 15.0 nightly backups'
  sleep 1
  echo 'ALERT CRITICAL nightly-backup tape jam in drive 2'
  sleep 1
  echo 'QUIT'
} | openssl s_client -quiet -connect sysmon-web.example.net:1347 \
      -CAfile aggregator-ca.pem -verify_return_error
```

## Example: Python

```python
import os, socket, ssl, time

HOST, PORT = "sysmon-web.example.net", 1347
NAME = "backupd"
# A credential stays out of source and argv: a mode-0600 file or the
# environment of the service unit that runs this.
TOKEN = os.environ["SYSMON_TOKEN"]

# Verify the certificate AND its name. sysmon-web puts the names the
# daemons dial it by into its generated certificate (the -agent-names
# flag); start it with the name you use here in that list. Only fall
# back to ctx.check_hostname = False against an old certificate that
# carries no usable name - it weakens the check to "any holder of a
# CA-signed cert", so regenerate the certificate instead if you can.
ctx = ssl.create_default_context(cafile="aggregator-ca.pem")

def connect():
    raw = socket.create_connection((HOST, PORT), timeout=20)
    tls = ctx.wrap_socket(raw, server_hostname=HOST)
    f = tls.makefile("rw", newline="\n")
    f.write(f"ALERTER {NAME} {TOKEN} Bacula 15.0 nightly backups\n"); f.flush()
    if not f.readline().startswith("333"):
        raise RuntimeError("rejected")
    return f

def alert(f, status, obj, text):
    f.write(f"ALERT {status} {obj} {text}\n"); f.flush()
    return f.readline().startswith("333")

f = connect()
alert(f, "CRITICAL", "nightly-backup", "tape jam in drive 2")
# ... later, when it clears:
alert(f, "OK", "nightly-backup", "backup completed after operator fixed the jam")
```

Reconnect on any read/write error, with backoff (the monitoring boxes
use a few seconds, doubling to a minute; do the same). The token is a
credential - keep it out of argv and world-readable files.
