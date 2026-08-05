# Aggregating many sysmonds behind one sysmon-web

Status: design, agreed.

Today sysmon-web manages exactly one sysmond: it dials `localhost:1345`,
and it reads and writes that daemon's `sysmon.conf` as a local file. This
document describes turning it into the front end for a fleet, and the
decisions taken along the way.

The guiding constraint, which every decision below serves:

> **sysmond must outlive its management plane.** No web UI being down,
> unreachable or wrong may stop a daemon from monitoring and paging.

---

## 1. Object identity

Objects are namespaced by the daemon that owns them:

    <site>:<object>

Each daemon carries **two** names, and the distinction matters:

    config sitename "sysmon-metro";                        /* the key */
    config sitedesc "Metro Station Monitoring (Linux)";    /* the label */

`sitename` is the identity. It is short, it appears in every stored key and
every alert (`sysmon-metro:corerouter`), and changing it is a rename that
orphans history - so it is chosen once and left alone. It is a name and not
an index because boxes get replaced and indices get reused.

`sitedesc` is presentation only. It is what the site selector shows, what a
NOC person reads, and it can be rewritten any afternoon without consequence
because nothing keys on it.

An unnamed daemon reports `local` with no description, so single-box
installs are unaffected.

The separator is `:` because it cannot appear in a sysmon object name and
reads naturally in an alert: `bend-noc:awbreyswitch`.

`sitename` is `[A-Za-z0-9_-]+` and nothing else, rejected at config load
if it isn't.

This identity is the key for:

- the delta protocol (`hostSignature`, `hostRev`, `removedAt`)
- push collapse keys - two sites' `coreswitch` must not collapse into one
  notification
- alert history rows
- map layout persistence
- acknowledgement and note edits, which must reach the right daemon

It is deliberately settled **before** multi-box work, because every one of
those is a stored key. Retrofitting a namespace onto persisted data means a
migration of five stores; adding it up front costs a string concatenation.

**Display**: the UI shows the bare object name when a single site is in
view and the qualified name when more than one is. The qualified name is
what is stored and what the API returns.

**Every page that acts on one daemon needs a site selector.** Config
editing, the dependency map, raw-config view, backups and reload are all
per-daemon operations - there is no such thing as editing "the" config once
there is more than one. The selector shows `sitedesc` with `sitename` as
the secondary line, and the chosen site is sticky across pages so an
operator working on one box does not have to reselect it on every screen.
Status pages (dashboard, alerts, history, traps) aggregate by default and
filter by site optionally, because those are read-only and cross-site
context is the point of them.

### Mobile apps: two filters, not one

The apps carry **two independent settings**, both defaulting to all sites:

    Show          all sites  |  one site
    Notify me about   all sites  |  one site

They are separate because the cases genuinely differ. Someone on call for
one region wants to be woken only for that region - but when they open the
app at 3am they usually want to see everything, because whether the
neighbouring site is also down is the first diagnostic question. Forcing
one control to serve both makes that person choose between being woken too
often and being unable to see context.

They are enforced in different places, for different reasons:

- **Show** is a request parameter: `?site=sysmon-metro` on the status and
  history endpoints. Not stored server-side and not filtered on the phone -
  a phone watching one site out of twenty should not be downloading twenty
  sites' worth of hosts over a mobile connection, and a parameter costs no
  server state and changes instantly.

  This works unchanged with the delta protocol: `rev` stays global and
  monotonic, and the server drops non-matching hosts from `changed` and
  `removed`. A client whose delta is empty because the change was in a site
  it does not watch simply stores the new rev and moves on. The one thing
  to get right is that *widening* the filter needs a full resync - the
  client's warm cache has never seen the sites it was excluding - so a
  changed `site` parameter forces `full`.

- **Notify me about** lives on the push subscription, because that is the
  only place it can be enforced. Filtering notifications in the app would
  mean the phone still buzzes at 3am for a site its owner excluded and then
  hides the row explaining why. The server skips subscribers whose filter
  does not match the host's site.

Consequences:

- `/api/sites` lists the fleet (name, description, reachable) so both
  pickers offer a list rather than asking someone to type a name.
- With **Show** narrowed to one site, object names render bare - the
  prefix is noise when only one site is in view. Showing all sites renders
  the qualified `site:object`.
- Changing **Notify** re-registers the subscription. Until that succeeds
  the server is still using the old filter, and the app says so rather than
  quietly disagreeing with what the phone will actually receive.
- Setting **Notify** to one site offers - but does not force - matching
  **Show** to it, since that is the common intent and the wrong default to
  impose.
- A filter pointing at a site that has left the fleet is **not** silently
  reset to "all". A phone that quietly starts alerting for everything is
  worse than one that alerts for nothing and says the site it was watching
  is gone.

### A site that goes dark keeps its hosts

When a poll cannot reach a daemon, its hosts stay in the merged view,
flagged `stale` with a `stale_since` of the last time it answered. They are
not dropped.

Dropping them looks tempting and is wrong twice over:

- **It lies about the fleet.** The hosts do not disappear from a map, an
  alert list and a history because they are fine; they disappear because
  nobody is watching them - and a row that is gone looks identical
  either way.
- **It churns the delta.** Hosts absent from a snapshot are reported
  *removed*. Every client deletes them, and on recovery every one is
  re-added - a revision bump per host in each direction, fleet-wide, for a
  link that blipped for three seconds.

A stale host keeps its last status, so nothing transitions and nobody is
paged by a site going quiet. What changes is the flag, which is part of the
host's signature: exactly one delta on the way out and one on the way back.
A site nobody has ever reached contributes nothing - there is no last
report to show.

---

## 2. Connection direction: sysmond dials out

sysmond opens the connection to sysmon-web, not the other way around, and
**neither daemon does the opposite by default**:

- sysmond does not listen at all unless `config listen` (or `-p`) asks it
  to. That socket was open on every sysmond for most of the daemon's life,
  unauthenticated until `AUTH`, on a process that ran as root - and it was
  the largest piece of attack surface the daemon had. Inverting the
  direction retires it for anyone using sysmon-web.
- sysmon-web does not dial anyone, ever. It listens on 1347 and waits.
  The code that dialled a daemon is gone rather than defaulted off: it was
  a second way in with a second credential (the shared authkey), and one
  direction that is always right beats two that mostly are.

The `sysmon(1)` client still connects to a daemon directly, and that is
still a perfectly good way to run - it is what `config listen` is for. It
just means that box is standing alone rather than being part of a fleet.

**Why:**

- **Firewalls.** Monitoring boxes sit behind NAT, on management VLANs, at
  customer premises. Outbound-only means no inbound rules, no port
  forwarding, no per-site VPN.
- **Blast radius.** One credential per box, revocable centrally. The
  alternative has sysmon-web holding credentials for every box, so
  compromising the UI compromises the fleet.
- **Failure mode.** A daemon that cannot reach sysmon-web keeps running its
  last known-good config and keeps monitoring and paging. This is the
  guiding constraint made concrete.
- **Bootstrap.** A new box is given one token and appears in the UI.
  Push would require teaching the UI about the box first, which is backwards.

**The connection carries both directions.** sysmond already talks once per
second; inverting who dials means status flows up and config flows down the
same socket. The sequence-number protocol built for `CONF <seq>` and
`TRAPS <seq>` works unchanged - the daemon simply serves those commands on
a connection it originated, and asks one extra question per cycle:

    CONFIG-GEN            -> 333 <generation> <hash>   (what should I be running?)

### Transport

TLS, with the client authenticating by bearer token over the encrypted
channel. Client certificates are stronger but require running a CA; a token
is provisioned by pasting one string and revoked by deleting one row, which
matches how these boxes actually get deployed. mTLS stays available for
sites that want it.

**Dialect: OpenSSL 1.1.1 / LibreSSL.** That is the universal floor - it is
what ships on OpenBSD, on long-lived Linux installs, and what LibreSSL
tracks. Specifically:

- `TLS_client_method()`, never `SSLv23_client_method()`
- `SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION)`
- hostname verification through `X509_VERIFY_PARAM_set1_host()` on the
  connection's verify param - present in 1.0.2 through 3.x and in LibreSSL,
  unlike some of the newer convenience wrappers
- explicit `SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL)` plus either the
  system trust store or a pinned CA file
- no 3.0-only surface: no providers, no `EVP_MAC`, no
  `SSL_CTX_set_ciphersuites` (TLS 1.3-only and absent from older LibreSSL)

**Fallback.** The existing inbound listener stays. A single-box install
where sysmon-web dials `localhost:1345` keeps working exactly as it does
now; dial-out is what a `config aggregator "…";` directive turns on.

---

## 3. Config distribution

The config file remains the source of truth **on each box**. sysmon-web
holds *desired state*; the daemon holds *actual state*; distribution
reconciles them.

### Unit of transfer: the whole file

Not field-level sync. A generation is a complete set of files (the main
config and every file it includes), delivered together.

    fetch -> validate locally -> swap atomically -> reload -> report

Validation is **sysmond's own parser, on the target box**. This is the step
that makes remote config survivable: sysmon-web's Go parser and sysmond's
lexer are two implementations of one grammar and can disagree, and the only
opinion that matters is the one held by the daemon that has to run it.

It runs in a forked child, on the real files, so that a config bad enough
to take the parser down takes the child down instead of the daemon that is
still paging people. What it refuses:

- anything the lexer marks as a config error
- a config that declares nothing to monitor
- a `root` naming an object nobody defined - which parses perfectly and
  quietly makes every object unreachable from the root

It also reports the object count, which the canary compares against the
count the box was running before the delivery.

The order on the box is: write into a *new* generation directory, validate
there, then swap a symlink. Nothing that is running is touched until that
last step, so a rejected delivery costs nothing at all - not a moment of
bad config on disk, not a byte of the running one - and the staging
directory is simply removed. A failed validation reports the parser's own
words back to the UI, verbatim, against that generation, for that box.

### The commands

    CONFIG-GEN       what am I running?    -> generation, hash, file count
    CONFIG-GET       give me what you run  -> every file, byte for byte
    CONFIG-PUT       run this instead      -> stage, validate, swap, reload
    CONFIG-ROLLBACK  undo the last PUT     -> swap back, reload
    CONFIG-REVERT    stop being managed    -> back to the seed config

All four need the authkey: a config carries community strings and contact
addresses on the way out, and decides what gets monitored on the way in.
`CONFIG-GEN` is the one asked every cycle - one line each way, on the
connection the poller already has open - which is what makes "somebody
edited this box" visible in seconds rather than whenever someone looks.

Paths and contents are base64 on the wire. The hash is over the decoded
bytes.

### The seed config is never written

`/etc/sysmon.conf` - or whatever `-f` names - is read-only to the daemon,
permanently. A managed box keeps its running copy somewhere it owns:

    <gendir>/main            the entry file's name, e.g. "sysmon.conf"
    <gendir>/current  ->     gen-0000000007
    <gendir>/previous ->     gen-0000000006
    <gendir>/gen-0000000007/ that generation's files, plus .order

`<gendir>` is `/var/db/sysmon` on every platform - one path to recite
rather than one per OS, since "where does this box keep its config" is
usually asked about somebody else's box - and moves with `config statedir`.
It is created, parent included, and handed to the daemon's user at startup
while the process is still root.

It holds everything the daemon writes, not only generations: the pidfile,
the log when logging to a file, the shutdown state dump, and the scratch
file the status page is built in. There used to be a directive per file -
`pidfile`, `savestate`, `statustempdir`, `logging file`, `aggregator-ca` -
and every one of them was a path a delivered config could aim anywhere the
daemon could write. One directory removes all five conflicts at once, and
leaves an operator with one path to get right instead of five. The
directives are still parsed, and warn that they are no longer used.

`config statusfile` keeps its path: it names a *published output*, and
where it is published is a local decision about a web server's document
root. It is still built in the state directory and renamed into place, so
a web server never sees a half-written page.

The daemon loads `<gendir>/current/<main>` when it exists and the seed
otherwise. Three things follow from that "otherwise":

- **The alternative was worse.** Writing the delivered config back over
  `/etc/sysmon.conf` means `/etc` has to be writable by the user sysmond
  drops to.
- **A wiped state directory is survivable.** The box comes back on the
  config an operator wrote, not on nothing and not on half of something.
- **There is a way out.** `CONFIG-REVERT` - "Unmanage" in the UI - drops
  the `current` pointer and the box is running its own config again. The
  generations stay on disk as the record of what was delivered.

`config statedir` is read from the **seed only**, and locked once the
seed is parsed. A delivered config carrying a different value is inert - it
cannot move the directory the daemon is currently running out of. It is not
a security control on its own (a box with real filesystem permissions gives
the daemon exactly one directory and no others, so a pushed value could not
take effect anyway); it just means the answer to "where does this box keep
its config" does not depend on which generation happens to be live.

**Files are named, not located.** A delivery carries plain filenames - no
slashes, no leading dots - and this side decides which directory they land
in. Nothing the aggregator sends is ever used to build a path. The content
hash is over those names too, which is what lets the same config hash
identically as a seed in `/etc` and as the running copy in a generation
directory; without that, adopting a box and delivering its own bytes
straight back would read as a change forever.

The consequence: a config whose `include` names a path
(`include "/etc/sysmon.d/hosts.conf"`) cannot be managed, because copying
it into one directory would change what it points at. The daemon says so
in its `CONFIG-GEN` reply and the fleet page shows it, rather than the
delivery failing.

### Write includes as absolute paths

`include "/etc/sysmon.d/hosts.conf"` is what a config is expected to use,
and it is opened exactly as written.

A relative include is ambiguous. It resolves against the working directory,
and sysmond does not set one - it inherits whatever started it, which
differs between a shell, systemd (which defaults to `/`) and an rc.d
script. The same directive can name different files on two boxes with
identical configs.

**That is not repaired, on purpose.** Re-pointing a relative include at the
config's directory would silently change which file an existing config
opens, on boxes that have been running for years, to fix something nobody
asked to have fixed - and a config that resolves differently after an
upgrade is a worse problem than one that was ambiguous all along.

There is exactly one repair, and it is a fallback rather than a redirect:
when a relative include does **not** resolve at all, the config file's own
directory is tried before giving up, and the daemon logs that it did. It
can only turn a silently-missing include into one that loads; it cannot
change a config that already works. (Verified three ways: a config whose
include resolves from the working directory still gets that file and logs
nothing; one whose include resolves nowhere gets the config directory's
copy with a log line; one with neither fails exactly as before.)

### The consequence for managed configs

Inside the managed directory an include must be a plain filename. Those
files are copies the daemon wrote into one flat directory it owns, so a
bare name is a member of the set that was validated and anything else names
something outside it.

Which means: **a config whose includes are absolute paths cannot be
config-managed.** Copying `/etc/sysmon.d/hosts.conf` into a generation
directory would not change what the main file points at, so the copy would
be delivered and never read. The daemon says so in its `CONFIG-GEN` reply
rather than letting it be discovered at delivery time, and the fleet page
shows the reason.

Such a box is still monitored, aggregated, alerted on and shown like any
other - only its config stays read-only in the UI. The options for widening
that are: keep the whole config in one file, use bare filenames beside the
main config, or manage only the main file and treat absolutely-included
fragments as read-only members of the hash. Not yet decided.

### Where a box reports is not editable from here

`config aggregator` and `config aggregator-token` decide which sysmon-web
a box reports to. The editor refuses any change to either, in any file of
the config.

sysmond keeps the ability to be moved - a box behind NAT may one day need
to point somewhere else - so this is a limit in the management plane, not
in the daemon. It is a limit because moving a box also needs the
certificate for its new destination, and this side has no way to put that
on the box.

The failure is quiet, which is why this is refused rather than warned
about. The delivery succeeds and the reply comes back on the old
connection; the daemon then reloads and dials somewhere that cannot
answer. From here that is indistinguishable from a network fault, and the
repair is a drive to the console.

Removing the directive is in fact survivable today - the seed still
carries it, the seed is parsed first at every start, and the value is not
cleared when a config omits it - but it is refused too, since that
survival is a side effect of the load order rather than anything the
editor checks.

Change it in the seed config, on the box, where the certificate can be put
in place at the same time.

---

## 4. Editing: splice, never regenerate

`Generate()` rebuilds the config from the parsed model. That is why:

- comments do not survive a save
- `include` directives do not survive a save - the parser follows them
  (`collectIncludes`) but the generator has no notion of them, so every
  included object is flattened into the main file and the includes vanish

That second one is live data loss on a single box today, and it becomes
fleet-wide the moment configs are distributed. It is also what makes
byte-stable hashing impossible.

**The fix is to stop regenerating.** The parser retains, for every object
and directive, the file it came from and its byte range within that file.
An edit becomes a minimal replacement of exactly those bytes:

- comments survive because nothing touches them
- indentation and file organisation survive
- includes survive because an object is edited in the file it lives in
- an unedited config hashes identically before and after a round trip

This is how `gofmt` and every serious config editor work, and this grammar
is tiny: `config …;`, `object NAME { … };`, `#` comments, `include`.

The rejected alternative - attaching comments to the node that follows them,
as YAML libraries do - is lossy at the edges (trailing comments, comments
in odd positions) and forces a canonical reformat of the whole file.

---

## 5. The dependency map is per daemon

Worth settling early, because it constrains the UI: **a dependency graph
cannot span daemons.** `dep` is resolved by name inside one sysmond's own
tree - there is no wire format, and no meaning, for "an object here depends
on an object over there". So the graph is per site as a matter of data, not
of presentation.

What follows from that:

- **One canvas may still show several sites**, as visually separate
  clusters with no edges between them. That is a wall-display view.
- **The default view is one site**, because a single real config already
  runs to 800 objects and five of those at once is not readable.
- **Layout storage does not fork.** Positions are keyed by the qualified
  name (`site:object`), so one store serves every site and filtering is a
  key prefix.
- **No invented cross-site edges.** It would be easy to let an operator
  draw a line between two sites in the map store alone. It would also be a
  lie: sysmond would not suppress the child's alert, and an operator who
  drew a dependency would reasonably assume it did. Refused.
- **There is a legitimate cross-site edge**, and it already exists:
  `type sysm` checks another sysmond. A site whose objects depend on an
  object that monitors the upstream site's daemon has expressed a real
  dependency that sysmond will actually honour, and the map should render
  it as the edge it is.

---

## 6. Consequences worth naming

**Two parsers, one grammar.** sysmon-web's Go parser and sysmond's flex
lexer can disagree. Mitigations, in order of value: validate on the target
box before swapping (§3); differential-test the two against the same corpus
and compare object sets; keep the grammar frozen.

**Scale.** One connection per box at one second. The incremental protocol
means a quiet box costs two round trips and no payload, so the cost is
per-box constant rather than per-object. The warm cache, revision counters
and sequence tracking all become per-box.

**Traps** are already per-daemon - whichever sysmond holds :162 at that
site receives them. They aggregate with the same namespacing.

**Acks and notes** must be routed to the owning daemon, which the namespace
makes trivial: split on `:`, look up the box.
