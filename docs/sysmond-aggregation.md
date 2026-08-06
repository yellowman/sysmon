# Aggregating many sysmonds behind one sysmon-web

Status: design, agreed.

Today sysmon-web manages exactly one sysmond: it dials `localhost:1345`,
and it reads and writes that daemon's `sysmon.conf` as a local file. This
document describes turning it into the front end for a fleet.

> **sysmond must outlive its management plane.** No web UI being down,
> unreachable or wrong may stop a daemon from monitoring and paging.

---

## 1. Object identity

Objects are namespaced by the daemon that owns them:

    <site>:<object>

Each daemon carries two names:

    config sitename "sysmon-metro";                        /* the key */
    config sitedesc "Metro Station Monitoring (Linux)";    /* the label */

`sitename` is the identity. It appears in every stored key and every
alert (`sysmon-metro:corerouter`), and changing it is a rename that
orphans history. It is `[A-Za-z0-9_-]+` and nothing else, rejected at
config load if it isn't.

`sitedesc` is presentation only. It is what the site selector shows, and
nothing keys on it.

An unnamed daemon reports `local` with no description, so single-box
installs are unaffected.

The separator is `:`, which cannot appear in a sysmon object name.

The qualified name is the key for:

- the delta protocol (`hostSignature`, `hostRev`, `removedAt`)
- push collapse keys - two sites' `coreswitch` must not collapse into one
  notification
- alert history rows
- map layout persistence
- acknowledgement and note edits, which must reach the right daemon

**Display**: the UI shows the bare object name when a single site is in
view and the qualified name when more than one is. The qualified name is
what is stored and what the API returns.

**Every page that acts on one daemon carries a site selector.** Config
editing, the dependency map, raw-config view, backups and reload are
per-daemon operations. The selector shows `sitedesc` with `sitename` as
the secondary line, and the chosen site is sticky across pages. Status
pages (dashboard, alerts, history, traps) aggregate by default and filter
by site optionally.

### Mobile apps: two filters

The apps carry two independent settings, both defaulting to all sites:

    Show          all sites  |  one site
    Notify me about   all sites  |  one site

They are enforced in different places:

- **Show** is a request parameter: `?site=sysmon-metro` on the status and
  history endpoints. It is not stored server-side and not filtered on the
  phone.

  With the delta protocol, `rev` stays global and monotonic, and the
  server drops non-matching hosts from `changed` and `removed`. A client
  whose delta is empty because the change was in a site it does not watch
  stores the new rev and moves on. *Widening* the filter needs a full
  resync - the client's warm cache has never seen the sites it was
  excluding - so a changed `site` parameter forces `full`.

- **Notify me about** lives on the push subscription. The server skips
  subscribers whose filter does not match the host's site, so an excluded
  site never reaches the phone.

Consequences:

- `/api/sites` lists the fleet (name, description, reachable) so both
  pickers offer a list rather than asking someone to type a name.
- With **Show** narrowed to one site, object names render bare. Showing
  all sites renders the qualified `site:object`.
- Changing **Notify** re-registers the subscription. Until that succeeds
  the server is still using the old filter, and the app says so.
- Setting **Notify** to one site offers - but does not force - matching
  **Show** to it.
- A filter pointing at a site that has left the fleet is not silently
  reset to "all". The app keeps the filter and says the site it was
  watching is gone.

### A site that goes dark keeps its hosts

When a poll cannot reach a daemon, its hosts stay in the merged view,
flagged `stale` with a `stale_since` of the last time it answered. They
are not dropped: a host absent from a snapshot is reported *removed*, so
dropping them would delete and re-add every host on the site, fleet-wide,
for a link that blipped.

A stale host keeps its last status, so nothing transitions and nobody is
paged by a site going quiet. What changes is the flag, which is part of
the host's signature: exactly one delta on the way out and one on the way
back. A site nobody has ever reached contributes nothing.

---

## 2. Connection direction: sysmond dials out

sysmond opens the connection to sysmon-web, and neither daemon does the
opposite by default:

- sysmond does not listen at all unless `config listen` (or `-p`) asks it
  to.
- sysmon-web does not dial anyone. It listens on 1347 and waits. The code
  that dialled a daemon is removed, along with the shared authkey it
  used.

The `sysmon(1)` client still connects to a daemon directly, which is what
`config listen` is for. That box is standing alone rather than being part
of a fleet.

Dial-out gives one credential per box, revocable centrally, and needs no
inbound rule at sites behind NAT or on management VLANs. A daemon that
cannot reach sysmon-web keeps running its last known-good config and
keeps monitoring and paging. A new box is given one token and appears in
the UI.

**The connection carries both directions.** sysmond already talks once
per second; status flows up and config flows down the same socket. The
sequence-number protocol built for `CONF <seq>` and `TRAPS <seq>` works
unchanged - the daemon serves those commands on a connection it
originated, and asks one extra question per cycle:

    CONFIG-GEN            -> 333 <generation> <hash>   (what should I be running?)

### Transport

TLS, with the client authenticating by bearer token over the encrypted
channel. A token is provisioned by pasting one string and revoked by
deleting one row. mTLS is available for sites that want it.

**Dialect: OpenSSL 1.1.1 / LibreSSL**, which is what ships on OpenBSD, on
long-lived Linux installs, and what LibreSSL tracks:

- `TLS_client_method()`, never `SSLv23_client_method()`
- `SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION)`
- hostname verification through `X509_VERIFY_PARAM_set1_host()` on the
  connection's verify param - present in 1.0.2 through 3.x and in
  LibreSSL, unlike some of the newer convenience wrappers
- explicit `SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL)` plus either
  the system trust store or a pinned CA file
- no 3.0-only surface: no providers, no `EVP_MAC`, no
  `SSL_CTX_set_ciphersuites` (TLS 1.3-only and absent from older
  LibreSSL)

**Fallback.** The inbound listener stays. A single-box install where
sysmon-web dials `localhost:1345` keeps working; dial-out is what a
`config aggregator "…";` directive turns on.

---

## 3. Config distribution

The config file remains the source of truth on each box. sysmon-web holds
*desired state*; the daemon holds *actual state*; distribution reconciles
them.

### Unit of transfer: the whole file

A generation is a complete set of files - the main config and every file
it includes - delivered together.

    fetch -> validate locally -> swap atomically -> reload -> report

Validation is sysmond's own parser, on the target box, in a forked child
running against the real files. sysmon-web's Go parser and sysmond's
lexer are two implementations of one grammar and can disagree; the
daemon's opinion is the one that decides. What it refuses:

- anything the lexer marks as a config error
- a config that declares nothing to monitor
- a `root` naming an object nobody defined - which parses perfectly and
  makes every object unreachable from the root

It also reports the object count, which the canary compares against the
count the box was running before the delivery.

The order on the box is: write into a *new* generation directory,
validate there, then swap a symlink. Nothing that is running is touched
until that last step, so a rejected delivery leaves the running config
untouched and the staging directory is removed. A failed validation
reports the parser's own words back to the UI, verbatim, against that
generation, for that box.

### The commands

    CONFIG-GEN       what am I running?    -> generation, hash, file count
    CONFIG-GET       give me what you run  -> every file, byte for byte
    CONFIG-PUT       run this instead      -> stage, validate, swap, reload
    CONFIG-ROLLBACK  undo the last PUT     -> swap back, reload
    CONFIG-REVERT    stop being managed    -> back to the seed config

All of them need the authkey. `CONFIG-GEN` is asked every cycle - one
line each way, on the connection the poller already has open - so an edit
made on the box is visible in seconds.

Paths and contents are base64 on the wire. The hash is over the decoded
bytes.

### The seed config is never written

`/etc/sysmon.conf` - or whatever `-f` names - is read-only to the daemon,
permanently. A managed box keeps its running copy somewhere it owns:

    <gendir>/main            the entry file's name, e.g. "sysmon.conf"
    <gendir>/current  ->     gen-0000000007
    <gendir>/previous ->     gen-0000000006
    <gendir>/gen-0000000007/ that generation's files, plus .order

`<gendir>` is `/var/db/sysmon` on every platform, and moves with `config
statedir`. It is created, parent included, and handed to the daemon's
user at startup while the process is still root.

It holds everything the daemon writes: generations, the pidfile, the log
when logging to a file, the shutdown state dump, and the scratch file the
status page is built in. The directives that used to name those paths
individually - `pidfile`, `savestate`, `statustempdir`, `logging file`,
`aggregator-ca` - are still parsed, and warn that they are no longer
used.

`config statusfile` keeps its path: it names a published output, whose
location is a local decision about a web server's document root. It is
still built in the state directory and renamed into place, so a web
server never sees a half-written page.

The daemon loads `<gendir>/current/<main>` when it exists and the seed
otherwise:

- A wiped state directory is survivable. The box comes back on the config
  an operator wrote.
- `CONFIG-REVERT` - "Unmanage" in the UI - drops the `current` pointer
  and the box runs its own config again. The generations stay on disk as
  the record of what was delivered.
- Writing a delivered config back over `/etc/sysmon.conf` would need
  `/etc` writable by the user sysmond drops to.

`config statedir` is read from the **seed only**, and locked once the
seed is parsed. A delivered config carrying a different value is inert.

**Files are named, not located.** A delivery carries plain filenames - no
slashes, no leading dots - and this side decides which directory they
land in. Nothing the aggregator sends is used to build a path. The
content hash is over those names too, so the same config hashes
identically as a seed in `/etc` and as the running copy in a generation
directory.

### Includes

`include "/etc/sysmon.d/hosts.conf"` is what a config is expected to use,
and it is opened exactly as written.

A relative include resolves against the working directory, which sysmond
does not set - it inherits whatever started it, and that differs between
a shell, systemd (which defaults to `/`) and an rc.d script. The same
directive can name different files on two boxes with identical configs.

**This is not repaired**, because re-pointing a relative include at the
config's directory would change which file an existing config opens on
boxes that have been running for years. There is one fallback: when a
relative include does not resolve at all, the config file's own directory
is tried before giving up, and the daemon logs that it did. It can only
turn a silently-missing include into one that loads. (Verified three
ways: a config whose include resolves from the working directory still
gets that file and logs nothing; one whose include resolves nowhere gets
the config directory's copy with a log line; one with neither fails
exactly as before.)

Inside the managed directory an include must be a plain filename, naming
a member of the set that was validated. **A config whose includes are
absolute paths cannot be config-managed**: copying
`/etc/sysmon.d/hosts.conf` into a generation directory would not change
what the main file points at, so the copy would be delivered and never
read. The daemon says so in its `CONFIG-GEN` reply and the fleet page
shows the reason.

Such a box is still monitored, aggregated, alerted on and shown like any
other - only its config stays read-only in the UI. The options for
widening that are: keep the whole config in one file, use bare filenames
beside the main config, or manage only the main file and treat
absolutely-included fragments as read-only members of the hash. Not yet
decided.

### Where a box reports is not editable from here

`config aggregator` and `config aggregator-token` decide which sysmon-web
a box reports to. The editor refuses any change to either, in any file of
the config, including removing the directive.

Moving a box also needs the certificate for its new destination, which
this side has no way to put on the box. A delivery that changed the
directive would succeed and reply on the old connection; the daemon would
then reload and dial somewhere that cannot answer, which from here is
indistinguishable from a network fault.

sysmond itself keeps the ability to be moved. Change it in the seed
config, on the box, where the certificate can be put in place at the same
time.

---

## 4. Editing: splice, never regenerate

`Generate()` rebuilds the config from the parsed model, which loses
comments on save, and loses `include` directives - the parser follows
them (`collectIncludes`) but the generator has no notion of them, so
every included object is flattened into the main file. It also makes
byte-stable hashing impossible.

**The fix is to stop regenerating.** The parser retains, for every object
and directive, the file it came from and its byte range within that file.
An edit becomes a minimal replacement of exactly those bytes:

- comments survive because nothing touches them
- indentation and file organisation survive
- includes survive because an object is edited in the file it lives in
- an unedited config hashes identically before and after a round trip

The grammar is small enough for this: `config …;`, `object NAME { … };`,
`#` comments, `include`.

---

## 5. The dependency map is per daemon

**A dependency graph cannot span daemons.** `dep` is resolved by name
inside one sysmond's own tree; there is no wire format for "an object
here depends on an object over there". The graph is per site as a matter
of data, not of presentation.

- **One canvas may show several sites**, as visually separate clusters
  with no edges between them - a wall-display view.
- **The default view is one site.** A single real config runs to 800
  objects.
- **Layout storage does not fork.** Positions are keyed by the qualified
  name (`site:object`), so one store serves every site and filtering is a
  key prefix.
- **No invented cross-site edges.** A line drawn between two sites in the
  map store alone would not suppress the child's alert, so it is not
  offered.
- **A real cross-site edge already exists**: `type sysm` checks another
  sysmond. A site whose objects depend on an object that monitors the
  upstream site's daemon has a dependency sysmond honours, and the map
  renders it.

---

## 6. Notes

**Two parsers, one grammar.** sysmon-web's Go parser and sysmond's flex
lexer can disagree. Mitigations, in order of value: validate on the
target box before swapping (§3); differential-test the two against the
same corpus and compare object sets; keep the grammar frozen.

**Scale.** One connection per box at one second. The incremental protocol
means a quiet box costs two round trips and no payload, so the cost is
per-box constant rather than per-object. The warm cache, revision
counters and sequence tracking all become per-box.

**Traps** are already per-daemon - whichever sysmond holds :162 at that
site receives them. They aggregate with the same namespacing.

**Acks and notes** are routed to the owning daemon: split on `:`, look up
the box.
