# Aggregating many sysmonds behind one sysmon-web

Status: design, agreed. Implementation is phased; see **Phasing** at the end
for what is built and what is not.

Today sysmon-web manages exactly one sysmond: it dials `localhost:1345`,
and it reads and writes that daemon's `sysmon.conf` as a local file. This
document describes turning it into the front end for a fleet, and the
decisions taken along the way.

The guiding constraint, which every decision below serves:

> **sysmond must outlive its management plane.** A monitoring daemon whose
> monitoring stops because a web UI is down, unreachable, or wrong is worse
> than no aggregation at all.

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

**`sitename` is `[A-Za-z0-9_-]+` and nothing else.** A colon in it would
make `metro:west:corerouter` ambiguous to every split in the codebase, so
it is rejected at config load with a plain error and the daemon refuses to
start rather than reporting under a name that cannot be parsed back. The
same rule keeps whitespace and quotes out, which would otherwise have to be
escaped in every log line, key and API path.

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
  nobody is watching them. That is the one thing the operator needs to see,
  and deleting the rows is the one presentation that hides it.
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

sysmond opens the connection to sysmon-web, not the other way around.

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

Anything outside that set is a portability bug waiting for the first
OpenBSD deployment.

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

Validation is `sysmond -c` **on the target box, before the swap**. This is
the step that makes remote config survivable: sysmon-web's parser and
sysmond's lexer are two implementations of one grammar and can disagree,
and the only opinion that matters is the one held by the daemon that has to
run it.

A failed validation leaves the running config untouched and reports the
parser's error back to the UI, against that generation, for that box.

### Hashing

Both sides must agree bit-for-bit on what "the config" is, or every box
shows as modified forever:

> SHA-256 over, for the main file and then each included file in load
> order: the file's path length, the path, the content length, the content.

Length-prefixed so no concatenation ambiguity exists. Bytes are hashed
**as-is** - never normalised, never re-indented, no line-ending
translation. That is only achievable if edits splice rather than
regenerate, which is why §4 is a prerequisite rather than a nicety.

### Conflict model

Per box, sysmon-web tracks `desired_generation` / `desired_hash`, and the
daemon reports `running_generation` / `running_hash` each cycle.

| condition | state | meaning |
|---|---|---|
| `running == desired` | **in sync** | nothing to do |
| `running_gen < desired_gen` | **pending** | delivery in flight or not yet fetched |
| `running_gen == desired_gen`, hash differs | **locally modified** | somebody edited the box directly |
| no `desired` recorded | **unmanaged** | never adopted; config is read-only in the UI |
| validation failed | **rejected** | daemon refused generation N, still running N-1 |

**Locally modified is never resolved automatically.** The operator is shown
a diff and chooses:

- **adopt local** - pull the box's file up and make it the new desired
  state. This is also how an existing box is onboarded, and how you recover
  when somebody fixed something on the console at 3am. It is the *default*
  offer, because the person at the console usually had a reason.
- **overwrite** - re-deliver the desired generation.

**Unmanaged is a real state, not a missing value.** A box that has never
been adopted shows its config read-only. Nothing is ever delivered to a box
that has not been explicitly adopted, so no amount of UI misclicking can
blank a daemon that sysmon-web has never seen the config of.

### Rollout

A generation is delivered in waves, first to one box.

Success is not "it applied". A config can parse perfectly and still be
catastrophically wrong - remove a `dep` line and a single upstream failure
becomes eight hundred pages. So the canary criteria are:

1. validation passed and the daemon reloaded
2. object count is within a tolerance of expected
3. no alert-rate spike in the watch window

Failing 2 or 3 within the watch window **rolls the box back to the previous
generation automatically** and marks the generation poisoned, which blocks
the remaining waves. The previous generation's files are kept on the box
precisely so rollback needs no network.

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
in odd positions) and forces a canonical reformat of the whole file, which
operators reasonably hate.

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

---

## Phasing

| phase | work | risk |
|---|---|---|
| 1 | Splice-based editing: comments and includes preserved | low - fixes a live bug |
| 2 | Object identity / site namespacing | low - expensive to defer |
| 3 | Multi-box read-only aggregation | low - most of the value |
| 4 | Dial-out, TLS, per-box tokens; retire the shared authkey | medium |
| 5 | Config distribution: generations, validation, conflict states, canary | medium |
| — | Field-level config DB per box | rejected; see below |

**Order matters.** Distributing a config format that cannot round-trip
losslessly, keyed on names that are not unique, is how a management tool
causes a fleet-wide outage. 1 and 2 are prerequisites, not polish.

### Rejected: a config database on each sysmond

The proposal was to tokenise `sysmon.conf` into a local database on each
box, have sysmon-web query or replace that, and run a process that rewrites
`sysmon.conf` when the database changes.

It is rejected because it adds a third representation of the config (flex
lexer, Go parser, schema) and a fourth moving part (the rewriter); creates
a race between the rewriter and the daemon's own reads; embeds a database
engine in a small C daemon we have just finished removing a dependency
from; and makes `sysmon.conf` a derived artifact while operators can still
edit it by hand - which recreates the two-master problem it was meant to
solve.

Whole-file replacement with local validation achieves the same goal with a
hash comparison instead of a merge algorithm, and fails safe. If field-level
queries ever turn out to matter, this decision can be revisited with
evidence.
