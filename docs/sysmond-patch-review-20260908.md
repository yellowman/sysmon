# sysmond correctness patch review — 2026-09-08

These three commits replace the earlier, unbuilt patch proposals and are based
on upstream `c996e210bd36c8b055aad2e64cbf9cae61356c0c`. They retain the existing
SHOWOBJ credential-isolation changes and its regression test.

## Runtime

Queue admission is checked at insertion as well as at both schedulers: zero
means unlimited, positive limits are exact. The watchdog retries the same
queue entry, frees the previous attempt, and never overwrites a completed
result. Raw ICMP descriptors are watched regardless of their numerical order;
a failed select is not followed by inspection of its descriptor sets. Missing
receive sockets produce an error; a send-only helper cannot replace a receiver.
The explicit administrative `-i` bypass keeps its previous behavior.

Per-object re-page intervals do not alter the global default, and zero disables
re-paging for that object. Re-pages require a current failure and DOWN contact
policy. TCP DNS failures close their descriptor, and terminal connect errors
cannot leave a pending check without protocol state.

## Reload and checkpoint

SIGHUP preflights the candidate in a child with a ten-second alarm. The live
parse then snapshots parser-owned fields, graph roots, spawn definitions and
tracked-file ownership. Reported candidate failures restore those values and
leave queued checks intact. Cancellation and replacement happen only after a
runnable candidate is available. This is not an immutable filesystem snapshot:
files can still change between preflight and the in-process parse, and a fatal
parser crash during that second parse is not a rollback event.

Undefined roots, dependencies, includes and named spawns are rejected. Unresolved
hostnames remain declared objects with NODNS status rather than disappearing
and breaking structural validation. A valid managed configuration can start
even when the seed is not runnable. Unrelated legacy parser warnings have not
all been promoted to errors.

Checkpoint restoration is all-or-nothing for malformed fields, incomplete
lines, count mismatches, duplicate identities and invalid timestamps. The writer
uses a fresh temporary file and checks stream errors, flush, fsync, close and
rename. This does not add a parent-directory fsync or claim full power-loss
durability on every filesystem. Failed periodic writes retry after five seconds
instead of every busy-loop pass or another ten minutes.

## Notifications and remaining boundaries

Sendmail is invoked directly using configure's executable path, with separate
arguments rather than shell interpolation. Message data has a header/body
separator and literal-dot handling. Paging timestamps and thread state are
committed only after successful writes and a zero mailer exit. This proves a
local handoff, not delivery to the recipient. Direct mail still waits for the
mailer; nonblocking delivery with a deadline is outside these changes.

Command notifications remain asynchronous: `contacted` records that a worker
was successfully launched, not the worker's eventual exit status. Fork failure
leaves notification state unchanged. Every worker path exits instead of falling
back into the daemon, and failure to mail optional output does not prevent the
primary command action. Parent-side acknowledgement of eventual worker results
requires a separate IPC/reaper design.

## Regression checks

`make -C src check` runs the existing trap, SNMP, config-generation, saved-state
and credential-isolation suites, plus runtime policy, real daemon-core, paging
and live reload tests. Paging tests use a temporary fake executable and real
pipes/children; no notification email is sent.

Clean builds should include the standalone `sysmon` client, not only `sysmond`.
Also test a build with `ac_cv_header_openssl_ssl_h=no`, an empty mailer and an
explicit `SENDMAIL=/bin/true`. The focused saved-state, runtime-policy,
daemon-core and paging tests support AddressSanitizer/UndefinedBehaviorSanitizer
runs. Native BSD execution is a separate platform check, not implied by Linux
builds or sanitizers.
