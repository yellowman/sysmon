# WAKEUP_CHECKS Analysis and Design

## Current Behavior (The Problem)

### What wakeup_checks() Currently Does

Located in `syswatch.c:1470-1525`, the function:

1. **Walks the queue** of active checks (`queuehead`)
2. **Kills stale checks** that exceed `killafter` threshold
3. **Warns about checks** that exceed `warnafter` threshold
4. **Does NOT actually "wake up" checks** - it's only a killer/warner

### Current Call Pattern

```c
// Main loop in syswatch.c:1612-1616
if (now_t > last_t)
{
    wakeup_checks();  /* wakeup any "stale" checks */
    last_t = now_t;
}
```

**Problem:** Runs EVERY SECOND (whenever now_t advances), which is excessive.

### The Wishlist Requirement

From WISHLIST line 48-51:
```
* make WAKEUP_CHECKS go out and actually do that, instead of just
  be killer...  also go out and make us pass better states
  around such that wakeup_checks actually only calls checks
  every few times, instead of every iteration
```

**Translation:**
1. **"actually do that"** = Actually wake up checks (restart stale/stuck ones)
2. **"only calls checks every few times"** = Throttle execution (not every second)
3. **"pass better states"** = Improve state tracking/passing

## Understanding the Check Lifecycle

### Check States (Inferred)

1. **Not Queued** - Object exists but not ready to check yet
2. **Queued** - Added to queue (queuehead), waiting for service
3. **In Service** - Currently being serviced (start_test_X called)
4. **Waiting Reply** - Waiting for network response
5. **Completed** - Got result, ready to dequeue
6. **Stale/Stuck** - Been in queue too long (>killafter seconds)

### Queue Operations

- **queue_checks(now)** - Walks tree, adds objects ready for checking
- **service_checks(now)** - Services queued checks, calls start/service/stop
- **wakeup_checks()** - Supposed to "wake" stale checks

## What "Wake Up" Should Mean

Based on code analysis, "wake up" should mean:

### Option 1: Restart Stale Checks
- If a check has been running too long
- Stop it forcefully (stop_test_X)
- Mark it failed/timeout
- Re-queue it for retry

### Option 2: Trigger Overdue Checks
- If a check should have run by now (past its queuetime)
- But hasn't been queued yet
- Force it into the queue

### Option 3: Both (Most Likely)
- Handle stuck active checks (Option 1)
- Handle missed/overdue checks (Option 2)

## Current Issues

### Issue 1: Only Kills, Doesn't Re-queue
```c
if (mydifftime(here->queueat, now) >= killafter)
{
    // ... kills the check
    stop_this(here);
    here->retval = SYSM_KILLED;
    killed++;
}
```

**Problem:** Check is killed but NOT re-queued for retry.

### Issue 2: Runs Too Frequently
Called every time `now_t` advances (every second in most cases).

**Cost:** Walks entire queue every second, even if nothing needs waking.

### Issue 3: No State Tracking
No tracking of:
- How many times a check has been woken
- Last wake-up time
- Retry count

## Proposed Solution

### Part 1: Actual Wake-Up Logic

```c
void wakeup_checks(time_t now)
{
    struct monitorent *here = NULL;
    struct monitorent *next = NULL;

    /* Walk the current queue */
    here = queuehead;
    while (here != NULL)
    {
        next = here->next;  /* Save next before potential dequeue */

        /* Check if this is stuck/stale */
        if (mydifftime(here->queueat, now) >= killafter)
        {
            print_err(0, "Waking up stale check %s:%s:%d (stale for %.2fs)",
                here->checkent->hostname,
                type_to_name(here->checkent->type),
                here->checkent->port,
                mydifftime(here->queueat, now));

            /* Stop the stuck check */
            if (here->checkent->type != SYSM_TYPE_PING)
            {
                stop_this(here);
            }

            /* Mark as timeout */
            here->retval = SYSM_TIMEDOUT;

            /* Increment retry counter */
            here->wakeup_count++;

            /* Re-queue for retry (if not exceeded max retries) */
            if (here->wakeup_count < MAX_WAKEUP_RETRIES)
            {
                here->checkent->lchecktime = now - here->checkent->queuetime;
                /* Will be re-queued on next queue_checks() call */
            }
            else
            {
                print_err(1, "Check %s exceeded max wakeup retries (%d), marking permanently failed",
                    here->checkent->hostname, MAX_WAKEUP_RETRIES);
                here->retval = SYSM_KILLED;
            }
        }

        here = next;
    }
}
```

### Part 2: Throttling (Run Less Frequently)

```c
/* Global state tracking */
static time_t last_wakeup_t = 0;
static unsigned int wakeup_interval = 10;  /* Run every 10 seconds */

/* In main loop */
if (now_t - last_wakeup_t >= wakeup_interval)
{
    wakeup_checks(now_t);
    last_wakeup_t = now_t;
}
```

**Benefit:** Reduces from ~60 calls/minute to ~6 calls/minute.

### Part 3: Better State Passing

Add to `struct monitorent`:
```c
unsigned int wakeup_count;      /* How many times woken up */
time_t last_wakeup_time;        /* When last woken */
```

Add to `struct hostinfo`:
```c
unsigned int max_wakeup_retries;  /* Configurable per-host */
```

## Configuration Options (Future)

Allow per-host configuration:
```
object {
    name test-server;
    hostname 10.1.2.3;
    type tcp;
    port 80;

    max_wakeup_retries 3;   /* Give up after 3 wake-ups */
    wakeup_action restart;  /* or 'kill', 'alert', 'ignore' */
}
```

Global configuration:
```
wakeup_interval 10;         /* Check for stale every 10 seconds */
default_max_retries 3;      /* Default retry count */
```

## Implementation Steps

1. **Add state tracking fields** to monitorent struct
2. **Implement throttling** in main loop
3. **Rewrite wakeup_checks()** to actually re-queue stale checks
4. **Add retry counting** with max retry limit
5. **Add debug logging** for wake-up events
6. **Test** with intentionally slow checks

## Risks and Considerations

### Risk 1: Re-queue Loop
If a check always times out, it could loop forever.

**Mitigation:** Max retry counter (`max_wakeup_retries`)

### Risk 2: Queue Overflow
Re-queuing could cause queue to grow unbounded.

**Mitigation:** Existing `maxqueued` check already handles this

### Risk 3: Race Conditions
Check might complete just as we're killing it.

**Mitigation:** Check `here->retval` before killing

## Testing Plan

1. **Create slow check** - TCP server that never responds
2. **Set low killafter** - e.g., 5 seconds
3. **Verify wake-up** - Check gets killed and re-queued
4. **Verify throttling** - wakeup_checks() not called every second
5. **Verify retry limit** - Check fails after N retries

## Success Criteria

1. ✅ Stale checks are restarted automatically
2. ✅ wakeup_checks() runs every N seconds (configurable)
3. ✅ Retry count tracked and enforced
4. ✅ Debug logging shows wake-up events
5. ✅ No infinite retry loops

---

**Status:** Analysis Complete - Ready for Implementation
**Estimated Effort:** 4-6 hours
**Priority:** Medium (Optimization, not critical bug)
