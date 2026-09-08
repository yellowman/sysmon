#include "config.h"
#include "runtime_policy.h"

static int failures;

static void
check(int condition, const char *what)
{
	if (!condition)
	{
		fprintf(stderr, "FAIL: %s\n", what);
		failures++;
	}
}

static void
test_queue_capacity(void)
{
	check(sysmon_queue_has_capacity(0, 0),
		"maxqueued zero is unlimited");
	check(sysmon_queue_has_capacity(100000, 0),
		"unlimited remains unlimited with a large queue");
	check(sysmon_queue_has_capacity(0, 1),
		"one-slot queue accepts its first check");
	check(!sysmon_queue_has_capacity(1, 1),
		"one-slot queue does not accept a second check");
	check(sysmon_queue_has_capacity(49, 50),
		"capacity is available below the limit");
	check(!sysmon_queue_has_capacity(50, 50),
		"capacity ends at the limit, not one entry later");
}

static void
test_repage_policy(void)
{
	check(sysmon_should_repage(1000, 800, -1, 3, TRUE),
		"an object inherits a positive global interval");
	check(!sysmon_should_repage(1000, 800, -1, 0, TRUE),
		"global zero disables inherited re-paging");
	check(!sysmon_should_repage(1000, 1, 0, 3, TRUE),
		"object zero overrides and disables a positive global");
	check(sysmon_should_repage(1000, 800, 2, 0, TRUE),
		"a positive object interval works with global zero");
	check(!sysmon_should_repage(1000, 800, 2, 0, FALSE),
		"an uncontacted outage is not re-paged");
	check(!sysmon_should_repage(800, 1000, 2, 0, TRUE),
		"a backwards clock does not re-page");
}

static void
test_stale_retry(void)
{
	struct monitorent entry;
	struct timeval now;

	check(sysmon_stale_retry_available(0, 3),
		"the first stale attempt may retry");
	check(sysmon_stale_retry_available(2, 3),
		"the last configured retry is available");
	check(!sysmon_stale_retry_available(3, 3),
		"the retry budget eventually ends");

	memset(&entry, 0, sizeof(entry));
	now.tv_sec = 1234;
	now.tv_usec = 5678;
	entry.started = TRUE;
	entry.retval = SYSM_TIMEDOUT;
	entry.filedes = 42;
	entry.fd_state = 1;
	entry.monitordata = (void *)0x1;
	entry.wakeup_count = 2;

	sysmon_prepare_stale_retry(&entry, &now, 1234);
	check(entry.started == FALSE, "retry is startable again");
	check(entry.retval == -1, "retry is pending, not a completed timeout");
	check(entry.filedes == -1, "retry carries no stale descriptor");
	check(entry.fd_state == 0, "retry carries no stale descriptor state");
	check(entry.monitordata == NULL, "retry carries no freed protocol state");
	check(entry.wakeup_count == 3, "retry count survives on the queue entry");
	check(entry.last_wakeup_time == 1234, "retry time is retained");
	check(entry.queueat.tv_sec == now.tv_sec &&
		entry.queueat.tv_usec == now.tv_usec,
		"staleness is measured from the new attempt");
}

int
main(void)
{
	test_queue_capacity();
	test_repage_policy();
	test_stale_retry();
	if (failures != 0)
		return 1;
	printf("runtime policy: all checks passed\n");
	return 0;
}
