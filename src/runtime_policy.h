#ifndef SYSMON_RUNTIME_POLICY_H
#define SYSMON_RUNTIME_POLICY_H

#include <sys/time.h>
#include <time.h>

struct monitorent;

/* maxqueued == 0 is the documented unlimited setting. */
int sysmon_queue_has_capacity(int queued, int maxqueued);

/* Object interval -1 inherits the global; zero disables re-paging. */
int sysmon_should_repage(time_t now, time_t lastcontacted,
	int object_interval, int global_interval, int contacted);

/* wakeup_count counts retries already attempted. */
int sysmon_stale_retry_available(unsigned int wakeup_count,
	unsigned int max_retries);

/* Reset one existing queue entry for another real attempt in place. */
void sysmon_prepare_stale_retry(struct monitorent *entry,
	const struct timeval *now, time_t now_t);

#endif
