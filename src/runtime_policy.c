#include "config.h"
#include "runtime_policy.h"

int
sysmon_queue_has_capacity(int queued, int limit)
{
	if (limit == 0)
		return TRUE;
	return queued < limit;
}

int
sysmon_should_repage(time_t now, time_t lastcontacted,
	int object_interval, int global_interval, int contacted)
{
	int interval;

	if (!contacted || now <= lastcontacted)
		return FALSE;
	interval = (object_interval == -1) ? global_interval : object_interval;
	if (interval <= 0)
		return FALSE;
	/* Avoid overflow on platforms with a 32-bit time_t. */
	return difftime(now, lastcontacted) > (double)interval * 60.0;
}

int
sysmon_stale_retry_available(unsigned int wakeup_count,
	unsigned int max_retries)
{
	return wakeup_count < max_retries;
}

void
sysmon_prepare_stale_retry(struct monitorent *entry,
	const struct timeval *now, time_t now_t)
{
	if (entry == NULL || now == NULL)
		return;

	/*
	 * Keep the same queue entry: wakeup_count belongs to this attempt
	 * series. Marking TIMEDOUT made service_checks consume and free the
	 * entry, so the advertised retry was never made and the next,
	 * independently queued entry started again at retry zero.
	 */
	entry->started = FALSE;
	entry->retval = -1;
	entry->filedes = -1;
	entry->fd_state = 0;
	entry->monitordata = NULL;
	entry->queueat = *now;
	entry->lastserv = *now;
	entry->wakeup_count++;
	entry->last_wakeup_time = now_t;
}
