/* Exercise the actual daemon entry points, not copies of their policy. */
#include "config.h"

static int failures;
static void check(int ok, const char *why)
{
	if (!ok) {
		fprintf(stderr, "FAIL: %s\n", why);
		failures++;
	}
}

static void missing_icmp(void)
{
	struct monitorent m;
	int disabled;
	for (disabled = 0; disabled <= 1; disabled++) {
		int expected = disabled ? SYSM_OK : SYSM_ERR;
		memset(&m, 0, sizeof(m));
		disable_icmp = disabled;
		glob_icmp_fd = glob_icmpv6_fd = -1;
		start_test_ping(&m);
		check(m.retval == expected, "missing IPv4 receive socket");
		start_test_pktloss(&m);
		check(m.retval == expected, "missing pktloss receive socket");
		start_test_rtt(&m);
		check(m.retval == expected, "missing RTT receive socket");
#ifdef HAVE_IPv6
		start_test_pingv6(&m);
		check(m.retval == expected, "missing IPv6 receive socket");
#endif
	}
}

static void watchdog(void)
{
	struct hostinfo h, other;
	struct monitorent *m;
	int i;
	time_t now = time(NULL);
	memset(&h, 0, sizeof(h));
	memset(&other, 0, sizeof(other));
	h.hostname = (unsigned char *)"127.0.0.1";
	h.type = SYSM_TYPE_TCP;
	h.max_wakeup_retries = 3;
	h.queuetime = 1;
	maxqueued = 1;
	queue_check(&h, (unsigned char *)"root");
	m = queuehead;
	check(m != NULL && numqueued == 1, "queue accepts one entry");
	if (m == NULL) return;
	queue_check(&other, (unsigned char *)"other");
	check(numqueued == 1 && !other.queued, "insertion enforces exact capacity");

	m->retval = SYSM_OK;
	m->started = TRUE;
	m->queueat.tv_sec = now - 1000;
	wakeup_checks(now);
	check(m->retval == SYSM_OK && m->wakeup_count == 0,
	    "watchdog preserves a completed result after an event-loop stall");

	m->retval = -1;
	for (i = 0; i < 4; i++) {
		/* Start a real TCP attempt, then force only its watchdog age.
		 * Port zero is not a listener; no external service is needed. */
		m->started = TRUE;
		start_test_tcp(m, now);
		m->queueat.tv_sec = now - 1000;
		m->queueat.tv_usec = 0;
		m->retval = -1;
		wakeup_checks(now);
		check(m == queuehead && numqueued == 1 && h.queued,
		    "retry preserves queue ownership");
		check(m->monitordata == NULL, "watchdog releases protocol state");
		if (i < 3) {
			check(!m->started && m->retval == -1 && m->filedes == -1,
			    "retry is a fresh pending attempt");
			check(m->wakeup_count == (unsigned)i + 1,
			    "watchdog retains retry count");
		} else
			check(m->retval == SYSM_KILLED, "watchdog terminates after three retries");
	}
	service_checks(now);
	check(queuehead == NULL && numqueued == 0 && !h.queued,
	    "terminal watchdog result is consumed once");
}

static void no_down_repage_when_up(void)
{
	struct hostinfo h;
	struct graph_elements g;
	memset(&h, 0, sizeof(h));
	memset(&g, 0, sizeof(g));
	h.hostname = (unsigned char *)"127.0.0.1";
	h.contacted = TRUE;
	h.contact_when = SYSM_CONTACT_UP | SYSM_CONTACT_DOWN;
	h.lastcontacted = 1;
	h.pageinterval = 1;
	g.data = &h;
	walk_periodic_page_checks(&g, 1000);
	check(h.lastcontacted == 1, "UP state is not re-paged as DOWN");
	g.visit = FALSE;
	h.lastcheck = SYSM_TIMEDOUT;
	h.contact_when = SYSM_CONTACT_UP;
	walk_periodic_page_checks(&g, 1000);
	check(h.lastcontacted == 1, "UP-only contact is not re-paged as DOWN");
}

int main(void)
{
	set_defaults();
	do_syslog = FALSE;
	donotify = FALSE;
	missing_icmp();
	watchdog();
	no_down_repage_when_up();
	if (failures) return 1;
	puts("daemon core: all checks passed");
	return 0;
}
