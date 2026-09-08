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

static void write_config(const char *path, const char *text)
{
	FILE *f = fopen(path, "w");
	if (f == NULL) { perror(path); exit(1); }
	if (fputs(text, f) == EOF || fclose(f) != 0) exit(1);
}

static void parser_transactions(void)
{
	char dir[] = "/tmp/sysmon-core-XXXXXX", oldpath[512], newpath[512];
	struct all_elements_list *old;
	struct graph_elements *root, *leaf;
	struct monitorent *pending;
	char *tracked;
	if (mkdtemp(dir) == NULL) exit(1);
	snprintf(oldpath, sizeof(oldpath), "%s/old.conf", dir);
	snprintf(newpath, sizeof(newpath), "%s/new.conf", dir);
	write_config(oldpath,
	    "root = \"root\";\nconfig queuetime 7;\nconfig numfailures 8;\n"
	    "config pageinterval 10;\nconfig date \"ISO\";\nconfig html refresh 7;\n"
	    "config noheartbeat;\nspawns {\nold \"/bin/true\"\n};\n"
	    "object root {\nip \"127.0.0.1\";\ntype tcp;\nspawn old;\n"
	    "config pageinterval 0;\nconfig queuetime 2;\nconfig numfailures 3;\n};\n"
	    "object leaf {\nip \"127.0.0.1\";\ntype tcp;\ndep \"root\";\n};\n");
	not_started_yet = FALSE;
	cieling_max_queued = 1024;
	currenthead = loadconfig(oldpath);
	check(!badconfig && currenthead != NULL, "valid baseline configuration loads");
	if (badconfig || currenthead == NULL) exit(1);
	update_globs_from_parser();
	root = find_object_by_name("root");
	leaf = find_object_by_name("leaf");
	check(root->data->queuetime == 2 && leaf->data->queuetime == 7,
	    "object queue interval does not overwrite global/default sibling interval");
	check(root->data->max_down == 3 && leaf->data->max_down == 8,
	    "object failure threshold does not overwrite the global");
	check(pageinterval == 10 && root->data->pageinterval == 0 && leaf->data->pageinterval == -1,
	    "global, disabled and inherited page intervals remain distinct");
	check(!heartbeat, "accepted noheartbeat survives applying parser globals");
	queue_check(root->data, root->unique_name);
	pending = queuehead;
	tracked = strdup(confset_path(0));
	old = currenthead;
	write_config(newpath,
	    "root = \"missing\";\nconfig date \"DEC\";\nconfig html refresh 99;\n"
	    "spawns {\nnew \"/bin/false\"\n};\n"
	    "object root {\nip \"127.0.0.1\";\ntype tcp;\n};\n");
	/* Invoke the candidate parse directly to simulate failure after the
	 * watch loop's child preflight, e.g. a file changed in between. */
	currenthead = sync_after_sighup(old, newpath);
	check(currenthead == old && configed_root == root && parser_head == old,
	    "late rejection restores all graph roots");
	check(queuehead == pending && root->data->queued,
	    "late rejection leaves the live queue untouched");
	check(parser_html_refresh == 7 && strcmp(parser_dateformat, "%F %T") == 0,
	    "late rejection restores parser-owned presentation settings");
	check(lookup_spawn_command("old") != NULL && lookup_spawn_command("new") == NULL,
	    "late rejection restores named command definitions");
	check(confset_count() == 1 && strcmp(confset_path(0), tracked) == 0,
	    "late rejection restores the tracked file set");
	check(!heartbeat && queuetime == 7, "late rejection leaves live globals intact");
	free(tracked);
	write_config(newpath,
	    "root = \"root\";\nconfig maxqueued -2;\n"
	    "object root {\nip \"127.0.0.1\";\ntype tcp;\n};\n");
	currenthead = sync_after_sighup(old, newpath);
	check(currenthead == old && queuehead == pending && badconfig,
	    "negative queue limits reject instead of silently stopping scheduling");
	write_config(newpath,
	    "root = \"root\";\nobject root {\nip \"127.0.0.1\";\ntype tcp;\n};\n");
	currenthead = sync_after_sighup(currenthead, newpath);
	check(!badconfig && currenthead != old, "a later valid candidate commits");
	check(queuehead == NULL && numqueued == 0, "accepted reload cancels old queue");
	check(configed_root->data->queuetime == 60 && configed_root->data->max_down == 4,
	    "deleted defaults reset instead of inheriting the previous generation");
	check(lookup_spawn_command("old") == NULL, "removed commands do not survive a valid reload");
	free_tree(currenthead);
	currenthead = parser_head = NULL;
	configed_root = NULL;
	initalize_parser();
	free_spawn_defs();
	confset_reset();
	unlink(oldpath); unlink(newpath); rmdir(dir);
}

int main(void)
{
	set_defaults();
	do_syslog = FALSE;
	donotify = FALSE;
	missing_icmp();
	watchdog();
	no_down_repage_when_up();
	parser_transactions();
	if (failures) return 1;
	puts("daemon core: all checks passed");
	return 0;
}
