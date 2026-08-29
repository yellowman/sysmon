/*
 * showobj_test.c - what an object's status XML is allowed to say to a
 * client that has not authenticated.
 *
 * An object record carries the credentials its checks run with: the SNMP
 * community, the check username and password, the RADIUS shared secret,
 * the HTTP header value, the URL, and the command line a failure runs.
 * send_object_xml() serialized all of it unconditionally, and SHOWOBJ
 * required only "MODE xml" - so anyone who could open the daemon's port
 * could read every credential in the config, one object at a time, by
 * name. CONF has always refused an unauthenticated client; SHOWOBJ never
 * checked.
 *
 * These tests hold the rule from both sides: an unprivileged document
 * contains no secret and still contains the status a monitoring client
 * needs, and a privileged one is unchanged.
 */

#include "config.h"

/* Daemon stand-ins. Kept short on purpose. */
bool debug = 0;
bool paused = 0;
bool stop_daemon = 0;
bool snmp_debug = 0;
bool nologconnects = 0;
int inactivetime = 0;
time_t boottime = 0;
unsigned long glob_change_seq = 0;
char *authkey = NULL;
char *sitename = NULL;
char *sitedesc = NULL;
int numqueued = 0;
struct all_elements_list *currenthead = NULL;
struct clientstatus *clienthead = NULL;
struct monitorent *queuehead = NULL;

void print_err(int a, const char *fmt, ...) { (void)a; (void)fmt; }
void *MALLOC(size_t n, char *why) { (void)why; return malloc(n); }
void FREE(void *p) { free(p); }
void ABORT(void) { }
int sendline(int fd, char *s) { (void)fd; (void)s; return 0; }
int getline_tcp(int fd, char *b) { (void)fd; (void)b; return 0; }
int nextfd(void) { return 0; }
void tls_disconnect(int fd) { (void)fd; }
struct graph_elements *find_object_by_name(char *n) { (void)n; return NULL; }
void object_changed(struct hostinfo *o) { (void)o; }
void expire_dns(time_t t) { (void)t; }
void print_queue(int fd) { (void)fd; }
char *type_to_name(int t) { (void)t; return "ping"; }
char *snmp_type_to_name(int t) { (void)t; return "generic"; }
char *str_difftime_sec(time_t a, time_t b) { (void)a; (void)b; return "0"; }
void confgen_receive(struct clientstatus *c, char *b) { (void)c; (void)b; }
void confgen_send(struct clientstatus *c) { (void)c; }
void confgen_report(struct clientstatus *c) { (void)c; }
void confgen_do_rollback(struct clientstatus *c) { (void)c; }
void confgen_do_revert(struct clientstatus *c) { (void)c; }
int trap_history_count(void) { return 0; }
unsigned long trap_history_total(void) { return 0; }
unsigned long trap_history_oldest_seq(void) { return 0; }
struct trap_record *trap_history_get(int i) { (void)i; return NULL; }

static int failures = 0;

static void check(int cond, const char *what)
{
	if (!cond)
	{
		fprintf(stderr, "FAIL: %s\n", what);
		failures++;
	}
}

#define MARKER "SECRET-DO-NOT-LEAK"

/*
 * An object with every credential-bearing field populated with the same
 * marker, so one search proves the whole class.
 */
static struct graph_elements *object_with_secrets(void)
{
	struct graph_elements *g = calloc(1, sizeof(*g));
	struct hostinfo *h = calloc(1, sizeof(*h));

	g->unique_name = (unsigned char *)"awbreyrouter";
	g->data = h;

	/* Status: must survive for any client. */
	h->hostname = (unsigned char *)"10.20.4.1";
	h->type = SYSM_TYPE_SNMP;
	h->totalchecked = 412;
	h->notes = (unsigned char *)"Awbrey tower router";
	h->group = (unsigned char *)"tower-awbrey";

	/* Credentials: must never reach an unauthenticated client. */
	h->snmp_community = (unsigned char *)MARKER;
	h->username = (unsigned char *)MARKER;
	h->password = (unsigned char *)MARKER;
	h->hdr = (unsigned char *)MARKER;
	h->hdrval = (unsigned char *)MARKER;
	h->secret = (unsigned char *)MARKER;
	h->url = (unsigned char *)"https://u:" MARKER "@example.com/health";
	h->url_text = (unsigned char *)MARKER;
	h->command = (unsigned char *)"/usr/bin/page --token " MARKER;

	return g;
}

/* Render an object to a string through the FILE* path. */
static char *render(struct graph_elements *g, int privileged)
{
	static char buf[65536];
	FILE *fh = tmpfile();
	long n;

	if (fh == NULL)
	{
		fprintf(stderr, "FAIL: tmpfile()\n");
		failures++;
		buf[0] = '\0';
		return buf;
	}
	send_object_xml(-1, fh, g, privileged);
	fflush(fh);
	n = ftell(fh);
	if (n < 0 || (size_t)n >= sizeof(buf))
		n = sizeof(buf) - 1;
	rewind(fh);
	n = (long)fread(buf, 1, (size_t)n, fh);
	buf[n] = '\0';
	fclose(fh);
	return buf;
}

int main(void)
{
	struct graph_elements *g = object_with_secrets();
	char *doc;

	/* Unauthenticated: status yes, secrets no. */
	doc = render(g, 0);
	check(strstr(doc, MARKER) == NULL,
		"unprivileged status XML must contain no credential");
	check(strstr(doc, "awbreyrouter") != NULL,
		"unprivileged status XML still names the object");
	check(strstr(doc, "10.20.4.1") != NULL,
		"unprivileged status XML still carries the hostname");
	check(strstr(doc, "412") != NULL,
		"unprivileged status XML still carries counters");
	check(strstr(doc, "Awbrey tower router") != NULL,
		"unprivileged status XML still carries the description");

	/* Named individually too, so a failure says which field leaked. */
	check(strstr(doc, "ObjectSNMPCommunity") == NULL, "no SNMP community tag");
	check(strstr(doc, "ObjectAuthUsername") == NULL, "no auth username tag");
	check(strstr(doc, "ObjectAuthPassword") == NULL, "no auth password tag");
	check(strstr(doc, "ObjectRadiusSecret") == NULL, "no RADIUS secret tag");
	check(strstr(doc, "ObjectHeaderValue") == NULL, "no HTTP header value tag");
	check(strstr(doc, "ObjectURL") == NULL, "no URL tag");
	check(strstr(doc, "ObjectExecCmd") == NULL, "no exec command tag");

	/*
	 * Authenticated: unchanged. sysmon-web reads objects over an
	 * authenticated CONF and needs the full record to render and
	 * round-trip config, so this path must not be narrowed.
	 */
	doc = render(g, 1);
	check(strstr(doc, "ObjectSNMPCommunity") != NULL,
		"privileged status XML still carries the SNMP community");
	check(strstr(doc, "ObjectAuthPassword") != NULL,
		"privileged status XML still carries the check password");
	check(strstr(doc, "ObjectRadiusSecret") != NULL,
		"privileged status XML still carries the RADIUS secret");
	check(strstr(doc, "ObjectExecCmd") != NULL,
		"privileged status XML still carries the command");

	if (failures == 0)
		printf("showobj-test: all checks passed\n");
	return failures ? 1 : 0;
}
