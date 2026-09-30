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
 *
 * They do it at two levels. The serializer tests call send_object_xml()
 * directly with each privilege value. The dispatch tests go through
 * do_service() with a real "SHOWOBJ <name>" command line and a client in
 * each auth state, which is the path a connection actually takes - so
 * they also pin the linkage the serializer tests cannot see: that the
 * SHOWOBJ handler derives the privilege from client->authlvl at all. A
 * call site passing a constant 1 would leave every serializer test green
 * and hand out every credential.
 */

#include "config.h"

/* The command dispatcher, which config.h does not export. */
void do_service(struct clientstatus *, char *, time_t);

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
/*
 * Everything the daemon says to a client goes through sendline() - the
 * XML lines of a document (do_send_xml with no FILE*) and the numeric
 * replies alike - so capturing it here is capturing the wire.
 */
static char wire[65536];
static size_t wirelen = 0;

int sendline(int fd, char *s)
{
	size_t n = strlen(s);

	(void)fd;
	if (wirelen + n + 2 < sizeof(wire))
	{
		memcpy(wire + wirelen, s, n);
		wirelen += n;
		wire[wirelen++] = '\n';
		wire[wirelen] = '\0';
	}
	return 0;
}
int getline_tcp(int fd, char *b) { (void)fd; (void)b; return 0; }
int nextfd(void) { return 0; }
void tls_disconnect(int fd) { (void)fd; }
static struct graph_elements *registered = NULL;

struct graph_elements *find_object_by_name(char *n)
{
	if (registered != NULL && strcmp(n, (char *)registered->unique_name) == 0)
		return registered;
	return NULL;
}
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

/*
 * Send one command line through the daemon's dispatcher, as a client in
 * the given state, and return everything the daemon wrote back.
 */
static char *dispatch(char *line, int authlvl, int xml)
{
	struct clientstatus c;
	char cmd[256];

	memset(&c, 0, sizeof(c));
	c.filedes = 7;
	c.ip = (unsigned char *)"192.0.2.1";
	c.authlvl = authlvl;
	c.xml = xml;

	wirelen = 0;
	wire[0] = '\0';
	/* do_service may tokenise its buffer; never hand it a literal. */
	snprintf(cmd, sizeof(cmd), "%s", line);
	do_service(&c, cmd, time(NULL));
	return wire;
}

static void dispatch_tests(struct graph_elements *g)
{
	char *out;

	registered = g;

	/*
	 * An unauthenticated client in xml mode: the case the leak lived in.
	 * It gets the status document and none of the credentials.
	 */
	out = dispatch("SHOWOBJ awbreyrouter", 0, 1);
	check(strstr(out, "<ObjectStatus>") != NULL,
		"dispatch: unauthenticated SHOWOBJ still returns the status document");
	check(strstr(out, "10.20.4.1") != NULL,
		"dispatch: unauthenticated SHOWOBJ still carries the hostname");
	check(strstr(out, MARKER) == NULL,
		"dispatch: unauthenticated SHOWOBJ must return no credential");
	check(strstr(out, "ObjectSNMPCommunity") == NULL,
		"dispatch: unauthenticated SHOWOBJ has no SNMP community tag");
	check(strstr(out, "ObjectAuthPassword") == NULL,
		"dispatch: unauthenticated SHOWOBJ has no auth password tag");
	check(strstr(out, "ObjectRadiusSecret") == NULL,
		"dispatch: unauthenticated SHOWOBJ has no RADIUS secret tag");
	check(strstr(out, "ObjectExecCmd") == NULL,
		"dispatch: unauthenticated SHOWOBJ has no exec command tag");

	/*
	 * Authenticated at either level: the full record, as before. This is
	 * what sysmon-web's own connection is, so narrowing it would break
	 * config round-tripping.
	 */
	out = dispatch("SHOWOBJ awbreyrouter", 1, 1);
	check(strstr(out, "ObjectSNMPCommunity") != NULL &&
	      strstr(out, "ObjectAuthPassword") != NULL,
		"dispatch: authlvl 1 SHOWOBJ still carries credentials");
	out = dispatch("SHOWOBJ awbreyrouter", 2, 1);
	check(strstr(out, "ObjectRadiusSecret") != NULL &&
	      strstr(out, "ObjectExecCmd") != NULL,
		"dispatch: authlvl 2 SHOWOBJ still carries credentials");

	/* Not in xml mode: refused, and nothing of the object at all. */
	out = dispatch("SHOWOBJ awbreyrouter", 0, 0);
	check(strstr(out, "403") != NULL,
		"dispatch: SHOWOBJ outside xml mode is refused");
	check(strstr(out, "<ObjectStatus>") == NULL && strstr(out, MARKER) == NULL,
		"dispatch: a refused SHOWOBJ sends none of the object");

	/* An unknown name is refused, and must not fall back to anything. */
	out = dispatch("SHOWOBJ nosuchobject", 0, 1);
	check(strstr(out, "403") != NULL,
		"dispatch: SHOWOBJ of an unknown object is refused");
	check(strstr(out, "<ObjectStatus>") == NULL,
		"dispatch: SHOWOBJ of an unknown object sends no document");

	registered = NULL;
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

	dispatch_tests(g);

	if (failures == 0)
		printf("showobj-test: all checks passed\n");
	return failures ? 1 : 0;
}
