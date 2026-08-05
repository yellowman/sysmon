/*
 * savestate_test.c - the checkpoint that carries check state across a
 * restart.
 *
 * This file is written by the daemon and read by the daemon, in a
 * directory it owns, so it is not exposed the way the trap decoder is.
 * What it is exposed to is a disk that filled up mid-write, a machine
 * that lost power, and a version of sysmond that is not the one that
 * wrote it - and the consequence of getting any of those wrong is a
 * monitoring daemon that comes back believing something false about
 * whether it has already paged somebody.
 *
 * So the cases here are all about a file that is not what was expected:
 * truncated, from the future, too old, garbage, or missing fields.
 */

#include "config.h"

/* Daemon stand-ins. Kept short on purpose. */
bool debug = 0;
struct all_elements_list *currenthead = NULL;

void print_err(int a, const char *fmt, ...) { (void)a; (void)fmt; }
void *MALLOC(size_t n, char *why) { (void)why; return malloc(n); }
void FREE(void *p) { free(p); }
void *STRDUP(char *s, char *why) { (void)why; return strdup(s); }

static int failures = 0;

static void check(int cond, const char *what)
{
	if (!cond)
	{
		fprintf(stderr, "FAIL: %s\n", what);
		failures++;
	}
}

/* ------------------------------------------------------------------ */

static char statepath[512];

/* Build a tree of named objects, all with clean state. */
static void make_tree(const char **names, int n)
{
	int i;

	currenthead = NULL;
	for (i = n - 1; i >= 0; i--)
	{
		struct all_elements_list *e = calloc(1, sizeof(*e));
		struct graph_elements *g = calloc(1, sizeof(*g));
		struct hostinfo *h = calloc(1, sizeof(*h));

		g->data = h;
		g->unique_name = (unsigned char *)strdup(names[i]);
		e->value = g;
		e->next = currenthead;
		currenthead = e;
	}
}

static struct hostinfo *find(const char *name)
{
	struct all_elements_list *e;

	for (e = currenthead; e != NULL; e = e->next)
	{
		if (strcmp((char *)e->value->unique_name, name) == 0)
			return e->value->data;
	}
	return NULL;
}

static void free_tree_local(void)
{
	struct all_elements_list *e = currenthead, *n;

	while (e != NULL)
	{
		n = e->next;
		free(e->value->unique_name);
		free(e->value->data);
		free(e->value);
		free(e);
		e = n;
	}
	currenthead = NULL;
}

static void writefile(const char *body)
{
	FILE *fh = fopen(statepath, "w");

	if (fh == NULL)
	{
		fprintf(stderr, "FAIL: cannot write %s\n", statepath);
		failures++;
		return;
	}
	fputs(body, fh);
	fclose(fh);
}

static void header(char *out, size_t outlen, int version, long age, int count)
{
	snprintf(out, outlen, "sysmon-state %d %lld %d\n", version,
		(long long)(time(NULL) - age), count);
}

/* ------------------------------------------------------------------ */

/* The whole point: a restart must not forget that it already paged. */
static void test_round_trip(void)
{
	static const char *names[] = { "core", "leaf" };
	char body[1024], hdr[128];
	struct hostinfo *h;

	make_tree(names, 2);
	find("core")->downct = 7;
	find("core")->contacted = TRUE;
	find("core")->deathtime = 1700000000;
	find("core")->totaldown = 3;
	find("leaf")->upct = 99;
	save_state(statepath);
	free_tree_local();

	/* A fresh tree, as a restart would produce it. */
	make_tree(names, 2);
	check(find("core")->downct == 0, "a fresh tree starts clean");
	load_state(statepath);

	h = find("core");
	check(h->downct == 7, "downct came back");
	check(h->contacted == TRUE, "the already-paged flag came back");
	check(h->deathtime == 1700000000, "deathtime came back");
	check(h->totaldown == 3, "totaldown came back");
	check(find("leaf")->upct == 99, "the second object came back too");
	free_tree_local();

	(void)body; (void)hdr;
}

/* An object name may contain a space; nothing else on the line may. */
static void test_name_with_spaces(void)
{
	static const char *names[] = { "core router eth1/1" };
	struct hostinfo *h;

	make_tree(names, 1);
	find("core router eth1/1")->downct = 4;
	save_state(statepath);
	free_tree_local();

	make_tree(names, 1);
	load_state(statepath);
	h = find("core router eth1/1");
	check(h != NULL && h->downct == 4, "a name with spaces round-trips");
	free_tree_local();
}

/*
 * Fields the writer did not write, and fields the reader does not know.
 * Both have to be survivable, because that is what lets one version of
 * this daemon read another's file.
 */
static void test_partial_and_unknown_fields(void)
{
	static const char *names[] = { "core" };
	char body[512], hdr[128];
	struct hostinfo *h;

	header(hdr, sizeof(hdr), 1, 60, 1);
	snprintf(body, sizeof(body),
		"%sdownct=5 somethingnew=12345 name=core\n", hdr);
	writefile(body);

	make_tree(names, 1);
	find("core")->upct = 42;   /* not in the file: must be left alone */
	load_state(statepath);
	h = find("core");
	check(h->downct == 5, "a field that is present is restored");
	check(h->upct == 42, "a field the file omits is left as the config had it");
	check(h->contacted == FALSE, "an omitted flag is not invented");
	free_tree_local();
}

/* Every way the file can be wrong must end in "start clean", never in
   half-applied state. */
static void test_rejections(void)
{
	static const char *names[] = { "core" };
	char body[512], hdr[128];

	/* not a state file at all */
	writefile("this is not a state file at all\ndowct=1 name=core\n");
	make_tree(names, 1);
	load_state(statepath);
	check(find("core")->downct == 0, "garbage is ignored");
	free_tree_local();

	/* a version this daemon does not write */
	header(hdr, sizeof(hdr), 99, 60, 1);
	snprintf(body, sizeof(body), "%sdownct=5 name=core\n", hdr);
	writefile(body);
	make_tree(names, 1);
	load_state(statepath);
	check(find("core")->downct == 0, "a future version is ignored");
	free_tree_local();

	/* older than the daemon is willing to believe */
	header(hdr, sizeof(hdr), 1, 48 * 60 * 60, 1);
	snprintf(body, sizeof(body), "%sdownct=5 name=core\n", hdr);
	writefile(body);
	make_tree(names, 1);
	load_state(statepath);
	check(find("core")->downct == 0, "a stale checkpoint is ignored");
	free_tree_local();

	/* truncated mid-line, as a full disk would leave it */
	header(hdr, sizeof(hdr), 1, 60, 2);
	snprintf(body, sizeof(body), "%sdownct=5 name=core\ndownct=9 upc", hdr);
	writefile(body);
	make_tree(names, 1);
	load_state(statepath);
	check(find("core")->downct == 5,
		"a complete line before the truncation is still used");
	free_tree_local();

	/* a line with no name is not attributable to anything */
	header(hdr, sizeof(hdr), 1, 60, 1);
	snprintf(body, sizeof(body), "%sdownct=5 upct=2\n", hdr);
	writefile(body);
	make_tree(names, 1);
	load_state(statepath);
	check(find("core")->downct == 0, "a nameless line is dropped");
	free_tree_local();

	/* no file at all - a first start */
	unlink(statepath);
	make_tree(names, 1);
	load_state(statepath);
	check(find("core")->downct == 0, "a missing checkpoint is not an error");
	free_tree_local();
}

/*
 * An object in the config that the checkpoint has never heard of - newly
 * added, or renamed - must start clean rather than inherit somebody
 * else's state.
 */
static void test_unknown_object(void)
{
	static const char *before[] = { "core" };
	static const char *after[] = { "core", "brandnew" };

	make_tree(before, 1);
	find("core")->downct = 6;
	save_state(statepath);
	free_tree_local();

	make_tree(after, 2);
	load_state(statepath);
	check(find("core")->downct == 6, "the known object is restored");
	check(find("brandnew")->downct == 0, "a new object starts clean");
	free_tree_local();
}

int main(void)
{
	char dir[] = "/tmp/sysmon-savestate-XXXXXX";

	if (mkdtemp(dir) == NULL)
	{
		fprintf(stderr, "cannot make a temp dir\n");
		return 1;
	}
	snprintf(statepath, sizeof(statepath), "%s/sysmond.state", dir);

	test_round_trip();
	test_name_with_spaces();
	test_partial_and_unknown_fields();
	test_rejections();
	test_unknown_object();

	unlink(statepath);
	rmdir(dir);

	if (failures != 0)
	{
		fprintf(stderr, "savestate: %d check(s) failed\n", failures);
		return 1;
	}
	printf("savestate: all checks passed\n");
	return 0;
}
