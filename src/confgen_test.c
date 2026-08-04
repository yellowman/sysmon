/*
 * confgen_test.c - the parts of config distribution that read bytes
 * somebody else wrote.
 *
 * A config delivery arrives base64-encoded over the aggregator link and is
 * decoded into a buffer that is then written to this box's config files.
 * The decoder is therefore in exactly the position the trap decoder is in:
 * a parser standing between a socket and something that matters. It gets
 * the same treatment - every prefix of valid input, then fuzzing, under
 * the sanitizers - because "it works on well-formed input" is not a
 * property worth testing on its own.
 *
 * The hash gets checked too, for a different reason: both ends compare it
 * to decide whether a box is in sync, so a hash that is not stable, or
 * that cannot tell two different file sets apart, silently breaks fleet
 * management rather than loudly breaking anything.
 *
 * Usage:
 *   ./confgen-test                     unit + fuzz
 *   ./confgen-test -fuzz <n> [seed]    more rounds
 */

#include "config.h"

/*
 * Stand-ins for the daemon. Kept short on purpose: anything that grows
 * this block is confgen reaching further into sysmond than it should.
 */
bool debug = 0;
bool badconfig = FALSE;
bool gotsighup = FALSE;
char configfile[256] = "/tmp/sysmon-confgen-test/sysmon.conf";

void print_err(int a, const char *fmt, ...) { (void)a; (void)fmt; }
void *MALLOC(size_t n, char *why) { (void)why; return malloc(n); }
void FREE(void *p) { free(p); }
void *STRDUP(char *s, char *why)
{
	(void)why;
	return strdup(s);
}
int sendline(int fd, char *buffer) { (void)fd; (void)buffer; return 0; }
int data_waiting_read(int fd, int secs) { (void)fd; (void)secs; return 0; }
int tls_pending(int fd) { (void)fd; return 0; }
int tls_read(int fd, void *b, int n) { (void)fd; (void)b; (void)n; return -1; }
struct all_elements_list *loadconfig(char *p) { (void)p; return NULL; }
struct graph_elements *configed_root = NULL;
char *parser_root = NULL;

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

static void test_b64_roundtrip(void)
{
	/* Every length from 0 to 300, so both padding cases and the
	   no-padding case are covered at each alignment. */
	unsigned char in[300];
	int len;

	for (len = 0; len < (int)sizeof(in); len++)
	{
		char *enc;
		unsigned char *dec;
		long declen = -1;
		int i;

		for (i = 0; i < len; i++)
			in[i] = (unsigned char)((i * 7 + len) & 0xff);

		enc = confgen_b64encode(in, len);
		check(enc != NULL, "encode returned something");
		if (enc == NULL)
			return;

		dec = confgen_b64decode(enc, &declen);
		check(dec != NULL, "decode returned something");
		check(declen == len, "decoded length matches");
		if (dec != NULL && declen == len)
			check(memcmp(in, dec, (size_t)len) == 0, "bytes survived the round trip");

		free(enc);
		free(dec);
	}
}

/* A config file is bytes, not text: NULs and high bytes must survive. */
static void test_b64_binary(void)
{
	unsigned char in[] = { 0x00, 0xff, 0x0a, 0x0d, 0x00, 0x80, 0x7f, 0x00 };
	char *enc = confgen_b64encode(in, (long)sizeof(in));
	long declen = -1;
	unsigned char *dec;

	check(enc != NULL, "binary encodes");
	if (enc == NULL)
		return;
	check(strchr(enc, '\n') == NULL, "encoded form has no newline in it");
	dec = confgen_b64decode(enc, &declen);
	check(dec != NULL && declen == (long)sizeof(in), "binary decodes to the same length");
	if (dec != NULL && declen == (long)sizeof(in))
		check(memcmp(in, dec, sizeof(in)) == 0, "NULs and high bytes survived");
	free(enc);
	free(dec);
}

/*
 * Anything that is not base64 must be refused. A decoder that silently
 * skips what it does not understand writes a config file with a hole in
 * it, and the hash comparison would then disagree forever with no
 * indication of why.
 */
static void test_b64_rejects_junk(void)
{
	static const char *bad[] = {
		"AAAA!",        /* not in the alphabet */
		"AA=A",         /* data after padding */
		"A",            /* truncated quad */
		"AAAAA",        /* truncated quad */
		"====",         /* nothing but padding is not a valid quad start */
		"AB CD~",       /* tilde is not base64 (space is skipped) */
	};
	size_t i;

	for (i = 0; i < sizeof(bad) / sizeof(bad[0]); i++)
	{
		long len = -1;
		unsigned char *out = confgen_b64decode(bad[i], &len);

		if (out != NULL)
		{
			fprintf(stderr, "FAIL: decoder accepted %s\n", bad[i]);
			failures++;
			free(out);
		}
	}

	/* Wrapping is how it arrives on the wire, so that must still work. */
	{
		long len = -1;
		unsigned char *out = confgen_b64decode("aGVs\r\nbG8g\r\nd29y\r\nbGQh", &len);

		check(out != NULL && len == 12, "wrapped base64 decodes");
		if (out != NULL && len == 12)
			check(memcmp(out, "hello world!", 12) == 0, "wrapped base64 is correct");
		free(out);
	}
}

/* Every prefix of a valid encoding: none may crash, and only the ones
   that land on a quad boundary may succeed. */
static void test_b64_prefixes(void)
{
	unsigned char in[64];
	char *enc;
	size_t n, i;

	for (i = 0; i < sizeof(in); i++)
		in[i] = (unsigned char)(i * 3);
	enc = confgen_b64encode(in, (long)sizeof(in));
	check(enc != NULL, "prefix source encoded");
	if (enc == NULL)
		return;

	for (n = 0; n <= strlen(enc); n++)
	{
		char *prefix = malloc(n + 1);
		long len = -1;
		unsigned char *out;

		memcpy(prefix, enc, n);
		prefix[n] = '\0';
		out = confgen_b64decode(prefix, &len);
		if (out != NULL)
		{
			check(n % 4 == 0, "a prefix only decodes on a quad boundary");
			free(out);
		}
		free(prefix);
	}
	free(enc);
}

static unsigned long rng_state = 1;

static unsigned long rng(void)
{
	rng_state = rng_state * 6364136223846793005UL + 1442695040888963407UL;
	return rng_state >> 17;
}

static void fuzz_b64(int rounds)
{
	static const char alphabet[] =
		"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
		"0123456789+/=\r\n \t!~\x01\x7f";
	int round;

	for (round = 0; round < rounds; round++)
	{
		size_t n = (size_t)(rng() % 200);
		char *buf = malloc(n + 1);
		size_t i;
		long len = -1;
		unsigned char *out;

		for (i = 0; i < n; i++)
			buf[i] = alphabet[rng() % (sizeof(alphabet) - 1)];
		buf[n] = '\0';

		out = confgen_b64decode(buf, &len);
		if (out != NULL)
		{
			/* Whatever it produced must be within what it promised. */
			check(len >= 0, "fuzz: length is not negative");
			free(out);
		}
		free(buf);
	}
}

/* ------------------------------------------------------------------ */

static void writefile(const char *path, const char *content)
{
	FILE *fh = fopen(path, "wb");

	if (fh == NULL)
	{
		fprintf(stderr, "FAIL: cannot write %s\n", path);
		failures++;
		return;
	}
	fwrite(content, 1, strlen(content), fh);
	fclose(fh);
}

/*
 * The hash is what tells "in sync" from "somebody edited this box", so:
 * it must be stable across calls, it must change when any byte changes,
 * and - the one that is easy to get wrong - two different splits of the
 * same total bytes across files must not collide. That last one is the
 * whole reason each contribution is length-prefixed.
 */
static void test_hash(void)
{
	char dir[] = "/tmp/sysmon-confgen-test-XXXXXX";
	char a[512], b[512];
	char h1[80], h2[80], h3[80];

	if (mkdtemp(dir) == NULL)
	{
		fprintf(stderr, "FAIL: cannot make a temp dir\n");
		failures++;
		return;
	}
	snprintf(a, sizeof(a), "%s/a.conf", dir);
	snprintf(b, sizeof(b), "%s/b.conf", dir);

	writefile(a, "root = \"x\";\n");
	writefile(b, "object x { ip \"1.2.3.4\"; type ping; };\n");

	confset_reset();
	confset_record(a);
	confset_record(b);
	check(confset_count() == 2, "two files tracked");

	check(confgen_hash(h1, sizeof(h1)), "hash computed");
	check(strlen(h1) == 64, "hash is 64 hex digits");
	check(confgen_hash(h2, sizeof(h2)), "hash computed again");
	check(strcmp(h1, h2) == 0, "hashing twice gives the same answer");

	/* One byte changes -> the hash changes. */
	writefile(b, "object x { ip \"1.2.3.5\"; type ping; };\n");
	check(confgen_hash(h3, sizeof(h3)), "hash after edit");
	check(strcmp(h1, h3) != 0, "an edited file changes the hash");

	/* Recording the same file twice must not double-count it. */
	confset_record(a);
	check(confset_count() == 2, "a repeated include is tracked once");

	/* Two different splits of identical total bytes must differ. */
	{
		char c[512], d[512];
		char split1[80], split2[80];

		snprintf(c, sizeof(c), "%s/c.conf", dir);
		snprintf(d, sizeof(d), "%s/d.conf", dir);

		writefile(c, "AB");
		writefile(d, "C");
		confset_reset();
		confset_record(c);
		confset_record(d);
		check(confgen_hash(split1, sizeof(split1)), "split1 hashed");

		writefile(c, "A");
		writefile(d, "BC");
		check(confgen_hash(split2, sizeof(split2)), "split2 hashed");
		check(strcmp(split1, split2) != 0,
			"moving a byte between files changes the hash");

		unlink(c);
		unlink(d);
	}

	confset_reset();
	unlink(a);
	unlink(b);
	rmdir(dir);
}

/*
 * A file the parser could not open is not part of the config, so hashing
 * must fail rather than quietly hash the files that do exist - a hash that
 * silently means something different is worse than no hash.
 */
static void test_hash_missing_file(void)
{
	char h[80];

	confset_reset();
	confset_record("/nonexistent/sysmon-confgen-test/nope.conf");
	check(!confgen_hash(h, sizeof(h)), "a missing file fails the hash");
	confset_reset();
}

int main(int argc, char **argv)
{
	int rounds = 20000;

	if (argc > 2 && strcmp(argv[1], "-fuzz") == 0)
	{
		rounds = atoi(argv[2]);
		if (argc > 3)
			rng_state = (unsigned long)strtoul(argv[3], NULL, 10);
	}

	test_b64_roundtrip();
	test_b64_binary();
	test_b64_rejects_junk();
	test_b64_prefixes();
	test_hash();
	test_hash_missing_file();
	fuzz_b64(rounds);

	if (failures != 0)
	{
		fprintf(stderr, "confgen: %d check(s) failed\n", failures);
		return 1;
	}
	printf("confgen: all checks passed (%d fuzz rounds)\n", rounds);
	return 0;
}
