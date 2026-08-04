/*
 * snmpget_test.c - check sysmond's SNMP client against the reference.
 *
 * Two things worth proving about a hand-written protocol implementation,
 * and neither of them is "it compiles":
 *
 *   1. The requests we emit are what a real agent expects. Proven by
 *      sending them to a live snmpd and comparing the value we decode
 *      against what net-snmp's own snmpget reports for the same OID.
 *      That is a differential test against the reference implementation,
 *      which is the only thing that can catch "plausible but wrong".
 *
 *   2. The responses we parse cannot be made to misbehave. The response
 *      path reads bytes from whatever answered on port 161, so it gets
 *      the same treatment as the trap decoder: every prefix of a valid
 *      packet, then fuzzing, under the sanitizers.
 *
 * Usage:
 *   ./snmpget-test                     unit + fuzz only (no network)
 *   ./snmpget-test <host> <port> <community> <oid>...   + live agent
 */

#include "config.h"

/*
 * Stand-ins for the daemon this file deliberately does not link. The SNMP
 * wire code touches very little of sysmond, and keeping that list short
 * and visible here is part of the point: anything that grows this block
 * is the protocol code reaching somewhere it should not.
 */
bool debug = 0;
struct all_elements_list *currenthead = NULL;
void print_err(int a, const char *fmt, ...) { (void)a; (void)fmt; }
void *MALLOC(size_t n, char *why) { (void)why; return malloc(n); }
void FREE(void *p) { free(p); }
int errno_to_error(int e) { (void)e; return SYSM_ERR; }
void print_in_hex(unsigned char *m, int n) { (void)m; (void)n; }
float mydifftime(struct timeval a, struct timeval b) { (void)a; (void)b; return 0; }
void page_someone(struct hostinfo *s, int n, time_t t) { (void)s; (void)n; (void)t; }

struct my_hostent *my_gethostbyname(unsigned char *n, int af)
{
	static struct my_hostent he;
	static unsigned char addr[4];
	struct in_addr in;

	(void)af;
	if (inet_pton(AF_INET, (char *)n, &in) != 1)
		return NULL;
	memcpy(addr, &in, 4);
	he.my_h_addr_v4 = addr;
	he.h_length_v4 = 4;
	return &he;
}

static int failures = 0;

static void check(int cond, const char *what)
{
	if (!cond) {
		fprintf(stderr, "FAIL: %s\n", what);
		failures++;
	}
}

/*
 * Decode our own GetRequest far enough to prove it is well-formed BER
 * with the fields in the right places. A packet that only we can read is
 * not evidence of anything, but a packet we cannot read is definitely
 * broken.
 */
static void test_request_shape(void)
{
	unsigned char pkt[512];
	struct ber_cursor msg, seq, pdu, vbl, vb;
	unsigned char tag;
	const unsigned char *val;
	size_t vlen;
	char oid[192];
	int len;

	len = snmp_build_get(pkt, sizeof(pkt), SNMP_VERSION_2C, "public",
		12345, ".1.3.6.1.2.1.1.3.0");
	check(len > 0, "v2c request builds");
	if (len <= 0)
		return;

	snmp_ber_open(&msg, pkt, (size_t)len);
	check(snmp_ber_next(&msg, &tag, &val, &vlen) && tag == 0x30, "outer SEQUENCE");
	check(msg.pos == (size_t)len, "outer length covers the whole packet");
	snmp_ber_open(&seq, val, vlen);

	check(snmp_ber_next(&seq, &tag, &val, &vlen) && tag == 0x02, "version is INTEGER");
	check(snmp_ber_int(val, vlen) == SNMP_VERSION_2C, "version is 1 for v2c");

	check(snmp_ber_next(&seq, &tag, &val, &vlen) && tag == 0x04, "community is OCTET STRING");
	check(vlen == 6 && memcmp(val, "public", 6) == 0, "community round-trips");

	check(snmp_ber_next(&seq, &tag, &val, &vlen) && tag == 0xa0, "PDU is GetRequest");
	snmp_ber_open(&pdu, val, vlen);

	check(snmp_ber_next(&pdu, &tag, &val, &vlen) && tag == 0x02, "request-id present");
	check(snmp_ber_int(val, vlen) == 12345, "request-id round-trips");
	check(snmp_ber_next(&pdu, &tag, &val, &vlen) && snmp_ber_int(val, vlen) == 0, "error-status 0");
	check(snmp_ber_next(&pdu, &tag, &val, &vlen) && snmp_ber_int(val, vlen) == 0, "error-index 0");

	check(snmp_ber_next(&pdu, &tag, &val, &vlen) && tag == 0x30, "varbind list");
	snmp_ber_open(&vbl, val, vlen);
	check(snmp_ber_next(&vbl, &tag, &val, &vlen) && tag == 0x30, "one varbind");
	snmp_ber_open(&vb, val, vlen);
	check(snmp_ber_next(&vb, &tag, &val, &vlen) && tag == 0x06, "varbind OID");
	snmp_ber_oid_str(val, vlen, oid, sizeof(oid));
	check(strcmp(oid, ".1.3.6.1.2.1.1.3.0") == 0, "OID round-trips");
	check(snmp_ber_next(&vb, &tag, &val, &vlen) && tag == 0x05, "varbind value is NULL");

	/* v1 differs only in the version field */
	len = snmp_build_get(pkt, sizeof(pkt), SNMP_VERSION_1, "public", 1, ".1.3.6.1.2.1.1.3.0");
	check(len > 0, "v1 request builds");
	snmp_ber_open(&msg, pkt, (size_t)len);
	snmp_ber_next(&msg, &tag, &val, &vlen);
	snmp_ber_open(&seq, val, vlen);
	snmp_ber_next(&seq, &tag, &val, &vlen);
	check(snmp_ber_int(val, vlen) == SNMP_VERSION_1, "version is 0 for v1");
}

/* Lengths must be minimal form: a strict agent will reject 0x82 for a
   length that fits in one byte. */
static void test_minimal_lengths(void)
{
	unsigned char pkt[512];
	int len = snmp_build_get(pkt, sizeof(pkt), SNMP_VERSION_2C, "public",
		1, ".1.3.6.1.2.1.1.3.0");

	check(len > 0 && len < 128, "a one-OID request is small");
	check(pkt[0] == 0x30, "starts with SEQUENCE");
	check(pkt[1] < 0x80, "outer length is short form, not 0x82");
	check((size_t)pkt[1] == (size_t)len - 2, "outer length matches the content");
}

static void test_bad_oids_are_refused(void)
{
	unsigned char pkt[512];
	const char *bad[] = { "", ".", "1", "1.", ".1", "1.2.x", "1.2..3",
		"..1.2", "9.1.2", "1.40.2", "-1.2", NULL };
	int i;

	for (i = 0; bad[i] != NULL; i++) {
		check(snmp_build_get(pkt, sizeof(pkt), SNMP_VERSION_2C, "public",
			1, bad[i]) == -1, "refuses a malformed OID");
	}

	check(snmp_build_get(pkt, 8, SNMP_VERSION_2C, "public", 1,
		".1.3.6.1.2.1.1.3.0") == -1, "refuses to overflow a small buffer");
	check(snmp_build_get(pkt, sizeof(pkt), 3, "public", 1,
		".1.3.6.1.2.1.1.3.0") == -1, "refuses v3");
}

/*
 * Build a GetResponse the way an agent would, so the parser can be tested
 * without one.
 */
struct rbuf { unsigned char b[2048]; size_t n; };

static void rb_put(struct rbuf *r, unsigned char c) { if (r->n < sizeof(r->b)) r->b[r->n++] = c; }
static size_t rb_open(struct rbuf *r, unsigned char tag)
{
	rb_put(r, tag); rb_put(r, 0x82); rb_put(r, 0); rb_put(r, 0);
	return r->n;
}
static void rb_close(struct rbuf *r, size_t start)
{
	size_t n = r->n - start;
	r->b[start - 2] = (unsigned char)(n >> 8);
	r->b[start - 1] = (unsigned char)(n & 0xff);
}
static void rb_int(struct rbuf *r, unsigned char tag, unsigned long v)
{
	size_t s = rb_open(r, tag);
	unsigned char tmp[8];
	int k = 0;
	if (v == 0) {
		rb_put(r, 0);
	} else {
		while (v > 0 && k < 8) { tmp[k++] = (unsigned char)(v & 0xff); v >>= 8; }
		if (tmp[k - 1] & 0x80) rb_put(r, 0);
		while (k-- > 0) rb_put(r, tmp[k]);
	}
	rb_close(r, s);
}
static void rb_str(struct rbuf *r, const char *v)
{
	size_t s = rb_open(r, 0x04);
	while (*v) rb_put(r, (unsigned char)*v++);
	rb_close(r, s);
}
static void rb_oid(struct rbuf *r)
{
	/* .1.3.6.1.2.1.1.3.0 */
	static const unsigned char enc[] = { 0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x03, 0x00 };
	size_t s = rb_open(r, 0x06);
	size_t i;
	for (i = 0; i < sizeof(enc); i++) rb_put(r, enc[i]);
	rb_close(r, s);
}

static void build_response(struct rbuf *r, unsigned long reqid, int errstat,
	unsigned char valtag, unsigned long value)
{
	size_t msg, pdu, vbl, vb;

	r->n = 0;
	msg = rb_open(r, 0x30);
	rb_int(r, 0x02, SNMP_VERSION_2C);
	rb_str(r, "public");
	pdu = rb_open(r, 0xa2);
	rb_int(r, 0x02, reqid);
	rb_int(r, 0x02, (unsigned long)errstat);
	rb_int(r, 0x02, 0);
	vbl = rb_open(r, 0x30);
	vb = rb_open(r, 0x30);
	rb_oid(r);
	if (valtag == 0x04) {
		rb_str(r, "some-router");
	} else if (valtag == 0x05 || valtag >= 0x80) {
		size_t s = rb_open(r, valtag);
		rb_close(r, s);
	} else {
		rb_int(r, valtag, value);
	}
	rb_close(r, vb);
	rb_close(r, vbl);
	rb_close(r, pdu);
	rb_close(r, msg);
}

static void test_response_parsing(void)
{
	struct rbuf r;
	struct snmp_value v;

	build_response(&r, 4242, 0, 0x43, 123456);	/* TimeTicks */
	check(snmp_parse_response(r.b, r.n, 4242, &v), "TimeTicks response parses");
	check(v.value == 123456, "TimeTicks value");
	check(strcmp(v.type, "TimeTicks") == 0, "TimeTicks type named");
	check(strcmp(v.oid, ".1.3.6.1.2.1.1.3.0") == 0, "response OID decoded");

	/* the whole point of not using net-snmp's guess-the-union path */
	build_response(&r, 7, 0, 0x46, 4294967296UL + 12345);
	check(snmp_parse_response(r.b, r.n, 7, &v), "Counter64 response parses");
	check(v.value == 4294967296UL + 12345, "Counter64 keeps its high word");
	check(strcmp(v.type, "Counter64") == 0, "Counter64 type named");

	build_response(&r, 8, 0, 0x41, 99);
	check(snmp_parse_response(r.b, r.n, 8, &v) && v.value == 99, "Counter32");
	build_response(&r, 9, 0, 0x42, 42);
	check(snmp_parse_response(r.b, r.n, 9, &v) && v.value == 42, "Gauge32");
	build_response(&r, 10, 0, 0x02, 7);
	check(snmp_parse_response(r.b, r.n, 10, &v) && v.value == 7, "INTEGER");

	/* someone else's answer must never be taken as ours */
	build_response(&r, 4242, 0, 0x43, 1);
	check(!snmp_parse_response(r.b, r.n, 4243, &v), "wrong request-id rejected");

	/* exceptions and errors are not values */
	build_response(&r, 11, 0, 0x81, 0);
	check(snmp_parse_response(r.b, r.n, 11, &v), "noSuchInstance is still an answer");
	check(!v.have_value, "noSuchInstance carries no value");
	check(strcmp(v.exception, "noSuchInstance") == 0, "exception named");

	/* A string where a threshold expects a number: an answer, not silence */
	build_response(&r, 13, 0, 0x04, 0);
	check(snmp_parse_response(r.b, r.n, 13, &v), "a STRING reply is still an answer");
	check(!v.have_value, "a STRING is not a comparable value");
	check(strcmp(v.type, "STRING") == 0, "STRING type named");

	build_response(&r, 12, 2, 0x05, 0);
	snmp_parse_response(r.b, r.n, 12, &v);
	check(v.error_status == 2, "error-status surfaced");
	check(!v.have_value, "an error PDU carries no value");
}

static void test_truncation_and_fuzz(int rounds)
{
	struct rbuf r;
	struct snmp_value v;
	unsigned char mutated[2048];
	size_t n;
	int i, j;

	build_response(&r, 4242, 0, 0x43, 123456);
	for (n = 0; n <= r.n; n++)
		snmp_parse_response(r.b, n, 4242, &v);	/* must not misbehave */

	for (i = 0; i < rounds; i++) {
		size_t len;

		if (i % 2) {
			build_response(&r, 4242, 0, 0x43, 123456);
		} else {
			r.n = (size_t)(rand() % (int)sizeof(r.b));
			for (j = 0; j < (int)r.n; j++)
				r.b[j] = (unsigned char)(rand() & 0xff);
		}
		len = r.n;
		memcpy(mutated, r.b, len);
		for (j = 0; j < 8 && len > 0; j++)
			mutated[rand() % (int)len] = (unsigned char)(rand() & 0xff);
		if (len > 0 && (rand() % 3) == 0)
			len = (size_t)(rand() % (int)len);

		snmp_parse_response(mutated, len, 4242, &v);
		check(memchr(v.type, '\0', sizeof(v.type)) != NULL, "type terminated");
		check(memchr(v.oid, '\0', sizeof(v.oid)) != NULL, "oid terminated");
		check(memchr(v.exception, '\0', sizeof(v.exception)) != NULL, "exception terminated");
	}
}

/*
 * Live differential test: ask a real agent, and compare against what
 * net-snmp's snmpget says about the same OID.
 */
static void test_against_agent(const char *host, int port, const char *community,
	char **oids, int noids)
{
	int i;

	for (i = 0; i < noids; i++) {
		struct snmp_value v;
		char cmd[512];
		char line[512];
		FILE *fp;
		int fd;
		int tries;

		fd = snmp_open_query(host, port, SNMP_VERSION_2C, community,
			1000 + i, oids[i]);
		if (fd == -1) {
			fprintf(stderr, "FAIL: could not query %s for %s: %s\n",
				host, oids[i], strerror(errno));
			failures++;
			continue;
		}

		for (tries = 0; tries < 50; tries++) {
			if (snmp_read_response(fd, 1000 + i, &v))
				break;
			usleep(20000);
		}
		close(fd);

		if (tries == 50) {
			fprintf(stderr, "FAIL: no answer for %s\n", oids[i]);
			failures++;
			continue;
		}

		snprintf(cmd, sizeof(cmd),
			"snmpget -v2c -c %s -Oqv %s:%d %s 2>/dev/null",
			community, host, port, oids[i]);
		fp = popen(cmd, "r");
		if (fp == NULL) {
			fprintf(stderr, "FAIL: cannot run snmpget\n");
			failures++;
			continue;
		}
		if (fgets(line, sizeof(line), fp) == NULL)
			line[0] = '\0';
		pclose(fp);

		printf("  %-28s ours=%-14lu (%s)  net-snmp=%s",
			oids[i], v.value, v.type, line[0] ? line : "(no answer)\n");

		/* What "agreement" means depends on what came back. Only a
		   number can be compared as a number; for everything else the
		   test is that we and net-snmp reached the same conclusion. */
		if (v.have_value) {
			char want[64];
			snprintf(want, sizeof(want), "%lu", v.value);
			if (strstr(line, want) == NULL) {
				if (strcmp(v.type, "TimeTicks") == 0) {
					printf("    (TimeTicks moved between queries - not a mismatch)\n");
				} else {
					fprintf(stderr, "FAIL: %s: ours %lu not in net-snmp's %s",
						oids[i], v.value, line);
					failures++;
				}
			}
		} else if (v.exception[0] != '\0') {
			if (strstr(line, "No Such") == NULL && strstr(line, "End of MIB") == NULL) {
				fprintf(stderr, "FAIL: %s: we said %s, net-snmp said %s",
					oids[i], v.exception, line);
				failures++;
			} else {
				printf("    (both report the object is not there)\n");
			}
		} else {
			/* not a number - net-snmp should not have printed one either */
			if (line[0] == '\0' || strspn(line, "0123456789 \n") == strlen(line)) {
				fprintf(stderr, "FAIL: %s: we found no value but net-snmp printed %s",
					oids[i], line);
				failures++;
			} else {
				printf("    (both report a non-numeric value: %s type)\n", v.type);
			}
		}
	}
}

int main(int argc, char **argv)
{
	srand(20260804);

	/* -dump <oid>: print the bytes we would put on the wire, so they can
	   be diffed against what net-snmp sends for the same request. */
	if (argc == 3 && strcmp(argv[1], "-dump") == 0) {
		unsigned char pkt[512];
		int len = snmp_build_get(pkt, sizeof(pkt), SNMP_VERSION_2C,
			"public", 1, argv[2]);
		int i;
		if (len < 0) {
			printf("refused\n");
			return 1;
		}
		for (i = 0; i < len; i++)
			printf("%02x", pkt[i]);
		printf("\n");
		return 0;
	}

	test_request_shape();
	test_minimal_lengths();
	test_bad_oids_are_refused();
	test_response_parsing();
	test_truncation_and_fuzz(50000);

	if (argc >= 5) {
		printf("--- against the agent at %s:%s ---\n", argv[1], argv[2]);
		test_against_agent(argv[1], atoi(argv[2]), argv[3], &argv[4], argc - 4);
	}

	if (failures == 0) {
		printf("snmpget: all checks passed\n");
		return 0;
	}
	printf("snmpget: %d failures\n", failures);
	return 1;
}
