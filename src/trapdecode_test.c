/*
 * trapdecode_test.c - exercise the SNMP trap decoder.
 *
 * decode_snmp_trap() parses UDP packets that anybody on the network can
 * send, so "it works on a real trap" is not evidence of anything. This
 * harness does three things:
 *
 *   1. round-trip: build known v1/v2c traps and check the decode is right
 *   2. truncation: decode every prefix of every valid packet
 *   3. fuzz: mutate valid packets, and throw random bytes at it
 *
 * Build and run it under the sanitizers, which is where the real value
 * is - the assertions catch wrong answers, ASan catches everything else:
 *
 *   make trapdecode-test && ./trapdecode-test
 *
 * Not linked into sysmond.
 */

#include "config.h"
#include <assert.h>

static int failures = 0;

static void check(int cond, const char *what)
{
	if (!cond) {
		fprintf(stderr, "FAIL: %s\n", what);
		failures++;
	}
}

static void check_str(const char *got, const char *want, const char *what)
{
	if (strcmp(got, want) != 0) {
		fprintf(stderr, "FAIL: %s: got \"%s\", want \"%s\"\n", what, got, want);
		failures++;
	}
}

/*
 * Minimal BER writer, only enough to build test packets.
 */
struct pkt {
	unsigned char buf[4096];
	size_t len;
};

static void put(struct pkt *p, const void *data, size_t len)
{
	assert(p->len + len <= sizeof(p->buf));
	memcpy(p->buf + p->len, data, len);
	p->len += len;
}

static void put_byte(struct pkt *p, unsigned char b)
{
	put(p, &b, 1);
}

/*
 * Open a TLV. Always uses the two-byte long form for the length so a
 * container can hold more than 127 bytes - and so the decoder's long-form
 * path gets exercised on every packet we build.
 */
static size_t open_tlv(struct pkt *p, unsigned char tag)
{
	put_byte(p, tag);
	put_byte(p, 0x82);	/* length follows in 2 bytes */
	put_byte(p, 0);
	put_byte(p, 0);
	return p->len;		/* offset of the first content byte */
}

static void close_tlv(struct pkt *p, size_t start)
{
	size_t len = p->len - start;
	assert(len <= 0xffff);
	p->buf[start - 2] = (unsigned char)((len >> 8) & 0xff);
	p->buf[start - 1] = (unsigned char)(len & 0xff);
}

static void put_int(struct pkt *p, unsigned char tag, long v)
{
	size_t s = open_tlv(p, tag);
	if (v == 0) {
		put_byte(p, 0);
	} else {
		unsigned char tmp[8];
		int n = 0;
		long x = v;
		while (x > 0) { tmp[n++] = (unsigned char)(x & 0xff); x >>= 8; }
		if (tmp[n - 1] & 0x80) put_byte(p, 0);	/* keep it positive */
		while (n-- > 0) put_byte(p, tmp[n]);
	}
	close_tlv(p, s);
}

static void put_str(struct pkt *p, const char *v)
{
	size_t s = open_tlv(p, 0x04);
	put(p, v, strlen(v));
	close_tlv(p, s);
}

/* Encode a dotted OID like "1.3.6.1.6.3.1.1.5.3". */
static void put_oid(struct pkt *p, const char *dotted)
{
	size_t s = open_tlv(p, 0x06);
	unsigned long subs[80];
	int n = 0;
	const char *c = dotted;
	int i;

	while (*c != '\0' && n < 80) {
		subs[n++] = strtoul(c, (char **)&c, 10);
		if (*c == '.') c++;
	}
	assert(n >= 2);
	put_byte(p, (unsigned char)(subs[0] * 40 + subs[1]));
	for (i = 2; i < n; i++) {
		unsigned long v = subs[i];
		unsigned char tmp[8];
		int k = 0;
		do { tmp[k++] = (unsigned char)(v & 0x7f); v >>= 7; } while (v > 0);
		while (k-- > 0)
			put_byte(p, (unsigned char)(tmp[k] | (k > 0 ? 0x80 : 0)));
	}
	close_tlv(p, s);
}

static void put_ip(struct pkt *p, unsigned char a, unsigned char b,
	unsigned char c, unsigned char d)
{
	size_t s = open_tlv(p, 0x40);
	put_byte(p, a); put_byte(p, b); put_byte(p, c); put_byte(p, d);
	close_tlv(p, s);
}

/*
 * A v2c linkDown naming interface Gi0/1.
 */
static void build_v2_linkdown(struct pkt *p)
{
	size_t msg, pdu, vbl, vb;

	p->len = 0;
	msg = open_tlv(p, 0x30);
	put_int(p, 0x02, 1);			/* version: v2c */
	put_str(p, "public");
	pdu = open_tlv(p, 0xa7);		/* SNMPv2-Trap */
	put_int(p, 0x02, 12345);		/* request-id */
	put_int(p, 0x02, 0);			/* error-status */
	put_int(p, 0x02, 0);			/* error-index */
	vbl = open_tlv(p, 0x30);

	vb = open_tlv(p, 0x30);
	put_oid(p, "1.3.6.1.2.1.1.3.0");
	put_int(p, 0x43, 123456);		/* sysUpTime */
	close_tlv(p, vb);

	vb = open_tlv(p, 0x30);
	put_oid(p, "1.3.6.1.6.3.1.1.4.1.0");	/* snmpTrapOID */
	put_oid(p, "1.3.6.1.6.3.1.1.5.3");	/* linkDown */
	close_tlv(p, vb);

	vb = open_tlv(p, 0x30);
	put_oid(p, "1.3.6.1.2.1.2.2.1.1.3");	/* ifIndex.3 */
	put_int(p, 0x02, 3);
	close_tlv(p, vb);

	vb = open_tlv(p, 0x30);
	put_oid(p, "1.3.6.1.2.1.2.2.1.2.3");	/* ifDescr.3 */
	put_str(p, "Gi0/1");
	close_tlv(p, vb);

	vb = open_tlv(p, 0x30);
	put_oid(p, "1.3.6.1.2.1.2.2.1.8.3");	/* ifOperStatus.3 */
	put_int(p, 0x02, 2);			/* down */
	close_tlv(p, vb);

	close_tlv(p, vbl);
	close_tlv(p, pdu);
	close_tlv(p, msg);
}

/*
 * A v1 trap. generic 0 is coldStart; generic 6 is enterprise-specific.
 */
static void build_v1(struct pkt *p, const char *enterprise, int generic, int specific)
{
	size_t msg, pdu, vbl;

	p->len = 0;
	msg = open_tlv(p, 0x30);
	put_int(p, 0x02, 0);			/* version: v1 */
	put_str(p, "public");
	pdu = open_tlv(p, 0xa4);		/* Trap-PDU */
	put_oid(p, enterprise);
	put_ip(p, 10, 1, 2, 3);			/* agent-addr */
	put_int(p, 0x02, generic);
	put_int(p, 0x02, specific);
	put_int(p, 0x43, 42);			/* timestamp */
	vbl = open_tlv(p, 0x30);
	close_tlv(p, vbl);
	close_tlv(p, pdu);
	close_tlv(p, msg);
}

static void build_v3(struct pkt *p)
{
	size_t msg;

	p->len = 0;
	msg = open_tlv(p, 0x30);
	put_int(p, 0x02, 3);			/* version: v3 */
	put_str(p, "junk");			/* not what v3 really carries */
	close_tlv(p, msg);
}

/*
 * A packet designed to be obnoxious: a string full of XML metacharacters
 * and control bytes, an over-long OID, and far more varbinds than we keep.
 */
static void build_nasty(struct pkt *p)
{
	size_t msg, pdu, vbl, vb;
	char longoid[1024];
	size_t used;
	int i;

	/* An OID longer than the field that has to hold it, with the largest
	   sub-identifiers that fit in 32 bits. */
	used = (size_t)snprintf(longoid, sizeof(longoid), "1.3");
	for (i = 0; i < 60 && used < sizeof(longoid) - 12; i++)
		used += (size_t)snprintf(longoid + used, sizeof(longoid) - used,
			".4294967295");

	p->len = 0;
	msg = open_tlv(p, 0x30);
	put_int(p, 0x02, 1);
	put_str(p, "<&\"'>");
	pdu = open_tlv(p, 0xa7);
	put_int(p, 0x02, 1);
	put_int(p, 0x02, 0);
	put_int(p, 0x02, 0);
	vbl = open_tlv(p, 0x30);

	vb = open_tlv(p, 0x30);
	put_oid(p, "1.3.6.1.6.3.1.1.4.1.0");
	put_oid(p, "1.3.6.1.4.1.9.9.41.2.0.1");	/* Cisco enterprise trap */
	close_tlv(p, vb);

	vb = open_tlv(p, 0x30);
	put_oid(p, "1.3.6.1.2.1.2.2.1.2.1");
	put_str(p, "</TrapDescription><script>alert(1)</script>");
	close_tlv(p, vb);

	vb = open_tlv(p, 0x30);
	put_oid(p, longoid);			/* longer than the field holding it */
	put_str(p, "over-long oid");
	close_tlv(p, vb);

	for (i = 0; i < 40; i++) {	/* more varbinds than TRAP_MAX_VARBIND */
		vb = open_tlv(p, 0x30);
		put_oid(p, "1.3.6.1.4.1.9.9.9.1");
		put_int(p, 0x02, i);
		close_tlv(p, vb);
	}

	close_tlv(p, vbl);
	close_tlv(p, pdu);
	close_tlv(p, msg);
}

/* Every fixed-size string in the record must be NUL-terminated. */
static void check_terminated(struct trap_content *t)
{
	int i;

	check(memchr(t->community, '\0', sizeof(t->community)) != NULL, "community terminated");
	check(memchr(t->trap_oid, '\0', sizeof(t->trap_oid)) != NULL, "trap_oid terminated");
	check(memchr(t->enterprise, '\0', sizeof(t->enterprise)) != NULL, "enterprise terminated");
	check(memchr(t->agent, '\0', sizeof(t->agent)) != NULL, "agent terminated");
	check(memchr(t->name, '\0', sizeof(t->name)) != NULL, "name terminated");
	check(memchr(t->description, '\0', sizeof(t->description)) != NULL, "description terminated");
	check(memchr(t->severity, '\0', sizeof(t->severity)) != NULL, "severity terminated");
	check(memchr(t->category, '\0', sizeof(t->category)) != NULL, "category terminated");
	check(memchr(t->vendor, '\0', sizeof(t->vendor)) != NULL, "vendor terminated");
	check(memchr(t->iface, '\0', sizeof(t->iface)) != NULL, "iface terminated");
	check(t->nvarbinds >= 0 && t->nvarbinds <= TRAP_MAX_VARBIND, "varbind count in range");
	for (i = 0; i < t->nvarbinds; i++) {
		check(memchr(t->vb[i].oid, '\0', sizeof(t->vb[i].oid)) != NULL, "vb oid terminated");
		check(memchr(t->vb[i].name, '\0', sizeof(t->vb[i].name)) != NULL, "vb name terminated");
		check(memchr(t->vb[i].type, '\0', sizeof(t->vb[i].type)) != NULL, "vb type terminated");
		check(memchr(t->vb[i].value, '\0', sizeof(t->vb[i].value)) != NULL, "vb value terminated");
		check(memchr(t->vb[i].note, '\0', sizeof(t->vb[i].note)) != NULL, "vb note terminated");
	}
}

static void test_v2_linkdown(void)
{
	struct pkt p;
	struct trap_content t;
	int i, seen_status = 0;

	build_v2_linkdown(&p);
	check(decode_snmp_trap(p.buf, p.len, &t) == TRUE, "v2 linkDown decodes");
	check(t.version == 1, "v2c version");
	check_str(t.community, "public", "v2 community");
	check_str(t.name, "linkDown", "v2 trap name");
	check_str(t.severity, "critical", "linkDown is critical");
	check_str(t.category, "link", "linkDown category");
	check_str(t.trap_oid, ".1.3.6.1.6.3.1.1.5.3", "v2 trap oid");
	check_str(t.iface, "Gi0/1", "interface from ifDescr");
	check(t.ifindex == 3, "ifIndex picked up");
	check(t.uptime == 123456, "sysUpTime picked up");
	check(strstr(t.description, "Gi0/1") != NULL, "description names the interface");
	check(t.nvarbinds == 5, "five varbinds");

	for (i = 0; i < t.nvarbinds; i++) {
		if (strcmp(t.vb[i].name, "ifOperStatus") == 0) {
			check_str(t.vb[i].note, "down", "ifOperStatus decoded to down");
			seen_status = 1;
		}
	}
	check(seen_status, "ifOperStatus varbind present");
	check_terminated(&t);
}

static void test_v1_coldstart(void)
{
	struct pkt p;
	struct trap_content t;

	build_v1(&p, "1.3.6.1.4.1.14988", 0, 0);
	check(decode_snmp_trap(p.buf, p.len, &t) == TRUE, "v1 coldStart decodes");
	check(t.version == 0, "v1 version");
	check_str(t.name, "coldStart", "v1 generic 0 is coldStart");
	check_str(t.severity, "warning", "coldStart severity");
	check_str(t.category, "restart", "coldStart category");
	check_str(t.agent, "10.1.2.3", "v1 agent-addr");
	check_str(t.vendor, "MikroTik", "enterprise 14988 is MikroTik");
	check_str(t.trap_oid, ".1.3.6.1.6.3.1.1.5.1", "v1 mapped to the v2 trap OID");
	check_terminated(&t);
}

static void test_v1_enterprise(void)
{
	struct pkt p;
	struct trap_content t;

	build_v1(&p, "1.3.6.1.4.1.9", 6, 17);
	check(decode_snmp_trap(p.buf, p.len, &t) == TRUE, "v1 enterprise trap decodes");
	check_str(t.name, "enterpriseSpecific(17)", "specific number kept");
	check_str(t.vendor, "Cisco", "enterprise 9 is Cisco");
	check_str(t.trap_oid, ".1.3.6.1.4.1.9.0.17", "v1 enterprise trap oid");
	check_terminated(&t);
}

static void test_v3(void)
{
	struct pkt p;
	struct trap_content t;

	build_v3(&p);
	check(decode_snmp_trap(p.buf, p.len, &t) == FALSE, "v3 is not decoded");
	check_str(t.name, "snmpv3Trap", "v3 says so plainly");
	check(t.decoded == FALSE, "v3 marked undecoded");
	check_terminated(&t);
}

static void test_nasty(void)
{
	struct pkt p;
	struct trap_content t;

	build_nasty(&p);
	check(decode_snmp_trap(p.buf, p.len, &t) == TRUE, "nasty packet still decodes");
	check(t.nvarbinds <= TRAP_MAX_VARBIND, "varbinds capped");
	check_str(t.vendor, "Cisco", "vendor from the trap OID");
	check_terminated(&t);
}

/* Every prefix of a valid packet must be handled without misbehaving. */
static void test_truncation(void)
{
	struct pkt p;
	struct trap_content t;
	size_t n;

	build_v2_linkdown(&p);
	for (n = 0; n <= p.len; n++) {
		decode_snmp_trap(p.buf, n, &t);
		check_terminated(&t);
	}

	build_v1(&p, "1.3.6.1.4.1.9", 6, 17);
	for (n = 0; n <= p.len; n++) {
		decode_snmp_trap(p.buf, n, &t);
		check_terminated(&t);
	}

	build_nasty(&p);
	for (n = 0; n <= p.len; n++) {
		decode_snmp_trap(p.buf, n, &t);
		check_terminated(&t);
	}
}

/*
 * Mutate known-good packets, and throw pure noise at it. Run under ASan
 * this is what says the parser is safe on hostile input.
 */
static void test_fuzz(int rounds)
{
	struct pkt p;
	struct trap_content t;
	unsigned char mutated[4096];
	int i, j;

	for (i = 0; i < rounds; i++) {
		size_t len;

		switch (i % 4) {
			case 0: build_v2_linkdown(&p); break;
			case 1: build_v1(&p, "1.3.6.1.4.1.9", 6, 17); break;
			case 2: build_nasty(&p); break;
			default:
				/* pure noise, random length */
				p.len = (size_t)(rand() % (int)sizeof(p.buf));
				for (j = 0; j < (int)p.len; j++)
					p.buf[j] = (unsigned char)(rand() & 0xff);
				break;
		}

		len = p.len;
		memcpy(mutated, p.buf, len);

		/* flip a handful of bytes */
		for (j = 0; j < 8 && len > 0; j++)
			mutated[rand() % (int)len] = (unsigned char)(rand() & 0xff);

		/* and sometimes lie about the length */
		if (len > 0 && (rand() % 3) == 0)
			len = (size_t)(rand() % (int)len);

		decode_snmp_trap(mutated, len, &t);
		check_terminated(&t);
	}
}

/*
 * The ring must stay bounded, hand traps back newest-first, and keep
 * counting past the point where it starts overwriting.
 */
static void test_history(void)
{
	struct pkt p;
	struct trap_content t;
	struct trap_record *r;
	char src[IP_ADDR_STR_SIZE];
	int i;
	int overfill = TRAP_HISTORY_MAX + 20;

	build_v2_linkdown(&p);
	decode_snmp_trap(p.buf, p.len, &t);

	for (i = 0; i < overfill; i++) {
		snprintf(src, sizeof(src), "10.0.0.%d", i % 256);
		trap_history_add(src, (time_t)(1000 + i), (int)p.len, &t,
			(i % 2) ? "someswitch" : NULL, (i % 2) ? TRUE : FALSE,
			(i % 2) ? TRUE : FALSE);
	}

	check(trap_history_count() == TRAP_HISTORY_MAX, "ring stays bounded");
	check(trap_history_total() == (unsigned long)overfill, "total keeps counting");

	r = trap_history_get(0);
	check(r != NULL, "newest trap present");
	if (r != NULL)
		check(r->when == (time_t)(1000 + overfill - 1), "newest trap is first");

	r = trap_history_get(1);
	if (r != NULL)
		check(r->when == (time_t)(1000 + overfill - 2), "second is next-newest");

	r = trap_history_get(TRAP_HISTORY_MAX - 1);
	check(r != NULL, "oldest retained trap present");
	if (r != NULL)
		check(r->when == (time_t)(1000 + overfill - TRAP_HISTORY_MAX),
			"oldest retained trap is the right one");

	check(trap_history_get(TRAP_HISTORY_MAX) == NULL, "past the end returns NULL");
	check(trap_history_get(-1) == NULL, "negative age returns NULL");
}

int main(int argc, char **argv)
{
	int rounds = 200000;

	if (argc > 1)
		rounds = atoi(argv[1]);

	srand(argc > 2 ? atoi(argv[2]) : 20260803);

	test_v2_linkdown();
	test_v1_coldstart();
	test_v1_enterprise();
	test_v3();
	test_nasty();
	test_truncation();
	test_history();
	test_fuzz(rounds);

	if (failures == 0) {
		printf("trapdecode: all checks passed (%d fuzz rounds)\n", rounds);
		return 0;
	}
	printf("trapdecode: %d failures\n", failures);
	return 1;
}
