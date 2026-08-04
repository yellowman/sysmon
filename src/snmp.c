/* $Id: snmp.c,v 1.47 2005/10/12 03:04:38 jared Exp $ */

#include "config.h"

/* Forward declaration for print_in_hex (defined in radius.c) */
void print_in_hex(unsigned char *message, int msgsize);

/* One of the many include files defines a 'clear' macro
which breaks the build on Mac OS X */
#undef clear

/*
 * SNMP - The not so SIMPLE NETWORK MANAGMENT PROTOCOL
 *
 * sysmond used one operation from net-snmp: a v2c GET of a single OID with
 * a community string. That is a page of RFC 3416, and it cost a 300k-line
 * dependency, an OpenSSL link, a configure test that silently disabled
 * SNMP when it broke, and a known-wrong Counter64 path ("#warning need to
 * correctly differentiate btw 32 and 64 bit responses") that guessed which
 * union member to read. So sysmond speaks SNMP itself now.
 *
 * Deliberately not an emulation of the net-snmp API. sysmond owns the
 * socket, which means an outstanding query is an ordinary file descriptor
 * in the daemon's main select() - not a second fd set polled with a
 * zero-timeout select on every service pass, which is what the old
 * integration did and why SNMP checks used to report themselves as "not
 * checked in N seconds".
 *
 * Scope is v1 and v2c GET, and nothing else. v3 is USM, engine discovery
 * and key localisation; a subtly wrong implementation of that is a silent
 * security hole rather than a visible failure, so it is not attempted.
 *
 * The response path parses bytes from whatever answered on port 161, so it
 * gets the same treatment as the trap decoder it shares a BER reader with:
 * bounds-checked reads, hard caps, and fuzzing.
 *
 * Below: the wire format first, then the check that uses it.
 */

/* ASN.1 / BER tags. The reader's copies live in trapdecode.c. */
#define SNMP_TAG_INTEGER	0x02
#define SNMP_TAG_OCTETSTR	0x04
#define SNMP_TAG_NULL		0x05
#define SNMP_TAG_OID		0x06
#define SNMP_TAG_SEQUENCE	0x30
#define SNMP_TAG_IPADDRESS	0x40
#define SNMP_TAG_COUNTER32	0x41
#define SNMP_TAG_GAUGE32	0x42
#define SNMP_TAG_TIMETICKS	0x43
#define SNMP_TAG_COUNTER64	0x46
#define SNMP_TAG_NOSUCHOBJECT	0x80
#define SNMP_TAG_NOSUCHINST	0x81
#define SNMP_TAG_ENDOFMIBVIEW	0x82

#define SNMP_PDU_GET		0xa0
#define SNMP_PDU_RESPONSE	0xa2

#define SNMP_MAX_SUBIDS		128

/*
 * A growing-into-fixed-storage BER writer. Everything it builds is small
 * and known - one GET of one OID - so it writes into the caller's buffer
 * and reports failure rather than allocating.
 */
struct ber_writer {
	unsigned char *buf;
	size_t cap;
	size_t len;
	bool overflow;
};

static void bw_init(struct ber_writer *w, unsigned char *buf, size_t cap)
{
	w->buf = buf;
	w->cap = cap;
	w->len = 0;
	w->overflow = FALSE;
}

static void bw_byte(struct ber_writer *w, unsigned char b)
{
	if (w->len >= w->cap) {
		w->overflow = TRUE;
		return;
	}
	w->buf[w->len++] = b;
}

static void bw_bytes(struct ber_writer *w, const unsigned char *b, size_t n)
{
	size_t i;

	for (i = 0; i < n; i++)
		bw_byte(w, b[i]);
}

/*
 * Open a constructed element. Three bytes are reserved for the length;
 * bw_close() writes the real one and shuffles the content back if the
 * short form will do, so what goes on the wire is always minimal-form -
 * some embedded agents are strict about that.
 */
static size_t bw_open(struct ber_writer *w, unsigned char tag)
{
	bw_byte(w, tag);
	bw_byte(w, 0);
	bw_byte(w, 0);
	bw_byte(w, 0);
	return w->len;
}

static void bw_close(struct ber_writer *w, size_t start)
{
	size_t content;

	if (w->overflow || start > w->len)
		return;

	content = w->len - start;

	if (content < 128) {
		/* short form: one length byte, so close the 2-byte gap */
		w->buf[start - 3] = (unsigned char)content;
		memmove(w->buf + start - 2, w->buf + start, content);
		w->len -= 2;
	} else if (content < 0x10000) {
		w->buf[start - 3] = 0x82;
		w->buf[start - 2] = (unsigned char)((content >> 8) & 0xff);
		w->buf[start - 1] = (unsigned char)(content & 0xff);
	} else {
		w->overflow = TRUE;	/* we never build anything this big */
	}
}

/*
 * Integers go out in the shortest two's-complement form that keeps the
 * sign, which is what BER requires and what agents expect.
 */
static void bw_int(struct ber_writer *w, unsigned char tag, long v)
{
	unsigned char tmp[sizeof(long)];
	unsigned long uv = (unsigned long)v;
	size_t start;
	int i, first;

	start = bw_open(w, tag);

	for (i = 0; i < (int)sizeof(long); i++)
		tmp[i] = (unsigned char)((uv >> ((sizeof(long) - 1 - i) * 8)) & 0xff);

	/* Shortest form that still carries the sign: drop leading 0x00 on a
	   positive value and leading 0xff on a negative one, but never the
	   byte that sets the sign bit of what follows. */
	first = 0;
	while (first < (int)sizeof(long) - 1) {
		if (tmp[first] == 0x00 && (tmp[first + 1] & 0x80) == 0) {
			first++;
			continue;
		}
		if (tmp[first] == 0xff && (tmp[first + 1] & 0x80) != 0) {
			first++;
			continue;
		}
		break;
	}

	for (; first < (int)sizeof(long); first++)
		bw_byte(w, tmp[first]);

	bw_close(w, start);
}

static void bw_string(struct ber_writer *w, unsigned char tag,
	const char *s, size_t n)
{
	size_t start = bw_open(w, tag);

	bw_bytes(w, (const unsigned char *)s, n);
	bw_close(w, start);
}

static void bw_null(struct ber_writer *w)
{
	size_t start = bw_open(w, SNMP_TAG_NULL);

	bw_close(w, start);
}

/*
 * Encode a dotted OID. Refuses anything that is not two or more numeric
 * sub-identifiers, because an OID we cannot encode must fail the check
 * loudly rather than query something else by accident.
 */
static bool bw_oid(struct ber_writer *w, const char *dotted)
{
	unsigned long subs[SNMP_MAX_SUBIDS];
	int n = 0;
	const char *c = dotted;
	size_t start;
	int i;

	if (dotted == NULL)
		return FALSE;

	if (*c == '.')
		c++;	/* one leading dot is conventional; ".." is malformed */

	while (*c != '\0' && n < SNMP_MAX_SUBIDS) {
		char *end = NULL;

		if (*c < '0' || *c > '9')
			return FALSE;
		subs[n++] = strtoul(c, &end, 10);
		if (end == c)
			return FALSE;
		c = end;
		if (*c == '.')
			c++;
		else if (*c != '\0')
			return FALSE;
	}

	if (n < 2 || subs[0] > 6 || subs[1] > 39)
		return FALSE;

	start = bw_open(w, SNMP_TAG_OID);
	bw_byte(w, (unsigned char)(subs[0] * 40 + subs[1]));

	for (i = 2; i < n; i++) {
		unsigned char tmp[10];
		int k = 0;
		unsigned long v = subs[i];

		do {
			tmp[k++] = (unsigned char)(v & 0x7f);
			v >>= 7;
		} while (v > 0 && k < (int)sizeof(tmp));

		while (k-- > 0)
			bw_byte(w, (unsigned char)(tmp[k] | (k > 0 ? 0x80 : 0)));
	}

	bw_close(w, start);
	return TRUE;
}

/*
 * snmp_build_get - encode a GetRequest for one OID.
 *
 * Returns the packet length, or -1 if the OID is unusable or the buffer
 * is too small.
 */
int snmp_build_get(unsigned char *out, size_t outlen, int version,
	const char *community, unsigned long reqid, const char *oid)
{
	struct ber_writer w;
	size_t msg, pdu, vblist, vb;

	if (out == NULL || community == NULL || oid == NULL)
		return -1;
	if (version != SNMP_VERSION_1 && version != SNMP_VERSION_2C)
		return -1;

	bw_init(&w, out, outlen);

	msg = bw_open(&w, SNMP_TAG_SEQUENCE);
	bw_int(&w, SNMP_TAG_INTEGER, version);
	bw_string(&w, SNMP_TAG_OCTETSTR, community, strlen(community));

	pdu = bw_open(&w, SNMP_PDU_GET);
	bw_int(&w, SNMP_TAG_INTEGER, (long)(reqid & 0x7fffffff));
	bw_int(&w, SNMP_TAG_INTEGER, 0);	/* error-status */
	bw_int(&w, SNMP_TAG_INTEGER, 0);	/* error-index  */

	vblist = bw_open(&w, SNMP_TAG_SEQUENCE);
	vb = bw_open(&w, SNMP_TAG_SEQUENCE);
	if (!bw_oid(&w, oid))
		return -1;
	bw_null(&w);
	bw_close(&w, vb);
	bw_close(&w, vblist);

	bw_close(&w, pdu);
	bw_close(&w, msg);

	if (w.overflow)
		return -1;
	return (int)w.len;
}

/*
 * Name a value's type and turn it into the unsigned long the threshold
 * checks work in. Counter64 is read as a 64-bit quantity rather than
 * guessed at, which is the bug this file exists to stop repeating.
 */
static void snmp_value_from_tag(unsigned char tag, const unsigned char *v,
	size_t len, struct snmp_value *out)
{
	switch (tag) {
		case SNMP_TAG_INTEGER:
			snprintf(out->type, sizeof(out->type), "INTEGER");
			out->value = (unsigned long)snmp_ber_int(v, len);
			out->have_value = TRUE;
			break;
		case SNMP_TAG_COUNTER32:
			snprintf(out->type, sizeof(out->type), "Counter32");
			out->value = snmp_ber_uint(v, len);
			out->have_value = TRUE;
			break;
		case SNMP_TAG_GAUGE32:
			snprintf(out->type, sizeof(out->type), "Gauge32");
			out->value = snmp_ber_uint(v, len);
			out->have_value = TRUE;
			break;
		case SNMP_TAG_TIMETICKS:
			snprintf(out->type, sizeof(out->type), "TimeTicks");
			out->value = snmp_ber_uint(v, len);
			out->have_value = TRUE;
			break;
		case SNMP_TAG_COUNTER64:
			snprintf(out->type, sizeof(out->type), "Counter64");
			out->value = snmp_ber_uint(v, len);
			out->have_value = TRUE;
			break;
		case SNMP_TAG_NOSUCHOBJECT:
			snprintf(out->type, sizeof(out->type), "exception");
			snprintf(out->exception, sizeof(out->exception), "noSuchObject");
			break;
		case SNMP_TAG_NOSUCHINST:
			snprintf(out->type, sizeof(out->type), "exception");
			snprintf(out->exception, sizeof(out->exception), "noSuchInstance");
			break;
		case SNMP_TAG_ENDOFMIBVIEW:
			snprintf(out->type, sizeof(out->type), "exception");
			snprintf(out->exception, sizeof(out->exception), "endOfMibView");
			break;
		case SNMP_TAG_OCTETSTR:
			/* A string where a number was expected is not an error we
			   can act on, but naming it beats reporting "no response". */
			snprintf(out->type, sizeof(out->type), "STRING");
			break;
		case SNMP_TAG_IPADDRESS:
			snprintf(out->type, sizeof(out->type), "IpAddress");
			break;
		default:
			snprintf(out->type, sizeof(out->type), "tag 0x%02x", tag);
			break;
	}
}

/*
 * snmp_parse_response - read a GetResponse and pull out the first varbind.
 *
 * TRUE means "this was an answer to our question", not "the answer was
 * useful": out->have_value says whether a number came back, and
 * out->exception / out->error_status say why not when it did not. The
 * difference matters - an agent replying noSuchInstance to a mistyped OID
 * must not look identical to an agent that never replied, or a
 * configuration mistake gets reported as an unreachable device.
 *
 * A mismatched request-id does return FALSE: UDP delivers duplicates and
 * stragglers, and the caller should keep waiting for its own answer.
 */
bool snmp_parse_response(const unsigned char *pkt, size_t len,
	unsigned long reqid, struct snmp_value *out)
{
	struct ber_cursor msg, seq, pdu, vblist, vb;
	unsigned char tag;
	const unsigned char *val;
	size_t vlen;
	long got_reqid;
	int version;

	if (out == NULL)
		return FALSE;
	memset(out, 0, sizeof(*out));

	if (pkt == NULL || len == 0)
		return FALSE;

	snmp_ber_open(&msg, pkt, len);
	if (!snmp_ber_next(&msg, &tag, &val, &vlen) || tag != SNMP_TAG_SEQUENCE)
		return FALSE;
	snmp_ber_open(&seq, val, vlen);

	if (!snmp_ber_next(&seq, &tag, &val, &vlen) || tag != SNMP_TAG_INTEGER)
		return FALSE;
	version = (int)snmp_ber_int(val, vlen);
	if (version != SNMP_VERSION_1 && version != SNMP_VERSION_2C)
		return FALSE;

	/* community - we do not check it: it is not an authenticator, and
	   pretending otherwise would be security theatre. */
	if (!snmp_ber_next(&seq, &tag, &val, &vlen) || tag != SNMP_TAG_OCTETSTR)
		return FALSE;

	if (!snmp_ber_next(&seq, &tag, &val, &vlen) || tag != SNMP_PDU_RESPONSE)
		return FALSE;
	snmp_ber_open(&pdu, val, vlen);

	if (!snmp_ber_next(&pdu, &tag, &val, &vlen) || tag != SNMP_TAG_INTEGER)
		return FALSE;
	got_reqid = snmp_ber_int(val, vlen);
	if ((unsigned long)got_reqid != (reqid & 0x7fffffff))
		return FALSE;	/* someone else's answer, or a stale duplicate */

	if (!snmp_ber_next(&pdu, &tag, &val, &vlen) || tag != SNMP_TAG_INTEGER)
		return FALSE;
	out->error_status = (int)snmp_ber_int(val, vlen);

	if (!snmp_ber_next(&pdu, &tag, &val, &vlen) || tag != SNMP_TAG_INTEGER)
		return FALSE;	/* error-index */

	if (!snmp_ber_next(&pdu, &tag, &val, &vlen) || tag != SNMP_TAG_SEQUENCE)
		return FALSE;
	snmp_ber_open(&vblist, val, vlen);

	if (!snmp_ber_next(&vblist, &tag, &val, &vlen) || tag != SNMP_TAG_SEQUENCE)
		return out->error_status != 0;	/* an error PDU can be empty */

	snmp_ber_open(&vb, val, vlen);

	if (!snmp_ber_next(&vb, &tag, &val, &vlen) || tag != SNMP_TAG_OID)
		return FALSE;
	snmp_ber_oid_str(val, vlen, out->oid, sizeof(out->oid));

	if (!snmp_ber_next(&vb, &tag, &val, &vlen))
		return FALSE;
	snmp_value_from_tag(tag, val, vlen, out);

	return TRUE;
}

/*
 * snmp_open_query - resolve, connect a UDP socket, and send the GET.
 *
 * Returns the socket, which the caller hands to sysmond's select loop and
 * later reads with snmp_read_response(). -1 means the query never left,
 * with errno set by whichever step failed.
 */
int snmp_open_query(const char *host, int port, int version,
	const char *community, unsigned long reqid, const char *oid)
{
	unsigned char packet[1500];
	struct sockaddr_in name;
	struct my_hostent *hp;
	int sock;
	int len;

	len = snmp_build_get(packet, sizeof(packet), version, community, reqid, oid);
	if (len < 0) {
		errno = EINVAL;
		return -1;
	}

	hp = my_gethostbyname((char *)host, AF_INET);
	if (hp == NULL || hp->my_h_addr_v4 == NULL) {
		errno = EHOSTUNREACH;
		return -1;
	}

	sock = socket(AF_INET, SOCK_DGRAM, 0);
	if (sock == -1)
		return -1;

	memset(&name, 0, sizeof(name));
	name.sin_family = AF_INET;
	name.sin_port = htons(port);
	memcpy((char *)&name.sin_addr, (char *)hp->my_h_addr_v4, hp->h_length_v4);

	/* connect() on a datagram socket so the kernel filters replies to
	   this agent, and so an ICMP port-unreachable comes back as an error
	   on recv() instead of a silent timeout. */
	if (connect(sock, (struct sockaddr *)&name, sizeof(name)) == -1) {
		close(sock);
		return -1;
	}

	/* Non-blocking, and not as an optimisation: sysmond services a check
	   on its timer as well as on select() readiness, so a blocking recv()
	   on a silent agent would stop the whole daemon. */
	if (fcntl(sock, F_SETFL, fcntl(sock, F_GETFL, 0) | O_NONBLOCK) == -1) {
		close(sock);
		return -1;
	}

	if (send(sock, packet, (size_t)len, 0) == -1) {
		close(sock);
		return -1;
	}

	return sock;
}

/*
 * snmp_read_response - read one datagram and decode it.
 *
 * FALSE means "keep waiting": nothing arrived, it answered someone else's
 * request, or it was not a GetResponse. TRUE means our answer arrived -
 * which is not the same as it being a number, so the caller still has to
 * look at out->have_value.
 */
bool snmp_read_response(int fd, unsigned long reqid, struct snmp_value *out)
{
	unsigned char packet[4096];
	ssize_t got;

	if (fd == -1)
		return FALSE;

	got = recv(fd, packet, sizeof(packet), 0);
	if (got <= 0)
		return FALSE;

	return snmp_parse_response(packet, (size_t)got, reqid, out);
}

/* ---- the check itself ---------------------------------------------- */

struct snmpdata {
	unsigned long reqid;		/* what we asked, so we know the answer */
	unsigned long snmp_retval;	/* the value the agent gave us */
	time_t snmp_response_time;
	bool snmp_response;
};

int snmp_debug = 0;

/*
 * A request-id an agent will not confuse with anyone else's. It only has
 * to be unique among our own outstanding queries, so a counter is enough -
 * and unlike a random one, a duplicate is impossible rather than unlikely.
 */
static unsigned long next_snmp_reqid(void)
{
	static unsigned long reqid = 0;

	if (++reqid > 0x7ffffffeUL)
		reqid = 1;
	return reqid;
}

/*
 * start snmp query
 */
void start_test_snmp(struct monitorent *here)
{
	struct snmpdata *localstruct;

	if (here->checkent->snmp_oid == NULL ||
	    here->checkent->snmp_community == NULL)
	{
		print_err(1, "snmp.c: %s has no oid or community configured",
			here->checkent->hostname);
		here->retval = SYSM_ERR;
		return;
	}

	localstruct = MALLOC(sizeof(struct snmpdata), "snmpdata");
	if (localstruct == NULL)
	{
		here->retval = SYSM_ERR;
		return;
	}
	memset(localstruct, 0, sizeof(struct snmpdata));

	here->monitordata = localstruct;
	localstruct->reqid = next_snmp_reqid();

	if (debug||snmp_debug)
		print_err(1, "snmp.c:start_test_snmp: %s oid %s reqid %lu (%s)",
			here->checkent->hostname, here->checkent->snmp_oid,
			localstruct->reqid,
			here->checkent->snmp_version == SNMP_VERSION_1 ? "v1" : "v2c");

	here->filedes = snmp_open_query((char *)here->checkent->hostname,
		here->checkent->port > 0 ? here->checkent->port : SNMP_PORTNUM,
		here->checkent->snmp_version, (char *)here->checkent->snmp_community,
		localstruct->reqid, (char *)here->checkent->snmp_oid);

	if (here->filedes == -1)
	{
		switch (errno)
		{
			case EHOSTUNREACH:
				here->retval = SYSM_NODNS;
				break;
			case EINVAL:
				print_err(1, "snmp.c: %s has an oid we cannot encode: %s",
					here->checkent->hostname, here->checkent->snmp_oid);
				here->retval = SYSM_ERR;
				break;
			default:
				here->retval = errno_to_error(errno);
				break;
		}
		FREE(here->monitordata);
		here->monitordata = NULL;
		return;
	}

	/* The reply is an ordinary readable descriptor, so the main select()
	   wakes us the moment it lands instead of us polling for it. */
	here->fd_state = TRUE;

	return;
}

void stop_test_snmp(struct monitorent *here)
{
	if (here->filedes != -1)
	{
		close(here->filedes);
		here->filedes = -1;
	}

	if (here->monitordata != NULL)
	{
		FREE(here->monitordata);
		here->monitordata = NULL;
	}

	return;
}

void service_test_snmp(struct monitorent *here)
{
	struct snmpdata *localstruct = NULL;
	struct snmp_value value;
	unsigned long rate_time;
	unsigned long rate_time_val;
	unsigned long rate_avg_val;
	struct timeval now;

	localstruct = here->monitordata;
	if (localstruct == NULL)
	{
		print_err(1, "snmp.c:service_test_snmp localstruct is null");
		return;
	}

	if (!localstruct->snmp_response &&
	    snmp_read_response(here->filedes, localstruct->reqid, &value))
	{
		if (value.error_status != 0)
		{
			print_err(1, "snmp.c: %s answered error-status %d for %s",
				here->checkent->hostname, value.error_status,
				here->checkent->snmp_oid);
			here->retval = SYSM_BAD_RESP;
		} else if (value.exception[0] != '\0') {
			/* The agent is up and answering - it just does not have
			   that object. Saying so beats reporting the device as
			   unreachable 30 seconds later. */
			print_err(1, "snmp.c: %s has no %s (%s)",
				here->checkent->hostname, here->checkent->snmp_oid,
				value.exception);
			here->retval = SYSM_BAD_RESP;
		} else if (!value.have_value) {
			print_err(1, "snmp.c: %s returned %s for %s - not a value a threshold can be compared against",
				here->checkent->hostname, value.type,
				here->checkent->snmp_oid);
			here->retval = SYSM_BAD_RESP;
		} else {
			localstruct->snmp_retval = value.value;
			localstruct->snmp_response = TRUE;
			time(&localstruct->snmp_response_time);
			if (debug||snmp_debug)
				print_err(1, "snmp.c: %s -> %s %lu",
					here->checkent->hostname, value.type, value.value);
		}
	}

	if (debug||snmp_debug) print_err(1, "snmp.c:svc_test_snmp:snmp_response = %d", localstruct->snmp_response);
	if (localstruct->snmp_response)
	{
		if (debug||snmp_debug) print_err(1, "snmp.c:snmp_response(%s)", here->checkent->hostname);
		switch (here->checkent->snmp_test_type)
		{
			case SYSM_SNMP_TYPE_REBOOT:
				if (debug||snmp_debug) print_err(1, "snmp.c:type_reboot:comparing last(%lu) > now(%lu)", here->checkent->system_uptime, localstruct->snmp_retval);
				if (here->checkent->system_uptime > localstruct->snmp_retval)
				{
					here->retval = SYSM_SNMP_REBOOT;
				} else {
					here->retval = SYSM_OK;
				}
				here->checkent->system_uptime = localstruct->snmp_retval;
				break;
			case SYSM_SNMP_TYPE_HIGH:
				if (debug||snmp_debug) print_err(1, "snmp.c:type_high:comparing received value %lu with configured %ld", localstruct->snmp_retval, here->checkent->snmp_high);
				if (here->checkent->snmp_high < (long)localstruct->snmp_retval)
				{
					here->retval = SYSM_SNMP_HIGH;
				} else {
					here->retval = SYSM_OK;
				}
				/* stash last snmp value */
				here->checkent->system_uptime = localstruct->snmp_retval;
				break;
			case SYSM_SNMP_TYPE_LOW:
				if (debug||snmp_debug) print_err(1, "snmp.c:type_low:comparing received value %lu with configured %ld", localstruct->snmp_retval, here->checkent->snmp_low);
				if (here->checkent->snmp_low > (long)localstruct->snmp_retval)
				{
					here->retval = SYSM_SNMP_LOW;
				} else {
					here->retval = SYSM_OK;
				}
				/* stash last snmp value */
				here->checkent->system_uptime = localstruct->snmp_retval;
				break;
			case SYSM_SNMP_TYPE_RANGE:
				if ((here->checkent->snmp_low < (long)localstruct->snmp_retval) && (here->checkent->snmp_high > (long)localstruct->snmp_retval))
				{
					here->retval = SYSM_SNMP_OOR;
				} else {
					here->retval = SYSM_OK;
				}
				/* stash last snmp value */
				here->checkent->system_uptime = localstruct->snmp_retval;
				break;
			case SYSM_SNMP_TYPE_EXACT:
				if (here->checkent->snmp_exact != (long)localstruct->snmp_retval)
				{
					here->retval = SYSM_SNMP_NOTEXACT;
				} else {
					here->retval = SYSM_OK;
				}
				/* stash last snmp value */
				here->checkent->system_uptime = localstruct->snmp_retval;
				break;
			case SYSM_SNMP_TYPE_COMPARE:
				break;
			case SYSM_SNMP_TYPE_RATE:
				rate_time = (localstruct->snmp_response_time - here->checkent->last_snmp_resptime);
				rate_time_val = (localstruct->snmp_retval - here->checkent->system_uptime);
				if (rate_time == 0)
				{
					/* first sample, or two answers in the same second:
					   a rate is not defined yet, so do not invent one */
					here->checkent->system_uptime = localstruct->snmp_retval;
					here->checkent->last_snmp_resptime = localstruct->snmp_response_time;
					here->retval = SYSM_OK;
					break;
				}
				if (here->checkent->snmp_octets)
				{
					rate_avg_val=(rate_time_val*8/rate_time);
				} else {
					rate_avg_val=(rate_time_val/rate_time);
				}

				if (debug||snmp_debug) 
					print_err(1, "snmp.c:rate_avg_val = %lu ; here->checkent->snmp_rate %ld", rate_avg_val, here->checkent->snmp_rate);
				here->checkent->system_uptime = localstruct->snmp_retval;
				here->checkent->last_snmp_resptime = localstruct->snmp_response_time;
				if (rate_avg_val > (unsigned long)here->checkent->snmp_rate)
				{
					here->retval = SYSM_SNMP_HIGHRATE;
				} else {
					here->retval = SYSM_OK;
				}
				break;
			default:
				print_err(1, "snmp.c:invalid snmp type");
				here->retval = SYSM_ERR;
				break;
		}

	} else if (here->retval == -1) {
		gettimeofday(&now, NULL); /* get the current time */
		if (mydifftime(here->queueat, now) >= 30)
		{
			here->retval = SYSM_NORESP;
		}
	}

	if (debug||snmp_debug) 
	{
		print_err(1, "snmp.c:svc_test_snmp:checking here->retval it is %d", here->retval);
	}

	if (here->retval != -1)
	{
		if (debug||snmp_debug) print_err(1, "snmp.c:svc_test_snmp:here->retval = %d", here->retval);
		stop_test_snmp(here);
	}

	return;
}



void process_snmp_trap(int skt)
{
	unsigned char buffer[4096];
	int len;
	struct sockaddr_in from;
	socklen_t fromlen = sizeof(from);
	char ip_string[IP_ADDR_STR_SIZE];
	struct graph_elements *obj;
	struct trap_content trap;
	time_t now;
	bool alert_sent = FALSE;
	bool alert_enabled = FALSE;

	/* Receive trap packet */
	len = recvfrom(skt, buffer, sizeof(buffer), 0, (struct sockaddr*)&from, &fromlen);

	if (len == -1) {
		if (errno != EINTR && errno != EAGAIN)
			perror("snmp.c:recvfrom");
		return;
	}

	/* Extract source IP */
	if (inet_ntop(AF_INET, &from.sin_addr, ip_string, sizeof(ip_string)) == NULL)
		snprintf(ip_string, sizeof(ip_string), "unknown");

	time(&now);

	/*
	 * Who sent this, before anything else is done with it.
	 *
	 * The source decides acceptance, and it decides first: a packet from
	 * an address no object claims is dropped here, unparsed, unlogged and
	 * unstored. Anyone can send to UDP 162 from any address they care to
	 * write, so the work done before that question is answered is work an
	 * unauthenticated stranger gets to command.
	 *
	 * The v1 agent-addr field no longer selects an object. It is inside
	 * the packet, so it is written by whoever sent it - trusting it meant
	 * an unconfigured sender could pick which monitored device got paged
	 * about, just by naming it. A relay must now be a configured object
	 * in its own right; the agent address is still decoded and shown, it
	 * simply cannot let a stranger in.
	 */
	obj = find_trap_source(ip_string);
	if (obj == NULL) {
		if (debug)
			print_err(1, "discarding a %d byte packet on the trap port from %s: "
				"no object with trap_alert names that address", len, ip_string);
		return;
	}

	/*
	 * Read what the device actually said. decode_snmp_trap() always
	 * leaves something printable behind, so the log line and the trap
	 * history are useful even when the packet is junk.
	 */
	decode_snmp_trap(buffer, (size_t)len, &trap);

	if (trap.decoded) {
		print_err(1, "snmp trap from %s: %s (%s%s%s) - %s [%d bytes, %s]",
			ip_string, trap.name, trap.severity,
			trap.vendor[0] != '\0' ? ", " : "", trap.vendor,
			trap.description, len,
			trap.version == 0 ? "v1" : "v2c");
	} else {
		print_err(1, "snmp trap from %s: %s [%d bytes]",
			ip_string, trap.description, len);
	}

	/* Debug: dump packet in hex */
	if (debug) {
		print_in_hex(buffer, len);
	}

	/*
	 * Getting here means the source is a configured object with
	 * trap_alert set - that is what find_trap_source() answers, and
	 * nothing else reaches this line.
	 */
	alert_enabled = TRUE;

	/*
	 * Only page for something that really was a trap. Before the packet
	 * was decoded, any UDP datagram from a monitored address woke
	 * somebody up - which made a page trivial to provoke with a spoofed
	 * packet, and meant a stray scanner could do it by accident.
	 */
	if (trap.alertable) {
		send_trap_alert(obj, ip_string, &trap);
		alert_sent = TRUE;
	} else {
		print_err(1, "not paging %s: the packet from %s was not an snmp trap",
			obj->data->hostname, ip_string);
	}

	/*
	 * Kept for the web UI. Only accepted traps are held now: the history
	 * used to collect anything that arrived, on the argument that a trap
	 * from an unconfigured address is a device somebody forgot to
	 * monitor. That argument holds right up until a stranger fills the
	 * ring with forged packets and pushes the real ones out of it.
	 */
	trap_history_add(ip_string, now, len, &trap,
		(char *)obj->unique_name, alert_enabled, alert_sent);
}


/*
 * find_trap_source - which configured object may send us this trap
 *
 * A trap is accepted only from an address an operator wrote down and
 * marked trap_alert. Everything else is discarded where it arrives.
 *
 * That is a deliberate allowlist, and it replaces a best-effort match
 * that tried to be helpful and could not be. The old one walked every
 * object calling gethostbyname() - the one uncached lookup left in this
 * daemon, in a process with a single select() loop - so a packet from an
 * address matching nothing cost a synchronous resolution of the entire
 * object list. Port 162 is unauthenticated UDP with a forgeable source,
 * which made "an address matching nothing" the cheapest thing in the
 * world to send and the most expensive thing here to receive.
 *
 * Now an unknown source costs one walk of integer-ish string compares
 * and no network at all.
 *
 * The comparison is against data->ipv4_str - the address the object's
 * name resolved to when the config was loaded - so naming a device by
 * hostname works exactly as well as naming it by address. That lookup
 * already happens at load time to decide whether an object is usable,
 * so recording its answer is what lets this path be both correct and
 * free. A name that moves is picked up at the next load, which is the
 * same cadence everything else about an object honours.
 *
 * Returns: the object, or NULL - and NULL means discard.
 */
struct graph_elements *find_trap_source(char *ip_string)
{
	struct all_elements_list *walker;

	if (ip_string == NULL)
		return NULL;

	for (walker = currenthead; walker != NULL; walker = walker->next) {
		if (walker->value == NULL || walker->value->data == NULL)
			continue;
		if (!walker->value->data->trap_alert)
			continue;

		if (walker->value->data->ipv4_str != NULL &&
		    strcmp((char *)walker->value->data->ipv4_str, ip_string) == 0)
			return walker->value;

		/*
		 * An object with no resolved v4 address - v6-only, or a name
		 * that would not resolve at load - can still be named by a
		 * literal address in the config.
		 */
		if (walker->value->data->hostname != NULL &&
		    strcmp((char *)walker->value->data->hostname, ip_string) == 0)
			return walker->value;
	}

	return NULL;
}

/*
 * send_trap_alert - Send an alert when SNMP trap is received
 *
 * Triggers the alert system to notify the configured contact that
 * an SNMP trap was received from this device, and tells them what the
 * device said. A page that reads "linkDown on Gi0/1 (critical)" is
 * actionable at 3am; "a trap arrived" is not.
 */
void send_trap_alert(struct graph_elements *obj, char *source,
	struct trap_content *trap)
{
	time_t now;
	char pagemsg[LARGE_TEMPBUF_SIZE];
	unsigned char *saved_message;

	if (obj == NULL || obj->data == NULL) {
		print_err(1, "send_trap_alert: NULL object pointer");
		return;
	}

	if (debug) {
		print_err(1, "Sending trap alert for %s (%s)",
			obj->data->hostname, source != NULL ? source : "?");
	}

	/* Get current time */
	time(&now);

	/*
	 * %w in a page message expands to the object's description. Point
	 * it at the trap for the duration of the page so the contact - and
	 * any spawn command - receives the decoded content, then put the
	 * configured description back. page_someone() forks for spawn
	 * commands, and the child gets its own copy of this string.
	 */
	if (trap != NULL && trap->name[0] != '\0') {
		snprintf(pagemsg, sizeof(pagemsg), "%s%sSNMP trap %s (%s)%s%s from %s: %s",
			obj->data->message != NULL ? (char *)obj->data->message : "",
			obj->data->message != NULL ? " - " : "",
			trap->name, trap->severity,
			trap->iface[0] != '\0' ? " on " : "", trap->iface,
			source != NULL ? source : "an unknown address",
			trap->description);
	} else {
		snprintf(pagemsg, sizeof(pagemsg), "SNMP trap from %s",
			source != NULL ? source : "an unknown address");
	}

	saved_message = obj->data->message;
	obj->data->message = (unsigned char *)pagemsg;

	/* Use existing alert infrastructure */
	page_someone(obj->data, SYSM_SNMP_TRAP, now);

	obj->data->message = saved_message;
}
