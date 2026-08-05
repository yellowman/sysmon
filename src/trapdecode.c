/*
 * trapdecode.c - decode the contents of an SNMP trap.
 *
 * sysmond used to treat a trap as a doorbell: something arrived from an
 * address we know, page someone. That throws away everything the device
 * actually said. This file reads the packet - version, community, trap
 * identity and every varbind - so an alert can say "linkDown on Gi0/1"
 * instead of "a trap happened", and so the web UI can show the operator
 * what the device reported.
 *
 * The BER parsing here is deliberately self-contained rather than handed
 * to net-snmp: trap reception is compiled in unconditionally, so decoding
 * must work on a build without net-snmp too.
 *
 * Everything below parses hostile input from a UDP socket. Rules kept
 * throughout: every read is bounds-checked against the buffer end, no
 * recursion, fixed-size destinations written only through snprintf or
 * explicit length-limited copies, and hard caps on varbind count and OID
 * length so a malformed packet costs a bounded amount of work.
 */

#include "config.h"

/*
 * ASN.1 / BER tags used by SNMP.
 */
#define BER_INTEGER		0x02
#define BER_OCTETSTR		0x04
#define BER_NULL		0x05
#define BER_OID			0x06
#define BER_SEQUENCE		0x30
#define BER_IPADDRESS		0x40
#define BER_COUNTER32		0x41
#define BER_GAUGE32		0x42
#define BER_TIMETICKS		0x43
#define BER_OPAQUE		0x44
#define BER_COUNTER64		0x46
#define BER_NOSUCHOBJECT	0x80
#define BER_NOSUCHINSTANCE	0x81
#define BER_ENDOFMIBVIEW	0x82

#define PDU_TRAP_V1		0xa4
#define PDU_INFORM		0xa6
#define PDU_TRAP_V2		0xa7

#define TRAP_MAX_SUBIDS		64	/* refuse absurd OIDs */

/* Well-known OIDs we name outright. */
static const struct {
	const char *oid;
	const char *name;
} trap_oid_exact[] = {
	{ ".1.3.6.1.2.1.1.3.0",		"sysUpTime" },
	{ ".1.3.6.1.6.3.1.1.4.1.0",	"snmpTrapOID" },
	{ ".1.3.6.1.6.3.1.1.4.3.0",	"snmpTrapEnterprise" },
	{ ".1.3.6.1.2.1.1.1.0",		"sysDescr" },
	{ ".1.3.6.1.2.1.1.5.0",		"sysName" },
	{ ".1.3.6.1.2.1.1.6.0",		"sysLocation" },
	{ NULL, NULL }
};

/* Table columns: the instance index follows, so match on the prefix. */
static const struct {
	const char *prefix;
	const char *name;
} trap_oid_prefix[] = {
	{ ".1.3.6.1.2.1.2.2.1.1.",	"ifIndex" },
	{ ".1.3.6.1.2.1.2.2.1.2.",	"ifDescr" },
	{ ".1.3.6.1.2.1.2.2.1.3.",	"ifType" },
	{ ".1.3.6.1.2.1.2.2.1.7.",	"ifAdminStatus" },
	{ ".1.3.6.1.2.1.2.2.1.8.",	"ifOperStatus" },
	{ ".1.3.6.1.2.1.31.1.1.1.1.",	"ifName" },
	{ ".1.3.6.1.2.1.31.1.1.1.18.",	"ifAlias" },
	{ ".1.3.6.1.6.3.18.1.3.",	"snmpTrapAddress" },
	{ ".1.3.6.1.6.3.18.1.4.",	"snmpTrapCommunity" },
	{ NULL, NULL }
};

/*
 * The six standard traps, keyed both ways: v2c sends an OID, v1 sends a
 * generic number, and they mean the same thing.
 */
static const struct {
	const char *oid;
	int generic;
	const char *name;
	const char *severity;
	const char *category;
	const char *desc;
} trap_standard[] = {
	{ ".1.3.6.1.6.3.1.1.5.1", 0, "coldStart", "warning", "restart",
	  "Device cold started - it was power cycled or reloaded" },
	{ ".1.3.6.1.6.3.1.1.5.2", 1, "warmStart", "warning", "restart",
	  "Device warm started - its agent reinitialised" },
	{ ".1.3.6.1.6.3.1.1.5.3", 2, "linkDown", "critical", "link",
	  "An interface went down" },
	{ ".1.3.6.1.6.3.1.1.5.4", 3, "linkUp", "informational", "link",
	  "An interface came back up" },
	{ ".1.3.6.1.6.3.1.1.5.5", 4, "authenticationFailure", "warning", "security",
	  "SNMP authentication failure - wrong community, or a poller that should not be there" },
	{ ".1.3.6.1.6.3.1.1.5.6", 5, "egpNeighborLoss", "warning", "routing",
	  "An EGP neighbour was lost" },
	{ NULL, -1, NULL, NULL, NULL, NULL }
};

/* Enterprise numbers under .1.3.6.1.4.1 worth naming on sight. */
static const struct {
	unsigned long number;
	const char *vendor;
} trap_vendors[] = {
	{ 9,		"Cisco" },
	{ 11,		"Hewlett-Packard" },
	{ 674,		"Dell" },
	{ 1916,		"Extreme Networks" },
	{ 2011,		"Huawei" },
	{ 2636,		"Juniper" },
	{ 3375,		"F5" },
	{ 4526,		"NETGEAR" },
	{ 6027,		"Dell Force10" },
	{ 8072,		"Net-SNMP" },
	{ 14988,	"MikroTik" },
	{ 25506,	"H3C" },
	{ 30065,	"Arista" },
	{ 41112,	"Ubiquiti" },
	{ 0,		NULL }
};

/* ifOperStatus / ifAdminStatus values, so a bare "2" reads as "down". */
static const char *if_status_name(long v)
{
	switch (v) {
		case 1: return "up";
		case 2: return "down";
		case 3: return "testing";
		case 4: return "unknown";
		case 5: return "dormant";
		case 6: return "notPresent";
		case 7: return "lowerLayerDown";
		default: return NULL;
	}
}

void snmp_ber_open(struct ber_cursor *c, const unsigned char *buf, size_t len)
{
	c->buf = buf;
	c->len = len;
	c->pos = 0;
}

/*
 * Read one tag-length-value. Returns FALSE on anything we will not
 * tolerate: truncation, multi-byte tags, indefinite lengths, or a length
 * that runs past the end of the buffer.
 */
bool snmp_ber_next(struct ber_cursor *c, unsigned char *tag,
	const unsigned char **val, size_t *vlen)
{
	unsigned char t;
	size_t l;
	int n;

	if (c->pos >= c->len)
		return FALSE;

	t = c->buf[c->pos++];
	if ((t & 0x1f) == 0x1f)
		return FALSE;	/* multi-byte tag: never valid in SNMP */

	if (c->pos >= c->len)
		return FALSE;

	l = c->buf[c->pos++];
	if (l & 0x80) {
		n = (int)(l & 0x7f);
		if (n == 0 || n > 4)
			return FALSE;	/* indefinite length, or absurd */
		if (c->pos + (size_t)n > c->len)
			return FALSE;
		l = 0;
		while (n-- > 0)
			l = (l << 8) | c->buf[c->pos++];
	}

	if (l > c->len - c->pos)
		return FALSE;	/* claims more data than we received */

	*tag = t;
	*val = c->buf + c->pos;
	*vlen = l;
	c->pos += l;
	return TRUE;
}

/* Descend into a constructed value. */
static void ber_enter(struct ber_cursor *c, const unsigned char *val, size_t vlen)
{
	snmp_ber_open(c, val, vlen);
}

long snmp_ber_int(const unsigned char *v, size_t len)
{
	unsigned long acc;
	size_t i;

	if (len == 0 || len > sizeof(long))
		return 0;

	/*
	 * Accumulate unsigned. Shifting a negative value left is undefined
	 * behaviour, and this runs on bytes off the network, so the sign is
	 * applied at the end rather than carried through the shifts.
	 */
	acc = (v[0] & 0x80) ? ~0UL : 0UL;	/* sign extend */
	for (i = 0; i < len; i++)
		acc = (acc << 8) | v[i];

	if (acc <= (unsigned long)LONG_MAX)
		return (long)acc;
	return -(long)(~acc) - 1;		/* defined for every value */
}

unsigned long snmp_ber_uint(const unsigned char *v, size_t len)
{
	unsigned long out = 0;
	size_t i;

	if (len == 0 || len > sizeof(unsigned long))
		return 0;

	for (i = 0; i < len; i++)
		out = (out << 8) | v[i];
	return out;
}

/*
 * Render an OID as ".1.3.6.1...". Truncates rather than overflows, and
 * gives up on sub-identifiers that would overflow an unsigned long.
 */
void snmp_ber_oid_str(const unsigned char *v, size_t len, char *out, size_t outlen)
{
	unsigned long sub = 0;
	size_t i, used;
	int subids = 0;
	int shifted = 0;
	char part[24];

	if (outlen == 0)
		return;
	out[0] = '\0';
	if (len == 0)
		return;

	/* The first byte packs the first two sub-identifiers. */
	if (v[0] >= 80)
		snprintf(out, outlen, ".2.%u", (unsigned)(v[0] - 80));
	else
		snprintf(out, outlen, ".%u.%u", (unsigned)(v[0] / 40), (unsigned)(v[0] % 40));

	used = strlen(out);

	for (i = 1; i < len; i++) {
		if (shifted > 4) {		/* > 35 bits: not a real OID */
			sub = 0;
			shifted = 0;
			continue;
		}
		sub = (sub << 7) | (unsigned long)(v[i] & 0x7f);
		shifted++;
		if (v[i] & 0x80)
			continue;		/* more bytes to come */

		if (++subids > TRAP_MAX_SUBIDS)
			return;			/* truncate: enough is enough */

		snprintf(part, sizeof(part), ".%lu", sub);
		sub = 0;
		shifted = 0;
		if (used + strlen(part) + 1 >= outlen)
			return;			/* truncate rather than overflow */
		memcpy(out + used, part, strlen(part));
		used += strlen(part);
		out[used] = '\0';
	}
}

/*
 * Copy an octet string into a fixed buffer. Printable text comes through
 * as text; anything else is hex, because trap payloads are attacker-
 * controlled and must never be pasted raw into a log line, an XML
 * document, or an e-mail.
 */
static void ber_string_str(const unsigned char *v, size_t len, char *out, size_t outlen)
{
	size_t i, used = 0;
	bool printable = TRUE;

	if (outlen == 0)
		return;
	out[0] = '\0';

	for (i = 0; i < len; i++) {
		if (v[i] == '\t' || v[i] == '\n' || v[i] == '\r')
			continue;
		if (v[i] < 0x20 || v[i] > 0x7e) {
			printable = FALSE;
			break;
		}
	}

	if (printable) {
		for (i = 0; i < len && used + 1 < outlen; i++) {
			out[used++] = (v[i] < 0x20) ? ' ' : (char)v[i];
		}
		out[used] = '\0';
		return;
	}

	for (i = 0; i < len && used + 3 < outlen; i++) {
		snprintf(out + used, outlen - used, "%02x", v[i]);
		used += 2;
	}
	out[used] = '\0';
}

/*
 * Format one varbind value and name its type.
 */
static void ber_value_str(unsigned char tag, const unsigned char *v, size_t len,
	char *type, size_t typelen, char *out, size_t outlen, char *note, size_t notelen)
{
	if (outlen == 0 || typelen == 0)
		return;

	out[0] = '\0';
	note[0] = '\0';
	snprintf(type, typelen, "unknown");

	switch (tag) {
		case BER_INTEGER:
			snprintf(type, typelen, "INTEGER");
			snprintf(out, outlen, "%ld", snmp_ber_int(v, len));
			break;
		case BER_OCTETSTR:
			snprintf(type, typelen, "STRING");
			ber_string_str(v, len, out, outlen);
			break;
		case BER_NULL:
			snprintf(type, typelen, "NULL");
			break;
		case BER_OID:
			snprintf(type, typelen, "OID");
			snmp_ber_oid_str(v, len, out, outlen);
			break;
		case BER_IPADDRESS:
			snprintf(type, typelen, "IpAddress");
			if (len == 4)
				snprintf(out, outlen, "%u.%u.%u.%u", v[0], v[1], v[2], v[3]);
			else
				ber_string_str(v, len, out, outlen);
			break;
		case BER_COUNTER32:
			snprintf(type, typelen, "Counter32");
			snprintf(out, outlen, "%lu", snmp_ber_uint(v, len));
			break;
		case BER_GAUGE32:
			snprintf(type, typelen, "Gauge32");
			snprintf(out, outlen, "%lu", snmp_ber_uint(v, len));
			break;
		case BER_TIMETICKS:
			{
				unsigned long ticks = snmp_ber_uint(v, len);
				snprintf(type, typelen, "TimeTicks");
				snprintf(out, outlen, "%lu", ticks);
				snprintf(note, notelen, "%lud %luh %lum %lus",
					ticks / 8640000UL,
					(ticks / 360000UL) % 24,
					(ticks / 6000UL) % 60,
					(ticks / 100UL) % 60);
			}
			break;
		case BER_COUNTER64:
			snprintf(type, typelen, "Counter64");
			snprintf(out, outlen, "%lu", snmp_ber_uint(v, len));
			break;
		case BER_OPAQUE:
			snprintf(type, typelen, "Opaque");
			ber_string_str(v, len, out, outlen);
			break;
		case BER_NOSUCHOBJECT:
			snprintf(type, typelen, "noSuchObject");
			break;
		case BER_NOSUCHINSTANCE:
			snprintf(type, typelen, "noSuchInstance");
			break;
		case BER_ENDOFMIBVIEW:
			snprintf(type, typelen, "endOfMibView");
			break;
		default:
			snprintf(type, typelen, "tag 0x%02x", tag);
			ber_string_str(v, len, out, outlen);
			break;
	}
}

/* Name a varbind OID if we recognise it. */
static void name_oid(const char *oid, char *out, size_t outlen)
{
	int i;

	out[0] = '\0';
	for (i = 0; trap_oid_exact[i].oid != NULL; i++) {
		if (strcmp(oid, trap_oid_exact[i].oid) == 0) {
			snprintf(out, outlen, "%s", trap_oid_exact[i].name);
			return;
		}
	}
	for (i = 0; trap_oid_prefix[i].prefix != NULL; i++) {
		size_t plen = strlen(trap_oid_prefix[i].prefix);
		if (strncmp(oid, trap_oid_prefix[i].prefix, plen) == 0) {
			snprintf(out, outlen, "%s", trap_oid_prefix[i].name);
			return;
		}
	}
}

/* Pull the enterprise number out of .1.3.6.1.4.1.<n>... and name it. */
static void name_vendor(const char *oid, char *out, size_t outlen)
{
	const char *ent = ".1.3.6.1.4.1.";
	unsigned long number;
	char *end;
	int i;

	out[0] = '\0';
	if (oid == NULL || strncmp(oid, ent, strlen(ent)) != 0)
		return;

	number = strtoul(oid + strlen(ent), &end, 10);
	if (end == oid + strlen(ent))
		return;

	for (i = 0; trap_vendors[i].vendor != NULL; i++) {
		if (trap_vendors[i].number == number) {
			snprintf(out, outlen, "%s", trap_vendors[i].vendor);
			return;
		}
	}
}

/*
 * Read the variable-bindings list into the record.
 */
static void decode_varbinds(struct ber_cursor *pdu, struct trap_content *out)
{
	struct ber_cursor list, vb;
	unsigned char tag;
	const unsigned char *val;
	size_t vlen;

	if (!snmp_ber_next(pdu, &tag, &val, &vlen) || tag != BER_SEQUENCE)
		return;

	ber_enter(&list, val, vlen);

	while (out->nvarbinds < TRAP_MAX_VARBIND) {
		struct trap_varbind *b = &out->vb[out->nvarbinds];
		unsigned char vtag;
		const unsigned char *vval;
		size_t vvlen;

		if (!snmp_ber_next(&list, &tag, &val, &vlen) || tag != BER_SEQUENCE)
			break;

		ber_enter(&vb, val, vlen);

		if (!snmp_ber_next(&vb, &tag, &vval, &vvlen) || tag != BER_OID)
			break;
		snmp_ber_oid_str(vval, vvlen, b->oid, sizeof(b->oid));
		name_oid(b->oid, b->name, sizeof(b->name));

		if (!snmp_ber_next(&vb, &vtag, &vval, &vvlen))
			break;
		ber_value_str(vtag, vval, vvlen, b->type, sizeof(b->type),
			b->value, sizeof(b->value), b->note, sizeof(b->note));

		/* Turn the varbinds we understand into facts about the trap. */
		if (strcmp(b->name, "snmpTrapOID") == 0 && b->value[0] != '\0') {
			snprintf(out->trap_oid, sizeof(out->trap_oid), "%s", b->value);
		} else if (strcmp(b->name, "sysUpTime") == 0) {
			out->uptime = strtoul(b->value, NULL, 10);
		} else if (strcmp(b->name, "snmpTrapEnterprise") == 0 &&
			out->enterprise[0] == '\0') {
			snprintf(out->enterprise, sizeof(out->enterprise), "%s", b->value);
		} else if (strcmp(b->name, "ifIndex") == 0) {
			out->ifindex = (int)strtol(b->value, NULL, 10);
		} else if (strcmp(b->name, "ifName") == 0 ||
			strcmp(b->name, "ifDescr") == 0 ||
			strcmp(b->name, "ifAlias") == 0) {
			/* ifName wins over ifDescr wins over ifAlias, but any
			   name at all beats an index. */
			if (out->iface[0] == '\0' || strcmp(b->name, "ifName") == 0)
				snprintf(out->iface, sizeof(out->iface), "%s", b->value);
		} else if (strcmp(b->name, "ifOperStatus") == 0 ||
			strcmp(b->name, "ifAdminStatus") == 0) {
			const char *s = if_status_name(strtol(b->value, NULL, 10));
			if (s != NULL)
				snprintf(b->note, sizeof(b->note), "%s", s);
		}

		out->nvarbinds++;
	}
}

/*
 * Decide what the trap means: name, severity, category, vendor.
 */
static void classify_trap(struct trap_content *out)
{
	bool known = FALSE;
	int i;

	for (i = 0; trap_standard[i].name != NULL; i++) {
		bool hit = FALSE;

		if (out->trap_oid[0] != '\0' &&
		    strcmp(out->trap_oid, trap_standard[i].oid) == 0)
			hit = TRUE;
		if (out->version == 0 && out->generic == trap_standard[i].generic)
			hit = TRUE;

		if (hit) {
			snprintf(out->name, sizeof(out->name), "%s", trap_standard[i].name);
			snprintf(out->severity, sizeof(out->severity), "%s", trap_standard[i].severity);
			snprintf(out->category, sizeof(out->category), "%s", trap_standard[i].category);
			snprintf(out->description, sizeof(out->description), "%s", trap_standard[i].desc);
			known = TRUE;
			break;
		}
	}

	/* Note this tests `known`, not an empty name: the record arrives
	   pre-filled with a placeholder so undecodable packets still print,
	   and testing the name would silently keep that placeholder on every
	   vendor trap. */
	if (!known) {
		/* Enterprise-specific. We cannot know what it means without
		   the vendor MIB, so say exactly that instead of guessing a
		   severity that would be wrong half the time. */
		if (out->version == 0 && out->generic == 6) {
			snprintf(out->name, sizeof(out->name), "enterpriseSpecific(%d)",
				out->specific);
		} else if (out->trap_oid[0] != '\0') {
			snprintf(out->name, sizeof(out->name), "enterpriseSpecific");
		} else {
			snprintf(out->name, sizeof(out->name), "trap");
		}
		snprintf(out->severity, sizeof(out->severity), "warning");
		snprintf(out->category, sizeof(out->category), "vendor");
		/* Explicit precision: an OID can be longer than the field it
		   is being described in, and a silently chopped sentence is
		   worse than a bounded one. */
		snprintf(out->description, sizeof(out->description),
			"Vendor-specific trap %.100s - see the vendor MIB for its meaning",
			out->trap_oid[0] != '\0' ? out->trap_oid : out->enterprise);
	}

	if (out->enterprise[0] != '\0')
		name_vendor(out->enterprise, out->vendor, sizeof(out->vendor));
	if (out->vendor[0] == '\0' && out->trap_oid[0] != '\0')
		name_vendor(out->trap_oid, out->vendor, sizeof(out->vendor));

	/* An interface name makes a link trap actionable; without one an
	   ifIndex at least says which port to look at. */
	if (out->iface[0] == '\0' && out->ifindex >= 0)
		snprintf(out->iface, sizeof(out->iface), "ifIndex %d", out->ifindex);

	if (out->iface[0] != '\0' && strcmp(out->category, "link") == 0) {
		char base[TRAP_VAL_LEN];
		snprintf(base, sizeof(base), "%s", out->description);
		snprintf(out->description, sizeof(out->description), "%.100s: %.50s",
			base, out->iface);
	}
}

/*
 * decode_snmp_trap - parse a trap packet.
 *
 * Always fills `out` with something printable, whether or not the packet
 * made sense; the return value says whether the contents are trustworthy.
 */
bool decode_snmp_trap(const unsigned char *buf, size_t len, struct trap_content *out)
{
	struct ber_cursor msg, seq, pdu;
	unsigned char tag;
	const unsigned char *val;
	size_t vlen;

	if (out == NULL)
		return FALSE;

	memset(out, 0, sizeof(*out));
	out->version = -1;
	out->generic = -1;
	out->specific = 0;
	out->ifindex = -1;
	snprintf(out->severity, sizeof(out->severity), "warning");
	snprintf(out->category, sizeof(out->category), "trap");
	snprintf(out->name, sizeof(out->name), "undecoded");
	snprintf(out->description, sizeof(out->description),
		"Trap could not be decoded (malformed or unsupported packet)");

	if (buf == NULL || len == 0)
		return FALSE;

	snmp_ber_open(&msg, buf, len);
	if (!snmp_ber_next(&msg, &tag, &val, &vlen) || tag != BER_SEQUENCE)
		return FALSE;
	ber_enter(&seq, val, vlen);

	if (!snmp_ber_next(&seq, &tag, &val, &vlen) || tag != BER_INTEGER)
		return FALSE;
	out->version = (int)snmp_ber_int(val, vlen);

	if (out->version == 3) {
		/* v3 hides the PDU behind USM keys we were never given. Be
		   honest about it rather than reporting a decode failure. */
		snprintf(out->name, sizeof(out->name), "snmpv3Trap");
		snprintf(out->category, sizeof(out->category), "trap");
		snprintf(out->description, sizeof(out->description),
			"SNMPv3 trap received - sysmond does not hold the v3 keys to decode it");
		/* We cannot read it, but it is a real SNMP message and the
		   device meant to tell us something. Worth an alert. */
		out->alertable = TRUE;
		return FALSE;
	}
	if (out->version != 0 && out->version != 1)
		return FALSE;	/* not v1 or v2c */

	if (!snmp_ber_next(&seq, &tag, &val, &vlen) || tag != BER_OCTETSTR)
		return FALSE;
	ber_string_str(val, vlen, out->community, sizeof(out->community));

	if (!snmp_ber_next(&seq, &tag, &val, &vlen))
		return FALSE;
	ber_enter(&pdu, val, vlen);

	if (tag == PDU_TRAP_V1) {
		const unsigned char *v;
		size_t l;
		unsigned char t;

		/* enterprise */
		if (!snmp_ber_next(&pdu, &t, &v, &l) || t != BER_OID)
			return FALSE;
		snmp_ber_oid_str(v, l, out->enterprise, sizeof(out->enterprise));

		/* agent-addr: the device's own idea of its address, which
		   differs from the packet source when a proxy forwards. */
		if (!snmp_ber_next(&pdu, &t, &v, &l))
			return FALSE;
		if (t == BER_IPADDRESS && l == 4)
			snprintf(out->agent, sizeof(out->agent), "%u.%u.%u.%u",
				v[0], v[1], v[2], v[3]);

		if (!snmp_ber_next(&pdu, &t, &v, &l) || t != BER_INTEGER)
			return FALSE;
		out->generic = (int)snmp_ber_int(v, l);

		if (!snmp_ber_next(&pdu, &t, &v, &l) || t != BER_INTEGER)
			return FALSE;
		out->specific = (int)snmp_ber_int(v, l);

		if (!snmp_ber_next(&pdu, &t, &v, &l))
			return FALSE;
		if (t == BER_TIMETICKS)
			out->uptime = snmp_ber_uint(v, l);

		/* v1 has no snmpTrapOID; build the equivalent so the web UI
		   and the v2c path can be compared like for like. */
		if (out->generic == 6) {
			char suffix[24];
			snprintf(suffix, sizeof(suffix), ".0.%d", out->specific);
			/* Only build the composite OID if it fits whole; a
			   truncated OID is worse than none at all. */
			if (strlen(out->enterprise) + strlen(suffix) < sizeof(out->trap_oid)) {
				snprintf(out->trap_oid, sizeof(out->trap_oid), "%.160s%.24s",
					out->enterprise, suffix);
			} else {
				snprintf(out->trap_oid, sizeof(out->trap_oid), "%s",
					out->enterprise);
			}
		} else if (out->generic >= 0 && out->generic <= 5) {
			snprintf(out->trap_oid, sizeof(out->trap_oid),
				".1.3.6.1.6.3.1.1.5.%d", out->generic + 1);
		}
	} else if (tag == PDU_TRAP_V2 || tag == PDU_INFORM) {
		const unsigned char *v;
		size_t l;
		unsigned char t;
		int i;

		out->inform = (tag == PDU_INFORM) ? TRUE : FALSE;

		/* request-id, error-status, error-index */
		for (i = 0; i < 3; i++) {
			if (!snmp_ber_next(&pdu, &t, &v, &l) || t != BER_INTEGER)
				return FALSE;
		}
	} else {
		/* Something aimed at port 162 that is not a trap - a GET, a
		   response, a scanner. Not our business. */
		snprintf(out->name, sizeof(out->name), "non-trap");
		snprintf(out->description, sizeof(out->description),
			"SNMP PDU type 0x%02x on the trap port - not a trap", tag);
		return FALSE;
	}

	decode_varbinds(&pdu, out);
	classify_trap(out);
	out->decoded = TRUE;
	out->alertable = TRUE;
	return TRUE;
}

/*
 * Recent trap history.
 *
 * A fixed ring: traps are a firehose on a bad night, and a monitoring
 * daemon must not grow a queue it cannot bound. Newest overwrites oldest.
 */
static struct trap_record trap_ring[TRAP_HISTORY_MAX];
static int trap_ring_count = 0;		/* entries in use */
static int trap_ring_next = 0;		/* where the next one lands */
static unsigned long trap_ring_total = 0;	/* everything ever seen */

void trap_history_add(const char *source, time_t when, int bytes,
	struct trap_content *content, const char *matched,
	bool alert_enabled, bool alert_sent)
{
	struct trap_record *r = &trap_ring[trap_ring_next];

	memset(r, 0, sizeof(*r));
	r->seq = trap_ring_total + 1;	/* 1-based, monotonic for this run */
	snprintf(r->source, sizeof(r->source), "%s", source != NULL ? source : "");
	r->when = when;
	r->bytes = bytes;
	if (matched != NULL)
		snprintf(r->matched, sizeof(r->matched), "%s", matched);
	r->alert_enabled = alert_enabled;
	r->alert_sent = alert_sent;
	if (content != NULL)
		r->content = *content;

	trap_ring_next = (trap_ring_next + 1) % TRAP_HISTORY_MAX;
	if (trap_ring_count < TRAP_HISTORY_MAX)
		trap_ring_count++;
	trap_ring_total++;
}

int trap_history_count(void)
{
	return trap_ring_count;
}

unsigned long trap_history_total(void)
{
	return trap_ring_total;
}

/*
 * The sequence of the oldest trap still held. A client that asked for
 * "everything after N" and gets back an oldest of N+5 knows four traps
 * fell out of the ring before it managed to ask.
 */
unsigned long trap_history_oldest_seq(void)
{
	struct trap_record *oldest = trap_history_get(trap_ring_count - 1);

	return oldest != NULL ? oldest->seq : 0;
}

/*
 * Fetch by age: 0 is the most recent trap, 1 the one before it.
 */
struct trap_record *trap_history_get(int age)
{
	int idx;

	if (age < 0 || age >= trap_ring_count)
		return NULL;

	idx = trap_ring_next - 1 - age;
	while (idx < 0)
		idx += TRAP_HISTORY_MAX;

	return &trap_ring[idx];
}
