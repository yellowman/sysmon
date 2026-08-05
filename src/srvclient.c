/* $Id: srvclient.c,v 1.68 2014/07/09 16:38:46 jared Exp $ */
#include "config.h"

extern int snmp_debug;

bool in_client_poll = FALSE;

#ifdef HAVE_LIBWRAP
#ifdef HAVE_TCPD_H
int allow_severity = ALLOWSEVERITY;
int deny_severity = DENYSEVERITY;
#endif /* HAVE_TCPD_H */
#endif

void client_poll(void);

void send_stat_start(struct clientstatus client, struct all_elements_list *head, int obj)
{
	char buff[256];
	struct all_elements_list *here = NULL;

	if (head == NULL)
	{
		return; /* shouldn't happen, just doing sanity checking */
	}

	for (here = head; here!= NULL;here=here->next)
	{
		if (here->value->data->lastcheck != 0)
		{
	                if (obj == 1)
	                {
	                        snprintf(buff, 256, "%s", here->value->unique_name);
			} else {

			/* down in some fashion */
			snprintf(buff, 256, "%s:%d:%d:%d:%ld:%d:%lld",
			here->value->data->hostname, here->value->data->type,
			here->value->data->port, here->value->data->lastcheck,
			here->value->data->downct,
			here->value->data->contacted,
			(long long)here->value->data->deathtime);
			}

			/* write it out the socket */
			sendline(client.filedes, buff);
		}
	}
	return;
}

/* Send status for ALL hosts (both up and down) - used by STATAL command */
void send_stat_all(struct clientstatus client, struct all_elements_list *head, int obj)
{
	char buff[256];
	struct all_elements_list *here = NULL;

	if (head == NULL)
	{
		return; /* shouldn't happen, just doing sanity checking */
	}

	for (here = head; here!= NULL;here=here->next)
	{
		/* NOTE: No lastcheck filter - return ALL objects */
		if (obj == 1)
		{
			/* Return just unique_name (like STATO) */
			snprintf(buff, 256, "%s", here->value->unique_name);
		} else {
			/* Return detailed format (like STAT) */
			snprintf(buff, 256, "%s:%d:%d:%d:%ld:%ld:%lld",
			here->value->data->hostname, here->value->data->type,
			here->value->data->port, here->value->data->lastcheck,
			here->value->data->downct,
			here->value->data->upct,
			(long long)here->value->data->deathtime);
		}

		/* write it out the socket */
		sendline(client.filedes, buff);
	}
	return;
}

int	send_stat(struct clientstatus *client, char *buff)
{
	int retval;
	/* STATAL = return all objects (both up and down) */
	if (strncmp(buff, "STATAL", 6) == 0)
	{
		send_stat_all(*client, currenthead, 1); /* obj=1 means return unique_name only */
	}
	/* STATO = return only down objects, unique_name format */
	else if (strncmp(buff, "STATO", 5) == 0)
	{
		send_stat_start(*client, currenthead, 1);
	}
	/* STAT = return only down objects, detailed format */
	else {
		send_stat_start(*client, currenthead, 0);
	}
	if (paused)
	{
		retval = sendline(client->filedes, "333 Paused Currently");
	} else {
		retval = sendline(client->filedes, "333 Not currently Paused");
	}
	if (retval == -1)
	{
		print_err(0, "unable to send message to client");
		/*
		 * tls_disconnect(), not a bare -1: dead_client_cleanup() frees
		 * this struct, so a descriptor dropped here is a descriptor
		 * nothing can ever close. On the aggregator link that also
		 * strands the SSL*, which is tracked by descriptor number - and
		 * the next connect() is very likely handed that same number.
		 * One leak per flap, against a 1024 limit.
		 */
		tls_disconnect(client->filedes);
		client->filedes = -1;
		return -1;
	}

	return 0;
}

/*
 * CONF [since]
 *
 * Every object's status XML. With a sequence number, only the objects
 * whose change_seq is above it - which on a quiet network is none of
 * them, and the whole exchange is two lines.
 *
 * The terminator carries the daemon's current sequence and how many
 * objects were sent: "333 <seq> <sent>". A client remembers <seq> and
 * passes it back next time; if it ever comes back lower than what the
 * client holds, the daemon restarted and the client resyncs from zero.
 */
int	send_conf(struct clientstatus *client, unsigned long since)
{

	struct all_elements_list *here;
	char buffer[TEMPBUF_SIZE];
	unsigned long sent = 0;
	unsigned long total = 0;

	here = currenthead;

	if (client->authlvl  <= 0)
	{
		sendline(client->filedes, "444 Permission Denied");
		return 0;
	}

	/* send xml */
	while (here != NULL)
	{
		if (here->value != NULL && here->value->data != NULL &&
		    here->value->data->change_seq > since)
		{
			send_object_xml(client->filedes, NULL, here->value);
			sent++;
		}
		here=here->next;
	}

	/*
	 * The terminator carries the total object count as well.
	 *
	 * An incremental CONF can say what changed but has no way to say what
	 * is gone: a deleted object simply stops being sent, and a client
	 * merging into a cache would keep it forever. The count is what lets
	 * the far end notice - if it holds a different number than the daemon
	 * has, its cache is wrong and it asks for everything.
	 */
	{
		struct all_elements_list *walk;

		for (walk = currenthead; walk != NULL; walk = walk->next)
			total++;
	}

	/* done printing config */
	snprintf(buffer, sizeof(buffer), "333 %lu %lu %lu",
		glob_change_seq, sent, total);
	if (sendline(client->filedes, buffer) == -1)
	{
		print_err(0, "unable to send message to client");
		return -1;
	}
	return 1;
}

/*
 * conditionally send line to either FILE or file(can be socket)
 * Returns: 0 on success, -1 on error
 */
int do_send_xml(int fd, FILE *fh, char *buff)
{
        if (fh == NULL)
	{
		int ret = sendline(fd, buff);
		if (ret == -1)
		{
			if (debug)
				print_err(1, "do_send_xml: sendline failed for fd %d", fd);
			return -1;
		}
		return 0;
	} else {
		int ret = fprintf(fh, "%s\n", buff);
		if (ret < 0)
		{
			if (debug)
				print_err(1, "do_send_xml: fprintf failed");
			return -1;
		}
		return 0;
	}
}

static char *xml_escape(const char *in, char *out, size_t outlen);

/*
 * send_object_xml - send an object described as obj
 * to either FILE or file(can be socket).  do FILE = null
 * if you want it to go to the socket.
 */
void send_object_xml(int fd, FILE *fh, struct graph_elements *obj)
{
	char buffer[TEMPBUF_SIZE];

	/*
	 * Every text field goes through xml_escape() on the way out. An
	 * object's URL, notes, message and contact are operator-written or
	 * come back off the wire, and one bare "&" - the kind an ordinary
	 * query string has - makes a document the reader rejects. sysmon-web
	 * then skips that object, so the host simply vanishes from the
	 * dashboard with nothing said. The trap path has escaped for this
	 * reason from the start; objects were missed.
	 *
	 * esc is sized so an escaped value plus the longest tag name, twice,
	 * still fits in buffer. That matters: truncating inside an entity
	 * would produce exactly the broken document being avoided here.
	 * xml_escape() itself stops on an entity boundary.
	 */
	char esc[TEMPBUF_SIZE - 128];

	/* Macro to check send errors and abort XML generation if write fails */
	#define SEND_OR_ABORT(fd, fh, buf) \
		if (do_send_xml(fd, fh, buf) == -1) { \
			if (debug) print_err(1, "send_object_xml: aborting due to send error"); \
			return; \
		}

	snprintf(buffer, sizeof(buffer), "<%s>", XML_OBJECT_STATUS);
	SEND_OR_ABORT(fd, fh, buffer);

	snprintf(buffer, sizeof(buffer), "<%s>%lu</%s>", XML_CHANGE_SEQ,
		obj->data->change_seq, XML_CHANGE_SEQ);
	SEND_OR_ABORT(fd, fh, buffer);

	snprintf(buffer, sizeof(buffer), "<%s>%s</%s>", XML_OBJECT,
			xml_escape(obj->unique_name, esc, sizeof(esc)), XML_OBJECT);
	SEND_OR_ABORT(fd, fh, buffer);

	snprintf(buffer, sizeof(buffer), "<%s>%s</%s>", XML_HOSTNAME,
			xml_escape(obj->data->hostname, esc, sizeof(esc)), XML_HOSTNAME);
	SEND_OR_ABORT(fd, fh, buffer);

	snprintf(buffer, sizeof(buffer), "<%s>%d</%s>", XML_OBJECT_PORT, obj->data->port, XML_OBJECT_PORT);
	SEND_OR_ABORT(fd, fh, buffer);

	snprintf(buffer, sizeof(buffer), "<%s>%s</%s>", XML_OBJECT_TYPE,
			xml_escape(type_to_name(obj->data->type), esc, sizeof(esc)), XML_OBJECT_TYPE);
	SEND_OR_ABORT(fd, fh, buffer);

	snprintf(buffer, sizeof(buffer), "<%s>%s</%s>", XML_OBJECT_MESSAGE,
			xml_escape(obj->data->message, esc, sizeof(esc)), XML_OBJECT_MESSAGE);
	SEND_OR_ABORT(fd, fh, buffer);

	if (obj->data->contact != NULL)
	{
		snprintf(buffer, sizeof(buffer), "<%s>%s</%s>", XML_OBJECT_CONTACT,
			xml_escape(obj->data->contact, esc, sizeof(esc)), XML_OBJECT_CONTACT);
		SEND_OR_ABORT(fd, fh, buffer);
	}

	/* XML_OBJ_GROUP */
        if (obj->data->group != NULL)
        {
                snprintf(buffer, sizeof(buffer), "<%s>%s</%s>", XML_OBJECT_GROUP,
			xml_escape(obj->data->group, esc, sizeof(esc)), XML_OBJECT_GROUP);
                SEND_OR_ABORT(fd, fh, buffer);
        }

        /* XML_OBJ_NOTES */
        if (obj->data->notes != NULL)
        {
                snprintf(buffer, sizeof(buffer), "<%s>%s</%s>", XML_OBJECT_NOTES,
			xml_escape(obj->data->notes, esc, sizeof(esc)), XML_OBJECT_NOTES);
                SEND_OR_ABORT(fd, fh, buffer);
        }

	if (obj->data->type == SYSM_TYPE_SNMP)
	{
		if (obj->data->snmp_community != NULL)
		{
			snprintf(buffer, sizeof(buffer), "<%s>%s</%s>", XML_SNMP_COMMUNITY,
			xml_escape(obj->data->snmp_community, esc, sizeof(esc)), XML_SNMP_COMMUNITY);
			SEND_OR_ABORT(fd, fh, buffer);
		}
		snprintf(buffer, sizeof(buffer), "<%s>%s</%s>", XML_SNMP_VERSION,
			xml_escape(obj->data->snmp_version == SNMP_VERSION_1 ? "1" : "2c", esc, sizeof(esc)), XML_SNMP_VERSION);
		SEND_OR_ABORT(fd, fh, buffer);
		if (obj->data->snmp_oid != NULL)
		{
			snprintf(buffer, sizeof(buffer), "<%s>%s</%s>", XML_SNMP_OID,
			xml_escape(obj->data->snmp_oid, esc, sizeof(esc)), XML_SNMP_OID);
			SEND_OR_ABORT(fd, fh, buffer);
		}
		snprintf(buffer, sizeof(buffer), "<%s>%s</%s>", XML_SNMP_TYPE,
			xml_escape(snmp_type_to_name(obj->data->snmp_test_type), esc, sizeof(esc)), XML_SNMP_TYPE);
		SEND_OR_ABORT(fd, fh, buffer);

		snprintf(buffer, sizeof(buffer), "<%s>%ld</%s>", XML_SNMP_LOW, obj->data->snmp_low, XML_SNMP_LOW);
		SEND_OR_ABORT(fd, fh, buffer);

		snprintf(buffer, sizeof(buffer), "<%s>%ld</%s>", XML_SNMP_HIGH, obj->data->snmp_high, XML_SNMP_HIGH);
		SEND_OR_ABORT(fd, fh, buffer);

		snprintf(buffer, sizeof(buffer), "<%s>%ld</%s>", XML_SNMP_EXACT, obj->data->snmp_exact, XML_SNMP_EXACT);
		SEND_OR_ABORT(fd, fh, buffer);

		snprintf(buffer, sizeof(buffer), "<%s>%ld</%s>", XML_SNMP_SysUpTime, obj->data->system_uptime, XML_SNMP_SysUpTime);
		SEND_OR_ABORT(fd, fh, buffer);

		snprintf(buffer, sizeof(buffer), "<%s>%d</%s>", XML_SNMP_OCTETS, obj->data->snmp_octets, XML_SNMP_OCTETS);
		SEND_OR_ABORT(fd, fh, buffer);

		snprintf(buffer, sizeof(buffer), "<%s>%ld</%s>", XML_SNMP_RATE, obj->data->snmp_rate, XML_SNMP_RATE);
		SEND_OR_ABORT(fd, fh, buffer);

		snprintf(buffer, sizeof(buffer), "<%s>%lld</%s>", XML_SNMP_LASTRESP, (long long)obj->data->last_snmp_resptime, XML_SNMP_LASTRESP);
		SEND_OR_ABORT(fd, fh, buffer);
	}

	snprintf(buffer, sizeof(buffer), "<%s>%d</%s>", XML_OBJECT_STATE, obj->data->lastcheck, XML_OBJECT_STATE);
	SEND_OR_ABORT(fd, fh, buffer);

	if (obj->data->username != NULL)
	{
		snprintf(buffer, sizeof(buffer), "<%s>%s</%s>", XML_AUTH_USER,
			xml_escape(obj->data->username, esc, sizeof(esc)), XML_AUTH_USER);
		SEND_OR_ABORT(fd, fh, buffer);
	}

	if (obj->data->password != NULL)
	{
		snprintf(buffer, sizeof(buffer), "<%s>%s</%s>", XML_AUTH_PASSWD,
			xml_escape(obj->data->password, esc, sizeof(esc)), XML_AUTH_PASSWD);
		SEND_OR_ABORT(fd, fh, buffer);
	}

	if (obj->data->hdr != NULL)
	{
		snprintf(buffer, sizeof(buffer), "<%s>%s</%s>", XML_HEADER,
			xml_escape(obj->data->hdr, esc, sizeof(esc)), XML_HEADER);
		SEND_OR_ABORT(fd, fh, buffer);
	}

	if (obj->data->hdrval != NULL)
	{
		snprintf(buffer, sizeof(buffer), "<%s>%s</%s>", XML_HEADER_VAL,
			xml_escape(obj->data->hdrval, esc, sizeof(esc)), XML_HEADER_VAL);
		SEND_OR_ABORT(fd, fh, buffer);
	}
	
	if (obj->data->secret != NULL)
	{
		snprintf(buffer, sizeof(buffer), "<%s>%s</%s>", XML_RADIUS_SECRET,
			xml_escape(obj->data->secret, esc, sizeof(esc)), XML_RADIUS_SECRET);
		SEND_OR_ABORT(fd, fh, buffer);
	}

	if (obj->data->lastmsgid != NULL)
	{
		snprintf(buffer, sizeof(buffer), "<%s>%s</%s>", XML_MESSAGE_ID,
			xml_escape(obj->data->lastmsgid, esc, sizeof(esc)), XML_MESSAGE_ID);
		SEND_OR_ABORT(fd, fh, buffer);
	}

	if (obj->data->unique_id != NULL)
	{
		snprintf(buffer, sizeof(buffer), "<%s>%s</%s>", XML_UNIQUE_ID,
			xml_escape(obj->data->unique_id, esc, sizeof(esc)), XML_UNIQUE_ID);
		SEND_OR_ABORT(fd, fh, buffer);
	}

	if (obj->data->url != NULL)
	{
		snprintf(buffer, sizeof(buffer), "<%s>%s</%s>", XML_OBJ_URL,
			xml_escape(obj->data->url, esc, sizeof(esc)), XML_OBJ_URL);
		SEND_OR_ABORT(fd, fh, buffer);
	}

	if (obj->data->url_text != NULL)
	{
		/* BUG FIX: Use url_text instead of url */
		snprintf(buffer, sizeof(buffer), "<%s>%s</%s>", XML_OBJ_URL_TEXT,
			xml_escape(obj->data->url_text, esc, sizeof(esc)), XML_OBJ_URL_TEXT);
		SEND_OR_ABORT(fd, fh, buffer);
	}
	
	if (obj->data->command != NULL)
	{
		snprintf(buffer, sizeof(buffer), "<%s>%s</%s>", XML_OBJ_EXEC,
			xml_escape(obj->data->command, esc, sizeof(esc)), XML_OBJ_EXEC);
		SEND_OR_ABORT(fd, fh, buffer);
	}

	snprintf(buffer, sizeof(buffer), "<%s>%ld</%s>", XML_TOT_CHECKED, obj->data->totalchecked, XML_TOT_CHECKED);
	SEND_OR_ABORT(fd, fh, buffer);

	snprintf(buffer, sizeof(buffer), "<%s>%ld</%s>", XML_TOT_DOWN, obj->data->totaldown, XML_TOT_DOWN);
	SEND_OR_ABORT(fd, fh, buffer);

	snprintf(buffer, sizeof(buffer), "<%s>%ld</%s>", XML_DOWN_CT, obj->data->downct, XML_DOWN_CT);
	SEND_OR_ABORT(fd, fh, buffer);

	snprintf(buffer, sizeof(buffer), "<%s>%ld</%s>", XML_UP_CT, obj->data->upct, XML_UP_CT);
	SEND_OR_ABORT(fd, fh, buffer);

	snprintf(buffer, sizeof(buffer), "<%s>%ld</%s>", XML_MAX_DOWN, obj->data->max_down, XML_MAX_DOWN);
	SEND_OR_ABORT(fd, fh, buffer);

	snprintf(buffer, sizeof(buffer), "<%s>%ld</%s>", XML_QUEUE_INT, obj->data->queuetime, XML_QUEUE_INT);
	SEND_OR_ABORT(fd, fh, buffer);

	snprintf(buffer, sizeof(buffer), "<%s>%d</%s>", XML_SEND_PING, obj->data->send_pings, XML_SEND_PING);
	SEND_OR_ABORT(fd, fh, buffer);
	
	snprintf(buffer, sizeof(buffer), "<%s>%d</%s>", XML_MIN_PING, obj->data->min_pings, XML_MIN_PING);
	SEND_OR_ABORT(fd, fh, buffer);

	snprintf(buffer, sizeof(buffer), "<%s>%d</%s>", XML_OBJ_REVERSED, obj->data->reverse, XML_OBJ_REVERSED);
	SEND_OR_ABORT(fd, fh, buffer);

	snprintf(buffer, sizeof(buffer), "<%s>%d</%s>", XML_OBJ_CONTACTED, obj->data->contacted, XML_OBJ_CONTACTED);
	SEND_OR_ABORT(fd, fh, buffer);

	snprintf(buffer, sizeof(buffer), "<%s>%lld</%s>", XML_OBJ_CONTACTEDAT, (long long)obj->data->lastcontacted, XML_OBJ_CONTACTEDAT);
	SEND_OR_ABORT(fd, fh, buffer);

	snprintf(buffer, sizeof(buffer), "<%s>%d</%s>", XML_CONTACT_UP, obj->data->contact_when, XML_CONTACT_UP);
	SEND_OR_ABORT(fd, fh, buffer);

	snprintf(buffer, sizeof(buffer), "<%s>%d</%s>", XML_QUEUED, obj->data->queued, XML_QUEUED);
	SEND_OR_ABORT(fd, fh, buffer);

	snprintf(buffer, sizeof(buffer), "<%s>%lld</%s>", XML_LASTCHECK, (long long)obj->data->lchecktime, XML_LASTCHECK);
	SEND_OR_ABORT(fd, fh, buffer);

	snprintf(buffer, sizeof(buffer), "<%s>%lld</%s>", XML_CHECK_START, (long long)obj->data->check_start, XML_CHECK_START);
	SEND_OR_ABORT(fd, fh, buffer);

	snprintf(buffer, sizeof(buffer), "<%s>%lld</%s>", XML_OUTAGE_TIME, (long long)obj->data->deathtime, XML_OUTAGE_TIME);
	SEND_OR_ABORT(fd, fh, buffer);

	snprintf(buffer, sizeof(buffer), "<%s>%lld</%s>", XML_LAST_TIME_UP, (long long)obj->data->last_up, XML_LAST_TIME_UP);
	SEND_OR_ABORT(fd, fh, buffer);

	/* Packet loss tolerance (max packets that can be lost) */
	if (obj->data->pktloss_tolerance > 0) {
		snprintf(buffer, sizeof(buffer), "<%s>%u</%s>", XML_PACKET_LOSS_THRESHOLD,
			obj->data->pktloss_tolerance, XML_PACKET_LOSS_THRESHOLD);
		SEND_OR_ABORT(fd, fh, buffer);
	}

	/* RTT threshold */
	if (obj->data->rtt_threshold > 0) {
		snprintf(buffer, sizeof(buffer), "<%s>%u</%s>", XML_RTT_THRESHOLD,
			obj->data->rtt_threshold, XML_RTT_THRESHOLD);
		SEND_OR_ABORT(fd, fh, buffer);
	}

	/* Jitter threshold */
	if (obj->data->jitter_threshold > 0) {
		snprintf(buffer, sizeof(buffer), "<%s>%u</%s>", XML_JITTER_THRESHOLD,
			obj->data->jitter_threshold, XML_JITTER_THRESHOLD);
		SEND_OR_ABORT(fd, fh, buffer);
	}

	/* Wakeup retries (max times to retry waking stale check) */
	if (obj->data->max_wakeup_retries > 0) {
		snprintf(buffer, sizeof(buffer), "<%s>%u</%s>", XML_WAKEUP_RETRIES,
			obj->data->max_wakeup_retries, XML_WAKEUP_RETRIES);
		SEND_OR_ABORT(fd, fh, buffer);
	}

	/* Trap alert configuration */
	if (obj->data->trap_alert) {
		snprintf(buffer, sizeof(buffer), "<%s>%d</%s>", XML_TRAP_ALERT,
			1, XML_TRAP_ALERT);
		SEND_OR_ABORT(fd, fh, buffer);
	}

	/* ===== PHASE 1: Extended Configuration Fields ===== */

	/* SNMP Extended Configuration */
	if (obj->data->type == SYSM_TYPE_SNMP) {
		if (obj->data->snmp_oid_sec != NULL) {
			snprintf(buffer, sizeof(buffer), "<%s>%s</%s>", XML_SNMP_OID_SEC,
			xml_escape(obj->data->snmp_oid_sec, esc, sizeof(esc)), XML_SNMP_OID_SEC);
			SEND_OR_ABORT(fd, fh, buffer);
		}
		if (obj->data->snmp_up_msg != NULL) {
			snprintf(buffer, sizeof(buffer), "<%s>%s</%s>", XML_SNMP_UP_MSG,
			xml_escape(obj->data->snmp_up_msg, esc, sizeof(esc)), XML_SNMP_UP_MSG);
			SEND_OR_ABORT(fd, fh, buffer);
		}
		if (obj->data->snmp_down_msg != NULL) {
			snprintf(buffer, sizeof(buffer), "<%s>%s</%s>", XML_SNMP_DOWN_MSG,
			xml_escape(obj->data->snmp_down_msg, esc, sizeof(esc)), XML_SNMP_DOWN_MSG);
			SEND_OR_ABORT(fd, fh, buffer);
		}
	}

	/* DNS Configuration */
	if (obj->data->type == SYSM_TYPE_DNS) {
		if (obj->data->dns_query != NULL) {
			snprintf(buffer, sizeof(buffer), "<%s>%s</%s>", XML_DNS_QUERY,
			xml_escape(obj->data->dns_query, esc, sizeof(esc)), XML_DNS_QUERY);
			SEND_OR_ABORT(fd, fh, buffer);

			snprintf(buffer, sizeof(buffer), "<%s>%d</%s>",
				XML_DNS_REQ_AA, obj->data->dns_aa, XML_DNS_REQ_AA);
			SEND_OR_ABORT(fd, fh, buffer);

			snprintf(buffer, sizeof(buffer), "<%s>%d</%s>",
				XML_DNS_RECURSION, obj->data->dns_recursion, XML_DNS_RECURSION);
			SEND_OR_ABORT(fd, fh, buffer);
		}
	}

	/* Per-Object Custom Page Message */
	if (obj->data->pmesg != NULL) {
		snprintf(buffer, sizeof(buffer), "<%s>%s</%s>", XML_PAGE_MESSAGE,
			xml_escape(obj->data->pmesg, esc, sizeof(esc)), XML_PAGE_MESSAGE);
		SEND_OR_ABORT(fd, fh, buffer);
	}

	/* Packet Loss Extended Configuration */
	if (obj->data->pktloss_history_hours > 0) {
		snprintf(buffer, sizeof(buffer), "<%s>%u</%s>",
			XML_PKTLOSS_HIST_HRS, obj->data->pktloss_history_hours,
			XML_PKTLOSS_HIST_HRS);
		SEND_OR_ABORT(fd, fh, buffer);
	}

	if (obj->data->pktloss_last_check > 0) {
		snprintf(buffer, sizeof(buffer), "<%s>%lld</%s>",
			XML_PKTLOSS_LAST_CHK, (long long)obj->data->pktloss_last_check,
			XML_PKTLOSS_LAST_CHK);
		SEND_OR_ABORT(fd, fh, buffer);
	}

	/* RTT Samples Configuration */
	if (obj->data->rtt_samples > 0) {
		snprintf(buffer, sizeof(buffer), "<%s>%u</%s>",
			XML_RTT_SAMPLES, obj->data->rtt_samples, XML_RTT_SAMPLES);
		SEND_OR_ABORT(fd, fh, buffer);
	}

	if (obj->data->rtt_interval > 0) {
		snprintf(buffer, sizeof(buffer), "<%s>%u</%s>",
			XML_RTT_INTERVAL, obj->data->rtt_interval, XML_RTT_INTERVAL);
		SEND_OR_ABORT(fd, fh, buffer);
	}

	/* Next Scheduled Queue Time */
	if (obj->data->next_queuetime > 0) {
		snprintf(buffer, sizeof(buffer), "<%s>%lld</%s>",
			XML_NEXT_QUEUE_TIME, (long long)obj->data->next_queuetime, XML_NEXT_QUEUE_TIME);
		SEND_OR_ABORT(fd, fh, buffer);
	}

	/* Debug & Diagnostic State */
	snprintf(buffer, sizeof(buffer), "<%s>%d</%s>",
		XML_TRACE_ENABLED, obj->data->trace, XML_TRACE_ENABLED);
	SEND_OR_ABORT(fd, fh, buffer);

	snprintf(buffer, sizeof(buffer), "<%s>%d</%s>",
		XML_ACKED, obj->data->acked, XML_ACKED);
	SEND_OR_ABORT(fd, fh, buffer);

	/* ===== PHASE 2: Runtime Check State ===== */

	/* Find this object in the queue to get runtime state */
	{
		extern struct monitorent *queuehead;
		struct monitorent *qent = queuehead;
		struct monitorent *found_qent = NULL;

		while (qent != NULL) {
			if (qent->checkent == obj->data) {
				found_qent = qent;
				break;
			}
			qent = qent->next;
		}

		if (found_qent != NULL) {
			/* Object is currently in queue - add runtime state */

			snprintf(buffer, sizeof(buffer), "<%s>%ld.%06ld</%s>",
				XML_CHECK_QUEUED_AT,
				(long)found_qent->queueat.tv_sec,
				(long)found_qent->queueat.tv_usec,
				XML_CHECK_QUEUED_AT);
			SEND_OR_ABORT(fd, fh, buffer);

			snprintf(buffer, sizeof(buffer), "<%s>%ld.%06ld</%s>",
				XML_CHECK_LAST_SERV,
				(long)found_qent->lastserv.tv_sec,
				(long)found_qent->lastserv.tv_usec,
				XML_CHECK_LAST_SERV);
			SEND_OR_ABORT(fd, fh, buffer);

			snprintf(buffer, sizeof(buffer), "<%s>%d</%s>",
				XML_CHECK_FD, found_qent->filedes, XML_CHECK_FD);
			SEND_OR_ABORT(fd, fh, buffer);

			snprintf(buffer, sizeof(buffer), "<%s>%d</%s>",
				XML_CHECK_STARTED, found_qent->started, XML_CHECK_STARTED);
			SEND_OR_ABORT(fd, fh, buffer);

			if (found_qent->retval != -1) {
				snprintf(buffer, sizeof(buffer), "<%s>%d</%s>",
					XML_CHECK_RETVAL, found_qent->retval, XML_CHECK_RETVAL);
				SEND_OR_ABORT(fd, fh, buffer);
			}

			if (found_qent->wakeup_count > 0) {
				snprintf(buffer, sizeof(buffer), "<%s>%u</%s>",
					XML_CHECK_WAKEUP_CNT, found_qent->wakeup_count,
					XML_CHECK_WAKEUP_CNT);
				SEND_OR_ABORT(fd, fh, buffer);

				snprintf(buffer, sizeof(buffer), "<%s>%lld</%s>",
					XML_CHECK_WAKEUP_TIME, (long long)found_qent->last_wakeup_time,
					XML_CHECK_WAKEUP_TIME);
				SEND_OR_ABORT(fd, fh, buffer);
			}

			/* ===== PHASE 3: Packet Loss Historical Data ===== */

			/* Add packet loss history for PKTLOSS checks */
			if (obj->data->type == SYSM_TYPE_PKTLOSS && found_qent->monitordata != NULL) {
				struct pktloss_data *pld = (struct pktloss_data *)found_qent->monitordata;

				/* Running totals */
				snprintf(buffer, sizeof(buffer), "<%s>%llu</%s>",
					XML_PKTLOSS_TOTAL_SENT, pld->total_sent, XML_PKTLOSS_TOTAL_SENT);
				SEND_OR_ABORT(fd, fh, buffer);

				snprintf(buffer, sizeof(buffer), "<%s>%llu</%s>",
					XML_PKTLOSS_TOTAL_RECV, pld->total_received, XML_PKTLOSS_TOTAL_RECV);
				SEND_OR_ABORT(fd, fh, buffer);

				snprintf(buffer, sizeof(buffer), "<%s>%llu</%s>",
					XML_PKTLOSS_TOTAL_LOST, pld->total_lost, XML_PKTLOSS_TOTAL_LOST);
				SEND_OR_ABORT(fd, fh, buffer);

				snprintf(buffer, sizeof(buffer), "<%s>%u</%s>",
					XML_PKTLOSS_HIST_SAMP, pld->history_count, XML_PKTLOSS_HIST_SAMP);
				SEND_OR_ABORT(fd, fh, buffer);

				/* History array - output last 24 hours of samples */
				if (pld->history_count > 0) {
					unsigned int i;
					unsigned int samples_to_output = pld->history_count;
					if (samples_to_output > 1440) samples_to_output = 1440; /* Max 24h @ 1min */

					snprintf(buffer, sizeof(buffer), "<%s>", XML_PKTLOSS_HISTORY);
					SEND_OR_ABORT(fd, fh, buffer);

					for (i = 0; i < samples_to_output; i++) {
						/* Calculate actual index in circular buffer */
						unsigned int idx = (pld->history_head + PKTLOSS_HISTORY_SIZE -
						                   samples_to_output + i) % PKTLOSS_HISTORY_SIZE;

						struct pktloss_sample *sample = &pld->history[idx];

						snprintf(buffer, sizeof(buffer),
							"<Sample timestamp=\"%lld\" sent=\"%u\" received=\"%u\" lost=\"%u\"/>",
							(long long)sample->timestamp, sample->sent, sample->received, sample->lost);
						SEND_OR_ABORT(fd, fh, buffer);
					}

					snprintf(buffer, sizeof(buffer), "</%s>", XML_PKTLOSS_HISTORY);
					SEND_OR_ABORT(fd, fh, buffer);
				}
			}
		}
	}

	snprintf(buffer, sizeof(buffer), "</%s>", XML_OBJECT_STATUS);
	SEND_OR_ABORT(fd, fh, buffer);

	#undef SEND_OR_ABORT
}

/*
 *
 */

void srv_client_do_trace(struct clientstatus *client, char *buff)
{
        char objname[OBJECT_NAME_SIZE];
        struct graph_elements *found_obj = NULL;

        strncpy(objname, buff+6, OBJECT_NAME_SIZE-1);
        objname[OBJECT_NAME_SIZE-1] = '\0';
        if (debug)
                print_err(1, "will search for object :%s:", objname);

        found_obj = find_object_by_name(objname);
        if (found_obj == NULL)
        {
                sendline(client->filedes, "403 object not found");
                return;
        } else {
		if (found_obj->data->trace == FALSE)
		{
			found_obj->data->trace = TRUE;
			sendline(client->filedes, "333 tracing enabled");
		} else {
			found_obj->data->trace = FALSE;
			sendline(client->filedes, "333 tracing disabled");
		}
	}
        return;

}

/*
 * SHOWOBJ <objectname>
 * Send object status in XML format
 */
void srv_client_do_showobject(struct clientstatus *client, char *buff)
{
	char objname[OBJECT_NAME_SIZE];
	struct graph_elements *found_obj = NULL;

	strncpy(objname, buff+8, OBJECT_NAME_SIZE-1);
	objname[OBJECT_NAME_SIZE-1] = '\0';
	if (debug)
		print_err(1, "will search for object :%s:", objname);
	if (!client->xml)
	{
		sendline(client->filedes, "403 do mode xml first");
		return;
	}

	found_obj = find_object_by_name(objname);
	if (found_obj == NULL)
	{
		sendline(client->filedes, "403 object not found");
		return;
	} else {
		send_object_xml(client->filedes, NULL, found_obj);
	}
	return;
}

/*
 * Acklowledge an object status
 */
void do_ack(struct clientstatus *client, char *buff)
{
        char objname[OBJECT_NAME_SIZE];
        struct graph_elements *found_obj = NULL;

        if (client->authlvl  <= 0)
        {
                sendline(client->filedes, "444 Permission Denied");
                return; /* SECURITY: Must return after permission denied */
        }

        strncpy(objname, buff+4, OBJECT_NAME_SIZE-1);
        objname[OBJECT_NAME_SIZE-1] = '\0';
        if (debug)
                print_err(1, "will search for object :%s:", objname);
        if (!client->xml)
        {
                sendline(client->filedes, "403 do mode xml first");
                return;
        }

        found_obj = find_object_by_name(objname);
        if (found_obj == NULL)
        {
                sendline(client->filedes, "403 object not found");
                return;
        } else {
                found_obj->data->acked = TRUE;
                object_changed(found_obj->data);
		sendline(client->filedes, "333 object updated");
        }
        return;
}

/*
 * UPD <objectname> <string>
 * like ACK but read a second line that includes a note
 */
int     do_upd(struct clientstatus *client, char *buff)
{

        char objname[128];
	char *ptr = NULL;
        struct graph_elements *found_obj = NULL;
	int sc = 0;
	int x;

        if (client->authlvl  <= 0)
        {
                sendline(client->filedes, "444 Permission Denied");
                return 0;
        }

        strncpy(objname, buff+4, 127);
        objname[127] = '\0';
	ptr = index(objname, ' ');
	if (ptr != NULL)
		*ptr = 0;

	if (debug)
		print_err(1, "do_upd/will search for object :%s:", objname);

	found_obj = find_object_by_name(objname);
	if (found_obj == NULL)
	{
		sendline(client->filedes, "403 object not found");
		return 1;
	} else {
		for (x = 0; x < strlen(buff); x++)
		{
			if (buff[x] == ' ')
				sc++;
			if (sc == 2)
				break;
		}
		if (sc == 2)
		{
		if (found_obj->data->notes != NULL)
		{
			FREE(found_obj->data->notes);
		}
		found_obj->data->notes = strdup(buff+x+1);
		object_changed(found_obj->data);
		sendline(client->filedes, "333 object updated");
		} else {
			sendline(client->filedes, "403 update error");
		}

	}
	return 0;
}


/*
 * MODE xml
 *
 * Change output mode into XML formatted text for easy parsing
 * by CGI or other programs
 */

void srv_client_do_mode(struct clientstatus *client, char *buff)
{
	if (strcmp(buff+5, "xml") == 0)
	{
		client->xml = TRUE;
		sendline(client->filedes, "333 xml enabled");
		return;
	} else if (strcmp(buff+5, "outagelog") == 0) {
		if (!client->outage_log)
		{
			client->outage_log = TRUE;
			sendline(client->filedes, "333 outagelog enabled");
		} else {
			client->outage_log = FALSE;
			sendline(client->filedes, "333 outagelog disabled");
		}
		return;
	} else {
		sendline(client->filedes, "444 unknown MODE subcommand");
	}
}

/*
 * AUTH xxx
 *
 * compares xxx against authkey to determine if they should be able
 * to authenticate and perform some functions.
 */ 
int	do_auth(struct clientstatus *client, char *buff)
{
	if (authkey != NULL)
	{
		if (strcmp(authkey, buff+5) == 0)
		{
			client->authlvl=2;
			sendline(client->filedes, "333 Good Authentication");
			return 1;
		}
	}
        if (sendline(client->filedes, "444") == -1)
        {
                print_err(0, "unable to send message to client");
                return -1;
        }

        return 0;
}

void do_client_http(struct clientstatus *client, char *request)
{
	char *url1;
	url1 = (char *)index(request, ' ');
	if (url1 == NULL)
	{
		print_err(0, "malformed GET request from a.b.c.d");
		return;
	}
	print_err(1, "do_client_http: url = %s", url1+1);
}

/*
 * Escape text for XML. Everything in a trap record came off the wire from
 * whoever felt like sending a UDP packet to port 162, so none of it may be
 * pasted into a document unescaped. Truncates rather than overflowing.
 */
static char *xml_escape(const char *in, char *out, size_t outlen)
{
	size_t used = 0;
	const char *rep;
	size_t rlen;

	if (outlen == 0)
		return out;
	out[0] = '\0';
	if (in == NULL)
		return out;

	for (; *in != '\0'; in++)
	{
		switch (*in)
		{
			case '&':  rep = "&amp;";  break;
			case '<':  rep = "&lt;";   break;
			case '>':  rep = "&gt;";   break;
			case '"':  rep = "&quot;"; break;
			case '\'': rep = "&apos;"; break;
			default:   rep = NULL;     break;
		}

		if (rep != NULL)
		{
			rlen = strlen(rep);
			if (used + rlen >= outlen)
				break;
			memcpy(out + used, rep, rlen);
			used += rlen;
		} else {
			/* Control characters have no business in XML. */
			if ((unsigned char)*in < 0x20)
				continue;
			if (used + 1 >= outlen)
				break;
			out[used++] = *in;
		}
	}
	out[used] = '\0';
	return out;
}

/*
 * TRAPS [since]
 *
 * Hand back the recent SNMP traps sysmond has caught, decoded. With a
 * sequence number, only the traps newer than it - so a client polling
 * every second normally transfers nothing at all, and neither side
 * spends anything re-sending or re-parsing what the caller already has.
 *
 * The terminator is "333 <current> <oldest-held> <sent>": the client
 * remembers <current>, and compares <oldest-held> against what it asked
 * for to know whether the ring overwrote traps it never saw. In XML mode
 * this is the full record - identity, severity, the interface it named and
 * every varbind - which is what the web UI renders. In plain mode it is one
 * summary line per trap for a human on a telnet session.
 */
void send_traps(struct clientstatus *client, unsigned long since)
{
	char buffer[LARGE_TEMPBUF_SIZE];
	char esc[TRAP_OID_LEN * 6 + 8];
	struct trap_record *r;
	int i, v;
	unsigned long sent = 0;

	/* tls_disconnect() before dropping the descriptor: see send_stat(). */
	#define TRAP_SEND(buf) \
		if (sendline(client->filedes, buf) == -1) { \
			tls_disconnect(client->filedes); \
			client->filedes = -1; \
			return; \
		}

	if (!client->xml)
	{
		for (i = 0; (r = trap_history_get(i)) != NULL; i++)
		{
			if (r->seq <= since)
				break;	/* newest first: the rest are older still */
			snprintf(buffer, sizeof(buffer), "%ld:%s:%s:%s:%s:%s",
				(long)r->when, r->source, r->content.name,
				r->content.severity,
				r->matched[0] != '\0' ? r->matched : "-",
				r->content.description);
			TRAP_SEND(buffer);
		}
		snprintf(buffer, sizeof(buffer), "333 %lu %lu %d",
			trap_history_total(), trap_history_oldest_seq(),
			trap_history_count());
		TRAP_SEND(buffer);
		return;
	}

	snprintf(buffer, sizeof(buffer), "<%s>", XML_TRAPS);
	TRAP_SEND(buffer);

	for (i = 0; (r = trap_history_get(i)) != NULL; i++)
	{
		struct trap_content *c = &r->content;

		if (r->seq <= since)
			break;	/* newest first: the rest are older still */

		sent++;

		snprintf(buffer, sizeof(buffer), "<%s>", XML_TRAP);
		TRAP_SEND(buffer);

		snprintf(buffer, sizeof(buffer), "<%s>%lu</%s>", XML_TRAP_SEQ,
			r->seq, XML_TRAP_SEQ);
		TRAP_SEND(buffer);

		snprintf(buffer, sizeof(buffer), "<%s>%s</%s>", XML_TRAP_SOURCE,
			xml_escape(r->source, esc, sizeof(esc)), XML_TRAP_SOURCE);
		TRAP_SEND(buffer);

		snprintf(buffer, sizeof(buffer), "<%s>%ld</%s>", XML_TRAP_TIME,
			(long)r->when, XML_TRAP_TIME);
		TRAP_SEND(buffer);

		snprintf(buffer, sizeof(buffer), "<%s>%d</%s>", XML_TRAP_BYTES,
			r->bytes, XML_TRAP_BYTES);
		TRAP_SEND(buffer);

		snprintf(buffer, sizeof(buffer), "<%s>%s</%s>", XML_TRAP_VERSION,
			c->version == 0 ? "v1" : (c->version == 1 ? "v2c" :
			(c->version == 3 ? "v3" : "unknown")), XML_TRAP_VERSION);
		TRAP_SEND(buffer);

		/* The community is a credential. Only an authenticated client
		   has any business seeing which one a device is using. */
		if (client->authlvl > 0 && c->community[0] != '\0')
		{
			snprintf(buffer, sizeof(buffer), "<%s>%s</%s>", XML_TRAP_COMMUNITY,
				xml_escape(c->community, esc, sizeof(esc)), XML_TRAP_COMMUNITY);
			TRAP_SEND(buffer);
		}

		snprintf(buffer, sizeof(buffer), "<%s>%s</%s>", XML_TRAP_NAME,
			xml_escape(c->name, esc, sizeof(esc)), XML_TRAP_NAME);
		TRAP_SEND(buffer);

		snprintf(buffer, sizeof(buffer), "<%s>%s</%s>", XML_TRAP_DESC,
			xml_escape(c->description, esc, sizeof(esc)), XML_TRAP_DESC);
		TRAP_SEND(buffer);

		snprintf(buffer, sizeof(buffer), "<%s>%s</%s>", XML_TRAP_SEVERITY,
			xml_escape(c->severity, esc, sizeof(esc)), XML_TRAP_SEVERITY);
		TRAP_SEND(buffer);

		snprintf(buffer, sizeof(buffer), "<%s>%s</%s>", XML_TRAP_CATEGORY,
			xml_escape(c->category, esc, sizeof(esc)), XML_TRAP_CATEGORY);
		TRAP_SEND(buffer);

		if (c->trap_oid[0] != '\0')
		{
			snprintf(buffer, sizeof(buffer), "<%s>%s</%s>", XML_TRAP_OID,
				xml_escape(c->trap_oid, esc, sizeof(esc)), XML_TRAP_OID);
			TRAP_SEND(buffer);
		}
		if (c->enterprise[0] != '\0')
		{
			snprintf(buffer, sizeof(buffer), "<%s>%s</%s>", XML_TRAP_ENTERPRISE,
				xml_escape(c->enterprise, esc, sizeof(esc)), XML_TRAP_ENTERPRISE);
			TRAP_SEND(buffer);
		}
		if (c->agent[0] != '\0')
		{
			snprintf(buffer, sizeof(buffer), "<%s>%s</%s>", XML_TRAP_AGENT,
				xml_escape(c->agent, esc, sizeof(esc)), XML_TRAP_AGENT);
			TRAP_SEND(buffer);
		}
		if (c->vendor[0] != '\0')
		{
			snprintf(buffer, sizeof(buffer), "<%s>%s</%s>", XML_TRAP_VENDOR,
				xml_escape(c->vendor, esc, sizeof(esc)), XML_TRAP_VENDOR);
			TRAP_SEND(buffer);
		}
		if (c->iface[0] != '\0')
		{
			snprintf(buffer, sizeof(buffer), "<%s>%s</%s>", XML_TRAP_IFACE,
				xml_escape(c->iface, esc, sizeof(esc)), XML_TRAP_IFACE);
			TRAP_SEND(buffer);
		}
		if (c->ifindex >= 0)
		{
			snprintf(buffer, sizeof(buffer), "<%s>%d</%s>", XML_TRAP_IFINDEX,
				c->ifindex, XML_TRAP_IFINDEX);
			TRAP_SEND(buffer);
		}

		snprintf(buffer, sizeof(buffer), "<%s>%lu</%s>", XML_TRAP_UPTIME,
			c->uptime, XML_TRAP_UPTIME);
		TRAP_SEND(buffer);

		snprintf(buffer, sizeof(buffer), "<%s>%d</%s>", XML_TRAP_DECODED,
			c->decoded ? 1 : 0, XML_TRAP_DECODED);
		TRAP_SEND(buffer);

		if (r->matched[0] != '\0')
		{
			snprintf(buffer, sizeof(buffer), "<%s>%s</%s>", XML_TRAP_MATCHED,
				xml_escape(r->matched, esc, sizeof(esc)), XML_TRAP_MATCHED);
			TRAP_SEND(buffer);
		}

		snprintf(buffer, sizeof(buffer), "<%s>%d</%s>", XML_TRAP_ALERT_EN,
			r->alert_enabled ? 1 : 0, XML_TRAP_ALERT_EN);
		TRAP_SEND(buffer);

		snprintf(buffer, sizeof(buffer), "<%s>%d</%s>", XML_TRAP_ALERT_SENT,
			r->alert_sent ? 1 : 0, XML_TRAP_ALERT_SENT);
		TRAP_SEND(buffer);

		for (v = 0; v < c->nvarbinds && v < TRAP_MAX_VARBIND; v++)
		{
			struct trap_varbind *b = &c->vb[v];

			snprintf(buffer, sizeof(buffer), "<%s>", XML_TRAP_VARBIND);
			TRAP_SEND(buffer);

			snprintf(buffer, sizeof(buffer), "<%s>%s</%s>", XML_TRAP_VB_OID,
				xml_escape(b->oid, esc, sizeof(esc)), XML_TRAP_VB_OID);
			TRAP_SEND(buffer);

			if (b->name[0] != '\0')
			{
				snprintf(buffer, sizeof(buffer), "<%s>%s</%s>", XML_TRAP_VB_NAME,
					xml_escape(b->name, esc, sizeof(esc)), XML_TRAP_VB_NAME);
				TRAP_SEND(buffer);
			}

			snprintf(buffer, sizeof(buffer), "<%s>%s</%s>", XML_TRAP_VB_TYPE,
				xml_escape(b->type, esc, sizeof(esc)), XML_TRAP_VB_TYPE);
			TRAP_SEND(buffer);

			snprintf(buffer, sizeof(buffer), "<%s>%s</%s>", XML_TRAP_VB_VALUE,
				xml_escape(b->value, esc, sizeof(esc)), XML_TRAP_VB_VALUE);
			TRAP_SEND(buffer);

			if (b->note[0] != '\0')
			{
				snprintf(buffer, sizeof(buffer), "<%s>%s</%s>", XML_TRAP_VB_NOTE,
					xml_escape(b->note, esc, sizeof(esc)), XML_TRAP_VB_NOTE);
				TRAP_SEND(buffer);
			}

			snprintf(buffer, sizeof(buffer), "</%s>", XML_TRAP_VARBIND);
			TRAP_SEND(buffer);
		}

		snprintf(buffer, sizeof(buffer), "</%s>", XML_TRAP);
		TRAP_SEND(buffer);
	}

	snprintf(buffer, sizeof(buffer), "</%s>", XML_TRAPS);
	TRAP_SEND(buffer);

	snprintf(buffer, sizeof(buffer), "333 %lu %lu %lu",
		trap_history_total(), trap_history_oldest_seq(), sent);
	TRAP_SEND(buffer);

	#undef TRAP_SEND
}

/*
 * SITE
 *
 * Who this daemon is. The name is the key half of every "site:object" a
 * client stores; the description is the label a person reads. An
 * unconfigured daemon answers "local" so a single-box install needs no
 * config change and no special case in the client.
 */
void send_site(struct clientstatus *client)
{
	char buffer[TEMPBUF_SIZE];

	if (client->xml)
	{
		snprintf(buffer, sizeof(buffer), "<%s>%s</%s>", XML_SITE_NAME,
			sitename != NULL ? sitename : "local", XML_SITE_NAME);
		if (sendline(client->filedes, buffer) == -1)
			return;
		snprintf(buffer, sizeof(buffer), "<%s>%s</%s>", XML_SITE_DESC,
			sitedesc != NULL ? sitedesc : "", XML_SITE_DESC);
		if (sendline(client->filedes, buffer) == -1)
			return;
		sendline(client->filedes, "333 site");
		return;
	}

	snprintf(buffer, sizeof(buffer), "333 %s %s",
		sitename != NULL ? sitename : "local",
		sitedesc != NULL ? sitedesc : "");
	sendline(client->filedes, buffer);
}

void send_uptime(struct clientstatus *client, time_t now_t)
{
	char buffer[256];

	snprintf(buffer, sizeof(buffer), "Uptime = %s", str_difftime_sec(boottime, now_t));
	sendline(client->filedes, buffer);
}

/*
 * Read the optional "since this sequence" argument of CONF/TRAPS.
 * Anything unparseable means 0, which is a full dump - the safe answer.
 */
static unsigned long parse_since(char *arg)
{
	char *end = NULL;
	unsigned long v;

	if (arg == NULL)
		return 0;
	while (*arg == ' ' || *arg == '\t')
		arg++;
	if (*arg == '\0')
		return 0;

	v = strtoul(arg, &end, 10);
	if (end == arg)
		return 0;
	return v;
}

/* CLIENT managment code */
void	do_service(struct clientstatus *here, char *buff, time_t now_t)
{
	/* Local buffer */
	char lb[256];
	if (debug)
	{
		snprintf(lb, 250, "[%s]:%s",here->ip, buff);
		print_err(0, "%s", lb);
	}

	if (strncmp(buff, "STAT", 4) == 0)
	{
		send_stat(here, buff);
	}
	else if (strncmp(buff, "UPTIME", 6) ==0)
	{
		send_uptime(here, now_t);
	}
	else if (strncmp(buff, "NFD", 3) == 0 && (here->authlvl >1))
	{
		snprintf(lb, 256, "%d is the next FD- %d queued", nextfd(), numqueued);
		sendline(here->filedes, lb);
		sendline(here->filedes, "what do you think about that?");
	}
	else if (strncmp(buff, "ABORT", 5) == 0 && (here->authlvl >1))
	{
		/* dump a core or something */
		ABORT();
	}
	else if (strncmp(buff, "KILLIT", 6) == 0 && (here->authlvl >1))
	{
		stop_daemon = TRUE;
	}
	else if (strncmp(buff, "QUIT", 4) == 0)
	{
		/* Send a quit message to far side */
		sendline(here->filedes, "333 Good Bye, please come again");
		/*
		 * Disallow any further communication.
		 *
		 * tls_disconnect() rather than close(): this client may be the
		 * aggregator link, and the SSL* is tracked by descriptor number.
		 * Closing the fd without dropping the SSL* leaves a stale entry
		 * behind, and the next accept() or connect() will very likely be
		 * handed that same number - at which point a plain socket would
		 * quietly be written through a dead TLS session. On a plain
		 * client this is exactly close().
		 */
		tls_disconnect(here->filedes);
		here->filedes = -1;
	}
        else if (strncmp(buff, "SNMPD", 5) == 0 && (here->authlvl >1))
        {
                /* Toggle Debugging */
                if (snmp_debug == 1)
                        snmp_debug = 0;
                else
                        snmp_debug = 1;
                sendline(here->filedes, "Toggled snmp debugging");
                print_err(0, "Toggled snmp debugging at client request");
        }
	else if (strncmp(buff, "DEBUG", 5) == 0 && (here->authlvl >1))
	{
		/* Toggle Debugging */
		if (debug == 1)
			debug = 0;
		else 
			debug = 1;
		sendline(here->filedes, "Toggled debugging");
		print_err(0, "Toggled debugging at client request");
	}
	/*
	 * Config generations. CONFIG-GEN is the cheap one a poller asks every
	 * cycle; the rest change what this box runs, so all four want the
	 * authkey - a config carries community strings and contact addresses
	 * on the way out, and decides what gets monitored on the way in.
	 *
	 * The longer command names are tested first: "CONFIG-GEN" would
	 * otherwise never be reached through a prefix match on "CONFIG-G".
	 */
	else if (strncmp(buff, "CONFIG-ROLLBACK", 15) == 0 && (here->authlvl > 1))
	{
		confgen_do_rollback(here);
	}
	else if (strncmp(buff, "CONFIG-REVERT", 13) == 0 && (here->authlvl > 1))
	{
		confgen_do_revert(here);
	}
	else if (strncmp(buff, "CONFIG-PUT ", 11) == 0 && (here->authlvl > 1))
	{
		confgen_receive(here, buff + 11);
	}
	else if (strncmp(buff, "CONFIG-GEN", 10) == 0 && (here->authlvl > 1))
	{
		confgen_report(here);
	}
	else if (strncmp(buff, "CONFIG-GET", 10) == 0 && (here->authlvl > 1))
	{
		confgen_send(here);
	}
	else if (strncmp(buff, "CONFIG-", 7) == 0)
	{
		/* Recognised but not permitted: say which, rather than letting it
		   fall through to "unknown request" and look like an old daemon
		   that has never heard of config management. */
		sendline(here->filedes, "403 - config management needs the authkey");
	}
	else if (strncmp(buff, "CONF", 4) == 0)
	{
		send_conf(here, parse_since(buff + 4));
	}
	else if (strncmp(buff, "EXPIREDNS", 9) == 0 && (here->authlvl >1))
	{
		expire_dns(now_t);
	}
	else if (strncmp(buff, "PRINTQ", 6) == 0 && (here->authlvl >1))
	{
		print_queue(here->filedes);
	}
	else if (strncmp(buff, "VERS", 4) == 0)
	{
		sendline(here->filedes, SYSM_VERS);
	}
	else if (strncmp(buff, "MODE", 4) == 0)
	{
		srv_client_do_mode(here, buff);
	}
	else if (strncmp(buff, "NOOP", 4) == 0)
	{
		sendline(here->filedes, "333 noop");
	}
	else if (strncmp(buff, "SHOWOBJ ", 8) == 0)
	{
		srv_client_do_showobject(here, buff);
	}
	else if (strncmp(buff, "TRACE ", 6) == 0)
	{
		srv_client_do_trace(here, buff);
	}
	else if (strncmp(buff, "SITE", 4) == 0)
	{
		send_site(here);
	}
	else if (strncmp(buff, "TRAPS", 5) == 0)
	{
		send_traps(here, parse_since(buff + 5));
	}
	else if (strncmp(buff, "AUTH", 4) == 0)
	{
		do_auth(here, buff);
	}
	else if (strncmp(buff, "UPD ", 4) == 0)
	{
		do_upd(here, buff);
	}
	else if (strncmp(buff, "ACK ", 4) == 0)
	{
		do_ack(here, buff);
	}
 	else if (strncmp(buff, "GET ", 4) == 0) /* Client is a web browser */
	{
		do_client_http(here, buff);
	}
	else
	{
		if (sendline(here->filedes, "444 - Unk")  == -1)
		{
			print_err(0, "error sending message to client");
			tls_disconnect(here->filedes);
			here->filedes = -1;
		}
		/* Log the unknown request */
		print_err(0, "Client sent unknown request: %s", buff);
	}
}

/*
 * log object state change to listening clients
 *
 * we get passed an object, it's old state, it's new state
 * and send it to the necessary clients that are
 * listening.
 */
void client_send_statechange(char *obj_name, int old_state, int new_state)
{
	struct clientstatus *here;
	char buff[TEMPBUF_SIZE];

        if (clienthead == NULL)
                return;
	
	for (here = clienthead->next; here != NULL ; here = here->next)
	{
		if (here->outage_log)
		{
			snprintf(buff, 1020, "state-change: %d:%s",
				new_state, obj_name);
			sendline(here->filedes, buff);
		}
	}

}


void timeout_clients()
{
	struct clientstatus *here;
	time_t now;

	if (clienthead == NULL)
		return;

        time(&now);

	for (here = clienthead->next; here != NULL ; here = here->next)
		if ((now - here->lastactivity) > inactivetime )
		{
			sendline(here->filedes, "444 - Timed out");
			/*
			 * tls_disconnect(), not close(): see the QUIT handler.
			 * A timed-out aggregator link that only had its fd closed
			 * would leave its SSL* tracked against a number the next
			 * connection is about to be given.
			 */
			if (here->filedes != -1)
				tls_disconnect(here->filedes);
			here->filedes = -1;
		}
}

void	dead_client_cleanup()
{
	/* free clients with filedes = -1 */

	struct clientstatus *here, *last, *freeme;

	if (clienthead == NULL)
		return;

	last = clienthead;
	freeme = NULL;
        for (here = clienthead->next; here != NULL ; here = here->next)
        {
		if (freeme != NULL)
		{
			if (freeme->un != NULL)
				FREE(freeme->un);
			if (freeme->ip != NULL)
				FREE(freeme->ip);
			FREE(freeme);
			freeme = NULL;
		}
		
		if (here->filedes == -1)
		{
			freeme = here;	
			last->next = here->next;
		} else {
			last = here;
		}
	}
	if (freeme != NULL)
	{
			if (freeme->un != NULL)
				FREE(freeme->un);
			if (freeme->ip != NULL)
				FREE(freeme->ip);
		FREE(freeme);
		freeme = NULL;
	}
}

void	setup_client()
{
        int msgsock; /* message socket for talking back and forth */
        struct sockaddr_in remote;
        int size;
	struct clientstatus *thisclient, *linkafter;

        size = sizeof (remote );

        /* do the accept() on the socket, then take care of it */
        msgsock = accept(clienthead->filedes,(struct sockaddr *)&remote,&size);

        if (msgsock == -1)
        {
                perror("accept");
                return;
        }

#ifdef HAVE_LIBWRAP
#ifdef HAVE_TCPD_H
        if(!hosts_ctl(DAEMONNAME,
			STRING_UNKNOWN,
			inet_ntoa(remote.sin_addr),
			STRING_UNKNOWN)) {
        	sendline(msgsock, "333 - You are not welcome here.");
		print_err(0,"denying connection from %s", inet_ntoa(remote.sin_addr));
        	close(msgsock);
		return;
	}
#endif /* HAVE_TCPD_H */
#endif

        /* figure out who's connecting and log it */
	if (!nologconnects)
	{
	        print_err(0, 
			"accepting connection from %s", 
			inet_ntoa(remote.sin_addr));
	}


        /* print our greeting banner */
        if (debug)
	{
		print_err(0, "sending hello banner");
	}

        sendline(msgsock, "111 - v1.0 Ready - Welcome");

	if (debug)
	{
		print_err(0, "setting up client structure");
	}

	thisclient = MALLOC(sizeof(struct clientstatus), "new_client");

	memset(thisclient, 0, sizeof(struct clientstatus));

	time(&thisclient->lastactivity); /* set current time */
	thisclient->filedes = msgsock; /* save accept()'ed fd */
	thisclient->un = NULL; /* no username yet */
	thisclient->ip = MALLOC(IP_ADDR_STR_SIZE, "thisclient_ip");
	if (thisclient->ip == NULL) {
		print_err(1, "srvclient.c: MALLOC failed for client IP");
		close(msgsock);
		return;
	}
	/* Use inet_ntop for thread-safe IP conversion */
	if (inet_ntop(AF_INET, &remote.sin_addr, thisclient->ip, IP_ADDR_STR_SIZE) == NULL) {
		snprintf(thisclient->ip, IP_ADDR_STR_SIZE, "unknown");
	}
	thisclient->authlvl = 0; /* no auth yet */
	thisclient->xml = FALSE;
	thisclient->outage_log = FALSE;
	thisclient->clientver = 0; /* no client vers yet, sent ours */
	thisclient->next = NULL; /* next client = NOTHING */

	linkafter = clienthead; /* start to walk client list */

	while (linkafter->next != NULL) /* until next client is null */
		linkafter = linkafter->next; /* do walk */
	linkafter->next = thisclient; /* link us at the end of it */
}

void	check_for_new_clients()
{
	/* check the specified socket for awating connections, if so, take
	   care of them */
	fd_set rd, wr, except;
	struct timeval local_timeout;
	
	if (clienthead->filedes == -1)
	/* do nothing */
		return;

	local_timeout.tv_sec = 0;
	local_timeout.tv_usec = 0;

	FD_ZERO(&wr);
	FD_ZERO(&except);
	FD_ZERO(&rd);
	FD_SET(clienthead->filedes, &rd);

	if (debug)
	{
		print_err(0, "srvclient.c:check_for_new_clients:Checking for a client");
	}

	while (select(clienthead->filedes+1,&rd,&wr,&except,&local_timeout)!=0)
		setup_client();

}

void	service_clients()
{
	struct clientstatus *here;
	char buff[1024];
	struct timeval tv;
	fd_set rd,wr,except;
	time_t now_t;
	int maxfd;
	int ret;

	time(&now_t);
	
	FD_ZERO(&wr);
	FD_ZERO(&rd);
	FD_ZERO(&except);
	maxfd = -1;

	tv.tv_sec = 0;
	tv.tv_usec = 0;

	for (here = clienthead->next;here != NULL;here = here->next)
	{
		if (here->filedes == -1)
			continue;
		FD_SET(here->filedes, &rd);
		if (here->filedes > maxfd)
			maxfd = here->filedes;
	}
	if (maxfd != -1)
	{
		ret = select(maxfd+1, &rd, &wr, &except, &tv);

		for (here=clienthead->next;here!=NULL;here=here->next)
		{
			if (here->filedes == -1)
				continue;
			if (FD_ISSET(here->filedes, &rd))
			{
				/*
				 * One line, one command. There used to be a second
				 * getline_tcp() here throwing a line away, to swallow the
				 * LF left over from a CRLF - which getline_tcp already
				 * skips on its own, as leading whitespace, at the start of
				 * the next read.
				 *
				 * It was not harmless. Whenever a client sent a command
				 * and its payload in one segment - or simply pipelined two
				 * commands - the discarded line was the client's next
				 * line, not a stray LF. CONFIG-PUT made that visible
				 * (the daemon ate the first line of the delivery and then
				 * blocked waiting for bytes that had already arrived), but
				 * any pipelining client was silently losing every second
				 * command before that.
				 */
				getline_tcp(here->filedes, buff);
				do_service(here, buff, now_t);
				here->lastactivity = now_t;
			}
		}
	}
}

void	client_poll()
{
        fd_set rd, wr, except;
        struct timeval local_timeout;
	struct clientstatus *here;

	if (in_client_poll)
	{
		return;
	}

	in_client_poll = TRUE;

        local_timeout.tv_sec = 0;
        local_timeout.tv_usec = 0;

        FD_ZERO(&wr);
        FD_ZERO(&except);
        FD_ZERO(&rd);

	/*
	 * There may be no listening socket at all - that is the default now,
	 * and a daemon that only dials out to a sysmon-web never has one. Its
	 * connections still live in this list and still have to be serviced,
	 * so it is the accept path that gets skipped, not the whole function.
	 *
	 * (This used to return early when there was no listener, and did it
	 * *after* setting in_client_poll, so the flag stayed set and no client
	 * was ever polled again. Nothing reached it while the daemon always
	 * listened.)
	 */
	if (clienthead->filedes != -1)
	{
		/* check for new clients */
		check_for_new_clients();
	}

	/* process old clients new data */
	service_clients();

	/* timeout old clients */
	timeout_clients();

	/* free dead client memory */
	dead_client_cleanup();

	if (clienthead->filedes == -1)
	{
		in_client_poll = FALSE;
		return;
	}

	for (here = clienthead; here != NULL; here = here->next)
		if (here->filedes != -1)
	        	FD_SET(here->filedes, &rd);

	if (select(clienthead->filedes+1,&rd,&wr,&except,&local_timeout) != 0)
	{
		if (FD_ISSET(clienthead->filedes, &rd))
		{
		        check_for_new_clients();
		}
		service_clients();
	}

	in_client_poll = FALSE;
}
