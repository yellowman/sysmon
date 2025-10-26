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

void client_poll();

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
			snprintf(buff, 256, "%s:%d:%d:%d:%ld:%d:%ld",
			here->value->data->hostname, here->value->data->type,
			here->value->data->port, here->value->data->lastcheck,
			here->value->data->downct,
			here->value->data->contacted,
			here->value->data->deathtime);
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
			snprintf(buff, 256, "%s:%d:%d:%d:%ld:%ld:%ld",
			here->value->data->hostname, here->value->data->type,
			here->value->data->port, here->value->data->lastcheck,
			here->value->data->downct,
			here->value->data->upct,
			here->value->data->deathtime);
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
		client->filedes = -1;
		return -1;
	}

	return 0;
}

int	send_conf(struct clientstatus *client)
{

	struct all_elements_list *here;

	here = currenthead;

	if (client->authlvl  <= 0)
	{
		sendline(client->filedes, "444 Permission Denied");
		return 0;
	}

	/* send xml */
	while (here != NULL)
	{
		send_object_xml(client->filedes, NULL, here->value);
		here=here->next;
	}

	/* done printing config */
	if (sendline(client->filedes, "333") == -1)
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

/*
 * send_object_xml - send an object described as obj
 * to either FILE or file(can be socket).  do FILE = null
 * if you want it to go to the socket.
 */
void send_object_xml(int fd, FILE *fh, struct graph_elements *obj)
{
	char buffer[TEMPBUF_SIZE];

	/* Macro to check send errors and abort XML generation if write fails */
	#define SEND_OR_ABORT(fd, fh, buf) \
		if (do_send_xml(fd, fh, buf) == -1) { \
			if (debug) print_err(1, "send_object_xml: aborting due to send error"); \
			return; \
		}

	snprintf(buffer, sizeof(buffer), "<%s>", XML_OBJECT_STATUS);
	SEND_OR_ABORT(fd, fh, buffer);

	snprintf(buffer, sizeof(buffer), "<%s>%s</%s>", XML_OBJECT, obj->unique_name , XML_OBJECT);
	SEND_OR_ABORT(fd, fh, buffer);

	snprintf(buffer, sizeof(buffer), "<%s>%s</%s>", XML_HOSTNAME, obj->data->hostname ,XML_HOSTNAME);
	SEND_OR_ABORT(fd, fh, buffer);

	snprintf(buffer, sizeof(buffer), "<%s>%d</%s>", XML_OBJECT_PORT, obj->data->port, XML_OBJECT_PORT);
	SEND_OR_ABORT(fd, fh, buffer);

	snprintf(buffer, sizeof(buffer), "<%s>%s</%s>", XML_OBJECT_TYPE, type_to_name(obj->data->type), XML_OBJECT_TYPE);
	SEND_OR_ABORT(fd, fh, buffer);

	snprintf(buffer, sizeof(buffer), "<%s>%s</%s>", XML_OBJECT_MESSAGE, obj->data->message, XML_OBJECT_MESSAGE);
	SEND_OR_ABORT(fd, fh, buffer);

	if (obj->data->contact != NULL)
	{
		snprintf(buffer, sizeof(buffer), "<%s>%s</%s>", XML_OBJECT_CONTACT, obj->data->contact, XML_OBJECT_CONTACT);
		SEND_OR_ABORT(fd, fh, buffer);
	}

	/* XML_OBJ_GROUP */
        if (obj->data->group != NULL)
        {
                snprintf(buffer, sizeof(buffer), "<%s>%s</%s>", XML_OBJECT_GROUP, obj->data->group, XML_OBJECT_GROUP);
                SEND_OR_ABORT(fd, fh, buffer);
        }

        /* XML_OBJ_NOTES */
        if (obj->data->notes != NULL)
        {
                snprintf(buffer, sizeof(buffer), "<%s>%s</%s>", XML_OBJECT_NOTES, obj->data->notes, XML_OBJECT_NOTES);
                SEND_OR_ABORT(fd, fh, buffer);
        }

	if (obj->data->type == SYSM_TYPE_SNMP)
	{
		if (obj->data->snmp_community != NULL)
		{
			snprintf(buffer, sizeof(buffer), "<%s>%s</%s>", XML_SNMP_COMMUNITY, obj->data->snmp_community ,XML_SNMP_COMMUNITY);
			SEND_OR_ABORT(fd, fh, buffer);
		}
		if (obj->data->snmp_oid != NULL)
		{
			snprintf(buffer, sizeof(buffer), "<%s>%s</%s>", XML_SNMP_OID, obj->data->snmp_oid, XML_SNMP_OID);
			SEND_OR_ABORT(fd, fh, buffer);
		}
		snprintf(buffer, sizeof(buffer), "<%s>%s</%s>", XML_SNMP_TYPE, snmp_type_to_name(obj->data->snmp_test_type), XML_SNMP_TYPE);
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

		snprintf(buffer, sizeof(buffer), "<%s>%ld</%s>", XML_SNMP_LASTRESP, obj->data->last_snmp_resptime, XML_SNMP_LASTRESP);
		SEND_OR_ABORT(fd, fh, buffer);
	}

	snprintf(buffer, sizeof(buffer), "<%s>%d</%s>", XML_OBJECT_STATE, obj->data->lastcheck, XML_OBJECT_STATE);
	SEND_OR_ABORT(fd, fh, buffer);

	if (obj->data->username != NULL)
	{
		snprintf(buffer, sizeof(buffer), "<%s>%s</%s>", XML_AUTH_USER, obj->data->username , XML_AUTH_USER);
		SEND_OR_ABORT(fd, fh, buffer);
	}

	if (obj->data->password != NULL)
	{
		snprintf(buffer, sizeof(buffer), "<%s>%s</%s>", XML_AUTH_PASSWD, obj->data->password, XML_AUTH_PASSWD);
		SEND_OR_ABORT(fd, fh, buffer);
	}

	if (obj->data->hdr != NULL)
	{
		snprintf(buffer, sizeof(buffer), "<%s>%s</%s>", XML_HEADER, obj->data->hdr, XML_HEADER);
		SEND_OR_ABORT(fd, fh, buffer);
	}

	if (obj->data->hdrval != NULL)
	{
		snprintf(buffer, sizeof(buffer), "<%s>%s</%s>", XML_HEADER_VAL, obj->data->hdrval, XML_HEADER_VAL);
		SEND_OR_ABORT(fd, fh, buffer);
	}
	
	if (obj->data->secret != NULL)
	{
		snprintf(buffer, sizeof(buffer), "<%s>%s</%s>", XML_RADIUS_SECRET, obj->data->secret, XML_RADIUS_SECRET);
		SEND_OR_ABORT(fd, fh, buffer);
	}

	if (obj->data->lastmsgid != NULL)
	{
		snprintf(buffer, sizeof(buffer), "<%s>%s</%s>", XML_MESSAGE_ID, obj->data->lastmsgid, XML_MESSAGE_ID);
		SEND_OR_ABORT(fd, fh, buffer);
	}

	if (obj->data->unique_id != NULL)
	{
		snprintf(buffer, sizeof(buffer), "<%s>%s</%s>", XML_UNIQUE_ID, obj->data->unique_id, XML_UNIQUE_ID);
		SEND_OR_ABORT(fd, fh, buffer);
	}

	if (obj->data->url != NULL)
	{
		snprintf(buffer, sizeof(buffer), "<%s>%s</%s>", XML_OBJ_URL, obj->data->url, XML_OBJ_URL);
		SEND_OR_ABORT(fd, fh, buffer);
	}

	if (obj->data->url_text != NULL)
	{
		snprintf(buffer, sizeof(buffer), "<%s>%s</%s>", XML_OBJ_URL_TEXT, obj->data->url, XML_OBJ_URL_TEXT);
		SEND_OR_ABORT(fd, fh, buffer);
	}
	
	if (obj->data->command != NULL)
	{
		snprintf(buffer, sizeof(buffer), "<%s>%s</%s>", XML_OBJ_EXEC, obj->data->command, XML_OBJ_EXEC);
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

	snprintf(buffer, sizeof(buffer), "<%s>%ld</%s>", XML_OBJ_CONTACTEDAT, obj->data->lastcontacted, XML_OBJ_CONTACTEDAT);
	SEND_OR_ABORT(fd, fh, buffer);

	snprintf(buffer, sizeof(buffer), "<%s>%d</%s>", XML_CONTACT_UP, obj->data->contact_when, XML_CONTACT_UP);
	SEND_OR_ABORT(fd, fh, buffer);

	snprintf(buffer, sizeof(buffer), "<%s>%d</%s>", XML_QUEUED, obj->data->queued, XML_QUEUED);
	SEND_OR_ABORT(fd, fh, buffer);

	snprintf(buffer, sizeof(buffer), "<%s>%ld</%s>", XML_LASTCHECK, obj->data->lchecktime, XML_LASTCHECK);
	SEND_OR_ABORT(fd, fh, buffer);

	snprintf(buffer, sizeof(buffer), "<%s>%ld</%s>", XML_CHECK_START, obj->data->check_start, XML_CHECK_START);
	SEND_OR_ABORT(fd, fh, buffer);

	snprintf(buffer, sizeof(buffer), "<%s>%ld</%s>", XML_OUTAGE_TIME, obj->data->deathtime, XML_OUTAGE_TIME);
	SEND_OR_ABORT(fd, fh, buffer);

	snprintf(buffer, sizeof(buffer), "<%s>%ld</%s>", XML_LAST_TIME_UP, obj->data->last_up, XML_LAST_TIME_UP);
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
			snprintf(buffer, sizeof(buffer), "<%s>%s</%s>",
				XML_SNMP_OID_SEC, obj->data->snmp_oid_sec, XML_SNMP_OID_SEC);
			SEND_OR_ABORT(fd, fh, buffer);
		}
		if (obj->data->snmp_up_msg != NULL) {
			snprintf(buffer, sizeof(buffer), "<%s>%s</%s>",
				XML_SNMP_UP_MSG, obj->data->snmp_up_msg, XML_SNMP_UP_MSG);
			SEND_OR_ABORT(fd, fh, buffer);
		}
		if (obj->data->snmp_down_msg != NULL) {
			snprintf(buffer, sizeof(buffer), "<%s>%s</%s>",
				XML_SNMP_DOWN_MSG, obj->data->snmp_down_msg, XML_SNMP_DOWN_MSG);
			SEND_OR_ABORT(fd, fh, buffer);
		}
	}

	/* DNS Configuration */
	if (obj->data->type == SYSM_TYPE_DNS) {
		if (obj->data->dns_query != NULL) {
			snprintf(buffer, sizeof(buffer), "<%s>%s</%s>",
				XML_DNS_QUERY, obj->data->dns_query, XML_DNS_QUERY);
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
		snprintf(buffer, sizeof(buffer), "<%s>%s</%s>",
			XML_PAGE_MESSAGE, obj->data->pmesg, XML_PAGE_MESSAGE);
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
		snprintf(buffer, sizeof(buffer), "<%s>%ld</%s>",
			XML_PKTLOSS_LAST_CHK, obj->data->pktloss_last_check,
			XML_PKTLOSS_LAST_CHK);
		SEND_OR_ABORT(fd, fh, buffer);
	}

	/* RTT Samples Configuration */
	if (obj->data->rtt_samples > 0) {
		snprintf(buffer, sizeof(buffer), "<%s>%u</%s>",
			XML_RTT_SAMPLES, obj->data->rtt_samples, XML_RTT_SAMPLES);
		SEND_OR_ABORT(fd, fh, buffer);
	}

	/* Next Scheduled Queue Time */
	if (obj->data->next_queuetime > 0) {
		snprintf(buffer, sizeof(buffer), "<%s>%ld</%s>",
			XML_NEXT_QUEUE_TIME, obj->data->next_queuetime, XML_NEXT_QUEUE_TIME);
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

				snprintf(buffer, sizeof(buffer), "<%s>%ld</%s>",
					XML_CHECK_WAKEUP_TIME, found_qent->last_wakeup_time,
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
							"<Sample timestamp=\"%ld\" sent=\"%u\" received=\"%u\" lost=\"%u\"/>",
							sample->timestamp, sample->sent, sample->received, sample->lost);
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

void send_uptime(struct clientstatus *client, time_t now_t)
{
	char buffer[256];

	snprintf(buffer, 256, "Uptime = %s", str_difftime_sec(boottime, now_t));
	sendline(client->filedes, buffer);
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
		/* Disallow any further communication */
		close(here->filedes);
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
	else if (strncmp(buff, "CONF", 4) == 0)
	{
		send_conf(here);
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
			close(here->filedes);
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
			if (here->filedes != -1)
				if (close(here->filedes) == -1)
					perror("waah! closing stuff\n");
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
	char throwmeout[TEMPBUF_SIZE], buff[1024];
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
				getline_tcp(here->filedes, buff);
				getline_tcp(here->filedes, throwmeout);
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

        if (clienthead->filedes == -1)
	{
	        /* do nothing */
                return;
	}

        local_timeout.tv_sec = 0;
        local_timeout.tv_usec = 0;

        FD_ZERO(&wr);
        FD_ZERO(&except);
        FD_ZERO(&rd);

	/* check for new clients */
	check_for_new_clients();

	/* process old clients new data */
	service_clients();

	/* timeout old clients */
	timeout_clients();

	/* free dead client memory */
	dead_client_cleanup();

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
