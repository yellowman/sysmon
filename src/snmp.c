/* $Id: snmp.c,v 1.47 2005/10/12 03:04:38 jared Exp $ */

#include "config.h"

/* One of the many include files defines a 'clear' macro
which breaks the build on Mac OS X */
#undef clear

/* Forward declaration for print_in_hex (defined in radius.c) */
void print_in_hex(unsigned char *message, int msgsize);

/* SNMP specific includes */
#ifdef ENABLE_SNMP

#ifdef HAVE_UCD_SNMP_VERSION_H
#include <ucd-snmp/ucd-snmp-config.h>
#include <ucd-snmp/ucd-snmp-includes.h>
#endif  

#ifdef HAVE_NET_SNMP_VERSION_H
#include <net-snmp/net-snmp-config.h>
#include <net-snmp/net-snmp-includes.h>
#include <net-snmp/library/snmp_client.h>
#endif

 
/* SNMP - The not so SIMPLE NETWORK MANAGMENT PROTOCOL */

struct snmpdata {
	struct snmp_pdu *req;
	oid oid_value[MAX_OID_LEN];
	int oid_len;
	unsigned long snmp_retval;
	time_t snmp_response_time;
	bool snmp_response;
	struct snmp_session *sess;
};
#endif /* ENABLE_SNMP */

int snmp_debug = 0;

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
	 * Read what the device actually said. decode_snmp_trap() always
	 * leaves something printable behind, so the log line and the trap
	 * history are useful even when the packet is junk.
	 */
	decode_snmp_trap(buffer, (size_t)len, &trap);

	obj = find_object_by_ip(ip_string);

	/*
	 * A v1 trap carries the agent's own address, which is what matters
	 * when a proxy or a NAT forwards it: the packet comes from the
	 * relay, but the event belongs to the device named inside.
	 */
	if (obj == NULL && trap.agent[0] != '\0' &&
	    strcmp(trap.agent, ip_string) != 0) {
		obj = find_object_by_ip(trap.agent);
		if (obj != NULL && debug)
			print_err(1, "trap relayed by %s matched agent-addr %s",
				ip_string, trap.agent);
	}

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

	if (obj != NULL && obj->data->trap_alert) {
		alert_enabled = TRUE;
		/*
		 * Only page for something that really was a trap. Before the
		 * packet was decoded, any UDP datagram from a monitored
		 * address woke somebody up - which made a page trivial to
		 * provoke with a spoofed packet, and meant a stray scanner
		 * could do it by accident.
		 */
		if (trap.alertable) {
			send_trap_alert(obj, ip_string, &trap);
			alert_sent = TRUE;
		} else {
			print_err(1, "not paging %s: the packet from %s was not an snmp trap",
				obj->data->hostname, ip_string);
		}
	} else if (debug && obj != NULL) {
		print_err(1, "trap from %s - object %s found but trap_alert not enabled",
			ip_string, obj->data->hostname);
	} else if (debug) {
		print_err(1, "trap from %s - no matching object found", ip_string);
	}

	/*
	 * Remember it either way. A trap from an address nobody configured
	 * is exactly the thing an operator wants to see in the web UI - it
	 * is usually a device that should have been monitored all along.
	 */
	trap_history_add(ip_string, now, len, &trap,
		obj != NULL ? (char *)obj->unique_name : NULL,
		alert_enabled, alert_sent);
}

#ifdef ENABLE_SNMP

/*
 * extract the data from the snmp packet
 */
int extract_snmp_result (int status, struct snmp_session *sp, 
	struct snmp_pdu *pdu, struct snmpdata *snmp_nfo)
{
  struct variable_list *vp;
  int ix;

/*
(gdb) print *pdu->variables->val->counter64
$6 = {high = 0, low = 1854873}

  eg: pdu->variables->val->counter64.low
 */

#warning need to correctly differentiate btw 32 and 64 bit responses

  switch (status) 
  {
   case STAT_SUCCESS:
   {
    vp = pdu->variables;
    if (pdu->errstat == SNMP_ERR_NOERROR)
    {
      if (vp->val.integer)
      {
        snmp_nfo->snmp_retval = (unsigned long)(*vp->val.integer);
        if ((snmp_nfo->snmp_retval == 0) && 
          (vp->val.counter64->low != 0))
		snmp_nfo->snmp_retval = (unsigned long)(vp->val.counter64->low);
        snmp_nfo->snmp_response = TRUE;
        time(&snmp_nfo->snmp_response_time);
      }
    } else {
      for (ix = 1; vp && ix != pdu->errindex; vp = vp->next_variable, ix++);
      if (vp != NULL)
      {
        if (vp->val.integer)
        {
          snmp_nfo->snmp_retval = (unsigned long)(*vp->val.integer);
        if ((snmp_nfo->snmp_retval == 0) &&
          (vp->val.counter64->low != 0))
                snmp_nfo->snmp_retval = (unsigned long)(vp->val.counter64->low);
          snmp_nfo->snmp_response = TRUE;
          time(&snmp_nfo->snmp_response_time);
        }
      }
    }
    return 1;
   }
   case STAT_TIMEOUT:
   {
    return -1;
   }

  }
  return 0;
}


int snmp_callback_response(int operation, struct snmp_session *sp, int reqid,
                    struct snmp_pdu *pdu, void *magic)
{
	struct monitorent *here = (struct monitorent *)magic;
	struct snmpdata *localstruct;

	if (debug||snmp_debug)
	{
        	print_err(1, "snmp.c:inside snmp_callback_response %x", 
			here->monitordata);
	}

	localstruct = here->monitordata;

#ifndef RECEIVED_MESSAGE
#define RECEIVED_MESSAGE NETSNMP_CALLBACK_OP_RECEIVED_MESSAGE
#endif /* RECEIVED_MESSAGE */
	if (operation == RECEIVED_MESSAGE)
	{
		if (extract_snmp_result(STAT_SUCCESS, localstruct->sess, pdu, localstruct))
		{
			if (debug||snmp_debug) 
				print_err(1, "snmp.c:snmp_callback_response:snmp_retval = %d on %s", localstruct->snmp_retval, here->checkent->hostname);
			return 1;
		}
	}
			
	here->retval = SYSM_NORESP;

	return 0;
}

/*
 * start snmp query
 */
void start_test_snmp(struct monitorent *here)
{
	struct snmpdata *localstruct;
        struct snmp_session startup_sess;

	localstruct = MALLOC(sizeof(struct snmpdata), "snmpdata");

	here->monitordata = localstruct;

	localstruct->snmp_retval = 0;
	localstruct->snmp_response = FALSE;

	snmp_sess_init(&startup_sess);	/* initialize session */
	
	startup_sess.version = SNMP_VERSION_2c;
	startup_sess.peername = here->checkent->hostname;
	startup_sess.community = here->checkent->snmp_community;

        startup_sess.remote_port = SNMP_DEFAULT_REMPORT;
        startup_sess.timeout = SNMP_DEFAULT_TIMEOUT;
        startup_sess.retries = SNMP_DEFAULT_RETRIES;

	startup_sess.community_len =strlen(here->checkent->snmp_community);

	/* set function to get callback data */
	startup_sess.callback = snmp_callback_response;
	startup_sess.callback_magic = here;

	/* call snmp_open */

	localstruct->sess = snmp_open(&startup_sess);

	if (localstruct->sess == NULL)
	{
		print_err(1, "snmp_open returned an error");
		/* return an error */
		here->retval = -2;
		return;
	}

	/* create pdu */

	localstruct->req = snmp_pdu_create(SNMP_MSG_GET);

	memset(localstruct->oid_value, 0, MAX_OID_LEN);

	localstruct->oid_len = sizeof(localstruct->oid_value);

	if (!read_objid(here->checkent->snmp_oid, localstruct->oid_value,
		&localstruct->oid_len))
	{
		snmp_perror("snmp.c:read_objid");
		here->retval = -2;
		return;
	}

	snmp_add_null_var(localstruct->req, 
		localstruct->oid_value,
		localstruct->oid_len);

	/* send snmp packet */
        if (debug||snmp_debug) print_err(1, "calling snmp_send");

	/* snmp_send returns 0 on error, 1 on success */
	if (snmp_send(localstruct->sess, localstruct->req) == 0)
	{
		perror("snmp_send");
	}

	return;
}

void stop_test_snmp(struct monitorent *here)
{
	struct snmpdata *localstruct = NULL;

	localstruct = here->monitordata;
        if (localstruct == NULL)
        {
                print_err(1, "snmp.c:stop_test_snmp localstruct is null");
                return;
        }

	/* close the snmp socket */
	snmp_close(localstruct->sess);

        free(localstruct);
        here->monitordata = NULL;

	return;
}

void service_test_snmp(struct monitorent *here)
{
	struct snmpdata *localstruct = NULL;
	fd_set fdset;
	int max_fd = 0;
	int block = 1;
	int ret = 0;
	unsigned long rate_time;
	unsigned long rate_time_val;
	unsigned long rate_avg_val;
	struct timeval timeout;
        struct timeval now;

	localstruct = here->monitordata;
	if (localstruct == NULL)
	{
		print_err(1, "snmp.c:service_test_snmp localstruct is null");
		return;
	}

	FD_ZERO(&fdset);
	snmp_select_info(&max_fd, &fdset, &timeout, &block);

        timeout.tv_sec = 0;
        timeout.tv_usec = 0;

	ret = select(max_fd, &fdset, NULL, NULL, &timeout);
	if (ret) 
	{
		snmp_read(&fdset);
	}

	if (debug||snmp_debug) print_err(1, "snmp.c:svc_test_snmp:snmp_response = %d", localstruct->snmp_response);
	if (localstruct->snmp_response)
	{
		if (debug||snmp_debug) print_err(1, "snmp.c:snmp_response(%s)", here->checkent->hostname);
		switch (here->checkent->snmp_test_type)
		{
			case SYSM_SNMP_TYPE_REBOOT:
				if (debug||snmp_debug) print_err(1, "snmp.c:type_reboot:comparing last(%d) > now(%d)", here->checkent->system_uptime, localstruct->snmp_retval);
				if (here->checkent->system_uptime > localstruct->snmp_retval)
				{
					here->retval = SYSM_SNMP_REBOOT;
				} else {
					here->retval = SYSM_OK;
				}
				here->checkent->system_uptime = localstruct->snmp_retval;
				break;
			case SYSM_SNMP_TYPE_HIGH:
				if (debug||snmp_debug) print_err(1, "snmp.c:type_high:comparing received value %d with configured %d", localstruct->snmp_retval, here->checkent->snmp_high);
				if (here->checkent->snmp_high < localstruct->snmp_retval)
				{
					here->retval = SYSM_SNMP_HIGH;
				} else {
					here->retval = SYSM_OK;
				}
				/* stash last snmp value */
                                here->checkent->system_uptime = localstruct->snmp_retval;
				break;
			case SYSM_SNMP_TYPE_LOW:
				if (debug||snmp_debug) print_err(1, "snmp.c:type_low:comparing received value %d with configured %d", localstruct->snmp_retval, here->checkent->snmp_low);
				if (here->checkent->snmp_low > localstruct->snmp_retval)
				{
					here->retval = SYSM_SNMP_LOW;
				} else {
					here->retval = SYSM_OK;
				}
				/* stash last snmp value */
                                here->checkent->system_uptime = localstruct->snmp_retval;
				break;
			case SYSM_SNMP_TYPE_RANGE:
				if ((here->checkent->snmp_low < localstruct->snmp_retval) && (here->checkent->snmp_high > localstruct->snmp_retval))
				{
					here->retval = SYSM_SNMP_OOR;
				} else {
					here->retval = SYSM_OK;
				}
				/* stash last snmp value */
                                here->checkent->system_uptime = localstruct->snmp_retval;
				break;
			case SYSM_SNMP_TYPE_EXACT:
				if (here->checkent->snmp_exact != localstruct->snmp_retval)
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
				if (here->checkent->snmp_octets)
				{
					rate_avg_val=(rate_time_val*8/rate_time);
				} else {
					rate_avg_val=(rate_time_val/rate_time);
				}

				if (debug||snmp_debug) 
					print_err(1, "snmp.c:rate_avg_val = %u ; here->checkent->snmp_rate %u", rate_avg_val, here->checkent->snmp_rate);
				here->checkent->system_uptime = localstruct->snmp_retval;
				here->checkent->last_snmp_resptime = localstruct->snmp_response_time;
				if (rate_avg_val > here->checkent->snmp_rate)
				{
					here->retval = SYSM_SNMP_HIGHRATE;
				} else {
					here->retval = SYSM_OK;
				}
				break;
			default:
				print_err(1, "snmp.c:invalid snmp type");
				here->retval = -2;
				break;
		}

	} else {
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
                snmp_close(localstruct->sess);

                free(here->monitordata);

                here->monitordata = NULL;
	}

	return;
}
#endif /* ENABLE_SNMP */

/*
 * find_object_by_ip - Find a monitored object by its IP address
 *
 * Searches through all configured objects and returns the first one
 * that matches the given IP address string.
 *
 * Returns: pointer to graph_elements if found, NULL otherwise
 */
struct graph_elements *find_object_by_ip(char *ip_string)
{
	struct all_elements_list *walker;
	struct hostent *he;
	char ip_addr[INET_ADDRSTRLEN];

	if (ip_string == NULL) {
		return NULL;
	}

	/*
	 * PASS 1: Check for direct IP string matches (no DNS)
	 * This is fast and handles the common case where hostname IS the IP
	 */
	for (walker = currenthead; walker != NULL; walker = walker->next) {
		if (walker->value == NULL || walker->value->data == NULL) {
			continue;
		}

		/* Check if hostname is directly the IP address */
		if (strcmp((char *)walker->value->data->hostname, ip_string) == 0) {
			return walker->value;
		}
	}

	/*
	 * PASS 2: DNS resolution (only if pass 1 failed)
	 * This is slower but necessary for hostname-based configs
	 */
	for (walker = currenthead; walker != NULL; walker = walker->next) {
		if (walker->value == NULL || walker->value->data == NULL) {
			continue;
		}

		/* Try to resolve hostname to IP and compare */
		he = gethostbyname((char *)walker->value->data->hostname);
		if (he != NULL && he->h_addr_list[0] != NULL) {
			if (inet_ntop(AF_INET, he->h_addr_list[0], ip_addr, sizeof(ip_addr)) != NULL) {
				if (strcmp(ip_addr, ip_string) == 0) {
					return walker->value;
				}
			}
		}
	}

	return NULL;  /* Not found */
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
