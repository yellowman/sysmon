/* $Id: icmp.c,v 1.64 2014/07/09 16:29:39 jared Exp $ */
#include "config.h"

extern struct protoent *icmpproto;
extern int glob_icmp_fd;

#define A(bit)          icmp_temp.rcvd_tbl[(bit)>>3]  /*identify byte in array*/
#define B(bit)          (1 << ((bit) & 0x07))   /* identify bit in byte */
#define CLR(bit)        (A(bit) &= (~B(bit)))  /* do something... */

int debug_icmp_replies_only = 0;

/* All the variables needed for pinging (I think) - needs to be locked */
/* for threaded use */
struct pingdata {
	struct sockaddr_in *to;
	struct ICMPHDR *icp;
	struct IPHDR *ip;
	int hlen;
	struct my_hostent *hp;
	unsigned char *datap, *packet;
	int counter;
	int ident;                  /* process id to identify our packets */
	int packetsent;             /* number of packets sent */
	struct sockaddr ping_target;        /* who to ping */
	unsigned char outpack[128];            /* the packet we output */
	char rcvd_tbl[8192];		/* for doing bit shifts */
	int nreceived;                  /* # of packets we got back */
	struct timeval lastsentat;
} icmp_temp;

/* Amount of time to wait for icmp response before doing
 * next packet
 */
unsigned int icmp_packet_delay = 1; /* delay in seconds */

void pinger_v4(struct pingdata*, struct monitorent*);

/*
 * Generate IDENT signature to be encoded within ICMP packet
 */
unsigned short int generate_ident()
{
	/* Generate an ident that is not currently in use */
	static unsigned short int this;

	this++;
	this++;
	if ((this % 2) == 0)
	{
		this++;
	}

	return this;

}

/*
 * set up the file descriptor as necessary for use by the rest
 * of the process
 *
 * do a isroot(), and possibly revoke root in future versions
 */
void setup_icmp_fd()
{
	int retval;
	unsigned int hold = ICMP_HOLD_QUEUE;

	if (glob_icmp_fd != -1)
	{
		return;
	}

	glob_icmp_fd = socket(AF_INET, SOCK_RAW, icmpproto->p_proto);

	if (glob_icmp_fd == -1)
	{
		if (errno == EPERM)
		{
			print_err(1, "We are not root, unable to perform icmp check, exiting");
			exit(1);
		}
		perror("icmp.c:setup_icmpv4_fd: error!");
		print_err(1, "icmp.c:glob_icmpv4_fd setup was -1, errno = %d",
			errno);
	}

	retval = -1;
	while (retval == -1)
	{
		retval = setsockopt(glob_icmp_fd, SOL_SOCKET,
			SO_RCVBUF, (char *)&hold, sizeof(hold));

		if (retval == -1)
		{
			if (errno == ENOBUFS)
			{
				hold = hold- (hold / 3);
				continue;
			}
			perror("icmp.c:setsockopt");
			print_err(1, 
				"icmp.c:setsockopt returned -1, errno = %d",
				errno);
			break;
		}
	}
	print_err(0, "sysmond: INFO: hold queue set to %d for icmp packets", hold);

	set_nonblock(glob_icmp_fd);

	return;
}

/*
 * Handle the icmp responses we may get, and coordinate the
 * responses appropriateley
 */
void	handle_icmp_responses()
{
	struct monitorent *here = NULL;
	struct pingdata *localstruct = NULL;
	struct pingdata rcvd_data;
	struct sockaddr_in from;
	char rcvd_pkt[ICMP_PACKET_SIZE];
	int ret;
	int fromlen;

	if (glob_icmp_fd == -1)
	{
		return;
	}

	fromlen = sizeof(from); /* no comment */

	while (data_waiting_read(glob_icmp_fd, 0))
	{
	        if ((ret = recvfrom(glob_icmp_fd, 
			rcvd_pkt, ICMP_PACKET_SIZE, 0,
			(struct sockaddr *)&from, &fromlen)) < 0)
		{
			if (errno == EINTR) /* if we get interrupted */
			{
				print_err(1, "icmp.c: got interrupted while attempting to recvfrom");
				/* Decrease the counter */
				continue; /* and try again */
			}
			perror("icmp.c: recvfrom");
			continue; /* try again */
		}
                /* Check the IP header */
		rcvd_data.ip = (struct IPHDR *)rcvd_pkt;
		rcvd_data.hlen = (rcvd_data.ip->IHL & 0x0f) << 2;

                        /* Now the ICMP part */
		rcvd_data.icp=(struct ICMPHDR *)(rcvd_pkt + rcvd_data.hlen);

		/* if not an echo reply, skip it */
		if (rcvd_data.icp->ICMP_TYPE != ICMP_ECHOREPLY)
			continue;

		/* determine if it was ours */

		/* Walk the queue to find active checks that are ping/icmp type */
		for (here = queuehead; here != NULL; here = here->next)
		{
			if (here->checkent->type != SYSM_TYPE_PING)
			{
				continue;
			}
			/* address the check */
			localstruct = here->monitordata;

			if (localstruct == NULL)
				continue;

#ifdef DEBUG
			/* 
			 * Do some debugging and print out what we
			 * generated with what we got back
			 */
			/* Compare received IDENT with the one that we sent */
			if (debug || here->checkent->trace)
				print_err(1, "comparing rcvd_data echo_id w/ ident sent (got %d and %d was sent)", rcvd_data.icp->ICMP_ECHO_ID, localstruct->ident);

#endif /* DEBUG */
			if (rcvd_data.icp->ICMP_ECHO_ID == localstruct->ident)
			{
				if (debug_icmp_replies_only || here->checkent->trace)
				{
					print_err(1, "got a reply for ping check of %s", here->checkent->hostname);
				}
				/* Increment our count */
			        localstruct->nreceived++;

				/* go on already */
				continue;
			}
		}
	}
}

/*
 *
 */
void	start_test_ping(struct monitorent *here)
{
	struct pingdata *localstruct;
	/* set things all up, and we should be Ok */

	if (glob_icmp_fd == -1)
	{
		/* If there is no icmp fd, say it's ok */
		here->retval = SYSM_OK;
		return;
	}

	here->filedes = -1; /* not used here */
	here->monitordata = MALLOC(sizeof(struct pingdata), "icmp-localstruct");

	memset(here->monitordata, 0, sizeof(struct pingdata));

	localstruct = here->monitordata;

	gettimeofday(&here->lastserv, NULL);

	localstruct->nreceived = 0; /* zero it out */

	localstruct->packetsent = 0; /* zero it out */

	localstruct->datap = &localstruct->outpack[8 + sizeof(struct timeval)];

	/* initalize the variable */
	memset(&localstruct->ping_target, 0, sizeof(struct sockaddr));

	if (debug || here->checkent->trace)
	{
		print_err(here->checkent->trace, "setting up ping of host %s", 
			here->checkent->hostname);
	}

	/* set to */
	localstruct->to = (struct sockaddr_in *)&localstruct->ping_target;

	/* internet protocol */
	localstruct->to->sin_family = AF_INET;

	/* do a dns lookup on the hostname we're being passed */
	localstruct->hp = my_gethostbyname(here->checkent->hostname, AF_INET);

	if (!localstruct->hp)  /* did we get an error doing a dns query */
	{
		/* if so, do the return thang */
		here->retval = SYSM_NODNS;
		FREE(localstruct);
		here->monitordata = NULL;
		return; /* can't forget this else we core */
	}

	/* set the family type */
	localstruct->to->sin_family = localstruct->hp->h_addrtype_v4;

	memcpy((caddr_t)&localstruct->to->sin_addr, localstruct->hp->my_h_addr_v4, 
		localstruct->hp->h_length_v4);

	if (!(localstruct->packet = (u_char *)MALLOC(ICMP_PACKET_SIZE, "icmp.c:packet_data"))) 
	{
		/* aie!! */
		print_err(1, "icmp.c: out of memory.");
		here->retval = here->checkent->lastcheck;
		FREE(localstruct);
		here->monitordata = NULL;
		return;
	}

	for (localstruct->counter = 8; localstruct->counter < 128;
		++localstruct->counter)  /* do something.. */
	{
			*localstruct->datap++ = localstruct->counter;
					/* and keep doing it */
	}

	/* generate our identity for the packet */
	localstruct->ident = generate_ident();

	if (debug || here->checkent->trace)
	{
		print_err(0, "icmp.c:Created ICMP identity id of %d", localstruct->ident);
	}

	/* Send the initial ping */
	pinger_v4(localstruct, here);

	if (debug || here->checkent->trace)
	{
		print_err(here->checkent->trace, "icmp.c:Sent an ICMP echo-request to %s",
			here->checkent->hostname);
	}

	/* Track the last time that we sent a ping */
	gettimeofday(&localstruct->lastsentat, NULL);

	/* end of setup, we send the packet, and leave it at that  -- 
		service_test_ping watches for replies*/

	return;
}

void	service_test_ping(struct monitorent *here, struct timeval *now_timeval)
{
	struct pingdata *localstruct = NULL;

	if (here == NULL)
	{
		return;
	}
	/* This must be done first, else we're pointing to nowhere land */
	localstruct = here->monitordata;
	
	if (localstruct == NULL)
	{
		print_err(0, "icmp.c:bug - localstruct == NULL in icmp.c:service_test_ping");
		return;
	}
	memcpy(&here->lastserv, now_timeval, sizeof(struct timeval));

	/* Do some time calculation: */

	if (mydifftime(localstruct->lastsentat, here->lastserv) <= icmp_packet_delay)
		return;
		/* It's not time yet to watch for more packets */

       /* watch for icmp echo-replies and send more
		echo requests if we need to */

	/* If we've sent too many icmp echo-requests, bail out */
	if (debug || here->checkent->trace)
	{
		print_err(0, "icmp.c:service_test_ping:While pinging %s, packetsent = %d",
			here->checkent->hostname, localstruct->packetsent);
	}

	if ((localstruct->packetsent >= here->checkent->send_pings) &&
		(mydifftime(localstruct->lastsentat, here->lastserv) >= icmp_packet_delay))
	{
		/* if so, do the return thang */
		if (debug || here->checkent->trace)
		{
			print_err(1, "icmp.c: %s unpingable after %d attempts",
				here->checkent->hostname, 
				localstruct->packetsent);
		}
		here->retval = SYSM_UNPINGABLE; /* It's not pingable */
		FREE(localstruct->packet); /* Free our packet */
		FREE(localstruct); /* Free memory we'd normally leak */
		here->monitordata = NULL; /* tag memory as freed internally */
		return; /* go back to where we came from */
	}

	if (debug || here->checkent->trace)
		print_err(1, "comparing nreceived (%d) with min_pings (%d)",
			localstruct->nreceived, here->checkent->min_pings);

	/* if received is less than minimum and it's gt 1 second
	 * since last tx, send another
	 */
	if ((localstruct->nreceived < here->checkent->min_pings) &&
		(mydifftime(localstruct->lastsentat, here->lastserv) >= 1))
	{
		/* Send another ping */
		pinger_v4(localstruct, here);
		if (debug || here->checkent->trace)
		{
			print_err(here->checkent->trace, "icmp.c:Sent an ICMP echo-request to %s",
				here->checkent->hostname);
		}
	}

	/*
	 * if number received is gt the minimum, mark as ok and dequeue
	 */
	if (here->checkent->min_pings <= localstruct->nreceived)
	{
		here->retval = SYSM_OK;
		if (debug || here->checkent->trace)
		{
			print_err(0, "icmp.c:Got an ICMP reply from %s", here->checkent->hostname);
		}

		/* avoid leaking */
		FREE(localstruct->packet);

		/* Free memory we'd normally leak */
		FREE(localstruct);
	
		here->monitordata = NULL;
	}

	return;
}

/*
 * pinger_v4 --
 *      Compose and transmit an ICMP ECHO REQUEST packet.  The IP packet
 * will be added on by the kernel.  The ID field is a random (unused) ID
 * and the sequence number is an ascending integer.
 *
 */
void	pinger_v4(struct pingdata *localdata, struct monitorent *here)
{
	int send_octets, sendtoret;
	int serrno;

	if (glob_icmp_fd == -1)
		return;

	localdata->packetsent++;
	localdata->icp = (struct ICMPHDR *)localdata->outpack;/* cast it */
	localdata->icp->ICMP_TYPE = ICMP_ECHO;	/* It's an ICMP_ECHO */
	localdata->icp->ICMP_CODE = 0;		/* icmp_code subtype */
	localdata->icp->ICMP_CHECKSUM = 0;

		/* put the sequence in the packet */
	localdata->icp->ICMP_SEQ = localdata->packetsent;

		/* stick the icmp id in the packet */
	localdata->icp->ICMP_ECHO_ID = localdata->ident;

	CLR(localdata->icp->ICMP_SEQ % 1024);	/* Clear it */

	send_octets = ICMP_PACKET_SIZE;

	/* compute ICMP checksum here */
	localdata->icp->ICMP_CHECKSUM = in_cksum((u_short *)localdata->icp, send_octets);

	/* send the packet */
	sendtoret = sendto(glob_icmp_fd, (char *)localdata->outpack, 
		send_octets, 0, &localdata->ping_target, sizeof(struct sockaddr));
	serrno = errno;

	if (sendtoret < 0 || sendtoret != send_octets)  
	{
	        switch(serrno)
	        {
	                case ENETUNREACH:
	                        here->retval = SYSM_NETUNRCH;
				return;
	                case EHOSTDOWN:
	                case EHOSTUNREACH:
	                        here->retval =  SYSM_HOSTDOWN;
				return;
			default:
			/* A new one to me */
				perror("icmp.c:pinger_v4:sendto");
		}
	}
	/* Track it */
	gettimeofday(&localdata->lastsentat, NULL);
}

/*
 * in_cksum --
 *	Checksum routine for Internet Protocol family headers (C Version)
 */
unsigned short in_cksum(addr, len)
        u_short *addr;
        int len;
{
        int nleft, sum;
        u_short *w;
        union {
                u_short us;
                u_char  uc[2];
        } last;
        u_short answer;

        nleft = len;
        sum = 0;
        w = addr;

        /*
         * Our algorithm is simple, using a 32 bit accumulator (sum), we add
         * sequential 16 bit words to it, and at the end, fold back all the
         * carry bits from the top 16 bits into the lower 16 bits.
         */
        while (nleft > 1)  {
                sum += *w++;
                nleft -= 2;
        }

        /* mop up an odd byte, if necessary */
        if (nleft == 1) {
                last.uc[0] = *(u_char *)w;
                last.uc[1] = 0;
                sum += last.us;
        }

        /* add back carry outs from top 16 bits to low 16 bits */
        sum = (sum >> 16) + (sum & 0xffff);     /* add hi 16 to low 16 */
        sum += (sum >> 16);                     /* add carry */
        answer = ~sum;                          /* truncate to 16 bits */
        return(answer);
}

void    stop_test_ping(struct monitorent *here)
{
	struct pingdata *localstruct = NULL;

	localstruct = here->monitordata;

	if (localstruct != NULL)
	{
		if (localstruct->packet != NULL)
		{
			FREE(localstruct->packet); /* Free our packet */
		}
		FREE(localstruct);

	}
	here->monitordata = NULL;
	return;
}

/*
 * ===================================================================
 * PACKET LOSS MONITORING IMPLEMENTATION
 * ===================================================================
 */

/*
 * pktloss_add_sample - Add a sample to the packet loss history
 *
 * Adds a new sample to the circular buffer, overwriting oldest if full.
 * Updates running totals with overflow protection.
 */
void pktloss_add_sample(struct pktloss_data *data, time_t timestamp,
                        unsigned int sent, unsigned int rcvd)
{
	struct pktloss_sample *sample;
	unsigned int lost;

	if (data == NULL) {
		print_err(1, "pktloss_add_sample: NULL data pointer");
		return;
	}

	/* Calculate packets lost */
	lost = (sent > rcvd) ? (sent - rcvd) : 0;

	/* Get current sample slot (circular buffer) */
	sample = &data->history[data->history_head];

	/* Store sample data */
	sample->timestamp = timestamp;
	sample->sent = sent;
	sample->received = rcvd;
	sample->lost = lost;

	/* Advance head (circular) */
	data->history_head = (data->history_head + 1) % PKTLOSS_HISTORY_SIZE;

	/* Update count (max at buffer size) */
	if (data->history_count < PKTLOSS_HISTORY_SIZE) {
		data->history_count++;
	}

	/* Update running totals with overflow protection */
	if (data->total_sent > (ULLONG_MAX - sent)) {
		/* Overflow would occur - reset counters */
		print_err(1, "pktloss: total_sent overflow, resetting counters");
		data->total_sent = sent;
		data->total_received = rcvd;
		data->total_lost = lost;
	} else {
		data->total_sent += sent;
		data->total_received += rcvd;
		data->total_lost += lost;
	}

	if (debug) {
		print_err(0, "pktloss: added sample - sent=%u rcvd=%u lost=%u",
		          sent, rcvd, lost);
	}
}

/*
 * start_test_pktloss - Initialize packet loss monitoring
 *
 * Allocates pktloss_data structure and embedded pingdata.
 * Sets up ICMP socket and prepares for packet loss tracking.
 */
void start_test_pktloss(struct monitorent *here)
{
	struct pktloss_data *pktdata;
	struct pingdata *localstruct;

	if (glob_icmp_fd == -1) {
		/* No ICMP socket - mark as OK and return */
		here->retval = SYSM_OK;
		return;
	}

	/* Allocate packet loss tracking structure */
	pktdata = MALLOC(sizeof(struct pktloss_data), "pktloss_data");
	if (pktdata == NULL) {
		print_err(1, "pktloss: MALLOC failed for pktloss_data");
		here->retval = SYSM_ERR;
		return;
	}

	/* Initialize to zero */
	memset(pktdata, 0, sizeof(struct pktloss_data));

	/* Allocate embedded pingdata structure */
	pktdata->ping = MALLOC(sizeof(struct pingdata), "pktloss_pingdata");
	if (pktdata->ping == NULL) {
		print_err(1, "pktloss: MALLOC failed for pingdata");
		FREE(pktdata);
		here->retval = SYSM_ERR;
		return;
	}

	/* Initialize pingdata */
	memset(pktdata->ping, 0, sizeof(struct pingdata));
	localstruct = pktdata->ping;

	/* Set up pingdata (same as start_test_ping) */
	here->filedes = -1;
	gettimeofday(&here->lastserv, NULL);

	localstruct->nreceived = 0;
	localstruct->packetsent = 0;
	localstruct->datap = &localstruct->outpack[8 + sizeof(struct timeval)];

	memset(&localstruct->ping_target, 0, sizeof(struct sockaddr));

	if (debug || here->checkent->trace) {
		print_err(here->checkent->trace,
		          "pktloss: setting up monitoring of %s",
		          here->checkent->hostname);
	}

	/* Set up target address */
	localstruct->to = (struct sockaddr_in *)&localstruct->ping_target;
	localstruct->to->sin_family = AF_INET;

	/* DNS lookup */
	localstruct->hp = my_gethostbyname(here->checkent->hostname, AF_INET);
	if (!localstruct->hp) {
		here->retval = SYSM_NODNS;
		FREE(localstruct);
		FREE(pktdata);
		here->monitordata = NULL;
		return;
	}

	localstruct->to->sin_family = localstruct->hp->h_addrtype_v4;
	memcpy((caddr_t)&localstruct->to->sin_addr,
	       localstruct->hp->my_h_addr_v4,
	       localstruct->hp->h_length_v4);

	/* Allocate packet buffer */
	localstruct->packet = (u_char *)MALLOC(ICMP_PACKET_SIZE, "pktloss_packet");
	if (!localstruct->packet) {
		print_err(1, "pktloss: out of memory for packet");
		here->retval = here->checkent->lastcheck;
		FREE(localstruct);
		FREE(pktdata);
		here->monitordata = NULL;
		return;
	}

	/* Fill packet data */
	for (localstruct->counter = 8; localstruct->counter < 128;
	     ++localstruct->counter) {
		*localstruct->datap++ = localstruct->counter;
	}

	/* Generate ICMP identity */
	localstruct->ident = generate_ident();

	if (debug || here->checkent->trace) {
		print_err(0, "pktloss: Created ICMP identity %d",
		          localstruct->ident);
	}

	/* Store pktloss_data in monitordata */
	here->monitordata = pktdata;

	/* Send initial ping */
	pinger_v4(localstruct, here);

	if (debug || here->checkent->trace) {
		print_err(here->checkent->trace,
		          "pktloss: Sent initial ICMP echo-request to %s",
		          here->checkent->hostname);
	}

	/* Track last send time */
	gettimeofday(&localstruct->lastsentat, NULL);
}

/*
 * service_test_pktloss - Monitor packet loss and update history
 *
 * Called periodically to:
 * 1. Send ICMP echo requests
 * 2. Track responses
 * 3. Record packet loss in history
 * 4. Check against tolerance threshold
 */
void service_test_pktloss(struct monitorent *here, struct timeval *now_timeval)
{
	struct pktloss_data *pktdata;
	struct pingdata *localstruct;
	unsigned int sent, rcvd, lost;
	time_t now;

	if (here == NULL) {
		return;
	}

	pktdata = here->monitordata;
	if (pktdata == NULL) {
		print_err(0, "pktloss: NULL monitordata");
		return;
	}

	localstruct = pktdata->ping;
	if (localstruct == NULL) {
		print_err(0, "pktloss: NULL pingdata");
		return;
	}

	memcpy(&here->lastserv, now_timeval, sizeof(struct timeval));

	/* Check if it's time to send more packets */
	if (mydifftime(localstruct->lastsentat, here->lastserv) <= icmp_packet_delay) {
		return; /* Not yet time */
	}

	if (debug || here->checkent->trace) {
		print_err(0, "pktloss: %s - sent=%d received=%d",
		          here->checkent->hostname,
		          localstruct->packetsent,
		          localstruct->nreceived);
	}

	/* Check if we've sent all pings */
	if ((localstruct->packetsent >= here->checkent->send_pings) &&
	    (mydifftime(localstruct->lastsentat, here->lastserv) >= icmp_packet_delay)) {

		/* Record this cycle's results */
		sent = localstruct->packetsent;
		rcvd = localstruct->nreceived;
		lost = sent - rcvd;

		time(&now);
		pktloss_add_sample(pktdata, now, sent, rcvd);

		if (debug || here->checkent->trace) {
			print_err(0, "pktloss: cycle complete - %u/%u lost (%.1f%%)",
			          lost, sent, (100.0 * lost) / sent);
		}

		/* Check tolerance */
		if (lost > here->checkent->pktloss_tolerance) {
			if (lost == sent) {
				/* 100% packet loss = unpingable */
				here->retval = SYSM_UNPINGABLE;
				if (debug || here->checkent->trace) {
					print_err(1, "pktloss: %s - 100%% loss (unpingable)",
					          here->checkent->hostname);
				}
			} else {
				/* Exceeds tolerance but not 100% */
				here->retval = SYSM_PKTLOSS_EXCEED;
				if (debug || here->checkent->trace) {
					print_err(1, "pktloss: %s - loss %u exceeds tolerance %u",
					          here->checkent->hostname,
					          lost, here->checkent->pktloss_tolerance);
				}
			}
		} else {
			/* Within tolerance */
			here->retval = SYSM_OK;
			if (debug || here->checkent->trace) {
				print_err(0, "pktloss: %s - within tolerance",
				          here->checkent->hostname);
			}
		}

		/* Clean up for this cycle */
		if (localstruct->packet) {
			FREE(localstruct->packet);
		}
		FREE(localstruct);
		FREE(pktdata);
		here->monitordata = NULL;
		return;
	}

	/* Send more pings if needed */
	if ((localstruct->nreceived < here->checkent->min_pings) &&
	    (mydifftime(localstruct->lastsentat, here->lastserv) >= 1)) {

		pinger_v4(localstruct, here);

		if (debug || here->checkent->trace) {
			print_err(here->checkent->trace,
			          "pktloss: Sent ICMP echo-request to %s",
			          here->checkent->hostname);
		}
	}

	/* Check if we have minimum required responses */
	if (here->checkent->min_pings <= localstruct->nreceived) {
		/* Have minimum, but continue to send_pings limit */
		if (localstruct->packetsent < here->checkent->send_pings) {
			/* Keep sending */
			return;
		}
	}
}

/*
 * stop_test_pktloss - Clean up packet loss monitoring
 *
 * Frees pktloss_data and embedded pingdata structures.
 */
void stop_test_pktloss(struct monitorent *here)
{
	struct pktloss_data *pktdata;
	struct pingdata *localstruct;

	pktdata = here->monitordata;

	if (pktdata != NULL) {
		localstruct = pktdata->ping;

		if (localstruct != NULL) {
			if (localstruct->packet != NULL) {
				FREE(localstruct->packet);
			}
			FREE(localstruct);
		}

		FREE(pktdata);
	}

	here->monitordata = NULL;
}

