/* $Id: icmp.c,v 1.64 2014/07/09 16:29:39 jared Exp $ */
#include "config.h"
#include <math.h>
#include "ping-helper.h"

extern struct protoent *icmpproto;
extern int glob_icmp_fd;
extern unsigned short int use_ping_helper;  /* From syswatch.c */

/* Forward declarations */
static int pinger_v4_via_helper(struct pingdata *localdata, struct monitorent *here);

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

	if (glob_icmp_fd == -1 && !use_ping_helper)
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

	/* Use ping helper if enabled */
	if (use_ping_helper) {
		if (pinger_v4_via_helper(localdata, here) == 0) {
			gettimeofday(&localdata->lastsentat, NULL);
		}
		return;
	}

	/* send the packet directly (traditional method) */
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
 * pinger_v4_via_helper - Send ICMP packet via setuid helper
 *
 * This function invokes the sysmon-ping-helper to send ICMP packets.
 * Used when running unprivileged to avoid needing root/CAP_NET_RAW.
 */
static int pinger_v4_via_helper(struct pingdata *localdata, struct monitorent *here)
{
	struct ping_helper_request req;
	int pipefd[2];
	pid_t pid;
	int status;
	ssize_t written;

	/* Build request for helper */
	memset(&req, 0, sizeof(req));
	req.address_family = HELPER_AF_INET;
	req.protocol = HELPER_PROTO_ICMP;
	memcpy(&req.dest.v4, &localdata->ping_target, sizeof(req.dest.v4));

	/* Copy ICMP packet */
	if (ICMP_PACKET_SIZE > MAX_PING_PACKET_SIZE) {
		print_err(1, "ICMP packet size too large for helper");
		here->retval = SYSM_ERR;
		return -1;
	}

	memcpy(req.packet, localdata->outpack, ICMP_PACKET_SIZE);
	req.packet_len = ICMP_PACKET_SIZE;

	/* Create pipe for communication */
	if (pipe(pipefd) < 0) {
		perror("pinger_v4_via_helper: pipe");
		here->retval = SYSM_ERR;
		return -1;
	}

	/* Fork helper process */
	pid = fork();
	if (pid < 0) {
		perror("pinger_v4_via_helper: fork");
		close(pipefd[0]);
		close(pipefd[1]);
		here->retval = SYSM_ERR;
		return -1;
	}

	if (pid == 0) {
		/* Child process - exec helper */
		close(pipefd[1]);  /* Close write end */

		/* Redirect stdin to read end of pipe */
		if (dup2(pipefd[0], STDIN_FILENO) < 0) {
			perror("dup2");
			exit(1);
		}
		close(pipefd[0]);

		/* Exec the helper */
		execl(PING_HELPER_PATH, "sysmon-ping-helper", (char *)NULL);

		/* If we get here, exec failed */
		perror("execl");
		exit(1);
	}

	/* Parent process */
	close(pipefd[0]);  /* Close read end */

	/* Write request to helper */
	written = write(pipefd[1], &req, sizeof(req));
	if (written != sizeof(req)) {
		perror("pinger_v4_via_helper: write");
		close(pipefd[1]);
		waitpid(pid, &status, 0);
		here->retval = SYSM_ERR;
		return -1;
	}
	close(pipefd[1]);

	/* Wait for helper to complete */
	if (waitpid(pid, &status, 0) < 0) {
		perror("pinger_v4_via_helper: waitpid");
		here->retval = SYSM_ERR;
		return -1;
	}

	/* Check helper exit status */
	if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
		print_err(1, "ping-helper failed with status %d",
		          WIFEXITED(status) ? WEXITSTATUS(status) : -1);
		here->retval = SYSM_ERR;
		return -1;
	}

	/* Success */
	return 0;
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

/*
 * ============================================================================
 * RTT (Round-Trip Time) and Jitter Measurement (SAA-lite)
 * ============================================================================
 *
 * Implements latency and jitter monitoring for VoIP quality assessment
 * and network performance monitoring.
 *
 * Features:
 * - ICMP-based RTT measurement
 * - RFC 3550 jitter calculation
 * - Rolling average over N samples
 * - Per-host thresholds
 */

/* RTT tracking structure */
struct rtt_data {
	struct pingdata *ping;              /* Reuse existing ICMP infrastructure */

	/* RTT tracking */
	double rtt_current;                 /* Current RTT in milliseconds */
	double rtt_min;                     /* Minimum RTT seen */
	double rtt_max;                     /* Maximum RTT seen */
	double rtt_avg;                     /* Rolling average RTT */
	double rtt_sum;                     /* Sum for averaging */
	unsigned int rtt_count;             /* Number of RTT samples collected */

	/* Jitter tracking (RFC 3550 algorithm) */
	double jitter_current;              /* Current jitter in milliseconds */
	double rtt_previous;                /* Previous RTT for jitter calculation */

	/* Timing */
	struct timeval last_send_time;      /* When we sent last packet */
};

/*
 * calculate_rtt_ms - Calculate RTT in milliseconds
 *
 * Calculates the time difference between send and receive timestamps.
 *
 * Returns: RTT in milliseconds (double precision)
 */
static double calculate_rtt_ms(struct timeval *send, struct timeval *recv)
{
	double elapsed;

	elapsed = (recv->tv_sec - send->tv_sec) * 1000.0;
	elapsed += (recv->tv_usec - send->tv_usec) / 1000.0;

	return elapsed;
}

/*
 * update_jitter - Update jitter using RFC 3550 algorithm
 *
 * Implements the jitter calculation from RFC 3550 (RTP):
 *   D = |RTT_current - RTT_previous|
 *   jitter = jitter + (D - jitter) / 16
 *
 * This provides a smoothed average of packet delay variation,
 * which is the key metric for VoIP quality assessment.
 */
static void update_jitter(struct rtt_data *data, double rtt)
{
	double diff;

	if (data == NULL) {
		return;
	}

	/* RFC 3550 jitter calculation */
	diff = fabs(rtt - data->rtt_previous);
	data->jitter_current = data->jitter_current + (diff - data->jitter_current) / 16.0;
}

/*
 * start_test_rtt - Initialize RTT/jitter monitoring
 *
 * Sets up ICMP-based RTT monitoring with jitter calculation.
 * Allocates resources and sends the first probe packet.
 */
void start_test_rtt(struct monitorent *here)
{
	struct rtt_data *rttdata;
	struct pingdata *localstruct;

	/* Check ICMP socket available */
	if (glob_icmp_fd == -1) {
		here->retval = SYSM_OK;
		return;
	}

	/* Allocate RTT tracking structure */
	rttdata = MALLOC(sizeof(struct rtt_data), "rtt_data");
	if (rttdata == NULL) {
		print_err(1, "start_test_rtt: MALLOC failed for rtt_data");
		here->retval = SYSM_ERR;
		return;
	}
	memset(rttdata, 0, sizeof(struct rtt_data));

	/* Allocate embedded pingdata (similar to start_test_ping) */
	rttdata->ping = MALLOC(sizeof(struct pingdata), "rtt_pingdata");
	if (rttdata->ping == NULL) {
		print_err(1, "start_test_rtt: MALLOC failed for pingdata");
		FREE(rttdata);
		here->retval = SYSM_ERR;
		return;
	}
	memset(rttdata->ping, 0, sizeof(struct pingdata));
	localstruct = rttdata->ping;

	/* Initialize RTT statistics */
	rttdata->rtt_min = 999999.0;
	rttdata->rtt_max = 0.0;
	rttdata->rtt_avg = 0.0;
	rttdata->rtt_sum = 0.0;
	rttdata->rtt_count = 0;
	rttdata->jitter_current = 0.0;
	rttdata->rtt_previous = 0.0;

	/* Setup pingdata (same pattern as start_test_ping) */
	here->filedes = -1;
	gettimeofday(&here->lastserv, NULL);

	localstruct->nreceived = 0;
	localstruct->packetsent = 0;
	localstruct->datap = &localstruct->outpack[8 + sizeof(struct timeval)];

	/* Initialize ping_target */
	memset(&localstruct->ping_target, 0, sizeof(struct sockaddr));
	localstruct->to = (struct sockaddr_in *)&localstruct->ping_target;
	localstruct->to->sin_family = AF_INET;

	/* DNS lookup */
	localstruct->hp = my_gethostbyname(here->checkent->hostname, AF_INET);
	if (!localstruct->hp) {
		FREE(rttdata->ping);
		FREE(rttdata);
		here->retval = SYSM_NODNS;
		return;
	}

	/* Set address family and copy address */
	localstruct->to->sin_family = localstruct->hp->h_addrtype_v4;
	memcpy((caddr_t)&localstruct->to->sin_addr, localstruct->hp->my_h_addr_v4,
		localstruct->hp->h_length_v4);

	/* Allocate packet buffer */
	if (!(localstruct->packet = (u_char *)MALLOC(ICMP_PACKET_SIZE, "rtt_packet"))) {
		print_err(1, "start_test_rtt: out of memory for packet");
		FREE(rttdata->ping);
		FREE(rttdata);
		here->retval = SYSM_ERR;
		return;
	}

	/* Fill data pattern */
	for (localstruct->counter = 8; localstruct->counter < 128; ++localstruct->counter) {
		*localstruct->datap++ = localstruct->counter;
	}

	/* Generate ICMP identity */
	localstruct->ident = generate_ident();

	if (debug || here->checkent->trace) {
		print_err(0, "RTT test started for %s (ident: %d, rtt_threshold: %u, jitter_threshold: %u, samples: %u)",
			here->checkent->hostname, localstruct->ident,
			here->checkent->rtt_threshold, here->checkent->jitter_threshold,
			here->checkent->rtt_samples);
	}

	/* Record send time before sending */
	gettimeofday(&rttdata->last_send_time, NULL);

	/* Send initial ping using existing pinger_v4 function */
	pinger_v4(localstruct, here);

	/* Track last send time */
	gettimeofday(&localstruct->lastsentat, NULL);

	/* Save rttdata to monitordata */
	here->monitordata = rttdata;
	here->retval = -1;  /* Pending result */
}

/*
 * service_test_rtt - Service RTT/jitter monitoring
 *
 * Checks for ICMP replies, calculates RTT and jitter, and determines
 * if thresholds are exceeded.
 */
void service_test_rtt(struct monitorent *here, struct timeval *now_timeval)
{
	struct rtt_data *rttdata;
	struct pingdata *ping;
	struct timeval recv_time;
	struct sockaddr_in from;
	socklen_t fromlen;
	char recv_buf[512];
	int recv_len;
	struct ip *ip_hdr;
	struct icmphdr *icmp_hdr;
	int ip_hdr_len;
	double rtt_ms;
	double elapsed_since_send;

	if (here == NULL || here->monitordata == NULL) {
		return;
	}

	rttdata = (struct rtt_data *)here->monitordata;
	ping = rttdata->ping;

	/* Check for ICMP reply */
	fromlen = sizeof(from);
	recv_len = recvfrom(glob_icmp_fd, recv_buf, sizeof(recv_buf), MSG_DONTWAIT,
	                    (struct sockaddr *)&from, &fromlen);

	if (recv_len > 0) {
		/* Record receive time immediately */
		gettimeofday(&recv_time, NULL);

		/* Validate minimum packet size for IP header */
		if (recv_len < sizeof(struct ip)) {
			if (debug) {
				print_err(1, "service_test_rtt: Received packet too small for IP header (%d bytes)", recv_len);
			}
			goto timeout_check;
		}

		/* Parse IP header */
		ip_hdr = (struct ip *)recv_buf;
		ip_hdr_len = ip_hdr->ip_hl << 2;

		/* Validate IP header length */
		if (ip_hdr_len < 20 || ip_hdr_len > recv_len) {
			if (debug) {
				print_err(1, "service_test_rtt: Invalid IP header length (%d), recv_len=%d", ip_hdr_len, recv_len);
			}
			goto timeout_check;
		}

		/* Validate enough space for ICMP header */
		if (recv_len < ip_hdr_len + (int)sizeof(struct icmphdr)) {
			if (debug) {
				print_err(1, "service_test_rtt: Packet too small for ICMP header (recv_len=%d, ip_hdr_len=%d)",
					recv_len, ip_hdr_len);
			}
			goto timeout_check;
		}

		/* Parse ICMP header */
		icmp_hdr = (struct icmphdr *)(recv_buf + ip_hdr_len);

		/* Check if this is our ICMP echo reply */
		if (icmp_hdr->type == ICMP_ECHOREPLY &&
		    icmp_hdr->un.echo.id == ping->ident) {

			/* Calculate RTT */
			rtt_ms = calculate_rtt_ms(&rttdata->last_send_time, &recv_time);

			/* Update RTT statistics */
			rttdata->rtt_current = rtt_ms;
			if (rtt_ms < rttdata->rtt_min) {
				rttdata->rtt_min = rtt_ms;
			}
			if (rtt_ms > rttdata->rtt_max) {
				rttdata->rtt_max = rtt_ms;
			}
			rttdata->rtt_sum += rtt_ms;
			rttdata->rtt_count++;
			rttdata->rtt_avg = rttdata->rtt_sum / rttdata->rtt_count;

			ping->nreceived++;

			/* Update jitter (if we have previous RTT) */
			if (rttdata->rtt_count > 1) {
				update_jitter(rttdata, rtt_ms);
			}
			rttdata->rtt_previous = rtt_ms;

			if (debug) {
				print_err(1, "RTT sample #%u: %.2fms (avg=%.2fms, jitter=%.2fms)",
					rttdata->rtt_count, rtt_ms, rttdata->rtt_avg,
					rttdata->jitter_current);
			}

			/* Check if we have enough samples */
			if (rttdata->rtt_count >= here->checkent->rtt_samples) {
				/* Threshold checking */
				if (rttdata->rtt_avg > here->checkent->rtt_threshold) {
					here->retval = SYSM_RTT_HIGH;

					if (debug) {
						print_err(1, "RTT threshold exceeded for %s: avg=%.2fms (threshold=%ums)",
							here->checkent->hostname, rttdata->rtt_avg,
							here->checkent->rtt_threshold);
					}
				} else if (here->checkent->jitter_threshold > 0 &&
				           rttdata->jitter_current > here->checkent->jitter_threshold) {
					here->retval = SYSM_JITTER_HIGH;

					if (debug) {
						print_err(1, "Jitter threshold exceeded for %s: jitter=%.2fms (threshold=%ums)",
							here->checkent->hostname, rttdata->jitter_current,
							here->checkent->jitter_threshold);
					}
				} else {
					here->retval = SYSM_OK;
				}

				/* Log final statistics */
				if (debug) {
					print_err(1, "RTT test complete for %s: min=%.2fms avg=%.2fms max=%.2fms jitter=%.2fms",
						here->checkent->hostname, rttdata->rtt_min, rttdata->rtt_avg,
						rttdata->rtt_max, rttdata->jitter_current);
				}

				/* Cleanup */
				FREE(ping->packet);
				FREE(ping);
				FREE(rttdata);
				here->monitordata = NULL;
				return;
			}

			/* Send another packet using pinger_v4 */
			gettimeofday(&rttdata->last_send_time, NULL);
			pinger_v4(ping, here);
			gettimeofday(&ping->lastsentat, NULL);
		}
	}

timeout_check:
	/* Check for timeout (30 seconds) */
	elapsed_since_send = calculate_rtt_ms(&rttdata->last_send_time, now_timeval);
	if (elapsed_since_send > 30000.0) {
		print_err(1, "RTT test timeout for %s after %.0fms",
			here->checkent->hostname, elapsed_since_send);
		here->retval = SYSM_TIMEDOUT;
		FREE(ping->packet);
		FREE(ping);
		FREE(rttdata);
		here->monitordata = NULL;
	}
}

/*
 * stop_test_rtt - Clean up RTT/jitter monitoring
 *
 * Frees all resources allocated for RTT monitoring.
 */
void stop_test_rtt(struct monitorent *here)
{
	struct rtt_data *rttdata;

	if (here == NULL || here->monitordata == NULL) {
		return;
	}

	rttdata = (struct rtt_data *)here->monitordata;

	if (rttdata != NULL) {
		if (rttdata->ping != NULL) {
			if (rttdata->ping->packet != NULL) {
				FREE(rttdata->ping->packet);
			}
			FREE(rttdata->ping);
		}
		FREE(rttdata);
	}

	here->monitordata = NULL;
}

