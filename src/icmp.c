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

