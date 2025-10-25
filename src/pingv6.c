/* $Id: pingv6.c,v 1.12 2012/01/10 02:46:48 jared Exp $ */

#include "config.h"

#ifdef HAVE_IPv6

int debug_pingv6 = 0;

/* structure that carries all the ipv6 ping related data */
struct pingv6data {
	unsigned int ident;			/* duh */
        struct icmp6_hdr *i6cmphdr;
	int hlen;
        unsigned char outpack[128];		/* the packet we output */
	unsigned char cmsgbuf[4096];		/* options */
	unsigned int cmsglen;			/* length of cmsgbuf */
	unsigned int ntransmitted;		/* duh */
	unsigned int nreceived;
	unsigned char *packet;
	unsigned char *datap;
	struct hostent *hp;
        int counter;
	struct sockaddr_in6 ping_target;	/* what to ping */
	struct sockaddr_in6 *to;
        struct timeval lastsentat;
	char rcvd_tbl[8192];
} tempv6;

/* Amount of time to wait for icmp response before doing
 * next packet
 */
unsigned int ping6_packet_delay = 1; /* delay in seconds */


#define A(bit)          tempv6.rcvd_tbl[(bit)>>3]  /* identify byte in array */
#define B(bit)          (1 << ((bit) & 0x07))   /* identify bit in byte */
#define SET(bit)        (A(bit) |= B(bit))
#define CLR(bit)        (A(bit) &= (~B(bit)))
#define TST(bit)        (A(bit) & B(bit))


/*
 * pinger_v6 --
 *      Compose and transmit an ICMP ECHO REQUEST packet.  The IP packet
 * will be added on by the kernel.  The ID field is our UNIX process ID,
 * and the sequence number is an ascending integer.  The first 8 bytes
 * of the data portion are used to hold a UNIX "timeval" struct in VAX
 * byte-order, to compute the round-trip time.
 */
void pinger_v6(struct pingv6data *localdata, struct monitorent *here)
{
        struct icmp6_hdr *icmph;
	unsigned int mx_dup_ck = 65536;
        int send_octets;
        int ret1;
	int serrno;

        icmph = (struct icmp6_hdr *)localdata->outpack;
        icmph->icmp6_type = ICMP6_ECHO_REQUEST;
        icmph->icmp6_code = 0;
        icmph->icmp6_cksum = 0;
        icmph->icmp6_seq = localdata->ntransmitted++;
        icmph->icmp6_id = localdata->ident;

        CLR(icmph->icmp6_seq % mx_dup_ck);

        send_octets = ICMP_PHDR_LEN + 8;                       /* skips ICMP portion */

	icmph->icmp6_cksum = in_cksum(localdata->outpack, send_octets);

	ret1 = sendto(glob_icmpv6_fd, localdata->outpack, send_octets, 0,
		(struct sockaddr *)&localdata->ping_target, sizeof(struct sockaddr_in6));

	if (debug|debug_pingv6)
		print_err(1, "pingv6.c:sendto got %d", ret1);

        serrno = errno;

        if (ret1 < 0 || ret1 != send_octets)
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
                                perror("pingv6.c:pinger_v6:sendto");
                }
        }
        /* Track it */
        gettimeofday(&localdata->lastsentat, NULL);


}

/*
 * Set up the global ICMPv6 packet listener socket
 */
void setup_icmpv6_fd()
{
	int retval = -1;
	unsigned int hold = ICMP_HOLD_QUEUE; /* Default hold queue size */

	/* Establish IPv6 socket */
	glob_icmpv6_fd = socket(AF_INET6, SOCK_RAW, IPPROTO_ICMPV6);
	if (glob_icmpv6_fd == -1)
	{
		/* Display an error */
		print_err(1, "pingv6.c:setup_icmpv6_fd() errno=%d", errno);
	}

	/* If success, update the queue size */
	if (glob_icmpv6_fd>0)
	{
	        retval = -1;
	        while (retval == -1)
	        {
	                retval = setsockopt(glob_icmpv6_fd, SOL_SOCKET,
	                        SO_RCVBUF, (char *)&hold, sizeof(hold));

	                if (retval == -1)
	                {
	                        if (errno == ENOBUFS)
	                        {
	                                hold = hold- (hold / 4);
	                                continue;
	                        }
	                        perror("pingv6.c:setsockopt");
	                        print_err(1,
	                                "pingv6.c:setsockopt returned -1, errno = %d",
	                                errno);
	                        break;
	                }
	        }
	        print_err(0, "sysmond: INFO: hold queue set to %d for icmpv6 packets", hold);
	}

}


void start_test_pingv6(struct monitorent *checkme)
{
	struct pingv6data *localstruct = NULL;

        if (glob_icmpv6_fd == -1)
        {
                /* If there is no icmp fd, say it's ok */
                checkme->retval = SYSM_OK;
                return;
        }
        checkme->monitordata=MALLOC(sizeof(struct pingv6data),"icmpv6-localstruct");

        memset(checkme->monitordata, 0, sizeof(struct pingv6data));

        localstruct = checkme->monitordata;

        gettimeofday(&checkme->lastserv, NULL);

        localstruct->nreceived = 0; /* zero it out */

        localstruct->ntransmitted = 0; /* zero it out */

        localstruct->datap = &localstruct->outpack[8 + sizeof(struct timeval)];

        /* initalize the variable */
        memset(&localstruct->ping_target, 0, sizeof(struct sockaddr));

        if (debug|debug_pingv6)
        {
                print_err(0, "setting up ping of host %s",
                        checkme->checkent->hostname);
        }

        /* set to */
        localstruct->to = (struct sockaddr_in6 *)&localstruct->ping_target;

        /* set family as IPv6 */
        localstruct->to->sin6_family = AF_INET6;

        /* do a dns lookup on the hostname we're being passed */
        localstruct->hp = gethostbyname2(checkme->checkent->hostname, AF_INET6);

        if (!localstruct->hp)  /* did we get an error doing a dns query */
        {
                /* if so, do the return thang */
                checkme->retval = SYSM_NODNS;
                FREE(localstruct);
                checkme->monitordata = NULL;
                return; /* can't forget this else we core */
        }

        /* set the family type */
        localstruct->to->sin6_family = AF_INET6;

        memcpy((caddr_t)&localstruct->to->sin6_addr, localstruct->hp->h_addr,
                localstruct->hp->h_length);

        if (!(localstruct->packet = (u_char *)MALLOC(ICMP_PACKET_SIZE, "pingv6.c:packet_data")))
        {
                /* aie!! */
                print_err(0, "pingv6.c: out of memory.");
                checkme->retval = checkme->checkent->lastcheck;
                FREE(localstruct);
                checkme->monitordata = NULL;
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

        if (debug|debug_pingv6)
        {
                print_err(0, "pingv6.c:Created ICMP identity id of %d", localstruct->ident);
        }

        /*  Send a ping */
        pinger_v6(localstruct, checkme);

        if (debug|debug_pingv6)
        {
                print_err(0, "pingv6.c:Sent an ICMP echo-request to %s",
                        checkme->checkent->hostname);
        }

        /* Track the last time that we sent a ping */
        gettimeofday(&localstruct->lastsentat, NULL);

        /* end of setup, we send the packet, and leave it at that  --
                service_test_ping watches for replies*/

        return;
}

void service_test_pingv6(struct monitorent *here)
{
        struct pingv6data *localstruct = NULL;
        struct timeval right_now;
        
        if (here == NULL)
        {
                return;
        }
        /* This must be done first, else we're pointing to nowhere land */
        localstruct = here->monitordata;
        if (localstruct == NULL)
        {
                print_err(0, "pingv6.c:bug - localstruct == NULL in pingv6.c:service_test_pingv6");
                return;
        }
        gettimeofday(&here->lastserv, NULL);

        /* Do some time calculation: */

        gettimeofday(&right_now, NULL);

        if (mydifftime(localstruct->lastsentat, right_now) <= ping6_packet_delay)
                return;
                /* It's not time yet to watch for more packets */

       /* watch for icmp echo-replies and send more
                echo requests if we need to */

        /* If we've sent too many icmp echo-requests, bail out */
        if (debug)
        {
                print_err(0, "pingv6.c:service_test_pingv6:While pinging %s, packetsent = %d",
                        here->checkent->hostname, localstruct->ntransmitted);
        }

        if ((localstruct->ntransmitted >= here->checkent->send_pings) &&
                (mydifftime(localstruct->lastsentat, right_now) >= ping6_packet_delay))
        {
                /* if so, do the return thang */
                if (debug)
                {
                        print_err(1, "pingv6.c: %s unpingable after %d attempts",
                                here->checkent->hostname,
                                localstruct->ntransmitted);
                }
                here->retval = SYSM_UNPINGABLE; /* It's not pingable */
                FREE(localstruct->packet); /* Free our packet */
                FREE(localstruct); /* Free memory we'd normally leak */
                here->monitordata = NULL; /* tag memory as freed internally */
                return; /* go back to where we came from */
        }

        gettimeofday(&right_now, NULL);
        if (debug)
                print_err(1, "pingv6.c:comparing nreceived (%d) with min_pings (%d)\n",  
                        localstruct->nreceived, here->checkent->min_pings);

        if ((localstruct->nreceived < here->checkent->min_pings) &&
                (mydifftime(localstruct->lastsentat, right_now) >= 2))
        {
                /* Send another ping */
                pinger_v6(localstruct, here); 
                if (debug)
                {
                        print_err(0, "pingv6.c:Sent an ICMP echo-request to %s",
                                here->checkent->hostname);
                }
        }

        /* Execution should reach here only upon one circumstance:
                We received an ICMP response from the host in question.
         */
         
        if (here->checkent->min_pings <= localstruct->nreceived)
        {
                here->retval = SYSM_OK;
                if (debug)
                {
                        print_err(0, "pingv6.c:Got an ICMP reply from %s", here->checkent->hostname);
                }
                
                /* no leaking please */
                FREE(localstruct->packet);
                
                /* Free memory we'd normally leak */
                FREE(localstruct);

                here->monitordata = NULL;
        }

	return;
}

void stop_test_pingv6(struct monitorent *checkme)
{
        struct pingv6data *localstruct = NULL;
                
        localstruct = checkme->monitordata;
 
        if (localstruct != NULL)
        {
                if (localstruct->packet != NULL)
                {
                        FREE(localstruct->packet); /* Free our packet */
                }
                FREE(localstruct);
   
        }
        checkme->monitordata = NULL;
	return;
}


/*
 * Handle the icmp responses we may get, and coordinate the
 * responses appropriateley
 */
void    handle_pingv6_responses()
{
        struct monitorent *here;
        struct pingv6data *localstruct = NULL;
        struct pingv6data rcvd_data;
        struct sockaddr_in from;
        char rcvd_pkt[ICMP_PACKET_SIZE];
        int ret, fromlen;

	if (debug)
		print_err(1, "entering handle_pingv6_responses()");
        if (glob_icmpv6_fd == -1)
        {
                return;
        }

        fromlen = sizeof(from); /* no comment */

        while (data_waiting_read(glob_icmpv6_fd, 0))
        {
                if ((ret = recvfrom(glob_icmpv6_fd, 
                        rcvd_pkt, ICMP_PACKET_SIZE, 0,
                        (struct sockaddr *)&from, &fromlen)) < 0)
                {
                        if (errno == EINTR) /* if we get interrupted */
                        {
                                print_err(1, "pingv6.c: got interrupted while attempting to recvfrom");
                                continue; /* and try again */
                        }
                        perror("pingv6.c: recvfrom");
                        continue; /* try again */
                }
		if (debug|debug_pingv6)
			print_err(1, "pingv6.c: have a packet, len = %d attempting to parse", ret);

                /* Check the IPv6 header */
                rcvd_data.i6cmphdr = (struct icmp6_hdr *)rcvd_pkt;
		rcvd_data.hlen = ret;

                /* if not an echo reply, skip it */
                if (rcvd_data.i6cmphdr->icmp6_type != ICMP6_ECHO_REPLY)
                        continue;

                /* determine if it was ours */

                /* Walk the queue to find active checks that are ping/icmp type */
                for (here = queuehead; here != NULL; here = here->next)
                {
                        if (here->checkent->type != SYSM_TYPE_PINGv6)
                        {
                                continue;
                        }
                        /* address the check */
                        localstruct = here->monitordata;

                        if (localstruct == NULL)
                                continue;

                        /* 
                         * Do some debugging and print out what we
                         * generated with what we got back
                         */
                        /* Compare received IDENT with the one that we sent */
                        if (debug)
                                print_err(1, "comparing rcvd_data echo_id w/ ident sent (got %d and %d was sent)", rcvd_data.i6cmphdr->icmp6_id, localstruct->ident);

                        if (rcvd_data.i6cmphdr->icmp6_id == localstruct->ident)
                        {
                                if (debug_pingv6)
                                {
                                        print_err(1, "got a reply for ping check of %s", here->checkent->hostname);
                                }
                                /* Increment our count */
                                localstruct->nreceived++;
                        }
                }
        }
}


#endif /* HAVE_IPv6 */

