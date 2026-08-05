/* $Id: pingv6.c,v 1.12 2012/01/10 02:46:48 jared Exp $ */

#include "config.h"

#ifdef HAVE_IPv6

#include "ping-helper.h"

int debug_pingv6 = 0;

/* External flag from syswatch.c indicating whether to use ping helper */
extern unsigned short int use_ping_helper;

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

/* Forward declarations */
static int pinger_v6_via_helper(struct pingv6data *localdata, struct monitorent *here);

/*
 * pinger_v6_via_helper - Send ICMPv6 packet via setuid helper
 *
 * This function invokes the sysmon-ping-helper to send ICMPv6 packets.
 * Used when running unprivileged to avoid needing root/CAP_NET_RAW.
 */
static int pinger_v6_via_helper(struct pingv6data *localdata, struct monitorent *here)
{
	struct ping_helper_request req;
	int pipefd[2];
	pid_t pid;
	int status;
	ssize_t written;
	int send_octets;
	struct icmp6_hdr *icmph;
	static int helper_failed_once = 0;

	/* If helper has already failed, don't keep trying */
	if (helper_failed_once) {
		here->retval = SYSM_ERR;
		return -1;
	}

	/* Build ICMPv6 packet (same as pinger_v6) */
	icmph = (struct icmp6_hdr *)localdata->outpack;
	icmph->icmp6_type = ICMP6_ECHO_REQUEST;
	icmph->icmp6_code = 0;
	icmph->icmp6_cksum = 0;
	icmph->icmp6_seq = localdata->ntransmitted++;
	icmph->icmp6_id = localdata->ident;

	send_octets = ICMP_PHDR_LEN + 8;
	icmph->icmp6_cksum = in_cksum(localdata->outpack, send_octets);

	/* Build request for helper */
	memset(&req, 0, sizeof(req));
	req.address_family = HELPER_AF_INET6;
	req.protocol = HELPER_PROTO_ICMPV6;
	memcpy(&req.dest.v6, &localdata->ping_target, sizeof(req.dest.v6));

	/* Copy ICMPv6 packet */
	if (send_octets > MAX_PING_PACKET_SIZE) {
		print_err(1, "ICMPv6 packet size too large for helper");
		here->retval = SYSM_ERR;
		return -1;
	}

	memcpy(req.packet, localdata->outpack, send_octets);
	req.packet_len = send_octets;

	/* Create pipe for communication */
	if (pipe(pipefd) < 0) {
		perror("pinger_v6_via_helper: pipe");
		here->retval = SYSM_ERR;
		return -1;
	}

	/* Fork helper process */
	pid = fork();
	if (pid < 0) {
		perror("pinger_v6_via_helper: fork");
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
		perror("pinger_v6_via_helper: write");
		close(pipefd[1]);
		waitpid(pid, &status, 0);
		here->retval = SYSM_ERR;
		return -1;
	}
	close(pipefd[1]);

	/* Wait for helper to complete */
	if (waitpid(pid, &status, 0) < 0) {
		perror("pinger_v6_via_helper: waitpid");
		here->retval = SYSM_ERR;
		return -1;
	}

	/* Check helper exit status */
	if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
		/* First failure - log detailed error and disable helper permanently */
		print_err(1, "FATAL: Ping helper failed with status %d - helper will be disabled",
		          WIFEXITED(status) ? WEXITSTATUS(status) : -1);
		print_err(1, "FATAL: ICMPv6 checks will fail - install helper at %s with setuid permissions",
		          PING_HELPER_PATH);
		print_err(1, "FATAL: Run 'make install' in src/ directory to install helper properly");

		/* Disable helper globally to prevent spam */
		use_ping_helper = 0;
		helper_failed_once = 1;

		here->retval = SYSM_ERR;
		return -1;
	}

	/* Success */
	return 0;
}

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

	/*
	 * Build the packet first, then send it on our own socket if we
	 * have one - see pinger_v4() for why that works after the
	 * privilege drop, and what forking a helper per packet cost.
	 * setup_icmpv6_fd() opens this socket in the same root window as
	 * the v4 one.
	 */
        icmph = (struct icmp6_hdr *)localdata->outpack;
        icmph->icmp6_type = ICMP6_ECHO_REQUEST;
        icmph->icmp6_code = 0;
        icmph->icmp6_cksum = 0;
        icmph->icmp6_seq = localdata->ntransmitted++;
        icmph->icmp6_id = localdata->ident;

        CLR(icmph->icmp6_seq % mx_dup_ck);

        send_octets = ICMP_PHDR_LEN + 8;                       /* skips ICMP portion */

	icmph->icmp6_cksum = in_cksum(localdata->outpack, send_octets);

	if (glob_icmpv6_fd != -1)
	{
		ret1 = sendto(glob_icmpv6_fd, localdata->outpack, send_octets, 0,
			(struct sockaddr *)&localdata->ping_target,
			sizeof(struct sockaddr_in6));

		if (debug||debug_pingv6)
			print_err(1, "pingv6.c:sendto got %d", ret1);

		serrno = errno;

		if (ret1 == send_octets)
		{
			gettimeofday(&localdata->lastsentat, NULL);
			return;
		}

		switch(serrno)
		{
			case ENETUNREACH:
				here->retval = SYSM_NETUNRCH;
				return;
			case EHOSTDOWN:
			case EHOSTUNREACH:
				here->retval =  SYSM_HOSTDOWN;
				return;
			case EPERM:
			case EACCES:
				/* Refused after the drop: fall through to the
				 * helper, which sends as root. */
				break;
			default:
			/* A new one to me */
				perror("pingv6.c:pinger_v6:sendto");
				return;
		}
	}

	/* No usable socket, or it refused us. */
	if (use_ping_helper) {
		if (pinger_v6_via_helper(localdata, here) == 0) {
			gettimeofday(&localdata->lastsentat, NULL);
		}
	}
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

        if (debug||debug_pingv6)
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

        if (debug||debug_pingv6)
        {
                print_err(0, "pingv6.c:Created ICMP identity id of %d", localstruct->ident);
        }

        /*  Send a ping */
        pinger_v6(localstruct, checkme);

        if (debug||debug_pingv6)
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

        /* After sending all pings, wait longer before declaring unpingable.
         * Use 2x ping6_packet_delay (2 seconds default) to allow for moderate
         * latency while keeping checks responsive. The original 1-second timeout
         * was causing false negatives for hosts with >1s RTT.
         */
        if ((localstruct->ntransmitted >= here->checkent->send_pings) &&
                (mydifftime(localstruct->lastsentat, right_now) >= (ping6_packet_delay * 2)))
        {
                /* if so, do the return thang */
                if (debug)
                {
                        print_err(1, "pingv6.c: %s unpingable after %d attempts (waited %.1fs after last ping)",
                                here->checkent->hostname,
                                localstruct->ntransmitted,
                                mydifftime(localstruct->lastsentat, right_now));
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
        /* Must be sockaddr_in6: with sockaddr_in the kernel truncated the
         * reply's source address, which is also why it was never checked. */
        struct sockaddr_in6 from;
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
		if (debug||debug_pingv6)
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

                        /* Ident AND source address - see the comment in
                         * icmp.c handle_icmp_responses(). */
                        if (rcvd_data.i6cmphdr->icmp6_id == localstruct->ident &&
                            localstruct->to != NULL &&
                            memcmp(&from.sin6_addr, &localstruct->to->sin6_addr,
                                   sizeof(from.sin6_addr)) == 0)
                        {
                                if (debug_pingv6)
                                {
                                        print_err(1, "got a reply for ping check of %s", here->checkent->hostname);
                                }
                                /* Increment our count */
                                localstruct->nreceived++;

                                /* a reply belongs to exactly one check */
                                break;
                        }
                }
        }
}


#endif /* HAVE_IPv6 */

