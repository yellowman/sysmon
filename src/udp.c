/* $Id: udp.c,v 1.16 2006/05/09 03:26:42 jared Exp $ */
#include "config.h"

/* all udp functions to be moved/recoded into here */

#define UDP_CONNECT	1 /* doing connect() */
#define UDP_SENT_PKT	2 /* sent a packet */
#define UDP_REXMIT	3 /* re-xmited pkt */
#define UDP_GOTRESP	4 /* got a response */

struct udpdata {
	unsigned char state;
	time_t start;
	time_t lastsent;
	unsigned int tries;
	};

void	start_test_udp(struct monitorent *here, time_t now_t)
{
	/* start a  test of an udp port on a remote server. do the
	   connect() part, and everything else so that service_test_udp
	   can find out if the port is working.  udp tests tend to be a
	   bit broken, as not all servers respond to bogus packets, and
	   since this is generic, it's hard to tell what will happen.  It
	   may crash some software */
	   

	struct udpdata *localstruct = NULL;
	struct my_hostent *hp = NULL;
        struct sockaddr_in name;
	int errcode = 0;
	
	/* Allocate our memory */
        here->monitordata = MALLOC(sizeof(struct udpdata), "udp-localstruct");

	localstruct = here->monitordata;

	memset(localstruct, 0, sizeof(localstruct));

	localstruct->start = now_t;
	localstruct->lastsent=localstruct->start;
	localstruct->tries = 0;
	here->filedes = udp_open_sock();

	if (here->filedes == -1)
	{
		print_err(1, "udp.c: unable to allocate a filedescriptor to perform check on %s", here->checkent->hostname);
		here->retval = here->checkent->lastcheck;
		FREE(here->monitordata);
		return;
	}

	hp = my_gethostbyname(here->checkent->hostname, AF_INET);

	if (hp == NULL)
	{
		here->retval = SYSM_NODNS;
		FREE(here->monitordata);
		return;
	}
	

        /* zero out the space */
        memset ( &name, 0, sizeof ( name ) );

        /* copy data */
        memcpy((char*)&name.sin_addr, (char*)hp->my_h_addr_v4, hp->h_length_v4);

        /* set family type */
        name.sin_family = AF_INET;

        /* set the port we're connecting to */
        name.sin_port = htons(here->checkent->port);

	if (debug)
	{
		print_err(0, "start_test_udp() doing connect() to %s:%d", 
			here->checkent->hostname, here->checkent->port);
	}

        errcode = connect(here->filedes, (struct sockaddr*)&name,
                sizeof(struct sockaddr_in));

        localstruct->start = now_t;

        if ((errcode < 0) && (errno != EINPROGRESS))
        {
                close(here->filedes);
		here->filedes = -1;
		switch(errno)
		{
			case ECONNREFUSED:
			case EINTR:
				here->retval = SYSM_CONNREF;
				break;
			case ENETUNREACH:
				here->retval = SYSM_NETUNRCH;
				break;
			case EHOSTDOWN:
			case EHOSTUNREACH:
                        	here->retval = SYSM_HOSTDOWN;
				break;
			case ETIMEDOUT:
				here->retval = SYSM_TIMEDOUT;
				break;
		}

                /* Free memory we'd normally leak */
                FREE(localstruct);
                here->monitordata = NULL;

                return;
        } 

	/* test set up -- check it again later */
	return;
}

void	service_test_udp(struct monitorent *here, time_t now_t)
{
	/* take the socket created in start_test_udp() and figure out
	   if connect() returned errors, and if we can send data to that
	   port and get a response, etc..
	 */

	struct udpdata *localstruct = NULL;
        char buf[100];         /* buffer */
	int errcode=0;
	int serrno=0;

	if (debug)
	{
		print_err(0, "doing service_test_udp() of %s:%d",
			here->checkent->hostname, here->checkent->port);
	}

	localstruct = here->monitordata;
	
	if (localstruct == NULL)
	{
		print_err(0, "bug! localstruct == NULL in udp.c:service_test_udp");
		return;
	}

	if (debug)
	{
		print_err(0, "service_test_tcp() now-lastsent = %d",
			(int)((now_t)-localstruct->lastsent));
	}
	if (((now_t)-localstruct->lastsent) <1)
	{
		return;
	}

	memset(buf, 0x33, sizeof(buf));

	if (data_waiting_read(here->filedes, 0))
	{
		if (debug)
			print_err(0, "service_test_tcp() calling recv()");
		errcode = recv(here->filedes, buf, sizeof(buf)-1, 0);
		if (debug)
			print_err(0, "recv() returned %d", errcode);
		if (errcode == -1)
		{
			serrno=errno;
			if (debug)
			{
				perror("udp.c:recv");
			}
		}
		/* if we received a response in any way shape or form */
		if (errcode > 0)
		{
			here->retval = SYSM_OK;
	                close(here->filedes);
			here->filedes = -1;
	                FREE(localstruct);
	                here->monitordata = NULL;
	                if (debug)
	                        print_err(0, "ending service_test_udp() with retval = %s",
	                                errtostr(here->retval));
	                return;
		}
	} else {
		errcode = send (here->filedes, buf, sizeof(buf), 0);
		if (errcode == -1)
		{
			print_err(0, "udp.c:sevice_test_udp:send returned %d", errcode);
			serrno=errno;
		}
                if (debug)
                {
			print_err(0, "service_test_udp() just sent %d", sizeof(buf));
                }

                localstruct->lastsent = now_t;

		localstruct->tries++;

		if (localstruct->tries >= MAX_TRIES)
		{
			here->retval = SYSM_TIMEDOUT;
			close(here->filedes);
			here->filedes = -1;
			FREE(localstruct);
			here->monitordata = NULL;
			if (debug)
				print_err(0, "ending service_test_udp() with retval = %s", errtostr(here->retval));
			return;
		}
	}
	if (serrno != 0)
	{
		/*
		** This is really digusting.  This really needs to go into
		** a seperate function.  I've seen this about 20 times now.
		** --Majdi
		*/

		switch(serrno)
		{
			case ECONNREFUSED:
			case EINTR:
                        	here->retval = SYSM_CONNREF;
				break;
			case ENETUNREACH:
				here->retval = SYSM_NETUNRCH;
				break;
			case EHOSTDOWN:
			case EHOSTUNREACH:
                        	here->retval = SYSM_HOSTDOWN;
				break;
			case ETIMEDOUT:
				here->retval = SYSM_TIMEDOUT;
				break;
			case EINPROGRESS:
				here->retval = SYSM_INPROG;
				break;
			case EBADF:
				here->retval = -1;
                }

		if (here->retval != 0)
		{
			close(here->filedes);
			here->filedes = -1;
			FREE(localstruct);
			here->monitordata = NULL;
			if (debug)
			{
				print_err(0, "ending service_test_udp() with retval = %s",
					errtostr(here->retval));
			}
		return;
		}
	}

	/* a timeout possibility */
	if (((now_t)-localstruct->start) >= globtimeout) 
	{
		here->retval = SYSM_TIMEDOUT;
		close(here->filedes);
		here->filedes = -1;
                FREE(localstruct);
                here->monitordata = NULL;
                if (debug)
		{
			print_err(0, "ending service_test_udp() with retval = %s",
				errtostr(here->retval));
		}
                return;
	}
	return;
}

int	udp_open_sock(int sock)
{
	/* Open a UDP network connection through the named socket */
	sock = socket(AF_INET, SOCK_DGRAM, 0);
	if (sock == -1)
	{
		if (debug)
		{
			perror("udp_open_sock: opening socket");
		}
		ABORT();
	}
	return sock;
}


void	stop_test_udp(struct monitorent *here)
{
        struct udpdata *localstruct = NULL;

        localstruct = here->monitordata;
	if (localstruct == NULL)
		return;

        close(here->filedes);
	here->filedes = -1;
        FREE(localstruct);
        here->monitordata = NULL;
        return;
}

