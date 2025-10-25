/* $Id: tcp.c,v 1.15 2006/05/09 03:26:42 jared Exp $ */

#include "config.h"

/* all tcp functions to be moved/recoded into here */

/* All the variables needed to be passed along from start to
   end of the test */

struct tcpdata {
	time_t start;
	};

void	start_test_tcp(struct monitorent *here, time_t now_t)
{
	/* set up the check, start to connect() to the remote host
	   then let service_test_tcp() watch for the fd to be
	   writable */

	struct tcpdata *localstruct = NULL;
	struct my_hostent *hp = NULL;
        struct sockaddr_in name;
	int errcode = 0;
	
	/* Allocate our memory */
        here->monitordata = MALLOC(sizeof(struct tcpdata), "tcp localstruct");

	localstruct = here->monitordata;

	localstruct->start = now_t;

	here->filedes = open_sock();

	if (here->filedes == -1)
	{
		print_err(1, "tcp.c: Unable to open a socket, unable to perform check on %s", here->checkent->hostname);
		/* Bad error, code around it later */
		here->retval = here->checkent->lastcheck;
		FREE(here->monitordata);
		here->monitordata = NULL;
		return;
	}

	hp = my_gethostbyname(here->checkent->hostname, AF_INET);

	/* If unable to perform check, because of dns, return */
	if (hp == NULL)
	{
		here->retval = SYSM_NODNS;
		FREE(here->monitordata);
		here->monitordata = NULL;
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
		print_err(0, "start_test_tcp() doing connect() to %s:%d", 
			here->checkent->hostname, here->checkent->port);

        errcode = connect(here->filedes, (struct sockaddr*)&name,
                sizeof(struct sockaddr_in));

        if ((errcode < 0) && (errno != EINPROGRESS))
        {
                if (errno == ECONNREFUSED || errno == EINTR)
                {
                        here->retval = SYSM_CONNREF;
                } else if (errno == ENETUNREACH) {
                        here->retval = SYSM_NETUNRCH; /* Network Unreachable */
                } else if (errno==EHOSTDOWN || errno==EHOSTUNREACH) {
                        here->retval = SYSM_HOSTDOWN; /* Host down */
                } else if (errno == ETIMEDOUT) {
                        here->retval = SYSM_TIMEDOUT; /* Conn timed out */
                }
		close(here->filedes);

                /* Free memory we'd normally leak */
                FREE(localstruct);
                here->monitordata = NULL;

                return;
        } 

	/* poll it again later */
	return;

}

void
service_test_tcp(struct monitorent *here, time_t now_t)
{
	/* take the check started by start_test_tcp() and watch our
	   fd for is_open() status, so we can close it down, and
	   let folks know that the port is answering.  Timeout is
	   either the kernel timeout, or 30 seconds from test start
	   time.  This time can be reconfigured */

	struct tcpdata *localstruct = NULL;
	int isopenretval = -1;

	if (debug)
	{
		print_err(0, "doing service_test_tcp() of %s:%d",
			here->checkent->hostname, here->checkent->port);
	}

	localstruct = here->monitordata;
	if (localstruct == NULL)
	{
		print_err(0, "bug - localstruct == NULL in tcp.c:service_test_tcp");
		return;
	}

	isopenretval = is_open(here->filedes);
	if ((isopenretval != -1) && (isopenretval != SYSM_INPROG))
	{
		if (debug)
		{
			print_err(0, "is_open() in srv_test_tcp() returned true");
		}
		here->retval = isopenretval;
		close(here->filedes);
		FREE(localstruct);
		here->monitordata = NULL;
		if (debug)
		{
			print_err(0, "ending service_test_tcp() with retval = %s",
				errtostr(here->retval));
		}
		return;
	}

        gettimeofday(&here->lastserv, NULL);

	if (((now_t)-localstruct->start) >= globtimeout) 
	{
		here->retval = SYSM_TIMEDOUT;
		close(here->filedes);
                FREE(localstruct);
                here->monitordata = NULL;
                if (debug)
		{
			print_err(0, "ending service_test_tcp() with retval = %s",
				errtostr(here->retval));
		}
                return;
	}

	return;
}

void
stop_test_tcp(struct monitorent *here)
{
        struct tcpdata *localstruct = NULL;
	
	localstruct = here->monitordata;

	if (localstruct != NULL)
	{
		close(here->filedes);
		FREE(localstruct);
	}
	here->monitordata = NULL;
        return;
}

