/* $Id: umichX500.c,v 1.13 2006/05/09 03:26:42 jared Exp $ */
#include "config.h"
/* (c) 1996-1997 Jared Mauch - All Rights Reserved */

/* code to check x.500 replication to be sure it's ok.  Very specific
   to the University of Michigan, it's totally a local hack, as this
   object of the code is also 
 */
struct x500data {
	int state;
	time_t start;
};

#define X500_CONNECT	1 /* doing connect() */
#define X500_CONNECTED	2 /* connect()'ed */

void	start_test_x500(struct monitorent *here, time_t now_t)
{
	/* set up the check, start to connect() to the remote host
	   then let service_test_x500() watch for the fd to be
	   writable */

	struct x500data *localstruct = NULL;
	struct my_hostent *hp = NULL;
        struct sockaddr_in name;
	int errcode = 0;
	
	/* Allocate our memory */
        here->monitordata = MALLOC(sizeof(struct x500data), "x500-localstruct");

	localstruct = here->monitordata;

	localstruct->start = now_t;

	here->filedes = open_sock();

	if (here->filedes == -1)
	{
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
        name.sin_port = htons(1111);

	if (debug)
		print_err(0, "start_test_x500() doing connect() to %s:%d", 
			here->checkent->hostname, here->checkent->port);

        errcode = connect(here->filedes, (struct sockaddr*)&name,
                sizeof(struct sockaddr_in));

	localstruct->state = X500_CONNECT;

        if ((errcode < 0) && (errno != EINPROGRESS))
        {
		close(here->filedes);

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

	/* poll it again later */
	return;
}

void	service_test_x500(struct monitorent *here)
{
        /* wait for the fd to be readable/writable, then read the banner,
           and send a QUIT if appropriate so that we can return the error
           code for the tcp connecton problem, or for the x500 response.
         */
        /* do the actual real parts of the checks after
           it's been set up */

        struct x500data *localstruct = NULL;
        char buffer[256];
        int isopenretval = -1;

        /* do some variable shufflign */
        localstruct = here->monitordata;
	if (localstruct == NULL)
	{
		print_err(0, "bug! - localstruct == NULL in umichX500.c:service_test_x500");
		return;
	}

        /* do different things based on the state */
        switch (localstruct->state)
        {
                case X500_CONNECT:
                {
                        isopenretval = is_open(here->filedes);
                        if ((isopenretval != -1) &&
                                (isopenretval != SYSM_INPROG))
                        {
                                if (debug)
                                        print_err(0, "is_open() in service_test_x500()");
                                if (isopenretval != SYSM_OK)
                                {
                                        here->retval = isopenretval;
                                        close(here->filedes);
                                        FREE(localstruct);
                                        here->monitordata = NULL;
                                        if (debug)
                                                print_err(0, "ending service_test_x500() with retval = %s", errtostr(here->retval));
                                        return;
                                }
                                localstruct->state = X500_CONNECTED;
                                if (debug)
                                        print_err(0, "connected() to the x500 port of %s", here->checkent->hostname);
                        }
                        break;
                }
                case X500_CONNECTED:
                {
                        if (data_waiting_read(here->filedes, 0))
                        {
                                int bytes_read;
                                memset(buffer, 0, 256);
                                bytes_read = read(here->filedes, buffer, 254);
                                if (bytes_read <= 0)
                                {
                                        here->retval = (bytes_read == 0) ? SYSM_CONNREF : SYSM_BAD_RESP;
                                        break;
                                }
                                if (debug)
                                        print_err(0, "Got :%s:", buffer);
                                if (strncmp(buffer, "replication okay", 16) == 0)
                                {
                                        here->retval = SYSM_OK;
                                } else {
                                        here->retval = X500_WEDGED;
                                }
                        }
                        break;
                }
                default:
                {
                        ABORT(); /* Muahaha */
                        break;
                }
        }

        if (here->retval != -1)
        {
                /* insert cleanup code here */
                close (here->filedes);
                FREE(localstruct);
                here->monitordata = NULL;
        }
        return;
}


int
um_x500_monitor(char *hostname, int portnum)
{
	int ret = -1;
	int fd = -1;
	char buffer[256];

	/* open a connection to remote host */
	ret = open_host(hostname, portnum, &fd, 30);
	if (ret != 0)
	{
		return ret;
		/* return error */
	}
	/* read banner */
	getline_tcp(fd, buffer);
	/* check results */
	if (strcmp(buffer, "replication okay") == 0)
	{
		ret = 0;
	}
	else
	{
		/* set return value */
		ret = X500_WEDGED; /* replication wedged */
	}
	if (close(fd) == -1)
		return -1;
	/* close socket */

	return ret;
	/* return */
}

void
stop_test_x500(struct monitorent *here)
{
        struct x500data *localstruct = NULL;
 
        localstruct = here->monitordata;
	if (localstruct == NULL)
		return;

        close(here->filedes);
        FREE(localstruct);
        here->monitordata = NULL;
        return;
}

