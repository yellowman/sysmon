/*
 * This file is not what it would appear to be at first look
 *
 * This file is not what becomes the sysmon file in the src
 * directory, that is client.c, this is the sysmond <-> sysmond
 * checks.
 *
 */

#include "config.h"

struct sysmon_data {
	time_t start;
	time_t lastact;
	int state;
	} ;

#define SYSMON_CONNECT		1
#define SYSMON_WAITBAN		2
#define SYSMON_SENT_QUIT	3
#define SYSMON_GOT_BYE		4

/* How sysmon client-srv stuff works.
 *
 * We connect to port 1345 of the remote sysmond, and it sends
 * a banner reading:
 * 111 - v1.0 Ready
 * At this point, we know that it is answering client-queries, and
 * hence, at least doing most of its job properly.
 *
 * We send a QUIT to it, and read the following banner:
 * 333 Good Bye, please come again
 * or some sort, of banner with 333 in it, which means "END OF LINE"
 *
 * The rest of it, basically looks like the other interactive 
 * client <-> server checks that we perform (SMTP, NNTP, etc..)
 *
 */

void start_check_sysmon(struct monitorent *here, time_t now_t)
{
	/* begin connect() */
        struct sysmon_data *localstruct = NULL;
        struct my_hostent *hp = NULL;
        struct sockaddr_in name;
        int serrno = -1, errcode = 0;

        /* Allocate our memory */
        here->monitordata = MALLOC(sizeof(struct sysmon_data), "sysmon-localstruct");

        localstruct = here->monitordata;

        localstruct->start = now_t;

	localstruct->lastact = localstruct->start;

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
        name.sin_port = htons(SYSMON_PORTNUM);

        if (debug)
		print_err(0, "start_test_sysmon() doing connect() to %s:%d",
                	here->checkent->hostname, SYSMON_PORTNUM);

        errcode = connect(here->filedes, (struct sockaddr*)&name,
                sizeof(struct sockaddr_in));
	serrno = errno;
	if (debug)
		perror("connect() in start_sysmon");

        if ((errcode < 0) && (serrno != EINPROGRESS))
        {
                if (close(here->filedes) == -1)
		{
			perror("sysmon.c: closing fd");
		}
		here->retval = errno_to_error(serrno);

	        /* Free memory we'd normally leak */
	        FREE(localstruct);
	        here->monitordata = NULL;

		print_err(0, "sysmon.c: retval = %d", here->retval);
		return;
        }

	/* doing a connect() */
	localstruct->state = SYSMON_CONNECT;

        /* poll it again later */
        return;
}

void service_check_sysmon(struct monitorent *here, time_t now_t)
{
	/* finish connect() */
	/* do the actual real parts of the checks after 
	   it's been set up */
	
	struct sysmon_data *localstruct = NULL;
	char buffer[256];
        int isopenretval = -1;
	int state = 0;

	/* do some variable shufflign */
	localstruct = here->monitordata;
	if (localstruct == NULL)
	{
		print_err(0, "bug! localstruct == NULL in sysmon.c:service_test_sysmon");
		return;
	}

	if (debug)
	print_err(0, "in service_test_sysmon and the state is %d",localstruct->state);

	/* do different things based on the state */
	state = localstruct->state;
	switch (state)
	{
		case SYSMON_CONNECT:
		{
			isopenretval = is_open(here->filedes);
		        if ((isopenretval != -1) && 
				(isopenretval != SYSM_INPROG))
		        {
				localstruct->lastact = now_t;
		                if (debug)
					print_err(0, "is_open() in service_test_sysmon()");
				if (isopenretval != SYSM_OK)
				{
			                here->retval = isopenretval;
			                close(here->filedes);
			                FREE(localstruct);
			                here->monitordata = NULL;
			                if (debug)
						print_err(0, "ending service_test_sysmon() with retval = %s", errtostr(here->retval));
					return;
				}
		                localstruct->state = SYSMON_WAITBAN;
				if (debug)
				{
					print_err(0, "connected() to the sysmon port of %s", 
						here->checkent->hostname);
				}
        		}
			break;
		}
		case SYSMON_WAITBAN:
		{
			if (data_waiting_read(here->filedes, 0))
			{
				memset(buffer, 0, sizeof(buffer));
				read(here->filedes, buffer, sizeof(buffer) - 1);
				buffer[strlen(buffer)-1] = '\0';
				if (debug)
					print_err(0, "Got :%s:", buffer);
				if (strncmp(buffer, "111 ", 4) == 0)
				{
					localstruct->state = SYSMON_SENT_QUIT;
				} else {
					here->retval = SYSM_BAD_RESP;
				}
				sendline(here->filedes, "QUIT");
			} else {
	                        if ((now_t-(localstruct->start)) >= globtimeout)
                        	{
					here->retval = SYSM_NORESP;
					close(here->filedes);
					FREE(localstruct);
					here->monitordata = NULL;
					if (debug)
					{
	                                        print_err(0, "ending service_test_sysmon() with retval = %s", errtostr(here->retval));
                                	}
	                                return;
				}
				break;
			}
			break;
		}
		case SYSMON_SENT_QUIT:
		{
                        if (data_waiting_read(here->filedes, 0))
                        {
                                memset(buffer, 0, sizeof(buffer));
                                read(here->filedes, buffer, sizeof(buffer) - 1);
                                buffer[strlen(buffer)-1] = '\0';
                                if (debug)
					print_err(0, "Got2:%s:", buffer);
				if (strncmp(buffer, "333 ", 4) == 0)
					localstruct->state = SYSMON_GOT_BYE;
				else
					here->retval = SYSM_BAD_RESP;
                        }
                        break;
		}
		case SYSMON_GOT_BYE:
		{
			here->retval = SYSM_OK;
			if (debug)
				print_err(0, "sysmon: returing a OK value");
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

void stop_check_sysmon(struct monitorent *here)
{
	/* clean up niceley */
	struct sysmon_data *localstruct = NULL;

	localstruct = here->monitordata;
	if (localstruct != NULL)
	{
		FREE(localstruct);
	}

	close(here->filedes);
	here->monitordata = NULL;
	return;
}

/* No code after here should exist */
