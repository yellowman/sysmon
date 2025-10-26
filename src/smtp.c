/* $Id: smtp.c,v 1.20 2006/05/09 03:26:42 jared Exp $ */
#include "config.h"

/* error banners 451 - out of memory */

/* ok banner 220 */

struct smtpdata {
	time_t start; /* test start time */
	time_t lastact; /* last activity */
	int state;
	};

#define SMTP_CONNECT	1 /* doing a connect() */
#define SMTP_WAITBAN	2 /* Waiting for the banner */
#define SMTP_SENT_QUIT	3 /* sent a QUIT */
#define SMTP_GOT_BYE	4 /* got a bye from the remote server */

/* 

	Here's the deal with smtp checks.  We do this:

We connect, and do this:

server>220 puck.nether.net ESMTP
us<QUIT
server>221 puck.nether.net closing connection

	If we get anything else, we return  SYSM_BAD_RESP

	If inactivity on socket is more than globtimeout, we return
	SYSM_NORESP

 */

void	start_test_smtp(struct monitorent *here, time_t now_t)
{
	struct smtpdata *localstruct = NULL;
	struct my_hostent *hp = NULL;
	struct sockaddr_in name;
	int serrno = -1, errcode = 0;

	/* Allocate our memory */
	here->monitordata = MALLOC(sizeof(struct smtpdata), "smtp localstruct");

	localstruct = here->monitordata;

	localstruct->start = now_t;

	localstruct->lastact = localstruct->start;

	here->filedes = open_sock();

	if (here->filedes == -1)
	{
		here->retval = here->checkent->lastcheck;
		FREE(here->monitordata);
		here->monitordata = NULL;
		return;
	}

	hp = my_gethostbyname(here->checkent->hostname, AF_INET);

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
	name.sin_port = htons(SMTP_PORTNUM);

	if (debug || here->checkent->trace)
	{
		print_err(here->checkent->trace, "start_test_smtp() doing connect() to %s:%d",
			here->checkent->hostname, SMTP_PORTNUM);
	}

	errcode = connect(here->filedes, (struct sockaddr*)&name,
		sizeof(struct sockaddr_in));
	serrno = errno;
	if (debug)
	{
		perror("connect() in start_smtp");
	}

	if ((errcode < 0) && (serrno != EINPROGRESS))
	{
		if (close(here->filedes) == -1)
		{
			perror("smtp.c: closing fd");
		}
		here->retval = errno_to_error(serrno);

		/* Free memory we'd normally leak */
		FREE(localstruct);
		here->monitordata = NULL;

		print_err(0, "smtp: retval = %d\n", here->retval);
		return;
	}

	/* doing a connect() */
	localstruct->state = SMTP_CONNECT;

	/* poll it again later */
	return;
}

void	service_test_smtp(struct monitorent *here, time_t now_t)
{
	/* do the actual real parts of the checks after 
	   it's been set up */
	
	struct smtpdata *localstruct = NULL;
	char buffer[256];
	int isopenretval = -1;
	int bytes = 0;

	/* Check for problems */
	if (here == NULL)
	{
		return;
	}

	/* do some variable shuffling */

	localstruct = here->monitordata;

	if (localstruct == NULL)
	{
		print_err(0, "bug! localstruct == NULL in smtp.c:service_test_smtp");
		return;
	}

	if (debug || here->checkent->trace)
	{
		print_err(here->checkent->trace, "in service_test_smtp and the state is %d",localstruct->state);
	}

	/* do different things based on the state */
	switch (localstruct->state)
	{
		case SMTP_CONNECT:
		{
			isopenretval = is_open(here->filedes);
			if ((isopenretval != -1) && 
				(isopenretval != SYSM_INPROG))
			{
				localstruct->lastact = now_t;
			        if (debug || here->checkent->trace)
					print_err(here->checkent->trace, "is_open() in service_test_smtp()");
				if (isopenretval != SYSM_OK)
				{
				        here->retval = isopenretval;
				        close(here->filedes);
				        FREE(localstruct);
				        here->monitordata = NULL;
				        if (debug || here->checkent->trace)
						print_err(here->checkent->trace, "ending service_test_smtp() with retval = %s", errtostr(here->retval));
					return;
				}
			        localstruct->state = SMTP_WAITBAN;
				if (debug || here->checkent->trace)
					print_err(here->checkent->trace, "connected() to the smtp port of %s", here->checkent->hostname);
			}
			if ((now_t-localstruct->start) >= globtimeout) 
			{
				here->retval = SYSM_TIMEDOUT;
				close(here->filedes);
			        FREE(localstruct);
			        here->monitordata = NULL;
			        if (debug || here->checkent->trace)
				{
					print_err(here->checkent->trace, "ending service_test_smtp() with retval = %s",
						errtostr(here->retval));
				}
			        return;
			}
			break;
		}
		case SMTP_WAITBAN:
		{
			if (data_waiting_read(here->filedes, 0))
			{
				memset(buffer, 0, sizeof(buffer));
				bytes =read(here->filedes, buffer, sizeof(buffer) - 1);
				if (bytes != 0 && bytes != -1)
				{
					buffer[strlen(buffer)-1] = '\0';
				} else if (bytes == -1) {
					perror("smtp.c:service_test_smtp:read");
				}

				if (debug || here->checkent->trace)
					print_err(0, "Got :%s:", buffer);
				if (strncmp(buffer, "220", 3) == 0)
				{
					localstruct->state = SMTP_SENT_QUIT;
				} else {
					print_err(1, "smtp.c:got %s from %s", buffer, here->checkent->hostname);
					here->retval = SYSM_BAD_RESP;
				}
				sendline(here->filedes, "QUIT");
			}
			break;
		}
		case SMTP_SENT_QUIT:
		{
		        if (data_waiting_read(here->filedes, 0))
		        {
		                memset(buffer, 0, sizeof(buffer));
		                bytes = read(here->filedes, buffer, sizeof(buffer) - 1);
				if (bytes != 0 && bytes != -1)
				{
		                	buffer[strlen(buffer)-1] = '\0';
				} else if (bytes == -1) {
					perror("smtp.c:service_test_smtp:read");
				}
		                if (debug || here->checkent->trace)
					print_err(here->checkent->trace, "smtp.c:sending_quit_received:%s:", buffer);
				if (strncmp(buffer, "221 ", 4) == 0)
					localstruct->state = SMTP_GOT_BYE;
				else
					here->retval = SYSM_BAD_RESP;
		        }
		        break;
		}
		case SMTP_GOT_BYE:
		{
			here->retval = SYSM_OK;
			if (debug || here->checkent->trace)
				print_err(here->checkent->trace, "smtp: returing a OK value");
			break;
		}
		default:
		{
			print_err(1, "smtp.c: bug, how did we get here? localstruct->state = %d", localstruct->state);
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

void
stop_test_smtp(struct monitorent *here)
{
	struct smtpdata *localstruct = NULL;
 
	localstruct = here->monitordata;

	if (localstruct == NULL)
		return;

	close(here->filedes);
	FREE(localstruct);
	here->monitordata = NULL;
	return;

}

