/* $Id: http.c,v 1.22 2006/05/09 03:26:41 jared Exp $ */
#include "config.h"

/* returns status based upon this:
  0 = ok,  1 = conn ref, 2 = ENETUNREACH, 3 = EHOSTDOWN||EHOSTUNREACH,
  4 = ETIMEDOUT, 5 = no dns entry, 6 = unpingable, 
  7 = Throttled, 8 = no auth, 9 = no response
  12 = bad response
 */

struct wwwdata {
	int timesblank;
	time_t start; /* test start time */
	time_t lastact; /* last activity */
	int state;
	};

#define WWW_CONNECT		1 /* doing a connect() */
#define WWW_SENT_REQUEST	2 /* Waiting for the banner */

void	start_test_www(struct monitorent *here, time_t now_t)
{
	/* start the test, get connect() rolling and let service_test_www()
	   take care of the rest, return either the tcp errorcode, or
	   that the text was not found 
	 */
	struct wwwdata *localstruct = NULL;
	struct my_hostent *hp = NULL;
	struct sockaddr_in name;
	int errcode = 0;
	int serrno = 0;

	/* Allocate our memory */
	here->monitordata = MALLOC(sizeof(struct wwwdata), "www localstruct");

	localstruct = here->monitordata;

	localstruct->start = now_t;

	localstruct->lastact = localstruct->start;

	here->filedes = open_sock();

	if (here->filedes == -1)
	{
		FREE(localstruct);
		here->monitordata = NULL;
		here->retval = here->checkent->lastcheck;
		print_err(1, "Unable to create a socket in start_test_www()");
		return;
	}

	hp = my_gethostbyname(here->checkent->hostname, AF_INET);

	if (hp == NULL)
	{
		here->retval = SYSM_NODNS;
		FREE(localstruct);
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
	{
		print_err(0, "start_test_www() doing connect() to %s:%d",
			here->checkent->hostname, HTTP_PORTNUM);
	}

	errcode = connect(here->filedes, (struct sockaddr*)&name,
		sizeof(struct sockaddr_in));
	serrno = errno;

	if ((errcode < 0) && (serrno != EINPROGRESS))
	{
	        if (close(here->filedes) == -1)
		{
	                perror("http.c:close()");
		}
		switch (serrno)
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
			default:
				break;
	        }

	        /* Free memory we'd normally leak */
	        FREE(localstruct);
	        here->monitordata = NULL;

	        return;
	}

	/* doing a connect() */
	localstruct->state = WWW_CONNECT;

	/* poll it again later */
	return;
}

void	service_test_www(struct monitorent *here, time_t now)
{
	/* take the filedes created in start_test_www() and watch for it to
	   be writable.  If so, send the http request to retrieve the page.
	   If the text is found, we're in good shape, otherwise, return the
	   appropriate error code
	 */

	struct wwwdata *localstruct = NULL;
	char buffer[1024];
	int isopenretval = -1;
	int times_read = 0;

	/* do some variable shufflign */
	localstruct = here->monitordata;
	if (localstruct == NULL)
	{
		print_err(0, "bug! - localstruct == NULL in http.c:service_test_www");
		return;

	}

	/* do different things based on the state */
	switch (localstruct->state)
	{
	        case WWW_CONNECT:
	        {
	                isopenretval = is_open(here->filedes);
	                if ((isopenretval != -1) &&
	                        (isopenretval != SYSM_INPROG))
	                {
	                        localstruct->lastact = now;
	                        if (debug)
	                                print_err(0, "is_open() in service_test_http()");
	                        if (isopenretval != SYSM_OK)
	                        {
	                                here->retval = isopenretval;
	                                close(here->filedes);
	                                FREE(localstruct);
	                                here->monitordata = NULL;
	                                if (debug)
					{
						print_err(0, "ending service_test_http() with retval = %s", errtostr(here->retval));
					}
	                                return;
	                        }
	                        memset(buffer, 0, 1024);
				snprintf(buffer, 1024, "GET %s HTTP/1.0", here->checkent->url);
				sendline(here->filedes, buffer);
				sendline(here->filedes, "User-Agent: sysmond/http.c");
				memset(buffer, 0, 1024);
				snprintf(buffer, 1024, "Host: %s", here->checkent->hostname);
				sendline(here->filedes, buffer);

				sendline(here->filedes, "");
				
	                        localstruct->state = WWW_SENT_REQUEST;
	                        if (debug)
	                                print_err(0, "connected() to the http port of %s", here->checkent->hostname);
	                }
	                break;
	        }
	        case WWW_SENT_REQUEST:
	        {
	                while (data_waiting_read(here->filedes, 0))
	                {
				localstruct->lastact = now;
				getline_tcp(here->filedes, buffer);
				times_read++;
	                        if (debug)
	                                print_err(0, "http.c:Got :%s: Searching for :%s:", buffer, here->checkent->url_text);
				if (strlen(buffer) == 0)
				{
					localstruct->timesblank++;
					if (localstruct->timesblank > 10)
					{
						here->retval = SYSM_BAD_RESP;
					}
					break;
				}
				localstruct->timesblank = 0;
				if (here->retval == SYSM_OK || 
					strlen(buffer) < strlen(here->checkent->url_text))
				{
					continue;
				}
				if (strstr(buffer,here->checkent->url_text))
				{
					if (debug) print_err(0, "http.c:Found it!");
					here->retval = SYSM_OK;
					break;
		                }
				if (times_read > 25)
					break;
	                }
			if ((now - localstruct->lastact) > 25)
			{
				/* We got zero response from the
				 * far http server after 25 seconds
				 */
				here->retval = SYSM_NORESP;
				break;
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

void
stop_test_www(struct monitorent *here)
{
	struct wwwdata *localstruct = NULL;
	
	localstruct = here->monitordata;

	if (localstruct == NULL)
	{
		return;
	}

	close(here->filedes);
	FREE(localstruct);
	here->monitordata = NULL;
	return;
}

