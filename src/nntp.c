/* $Id: nntp.c,v 1.14 2006/05/09 03:26:42 jared Exp $ */
#include "config.h"

/* Does a rfc nntp check to see if the server is responding -- 

RFC's important to News:
        RFC 977: NNTP (Phil Lapsley and Brian Kantor)
        RFC 1036: Standard for Interchange of USENET Messages
                (M.Horton, Rick Adams)

	Excerpt from rfc 977:
2.4.2.  Status Responses

   These are status reports from the server and indicate the response to
   the last command received from the client.

   Status response lines begin with a 3 digit numeric code which is
   sufficient to distinguish all responses.  Some of these may herald
   the subsequent transmission of text.

   The first digit of the response broadly indicates the success,
   failure, or progress of the previous command.

      1xx - Informative message
      2xx - Command ok
      3xx - Command ok so far, send the rest of it.
      4xx - Command was correct, but couldn't be performed for
            some reason.
      5xx - Command unimplemented, or incorrect, or a serious
            program error occurred.

 */

/* returns status based upon this:

  0 = ok,  1 = conn ref, 2 = ENETUNREACH, 3 = EHOSTDOWN||EHOSTUNREACH,
  4 = ETIMEDOUT, 5 = no dns entry, 6 = unpingable, 
  7 = Throttled, 8 = no auth, 9 = no response

 */

struct nntpdata {
        time_t start; /* test start time */
        time_t lastact; /* last activity */
        int state;
	int retval;
        };

#define NNTP_CONNECT    1 /* doing a connect() */
#define NNTP_WAITBAN    2 /* Waiting for the banner */
#define NNTP_SENT_QUIT  3 /* sent a QUIT */
#define NNTP_GOT_BYE    4 /* got a bye from the remote server */

void	start_test_nntp(struct monitorent *here, time_t now_t)
{
	/* start the socket connecting to the remote host, and then
	   let service_test_nntp take care of the rest
	 */

        struct nntpdata *localstruct = NULL;
        struct my_hostent *hp = NULL;
        struct sockaddr_in name;
	int serrno = 0;
        int errcode = 0;

        /* Allocate our memory */
        here->monitordata = MALLOC(sizeof(struct nntpdata), "nntp localstruct");

        localstruct = here->monitordata;

        localstruct->start = now_t;

        localstruct->lastact = localstruct->start;

        here->filedes = open_sock();
	localstruct->retval = 666;

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
        name.sin_port = htons(NNTP_PORTNUM);

        if (debug)
                print_err(0, "start_test_nntp() doing connect() to %s:%d",
                        here->checkent->hostname, NNTP_PORTNUM);

        errcode = connect(here->filedes, (struct sockaddr*)&name,
                sizeof(struct sockaddr_in));
	serrno = errno;

        if ((errcode < 0) && (serrno != EINPROGRESS))
        {
                close(here->filedes);

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
			default:
				break;
		}

                /* Free memory we'd normally leak */
                FREE(localstruct);
                here->monitordata = NULL;

                return;
        }

        /* doing a connect() */
        localstruct->state = NNTP_CONNECT;

        /* poll it again later */
        return;
}

void	service_test_nntp(struct monitorent *here, time_t now_t)
{
        /* wait for the fd to be readable/writable, then read the banner,
           and send a QUIT if appropriate so that we can return the error
           code for the tcp connecton problem, or for the nntp response.
         */
        /* do the actual real parts of the checks after
           it's been set up */

        struct nntpdata *localstruct = NULL;
        char buffer[256];
        int isopenretval = -1;

        /* do some variable shufflign */
        localstruct = here->monitordata;
	if (localstruct == NULL)
	{
		print_err(0, "bug! localstruct == NULL in nntp.c:service_test_nntp");
		return;
	}

	if (debug)
		print_err(0, "service_test_nntp: state = %d", localstruct->state);
        /* do different things based on the state */
        switch (localstruct->state)
        {
                case NNTP_CONNECT:
                {
                        isopenretval = is_open(here->filedes);
			if (debug)
   			    print_err(0, "is_open is returning %d",isopenretval);
                        if ((isopenretval != -1) &&
                                (isopenretval != SYSM_INPROG))
                        {
                                localstruct->lastact = now_t;
                                if (debug)
                                        print_err(0, "is_open() in service_test_nntp()");
                                if (isopenretval != SYSM_OK)
                                {
                                        here->retval = isopenretval;
                                        close(here->filedes);
                                        FREE(localstruct);
                                        here->monitordata = NULL;
                                        if (debug)
                                                print_err(0, "ending service_test_nntp() with retval = %s", errtostr(here->retval));
                                        return;
                                }
                                localstruct->state = NNTP_WAITBAN;
                                if (debug)
                                        print_err(0, "connected() to the nntp port of %s", here->checkent->hostname);
                        }
                        break;
                }
                case NNTP_WAITBAN:
                {
                        if (data_waiting_read(here->filedes, 0))
                        {
                                memset(buffer, 0, 256);
                                getline_tcp(here->filedes, buffer);
                                if (debug)
                                        print_err(0, "nntp.c:getline_tcp:Got :%s:", buffer);
                                if (strncmp(buffer, "200 ", 4) == 0)
                                {
					localstruct->retval = SYSM_OK;
                                } else {
                                        here->retval = SYSM_BAD_RESP;
                                }
                                sendline(here->filedes, "QUIT");
				localstruct->state = NNTP_SENT_QUIT;
                        }
			if ((now_t - localstruct->lastact) > 25)
			{
				/* No responce after 25 sec */
				here->retval = SYSM_NORESP;
				break;
			}
                        break;
                }
                case NNTP_SENT_QUIT:
                {
                        if (data_waiting_read(here->filedes, 0))
                        {
                                memset(buffer, 0, 256);
                                getline_tcp(here->filedes, buffer);
                                if (debug)
                                        print_err(0, "nntp.c:getline_tcp:Got2:%s:", buffer);
                                if (strncmp(buffer, "205 ", 4) == 0)
				{
                                        localstruct->state = NNTP_GOT_BYE;
				}
				if (localstruct->retval != 666)
				{
					here->retval = localstruct->retval;
				} else {
					here->retval = SYSM_BAD_RESP;
				}
                        }
			if ((now_t - localstruct->lastact) > 25)
			{
				/* No responce after 25 sec */
				here->retval = SYSM_NORESP;
				break;
			}
                        break;
                }
                case NNTP_GOT_BYE:
                {
                        here->retval = SYSM_OK;
                        if (debug)
			{
				print_err(0, "nntp: returing a OK value");
			}
                        break;
                }
                default:
                {
			print_err(1, "nntp.c: not sure how I got here.");
                        break;
                }
        }
        if (here->retval != -1)
        {
                /* insert cleanup code here */
                close(here->filedes);
                FREE(localstruct);
                here->monitordata = NULL;
        }
        return;

}

void
stop_test_nntp(struct monitorent *here)
{
        struct nntpdata *localstruct = NULL;
	
	localstruct = here->monitordata;

	if (localstruct == NULL)
		return;

	close(here->filedes);
	FREE(localstruct);
	here->monitordata = NULL;
        return;
}

