/* $Id: pop3.c,v 1.13 2006/05/09 03:26:42 jared Exp $ */
#include "config.h"

struct pop3data {
	time_t start;
	time_t lastact;
	int state;
	};

#define POP3_CONNECT	1 /* Doing the connect() */
#define POP3_WAITBAN	2 /* Waiting for the banner of +OK */
#define POP3_SENT_USER 	3 /* sent our username */
#define POP3_SENT_PASS  4 /* sent our password */
#define POP3_SENT_QUIT	5 /* sent a QUIT */
#define POP3_GOT_BYE	6 /* got a +OK saying goodbye */

/* Notes :

	Some pop servers disconnect after a bad password automagically,
	so we need to trap that properly if we can't send a quit, don't
	give any protocol mismatch errors 
 */

void	start_test_pop3(struct monitorent *here, time_t now_t)
{

        /* set up the check, start to connect() to the remote host
           then let service_test_pop3() watch for the fd to be
           writable */

        struct pop3data *localstruct = NULL;
        struct my_hostent *hp = NULL;
        struct sockaddr_in name;
        int errcode = 0;

        /* Allocate our memory */
        here->monitordata = MALLOC(sizeof(struct pop3data), "pop3 localstruct");

        localstruct = here->monitordata;

        localstruct->start = now_t;

	localstruct->state = POP3_CONNECT;

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
        name.sin_port = htons(POP3_PORTNUM);

	if (debug)
	{
	        print_err(0, "start_test_pop3() doing connect() to %s:%d",
	                here->checkent->hostname, POP3_PORTNUM);
	}

        /* do the connect() here: */
        errcode = connect(here->filedes, (struct sockaddr*)&name,
                sizeof(struct sockaddr_in));

	/* poll it again later */
	return;
}

void	service_test_pop3(struct monitorent *here, time_t now_t)
{
        /* do the actual real parts of the checks after
           it's been set up */

        struct pop3data *localstruct = NULL;
        char buffer[PROTO_RESPONSE_SIZE + 1];
        int isopenretval = -1;

        /* do some variable shufflign */
        localstruct = here->monitordata;
	if (localstruct == NULL)
	{
		print_err(0, "bug! localstruct == NULL in pop3.c:service_test_pop3");
		return;
	}

        if (debug)
	{
                print_err(0, "service_test_pop3: state = %d", localstruct->state);
	}

        /* do different things based on the state */
        switch (localstruct->state)
        {
                case POP3_CONNECT:
                {
                        isopenretval = is_open(here->filedes);
			if (debug)
			{
				print_err(0, 
					"is_open is returning %d", 
					isopenretval);
			}
                        if ((isopenretval != -1) &&
                                (isopenretval != SYSM_INPROG))
                        {
                                localstruct->lastact = now_t;
                                if (debug)
				{
                                        print_err(0, "is_open() in service_test_pop3()");
				}

                                if (isopenretval != SYSM_OK)
                                {
                                        here->retval = isopenretval;
                                        close(here->filedes);
                                        FREE(localstruct);
                                        here->monitordata = NULL;
                                        if (debug)
                                                print_err(0, "ending service_test_pop3() with retval = %s", errtostr(here->retval));
                                        return;
                                }
                                localstruct->state = POP3_WAITBAN;
                                if (debug)
				{
                                        print_err(0, "connected() to the pop3 port of %s", here->checkent->hostname);
				}
                        }
                        break;
                }
                case POP3_WAITBAN:
                {
                        if (data_waiting_read(here->filedes, 0))
                        {
                                int bytes_read;
                                memset(buffer, 0, sizeof(buffer));
                                bytes_read = read(here->filedes, buffer, PROTO_RESPONSE_SIZE);
                                if (bytes_read <= 0)
                                {
                                        here->retval = (bytes_read == 0) ? SYSM_CONNREF : SYSM_BAD_RESP;
                                        break;
                                }
                                if (debug)
                                        print_err(0, "Got :%s:", buffer);
                                if (strncmp(buffer, "+OK", 3) == 0)
                                {
				        /* prepare the buffer */
				        snprintf(buffer, sizeof(buffer), "USER %s",
						here->checkent->username);

				        /* send the buffer out the socket */
				        sendline(here->filedes, buffer);
                                        localstruct->state = POP3_SENT_USER;
                                } else {
                                        here->retval = SYSM_BAD_RESP;
                                }
                        }
                        break;
                }
		case POP3_SENT_USER:
		{
                        if (data_waiting_read(here->filedes, 0))
                        {
                                int bytes_read;
                                memset(buffer, 0, sizeof(buffer));
                                bytes_read = read(here->filedes, buffer, PROTO_RESPONSE_SIZE);
                                if (bytes_read <= 0)
                                {
                                        here->retval = (bytes_read == 0) ? SYSM_CONNREF : SYSM_BAD_RESP;
                                        break;
                                }
                                if (debug)
                                        print_err(0, "Got :%s:", buffer);
                                if (strncmp(buffer, "+OK", 3) == 0)
                                {
                                        /* prepare the buffer */
                                        snprintf(buffer, sizeof(buffer), "PASS %s",
						here->checkent->password);

                                        /* send the buffer out the socket */
                                        sendline(here->filedes, buffer);
                                        localstruct->state = POP3_SENT_PASS;
                                } else {
                                        here->retval = SYSM_BAD_RESP;
                                }
                        }
                        break;
		}
		case POP3_SENT_PASS:
		{
                        if (data_waiting_read(here->filedes, 0))
                        {
                                int bytes_read;
                                memset(buffer, 0, sizeof(buffer));
                                bytes_read = read(here->filedes, buffer, PROTO_RESPONSE_SIZE);
                                if (bytes_read <= 0)
                                {
                                        here->retval = (bytes_read == 0) ? SYSM_CONNREF : SYSM_BAD_RESP;
                                        break;
                                }
                                if (debug)
                                        print_err(0, "Got(pop3_sent_pass):%s:",
						buffer);
				if (strncmp(buffer, "+OK", 3) == 0)
					here->retval = SYSM_OK;
				else if (strncmp(buffer, "-ERR", 4) == 0)
                                {
					here->retval = SYSM_BAD_AUTH;
                                } else {
                                        here->retval = SYSM_BAD_RESP;
                                }
                                sendline(here->filedes, "QUIT");
                                localstruct->state = POP3_SENT_QUIT;
                        }
                        break;
		}
                case POP3_SENT_QUIT:
                {
                        if (data_waiting_read(here->filedes, 0))
                        {
                                int bytes_read;
                                memset(buffer, 0, sizeof(buffer));
                                bytes_read = read(here->filedes, buffer, PROTO_RESPONSE_SIZE);
                                if (bytes_read <= 0)
                                {
                                        here->retval = (bytes_read == 0) ? SYSM_CONNREF : SYSM_BAD_RESP;
                                        break;
                                }
                                if (debug)
                                        print_err(0, "Got2:%s:", buffer);
                                if (strncmp(buffer, "+OK", 3) == 0)
                                        localstruct->state = POP3_GOT_BYE;
                        }
                        break;
                }

	} /* end of switch */
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
stop_test_pop3(struct monitorent *here)
{
        struct pop3data *localstruct = NULL;
 
        localstruct = here->monitordata;

	if (localstruct != NULL)
	{
	        close(here->filedes);
	        FREE(localstruct);
	}
        here->monitordata = NULL;
        return;
}

