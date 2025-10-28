/* $Id: imap.c,v 1.13 2006/05/09 03:26:41 jared Exp $ */
#include "config.h"

/* see RFC 2060 for protocol details 
 Excerpt included here:

6.2.2.  LOGIN Command

   Arguments:  user name
               password

   Responses:  no specific responses for this command

   Result:     OK - login completed, now in authenticated state
               NO - login failure: user name or password rejected
               BAD - command unknown or arguments invalid

      The LOGIN command identifies the client to the server and carries
      the plaintext password authenticating this user.

   Example:    C: a001 LOGIN SMITH SESAME
               S: a001 OK LOGIN completed

6.1.3.  LOGOUT Command

   Arguments:  none

   Responses:  REQUIRED untagged response: BYE

   Result:     OK - logout completed
               BAD - command unknown or arguments invalid

      The LOGOUT command informs the server that the client is done with
      the connection.  The server MUST send a BYE untagged response
      before the (tagged) OK response, and then close the network
      connection.

   Example:    C: A023 LOGOUT
               S: * BYE IMAP4rev1 Server logging out
               S: A023 OK LOGOUT completed
               (Server and client then close the connection)

 */

struct imapdata {
        time_t start; /* test start time */
        time_t lastact; /* last activity */
        int state;
        };

#define IMAP_CONNECT    1 /* doing a connect() */
#define IMAP_WAITBAN    2 /* Waiting for the banner */
#define IMAP_SENT_AUTH	3 /* sent our auth data */
#define IMAP_SENT_QUIT  4 /* sent logout */
#define IMAP_GOT_BYE    5 /* got a bye from the remote server */

void	start_test_imap(struct monitorent *here, time_t now_t)
{
        struct imapdata *localstruct = NULL;
        struct my_hostent *hp = NULL;
        struct sockaddr_in name;
        int serrno = -1, errcode = 0;

        /* Allocate our memory */
        here->monitordata = MALLOC(sizeof(struct imapdata), "imap localstruct");

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
        name.sin_port = htons(IMAP_PORTNUM);

        if (debug)
	{
		print_err(0, "start_test_imap() doing connect() to %s:%d\n",
			here->checkent->hostname, IMAP_PORTNUM);
	}

        errcode = connect(here->filedes, (struct sockaddr*)&name,
                sizeof(struct sockaddr_in));
        serrno = errno;
        if (debug)
	{
                perror("connect() in start_imap");
	}

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
                }

                /* Free memory we'd normally leak */
                FREE(localstruct);
                here->monitordata = NULL;

		if (debug)
		{
			print_err(0, "imap.c: retval = %d\n", here->retval);
		}
                return;
        }

        /* doing a connect() */
        localstruct->state = IMAP_CONNECT;

        /* poll it again later */
        return;
}

void	service_test_imap(struct monitorent *here, time_t now_t)
{
        struct imapdata *localstruct = NULL;
        char buffer[PROTO_RESPONSE_SIZE + 1], *retptr;
        int isopenretval = -1;

        /* do some variable shufflign */
        localstruct = here->monitordata;
	
	if (localstruct == NULL)
	{
		print_err(1, "bug - localstruct == NULL in imap.c:service_test_imap\n");
		return;
	}

        if (debug)
	{
                print_err(0, "service_test_imap: state = %d\n", localstruct->state);
	}
        /* do different things based on the state */
        switch (localstruct->state)
        {
                case IMAP_CONNECT:
                {
                        isopenretval = is_open(here->filedes);
                        if (debug)
			{
				print_err(0, "is_open is returning %d\n", isopenretval);
			}
                        if ((isopenretval != -1) &&
                                (isopenretval != SYSM_INPROG))
                        {
                                localstruct->lastact = now_t;
                                if (debug)
				{
					print_err(0, "is_open() in service_test_imap()\n");
				}
                                if (isopenretval != SYSM_OK)
                                {
                                        here->retval = isopenretval;
                                        close(here->filedes);
                                        FREE(localstruct);
                                        here->monitordata = NULL;
                                        if (debug)
					{
                                                print_err(0, "ending service_test_imap() with retval = %s\n", errtostr(here->retval));
					}
                                        return;
                                }
                                localstruct->state = IMAP_WAITBAN;
                                if (debug)
				{
					print_err(0, "connected() to the imap port of %s\n", here->checkent->hostname);
				}
                        }
                        break;
                }

                case IMAP_WAITBAN:
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
				{
					print_err(0, "imap.c:Got :%s:\n", buffer);
				}
                                if (strncmp(buffer, "* OK", 4) == 0)
                                {
                                        /* prepare the buffer */
                                        snprintf(buffer, sizeof(buffer), "A100 LOGIN %s %s",
                                                here->checkent->username,
						here->checkent->password);

                                        /* send the buffer out the socket */
                                        sendline(here->filedes, buffer);
                                        localstruct->state = IMAP_SENT_AUTH;
                                } else {
                                        here->retval = SYSM_BAD_RESP;
				}
                        }
                        break;
                }
		case IMAP_SENT_AUTH:
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
				{
					print_err(0, "imap.c:Got :%s:\n", buffer);
				}
				/* ditch informational msg(s) */
doover:				if (strncmp(buffer, "*", 1) == 0) {
				    if ((retptr = strchr(buffer, '\n')) != NULL) {
					strncpy(buffer, retptr + 1, PROTO_RESPONSE_SIZE - 5);
					goto doover;
				    }
				}
                                if (strncmp(buffer, "A100 OK", 7) == 0)
                                {
					here->retval = SYSM_OK;
				} else if (strncmp(buffer, "A100 NO", 7) == 0)
				{
					here->retval = SYSM_BAD_AUTH;
                                } else {
                                        here->retval = SYSM_BAD_RESP;
                                }

				sendline(here->filedes, "A102 LOGOUT");

                                /* send the buffer out the socket */
                                localstruct->state = IMAP_SENT_QUIT;
                        }
                        break;
		}
		case IMAP_SENT_QUIT:
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
				{
					print_err(0, "imap.c:Got :%s:\n", buffer);
				}
                                if (strncmp(buffer, "A102 OK", 7) == 0)
                                {
                                        here->retval = SYSM_OK;
					localstruct->state = IMAP_GOT_BYE;
                                } else {
                                        here->retval = SYSM_BAD_RESP;
                                }
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

void    stop_test_imap(struct monitorent *here)
{
        struct imapdata *localstruct = NULL;

        localstruct = here->monitordata;
	if (localstruct == NULL)
		return;

        close(here->filedes);
        FREE(localstruct);
        here->monitordata = NULL;
        return;

}


