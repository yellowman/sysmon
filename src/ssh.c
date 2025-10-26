#include "config.h"

struct sshdata {
	time_t start; /* test start time */
	time_t lastact; /* last activity */
	int state;
};

#define SSH_CONNECT		1 /* doing a connect() */
#define SSH_WAITBAN		2 /* Waiting for the version banner */
#define SSH_CLIVERS		"SSH-2.0-Sysmon"

/* 
	Here's the deal with ssh checks.  We do this:

	We connect, and do this:

	server>SSH-1.99-OpenSSH_3.4p1 Debian 1:3.4p1-1
	us<SSH-2.0-Sysmon

	If we get anything else than "SSH" at the first 3 chars, we return  SYSM_BAD_RESP

	If inactivity on socket is more than globtimeout, we return
	SYSM_NORESP

	Yes, i know this is a pretty lame check for now but it reduces the amount of warning messages
	from sshd like "Did not receive identification string".
*/

void	start_test_sshd(struct monitorent *here, time_t now_t)
{
        struct sshdata *localstruct = NULL;
        struct my_hostent *hp = NULL;
        struct sockaddr_in name;
        int serrno = -1, errcode = 0;

        /* Allocate our memory */
        here->monitordata = MALLOC(sizeof(struct sshdata), "ssh localstruct");

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
        name.sin_port = htons(SSH_PORTNUM);

        if (debug)
	{
		print_err(0, "start_test_sshd() doing connect() to %s:%d",
                	here->checkent->hostname, SSH_PORTNUM);
	}

        errcode = connect(here->filedes, (struct sockaddr*)&name,
                sizeof(struct sockaddr_in));
	serrno = errno;
	if (debug)
	{
		perror("connect() in start_sshd");
	}

        if ((errcode < 0) && (serrno != EINPROGRESS))
        {
                if (close(here->filedes) == -1)
		{
			perror("ssh.c: closing fd");
		}
		here->retval = errno_to_error(serrno);

	        /* Free memory we'd normally leak */
	        FREE(localstruct);
	        here->monitordata = NULL;

		print_err(0, "ssh: retval = %d\n", here->retval);
		return;
        }

	/* doing a connect() */
	localstruct->state = SSH_CONNECT;

        /* poll it again later */
        return;
}

void	service_test_sshd(struct monitorent *here, time_t now_t)
{
	/* do the actual real parts of the checks after
	   it's been set up */

	struct sshdata *localstruct = NULL;
	char buffer[PROTO_RESPONSE_SIZE + 1];
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
		print_err(0, "bug! localstruct == NULL in ssh.c:service_test_sshd");
		return;
	}

	if (debug)
	{
		print_err(0, "in service_test_sshd and the state is %d",localstruct->state);
	}

	/* do different things based on the state */
	switch (localstruct->state)
	{
		case SSH_CONNECT:
		{
			isopenretval = is_open(here->filedes);
		        if ((isopenretval != -1) && 
				(isopenretval != SYSM_INPROG))
		        {
				localstruct->lastact = now_t;
		                if (debug)
					print_err(0, "is_open() in service_test_sshd()");
				if (isopenretval != SYSM_OK)
				{
			                here->retval = isopenretval;
			                close(here->filedes);
			                FREE(localstruct);
			                here->monitordata = NULL;
			                if (debug)
						print_err(0, "ending service_test_sshd() with retval = %s", errtostr(here->retval));
					return;
				}
		                localstruct->state = SSH_WAITBAN;
				if (debug)
					print_err(0, "connected() to the ssh port of %s", here->checkent->hostname);
        		}
			if (((now_t)-localstruct->start) >= globtimeout) 
			{
				here->retval = SYSM_TIMEDOUT;
				close(here->filedes);
		                FREE(localstruct);
		                here->monitordata = NULL;
		                if (debug)
				{
					print_err(0, "ending service_test_sshd() with retval = %s",
						errtostr(here->retval));
				}
		                return;
			}
			break;
		}
		case SSH_WAITBAN:
		{
			if (data_waiting_read(here->filedes, 0))
			{
				memset(buffer, 0, sizeof(buffer));
				bytes =read(here->filedes, buffer, PROTO_RESPONSE_SIZE);
				if (bytes != 0 && bytes != -1)
				{
					buffer[strlen(buffer)-1] = '\0';
				} else if (bytes == -1) {
					perror("ssh.c:service_test_sshd:read");
				}
				if(debug)
					print_err(0, "Got: '%s'", buffer);  

				if (strncmp(buffer, "SSH", 3) == 0)
				{
					sendline(here->filedes, SSH_CLIVERS);
					here->retval = SYSM_OK;
				} else {
					here->retval = SYSM_BAD_RESP;
				}
			}
			break;
		}
		default:
		{
			print_err(1, "ssh.c: bug, how did we get here? localstruct->state = %d", localstruct->state);
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
stop_test_sshd(struct monitorent *here)
{
        struct sshdata *localstruct = NULL;
 
        localstruct = here->monitordata;

	if (localstruct == NULL)
		return;

        close(here->filedes);
        FREE(localstruct);
        here->monitordata = NULL;
        return;

}
