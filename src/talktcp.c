/* $Id: talktcp.c,v 1.12 2006/09/16 02:21:26 jared Exp $ */
#include "config.h"

extern struct clientstatus *clienthead;

/* handle sig pipes instead of killing process */
void
handle_sig_pipe()
{
}

int is_open(int fd)
/* check to see if the socket is ready for IO -- usually called once
   open_host returns 10 (Connection in progress)  It will return
   if there is an error such as connection refused, conn timed out,
   otherwise it returns 10 if the socket is not connected yet */
{
	int vals = -1, size = 0;
	unsigned int optval = 0;
	int serrno = 0; /* saved errno */

	size = sizeof(optval);

	errno = 0;

	/* check socket for error */
	vals = getsockopt(fd, SOL_SOCKET, SO_ERROR,  (void*)&optval, &size);
	
        serrno = optval;

	if (vals == -1)
	{
		errno = serrno;
		if (debug)
			perror("is_open:getsockopt");
	}

	if (serrno != 0)
		switch(serrno)
		{
			case ECONNREFUSED:
			case EINTR:
				return SYSM_CONNREF;
			case ENETUNREACH:
				return SYSM_NETUNRCH;
			case EHOSTDOWN:
			case EHOSTUNREACH:
				return SYSM_HOSTDOWN;
			case ETIMEDOUT:
				return SYSM_TIMEDOUT;
			case EINPROGRESS:
				return SYSM_INPROG;
			case EBADF:
				return -1;
			default:
				perror("is_open:getsockopt");
				break;
		}

	/* check socket for connection */
	vals = can_write(fd,0);
	if (vals == 1)
		return SYSM_OK;

	if (debug)
		print_err(0, "can_write returned %d", vals);

	if (vals == -1)
	{
		print_err(0, "error checking socket for data");
		return -1;
	}
	
	errno = 0;
        /* check socket for error */
        vals = getsockopt(fd, SOL_SOCKET, SO_ERROR, (void*) &optval, &size);
#ifdef __svr4__
        serrno = errno;
#endif
#ifndef __svr4__
        serrno = optval;
#endif
        if (vals == -1)
                perror("getsockopt");

        if (vals == 0)
                return -1;

        if (serrno != 0)
		switch(serrno)
		{
			case ECONNREFUSED:
			case EINTR:
				close(fd);
                        	return SYSM_CONNREF;
			case ENETUNREACH:
				close(fd);
                        	return SYSM_NETUNRCH;
                	case EHOSTDOWN:
			case EHOSTUNREACH:
				close(fd);
                        	return SYSM_HOSTDOWN;
			case ETIMEDOUT:
				close(fd);
				return SYSM_TIMEDOUT;
			case EINPROGRESS:
				return SYSM_INPROG;
			case EBADF:
				close(fd);
				return -1;
			default:
				close(fd);
				perror("getsockopt");
				break;
                }

	/* return 0 if socket ok to do I/O */
        vals = can_write(fd,0);

	if (debug)
		print_err(0, "talktcp.c:can_write returned %d", vals);

        if ( vals == TRUE )
                return SYSM_OK;

	return SYSM_INPROG; /* connection still in progress */
}

/*
 * sends the specified line out the specified filedescriptor -- we add
 * cr and newline to the end.  return: bytes written out socket
 */
int sendline(int fd, char *buffer)
{
	int val = -1;
	char *space;

	signal(SIGPIPE, handle_sig_pipe); /* set signal handler if there is
			a problem */
	space = MALLOC(strlen(buffer)+3, "sendline-temp buffer"); /* allocate memory for buffer */
	if (space == NULL) {
		print_err(1, "talktcp.c: MALLOC failed for sendline buffer");
		signal(SIGPIPE, SIG_DFL);
		return -1;
	}
	memset(space, 0, strlen(buffer)+3);
	strncpy(space, buffer, strlen(buffer)); /* copy stuff to temp buffer */
	strncat(space, "\r\n", 2); /* add end stuff */
	val = write(fd, space, strlen(space)/* - test - jared +1 */);
	if (val == -1)
	{
		if (debug)
			perror("sendline:write");
	}
	signal(SIGPIPE, SIG_DFL); /* set signal type back to default */
	FREE(space); /* free the memory */
	return val; /* return the number of bytes written */
}

int can_write(int fd, int secs)
{
        /* check the descriptor fd for pending data -- wait up to 'secs'
                seconds for data, else return a timeout (FALSE)
         */
        fd_set rd, wr, except;
        struct timeval local_timeout;

        int ret = 0;

        /* set up all the data structures */
        FD_ZERO(&wr);
        FD_ZERO(&except);
        FD_ZERO(&rd);
        FD_SET(fd, &wr);
        local_timeout.tv_sec = secs;
        local_timeout.tv_usec = 0;
        /* done */

        ret = select(fd+1, &rd, &wr, &except, &local_timeout);
        if (ret < 0)
        {
		if (debug)
		{
	                perror("talktcp.c:can_write:select");
		}
                return -1;
        }

        if (ret == 0) /* if timelimit exceeded */
                return FALSE;

        /* else, there is data waiting in this socket */
        return TRUE;
}

int data_waiting_read(int fd, int secs)
{
	/* check the descriptor fd for pending data -- wait up to 'secs'
		seconds for data, else return a timeout (FALSE)
	 */
	fd_set rd, wr, except;
	struct timeval local_timeout;

	int ret = 0;

	/* set up all the data structures */
	FD_ZERO(&wr);
	FD_ZERO(&except);
	FD_ZERO(&rd);
	FD_SET(fd, &rd);
	local_timeout.tv_sec = secs;
	local_timeout.tv_usec = 0;
	/* done */

	ret = select(fd+1, &rd, &wr, &except, &local_timeout);
	if (ret < 0)
	{
		if (debug)
		{
			perror("talktcp.c:data_waiting_read:select");
		}
		return -1;
	}

	if (ret == 0) /* if timelimit exceeded */
		return FALSE;

	/* else, there is data waiting in this socket */
	return TRUE;
}

int getline_tcp(int fd, char *buffer)
{
        char buf; /* buffer */
        int red = 0; /* bytes read */
	int counter = 0;
	int selTimeout = 0;
	int ret = 0;

	/* Null it out */
	memset(buffer, 0, sizeof(buffer));

        while ( 1 ) /* while forever */
        {
		if (clienthead == NULL)
		{
			ret = data_waiting_read(fd, 1);
		} else if (clienthead->filedes == -1)
		{
			ret = data_waiting_read(fd, 1);
		} else {
			ret = data_waiting_read(fd, 0);
		}

		if (ret == -1) /* if an error */
		{
			selTimeout++;
			if (selTimeout > 20) /* if we've waited too long */
			{
				if (debug)
				print_err(0, "Timeout REACHED-selTimeout");
				return 0; /* bail */
			}

			if (clienthead->filedes == -1)
				continue;

			continue; /* go along and try again */
		}

		red = 0; /* init it */
		if (ret > 0) /* if there's data waiting */
		{
	                red = read(fd, &buf, 1);
		}

                if (red == -1)
		{
			if (debug)
				perror("talktcp.c:getline_tcp:read");
                        return -1;
		}

                if (red == 0)
                {
			counter++;
			if (counter > 20)
			{
				return -1; /* error */
			}
                        continue;
                }
        	if ((strlen(buffer) == 0) && ((buf == '\n') || (buf == '\r')))
		{
			continue; /* throw \r or \n if at beginning of line */
		}
                if ((buf == '\n') || (buf == '\r'))
		{
                        return 0;
		}
                strncat(buffer, &buf, 1);
		if (strlen(buffer) > 200)
		{
			return 0;
		}
        }
}

/* this socket will be used for both sending and receiving */
int open_host(char *host, int port, int *filedes, int ltimeout)
{
	int fails = 0;
        struct sockaddr_in name;
        struct my_hostent *hp;
        int errcode = -1;
	int serrno = 0 ;
	time_t start_time;

	/* record current time */
	start_time = time(NULL);

	/* open a filedescriptor to use */
        *filedes = open_sock();

	/* check for error */
	if (*filedes == -1)
	{
		/* try again.. maybe a fluke */
		*filedes = open_sock();
		if (*filedes == -1)
			return(-1); /* return error */
	}

	/* get the data structure for the hostname */
        hp = my_gethostbyname(host, AF_INET);

        if (hp == 0) 
	{
		/* print an error if one happened */
		if (debug)
	                print_err(0, "%s: unknown host", host);
                return SYSM_NODNS;
        }

	/* zero out the space */
        memset ( &name, 0, sizeof ( name ) );

	/* copy data */
        memcpy((char*)&name.sin_addr, (char*)hp->my_h_addr_v4, hp->h_length_v4);

	/* set family type */
        name.sin_family = AF_INET;

	/* set the port we're connecting to */
        name.sin_port = htons(port);

        /* try to make the connection */
        while (1) 
	{
		if (debug)
			print_err(0, "Calling connect() with fd = %d", *filedes);

                errcode = connect(*filedes, (struct sockaddr*)&name,
                                  sizeof(struct sockaddr_in));
		/* doesn't happen often, but can, so we must trap
		 * for it, duh! PR#34
		 */

		if (errcode == 0)
			return SYSM_OK;

		/* Save that error code so it doesn't get clobbered */
		serrno = errno;

		if (debug)
			print_err(0, "serrno = %d, errcode = %d", serrno, errcode);

		if ((errcode == -1) && (serrno == EINPROGRESS))
		{
			if (debug)
			{
				print_err(0, "talktcp.c:connection in progress");
			}
			break;
		} else if (errcode == -1) {
			perror("open_host:connect");
		}

                if ((errcode == -1) && (serrno != EINPROGRESS))
		{
			if (close(*filedes) == -1)
			{
				return -1; /* close the fd incase it's left */
			}
			fails ++; /* failure my son */

			switch(serrno)
			{
				case ECONNREFUSED:
				case EINTR:
					if (fails >= MAX_TRIES)
						return SYSM_CONNREF;
                                	*filedes = open_sock();
					break;
				case ENETUNREACH:
					return SYSM_NETUNRCH;
				case EHOSTDOWN:
				case EHOSTUNREACH:
					return SYSM_HOSTDOWN;
				case ETIMEDOUT:
					return SYSM_TIMEDOUT;
				default:
					break;
                	}
		}
        }

	if (serrno == EINPROGRESS)
	while (1)
	{
		errcode = is_open(*filedes);
		if (errcode == 0)
		{
			break;
		}

		/* check to see if we should have timed out already */
		if (time(NULL) >= start_time+ltimeout)
		{
			if (debug)
				print_err(0, "open_host: timeout reached");
			if (close(*filedes) == -1)
				return -1; /* don't leak that fd */
			return SYSM_TIMEDOUT; /* return connection timed out */
		}
	
		if (debug)
			print_err(0, "While connecting, got %s(%d)",
				errtostr(errcode),errcode);
		if (errcode == 1 || errcode == 2 || errcode == 3 || 
			errcode == 4)
		{
			if (close(*filedes) == -1)
			{
				perror("talktcp.c:open_host:second_loop_close");
				return -1;
			}
			return errcode;
		}
	}

        return 0; /* return ok status */
}

/* 
 * Create a nonblocking socket for the other functions to 
 * handle and do processing with 
 */
int open_sock() 
{
        int sock = 0;

	sock = socket(AF_INET, SOCK_STREAM, 0);

        if (sock == -1) 
        {
                perror("opening datagram socket");
		if (debug)
			print_err(0, "sock = %d at return(-1)", sock);
		return -1;
        }

	set_nonblock(sock);

        return sock;
}

/*
 *
 */
void set_nonblock(int sock)
{
	int errcode;

#if defined (NBIO_FCNTL)
#if ! defined (FNDELAY)
#define FNDELAY O_NDELAY
#endif /* ! defined (FNDELAY) */

	errcode = fcntl (sock, F_SETFL, FNDELAY) ;

#else /* defined NBIO_FCNTL */
	/* linux and whatnot */
	int state = 1;

	errcode = ioctl (sock, FIONBIO, (char *) &state) ;
#endif /* defined NBIO_FCNTL */

	if (errcode == -1)
	{
		perror("set_nonblock");
	}

}

/*
 * wait until we are ready
 */
void blocktillready(int fd, int secs)
{
	time_t start = time(NULL); /* duh */ 

	while ((time(NULL) - start) > secs)
	{
		if (is_open(fd))
			return;
		sleep(1);
	}
}
