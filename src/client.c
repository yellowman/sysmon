/* $Id: client.c,v 1.27 2003/05/18 03:00:07 jared Exp $ */

#include "config.h"

/* pre-defines */
char *myname;

int facility = -2, dnsexpire = 0;
char *log_file;
bool debug = FALSE;
int dnslog = FALSE;
unsigned long queuetime = 60;
unsigned short int disable_icmp = 0;
bool mallocdebug = FALSE;
struct dnscache *dnshead = NULL;
struct clientstatus *clienthead = NULL;
bool do_syslog = FALSE;
struct downdata {
	char hostname[256];
	int type;
	int port;
	int lastcheck;
	int downct;
	int notified;
	time_t deathtime;
};

void	do_exit()
{
#ifdef NICEINTERFACE
	int maxy, maxx;
        getmaxyx(stdscr, maxy, maxx); /* get the max x, and the max y */
	move(maxy, 0);
	doupdate();
	refresh();
	nocbreak();
	noraw();
	echo();
	nl();
	endwin();
#endif	/* NICEINTERFACE */
	printf("\r\n\r");
	/* done setting terminal back */
	exit(0);
	/* never reached */
}

void	client_poll(unsigned int local_timeout)
{
	sleep(local_timeout);
}

void	parse_data(char *buff, struct downdata *stuff, int bufflen)
{
	int x = 0, end, start = 0, field = 0;
	char space[256];

	/*
	** Rather than go through a bunch of sequential loops, we
	** might as well make this one big loop and keep track of
	** which field we're parsing. --Majdi
	*/

	for (;x < bufflen;x++)
	{
		if (buff[x] == ':')
		{
			field++;
			end = x;

			memset(space,0,sizeof(space));

			strncat(space, buff+start, (end - start));

			switch(field)
			{
				case 1:
					strcpy(stuff->hostname, space);
					break;
				case 2:
					stuff->type = atoi(space);
					break;
				case 3:
					stuff->port = atoi(space);
					break;
				case 4:
					stuff->lastcheck = atoi(space);
					break;
				case 5:
					stuff->downct = atoi(space);
					break;
				case 6:
					stuff->notified = atoi(space);
					break;
				case 7:
					stuff->deathtime = atol(space);
					break;
			}
			start = x+1;
		}
	}
}

void	show_data(struct downdata down, int ln)
{
	char *data = timedata(down.deathtime);
	char tempbuff[1024];
	sprintf(tempbuff, "%-25.24s%-6s%-5d%-6d%-6s%-15s%s\n", down.hostname,
                type_to_name(down.type), down.port, down.downct,
                yes_no(down.notified), errtostr(down.lastcheck), data);
#ifdef NICEINTERFACE
	mvaddstr(ln, 0, tempbuff);
#else
	fprintf(stdout, tempbuff);
#endif /* NICEINTERFACE */
        FREE(data);
}

#ifdef NICEINTERFACE
void	bottom_banner()
{
	int maxx, maxy;
	char tempbuff[1024];

	getmaxyx(stdscr, maxy, maxx); /* get the max x, and the max y */

        memset(tempbuff, 0, 1024);
        memset(tempbuff, '-', maxx);
	mvaddstr(maxy-2, 0, tempbuff);
	mvaddstr(maxy-1, 0, " q = quit   space = refresh   h = help\n");
}

#endif /* NICEINTERFACE */

void	top_banner(char *server)
{
        time_t t;
        char nfo[30];

#ifdef NICEINTERFACE
	char tempbuff[1024];
	int maxx, maxy;
	getmaxyx(stdscr, maxy, maxx);
#endif

        time (&t); /* get the time */
        strcpy(nfo,ctime(&t)+4); /* convert it to a string, copy to buffer */

#ifdef NICEINTERFACE
	sprintf(tempbuff, "Server: %-30s%-20s%-20s", server, 
		"     Current Time: ", nfo);
	mvaddstr(0,0, tempbuff);
	
	sprintf(tempbuff, "%-25s%-6s%-5s%-6s%-6s%-15s%s\n", 
		"Hostname", "Type", "Port", 
		"Count", "Notif", "Stat", "Time Failed");
	mvaddstr(1,0, tempbuff);
	memset(tempbuff, 0, 1024);
	memset(tempbuff, '-', maxx);
	mvaddstr(2,0,tempbuff);
	mvaddstr(3,0, "");
	doupdate();
	refresh();
#else
	fprintf(stdout,"%-25s%-6s%-5s%-6s%-6s%-15s%s\n", "Hostname", "Type", 
		"Port", "Count", "Notified", "Stat", "Time Failed");
#endif
}

void	text_query(char *server, int port)
{
}

void	start_client(char *server, int port)
{
	int ret, filedes;
	char buff[256];
	struct downdata data;
	struct my_hostent *hp;
	int ln = 3;

	hp = my_gethostbyname(server, AF_INET);
	if (hp == NULL)
	{
		fprintf(stderr, "unable to find %s in DNS\n", server);
		exit(1);
	}


	/* Do the open_host call */
	ret = open_host(server, port, &filedes, 20);
	if (ret == SYSM_INPROG)
	{
		if (debug)
		{
			printf("Connection in progress, waiting until FD is ready\n");
		}
		blocktillready(filedes, 20);
		
	}

	if (debug)
		fprintf(stdout,"open_host returned %d with fd %d\n", ret, 
			filedes);
	if (ret != 0)
	{
		fprintf(stderr, "Unable to connect to %s:%d\n", server, port);
		exit(1);
	}
	
	getline_tcp(filedes, buff);
	if (debug)
		fprintf(stdout,"Got this: %s\n", buff);
	if (strncmp(buff, "111", 3) != 0)
	{
		fprintf(stderr,"invalid response from server\n");
		fprintf(stderr,"got:%s:\n", buff);
		do_exit();
	}
	if (debug)
		fprintf(stdout,"sending status request\n");
	sendline(filedes, "STAT");
	top_banner(server);
#ifdef NICEINTERFACE
	mvaddch(ln, 0, 0);
#endif /* NICEINTERFACE */
	while (1)
	{
		getline_tcp(filedes, buff);
		if (debug)
			fprintf(stdout,"got this: :%s:\n", buff);
		/* hostname, type, port, lastcheck, downct, deathtime */
		if (strncmp(buff, "333", 3) == 0)
			break; /* done reading data */
		/* parse the line to extract the important data */
		parse_data(buff, &data, sizeof(buff));
		show_data(data, ln);
		ln++;
	}
#ifdef NICEINTERFACE
	clrtobot();
	bottom_banner();
#endif
	
	sendline(filedes, "QUIT");
	getline_tcp(filedes, buff);
	if (close(filedes) == -1)
		return;
}

#ifdef NICEINTERFACE
void	my_client_sleep(int sleeptime)
{
        time_t start = time(NULL); /* record start time */
        time_t now = time(NULL); /* time now */
        char ch = '\0', nfo[30];
        int maxx, maxy;

        getmaxyx(stdscr, maxy, maxx); /* get the max x, and the max y */
	doupdate();
	refresh();

	if (debug)
	        fprintf(stdout, " starting to sleep... \n");

        while ((now-start) < sleeptime)
        {
		/* 0 = stdin */
		if (data_waiting_read(0, 1))
		{
			ch = getch();
			if (ch == 'q' || ch == 'Q')
			{
				doupdate();
				refresh();
				do_exit();
			} 
			else
				return;
		/* normally we would parse the input and do other
		   fancier things, but not now */
		}

	/* should really be doing a select() on stdin with a timeout value
		of one second */

                time(&now);
		strcpy(nfo, ctime(&now)+4); /* convert it to a string */
		doupdate();
		refresh();
		mvaddstr(0, 58, nfo);
		doupdate();
		refresh();
		doupdate();
		refresh();

        }
	if (debug)
	        fprintf(stdout, " waking up \n");

}

#endif /* NICEINTERFACE */

int	main(int argc, char **argv)
{
	char server[1024]; /* remove server to connect to */
	char *temp;
	int port = SYSMON_PORTNUM; /* remote port number */
#ifdef NICEINTERFACE
	char tempbuf[1024];
#endif /* NICEINTERFACE */

	myname = argv[0]; /* save myname */

	temp = getenv("SYSMON_HOST");
	if (temp != NULL)
	{
		strcpy(server, temp);
	} 
	switch(argc)
	{
		case 2:
			strcpy(server, argv[1]);
			break;
		case 3:
			strcpy(server, argv[1]);
			port = atoi(argv[2]);
			break;
		default:
			if (temp != NULL)
				break;
			fprintf(stderr,"usage: %s server-host-name [ port ]\n", 
				argv[0]);
			exit(1);
	}

	if (debug)
		fprintf(stderr, "host: %s port: %d \n", server, port);

#ifdef NICEINTERFACE

	/* ncurses setup stuff */
	initscr(); /* Initalize the screen */
	nocbreak(); /* FOO */
	raw(); 	/* set raw mode */
	noecho();  /* set no echo */
	nonl();		/* no newline */
	/* end curses setup */

	clear();
	refresh();
	sprintf(tempbuf, 
		"Connecting to server %s and getting inital data...\n", 
		server);
	mvaddstr(0,0, tempbuf);

	/* ncurses update the screen stuff */
	doupdate();
	refresh();
	clear(); /* for when the next screen refresh happens */
#endif
	start_client(server, port);

#ifdef NICEINTERFACE
	while (1)
	{
		doupdate();
		refresh();

		my_client_sleep (60);

		start_client(server, port);
	}
#endif /* NICEINTERFACE */
	return(0);
}
