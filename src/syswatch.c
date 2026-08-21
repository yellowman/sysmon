/* $Id: syswatch.c,v 1.197 2014/07/09 16:29:39 jared Exp $ */
#include "config.h"
#include "ping-helper.h"

/* Normal global vars */
unsigned char *ident_hash = NULL;
bool gotsighup = FALSE;   /* quit all things we're doing asap, and then
				cleanup and shuffle config files, etc.. */
bool stop_daemon = FALSE;
int numqueued = 0;   /* number of elements in the queue */
time_t boottime = 0; /* boot time for uptime */
bool debug = 0; /* debugging flag - 0 = off 1 = on */
bool mallocdebug = FALSE; /* 0 = off, 1 = on */
char *myname; /* myname */
char *log_file; /* Log file used if facility = -3 */
u_long addr=0; /* IP Addr to bind to */
struct all_elements_list *currenthead = NULL; /* master list of objects */
struct spawn_def *spawn_defs_head = NULL; /* list of spawn command definitions */
struct graph_elements *configed_root = NULL;
struct dnscache *dnshead = NULL;
struct clientstatus *clienthead;
struct monitorent *queuehead = NULL;
struct protoent *icmpproto;
bool statuschanged = TRUE;
bool quiet = FALSE;
bool not_started_yet = TRUE;
bool do_syslog = TRUE;
time_t last_queued_at = 0;
bool last_queued_warn = FALSE;
int snmp_trap_fd = -1;
unsigned long elements_to_monitor = 0; /* gets updated with how many
						elements we monitor */
unsigned short int killed = 0;
unsigned short int killafter = 61; /* kill a check after this many seconds */
unsigned short int warnafter = 45; /* warn of a stale check after */
unsigned short int warnlog = 1; /* default = on */

/* Wakeup retry configuration */
#define DEFAULT_MAX_WAKEUP_RETRIES 3  /* Default max retry attempts for stale checks */
unsigned short disable_icmp = 0;
unsigned short int use_ping_helper = 0;  /* Use setuid helper for ICMP/ICMPv6 */

/* command line specified vars & args */
#define CONFIGFILE_SIZE 256
char configfile[CONFIGFILE_SIZE]; /* config file path */
bool donotify = 1; /* Do notifies - a value of 0 doesn't notify contacts */
int dofork = 0; /* 0 = fork, 1 = don't */
bool ckconfigonly = FALSE; /* 0 = normal, 1 = just check config then exit */
bool send_reload_sig = FALSE; /* false = no send sighup to pid listed in /etc/sysmond.pid */
bool paused = FALSE; /* false = do not suspend monitoring */
bool send_pause_sig = FALSE; /* false = do not send pause signal */
bool send_stop_sig = FALSE; /* false = do not send pause signal */
bool badconfig = FALSE; /* false = config parsed ok */

/* defaults set in set_defaults */
int numfailures; /* Number of failures before mailing contact */
int minnumfailures = 1; /* Minimum failures before yellow status (default 1) */
int flaptime = 0; /* Minutes to show green after recovery (default 0 = disabled) */
int inactivetime; /* timeout for client inactivity */
int globtimeout; /* amount of time it takes to time out internal tests 
			(in seconds) */
int globtimeoutlen; /* when to dequeue the request (in seconds) */
int pageinterval; /* no re-page interval for hosts when they're down,
			otherwise the number of minutes to re-page in */
bool showupalso; /* show up also in textfile */
unsigned long queuetime; /* How often to queue an individual request */
int facility; /* facility to log into */
int glob_icmp_fd = -1; /* Global ICMP file des */
int glob_icmpv6_fd = -1; /* Global ICMPv6 file descriptor */
int maxqueued;   /* number of elements that can be in the queue at
			once - delay queueing until it comes down,
			default = 75, 0 = Unlimited (Dangerous) */
int cieling_max_queued; /* based on limit of open files */
char *pmesg = NULL;
char *subject = NULL;
char *sender = NULL;
int dnslog = 900;
int dnsexpire = 3600;
bool heartbeat = TRUE;
bool nologconnects = FALSE;
char *errorsto = NULL;
char *replyto = NULL;
int html = -1;
char *statusfilename = NULL;
char *statustempdirname = NULL;
char *cssfilename = NULL;
char *upcolor = NULL;
char *downcolor = NULL;
char *recentcolor = NULL;
char *globhdr = NULL;
char *globhdrval = NULL;
char *authkey = NULL;
/* Unset means "local", so a single-box install needs no config change. */
char *sitename = NULL;
char *sitedesc = NULL;
char *path_savestate = NULL;
char *statefile = NULL;
#ifdef HAVE_LIBPTHREAD
pthread_mutex_t Sysmon_Giant;
#endif /* HAVE_LIBPTHREAD */

extern int max_numnei;

struct all_elements_list *parser_head = NULL;


/* set defaults */
void set_defaults()
{
	/* Set global variables to some sort of defaults */

	numfailures = 4;
	minnumfailures = 1;
	flaptime = 0;
	inactivetime = 300;
	globtimeout = 30;
	globtimeoutlen = 35;
	pageinterval = 0;
	showupalso = FALSE;
	queuetime = 60;
	facility = LOG_DAEMON;
	maxqueued = 75;
	dnslog = 900;
	dnsexpire = 3600;
	heartbeat = TRUE;
	html = -1;
	if (errorsto != NULL)
	{
		free(errorsto);
		errorsto = NULL;
	}
	if (replyto != NULL)
	{
		free(replyto);
		replyto = NULL;
	}
	if (globhdr != NULL)
	{
		free(globhdr);
		globhdr = NULL;
	}
	if (globhdrval != NULL)
	{
		free(globhdrval);
		globhdrval = NULL;
	}
	if (statusfilename != NULL)
	{
		free(statusfilename);
		statusfilename = NULL;
	}
	if (statustempdirname != NULL)
	{
		free(statustempdirname);
		statustempdirname = NULL;
	}
	if (cssfilename != NULL)
	{
		free(cssfilename);
		cssfilename = NULL;
	}
	if (pmesg != NULL)
	{
		free(pmesg);
		pmesg = strdup(PMESG);
		if (pmesg == NULL)
		{
			print_err(1, "reset_defaults: strdup(PMESG) failed - out of memory");
			exit(1);
		}
	}
	if (statefile != NULL)
	{
		free(statefile);
		statefile = NULL;
	}
	if (subject != NULL)
	{
		free (subject);
		subject = strdup(SUBJECT);
		if (subject == NULL)
		{
			print_err(1, "reset_defaults: strdup(SUBJECT) failed - out of memory");
			exit(1);
		}
	}
	if (sender != NULL)
	{
		free(sender);
		sender = NULL;
	}
	if (upcolor == NULL)
	{
		upcolor=strdup(UPCOLOR);
		if (upcolor == NULL)
		{
			print_err(1, "reset_defaults: strdup(UPCOLOR) failed - out of memory");
			exit(1);
		}
	} else {
		free(upcolor);
		upcolor = strdup(UPCOLOR);
		if (upcolor == NULL)
		{
			print_err(1, "reset_defaults: strdup(UPCOLOR) failed - out of memory");
			exit(1);
		}
	}
	if (downcolor == NULL)
	{
		downcolor = strdup(DOWNCOLOR);
		if (downcolor == NULL)
		{
			print_err(1, "reset_defaults: strdup(DOWNCOLOR) failed - out of memory");
			exit(1);
		}
	} else {
		free(downcolor);
		downcolor = strdup(DOWNCOLOR);
		if (downcolor == NULL)
		{
			print_err(1, "reset_defaults: strdup(DOWNCOLOR) failed - out of memory");
			exit(1);
		}
	}
	if (recentcolor == NULL)
	{
		recentcolor = strdup(RECENTCOLOR);
		if (recentcolor == NULL)
		{
			print_err(1, "reset_defaults: strdup(RECENTCOLOR) failed - out of memory");
			exit(1);
		}
	} else {
		free(recentcolor);
		recentcolor = strdup(RECENTCOLOR);
		if (recentcolor == NULL)
		{
			print_err(1, "reset_defaults: strdup(RECENTCOLOR) failed - out of memory");
			exit(1);
		}
	}
}

/* 
 * This function counts total hosts, those up currently, down currently
 * and stores them in long ints, for showing in textfiles
 */

void update_count()
{
	unsigned long total = 0;
	struct all_elements_list *here;
	for (here = currenthead; here != NULL;here=here->next)
	{
		total++;
		/* A (re)loaded object is new to every client, whatever it was
		   called before, so stamp it as changed now. A client asking
		   "what moved since N" after a SIGHUP gets the whole tree. */
		if (here->value != NULL)
			object_changed(here->value->data);
	}
	print_err(0, "total entries to be monitored = %d", total);
	elements_to_monitor = total;
	return;
}

void usage ()
{
	/* Print out the real way to use the program */
	fprintf(stderr,"Usage: %s [ -f config-file ] [ -n ] [ -d ] [ -v ] [ -t ] \n\t [ -p port ] [ reload ] \n", myname);
	fprintf(stderr,"  -b             : IP Address to listen on\n");
	fprintf(stderr,"  -f config-file : Alternate config file location\n");
	fprintf(stderr,"          DEFAULT: %s\n", CFILE);
	fprintf(stderr,"  -n             : Don't do notifies\n");
	fprintf(stderr,"  -d             : Don't fork\n");
	fprintf(stderr,"  -i             : Disable ICMP\n");
	fprintf(stderr,"  -v             : Print version then exit\n");
	fprintf(stderr,"  -w             : Toggle warning messages\n");
	fprintf(stderr,"  -D             : Toggle debug messages\n");
	fprintf(stderr,"  -M             : Toggle memory debugging\n");
	fprintf(stderr,"  -t             : Test/check config file then exit\n");
	fprintf(stderr,"  -p #           : Change port number listening on (0 to disable)\n");
	fprintf(stderr,"  -q             : Quiet\n");
	fprintf(stderr,"  -l             : do not syslog\n");
	fprintf(stderr,"  reload         : Test/check config file, and if it passes, reload config (SIGHUP)\n");
	fprintf(stderr,"  pause          : Suspend/resume monitoring (SIGUSR2)\n");
	fprintf(stderr,"  resume         : Suspend/resume monitoring (SIGUSR2)\n");
	fprintf(stderr,"  stop           : End monitoring and quit (SIGTERM)\n");
#ifdef ENABLE_SNMP
	fprintf(stderr, "\nSNMP support is available\n");
#endif /* ENABLE_SNMP */
	exit(1);
}

/*
 * Toggle warning logging
 */
void toggle_warnlog()
{
	if (warnlog)
		warnlog = 0;
	else
		warnlog = 1;
	signal(SIGUSR1, toggle_warnlog);
}

/*
 * Toggle pause
 */
void toggle_pause()
{
	if (paused)
	{
		paused = 0;
		print_err(0, "monitoring unpaused");
	} else {
		paused = 1;
		print_err(0, "monitoring PAUSED");
	}
	signal(SIGUSR2, toggle_pause);
}

/* parse the command line arguments */
void cmdline(int argc, char **argv, char *conf_file, int *listenport)
{
	int er = 0, x;

	for (x=1; argc > x ; x++)
	{
		if (argv[x][0]=='-')
		{
			switch (argv[x][1]) 
			{
				case 'b':
					if (x+1 == argc)
						usage();
					addr=inet_addr(argv[x+1]);
					x++;
					break;
				case 'f':
					if (x+1 == argc)
						usage();
					/* Use snprintf to prevent buffer overflow */
					if (strlen(argv[x]+2) > 0)
					{
						snprintf(conf_file, CONFIGFILE_SIZE, "%s", argv[x]+2);
					}
					else if (x+1 < argc)
					{
						snprintf(conf_file, CONFIGFILE_SIZE, "%s", argv[x+1]);
						x++;
					}
					break;
				case 'p': /* alternate port number */
					if (x+1 == argc)
						usage();
					*listenport = atoi(argv[x+1]);
					x++; /* skip it as the next arg */
					break;
				case 'i':
					disable_icmp = TRUE;
					print_err(1, "ICMP disabled");
					break;
				case 'n': /* don't do notifies */
					donotify = FALSE;
					break;
				case 'd': /* don't fork */
					dofork = TRUE;
					break;
				case 'l': /* no syslog */
					do_syslog = FALSE;
					break;
				case 't': /* verify config file */
					ckconfigonly = TRUE;
					break;
				case 'M': /* malloc debug on */
					mallocdebug = TRUE;
					break;
				case 'w': /* warning log */
					toggle_warnlog();
					break;
				case 'D': /* debug on */
					debug = 1;
					print_err(1, "Debug On");
					break;
				case 'v': /* print version */
					fprintf(stdout, "%s\n", SYSM_VERS);
					exit(0);
				case 'q': /* Quiet */
					quiet = TRUE;
					break;
				case '-': /* gnu style args */
					if (strcmp(argv[x]+2, "version") == 0)
					{
						fprintf(stdout, "%s\n", SYSM_VERS);
						exit(0);
					}
					if (strcmp(argv[x]+2, "help") == 0)
						usage();
				default:
					er++;
			}
		} else {
			if (strcmp(argv[x], "reload") == 0)
			{
				send_reload_sig = TRUE;
				ckconfigonly = TRUE;
			} else if (strcmp(argv[x], "pause") == 0 ||
			  strcmp(argv[x], "resume") == 0)
			{
				send_pause_sig = TRUE;
				ckconfigonly = TRUE;
			} else if (strcmp(argv[x], "stop") == 0 ||
			  strcmp(argv[x], "shutdown") == 0 ||
			  strcmp(argv[x], "suicide") == 0)
			{
				send_stop_sig = TRUE;
				ckconfigonly = TRUE;
			}
		}
	} /* end for */
	/* error */
	if (er > 0)
		usage();
}

void handle_stop()
{
	stop_daemon = TRUE;
}

/* 
 * Stop the daemon, free memory that is currently allocated
 * and other fun stuff like that, such that we are not
 * leaking anything, etc..
 */
void stop_it(time_t now)
{

	print_err(1, "Please remain seated as your ride comes to a complete stop");

	/* insert cleanup code here */

	/* dump current network status to a file */
	if (html != -1)
		dump_to_file(statusfilename, html, now);
	if (path_savestate != NULL)
		save_state(path_savestate);


	/* timeout old clients */
	inactivetime = 0;

	/* expire clients */
	timeout_clients();

	/* free dead client memory */
	dead_client_cleanup();

	if (clienthead != NULL)
	{
		/* un bind the listen socket */
		if (clienthead->filedes != -1)
			close(clienthead->filedes); 
	}
	/* Free the memory */
	FREE(ident_hash);

	/* set the timer to zero */
	dnsexpire = 0;

	/* clear dns cache */
	expire_dns(now);

	/* free the memory in use */
	free_tree(currenthead);

	/* Attempt to nuke the pidfile */
	unlink(sysmon_pidfile());

	exit(0);
}

/*
 * BUG: should allow port setting in config file, and port
 * BUG: settings change in config file w/ SIGHUP or other signal
 */
void setup_client_listen(int listenport)
{
	clienthead = MALLOC(sizeof(struct clientstatus), "clienthead");
	if (clienthead == NULL) {
		print_err(1, "syswatch.c: MALLOC failed for clienthead");
		exit(1);
	}

	/* listen on port PORTNUM */
	if (listenport == 0)
	{
		clienthead->filedes = -1;
	} else {
		clienthead->filedes = init_tcp_socket(listenport);
	}

	/* master client socket */
	clienthead->clientver = -1;
	clienthead->next = NULL;
}

/* 
 * Dump the queue state based on all elements.. should be roughly
 * in the same order as the config file
 */
void recurs_print_q(int filedes, struct all_elements_list *start)
{
	char buffer[256];
	struct all_elements_list *here;

	if (start == NULL)
		return;

	for (here=start; here!= NULL; here=here->next)
	{
		if (here->value->data->queued == 1)
		{
			snprintf(buffer, sizeof(buffer), "treeQ: %s", 
				here->value->unique_name);
		       	sendline(filedes, buffer);
		}
	}
}

void print_queue(int filedes)
{
	char buffer[256];

	/* Print out the currently queued entries for debugging */
	recurs_print_q(filedes, currenthead);

	snprintf(buffer, sizeof(buffer), "Number of elements in queue count: %d", numqueued);
	sendline(filedes, buffer);

	return;
}

/*
 * This is where we actually add the object into the queue
 * for monitoring.
 */
void queue_check(struct hostinfo *entry, unsigned char *unique_name)
{
	struct monitorent *newentry = NULL;

	/* put a pointer on the stack for this entry */

	/* stick it at the top for easy access */

	if (entry == NULL)
	{
		print_err(1, "queue_check called w/ NULL");
		return;
	}
	if (entry->queued == 1)
	{
		print_err(1, "BUG:queue_check: Attempt to queue check already in q");
		return;
	}
	entry->warnlog = 0; /* reset warnings for long time btw checks */
	newentry = MALLOC(sizeof(struct monitorent), "new entry - monitorent in queue_check");
	if (newentry == NULL) {
		print_err(1, "syswatch.c: MALLOC failed for queue entry");
		return;
	}

	newentry->checkent = entry;
	newentry->unique_name = unique_name; /* DO NOT FREE */
	newentry->started = 0;
	newentry->monitordata = NULL;
	gettimeofday(&newentry->queueat, NULL);
	newentry->retval = -1;
	newentry->filedes = -1;
	newentry->fd_state = 0;
	newentry->checkent->queued = 1;

	/* Initialize wakeup tracking fields (CRITICAL: prevents garbage values) */
	newentry->wakeup_count = 0;
	newentry->last_wakeup_time = 0;

	/* insert it at the top of the queue */
	newentry->next = queuehead;
	queuehead = newentry;

	numqueued++;

	/* entry is queued for checking */
	if (debug)
	{
		print_err(0, "queue_check:Queued %s:%s:%p", 
			entry->hostname, type_to_name(entry->type), entry);
	}

	return;
}

/*
 * This function is used to walk the queue to determine if an object
 * should be queued for testing/check
 */
void walk_queue_checks_add(struct graph_elements *here, time_t now, struct graph_elements **array_elements, int *numele)
{
	int x;

	/* trouble check */   
	if (here == NULL)
		return;

	/* If we've been here, we SHOULD NOT do any work here */
	if (here->visit == TRUE)
	{ 
		if (debug)
		print_err(0, "walk_queue_checks: %s already visited",  here->unique_name);
		return;
	}

	/* trouble check */
	if (here->data == NULL)
		return;

	/* don't check if it's in the queue */
	if (here->data->queued)
		return;

	/* Set the visited flag */
	here->visit = TRUE;
	 
	if (debug || here->data->trace)
	{
		print_err(0, "walk_queue_checks_add - working with %s (lchecktime+here->queuetime) = %d, now=%d, numqueued=%d maxqueued=%d",
			here->unique_name, (here->data->lchecktime+here->data->queuetime),
			now, numqueued, maxqueued);
	}

	/* Queue it if it's time to be queued */
	if (here->data->next_queuetime <= now )
	{
		array_elements[(*numele)] = here;
		(*numele)++;
	}

	/* if we are "up" (or down if reverse is set) walk our
	 * neighbors and queue them as well */
	if ( ((here->data->lastcheck == 0) && (here->data->reverse == 0)) ||
		((here->data->lastcheck != 0) && (here->data->reverse == 1)) )
	{
		for (x = 0; x < here->tot_nei; x++)
		{
			walk_queue_checks_add(here->neighbors[x], now, array_elements, numele);
		}
	}
}

/*
 * This function is used to walk the queue to determine if an object
 * should be queued for testing/check
 */
void walk_queue_checks(struct graph_elements *here, time_t now)
{
        int x;
        bool last_queued_warn = FALSE;

        /* trouble check */
        if (here == NULL)
                return;

        /* If we've been here, we SHOULD NOT do any work here */
        if (here->visit == TRUE)
        {
                if (debug)
                print_err(0, "walk_queue_checks: %s already visited",  here->unique_name);
                return;
        }

        /* trouble check */
        if (here->data == NULL)
                return;

        /* don't check if it's in the queue */
        if (here->data->queued)
                return;

        /* Set the visited flag */
        here->visit = TRUE;

        if (debug)
        {
                print_err(0, "walk_queue_checks - working with %s (lchecktime+here->queuetime) = %d, now=%d, numqueued=%d maxqueued=%d",
                        here->unique_name, (here->data->lchecktime+here->data->queuetime),
                        now, numqueued, maxqueued);
        }

        /* Queue it if it's time to be queued */
        if (here->data->next_queuetime <= now )
        {
                /* Do not exceed queue limit */
                if (numqueued <= maxqueued)
                {
                        last_queued_at = now;
                        queue_check(here->data, here->unique_name);

                        /* BUG: We may want to add a return HERE to allow
                         * us to not monitor children at the same time
                         * as the parent object
                         */
                } else {
                        /* BUG: no checks have left the queue in the past 3
                         * seconds and we still have things to monitor
                         */

                        if (((last_queued_at+3) < now) && warnlog && (last_queued_warn == FALSE))
                        {
                                print_err(1, "too many checks in the queue, unable to queue checks after %d seconds", (now-last_queued_at));
                                last_queued_warn = TRUE;
                        }

                        return;
                }

        }

        /* if we are "up" (or down if reverse is set) walk our
         * neighbors and queue them as well */
        if ( ((here->data->lastcheck == 0) && (here->data->reverse == 0)) ||
                ((here->data->lastcheck != 0) && (here->data->reverse == 1)) )
        {
                for (x = 0; x < here->tot_nei; x++)
                {
                        walk_queue_checks(here->neighbors[x], now);
                }
        }
}

/*
 * time comparison function for qsort
 */
int q_time_cmp(const void *arg_a, const void *arg_b)
{
        struct graph_elements *sort_a, *sort_b;

        /* Cast from const void * to struct graph_elements ** then dereference */
        sort_a = *(struct graph_elements * const *)arg_a;
        sort_b = *(struct graph_elements * const *)arg_b;

	/* if they're both null, then they're equal */
	if ((sort_a == NULL) && (sort_b == NULL))
		return 0;
	/* if b is null, they're not */
	if (sort_b == NULL)
		return 1;
	/* if a is null, they're not */
	if (sort_a == NULL)
		return -1;
#ifdef DEBUG_QSORT
	printf ("q_time_cmp: working on 0x%x (%s) and 0x%x\n", (unsigned int)sort_a, sort_a->unique_name, (unsigned int)sort_b);
#endif /* DEBUG_QSORT */
	/* if eq, return eq */
	if ((sort_a->data == NULL) && (sort_b->data == NULL))
		return 0;
	/* if b->data is null, they're not equal */
	if (sort_b->data == NULL)
		return 1;
	/* if a->data is null, they're not equal */
	if (sort_a->data == NULL)
		return -1;

	/* if sort_a eq sort_b */
	if (sort_a->data->next_queuetime == sort_b->data->next_queuetime)
		return 0;
	/* if sort_a gt sort_b */
	if (sort_a->data->next_queuetime > sort_b->data->next_queuetime)
		return 1;
	/* if sort_a lt sort_b */
	return -1;
}

#ifndef QSORT_WAY
/*
 * Add objects that need to be checked to the queue
 * such that they will be monitored
 */
void queue_checks(time_t now)
{
        if (configed_root != NULL)
        {
                /* Insure the visited flag is not set */
                clear_visited();
                walk_queue_checks(configed_root, now);
        } else {
                print_err(1, "no configured root?");
        }
        clear_visited();
}
#else

/*
 * Add objects that need to be checked to the queue 
 * such that they will be monitored
 * return the number of seconds until the next object is ready
 * to be queued
 */
int queue_checks_qsort_way(time_t now)
{
	struct graph_elements **queue_list;
	int numele = 0;
	int curr = 0;
	size_t alloc_size = 0;

	if (configed_root == NULL)
	{
		/* no objects to monitor */
		print_err(1, "Nothing to monitor, should pause 60 seconds");
		return 60;
	}

	/* allocate some space for all the objects */
	alloc_size = ((sizeof(struct graph_elements*) * (elements_to_monitor+1)));
	queue_list = MALLOC(alloc_size, "queue_list");
	if (queue_list == NULL) {
		print_err(1, "syswatch.c: MALLOC failed for queue_list");
		return 60;
	}
	for (curr = 0; curr < elements_to_monitor ; curr++)
	{
		queue_list[curr] = NULL;
	}

	/*
	 * what we want to do is take the current
	 * set of objects and then quicksort()
	 * to update the sorting criteria and walk the list
	 * top-down as necessary
	 */
	if (configed_root != NULL)
	{
		/* Insure the visited flag is not set */
		clear_visited();

		/* add objects to queue_list that are ready to be tested */
		walk_queue_checks_add(configed_root, now, queue_list, &numele);

		/* cleanup */
		clear_visited();

		if (numele > 0)
		{
#ifdef DEBUG_QSORT
		        printf("elements_to_monitor = %ld, sizeof sizeof(struct graph_elements*) = %d, alloc_size = %d\n", elements_to_monitor, sizeof(struct graph_elements*), alloc_size);
	                printf("qsort debug:\n");
	                for (curr = 0; curr < numele ; curr++)
	                {
	                        printf("\t0x%x\t%s\t%d\t%x\n", (int)queue_list[curr], queue_list[curr]->unique_name, (now-queue_list[curr]->data->next_queuetime), (int)queue_list[curr]->data);
	                }
#endif /* DEBUG_QSORT */

			/* sort based on queue time */
			qsort(queue_list, numele, sizeof(struct graph_elements *), q_time_cmp);

			/* now queue them based on the time */
			for (curr = 0; curr < numele; curr++)
			{
				/* Do not exceed queue limit */
				if (numqueued <= maxqueued)
				{
					last_queued_at = now;
					last_queued_warn = FALSE;

					/* add it to the queue */
					if (queue_list[curr] != NULL)
						queue_check(queue_list[curr]->data, queue_list[curr]->unique_name);
				} else {
					/* XXX: no checks have left the queue in the past 3
					 * seconds and we still have things to monitor 
					 */
				
					if (((last_queued_at+3) < now) && warnlog && (last_queued_warn == FALSE))
					{
						print_err(1, "too many checks in the queue, unable to queue checks after %d seconds", (now-last_queued_at));
						last_queued_warn = TRUE;
					}
				}
			}
		}
	} else {
		print_err(1, "no configured root?");
	}

	FREE(queue_list);
	return 1;
}
#endif /* QSORT_WAY */

/*
 *
 */
void needssleep(time_t now_t)
{
	fd_set rd, wr, except;
	struct timeval local_timeout;
	struct clientstatus *clienthere = NULL;
	struct monitorent *here = NULL;
	int mincalctime = 2; /* BUG: somewhat arbitrary right now, but should work well for most folks i hope */
	int maxfd = 1;
	struct timeval now_timeval;

        /* cache the current time */
        gettimeofday(&now_timeval, NULL);


	/* determine if we need sleep */

	/* set up all the data structures */
	FD_ZERO(&wr);
	FD_ZERO(&except);
	FD_ZERO(&rd);

	/* Service clients */
	client_poll();

	/* Watch the clients for data to be read */
	for (clienthere = clienthead; clienthere != NULL;
		clienthere = clienthere->next)
	{
		if (clienthere->filedes == -1)
		{
			continue;
		}
		FD_SET(clienthere->filedes, &rd);
		if (clienthere->filedes > maxfd)
			maxfd = clienthere->filedes;
	}

	/* basically, set up all the fd's we need to watch
		in a fd_set with select timeout set for the
		minimum time for any check in the tree for
		the time it needs to wake up, include client
		fd's in this also */
	for (here=queuehead;here!= NULL;here=here->next)
	{
		if (here->filedes == -1)
			continue;
		if (here->retval != -1)
			continue;
		if (here->fd_state)
		{
			FD_SET(here->filedes, &rd);
		} else {
			FD_SET(here->filedes, &wr);
		}
		if (here->filedes > maxfd)
			maxfd = here->filedes;
	}

	/* if the snmp trap fd is set, watch it and reset maxfd accordingly */
	if (snmp_trap_fd != -1)
	{
		FD_SET(snmp_trap_fd, &rd);
		if (snmp_trap_fd > maxfd)
			maxfd = snmp_trap_fd;
	}

	/* if icmp enabled, watch icmp fd */
	if (glob_icmp_fd > maxfd && (!disable_icmp))
	{
		maxfd = glob_icmp_fd;
		FD_SET(glob_icmp_fd, &rd);
	}

	/* if icmpv6 enabled, watch icmpv6 fd */
	if (glob_icmpv6_fd > maxfd && (!disable_icmp))
	{
		maxfd = glob_icmpv6_fd;
		FD_SET(glob_icmpv6_fd, &rd);
	}

	/* Check:
	   checkent->next_queuetime for diff to now */
        for (here=queuehead;here!= NULL;here=here->next)
	{
		if (here->checkent->next_queuetime > now_t)
			if ((here->checkent->next_queuetime - now_t) < mincalctime)
				mincalctime = here->checkent->next_queuetime - now_t;
	}
/*	printf("mincalctime = %d\n", mincalctime); */
	local_timeout.tv_sec = mincalctime;
	local_timeout.tv_usec = 0;

	/*
	 * An rtt check paces its probes in milliseconds, which is finer
	 * than this timeout's usual whole seconds. Ask each one when it
	 * next needs to send and shorten the sleep to suit, or the probe
	 * schedule is silently rounded up to however often we happen to
	 * wake and a five-sample check stretches over ten seconds.
	 */
	if (!disable_icmp)
	{
		double soonest = -1.0;

		for (here = queuehead; here != NULL; here = here->next)
		{
			double due = rtt_ms_until_next_probe(here, &now_timeval);

			if (due < 0.0)
				continue;
			if (soonest < 0.0 || due < soonest)
				soonest = due;
		}

		if (soonest >= 0.0)
		{
			double budget = local_timeout.tv_sec * 1000.0 +
				local_timeout.tv_usec / 1000.0;

			if (soonest < budget)
			{
				local_timeout.tv_sec = (time_t)(soonest / 1000.0);
				local_timeout.tv_usec = (suseconds_t)
					((soonest - local_timeout.tv_sec * 1000.0) * 1000.0);
			}
		}
	}

	/* Watch the fd_sets accordingly */
	select(maxfd+1, &rd, &wr, &except, &local_timeout);

	/* if icmp enabled */
	if (!disable_icmp && glob_icmp_fd > 0)
	{
		/* and there are icmp packets */
		if (FD_ISSET(glob_icmp_fd, &rd))
		{
			/* handle pending icmp responses */
			handle_icmp_responses();
		}
	}
	/* if icmpv6 enabled */
	if (!disable_icmp && glob_icmpv6_fd > 0)
	{
		/* and there are icmpv6 packets */
		if (FD_ISSET(glob_icmpv6_fd, &rd))
		{
			/* handle pending ping icmpv6 responses */
			handle_pingv6_responses();
		}
	}
	/* if snmp traps are enabled */
	if (snmp_trap_fd != -1)
	{
		/* and there are pending snmp trap packets */
		if (FD_ISSET(snmp_trap_fd, &rd))
		{
			process_snmp_trap(snmp_trap_fd);
		}
	}

	/*
	 * current queue
	 */
	for (here=queuehead;here!= NULL;here=here->next)
	{
		/* if no file desc, then no need to check up on it */
		if (here->filedes == -1)
			continue;
		/* if retval is not -1 (pending) */
		if (here->retval != -1)
			continue;
		if (FD_ISSET(here->filedes, &rd))
		{
			service_this(here, &now_timeval, now_t);
		}
	}

	/* Expire pending dns entries */
	expire_dns(now_t);
}

void stop_this(struct monitorent *here)
{
	switch (here->checkent->type)
	{
		case SYSM_TYPE_TCP:
		       	stop_test_tcp(here);
		       	break;
		case SYSM_TYPE_UDP:
		       	stop_test_udp(here);
		       	break;
		case SYSM_TYPE_PING:
		       	stop_test_ping(here);
		       	break;
		case SYSM_TYPE_PKTLOSS:
		       	stop_test_pktloss(here);
		       	break;
		case SYSM_TYPE_PING_LATENCY:
		       	stop_test_rtt(here);
		       	break;
#ifdef ENABLE_SNMP
		case SYSM_TYPE_SNMP:
		       	stop_test_snmp(here);
		       	break;
#endif /* ENABLE_SNMP */
		case SYSM_TYPE_NNTP:
		       	stop_test_nntp(here);
		       	break;
		case SYSM_TYPE_SMTP:
		       	stop_test_smtp(here);
		       	break;
		case SYSM_TYPE_IMAP:
		       	stop_test_imap(here);
		       	break;
		case SYSM_TYPE_POP3:
		       	stop_test_pop3(here);
		       	break;
		case SYSM_TYPE_X500:
		       	stop_test_x500(here);
		       	break;
#ifdef IMPLEMENT
		case SYSM_TYPE_POP2:
		       	stop_test_pop2(here);
		       	break;
		case SYSM_TYPE_BOOTP:
		       	stop_test_bootp(here);
		       	break;
#endif /* IMPLEMENT */
		case SYSM_TYPE_DNS:
		       	stop_check_dns(here);
		       	break;
		case SYSM_TYPE_WWW:
		       	stop_test_www(here);
		       	break;
		case SYSM_TYPE_RADIUS:
		       	stop_check_radius(here);
		       	break;
#ifdef IMPLEMENT
		case SYSM_TYPE_HTTPS:
		       	stop_test_https(here);
		       	break;
#endif /* IMPLEMENT */
		case SYSM_TYPE_SYSM:
		       	stop_check_sysmon(here);
		       	break;
		case SYSM_TYPE_SSHD:
		       	stop_test_sshd(here);
		       	break;
#ifdef HAVE_IPv6
		case SYSM_TYPE_PINGv6:
			stop_test_pingv6(here);
#endif /* HAVE_IPv6 */
		default:
			print_err(1, "stop_this:BUG Invalid event type");
			break;
       	}
}

void service_this(struct monitorent *here, struct timeval *now_timeval, time_t now_t)
{
	if (here == NULL)
	{
		print_err(1, "service_this:BUG Called with NULL `here'");
		return;
	}
	if (debug || here->checkent->trace)
	{
		print_err(0, "service_this:Servicing entry in queue of %s:%s",
			here->checkent->hostname,
			type_to_name(here->checkent->type));
	}

	if (here->started)
	{
		/* service a check already started */
		switch (here->checkent->type)
		{
			case SYSM_TYPE_TCP: service_test_tcp(here, now_t);
				break;
			case SYSM_TYPE_UDP: service_test_udp(here, now_t);
				break;
			case SYSM_TYPE_PING: service_test_ping(here, now_timeval);
				break;
			case SYSM_TYPE_PKTLOSS: service_test_pktloss(here, now_timeval);
				break;
			case SYSM_TYPE_PING_LATENCY: service_test_rtt(here, now_timeval);
				break;
#ifdef ENABLE_SNMP
			case SYSM_TYPE_SNMP: service_test_snmp(here);
				break;
#endif /* ENABLE_SNMP */
			case SYSM_TYPE_NNTP: service_test_nntp(here, now_t);
				break;
			case SYSM_TYPE_SMTP: service_test_smtp(here, now_t);
				break;
			case SYSM_TYPE_IMAP: service_test_imap(here, now_t);
				break;
			case SYSM_TYPE_POP3: service_test_pop3(here, now_t);
				break;
			case SYSM_TYPE_X500: service_test_x500(here);
				break;
#ifdef IMPLEMENT
			case SYSM_TYPE_POP2: service_test_pop2(here);
				break;
			case SYSM_TYPE_BOOTP: service_test_bootp(here);
				break;
#endif /* IMPLEMENT */
			case SYSM_TYPE_DNS: service_check_dns(here);
				break;
			case SYSM_TYPE_WWW: service_test_www(here, now_t);
				break;
			case SYSM_TYPE_RADIUS: service_check_radius(here, now_t);
				break;
/* Never compiled: HAVE_SSL is not defined by any build, and
   service_test_https() has no definition anywhere in the tree, so
   enabling this arm fails to link. The type is refused at parse
   time for that reason - see name_to_type() in lib.c. */
#ifdef HAVE_SSL
			case SYSM_TYPE_HTTPS: service_test_https(here);
				break;
#endif /* HAVE_SSL */
			case SYSM_TYPE_SYSM: service_check_sysmon(here, now_t);
				break;
#ifdef HAVE_IPv6
			case SYSM_TYPE_PINGv6: service_test_pingv6(here);
				break;
#endif /* HAVE_IPv6 */
			case SYSM_TYPE_SSHD: service_test_sshd(here, now_t);
				break;

			default: print_err(1, "service_this:BUG, invalid event type");
				break;
		} /* end switch */
	}
	if (!here->started)
	{
		switch (here->checkent->type)
		{
			case SYSM_TYPE_TCP: 
				start_test_tcp(here, now_t);
				break;
			case SYSM_TYPE_UDP: 
				start_test_udp(here, now_t);
				break;
			case SYSM_TYPE_PING:
				start_test_ping(here);
				break;
			case SYSM_TYPE_PKTLOSS:
				start_test_pktloss(here);
				break;
			case SYSM_TYPE_PING_LATENCY:
				start_test_rtt(here);
				break;
#ifdef ENABLE_SNMP
			case SYSM_TYPE_SNMP: 
				start_test_snmp(here);
				break;
#endif /* ENABLE_SNMP */
			case SYSM_TYPE_NNTP: 
				start_test_nntp(here, now_t);
				break;
			case SYSM_TYPE_SMTP: start_test_smtp(here, now_t);
				break;
			case SYSM_TYPE_IMAP: start_test_imap(here, now_t);
				break;
			case SYSM_TYPE_POP3: start_test_pop3(here, now_t);
				break;
			case SYSM_TYPE_X500: start_test_x500(here, now_t);
				break;
#ifdef IMPLEMENT
			case SYSM_TYPE_POP2: start_test_pop2(here);
				break;
			case SYSM_TYPE_BOOTP: start_test_bootp(here);
				break;
#endif /* IMPLEMENT */
			case SYSM_TYPE_DNS: start_check_dns(here);
				break;
			case SYSM_TYPE_WWW: start_test_www(here, now_t);
				break;
			case SYSM_TYPE_RADIUS: start_check_radius(here, now_t);
				break;
/* Likewise unimplemented; see the note on the service arm. */
#ifdef HAVE_SSL
			case SYSM_TYPE_HTTPS: start_test_https(here);
				break;
#endif /* HAVE_SSL */
			case SYSM_TYPE_SYSM: start_check_sysmon(here, now_t);
				break;
#ifdef HAVE_IPv6
			case SYSM_TYPE_PINGv6: start_test_pingv6(here);
				break;
#endif /* HAVE_IPv6 */
			case SYSM_TYPE_SSHD: start_test_sshd(here, now_t);
				break;

			default: print_err(1, "service_this:BUG, invalid event type");
				break;
		} /* end switch */
		here->started = TRUE;
	}
}

void handle_retval(struct monitorent *handle_this, time_t now)
{
	if (debug || handle_this->checkent->trace)
	{
		print_err(0, "handle_retval:dequeued %s:%s:%p",
			handle_this->checkent->hostname,
			type_to_name(handle_this->checkent->type),
			handle_this);

		print_err(0, "handle_retval:checking %s type %s got us %s",
			handle_this->checkent->hostname,
			type_to_name(handle_this->checkent->type),
			errtostr(handle_this->retval));
	} /* endif debug */

	handle_this->checkent->totalchecked++;

	/* Set next time object should be queued */
	handle_this->checkent->next_queuetime = now+ handle_this->checkent->queuetime;

	if (handle_this->retval != handle_this->checkent->lastcheck)
	{
		/* XXX */
		client_send_statechange(handle_this->unique_name, handle_this->checkent->lastcheck, handle_this->retval);
		object_changed(handle_this->checkent);
	}

	/* Do necessary post-check status stuff */

	/* check to see if the service came up */
	if ((handle_this->retval == SYSM_OK) &&
		(handle_this->checkent->contacted == TRUE) &&
		(handle_this->checkent->lastcheck != SYSM_OK))
	{
		/* if so, set the state */
		handle_this->checkent->lastcheck = handle_this->retval;

		if (debug)
			print_err(1, "handle_retval:donotify = %d, handle_this->checkent->contact_when = %d", donotify, handle_this->checkent->contact_when);
		/* determine if we need to page */
		if (donotify && (handle_this->checkent->contact_when & SYSM_CONTACT_UP))
		{
			/* page */
			if (debug) print_err(1, "handle_retval:calling page_someone");
			page_someone(handle_this->checkent, SYSM_CONTACT_UP, now);
		}

		handle_this->checkent->last_up = now;
		handle_this->checkent->last_recovery = now; /* for flaptime feature */

		/* reset contacted */
		handle_this->checkent->contacted = FALSE; /* init it */

	} /* endif some long if statement */

	/* if service is down, and state is
	   same as last time */
	if ((handle_this->retval != SYSM_OK) &&
		(handle_this->checkent->lastcheck == handle_this->retval))
	{
		/* increment times service has failed */
		handle_this->checkent->downct++;
		handle_this->checkent->totaldown++;

		if (debug) print_err(1, "handle_retval downct = %d, max = %d", handle_this->checkent->downct, handle_this->checkent->max_down);

		/* if it's failed too many times and we
			haven't paged */

		if ((handle_this->checkent->downct >=
			handle_this->checkent->max_down) &&
			(handle_this->checkent->contacted == FALSE) &&
			(handle_this->checkent->contact_when & SYSM_CONTACT_DOWN))
		{
			/* page someone */
			page_someone(handle_this->checkent, SYSM_CONTACT_DOWN, now);
		}

	} /* endif some other retval check thing */

	/* state changed */
	if (handle_this->retval != handle_this->checkent->lastcheck)
	{
		int was_ok = (handle_this->checkent->lastcheck == SYSM_OK);

		handle_this->checkent->upct = 0;
		handle_this->checkent->lastcheck = handle_this->retval;

		if (handle_this->retval != SYSM_OK)
		{
			handle_this->checkent->downct = 1;
			handle_this->checkent->totaldown++;
			/* A new outage starts when we FALL from OK. Changing
			 * from one failure kind to another is the SAME outage:
			 * keep the original deathtime so "down for X" and the
			 * outage clock don't reset midway through. (This block
			 * also used to stamp deathtime and bump totaldown on
			 * transitions back to OK - pure bookkeeping damage.) */
			if (was_ok || handle_this->checkent->deathtime == 0)
				handle_this->checkent->deathtime = now;

			if (debug) print_err(1, "handle_retval downct = %d, max %d", handle_this->checkent->downct, handle_this->checkent->max_down);
			/* if it's failed too many times and we
				haven't paged */

			if ((handle_this->checkent->downct >=
				handle_this->checkent->max_down) &&
				(handle_this->checkent->contacted == FALSE) &&
				(handle_this->checkent->contact_when & SYSM_CONTACT_DOWN))
			{
				/* page someone */
				page_someone(handle_this->checkent, SYSM_CONTACT_DOWN, now);
			}
		}
		else
		{
			handle_this->checkent->downct = 0;
		}

	} /*endif handle_this->retval!=handle_this->checkent->lastcheck*/

	/* If we came up, clear this counter */
	if (handle_this->retval == SYSM_OK)
	{
		handle_this->checkent->upct ++;
		handle_this->checkent->downct = 0;
		/* An ack lives for one outage. The first OK check ends both. */
		if (handle_this->checkent->acked)
		{
			handle_this->checkent->acked = FALSE;
			object_changed(handle_this->checkent);
		}
		/* and maybe tell someone */
		if ((handle_this->checkent->upct >=
			handle_this->checkent->max_down) &&
			(handle_this->checkent->contacted == FALSE) &&
			(handle_this->checkent->contact_when == SYSM_CONTACT_UP))
		{
			/* page someone */
			page_someone(handle_this->checkent, SYSM_CONTACT_UP, now);
		}
	}

	statuschanged = TRUE;

	return;
}

/*
 *
 */
void service_checks(time_t now)
{
	struct monitorent *here, *last, *freeit;
        struct timeval now_timeval;


	if (queuehead == NULL)
	{
		return;
	}

        /* cache the current time */
        gettimeofday(&now_timeval, NULL);


	/* setup checks that need to be, service current checks */
	last = NULL;
	freeit = NULL;
	here = queuehead;
	while (here != NULL)
	{
		/* if no return value */
		if (here->retval == -1)
		{
			service_this(here, &now_timeval, now); /* service the check */
			last = here;
		} else {
			/* Handle the return value */
			handle_retval(here, now);

			/* set the current element to be free'ed */
			freeit = here;

			/* detect trouble */
			if (here->checkent == NULL)
			{
				print_err(1, "service_checks:BUG: here->checkent == NULL");
			}
			/*
			  Tag it as not queued in the check entry
			  otherwise it won't ever get checked again
			 */
			here->checkent->queued=0;

			/* 
			   Decrease counter saying how many elements
			   are in the queue.  This is important if we
			   are doing max-queue-size stuff
			 */
			numqueued--; 	/* decrease queue counter */

			/* Save the time of the completion of our check */
			here->checkent->lchecktime = now;

			if (last == NULL)
			{ /* If we intend to free the head of the queue */
				queuehead = here->next;
			} else {
				last->next = here->next;
			}
		}
		 
		here = here->next;

		if (freeit != NULL)
		{
			FREE(freeit);
			freeit = NULL;
		}
	} /* end while */

}

void fast_cleanup_checks()
{
	struct monitorent *here, *next;
	/* cleanup checks, and shut them down asap */

	if (numqueued == 0)
	{
		if (debug)
		{
			print_err(0, "fast_cleanup_checks w/ no checks in queue");
		}
		return;
	} 

	/* walk the current queue */
	for (here = queuehead ; here != NULL ; here=here->next)
	{
		if (debug) 
		{
			print_err(0, "in q @ sighup - %s:%d", here->checkent->hostname,
				here->checkent->type);
		}
		if (!here->started)
		{
			here->checkent->queued = 0;
			here->retval = here->checkent->lastcheck;
		} else {
			if (here->monitordata != NULL)
			{
				stop_this(here);
			}

		}
	}

	/* Free everything in the queue */
	for (here = queuehead ; here != NULL ; )
	{
		if (here == NULL)
			break;

		next = here->next;
		FREE(here);
		numqueued--;
		here = next;

	}
	queuehead = NULL;
}

/*
 * This makes sure that something being monitored isn't "Dead"
 */
void wakeup_checks(time_t now_t)
{
	/* Wake up checks that have become stale, with retry logic */
	struct monitorent *here = NULL;
	struct monitorent *next = NULL;
	struct timeval now;
	double stale_time;
	unsigned int max_retries;

	gettimeofday(&now, NULL); /* get the current time */

	if (debug)
	{
		print_err(0, "syswatch.c:wakeup_checks() checking for stale checks");
	}

	/* Walk the current queue */
	here = queuehead;
	while (here != NULL)
	{
		next = here->next;  /* Save next pointer before potential modifications */
		stale_time = mydifftime(here->queueat, now);

		if (debug)
		{
			print_err(0, "syswatch.c:wakeup_checks() examining %s:%s:%d (queued %.2fs ago, wakeup_count=%u)",
				here->checkent->hostname,
				type_to_name(here->checkent->type),
				here->checkent->port,
				stale_time,
				here->wakeup_count);
		}

		/* Check if this check has been queued too long */
		if (stale_time >= killafter)
		{
			/* Determine max retries (use per-host config if set, otherwise default) */
			max_retries = (here->checkent->max_wakeup_retries > 0)
				? here->checkent->max_wakeup_retries
				: DEFAULT_MAX_WAKEUP_RETRIES;

			/* Check if we've exceeded max retries */
			if (here->wakeup_count >= max_retries)
			{
				print_err(0, "Permanently killing check %s:%s:%d after %u wakeup attempts (stale for %.2fs)",
					here->checkent->hostname,
					type_to_name(here->checkent->type),
					here->checkent->port,
					here->wakeup_count,
					stale_time);

				if (here->checkent->type != SYSM_TYPE_PING)
				{
					stop_this(here);
				}
				here->retval = SYSM_KILLED;
				killed++;
			}
			else
			{
				/* Wake up the stale check and retry */
				print_err(0, "Waking up stale check %s:%s:%d (attempt %u/%u, stale for %.2fs)",
					here->checkent->hostname,
					type_to_name(here->checkent->type),
					here->checkent->port,
					here->wakeup_count + 1,
					max_retries,
					stale_time);

				/* Stop the stuck check */
				if (here->checkent->type != SYSM_TYPE_PING)
				{
					stop_this(here);
				}

				/* Mark as timeout (will trigger alert if configured) */
				here->retval = SYSM_TIMEDOUT;

				/* Increment wakeup counter and update timestamp */
				here->wakeup_count++;
				here->last_wakeup_time = now_t;

				/* Re-queue by resetting last check time */
				/* This will cause queue_checks() to pick it up again */
				here->checkent->lchecktime = now_t - here->checkent->queuetime;

				if (debug)
				{
					print_err(0, "Re-queued %s:%s:%d for retry (lchecktime set to %ld)",
						here->checkent->hostname,
						type_to_name(here->checkent->type),
						here->checkent->port,
						here->checkent->lchecktime);
				}
			}
		}
		else if (stale_time >= warnafter && warnlog)
		{
			/* Warn about possibly stale check */
			print_err(0, "Possibly stale check of %s:%s:%d lasting %.2fs (wakeup_count=%u)",
				here->checkent->hostname,
				type_to_name(here->checkent->type),
				here->checkent->port,
				stale_time,
				here->wakeup_count);
		}

		here = next;
	}

	if (debug)
	{
		print_err(0, "wakeup_checks() exiting");
	}
}

void write_pid_file()
{
	pid_t mypid = getpid();
	FILE *fh;

	/*
	 * No euid check here: this must run BEFORE revoke_root_if_necessary()
	 * (the old euid==0 guard combined with being called after the
	 * privilege drop meant the pidfile was silently never written in any
	 * privilege-dropping setup, so tools reading it saw a stale or
	 * missing pid). Non-root runs simply get a perror if the path isn't
	 * writable.
	 */
	fh = fopen(sysmon_pidfile(), "w");
	if (fh == NULL)
	{
		perror(sysmon_pidfile());
		return;
	}
	fprintf(fh, "%d\n", mypid);
	if (fclose(fh) != 0)
	{
		perror("write_pid_file:fclose");
		return;
	}
}

/*
 * We should revoke root if it's not necessary anymore.
 * This would be done by doing a setuid(nobody) or something
 * that sort.  We should write pid file as superuser
 * or whatever is required.  Basically we only have to be
 * root to write /etc/sysmond.pid, and to create the
 * inital icmp file descriptor that we will be sending
 * our pings out.
 *
 * We should also be able to run as non-root if nothing icmp
 * is being monitored.  If we catch sighup as non-root, and 
 * reload conf file to have something imcp in it, we should
 * basically disable icmp totally, and reject those parts
 * of config file
 */
/*
 * The user this daemon drops to, or NULL if it is not running as root and
 * so will not drop at all. Looked up in one place because two callers need
 * it: the state directory is created and handed over before the drop, and
 * the drop itself happens after.
 */
struct passwd *sysmon_drop_user(void)
{
	struct passwd *pw;

	pw = getpwnam("nobody");
	if (pw == NULL)
		pw = getpwnam("daemon");
	return pw;
}

/*
 * Create the state directory and give it to the user we are about to
 * become. Separate from revoke_root_if_necessary() because the pidfile
 * lives in that directory and is written before the drop.
 */
void confgen_prepare_as_root(void)
{
	struct passwd *pw;

	if (geteuid() != 0)
	{
		/* Not root: nothing to hand over, and the directory is either
		   already ours or about to fail loudly when we write it. */
		confgen_prepare(getuid(), getgid());
		return;
	}

	pw = sysmon_drop_user();
	if (pw == NULL)
	{
		print_err(1, "WARNING: neither 'nobody' nor 'daemon' exists; "
			"leaving %s owned by root", confgen_statedir());
		confgen_prepare(0, 0);
		return;
	}
	confgen_prepare(pw->pw_uid, pw->pw_gid);
}

void revoke_root_if_necessary()
{
	uid_t current_uid;
	uid_t current_euid;
	struct passwd *pw;
	const char *drop_user = "nobody";  /* User to drop privileges to */

	current_uid = getuid();
	current_euid = geteuid();

	/* If not running as root, nothing to do */
	if (current_euid != 0)
	{
		if (debug)
		{
			print_err(0, "revoke_root: Not running as root (euid=%d), no privileges to drop", current_euid);
		}
		return;
	}

	pw = sysmon_drop_user();
	if (pw == NULL)
	{
		print_err(1, "WARNING: Cannot drop root privileges - neither "
			"'nobody' nor 'daemon' exists");
		return;
	}
	drop_user = pw->pw_name;

	/*
	 * ICMP needs no helper to survive the drop: the raw sockets were
	 * opened while still root, a raw socket's privilege is checked at
	 * creation rather than per send, and the descriptors keep working
	 * after setuid. The setuid helper is registered only as a fallback
	 * for a platform that refuses to send on them post-drop - which the
	 * send path discovers from the send itself (EPERM/EACCES) rather
	 * than assuming it here.
	 *
	 * The probe cannot be access(X_OK): we are still root here, so that
	 * answers yes for a helper the post-drop identity cannot run. What
	 * the fallback actually needs is setuid root plus an execute bit
	 * that reaches the user we are about to become - the install puts
	 * it at 4750 root:<drop group>, so group-exec counts only when the
	 * group matches, world-exec always does. The drop below clears
	 * supplementary groups to exactly pw_gid, so the primary gid is
	 * the whole story and this check matches post-drop reality.
	 */
	if (!disable_icmp)
	{
		struct stat hst;

		if (stat(PING_HELPER_PATH, &hst) == 0)
		{
			if ((hst.st_mode & S_ISUID) && hst.st_uid == 0 &&
			    ((hst.st_mode & S_IXOTH) ||
			     ((hst.st_mode & S_IXGRP) && hst.st_gid == pw->pw_gid)))
			{
				use_ping_helper = 1;
				print_err(0, "revoke_root: ICMP raw sockets opened while root stay usable after the drop; %s stands by as the fallback", PING_HELPER_PATH);
			}
			else
			{
				print_err(0, "revoke_root: ICMP raw sockets opened while root stay usable after the drop");
				print_err(0, "revoke_root: helper at %s is not setuid root and executable as %s (mode %04o, gid %d) - only matters if this platform refuses raw-socket sends after a privilege drop",
					PING_HELPER_PATH, drop_user,
					(unsigned int)(hst.st_mode & 07777),
					(int)hst.st_gid);
			}
		}
		else
		{
			print_err(0, "revoke_root: ICMP raw sockets opened while root stay usable after the drop");
			print_err(0, "revoke_root: no fallback helper at %s - only matters if this platform refuses raw-socket sends after a privilege drop", PING_HELPER_PATH);
		}
	}

	if (debug)
	{
		print_err(0, "revoke_root: Dropping privileges from root (uid=0) to user '%s' (uid=%d)",
			drop_user, pw->pw_uid);
	}

	/*
	 * Supplementary groups first, while still root: setgid/setuid do
	 * not touch them, and a process that keeps root's supplementary
	 * groups after "dropping" root has not dropped much. Clearing them
	 * also makes the helper probe above honest - from here on, pw_gid
	 * really is the only group this process holds, so a helper the
	 * probe called unusable genuinely is.
	 *
	 * On failure, warn and CARRY ON to setgid/setuid: a uid/gid drop
	 * with stale supplementary groups is a partial drop, but bailing
	 * out here would keep the daemon fully root, which is strictly
	 * worse. (The one side effect: a retained group could keep the
	 * ping helper usable after the probe called it unusable - the
	 * conservative direction, and only on this rare failure.)
	 */
	if (setgroups(1, &pw->pw_gid) != 0)
	{
		perror("revoke_root: setgroups");
		print_err(1, "WARNING: Failed to drop supplementary groups; "
			"continuing with the uid/gid drop");
	}

	/* Drop privileges */
	if (setgid(pw->pw_gid) != 0)
	{
		perror("revoke_root: setgid");
		print_err(1, "WARNING: Failed to drop group privileges to gid=%d", pw->pw_gid);
		return;
	}

	if (setuid(pw->pw_uid) != 0)
	{
		perror("revoke_root: setuid");
		print_err(1, "WARNING: Failed to drop user privileges to uid=%d", pw->pw_uid);
		return;
	}

	/* Verify privileges were actually dropped */
	if (geteuid() == 0 || getuid() == 0)
	{
		print_err(1, "CRITICAL: Failed to drop root privileges! Still running as root (uid=%d, euid=%d)",
			getuid(), geteuid());
		print_err(1, "CRITICAL: This is a security risk. Exiting.");
		exit(1);
	}

	print_err(0, "Successfully dropped root privileges to user '%s' (uid=%d, gid=%d)",
		drop_user, getuid(), getgid());
}

/*
 * main monitoring loop and last minute setup work
 */
void 
do_watch(char *cmdname, int listenport, char *myhostname)
{
	struct all_elements_list *hupdata = NULL;
	time_t now_t, last_t;
	time_t last_periodic_t = 0;
	time_t last_wakeup_t = 0;  /* Throttle wakeup_checks() calls */
	last_t = 0;

#ifdef HAVE_LIBPTHREAD
	pthread_mutex_init(&Sysmon_Giant, NULL);
#endif /* HAVE_LIBPTHREAD */

	setup_client_listen(listenport);

	/*
	 * Say plainly how - or whether - anything can talk to this daemon.
	 *
	 * The client socket used to be unconditional, and for most of this
	 * daemon's life it was an unauthenticated port opened by a process
	 * running as root. It is off unless asked for now, which means a box
	 * with neither a listener nor an aggregator monitors and pages
	 * perfectly well but cannot be looked at - a reasonable thing to want
	 * and a very easy thing to do by accident, so it gets said out loud.
	 */
	if (listenport > 0)
	{
		print_err(1, "listening for sysmon clients on TCP %d", listenport);
	}
	else if (aggregator_host != NULL)
	{
		print_err(0, "no client socket; reporting to sysmon-web at %s:%d",
			aggregator_host, aggregator_port);
	}
	else
	{
		print_err(1, "WARNING: no client socket and no aggregator - this daemon "
			"will monitor and page, but nothing can query it. Set "
			"\"config aggregator\" to report to a sysmon-web, or "
			"\"config listen 1345\" (or -p) for the sysmon client.");
	}
	if (!disable_icmp)
	{
		setup_icmp_fd();
#ifdef HAVE_IPv6
		setup_icmpv6_fd();
#endif /* HAVE_IPv6 */
	}
	/*
	 * The state directory holds the pidfile now, so it has to exist
	 * before the pidfile is written - and both have to happen while we
	 * are still root, because after the drop neither /var/db nor the
	 * directory's ownership is ours to arrange.
	 */
	confgen_prepare_as_root();
	write_pid_file();
	revoke_root_if_necessary();

	while (1)
	{
		time(&now_t);
		if (currenthead != NULL && (numqueued <= maxqueued)) 
		/* something in the tree to monitor */
		{
#ifndef QSORT_WAY
			queue_checks(now_t);   /* queue checks ready for us */
#else
			queue_checks_qsort_way(now_t);
#endif
		}

		/* Throttled wakeup check - run every 10 seconds instead of every second */
		if ((now_t - last_wakeup_t) >= 10)
		{
			wakeup_checks(now_t);  /* wakeup any "stale" checks */
			last_wakeup_t = now_t;
		}

		if (now_t > last_t)
		{
			last_t = now_t;
		}

		/* Process any pending ICMP/ICMPv6 replies BEFORE checking timeouts.
		 * This prevents a race condition where replies arrive but aren't processed
		 * before service_test_ping() evaluates timeouts, causing false negatives.
		 * We call handle_icmp_responses() here using non-blocking reads to drain
		 * the kernel buffer of any waiting packets.
		 */
		if (!disable_icmp && glob_icmp_fd > 0)
		{
			handle_icmp_responses();
		}
#ifdef HAVE_IPv6
		if (!disable_icmp && glob_icmpv6_fd > 0)
		{
			handle_pingv6_responses();
		}
#endif /* HAVE_IPv6 */

		/* Keep the aggregator link up, if one is configured. Cheap
		   when it already is, and never load-bearing: monitoring
		   carries on regardless of whether sysmon-web is reachable. */
		aggregator_poll(now_t);

		service_checks(now_t); /* do checks that are ready for us */

		needssleep(now_t);     /* if we need a sleep, do it here */

		/* only do this once every 60 seconds */
		if ((now_t - last_periodic_t) > 60)
		{
			do_tree_periodic(now_t); /* Do periodic checks/tests */
			last_periodic_t = now_t;
		}

		/* dump current network status to a file */
		if ((html != -1) && (statuschanged))
		{
			dump_to_file(statusfilename, html, now_t);
			statuschanged = FALSE;
		}

		/* stop_daemon must break this loop too: SIGTERM during a
		   pause otherwise sets the flag and then waits for an unpause
		   or a SIGHUP that may never come, and the supervisor's
		   graceful stop times out into a SIGKILL - skipping the very
		   state save a graceful stop exists for. */
		while (paused && !gotsighup && !stop_daemon)
		{
			time(&now_t);
			service_checks(now_t);
			wakeup_checks(now_t);
			do_tree_periodic(now_t);
			needssleep(now_t);
			/* Paused is not stopped: checks in flight still finish
			   and pages still record, and a pause can last hours -
			   the checkpoint keeps its schedule through it. */
			checkpoint_state(now_t, path_savestate);
		}

		/* Checkpoint check state every so often. Saving only at
		   shutdown meant a crash or power loss lost everything since
		   the last clean stop - and an unclean death is exactly when
		   the next start most needs to know who was already paged.
		   Self-gated to once per interval. */
		checkpoint_state(now_t, path_savestate);

		if (stop_daemon)
		{
			stop_it(now_t);
		}

		if (gotsighup)
		{
			/* Kill all checks currently pending */
			fast_cleanup_checks();

			/* do all the fun stuff */
			if (debug)
			{
				print_err(0, "calling sync_after_sighup");
			}
			/* Which config is live can change between reloads: a
			   delivery swaps the current generation, a rollback swaps
			   it back, and a revert drops it and returns to the seed.
			   Ask rather than remember. */
			hupdata = sync_after_sighup(currenthead,
				(char *)confgen_active_config());

			currenthead = hupdata;
			/* Must do this to avoid qsort having out of bounds issues
			 * fix from corne.cornelius/at/gmail.com */
			update_count();

			if (debug)
			{
				print_err(0, "resetting gotsighup");
			}
			gotsighup = FALSE;
			statuschanged = TRUE;
		}

	}
}

/*
 */
void periodic_rewalk(struct all_elements_list *here, time_t right_now, int down)
{
	struct all_elements_list *loc;

	for (loc=here;loc != NULL; loc=loc->next)
	{
		if (right_now > loc->value->data->next_queuetime)
		{

		if ((right_now > ((3 * loc->value->data->queuetime)+loc->value->data->next_queuetime)) && (warnlog))
		{
		if ((loc->value->data->next_queuetime != 0) && (!down) && (!loc->value->data->warnlog))
		{
			print_err(1, 
			"WARNING: check of %s:%s:%d not checked in %d seconds", 
				loc->value->data->hostname, 
				type_to_name(loc->value->data->type), 
				loc->value->data->port, 
				(right_now - loc->value->data->lchecktime));
#ifdef HAVE_LIBPTHREAD
			pthread_mutex_lock(&Sysmon_Giant);
#endif /* HAVE_LIBPTHREAD */
			loc->value->data->warnlog = 1;
#ifdef HAVE_LIBPTHREAD
			pthread_mutex_unlock(&Sysmon_Giant);
#endif /* HAVE_LIBPTHREAD */
		}
		}
		if (loc->value->data->lastcheck == SYSM_NODNS)
		{
			/* redo dns query */
			if (my_gethostbyname(loc->value->data->hostname, -1) 
				!= NULL)
			{
#ifdef HAVE_LIBPTHREAD
				pthread_mutex_lock(&Sysmon_Giant);
#endif /* HAVE_LIBPTHREAD */
				loc->value->data->lastcheck = 0;
#ifdef HAVE_LIBPTHREAD
				pthread_mutex_unlock(&Sysmon_Giant);
#endif /* HAVE_LIBPTHREAD */

			}
		}
		}
	}

}

/*
 * walk_periodic_page_checks
 * Walks graph based upon deps and hosts down
 * only called by periodic_page, but we need
 * to traverse the graph...
 */
void walk_periodic_page_checks(struct graph_elements *here, time_t now)
{
	int x;
	if (here == NULL)
		return;
	/* If we've been here, we SHOULD NOT do any work here */
	if (here->visit == 1)
	{
		if (debug)
			print_err(0, "walk_periodic_page_checks: %s already visited",  here->unique_name);
		return;
	}
	/* trouble check */
	if (here->data == NULL)
		return;
	here->visit = TRUE;
	/* Do the check and page */
	/* Use per-object pageinterval if set (-1 means use global) */
	int effective_pageinterval = (here->data->pageinterval == -1) ?
		pageinterval : here->data->pageinterval;

	if (((now - here->data->lastcontacted) > (effective_pageinterval*60)) &&
		(here->data->contacted))
	{
		page_someone(here->data, SYSM_CONTACT_DOWN, now);
	}

	/* BUG: walk_periodic_page_checks: are we doing this right? */
	if ( ((here->data->lastcheck == 0) && (here->data->reverse == 0)) ||
		((here->data->lastcheck != 0) && (here->data->reverse == 1)) )
	{
		for (x = 0; x < here->tot_nei; x++)
		{
			walk_periodic_page_checks(here->neighbors[x], now);
		}
	}

}

/*
 *
 */
void periodic_page(time_t now)
{
	if (configed_root != NULL)
	{
		clear_visited();
		walk_periodic_page_checks(configed_root, now);
	} else {
		print_err(1, "periodic_page: no configured root");
	}
	clear_visited();
}

void signal_ourselves(int oursignal)
{
	pid_t that_pid;
	FILE *fh;
	char buffer[256];

	fh = fopen(sysmon_pidfile(), "r");
	if (fh == NULL)
	{
		perror("signal_ourselves:fopen");
		return;
	}

	memset(buffer,0,256);
	if (fgets(buffer, 250, fh) == NULL)
	{
		perror("signal_ourselves:open_pid_file:fgets()");
	} else {
		that_pid = atoi(buffer);
		if (!quiet)
		print_err(1, "sending signal %d to sysmond process %d\n", oursignal, that_pid);
		if(kill(that_pid, oursignal) == -1)
		{
			perror("signal_ourselves:kill failed");
		}
	}

	if (fclose(fh) != 0)
	{
		perror("signal_ourselves:fclose");
		return;
	}
}

/*
 *
 */
static void zombiecollect(void)
{ 
	/* Collect any zombies */
	while(waitpid((pid_t)-1,(int*)0,WNOHANG)>0);
}

/*
 *
 */
void do_tree_periodic(time_t now)
{
	zombiecollect();

	/* walk tree and check for now valid dns entries */
	periodic_rewalk(currenthead, now, 0);

	/* walk tree and check for time to repage about sites */
	if (pageinterval != 0)
	{
		periodic_page(now);
	}
}


/* The main part of the program */
int main(int argc, char **argv)
{
	int pid = 0; /* pid of child */
	/*
	 * -1 means "nobody has said". The client socket is opt-in: a -p on
	 * the command line or "config listen" in the config turns it on, and
	 * without either the daemon never binds anything. See the comment on
	 * the listen directive in parser.l for why.
	 */
	int listenport = -1;
	char myhostname[80]; /* my hostname */
	struct rlimit thislimit; /* used for resetting fd limits */
	struct timeval tv;

	gettimeofday(&tv, NULL);
	srandom((unsigned int)(tv.tv_sec ^ tv.tv_usec ^ getpid()));

	/* setup the global defaults */
	set_defaults();

	ident_hash = MALLOC(0xffff, "ident_hash");
	if (ident_hash == NULL) {
		fprintf(stderr, "FATAL: Cannot allocate memory for ident_hash\n");
		exit(1);
	}
	boottime = time(NULL);

	myname = argv[0];
	dnslog_last_log = boottime;

	currenthead = NULL; /* initalize it */

	gethostname(myhostname, 80); /* get my hostname */

	/* trap those signals that tell us to stop and do proper
	   cleanup */
	signal(SIGHUP, reload_config);
	signal(SIGUSR1, toggle_warnlog);
	signal(SIGUSR2, toggle_pause);
	signal(SIGINT, handle_stop);
	signal(SIGQUIT, handle_stop);
	signal(SIGTERM, handle_stop);

#ifndef __FreeBSD__
	/* FreeBSD can trigger some interesting situations if
	   we trap their signals, eg:

	sysmond in free(): error: chunk is already free
	sysmond in malloc(): error: recursive call
	sysmond in malloc(): error: recursive call
	...

	 */

	signal(SIGBUS, ABORT);
	signal(SIGABRT, ABORT);
	signal(SIGILL, ABORT);
	signal(SIGBUS, ABORT);
#endif /* __FreeBSD__ */

	thislimit.rlim_cur = 1024;
	thislimit.rlim_max = 1024;

#if (defined(__FreeBSD) || defined(FreeBSD) || defined(__FreeBSD__) || \
	defined(sun))
	setrlimit(RLIMIT_NOFILE, &thislimit);
	getrlimit(RLIMIT_NOFILE, &thislimit);
#else
	setrlimit(RLIMIT_OFILE, &thislimit);
	getrlimit(RLIMIT_OFILE, &thislimit);
#endif
	cieling_max_queued = thislimit.rlim_cur;
	print_err(0, "sysmond: INFO: max queued cieling is %d ", cieling_max_queued);


	/* do some setting up for icmp stuff */
	if (!(icmpproto = getprotobyname("icmp")))
	{
		/* huh, what's icmp? */
		print_err(1, "sysmond:syswatch.c: unknown protocol icmp.");
		exit(1);
	}

	/* Use snprintf to prevent buffer overflow from long CFILE macro */
	snprintf(configfile, sizeof(configfile), "%s", CFILE);

	if (argc > 1)
	{
		cmdline(argc, argv, configfile, &listenport);
	}
	badconfig = FALSE;



	/*
	 * Two parses, and only when this box is managed.
	 *
	 * The first is the seed - /etc/sysmon.conf, or whatever -f named.
	 * It is read for one reason beyond being the fallback: it is where
	 * "config generation-dir" lives, and that has to be known before
	 * anything can look for a managed copy. The setting is locked
	 * immediately afterwards, so a delivered config cannot move the
	 * directory the daemon is currently running out of. (On a box with
	 * real filesystem permissions it could not take effect anyway - the
	 * daemon owns one directory and no others.)
	 *
	 * The second parse, if there is a managed generation, is the config
	 * this daemon actually runs.
	 */
	currenthead = loadconfig(configfile);
	update_globs_from_parser();
	confgen_lock_statedir();

	/*
	 * Command line wins over config: -p is somebody at a terminal saying
	 * what they want right now, and it is also how the config gets
	 * overridden when the config is the thing being debugged.
	 */
	if (listenport < 0)
		listenport = (parser_listenport >= 0) ? parser_listenport : 0;

	{
		const char *active = confgen_active_config();

		if (strcmp(active, configfile) != 0)
		{
			print_err(1, "running managed generation %lu from %s",
				confgen_generation(), confgen_statedir());
			free_tree(currenthead);
			currenthead = loadconfig((char *)active);
			update_globs_from_parser();
		}
		else
		{
			print_err(0, "running %s; generations would be kept in %s",
				configfile, confgen_statedir());
		}
	}

	if (max_numnei > maxqueued && (!quiet))
	{
		print_err(1, "WARNING: one object has %d nei/adj and maxqueued is %d, may cause trouble",
			max_numnei, maxqueued);
	}

	/* XXX: can this be done before parsing the config? */
	if (send_stop_sig) 
	{
		signal_ourselves(SIGTERM);
		exit(0);
	}

	/* check if we should pause/unpause monitoring */
	if (send_pause_sig)
	{
		signal_ourselves(SIGUSR2);
		exit(0);
	}

	not_started_yet = FALSE;

	update_count();

	if (ckconfigonly)
	{
		if (badconfig)
		{
			print_err(1, "Configuration file failed parsing, will not (re)load config file");
			exit(1);
		}
		if (send_reload_sig)
		{
			signal_ourselves(SIGHUP);
		}
		exit(0);
	}

	if (currenthead == NULL)
	{
		print_err(1, "main: currenthead == NULL - nothing to monitor, exiting");
		exit(1);
	}

	/*
	 * Put back what the last run knew: how long each host had been down,
	 * how many consecutive failures it was at, and whether anyone had
	 * already been paged about it. Without this a daemon restarted during
	 * an outage pages again for something it has already reported.
	 *
	 * After the config is loaded and before the first check, so the
	 * restored counts are what the first check compares against - and
	 * only at startup, because a SIGHUP reload already carries all of it
	 * across in hard_copy().
	 */
	load_state(path_savestate);

	/* if we're syslogging stuff, log a bootup message in syslog
	 */
	print_err(1, "Starting sysmon %s", SYSM_VERS);

	fprintf(stdout, "%s started on %s\n", myname, myhostname);

	if (heartbeat)
	{
		send_heartbeat(myhostname);
	}

	if (dofork == 0)
	{
		pid = fork();
	}

	if ((pid == 0) || (dofork == 1))
	{
		do_watch(argv[0], listenport, myhostname);
	} else {
		fprintf(stdout, "forked process as pid %d\n", pid);
	}
	exit(0);
}


int init_udp_socket(int listenport)
{
	struct sockaddr_in name;
	int sock;

	int on = 1;
	sock = socket(AF_INET, SOCK_DGRAM, 0);
	if (sock < 0) {
		perror("opening datagram socket");
		exit(2);
	}

	/* use keepalives to force us to die when the remote dies */
	if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, (void*)&on, sizeof(on)) == -1)
	{
	  	perror("init_socket:setsockopt: cannot set socket option");
	}

	name.sin_family = AF_INET;
	if (addr==0) {
		name.sin_addr.s_addr = INADDR_ANY;
	} else {
		name.sin_addr.s_addr = addr;
	}
	name.sin_port = htons(listenport);

	while (1)
	{
		/* bind it */
		if (bind(sock, (struct sockaddr*)&name, 
			sizeof(struct sockaddr_in)) < 0) 
		{
			perror("bind()");
			print_err(0, "unable to bind snmp socket");
			close(sock);
			return -1;
		} else  {
			break;
		}
	}
	listen(sock,2);
	return sock;
}

/*
 * init_tcp_socket
 */
int init_tcp_socket(int listenport) 
{
	struct sockaddr_in name;
	int sock;

	int on = 1;
	sock = socket(AF_INET, SOCK_STREAM, 0);
	if (sock < 0) {
		perror("opening datagram socket");
		exit(2);
	}

	/* use keepalives to force us to die when the remote dies */
	if ((setsockopt(sock, SOL_SOCKET, SO_KEEPALIVE, (void*)&on, sizeof(on)) == -1) ||
		(setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, (void*)&on, sizeof(on)) == -1))
	{
	  	perror("init_socket:setsockopt: cannot set socket option");
	}

	name.sin_family = AF_INET;
	if (addr==0) {
	name.sin_addr.s_addr = INADDR_ANY;
	} else {
	name.sin_addr.s_addr = addr;
	}
	name.sin_port = htons(listenport);

	while (1)
	{
		/* bind it */
		if (bind(sock, (struct sockaddr*)&name, 
			sizeof(struct sockaddr_in)) < 0) 
		{
			perror("bind()");
			exit(1);
		} else  {
			break;
		}
	}
	listen(sock,2);
	return sock;

}


