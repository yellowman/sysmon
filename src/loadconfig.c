/* $Id: loadconfig.c,v 1.120 2006/09/22 19:43:45 jared Exp $ */

#include "config.h"

extern char *parser_root;

/* Forward declaration for lex-generated function */
int sysmon_conf_yylex(void);

struct set_type {
	unsigned char *name;
	unsigned char *value;
	struct set_type *next;
	} *set_head = NULL;

int debug_adj_builder = 0;

int max_numnei = 0;

void debug_made_deps(struct all_elements_list *);

int match_facility(char *factomatch)
{
	if (strcmp(factomatch, "kern") == 0) 
		return LOG_KERN;
	if (strcmp(factomatch, "user") == 0) 
		return LOG_USER;
	if (strcmp(factomatch, "mail") == 0) 
		return LOG_MAIL;
	if (strcmp(factomatch, "daemon") == 0) 
		return LOG_DAEMON;
	if (strcmp(factomatch, "auth") == 0) 
		return LOG_AUTH;
	if (strcmp(factomatch, "syslog") == 0) 
		return LOG_SYSLOG;
	if (strcmp(factomatch, "lpr") == 0) 
		return LOG_LPR;
	if (strcmp(factomatch, "news") == 0) 
		return LOG_NEWS;
	if (strcmp(factomatch, "uucp") == 0) 
		return LOG_UUCP;
	if (strcmp(factomatch, "cron") == 0) 
		return LOG_CRON;
#ifdef LOG_AUTHPRIV
	if (strcmp(factomatch, "authpriv") == 0) 
		return LOG_AUTHPRIV;
#endif /* LOG_AUTHPRIV */
	if (strcmp(factomatch, "local0") == 0) 
		return LOG_LOCAL0;
	if (strcmp(factomatch, "local1") == 0) 
		return LOG_LOCAL1;
	if (strcmp(factomatch, "local2") == 0) 
		return LOG_LOCAL2;
	if (strcmp(factomatch, "local3") == 0) 
		return LOG_LOCAL3;
	if (strcmp(factomatch, "local4") == 0) 
		return LOG_LOCAL4;
	if (strcmp(factomatch, "local5") == 0) 
		return LOG_LOCAL5;
        if (strcmp(factomatch, "local6") == 0) 
		return LOG_LOCAL6;
        if (strcmp(factomatch, "local7") == 0) 
		return LOG_LOCAL7;
	if (strcmp(factomatch, "none") == 0) /* user requsted no syslogging */
		return -2;

	return -1; /* no facility matches */
}

void free_sets()
{
	struct set_type *here, *last = NULL;
	
	here = set_head;
	while (here != NULL)
	{
		if (last != NULL)
		{
			free(last->name);
			free(last->value);
			FREE(last);
			last = NULL;
		}
		last = here;
		here = here->next;
	}
	if (last != NULL)
	{
		free(last->name);
		free(last->value);
		FREE(last);
		last = NULL;
	}
	set_head = NULL;
}

/* We can now do generic variables in our sysmon.confs */
void do_set(unsigned char *var, unsigned char *value)
{
	struct set_type *setter;
	
	if (debug)
	{
		print_err(0, "set %s = %s", var, value);
	}
	setter = MALLOC(sizeof(struct set_type), "loadconfig:setter for do_set");
	setter->name = STRDUP(var,"config variable name");
	setter->value = STRDUP(value,"config variable value");
	setter->next = set_head;
	set_head = setter;
	return;
}

char *find_value(unsigned char *string)
{
	struct set_type *here;
	here = set_head;
	
	while (here != NULL)
	{
		if (strcmp(string,here->name) == 0)
		{
			return here->value;
		}
		here = here->next;
	}
	
	/* Not found */
	return NULL;
}

/*
 * Make it return the translated string or NULL if it did
 * not translate the string
 */
unsigned char *do_set_replace(unsigned char *string)
{
	unsigned char new_string[MAX_STRLEN];
	unsigned char buff[MAX_STRLEN];
	unsigned char *repl = NULL;
	int x,y;
	size_t current_len = 0;

	memset(new_string, 0, MAX_STRLEN);
	for (x = 0;x < strlen(string) ;x++)
	{
		if (string[x] == '$')
		{
			for (y =x; y < strlen(string);y++)
			{
				if (isspace(string[y]))
					break;
				if (string[y] == ',')
					break;
			}
			memset(buff, 0, MAX_STRLEN);
			strncpy(buff, string+x+1, (y-x)-1);
			repl = find_value(buff);
			if (repl != NULL)
			{
				size_t repl_len = strlen(repl);
			if (current_len + repl_len < MAX_STRLEN) {
				strncat(new_string, repl, MAX_STRLEN - current_len - 1);
				current_len += repl_len;
			}
				x = (y-1);
			}
		} else {
			if (current_len + 1 < MAX_STRLEN) {
			strncat(new_string, string+x, 1);
			current_len++;
		}
		}
	}
	if (repl != NULL)
	{
		return STRDUP(new_string,"config variable replacement value");
	} else {
		return NULL;
	}
}

void free_struct_hostinfo(struct hostinfo *item_to_free)
{	
	if (item_to_free == NULL)
		return;
	if (item_to_free->hostname != NULL)
		FREE(item_to_free->hostname);
	if (item_to_free->message != NULL)
		FREE(item_to_free->message);
	if (item_to_free->contact != NULL)
		FREE(item_to_free->contact);
	if (item_to_free->snmp_oid != NULL)
		FREE(item_to_free->snmp_oid);
	if (item_to_free->snmp_community != NULL)
		FREE(item_to_free->snmp_community);
	if (item_to_free->dns_query != NULL)
		FREE(item_to_free->dns_query);
	if (item_to_free->username != NULL)
		FREE(item_to_free->username);
	if (item_to_free->password != NULL)
		FREE(item_to_free->password);
	if (item_to_free->hdr != NULL)
		FREE(item_to_free->hdr);
	if (item_to_free->hdrval != NULL)
		FREE(item_to_free->hdrval);
	if (item_to_free->secret != NULL)
		FREE(item_to_free->secret);
	if (item_to_free->lastmsgid != NULL)
		FREE(item_to_free->lastmsgid);
	if (item_to_free->notes != NULL)
		FREE(item_to_free->notes);
	if (item_to_free->unique_id != NULL)
		FREE(item_to_free->unique_id);
	if (item_to_free->url != NULL)
		FREE(item_to_free->url);
	if (item_to_free->url_text != NULL)
		FREE(item_to_free->url_text);
	if (item_to_free->command != NULL)
		FREE(item_to_free->command);
	if (item_to_free->ipv4_str != NULL)
		FREE(item_to_free->ipv4_str);
	
	/* This must be the last thing */
	FREE(item_to_free);
	return;
}

void free_struct_graph_elements(struct graph_elements *struct_to_free)
{
	int x;
	if (struct_to_free == NULL)
		return;
	free_struct_hostinfo(struct_to_free->data);
	for (x = 0; x <struct_to_free->num_dep; x++)
	{
		FREE(struct_to_free->dep_txt_name[x]);
	}
	/* This is just an ARRAY, so just free it, not the values
		inside it */
	if (struct_to_free->neighbors != NULL)
	{
		/* Root object with nothing else - has no neighbors..
		 */
		FREE(struct_to_free->neighbors);
	}
	if (struct_to_free->unique_name != NULL)
	{
	        FREE(struct_to_free->unique_name);
	}
	FREE(struct_to_free);
}

/*
 *
 */
void free_tree(struct all_elements_list *freethis)
{
        struct all_elements_list *last = NULL;
        struct all_elements_list *here = NULL;

        here = freethis;

	for (here=freethis;here != NULL;here=here->next)
        {
                if (last != NULL)
                {
			if (last->value != NULL)
			{
				free_struct_graph_elements(last->value);
			}
                        FREE(last);
                }
		last = here;
        }
        if (last != NULL)
	{
		if (last->value != NULL)
		{
			free_struct_graph_elements(last->value);
		}
                FREE(last);
	}
}

/*
 *
 */
void reload_config()
{
	/* log a message */
	syslogmsg("caught SIGHUP preparing to reload config", time(NULL));
	signal(SIGHUP, reload_config);
	
	gotsighup = TRUE; /* we need to watch for this, and when 
		it gets set, bail out of checks and do some cleanup, then
		copy alerts over, then free old tree */

	return;
}


/*
 * While we are processing sighup, we attempt to preserve a lot of
 * the statistical data.  This function finds matches then calls
 * hard_copy() which makes a copy of the relevant data for the
 * new structure
 */
void find_match(struct all_elements_list *matchme,
	struct all_elements_list *newtree)
{
	struct all_elements_list *here;
	if (newtree == NULL)
		return;

	for (here = newtree; here!= NULL; here=here->next)
	{
		if ((strcmp(matchme->value->data->hostname, 
			here->value->data->hostname) == 0) &&
		(strcmp(matchme->value->unique_name, here->value->unique_name)==0) &&
		(matchme->value->data->type == here->value->data->type) && 
		(matchme->value->data->port == here->value->data->port))
		{
			hard_copy(matchme->value->data, here->value->data);
			return;
		}
	}
}

/*
 * save relevant information when sighup is caught and objects
 * match
 */
void	hard_copy(struct hostinfo *old, struct hostinfo *new)
{
	if (debug)
	{
		print_err(0, "copying %s %d %d over %s %d %d", old->hostname, 
			old->port, old->lastcheck, new->hostname, 
			new->port, new->lastcheck);
	}
	FREE(new->unique_id);
	new->unique_id = STRDUP(old->unique_id,"copy of unique ID");
	new->lastcheck = old->lastcheck;
	new->downct = old->downct;
	new->upct = old->upct;
	new->contacted = old->contacted;
	new->lastcontacted = old->lastcontacted;
	new->lchecktime = old->lchecktime;
	new->deathtime = old->deathtime;
	new->totalchecked = old->totalchecked;
	new->totaldown = old->totaldown;
	new->last_up = old->last_up;
	new->last_recovery = old->last_recovery;
	new->acked = old->acked;
	/* copy over data related to snmp based tests */
	new->last_snmp_resptime = old->last_snmp_resptime;
	new->system_uptime = old->system_uptime;
	/* and what the last rtt check measured, so a config reload does
	   not blank the latency figures the UI is showing */
	new->rtt_last_min = old->rtt_last_min;
	new->rtt_last_avg = old->rtt_last_avg;
	new->rtt_last_max = old->rtt_last_max;
	new->rtt_last_jitter = old->rtt_last_jitter;
	new->rtt_last_replies = old->rtt_last_replies;
	new->rtt_last_probes = old->rtt_last_probes;
	new->pktloss_last_sent = old->pktloss_last_sent;
	new->pktloss_last_recv = old->pktloss_last_recv;
	if (old->lastmsgid != NULL)
		new->lastmsgid = STRDUP(old->lastmsgid,"last msgid");
	if (old->notes != NULL)
		new->notes = STRDUP(old->notes, "old notes");
}

/*
 *
 */
void copy_alerts(struct all_elements_list *old, struct all_elements_list *new)
{
	struct all_elements_list *here;
	if (old == NULL)
		return;
	if (new == NULL)
		return;

	for (here=old; here != NULL; here=here->next)
	{
		find_match(here, new);
	}
}

/* 
 * update_globs_from_parser: 
 * Here, we take the parsed information and set it into the
 * global settings that were parsed from the configuration file...
 */
void update_globs_from_parser()
{
	set_defaults();

	/*
	 * First, before anything that derives a path from it - the pidfile,
	 * the log, the state checkpoint, the aggregator's CA. Getting this
	 * order wrong does not fail loudly; it silently looks in the default
	 * directory on a box that configured a different one. (Which is
	 * exactly what happened to the CA lookup.)
	 */
	confgen_set_statedir(parser_statedir);
	if (parser_catch_snmptrap && (!ckconfigonly))
	{
		if (snmp_trap_fd == -1)
		{
			snmp_trap_fd = init_udp_socket(SNMP_TRAP_PORTNUM);
			if (snmp_trap_fd == -1)
			{
				/* Port 162 is privileged. The first config read
				 * happens while we are still root, so this only
				 * fails when snmp-trap is switched on by a SIGHUP
				 * reload after the privilege drop - and then it
				 * needs a restart, not another reload. */
				print_err(1, "could not bind UDP %d for snmp traps%s",
					SNMP_TRAP_PORTNUM,
					(geteuid() != 0) ?
					  " - traps were enabled after privileges were dropped, restart sysmond to listen" :
					  " - is another trap receiver already running?");
			} else {
				print_err(0, "listening for snmp traps on UDP %d",
					SNMP_TRAP_PORTNUM);
			}
		}
	}
	if (parser_sitename != NULL)
	{
		if (sitename != NULL)
			FREE(sitename);
		sitename = STRDUP(parser_sitename, "sitename");
	}
	if (parser_sitedesc != NULL)
	{
		if (sitedesc != NULL)
			FREE(sitedesc);
		sitedesc = STRDUP(parser_sitedesc, "sitedesc");
	}

	if (parser_aggregator != NULL)
	{
		aggregator_set_target(parser_aggregator);
	}
	if (parser_agg_token != NULL)
	{
		if (aggregator_token != NULL)
			FREE(aggregator_token);
		aggregator_token = STRDUP(parser_agg_token, "aggregator token");
	}
	/* The CA that signs the aggregator's certificate, if the operator has
	   put one in the state directory. NULL means the system trust store,
	   which is the right answer for a publicly signed aggregator. */
	{
		const char *ca = sysmon_ca_file();

		if (aggregator_ca != NULL)
			FREE(aggregator_ca);
		aggregator_ca = (ca != NULL) ?
			STRDUP((unsigned char *)ca, "aggregator ca") : NULL;
	}

	if (parser_pmesg != NULL)
	{
		if (pmesg != NULL)
			FREE(pmesg);
		pmesg = STRDUP(parser_pmesg,"message");
	}
	if (parser_sender != NULL)
	{
		if (sender != NULL)
			FREE(sender);
		sender=STRDUP(parser_sender,"sender mail header");
	}
	if (parser_subject != NULL)
	{
		if (subject != NULL)
			FREE(subject);
		subject = STRDUP(parser_subject,"subject mail header");
	} else {
		subject = STRDUP(SUBJECT,"subject mail header");
	}
	if (parser_upcolor != NULL)
	{
		if (upcolor != NULL)
			FREE(upcolor);
		upcolor = STRDUP(parser_upcolor,"up colour");
	}
	if (parser_downcolor != NULL)
	{
		if (downcolor != NULL)
			FREE(downcolor);
		downcolor = STRDUP(parser_downcolor,"down colour");
	}
	if (parser_recentcolor != NULL)
	{
		if (recentcolor != NULL)
			FREE(recentcolor);
		recentcolor = STRDUP(parser_recentcolor,"recent colour");
	}
	if (parser_replyto != NULL)
	{
		if (replyto != NULL)
			FREE(replyto);
		replyto = STRDUP(parser_replyto,"reply-to mail header");
	}
	if (parser_errorsto != NULL)
	{
		if (errorsto != NULL)
			FREE(errorsto);
		errorsto = STRDUP(parser_errorsto,"errors-to mail header");
	}
	if (parser_authkey != NULL)
	{
		if (authkey != NULL)
			FREE(authkey);
		authkey = STRDUP(parser_authkey,"authentication key");
	}
	{
		/* Always written, always in the same place. It costs one small
		   file at shutdown and it is how a restart finds what the last
		   run knew. */
		if (path_savestate != NULL)
			FREE(path_savestate);
		path_savestate = STRDUP((unsigned char *)sysmon_statefile(),
			"savestate path");
	}
	if (parser_statusfile != NULL)
	{
		if (statusfilename != NULL)
			FREE(statusfilename);
		statusfilename = STRDUP(parser_statusfile,"status file name");
		html = parser_statusfile_type;
	}
	{
		/* The status page is built next to everything else the daemon
		   writes and renamed into place at whatever path the operator
		   named - which is the one path directive worth keeping, since
		   where the page is published is the whole point of it. */
		if (statustempdirname != NULL)
			FREE(statustempdirname);
		statustempdirname = STRDUP((unsigned char *)confgen_statedir(),
			"status temp dir name");
	}
	if (parser_cssfile != NULL)
	{
		if (cssfilename != NULL )
			FREE(cssfilename);
		if (parser_statusfile_type == 1 ) {
			cssfilename = STRDUP(parser_cssfile, "css file name");
		} else {
			cssfilename = NULL;
		}
	}
	/* "config logging file;" turns file logging on; which file is not a
	   question any more. -3 is the sentinel for "a file, not syslog". */
	if (parser_logging_fac != 0)
	{
		facility = parser_logging_fac;
		if (facility == -3)
		{
			if (log_file != NULL)
				FREE(log_file);
			log_file = STRDUP((unsigned char *)sysmon_logfile(), "log file name");
		}
	}
	if (parser_queuetime != NULL)
	{
		queuetime = parser_i_queuetime;
	}
	if (parser_dnsexpire != NULL)
	{
		dnsexpire = parser_i_dnsexpire;
	}
	if (parser_dnslog != NULL)
	{
		dnslog = parser_i_dnslog;
	}
	if (parser_pageinterval != NULL)
	{
		pageinterval = parser_i_pageinterval;
	}
	if (parser_maxqueued != NULL)
	{
		maxqueued = parser_i_maxqueued;
		if (maxqueued > cieling_max_queued)
		{
			maxqueued = (cieling_max_queued-10);
			print_err(1, "ERROR: reducing maxqueued as necessary based on file descriptors available");
		}
	}
	if (parser_minnumfailures != NULL)
	{
		minnumfailures = parser_i_minnumfailures;
	}
	if (parser_flaptime != NULL)
	{
		flaptime = parser_i_flaptime;
	}
	showupalso = parser_showupalso;
	
	if (parser_nosubject)
	{
		if (subject != NULL)
			if (subject != SUBJECT)
				FREE(subject);
		subject = NULL;
	}
	nologconnects = parser_nologconnects;
}

/*
 *
 */
struct all_elements_list *sync_after_sighup(struct all_elements_list *oldhead, char *cnffile)

{
	struct all_elements_list *newhead = NULL;
	
	if (debug)
	{
		print_err(0, "entering sync_after_sighup");
	}

	/* load the config file */
	newhead = loadconfig(cnffile);
	if (badconfig)
	{
		print_err(1, "New configuration file is invalid.  Will not use it");
		free_tree(newhead);
		return currenthead;
	}

        update_globs_from_parser();

        if (max_numnei > maxqueued && (!quiet))
        {
                print_err(1, "WARNING: one object has %d nei/adj and maxqueued is %d, may cause trouble",
                        max_numnei, maxqueued);
        }

	if (debug)
	{
		print_err(0, "calling copy_alerts");
	}

	/* copy the alerts */
	copy_alerts(oldhead, newhead);

	/* free the old tree */
	free_tree(oldhead);
	oldhead = NULL;

	if (debug)
	{
		print_err(0, "exiting sync_after_sighup");
	}
	print_err(1, "Done reloading new config file");

	return newhead;
}

/*
 * generate a unique identifier that is 25 chars long
 */
unsigned char *gen_unique_id ()
{
	/* Generate a unique ascii id */

	/* length ~ 25 chars or so */
	char rand_text[30];

	gen_rand_ascii(rand_text, 25);

	return STRDUP(rand_text,"unique ASCII ID");
}

/*
 * Clear visited value
 */
void clear_visited()
{
        struct all_elements_list *here = NULL;
        for (here = parser_head; here != NULL; here=here->next)
	{
		here->value->visit = FALSE;
	}
}

/*
 * search the current parser_head based list for the
 * specified name
 */
struct graph_elements *find_object_by_name(char *text_name)
{
	struct all_elements_list *here = NULL;

	if (text_name == NULL)
		return NULL;

	for (here = parser_head; here != NULL; here=here->next)
	{
		if (strcmp(here->value->unique_name, text_name) == 0)
		{
			return here->value;
		}
	}
	return NULL;
}

/*
 * Search all_elements_list for an element matching
 * the specified name
 */
struct graph_elements *search_dep_list(struct all_elements_list *here, 
	char *name)
{
	int x = 0;
	/* search the dep list for references to NAME */

	for (x = 0; x < here->value->num_dep; x++)
	{
		if (here->value->visit == 1)
			return NULL;
		if (strcmp(here->value->dep_txt_name[x], name) == 0)
		{
			here->value->visit = TRUE;
			return find_object_by_name(here->value->dep_txt_name[x]); 
		}
	}
	return NULL;
}

/*
 * make_adj_add_neighbor
 */
struct nei_list *make_adjs_add_neighbor(struct nei_list *current_list, struct graph_elements *add)
{
	struct nei_list *new_nei = NULL;
	struct nei_list *nei_tmp = NULL;

	/* don't add if its already there */
	for (nei_tmp = current_list; nei_tmp != NULL; nei_tmp = nei_tmp->next)
	{
		if (strcmp(nei_tmp->nei_name, add->unique_name) == 0)
			return current_list;
	}

	new_nei = MALLOC(sizeof(struct nei_list), "loadconfig.c:make_adjs_add_nei:nei_list");
	new_nei->nei_name = strdup(add->unique_name);
	if (new_nei->nei_name == NULL)
	{
		print_err(1, "make_adjs_add_nei: strdup() failed - out of memory");
		FREE(new_nei);
		return current_list;
	}
	new_nei->g_element = add;
	new_nei->next = current_list;
	return new_nei;
}


/*
 * build adjacency list
 *
 * This currently results in (roughly) NumObjects^2 calls to
 * search_dep_list which has NumObjects^5 calls to 
 * find_object_by_name
 */
void make_adjs(struct all_elements_list *root)
{
	struct all_elements_list *here = NULL;
	struct all_elements_list *here2= NULL;
        struct graph_elements *find_result = NULL;
	struct nei_list *my_nei_list = NULL;
	struct nei_list *new_nei = NULL;
	int x = 0;
	int numnei = 0;

	/* Walk the list of all objects we loaded from config file */ 
	for (here = root; here!= NULL; here=here->next)
	{
		/* Collect my parents */
		for (x = 0; x < here->value->num_dep; x++)
		{	
			/* Use the textual name to find the struct that references it */
			find_result = find_object_by_name(here->value->dep_txt_name[x]);

			/* If a result is found */
			/* AND If it's not been visited */
			if (find_result != NULL) if (!find_result->visit)
			{
				/* Mark as visited */
				find_result->visit = 1;

				/* Add object as a neighbor */
				my_nei_list = make_adjs_add_neighbor(my_nei_list, find_result);

				/* Increase the Neighbor Count */
				numnei++;
			}
		} /* END parental collection */

		/* Collect my Children/sibs
		* this is done by searching everyones dep list for the
		* here->value->unique_name 
		*/

		/* Start a 2nd loop through the entire list */
		for (here2 = root; here2 != NULL; here2 = here2->next)
		{
			/* We needn't examine ourselves when in the 2nd depth loop */
			if (here2 == here)
				continue;

			/* Search here2 dep list for our (here->value->unique_name)
			 * name. */
			find_result = search_dep_list(here2, here->value->unique_name);

			if (find_result != NULL) 
			{
				/* Mark as visited */
				find_result->visit = 1;

				/* Add object as a neighbor */
				my_nei_list = make_adjs_add_neighbor(my_nei_list, here2->value);

				/* Increase the Neighbor Count */
				numnei++;
			} /* find_result != NULL */

		} /* 2nd traverse loop */

		/* Clear visited flag */
		clear_visited();

		/* debugging */
		if (debug_adj_builder)
			print_err(1, "%s has %d adjs\n", here->value->unique_name, numnei);

		/* If numnei != 0 */
		if (numnei)
		{
			if (debug_adj_builder) print_err(0, "adjs are: ");
			here->value->neighbors = MALLOC(sizeof(struct graph_elements *) * numnei, "graph_elements.neighbors");
			x = 0;
			for (new_nei= my_nei_list; new_nei!= NULL; new_nei=new_nei->next)
			{
				here->value->neighbors[x] = new_nei->g_element;
				if (debug_adj_builder) 
					print_err(1, "%s\t", new_nei->g_element->unique_name);
				x++;
			} /* for */
			here->value->tot_nei = x;
			if (debug_adj_builder)
				print_err(1, "(%d) total adjs vs %d (numnei)\n", x, numnei);
		  } /* if numnei */

		if (numnei > max_numnei)
			max_numnei = numnei;
		numnei = 0;
		free_struct_nei_list(my_nei_list);
		my_nei_list = NULL;
	} /* for */
}

/*
 * Visit all "reachable" elements in the graph
 */
void visit_them(struct graph_elements *here)
{
	int x;
	if (here == NULL)
		return;
	if (here->visit == TRUE)
		return;
	if (debug)
		print_err(1, "visit_them: marking %s as visited", 
			here->unique_name);
	here->visit = TRUE;
	if (here->tot_nei == 0)
		return;
        for (x = 0; x < here->tot_nei; x++)
	{
		visit_them(here->neighbors[x]);
	}
}

/*
 * Log all objects that are not reachable via the configured
 * topology from the root object.
 */
void log_orphans(struct all_elements_list *all_objects, struct graph_elements *configured_root)
{
	struct all_elements_list *here = NULL;

	if (all_objects == NULL)
		return;

	/* clear visited flag */
	clear_visited();

	/* visit all reachable objects */
	visit_them(configured_root);

	/* Log all "unreachable" objects */
        for (here = all_objects; here != NULL; here=here->next)
        {
		if (here->value->visit == FALSE)
		{
			print_err(1, "object %s has no relationship. It will not be monitored.",
				here->value->unique_name);
		}
        }

	clear_visited();

}

/*
 * Load the config file specified
 */
struct all_elements_list *loadconfig(char *cfg_path)
{
	FILE *file_to_parse = NULL;
	struct all_elements_list *root = NULL;

	/* Open the file */
	file_to_parse = fopen(cfg_path, "r");

	if (file_to_parse == NULL)
	{
		perror(cfg_path);
		return NULL;
	}

	/* set what to parse */
	yyin = file_to_parse;

	/* Start the file set over. What the parser opens from here is what
	   this daemon considers "the config" for hashing and for fleet
	   management - open_new_file() adds each include as it follows it.
	   The main file is known by its basename, so a config means the same
	   thing whether it is being read as a seed from /etc or as the
	   running copy from the generation directory. */
	confset_reset();
	confset_record(NULL, cfg_path);

	parser_head = NULL;

	/* init parser variables */
	initalize_parser();

	/* init line numbers */
	line_no = 1;

	/* set the name of the file we are parsing */
	current_parsing_filename = cfg_path;

	/* parse with lex scanner */
	sysmon_conf_yylex();

	/* build the adjencies */
	max_numnei = 0;
	make_adjs(parser_head);

	/* debug the built dependencies */
	if (debug || debug_adj_builder)
	{
		debug_made_deps(parser_head);
	}

	root=parser_head;

	configed_root = find_object_by_name(parser_root);

	/* Free generic variables */
	free_sets();

	/* log unreachable objects */
	log_orphans(root, configed_root);

	/* close the file */
	fclose(file_to_parse);

	/* return the new set to be monitored */
	return root;
}

void debug_made_deps(struct all_elements_list *root)
{
        struct all_elements_list *loc_here = NULL;
	int x = 0;
	int printed = 0;

	for (loc_here = root;loc_here!= NULL;loc_here=loc_here->next)
	{
		print_err(1, "element %s has %d deps\n", 
			loc_here->value->unique_name, 
			loc_here->value->num_dep);
		for (x = 0; x < loc_here->value->num_dep; x++)
		{
			print_err(1, "(%d)%s\t", x,
				loc_here->value->dep_txt_name[x]);
			printed = 1;
		}
		if (printed)
			print_err(1, "");
	}
}

/*
 * Spawn command management functions
 * Support for spawns {} block with named spawn commands
 */

/* Add a spawn command definition to the global list */
void add_spawn_def(char *name, char *command)
{
	struct spawn_def *new_spawn;
	struct spawn_def *current;

	if (name == NULL || command == NULL)
	{
		print_err(1, "add_spawn_def: NULL name or command");
		return;
	}

	/* Check if spawn name already exists */
	current = spawn_defs_head;
	while (current != NULL)
	{
		if (strcmp(current->name, name) == 0)
		{
			print_err(1, "WARNING: Spawn command '%s' redefined, using new definition", name);
			FREE(current->command);
			current->command = STRDUP(command, "spawn command");
			return;
		}
		current = current->next;
	}

	/* Create new spawn definition */
	new_spawn = (struct spawn_def *)MALLOC(sizeof(struct spawn_def), "spawn_def");
	new_spawn->name = STRDUP(name, "spawn name");
	new_spawn->command = STRDUP(command, "spawn command");
	new_spawn->next = spawn_defs_head;
	spawn_defs_head = new_spawn;

	if (debug)
		print_err(0, "Added spawn definition: %s = %s", name, command);
}

/* Look up a spawn command by name, return command string or NULL */
char *lookup_spawn_command(char *name)
{
	struct spawn_def *current;

	if (name == NULL)
		return NULL;

	current = spawn_defs_head;
	while (current != NULL)
	{
		if (strcmp(current->name, name) == 0)
		{
			if (debug)
				print_err(0, "Found spawn '%s': %s", name, current->command);
			return current->command;
		}
		current = current->next;
	}

	if (debug)
		print_err(0, "Spawn command '%s' not found in definitions", name);
	return NULL;
}

/* Free all spawn definitions (cleanup on config reload) */
void free_spawn_defs()
{
	struct spawn_def *current;
	struct spawn_def *next;

	current = spawn_defs_head;
	while (current != NULL)
	{
		next = current->next;
		FREE(current->name);
		FREE(current->command);
		FREE(current);
		current = next;
	}
	spawn_defs_head = NULL;

	if (debug)
		print_err(0, "Freed all spawn definitions");
}

