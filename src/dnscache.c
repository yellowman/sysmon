/* $Id: dnscache.c,v 1.33 2006/05/09 03:26:41 jared Exp $ */

#include "config.h"

int cache_misses = 0, cache_hits = 0;
int dnsentries = 0;
time_t dnslog_last_log;

/*
 *
 */
char *get_ip(struct my_hostent *hp)
{
	static char local[20];
	if (hp == NULL)
	{
		return NULL;
	}
	if (debug)
	{
		print_err(0, "hp->h_length = %d", hp->h_length_v4);
		print_err(0, "hp->my_h_addr= %p", hp->my_h_addr_v4);
	}
	snprintf(local, 20, "%d.%d.%d.%d", (unsigned char)hp->my_h_addr_v4[0], 
		(unsigned char)hp->my_h_addr_v4[1], 
		(unsigned char)hp->my_h_addr_v4[2],
		(unsigned char)hp->my_h_addr_v4[3]);
	if (debug)
	{
		print_err(0, "%s", local);
	}

	return local;
}

/*
 *
 */
char *get_hostname(struct my_hostent *hp)
{
	static char local[256];
	struct hostent *localhp;

	memset(local, 0, 256);
	if (hp == NULL)
	{
		return "NULL";
	}

	localhp = gethostbyaddr(hp->my_h_addr_v4, hp->h_length_v4, AF_INET);
	if (localhp == NULL)
	{
		return(get_ip(hp));
	}

	strncpy(local, localhp->h_name, 250);

	return local;
	
}

/*
 *
 */
void	expire_dns(time_t now)
{
	struct dnscache *here = NULL;
	struct dnscache *last = NULL, *freethis = NULL;
	int expired = 0;
	int count = 0;

	/* Check for a possible error case */
	if (dnshead == NULL)
		return;

	/* Count the elements in the dns cache */
	for (here=dnshead; here != NULL; here = here->next)
	{
		count++;
	}

	/* log the number of elements */
	if (debug)
	{
		print_err(0, "counted dns elements = %d", count);
	}
	
	/* Save the current time */
	
	here = dnshead;

	while (here != NULL)
	{
		if (freethis != NULL)
		{
			if (freethis->hp != NULL)
			{
				/* free ->hp->h_name */
				free(freethis->hp->h_name);
				freethis->hp->h_name = NULL;

				/* free ->hp_>my_h_addr */
				FREE(freethis->hp->my_h_addr_v4);
				freethis->hp->my_h_addr_v4 = NULL;
			
				/* free ->hp */
				FREE(freethis->hp);
				freethis->hp = NULL;
				
				/* free freethis->hostname */
				free(freethis->hostname);

				/* free * */
				FREE(freethis);
			}

			/* Count number of expired elements */
			expired++;

			/* decrement entries in the dns list accordingly */
			dnsentries--;

			/* set the fact we've got nothing to free() since
			   we just did it */

			freethis = NULL;
		}

#ifdef DEBUG
		if (debug)
		{
			print_err(0, "Examining %s for dns cache expire - Difftime = %d", here->hostname, (now - here->lastquery));
		}
#endif /* DEBUG */
		if ((now - here->lastquery) > dnsexpire)
		{
			/* entry needs expiry */
			if (last == NULL)	/* set the new dnshead */
			{
				if (dnshead != NULL)
				{
					dnshead = here->next;
				}
			}
			else 
			{
				last->next = here->next;
				/* set the previous entry to point to the next
				   one so we can unlink the current entry */
			}

			/* tag the data for freeing */
			freethis = here;
		} else {
			last = here;
		}
		here = here->next;
	}

	if (freethis != NULL)
	{
		if (freethis->hp != NULL)
		{
			/* free ->hp->h_name */
			FREE(freethis->hp->h_name);
			freethis->hp->h_name = NULL;

			/* free ->hp_>my_h_addr_v4 */
			FREE(freethis->hp->my_h_addr_v4);
			freethis->hp->my_h_addr_v4 = NULL;

			/* free ->hp */
			FREE(freethis->hp);
			freethis->hp = NULL;
		}
		FREE(freethis->hostname);

		/* free * */
		FREE(freethis);
		/* decrement entries in the dns list accordingly */
		dnsentries--;

		expired++;
		freethis = NULL;
	}

	if ((now - dnslog_last_log) > dnslog)
	{
		/* generate stats string - and log it */
		print_err(0,  "dnscache - %d hit %d miss %d exp %d count entr %d est entries",
			cache_hits, cache_misses, expired, count, dnsentries);
		dnslog_last_log = now;
	}
}
	
/*
 * if query_af is -1, this means *any* address family, IPv4 or
 * IPv6 is valid.
 */
struct my_hostent *do_my_gethostbyname(char *hostname, int query_af)
{
	struct dnscache *newent;
	struct hostent hp;
	struct hostent *hp2;
	struct timeval start;
	struct timeval stop;
	char temp[1024];
	if (hostname == NULL)
		return NULL;

	gettimeofday(&start, NULL);

#ifdef HAVE_GETHOSTBYNAME2
	if (query_af == -1)
	{
		hp2=gethostbyname2(hostname, AF_INET);
	} else {
		hp2 = gethostbyname2(hostname, query_af);
	}
#else
	hp2 = gethostbyname(hostname);
#endif /* HAVE_GETHOSTBYNAME2 */
	gettimeofday(&stop, NULL);

	snprintf(temp, 1000, "gethostbyname_inside_do_my(%s)",
		hostname);
	check_runtime(start, stop, temp, 1);

	if (!hp2)
		return NULL;

	/* memset(&hp, 0, sizeof (struct hostent)); */
	memcpy(&hp, hp2, sizeof(struct hostent));

	if (!&hp)
		return NULL;

	/* allocate memory for the new entry */
	newent = MALLOC(sizeof(struct dnscache), "struct dnscache");

	memset(newent, 0, sizeof(struct dnscache));

	/* copy hostname over */
	newent->hostname = strdup(hostname);

	/* allocate memory for this entry */
	newent->hp = MALLOC(sizeof(struct my_hostent), "struct my_hostent");
	
	/* XXX: save the current time */
	time(&newent->lastquery);

	/* copy needed date to new hp thingie */

	newent->hp->h_name = strdup(hp.h_name);
	newent->hp->h_addrtype_v4 = hp.h_addrtype;
	newent->hp->h_length_v4 = hp.h_length;

	newent->hp->my_h_addr_v4 = MALLOC(hp.h_length, "hp.h_length");
	memset(newent->hp->my_h_addr_v4, 0, hp.h_length);

	memcpy(newent->hp->my_h_addr_v4, hp.h_addr, hp.h_length);

	/* XXX: lock */
	newent->next = dnshead;
	dnshead = newent;
	cache_misses++;
	dnsentries++;
	/* XXX: unlock */

	return newent->hp;
}

/*
 *
 */
struct my_hostent *my_gethostbyaddr(const char *addr, int len, int type)
{
	return NULL;
}

/*
 *
 */
struct my_hostent *my_gethostbyname(unsigned char *hostname, int get_af)
{
	struct dnscache *here;

	if (debug)
	{
		print_err(0, "Estimated number of entries in dns cache is %d", dnsentries);
	}

	for (here = dnshead; here != NULL; here = here->next)
	{
		if (strcmp(hostname, here->hostname) == 0)
		{
			cache_hits++;
			return here->hp;
		}
	}

	return do_my_gethostbyname(hostname, get_af);
}

