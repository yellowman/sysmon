/*
 * aggregator.c - dial out to a sysmon-web, and serve it.
 *
 * A monitoring box usually sits somewhere awkward: behind NAT, on a
 * management VLAN, at a customer site. Waiting to be dialled means an
 * inbound firewall rule per site; dialling out means none. So when
 * `config aggregator "host:port";` is set, sysmond opens a TLS connection
 * to sysmon-web, proves who it is with a token, and then simply serves the
 * ordinary client protocol on the socket it originated.
 *
 * That last part is the whole trick: once the connection exists, it is
 * added to the client list exactly as an accepted connection would be, and
 * client_poll() answers VERS, SITE, CONF and TRAPS on it without knowing
 * or caring which end dialled. No second protocol, no duplicated command
 * handling.
 *
 * The link is not load-bearing for monitoring. If it cannot be
 * established, or drops, checks and pages carry on exactly as they would
 * on a standalone box, and the daemon retries with a backoff. A monitoring
 * daemon whose monitoring depends on its management plane is not one worth
 * running.
 */

#include "config.h"

char *aggregator_host = NULL;	/* NULL = standalone, no dialling */
int aggregator_port = 0;
char *aggregator_token = NULL;
char *aggregator_ca = NULL;

/* The live link, and when to try again after it fails. */
static int agg_fd = -1;
static time_t agg_next_try = 0;
static int agg_backoff = 0;

#define AGG_BACKOFF_MIN 5
#define AGG_BACKOFF_MAX 300

/*
 * Tell the aggregator who we are. The token is a bearer credential over an
 * already-verified TLS channel; it authenticates this daemon to sysmon-web,
 * while the config authkey still authenticates sysmon-web to this daemon
 * when it asks for CONF. Two directions, two credentials, on purpose.
 */
static bool aggregator_announce(int fd)
{
	char line[TEMPBUF_SIZE];
	char reply[NETWORK_LINE_SIZE];

	snprintf(line, sizeof(line), "HELLO %s %s",
		sitename != NULL ? sitename : "local",
		aggregator_token != NULL ? aggregator_token : "");

	if (sendline(fd, line) == -1)
	{
		print_err(1, "aggregator: could not send HELLO");
		return FALSE;
	}

	if (getline_tcp(fd, reply) != 0)
	{
		print_err(1, "aggregator: no answer to HELLO");
		return FALSE;
	}

	if (strncmp(reply, "333", 3) != 0)
	{
		/* A rejected token is a configuration error, not a blip. Say
		   what came back rather than retrying in silence forever. */
		print_err(1, "aggregator: %s:%d refused this daemon: %s",
			aggregator_host, aggregator_port, reply);
		return FALSE;
	}

	return TRUE;
}

/*
 * Hand the connected socket to the client machinery, so every command is
 * served by the code that already serves them.
 */
static void aggregator_adopt(int fd)
{
	struct clientstatus *thisclient, *linkafter;

	thisclient = MALLOC(sizeof(struct clientstatus), "aggregator_client");
	if (thisclient == NULL)
	{
		tls_disconnect(fd);
		return;
	}
	memset(thisclient, 0, sizeof(struct clientstatus));

	time(&thisclient->lastactivity);
	thisclient->filedes = fd;
	thisclient->un = NULL;
	thisclient->ip = STRDUP(aggregator_host, "aggregator_ip");
	thisclient->authlvl = 0;	/* it still has to AUTH for CONF */
	thisclient->xml = FALSE;
	thisclient->outage_log = FALSE;
	thisclient->clientver = 0;
	thisclient->next = NULL;

	linkafter = clienthead;
	while (linkafter->next != NULL)
		linkafter = linkafter->next;
	linkafter->next = thisclient;
}

/* Is our aggregator connection still in the client list and alive? */
static bool aggregator_still_up(void)
{
	struct clientstatus *here;

	if (agg_fd == -1)
		return FALSE;

	for (here = clienthead; here != NULL; here = here->next)
	{
		if (here->filedes == agg_fd)
			return TRUE;
	}

	/* The client machinery dropped it - timeout, QUIT, or a dead peer.
	   Let go of the TLS side too. */
	tls_forget(agg_fd);
	agg_fd = -1;
	return FALSE;
}

/*
 * Called from the main loop. Cheap when the link is up: one walk of a
 * short list.
 */
void aggregator_poll(time_t now)
{
	int fd;

	if (aggregator_host == NULL)
		return;		/* standalone; nothing to do */

	if (aggregator_still_up())
		return;

	if (now < agg_next_try)
		return;

	fd = tls_connect(aggregator_host, aggregator_port, aggregator_ca);
	if (fd == -1 || !aggregator_announce(fd))
	{
		if (fd != -1)
			tls_disconnect(fd);

		/* Back off, but keep trying: the aggregator being down is a
		   normal condition and this daemon has nothing else to do
		   about it. */
		agg_backoff = agg_backoff == 0 ? AGG_BACKOFF_MIN : agg_backoff * 2;
		if (agg_backoff > AGG_BACKOFF_MAX)
			agg_backoff = AGG_BACKOFF_MAX;
		agg_next_try = now + agg_backoff;
		return;
	}

	agg_fd = fd;
	agg_backoff = 0;
	aggregator_adopt(fd);
	print_err(1, "aggregator: connected to %s:%d as site %s",
		aggregator_host, aggregator_port,
		sitename != NULL ? sitename : "local");
}

/*
 * Split "host:port" from the config. Defaults to the aggregator port when
 * none is given.
 */
void aggregator_set_target(const char *spec)
{
	const char *colon;

	if (aggregator_host != NULL)
	{
		FREE(aggregator_host);
		aggregator_host = NULL;
	}
	aggregator_port = SYSMON_AGG_PORTNUM;

	if (spec == NULL || *spec == '\0')
		return;

	colon = strrchr(spec, ':');
	if (colon != NULL && colon[1] != '\0')
	{
		int len = (int)(colon - spec);
		char *host = MALLOC((size_t)len + 1, "aggregator_host");

		if (host == NULL)
			return;
		memcpy(host, spec, (size_t)len);
		host[len] = '\0';
		aggregator_host = host;
		aggregator_port = atoi(colon + 1);
		if (aggregator_port <= 0 || aggregator_port > 65535)
			aggregator_port = SYSMON_AGG_PORTNUM;
	} else {
		aggregator_host = STRDUP((char *)spec, "aggregator_host");
	}
}
