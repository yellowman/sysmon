/*
 * savestate.c - carry check state across a restart.
 *
 * A restart used to lose everything the daemon had learned: how long a
 * host had been down, how many consecutive failures it was at, and - the
 * one that gets somebody out of bed - whether anyone had already been
 * paged about it. A sysmond restarted during an outage would page again
 * for something it had already reported, which is exactly the moment when
 * a duplicate page is least welcome.
 *
 * WHAT IS SAVED
 *
 * Only the runtime state, and only the fields hard_copy() already carries
 * across a SIGHUP reload - that list is the existing answer to "what must
 * survive when the config is reloaded underneath us", and a restart is the
 * same question with a gap in the middle.
 *
 * Nothing structural: the config supplies hostnames, types, ports,
 * dependencies, thresholds and contacts on the way back up. Nothing
 * secret either, which is a change - the old state dump went through
 * send_object_xml() and so wrote SNMP community strings and RADIUS
 * secrets to disk, for a file nothing ever read.
 *
 * WHY NOT XML
 *
 * sysmond emits XML and has never parsed any - there is no XML parser in
 * this daemon, and the state dump was write-only, so nothing needed one.
 * Reusing the XML would mean writing that parser, in C, to read a file
 * this daemon wrote itself. A line of "key=value" pairs needs strtoul()
 * and strchr(), tolerates fields being added or removed in either
 * direction, and cannot be got wrong in an interesting way.
 *
 * FORMAT
 *
 *   sysmon-state 1 <written> <objects>
 *   lastcheck=0 downct=0 upct=42 ... name=core router
 *
 * The name comes last and takes the rest of the line, because an object
 * name may contain spaces and nothing else on the line may. Unknown keys
 * are skipped and missing keys are left at whatever the config gave them,
 * so an older daemon can read a newer file and the other way round.
 */

#include "config.h"

#define STATE_MAGIC	"sysmon-state"
#define STATE_VERSION	1

/*
 * How old a checkpoint may be and still be worth having.
 *
 * "Down since Tuesday, already paged" is worth restoring on a box that
 * was rebooted for an upgrade. The same record a week later describes a
 * network that has since been rebuilt twice, and consecutive-failure
 * counts from then mean nothing at all. Twelve hours covers a planned
 * restart and a long night; beyond that the daemon starts clean and says
 * so rather than acting on stale beliefs.
 */
#define STATE_MAX_AGE	(12 * 60 * 60)

/*
 * Which fields the line actually carried. A checkpoint written by another
 * version of this daemon may be missing some, and "missing" has to mean
 * "leave it as the config had it" rather than "set it to zero" - the
 * second is how a forward-compatible format quietly loses data.
 */
#define SEEN_LASTCHECK		(1u << 0)
#define SEEN_DOWNCT		(1u << 1)
#define SEEN_UPCT		(1u << 2)
#define SEEN_TOTALCHECKED	(1u << 3)
#define SEEN_TOTALDOWN		(1u << 4)
#define SEEN_CONTACTED		(1u << 5)
#define SEEN_ACKED		(1u << 6)
#define SEEN_LASTCONTACTED	(1u << 7)
#define SEEN_DEATHTIME		(1u << 8)
#define SEEN_LAST_UP		(1u << 9)
#define SEEN_LAST_RECOVERY	(1u << 10)

struct saved_state {
	unsigned int seen;
	char *name;
	unsigned int lastcheck;
	unsigned long downct;
	unsigned long upct;
	unsigned long totalchecked;
	unsigned long totaldown;
	bool contacted;
	bool acked;
	time_t lastcontacted;
	time_t deathtime;
	time_t last_up;
	time_t last_recovery;
	struct saved_state *next;
};

/* ------------------------------------------------------------------ */
/* Writing                                                              */
/* ------------------------------------------------------------------ */

/*
 * Write the checkpoint, atomically. A restart that reads a half-written
 * file would be worse than one that reads none, and a daemon being shut
 * down is exactly when a write is most likely to be interrupted.
 */
void save_state(const char *path)
{
	char tmp[PATH_MAX + 8];
	FILE *fh;
	struct all_elements_list *here;
	unsigned long count = 0;

	if (path == NULL || *path == '\0')
		return;

	for (here = currenthead; here != NULL; here = here->next)
		count++;

	snprintf(tmp, sizeof(tmp), "%s.new", path);
	fh = fopen(tmp, "w");
	if (fh == NULL)
	{
		print_err(1, "save_state: cannot write %s: %s", tmp, strerror(errno));
		return;
	}

	fprintf(fh, "%s %d %lld %lu\n", STATE_MAGIC, STATE_VERSION,
		(long long)time(NULL), count);

	for (here = currenthead; here != NULL; here = here->next)
	{
		struct hostinfo *d;

		if (here->value == NULL || here->value->data == NULL ||
			here->value->unique_name == NULL)
			continue;
		d = here->value->data;

		fprintf(fh, "lastcheck=%u downct=%lu upct=%lu totalchecked=%lu "
			"totaldown=%lu contacted=%d acked=%d lastcontacted=%lld "
			"deathtime=%lld last_up=%lld last_recovery=%lld name=%s\n",
			d->lastcheck, d->downct, d->upct, d->totalchecked,
			d->totaldown, d->contacted ? 1 : 0, d->acked ? 1 : 0,
			(long long)d->lastcontacted, (long long)d->deathtime,
			(long long)d->last_up, (long long)d->last_recovery,
			here->value->unique_name);
	}

	if (fclose(fh) != 0)
	{
		print_err(1, "save_state: cannot finish writing %s", tmp);
		unlink(tmp);
		return;
	}
	if (rename(tmp, path) == -1)
	{
		print_err(1, "save_state: cannot move %s into place: %s",
			path, strerror(errno));
		unlink(tmp);
		return;
	}
	print_err(0, "save_state: wrote %lu objects to %s", count, path);
}

/* ------------------------------------------------------------------ */
/* Reading                                                              */
/* ------------------------------------------------------------------ */

static void free_saved(struct saved_state *head)
{
	struct saved_state *next;

	while (head != NULL)
	{
		next = head->next;
		if (head->name != NULL)
			FREE(head->name);
		FREE(head);
		head = next;
	}
}

/*
 * Pull "key=value" out of a line, one pair at a time. Returns a pointer
 * past the pair, or NULL at the end of the line.
 */
static char *next_pair(char *p, char **key, char **val)
{
	char *eq, *sp;

	while (*p == ' ' || *p == '\t')
		p++;
	if (*p == '\0')
		return NULL;

	eq = strchr(p, '=');
	if (eq == NULL)
		return NULL;
	*eq = '\0';
	*key = p;

	/* "name" takes the rest of the line: an object name may contain a
	   space, and nothing else on the line may. */
	if (strcmp(p, "name") == 0)
	{
		*val = eq + 1;
		return NULL;
	}

	sp = strchr(eq + 1, ' ');
	if (sp != NULL)
		*sp = '\0';
	*val = eq + 1;
	return (sp != NULL) ? sp + 1 : NULL;
}

static struct saved_state *read_state(const char *path, time_t now)
{
	FILE *fh;
	char line[LARGE_TEMPBUF_SIZE];
	struct saved_state *head = NULL;
	int version = 0;
	long long written = 0;
	unsigned long claimed = 0;

	fh = fopen(path, "r");
	if (fh == NULL)
		return NULL; /* no checkpoint is normal - a first start */

	if (fgets(line, sizeof(line), fh) == NULL ||
		sscanf(line, STATE_MAGIC " %d %lld %lu",
			&version, &written, &claimed) != 3)
	{
		print_err(1, "save_state: %s is not a state file; ignoring it", path);
		fclose(fh);
		return NULL;
	}
	if (version != STATE_VERSION)
	{
		print_err(1, "save_state: %s is version %d, this daemon writes %d; "
			"starting clean", path, version, STATE_VERSION);
		fclose(fh);
		return NULL;
	}
	if (now - (time_t)written > STATE_MAX_AGE)
	{
		print_err(1, "save_state: %s is %lld hours old; starting clean rather "
			"than acting on it", path,
			(long long)((now - (time_t)written) / 3600));
		fclose(fh);
		return NULL;
	}

	while (fgets(line, sizeof(line), fh) != NULL)
	{
		struct saved_state *s;
		char *p, *key, *val;
		char *nl = strchr(line, '\n');

		if (nl != NULL)
			*nl = '\0';
		if (line[0] == '\0')
			continue;

		s = MALLOC(sizeof(struct saved_state), "savestate:entry");
		if (s == NULL)
			break;
		memset(s, 0, sizeof(*s));

		p = line;
		while (p != NULL)
		{
			p = next_pair(p, &key, &val);
			if (key == NULL || val == NULL)
				break;

			/* Unknown keys fall through untouched, which is what lets
			   this file be read by a daemon older or newer than the one
			   that wrote it. */
			if (strcmp(key, "name") == 0)
				s->name = STRDUP((unsigned char *)val, "savestate:name");
			else if (strcmp(key, "lastcheck") == 0)
			{
				s->lastcheck = (unsigned int)strtoul(val, NULL, 10);
				s->seen |= SEEN_LASTCHECK;
			}
			else if (strcmp(key, "downct") == 0)
			{
				s->downct = strtoul(val, NULL, 10);
				s->seen |= SEEN_DOWNCT;
			}
			else if (strcmp(key, "upct") == 0)
			{
				s->upct = strtoul(val, NULL, 10);
				s->seen |= SEEN_UPCT;
			}
			else if (strcmp(key, "totalchecked") == 0)
			{
				s->totalchecked = strtoul(val, NULL, 10);
				s->seen |= SEEN_TOTALCHECKED;
			}
			else if (strcmp(key, "totaldown") == 0)
			{
				s->totaldown = strtoul(val, NULL, 10);
				s->seen |= SEEN_TOTALDOWN;
			}
			else if (strcmp(key, "contacted") == 0)
			{
				s->contacted = (strtol(val, NULL, 10) != 0);
				s->seen |= SEEN_CONTACTED;
			}
			else if (strcmp(key, "acked") == 0)
			{
				s->acked = (strtol(val, NULL, 10) != 0);
				s->seen |= SEEN_ACKED;
			}
			else if (strcmp(key, "lastcontacted") == 0)
			{
				s->lastcontacted = (time_t)strtoll(val, NULL, 10);
				s->seen |= SEEN_LASTCONTACTED;
			}
			else if (strcmp(key, "deathtime") == 0)
			{
				s->deathtime = (time_t)strtoll(val, NULL, 10);
				s->seen |= SEEN_DEATHTIME;
			}
			else if (strcmp(key, "last_up") == 0)
			{
				s->last_up = (time_t)strtoll(val, NULL, 10);
				s->seen |= SEEN_LAST_UP;
			}
			else if (strcmp(key, "last_recovery") == 0)
			{
				s->last_recovery = (time_t)strtoll(val, NULL, 10);
				s->seen |= SEEN_LAST_RECOVERY;
			}
		}

		if (s->name == NULL)
		{
			FREE(s);
			continue;
		}
		s->next = head;
		head = s;
	}
	fclose(fh);
	return head;
}

/*
 * Put the saved state back onto a freshly loaded tree.
 *
 * Matched by unique_name, which is the same key SIGHUP matching uses and
 * the same one a sysmon-web stores everything under. An object that is
 * not in the checkpoint - newly added to the config, or renamed - simply
 * starts clean, which is the correct answer for something the daemon has
 * never checked.
 */
void load_state(const char *path)
{
	struct saved_state *saved, *s;
	struct all_elements_list *here;
	unsigned long restored = 0, missing = 0;
	time_t now = time(NULL);

	if (path == NULL || *path == '\0' || currenthead == NULL)
		return;

	saved = read_state(path, now);
	if (saved == NULL)
		return;

	for (here = currenthead; here != NULL; here = here->next)
	{
		if (here->value == NULL || here->value->data == NULL ||
			here->value->unique_name == NULL)
			continue;

		for (s = saved; s != NULL; s = s->next)
		{
			if (strcmp(s->name, (char *)here->value->unique_name) != 0)
				continue;

			/* Only what the line actually carried. */
			if (s->seen & SEEN_LASTCHECK)
				here->value->data->lastcheck = s->lastcheck;
			if (s->seen & SEEN_DOWNCT)
				here->value->data->downct = s->downct;
			if (s->seen & SEEN_UPCT)
				here->value->data->upct = s->upct;
			if (s->seen & SEEN_TOTALCHECKED)
				here->value->data->totalchecked = s->totalchecked;
			if (s->seen & SEEN_TOTALDOWN)
				here->value->data->totaldown = s->totaldown;
			if (s->seen & SEEN_CONTACTED)
				here->value->data->contacted = s->contacted;
			if (s->seen & SEEN_ACKED)
				here->value->data->acked = s->acked;
			if (s->seen & SEEN_LASTCONTACTED)
				here->value->data->lastcontacted = s->lastcontacted;
			if (s->seen & SEEN_DEATHTIME)
				here->value->data->deathtime = s->deathtime;
			if (s->seen & SEEN_LAST_UP)
				here->value->data->last_up = s->last_up;
			if (s->seen & SEEN_LAST_RECOVERY)
				here->value->data->last_recovery = s->last_recovery;
			restored++;
			break;
		}
		if (s == NULL)
			missing++;
	}

	free_saved(saved);
	print_err(1, "save_state: restored %lu objects from %s (%lu had no saved "
		"state and start clean)", restored, path, missing);
}
