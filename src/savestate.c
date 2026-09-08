/*
 * savestate.c - carry check state across a restart.
 *
 * Written at shutdown and checkpointed every few minutes in between,
 * so an unclean death (crash, OOM, power) costs minutes of state, not
 * everything since the last clean stop.
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
#include <stdint.h>

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

/* Tolerate a small clock correction, not a checkpoint from the future. */
#define STATE_FUTURE_SKEW	(5 * 60)

/* How often the watch loop checkpoints. Ten minutes bounds what an
   unclean death can forget to ten minutes of state changes. */
#define STATE_CHECKPOINT_SECS	(10 * 60)

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
 *
 * Returns the number of objects written, or -1 when nothing was written
 * (no path, or the write failed - which complains on its own). Quiet on
 * success: this also runs every few minutes from the watch loop, and a
 * routine checkpoint is not news.
 */
static long write_state(const char *path)
{
	char tmp[PATH_MAX + 16];
	FILE *fh;
	int fd, failed;
	struct all_elements_list *here;
	unsigned long count = 0;

	if (path == NULL || *path == '\0')
		return -1;

	for (here = currenthead; here != NULL; here = here->next)
		if (here->value != NULL && here->value->data != NULL &&
		    here->value->unique_name != NULL)
			count++;

	if (snprintf(tmp, sizeof(tmp), "%s.new.XXXXXX", path) >= (int)sizeof(tmp))
		return -1;
	fd = mkstemp(tmp);
	if (fd < 0) {
		print_err(1, "save_state: cannot create temporary checkpoint: %s", strerror(errno));
		return -1;
	}
	fh = fdopen(fd, "w");
	if (fh == NULL)
	{
		close(fd);
		unlink(tmp);
		print_err(1, "save_state: cannot write %s: %s", tmp, strerror(errno));
		return -1;
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

	failed = ferror(fh);
	if (fflush(fh) != 0) failed = TRUE;
	if (!failed && fsync(fileno(fh)) != 0) failed = TRUE;
	if (fclose(fh) != 0) failed = TRUE;
	if (failed)
	{
		print_err(1, "save_state: cannot finish writing %s", tmp);
		unlink(tmp);
		return -1;
	}
	if (rename(tmp, path) == -1)
	{
		print_err(1, "save_state: cannot move %s into place: %s",
			path, strerror(errno));
		unlink(tmp);
		return -1;
	}
	return (long)count;
}

/*
 * The shutdown save: the same write, but announced - a stopping daemon
 * saying what it preserved is worth one syslog line.
 */
void save_state(const char *path)
{
	long count = write_state(path);

	if (count >= 0)
		print_err(0, "save_state: wrote %ld objects to %s", count, path);
}

/*
 * The periodic checkpoint. Shutdown-only saving meant a crash or power
 * loss lost everything since the last clean stop - and an unclean death
 * is exactly when the next start most needs to know who was already
 * paged. Called from the watch loop every pass; writes at most once per
 * STATE_CHECKPOINT_SECS after success; failures retry at a bounded rate.
 */
void checkpoint_state(time_t now, const char *path)
{
	static time_t last = 0, last_attempt = 0;
	static bool retry_pending = FALSE;

	if (path == NULL || *path == '\0') return;
	if (last == 0 || now < last || now < last_attempt) {
		last = last_attempt = now;
		retry_pending = FALSE;
		return;
	}
	if (difftime(now, last) < STATE_CHECKPOINT_SECS) return;
	/* A full disk must not cause a write/log storm on a busy event loop.
	 * Retry failed writes after five seconds, not another ten minutes. */
	if (retry_pending && difftime(now, last_attempt) < 5) return;
	last_attempt = now;
	if (write_state(path) >= 0) {
		last = now;
		retry_pending = FALSE;
	} else
		retry_pending = TRUE;
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
	*key = *val = NULL;
	while (*p == ' ' || *p == '\t') p++;
	if (*p == '\0') return NULL;
	eq = strchr(p, '=');
	sp = strpbrk(p, " \t");
	if (eq == NULL || eq == p || (sp != NULL && sp < eq)) return NULL;
	*eq = '\0';
	*key = p;
	*val = eq + 1;
	if (strcmp(p, "name") == 0) return NULL;
	sp = strpbrk(*val, " \t");
	if (sp == NULL) return NULL;
	*sp++ = '\0';
	while (*sp == ' ' || *sp == '\t') sp++;
	return *sp != '\0' ? sp : NULL;
}

static int state_number(const char *text, unsigned long long *out)
{
	const unsigned char *p = (const unsigned char *)text;
	char *end;
	if (*p == '\0') return FALSE;
	for (; *p != '\0'; p++)
		if (*p < '0' || *p > '9') return FALSE;
	errno = 0;
	*out = strtoull(text, &end, 10);
	return errno != ERANGE && *end == '\0';
}

static char *state_word(char **p)
{
	char *word;
	while (isspace((unsigned char)**p)) (*p)++;
	if (**p == '\0') return NULL;
	word = *p;
	while (**p != '\0' && !isspace((unsigned char)**p)) (*p)++;
	if (**p != '\0') *(*p)++ = '\0';
	return word;
}

static int state_field(struct saved_state *s, const char *key, const char *val)
{
	unsigned long long n;
	/* Unknown keys remain forward-compatible. Known keys must be
	 * whole nonnegative numbers that fit, not strtoul's valid prefix. */
#define NUMBER_FIELD(field, flag, limit, type) \
	if (strcmp(key, #field) == 0) { \
		if ((s->seen & flag) || !state_number(val, &n) || n > (limit)) return FALSE; \
		s->field = (type)n; s->seen |= flag; return TRUE; \
	}
	NUMBER_FIELD(lastcheck, SEEN_LASTCHECK, UINT_MAX, unsigned int)
	NUMBER_FIELD(downct, SEEN_DOWNCT, ULONG_MAX, unsigned long)
	NUMBER_FIELD(upct, SEEN_UPCT, ULONG_MAX, unsigned long)
	NUMBER_FIELD(totalchecked, SEEN_TOTALCHECKED, ULONG_MAX, unsigned long)
	NUMBER_FIELD(totaldown, SEEN_TOTALDOWN, ULONG_MAX, unsigned long)
	NUMBER_FIELD(contacted, SEEN_CONTACTED, 1, bool)
	NUMBER_FIELD(acked, SEEN_ACKED, 1, bool)
#undef NUMBER_FIELD
#define TIME_FIELD(field, flag) \
	if (strcmp(key, #field) == 0) { \
		if ((s->seen & flag) || !state_number(val, &n) || n > LLONG_MAX || \
		    (time_t)n < 0 || (unsigned long long)(time_t)n != n) return FALSE; \
		s->field = (time_t)n; s->seen |= flag; return TRUE; \
	}
	TIME_FIELD(lastcontacted, SEEN_LASTCONTACTED)
	TIME_FIELD(deathtime, SEEN_DEATHTIME)
	TIME_FIELD(last_up, SEEN_LAST_UP)
	TIME_FIELD(last_recovery, SEEN_LAST_RECOVERY)
#undef TIME_FIELD
	return TRUE;
}

static int saved_name_cmp(const void *a, const void *b)
{
	const struct saved_state *sa = *(const struct saved_state *const *)a;
	const struct saved_state *sb = *(const struct saved_state *const *)b;
	return strcmp(sa->name, sb->name);
}

static struct saved_state *read_state(const char *path, time_t now)
{
	FILE *fh;
	char line[LARGE_TEMPBUF_SIZE], *p, *magic, *version, *stamp, *count;
	struct saved_state *head = NULL, *s;
	unsigned long long v, written, claimed, parsed = 0;

	fh = fopen(path, "r");
	if (fh == NULL) return NULL;
	if (fgets(line, sizeof(line), fh) == NULL || strchr(line, '\n') == NULL)
		goto invalid;
	p = line;
	magic = state_word(&p);
	version = state_word(&p);
	stamp = state_word(&p);
	count = state_word(&p);
	if (magic == NULL || version == NULL || stamp == NULL || count == NULL ||
	    state_word(&p) != NULL || strcmp(magic, STATE_MAGIC) != 0 ||
	    !state_number(version, &v) || v != STATE_VERSION ||
	    !state_number(stamp, &written) || written > LLONG_MAX ||
	    (time_t)written < 0 || (unsigned long long)(time_t)written != written ||
	    !state_number(count, &claimed) || claimed > SIZE_MAX / sizeof(s))
		goto invalid;
	if (difftime(now, (time_t)written) > STATE_MAX_AGE ||
	    difftime((time_t)written, now) > STATE_FUTURE_SKEW)
		goto invalid;

	while (fgets(line, sizeof(line), fh) != NULL) {
		char *key, *val, *nl = strchr(line, '\n');
		if (nl == NULL) goto invalid;
		*nl = '\0';
		if (nl > line && nl[-1] == '\r') nl[-1] = '\0';
		if (line[0] == '\0') continue;
		if (parsed >= claimed) goto invalid;
		s = MALLOC(sizeof(*s), "savestate:entry");
		if (s == NULL) goto invalid;
		memset(s, 0, sizeof(*s));
		s->next = head;
		head = s;
		p = line;
		do {
			p = next_pair(p, &key, &val);
			if (key == NULL || val == NULL) goto invalid;
			if (strcmp(key, "name") == 0) {
				if (*val == '\0') goto invalid;
				s->name = STRDUP(val, "savestate:name");
				if (s->name == NULL) goto invalid;
			} else if (!state_field(s, key, val))
				goto invalid;
		} while (p != NULL);
		if (s->name == NULL) goto invalid;
		parsed++;
	}
	if (ferror(fh) || parsed != claimed) goto invalid;
	/* Duplicate identities cannot stand in for missing records. */
	if (parsed > 1) {
		struct saved_state **names = malloc((size_t)parsed * sizeof(*names));
		size_t i = 0;
		int duplicate = FALSE;
		if (names == NULL) goto invalid;
		for (s = head; s != NULL; s = s->next) names[i++] = s;
		qsort(names, (size_t)parsed, sizeof(*names), saved_name_cmp);
		for (i = 1; i < (size_t)parsed; i++)
			if (strcmp(names[i - 1]->name, names[i]->name) == 0) duplicate = TRUE;
		free(names);
		if (duplicate) goto invalid;
	}
	if (fclose(fh) != 0) {
		free_saved(head);
		return NULL;
	}
	return head;
invalid:
	print_err(1, "load_state: invalid, stale or incomplete checkpoint %s; starting clean", path);
	fclose(fh);
	free_saved(head);
	return NULL;
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
	print_err(1, "load_state: restored %lu objects from %s (%lu had no saved "
		"state and start clean)", restored, path, missing);
}
