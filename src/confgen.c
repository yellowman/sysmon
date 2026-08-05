/*
 * confgen.c - config generations: what this daemon is running, and how a
 * sysmon-web replaces it.
 *
 *   CONFIG-GEN       what am I running?      -> generation number + hash
 *   CONFIG-GET       give me what you run    -> every file, byte for byte
 *   CONFIG-PUT       run this instead        -> stage, validate, swap, reload
 *   CONFIG-ROLLBACK  undo the last PUT       -> swap back, reload
 *   CONFIG-REVERT    stop being managed      -> go back to the seed config
 *
 * The seed config - /etc/sysmon.conf, or whatever -f names - is read-only
 * to this daemon, forever. It is what a box boots with, what an operator
 * edits with vi, and what the box falls back to if everything else here is
 * deleted. A managed config never touches it.
 *
 * Instead a managed box keeps its config in a directory it owns:
 *
 *     <gendir>/main            the entry file's name, e.g. "sysmon.conf"
 *     <gendir>/current  ->     gen-0000000007
 *     <gendir>/previous ->     gen-0000000006
 *     <gendir>/gen-0000000007/ the file set of that generation
 *
 * The daemon loads <gendir>/current/<main> when it exists and the seed
 * otherwise, so "unmanage this box" is exactly "remove the current
 * symlink", and a box whose state directory is wiped comes back on its
 * original config rather than on nothing.
 *
 * Four properties hold, and each of them is why something below is shaped
 * the way it is:
 *
 * 1. /etc is never written. The daemon drops privileges; asking an
 *    operator to make /etc writable by nobody in order to manage a config
 *    is a bad trade, and it is not one this makes them take.
 *
 * 2. The running config is never replaced by one this daemon would refuse.
 *    A delivery is staged in a new directory and parsed there, by this
 *    daemon's own lexer in a forked child, before anything swaps.
 *
 * 3. A rejected delivery costs nothing. Nothing on disk changes and
 *    nothing in memory changes; the staging directory is simply removed.
 *
 * 4. No path from the other end is ever used to build a filename. A
 *    delivery carries flat names - no slashes, no dots - and this side
 *    decides which directory they land in. An aggregator is trusted with
 *    the monitoring config; it is not trusted with the filesystem.
 */

#include "config.h"

#include <sys/wait.h>
#include <dirent.h>

#ifdef HAVE_TLS
#include <openssl/evp.h>
#endif

/*
 * The set of files the parser actually opened, in load order. Recorded as
 * the config is read rather than re-derived by scanning for "include",
 * because the parser is the authority on what it followed - and a hash
 * over a guess is worse than no hash.
 *
 * Each entry has two halves that must not be confused:
 *
 *   name - what the config calls it: the string in the include directive,
 *          or the main file's basename. This is the identity: it is what
 *          gets hashed and what a delivery names. It carries no directory,
 *          so it means the same thing on a box whose seed is in /etc and
 *          on one whose seed is in /usr/local/etc.
 *
 *   path - where it actually is right now, which changes every time a
 *          generation is swapped in. Used to read; never hashed.
 */
#define CONFSET_MAX 64

/*
 * Each generation directory records the load order of its files. A
 * directory listing cannot supply it, and the order is part of the hash -
 * so without this, a generation could be put back on disk but never
 * hashed again, and a rollback would have no way to say what it restored.
 */
#define GEN_ORDER_FILE ".order"

static struct {
	char *name;
	char *path;
	bool flat; /* name is a plain filename, so this file can be managed */
} confset[CONFSET_MAX];

static int confset_n = 0;

/*
 * Where generations live. Read from the seed config only - it is a
 * property of the box, not of the config being delivered to it - so a
 * delivered config cannot move the directory the daemon is currently
 * running out of.
 */
static char *gen_statedir = NULL;
static bool gen_statedir_locked = FALSE;

/* Name of the entry file, e.g. "sysmon.conf". */
static char gen_mainname[PATH_MAX] = "";

/* Absolute path of the config actually loaded, managed or seed. */
static char gen_active[PATH_MAX] = "";

/* What we are running. Generation 0 means "running the seed". */
static unsigned long running_generation = 0;

/* ------------------------------------------------------------------ */
/* The file set                                                         */
/* ------------------------------------------------------------------ */

void confset_reset(void)
{
	int i;

	for (i = 0; i < confset_n; i++)
	{
		FREE(confset[i].name);
		FREE(confset[i].path);
		confset[i].name = NULL;
		confset[i].path = NULL;
	}
	confset_n = 0;
}

/*
 * A name is manageable when it is a plain filename: no directory
 * separator, not "." or "..", not empty. Everything a delivery can name
 * has to pass this, and so does everything adopted from a box - because a
 * config whose includes point outside their own directory cannot be
 * copied into a managed directory and still mean the same thing.
 */
static bool flat_name(const char *name)
{
	if (name == NULL || *name == '\0')
		return FALSE;
	if (strchr(name, '/') != NULL)
		return FALSE;
	/* A leading dot is refused rather than merely "." and "..": the
	   generation directory keeps its load order in a dotfile, and a
	   delivery that could name that file could rewrite the order its own
	   files are read in. Config files do not begin with dots. */
	if (name[0] == '.')
		return FALSE;
	if (strlen(name) >= 128)
		return FALSE;
	return TRUE;
}

void confset_record(const char *name, const char *path)
{
	char resolved[PATH_MAX];
	const char *base;
	int i;

	if (path == NULL || *path == '\0')
		return;

	/* No name given means the main file: it is known by its basename. */
	if (name == NULL || *name == '\0')
	{
		base = strrchr(path, '/');
		name = (base != NULL) ? base + 1 : path;
	}

	if (realpath(path, resolved) != NULL)
		path = resolved;

	/* An include pulled in twice is one file, and must be hashed once. */
	for (i = 0; i < confset_n; i++)
	{
		if (strcmp(confset[i].path, path) == 0)
			return;
	}

	if (confset_n >= CONFSET_MAX)
	{
		print_err(1, "confgen: more than %d config files; the rest are "
			"parsed but not tracked for fleet management", CONFSET_MAX);
		return;
	}

	confset[confset_n].name = STRDUP((unsigned char *)name, "confgen:name");
	confset[confset_n].path = STRDUP((unsigned char *)path, "confgen:path");
	if (confset[confset_n].name == NULL || confset[confset_n].path == NULL)
	{
		if (confset[confset_n].name != NULL)
			FREE(confset[confset_n].name);
		if (confset[confset_n].path != NULL)
			FREE(confset[confset_n].path);
		return;
	}
	confset[confset_n].flat = flat_name(name);
	confset_n++;
}

int confset_count(void)
{
	return confset_n;
}

const char *confset_name(int i)
{
	if (i < 0 || i >= confset_n)
		return NULL;
	return confset[i].name;
}

const char *confset_path(int i)
{
	if (i < 0 || i >= confset_n)
		return NULL;
	return confset[i].path;
}

/*
 * Can this config be managed at all? Only if every file in it is named by
 * a plain filename. An `include "/etc/sysmon.d/x.conf"` is a perfectly
 * good config and stays a perfectly good config - it just cannot be copied
 * into a managed directory without changing what it points at, so this
 * side says so rather than quietly copying a file that would then never be
 * read.
 */
bool confgen_manageable(char *why, size_t whylen)
{
	int i;

	if (why != NULL && whylen > 0)
		why[0] = '\0';

	if (confset_n == 0)
	{
		snprintf(why, whylen, "no config files are tracked");
		return FALSE;
	}
	for (i = 0; i < confset_n; i++)
	{
		if (!confset[i].flat)
		{
			snprintf(why, whylen,
				"include \"%s\" names a path rather than a plain filename; "
				"a managed config keeps all its files in one directory",
				confset[i].name);
			return FALSE;
		}
	}
	return TRUE;
}

/* ------------------------------------------------------------------ */
/* Small file helpers                                                   */
/* ------------------------------------------------------------------ */

static unsigned char *slurp(const char *path, long *len)
{
	FILE *fh;
	unsigned char *buf;
	long size;

	*len = 0;
	fh = fopen(path, "rb");
	if (fh == NULL)
		return NULL;

	if (fseek(fh, 0, SEEK_END) != 0)
	{
		fclose(fh);
		return NULL;
	}
	size = ftell(fh);
	if (size < 0 || fseek(fh, 0, SEEK_SET) != 0)
	{
		fclose(fh);
		return NULL;
	}

	buf = MALLOC((size_t)size + 1, "confgen:slurp");
	if (buf == NULL)
	{
		fclose(fh);
		return NULL;
	}
	if (size > 0 && fread(buf, 1, (size_t)size, fh) != (size_t)size)
	{
		FREE(buf);
		fclose(fh);
		return NULL;
	}
	buf[size] = '\0';
	fclose(fh);
	*len = size;
	return buf;
}

static int write_whole(const char *path, const unsigned char *data, long len)
{
	FILE *fh;

	fh = fopen(path, "wb");
	if (fh == NULL)
		return -1;
	if (len > 0 && fwrite(data, 1, (size_t)len, fh) != (size_t)len)
	{
		fclose(fh);
		return -1;
	}
	if (fclose(fh) != 0)
		return -1;
	return 0;
}

/* Remove a flat directory of files. Never recurses: a generation
   directory holds files and nothing else, and anything that is not a
   plain file in there is left alone rather than followed. */
static void remove_gen_dir(const char *dir)
{
	DIR *d;
	struct dirent *e;
	char path[PATH_MAX];
	struct stat st;

	d = opendir(dir);
	if (d == NULL)
		return;
	while ((e = readdir(d)) != NULL)
	{
		if (strcmp(e->d_name, ".") == 0 || strcmp(e->d_name, "..") == 0)
			continue;
		/* Delivered files fail flat_name() on a leading dot, so the
		   order manifest has to be named explicitly here. */
		if (!flat_name(e->d_name) && strcmp(e->d_name, GEN_ORDER_FILE) != 0)
			continue;
		if (strchr(e->d_name, '/') != NULL)
			continue;
		snprintf(path, sizeof(path), "%s/%s", dir, e->d_name);
		if (lstat(path, &st) == 0 && S_ISREG(st.st_mode))
			unlink(path);
	}
	closedir(d);
	rmdir(dir);
}

#ifdef HAVE_TLS

/*
 * The content hash both ends compare.
 *
 * SHA-256 over, for each file in load order: the length of its name, the
 * name, the length of its content, the content - each length as 8 bytes
 * big-endian so no two file sets can produce the same stream.
 *
 * The *name*, not the path. A config is the same config whether it is
 * sitting in /etc as a seed or in a generation directory as the running
 * copy, and the hash has to say so - otherwise adopting a box and then
 * delivering its own bytes back would look like a change, forever.
 *
 * Bytes are hashed exactly as they sit on disk. Nothing is normalised, no
 * whitespace is touched, no line endings are translated. That is the whole
 * reason sysmon-web edits by splicing rather than regenerating: a config
 * nobody edited has to hash identically forever, or every box in the fleet
 * reads as "locally modified" and the state means nothing.
 */
static void hash_u64(EVP_MD_CTX *ctx, unsigned long v)
{
	unsigned char n[8];
	int i;

	for (i = 7; i >= 0; i--)
	{
		n[i] = (unsigned char)(v & 0xff);
		v >>= 8;
	}
	EVP_DigestUpdate(ctx, n, sizeof(n));
}

/*
 * Writes 65 bytes (64 hex digits and a NUL) into out.
 * Returns FALSE if any tracked file could not be read.
 *
 * EVP rather than the SHA256_* calls: both exist in 1.1.1 and LibreSSL,
 * but the direct ones are deprecated from 3.0 onward, and this is the one
 * spelling that compiles clean everywhere the daemon is expected to build.
 */
/*
 * The hashing itself, over (name, bytes) pairs. Three things need it and
 * they get their pairs from different places - what is loaded, what has
 * just been delivered, and what is sitting in a generation directory - so
 * the rule that both ends of the fleet must agree on lives in exactly one
 * function.
 */
struct hash_ctx {
	EVP_MD_CTX *md;
};

static bool hash_begin(struct hash_ctx *h)
{
	h->md = EVP_MD_CTX_new();
	if (h->md == NULL)
		return FALSE;
	if (EVP_DigestInit_ex(h->md, EVP_sha256(), NULL) != 1)
	{
		EVP_MD_CTX_free(h->md);
		h->md = NULL;
		return FALSE;
	}
	return TRUE;
}

static void hash_pair(struct hash_ctx *h, const char *name,
	const unsigned char *data, long len)
{
	hash_u64(h->md, (unsigned long)strlen(name));
	EVP_DigestUpdate(h->md, name, strlen(name));
	hash_u64(h->md, (unsigned long)len);
	EVP_DigestUpdate(h->md, data, (size_t)len);
}

static bool hash_end(struct hash_ctx *h, char *out)
{
	unsigned char md[EVP_MAX_MD_SIZE];
	unsigned int mdlen = 0;
	unsigned int j;
	int i;

	if (EVP_DigestFinal_ex(h->md, md, &mdlen) != 1)
	{
		EVP_MD_CTX_free(h->md);
		return FALSE;
	}
	EVP_MD_CTX_free(h->md);

	for (i = 0, j = 0; j < mdlen; j++)
	{
		static const char hex[] = "0123456789abcdef";
		out[i++] = hex[(md[j] >> 4) & 0xf];
		out[i++] = hex[md[j] & 0xf];
	}
	out[i] = '\0';
	return TRUE;
}

/* The config that is loaded right now. */
bool confgen_hash(char *out, size_t outlen)
{
	struct hash_ctx h;
	unsigned char *content;
	long len;
	int i;

	if (out == NULL || outlen < 65)
		return FALSE;
	out[0] = '\0';
	if (!hash_begin(&h))
		return FALSE;

	for (i = 0; i < confset_n; i++)
	{
		content = slurp(confset[i].path, &len);
		if (content == NULL)
		{
			print_err(1, "confgen: cannot read %s to hash it", confset[i].path);
			EVP_MD_CTX_free(h.md);
			return FALSE;
		}
		hash_pair(&h, confset[i].name, content, len);
		FREE(content);
	}
	return hash_end(&h, out);
}

/*
 * A set that has just been delivered, straight from memory.
 *
 * This is what goes back in the reply to CONFIG-PUT, and it has to be the
 * delivered bytes rather than what is loaded: the reload has not happened
 * yet at that point, so hashing the loaded config would report the
 * generation the box is leaving as though it were the one it is joining.
 */
bool confgen_hash_files(struct confgen_file *files, int nfiles,
	char *out, size_t outlen)
{
	struct hash_ctx h;
	int i;

	if (out == NULL || outlen < 65)
		return FALSE;
	out[0] = '\0';
	if (!hash_begin(&h))
		return FALSE;

	for (i = 0; i < nfiles; i++)
		hash_pair(&h, files[i].name, files[i].data, files[i].len);
	return hash_end(&h, out);
}

#else /* !HAVE_TLS */

bool confgen_hash(char *out, size_t outlen)
{
	if (out != NULL && outlen > 0)
		out[0] = '\0';
	return FALSE;
}

bool confgen_hash_files(struct confgen_file *files, int nfiles,
	char *out, size_t outlen)
{
	(void)files; (void)nfiles;
	if (out != NULL && outlen > 0)
		out[0] = '\0';
	return FALSE;
}

#endif /* HAVE_TLS */

/* ------------------------------------------------------------------ */
/* base64: config files are arbitrary bytes and the protocol is lines. */
/* ------------------------------------------------------------------ */

static const char b64set[] =
	"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/* Returns a malloc'd NUL-terminated string, or NULL. */
char *confgen_b64encode(const unsigned char *in, long len)
{
	char *out;
	long i, o = 0;
	unsigned int v;

	out = MALLOC((size_t)(((len + 2) / 3) * 4) + 1, "confgen:b64encode");
	if (out == NULL)
		return NULL;

	for (i = 0; i + 2 < len; i += 3)
	{
		v = ((unsigned int)in[i] << 16) | ((unsigned int)in[i + 1] << 8) |
			(unsigned int)in[i + 2];
		out[o++] = b64set[(v >> 18) & 0x3f];
		out[o++] = b64set[(v >> 12) & 0x3f];
		out[o++] = b64set[(v >> 6) & 0x3f];
		out[o++] = b64set[v & 0x3f];
	}
	if (len - i == 1)
	{
		v = (unsigned int)in[i] << 16;
		out[o++] = b64set[(v >> 18) & 0x3f];
		out[o++] = b64set[(v >> 12) & 0x3f];
		out[o++] = '=';
		out[o++] = '=';
	}
	else if (len - i == 2)
	{
		v = ((unsigned int)in[i] << 16) | ((unsigned int)in[i + 1] << 8);
		out[o++] = b64set[(v >> 18) & 0x3f];
		out[o++] = b64set[(v >> 12) & 0x3f];
		out[o++] = b64set[(v >> 6) & 0x3f];
		out[o++] = '=';
	}
	out[o] = '\0';
	return out;
}

static int b64value(int c)
{
	if (c >= 'A' && c <= 'Z') return c - 'A';
	if (c >= 'a' && c <= 'z') return c - 'a' + 26;
	if (c >= '0' && c <= '9') return c - '0' + 52;
	if (c == '+') return 62;
	if (c == '/') return 63;
	return -1;
}

/*
 * Decodes into a malloc'd buffer, setting *outlen. Returns NULL on any
 * character that is not base64 - a truncated or mangled transfer must
 * fail loudly, not produce a config file with a hole in it.
 */
unsigned char *confgen_b64decode(const char *in, long *outlen)
{
	unsigned char *out;
	size_t inlen;
	long o = 0;
	int quad[4], n = 0, pad = 0, v;
	size_t i;

	*outlen = 0;
	if (in == NULL)
		return NULL;
	inlen = strlen(in);

	out = MALLOC((inlen / 4 + 1) * 3 + 1, "confgen:b64decode");
	if (out == NULL)
		return NULL;

	for (i = 0; i < inlen; i++)
	{
		int c = (unsigned char)in[i];

		if (c == '\r' || c == '\n' || c == ' ' || c == '\t')
			continue;
		if (c == '=')
		{
			/* Padding is only ever the 3rd or 4th character of the last
			   quad. "====" carries no data at all, and a decoder that
			   accepted it would emit a byte nobody sent. */
			if (n < 2 || pad >= 2)
			{
				FREE(out);
				return NULL;
			}
			pad++;
			quad[n++] = 0;
		}
		else
		{
			v = b64value(c);
			if (v < 0 || pad > 0)
			{
				FREE(out);
				return NULL;
			}
			quad[n++] = v;
		}
		if (n == 4)
		{
			unsigned int acc = ((unsigned int)quad[0] << 18) |
				((unsigned int)quad[1] << 12) |
				((unsigned int)quad[2] << 6) | (unsigned int)quad[3];
			out[o++] = (unsigned char)((acc >> 16) & 0xff);
			if (pad < 2)
				out[o++] = (unsigned char)((acc >> 8) & 0xff);
			if (pad < 1)
				out[o++] = (unsigned char)(acc & 0xff);
			n = 0;
		}
	}
	if (n != 0)
	{
		FREE(out);
		return NULL; /* truncated */
	}
	out[o] = '\0';
	*outlen = o;
	return out;
}

/* ------------------------------------------------------------------ */
/* The state directory                                                  */
/* ------------------------------------------------------------------ */

/*
 * Default: somewhere the daemon can own, never /etc. The seed config
 * belongs to the operator and to the package manager; the running copy
 * belongs to the daemon, and mixing the two is what forced /etc to be
 * writable by the dropped-privilege user in the first place.
 *
 * The same path on every platform, deliberately. "Where does this box keep
 * its config" is a question asked about someone else's box, often at 3am
 * and often about an OS the person asking does not run - and a per-platform
 * answer makes it a question at all. /var/db is not conventional on Linux;
 * one path everyone can recite is worth more than matching each platform's
 * habit. "config generation-dir" moves it for anyone who disagrees.
 */
#define GENDIR_DEFAULT "/var/db/sysmon"

const char *confgen_statedir(void)
{
	return (gen_statedir != NULL) ? gen_statedir : GENDIR_DEFAULT;
}

/*
 * Set from "config generation-dir". Honoured once, from the seed config:
 * a delivered config must not be able to move the directory the daemon is
 * currently running out of, and an operator asking "where does this box
 * keep its config" wants one answer that does not depend on which
 * generation happens to be live.
 */
void confgen_set_statedir(const char *dir)
{
	if (gen_statedir_locked)
		return;
	if (dir != NULL && *dir != '\0')
	{
		if (gen_statedir != NULL)
			FREE(gen_statedir);
		gen_statedir = STRDUP((unsigned char *)dir, "confgen:statedir");
	}
}

void confgen_lock_statedir(void)
{
	gen_statedir_locked = TRUE;
}

/*
 * Everything this daemon writes, named rather than configured.
 *
 * There used to be a directive per file - pidfile, savestate,
 * statustempdir, logging file, aggregator-ca - and each one was a path a
 * delivered config could aim anywhere the daemon could write. One
 * directory removes all five conflicts at once, and leaves an operator
 * with one path to get right instead of five.
 *
 * Each has its own buffer, so two of them can be held at the same time
 * without the second quietly overwriting the first.
 */
const char *sysmon_pidfile(void)
{
	static char path[PATH_MAX];

	snprintf(path, sizeof(path), "%s/sysmond.pid", confgen_statedir());
	return path;
}

const char *sysmon_logfile(void)
{
	static char path[PATH_MAX];

	snprintf(path, sizeof(path), "%s/sysmond.log", confgen_statedir());
	return path;
}

/*
 * The check-state checkpoint, written at shutdown and read at startup.
 * Not .xml: it stopped being XML when something finally had to read it
 * back, and a name that lies about a format is worse than no name.
 */
const char *sysmon_statefile(void)
{
	static char path[PATH_MAX];

	snprintf(path, sizeof(path), "%s/sysmond.state", confgen_statedir());
	return path;
}

/*
 * The CA that signs the aggregator's certificate, if the operator has
 * put one here. NULL means none, which means the system trust store -
 * the right answer for an aggregator with a publicly signed certificate.
 */
const char *sysmon_ca_file(void)
{
	static char path[PATH_MAX];
	struct stat st;

	snprintf(path, sizeof(path), "%s/aggregator-ca.pem", confgen_statedir());
	if (stat(path, &st) == 0 && S_ISREG(st.st_mode))
		return path;
	return NULL;
}

static void statepath(char *out, size_t outlen, const char *leaf)
{
	snprintf(out, outlen, "%s/%s", confgen_statedir(), leaf);
}

static void gendir_path(char *out, size_t outlen, unsigned long gen)
{
	snprintf(out, outlen, "%s/gen-%010lu", confgen_statedir(), gen);
}

/* The generation a symlink points at, or 0 if there is no such link. */
static unsigned long linked_generation(const char *link)
{
	char path[PATH_MAX], target[PATH_MAX];
	ssize_t n;
	char *dash;

	statepath(path, sizeof(path), link);
	n = readlink(path, target, sizeof(target) - 1);
	if (n <= 0)
		return 0;
	target[n] = '\0';

	dash = strrchr(target, '-');
	if (dash == NULL)
		return 0;
	return strtoul(dash + 1, NULL, 10);
}

/* Point <gendir>/<link> at gen-NNNN, atomically. */
static bool point_link(const char *link, unsigned long gen)
{
	char path[PATH_MAX], tmp[PATH_MAX + 8];
	char target[64];

	statepath(path, sizeof(path), link);
	snprintf(tmp, sizeof(tmp), "%s.new", path);
	snprintf(target, sizeof(target), "gen-%010lu", gen);

	unlink(tmp);
	if (symlink(target, tmp) == -1)
	{
		print_err(1, "confgen: cannot create %s: %s", tmp, strerror(errno));
		return FALSE;
	}
	if (rename(tmp, path) == -1)
	{
		print_err(1, "confgen: cannot move %s into place: %s", path, strerror(errno));
		unlink(tmp);
		return FALSE;
	}
	return TRUE;
}

unsigned long confgen_generation(void)
{
	return running_generation;
}

/*
 * The config this daemon should load: the managed copy when there is one,
 * the seed otherwise.
 *
 * "Otherwise" is doing real work here. A box whose state directory has
 * been wiped, or whose disk filled before a generation finished landing,
 * comes back up on the config an operator wrote - not on nothing, and not
 * on half of something.
 */
const char *confgen_active_config(void)
{
	char candidate[PATH_MAX];
	char namepath[PATH_MAX];
	FILE *fh;
	unsigned long gen;
	struct stat st;

	/* The entry file's name, remembered from when the box was adopted. */
	statepath(namepath, sizeof(namepath), "main");
	fh = fopen(namepath, "r");
	if (fh != NULL)
	{
		if (fgets(gen_mainname, sizeof(gen_mainname), fh) != NULL)
		{
			char *nl = strchr(gen_mainname, '\n');
			if (nl != NULL)
				*nl = '\0';
		}
		fclose(fh);
	}
	if (!flat_name(gen_mainname))
	{
		const char *base = strrchr(configfile, '/');
		snprintf(gen_mainname, sizeof(gen_mainname), "%s",
			(base != NULL) ? base + 1 : configfile);
	}

	gen = linked_generation("current");
	if (gen > 0)
	{
		snprintf(candidate, sizeof(candidate), "%s/current/%s",
			confgen_statedir(), gen_mainname);
		if (stat(candidate, &st) == 0 && S_ISREG(st.st_mode))
		{
			running_generation = gen;
			snprintf(gen_active, sizeof(gen_active), "%s", candidate);
			return gen_active;
		}
		print_err(1, "confgen: generation %lu is incomplete - falling back to %s",
			gen, configfile);
	}

	running_generation = 0;
	snprintf(gen_active, sizeof(gen_active), "%s", configfile);
	return gen_active;
}

/*
 * Is this file part of the managed copy?
 *
 * Include resolution depends on the answer. Inside the managed directory
 * an include names a sibling and nothing else - not a file in the working
 * directory, which is / by the time the daemon is running and is a place
 * anyone might be able to create a file. Outside it, resolution is what it
 * always was.
 */
bool confgen_is_managed_file(const char *path)
{
	char dir[PATH_MAX];
	size_t n;

	if (path == NULL)
		return FALSE;

	/*
	 * Anything under the state directory, whether or not a generation is
	 * live right now. That matters during validation: a delivery is
	 * parsed in its staging directory *before* it becomes current, and if
	 * this asked "is a generation live" it would resolve the staged
	 * config's includes by the other rule - so the daemon would validate
	 * one set of files and then run a different one.
	 */
	snprintf(dir, sizeof(dir), "%s/", confgen_statedir());
	n = strlen(dir);
	return strncmp(path, dir, n) == 0;
}

/*
 * Create the state directory while still root, and hand it to the user the
 * daemon is about to become. Called before the privilege drop, because
 * afterwards /var/lib is not writable and the alternative is asking an
 * operator to mkdir it by hand on every box in the fleet.
 */
void confgen_prepare(uid_t uid, gid_t gid)
{
	const char *dir = confgen_statedir();
	struct stat st;

	if (stat(dir, &st) == -1)
	{
		/*
		 * Make the parent too if it is missing. /var/db is standard on
		 * BSD and absent on most Linux installs, and failing there would
		 * mean every Linux box in a fleet needed a mkdir by hand before
		 * it could be managed.
		 */
		char parent[PATH_MAX];
		char *slash;

		snprintf(parent, sizeof(parent), "%s", dir);
		slash = strrchr(parent, '/');
		if (slash != NULL && slash != parent)
		{
			*slash = '\0';
			if (stat(parent, &st) == -1 && mkdir(parent, 0755) == -1)
			{
				print_err(1, "confgen: cannot create %s: %s", parent,
					strerror(errno));
			}
		}

		if (mkdir(dir, 0750) == -1)
		{
			print_err(1, "confgen: cannot create %s: %s - this box cannot be "
				"managed remotely until it exists", dir, strerror(errno));
			return;
		}
		print_err(0, "confgen: created %s", dir);
	}
	else if (!S_ISDIR(st.st_mode))
	{
		print_err(1, "confgen: %s is not a directory", dir);
		return;
	}

	if (geteuid() == 0 && chown(dir, uid, gid) == -1)
	{
		print_err(1, "confgen: cannot give %s to uid %d: %s",
			dir, (int)uid, strerror(errno));
	}
	chmod(dir, 0750);
}

/* Remember the entry file's name for next boot. */
static bool save_mainname(void)
{
	char path[PATH_MAX], tmp[PATH_MAX + 8];
	FILE *fh;

	statepath(path, sizeof(path), "main");
	snprintf(tmp, sizeof(tmp), "%s.new", path);

	fh = fopen(tmp, "w");
	if (fh == NULL)
	{
		print_err(1, "confgen: cannot write %s: %s", tmp, strerror(errno));
		return FALSE;
	}
	fprintf(fh, "%s\n", gen_mainname);
	if (fclose(fh) != 0)
		return FALSE;
	if (rename(tmp, path) == -1)
	{
		unlink(tmp);
		return FALSE;
	}
	return TRUE;
}

/* Keep a few generations behind the live one; drop the rest. */
#define GENERATIONS_KEPT 5

static void prune_generations(void)
{
	DIR *d;
	struct dirent *e;
	unsigned long cur = linked_generation("current");
	unsigned long prev = linked_generation("previous");
	char path[PATH_MAX];

	d = opendir(confgen_statedir());
	if (d == NULL)
		return;
	while ((e = readdir(d)) != NULL)
	{
		unsigned long gen;

		if (strncmp(e->d_name, "gen-", 4) != 0)
			continue;
		gen = strtoul(e->d_name + 4, NULL, 10);
		if (gen == 0 || gen == cur || gen == prev)
			continue;
		if (cur > GENERATIONS_KEPT && gen >= cur - GENERATIONS_KEPT)
			continue;
		snprintf(path, sizeof(path), "%s/%s", confgen_statedir(), e->d_name);
		remove_gen_dir(path);
	}
	closedir(d);
}

/* A generation sitting on disk, read back in its recorded load order. */
static bool hash_generation(unsigned long gen, char *out, size_t outlen)
{
	char dir[PATH_MAX], path[PATH_MAX + 160], line[256];
	FILE *order;

	if (out == NULL || outlen < 65)
		return FALSE;
	out[0] = '\0';

	gendir_path(dir, sizeof(dir), gen);
	snprintf(path, sizeof(path), "%s/%s", dir, GEN_ORDER_FILE);
	order = fopen(path, "r");
	if (order == NULL)
		return FALSE;

	{
		struct hash_ctx h;
		unsigned char *content;
		long len;

		if (!hash_begin(&h))
		{
			fclose(order);
			return FALSE;
		}
		while (fgets(line, sizeof(line), order) != NULL)
		{
			char *nl = strchr(line, '\n');

			if (nl != NULL)
				*nl = '\0';
			if (!flat_name(line))
				continue;
			snprintf(path, sizeof(path), "%s/%s", dir, line);
			content = slurp(path, &len);
			if (content == NULL)
			{
				fclose(order);
				EVP_MD_CTX_free(h.md);
				return FALSE;
			}
			hash_pair(&h, line, content, len);
			FREE(content);
		}
		fclose(order);
		return hash_end(&h, out);
	}
}

/* ------------------------------------------------------------------ */
/* Validation                                                           */
/* ------------------------------------------------------------------ */

/*
 * Parse a config, in a child process, and collect whatever the parser
 * complained about.
 *
 * A child rather than an in-process parse for two reasons: the lexer and
 * its globals are not re-entrant against a live tree, and a config bad
 * enough to take the parser down takes the child down instead of the
 * daemon that is still paging people.
 *
 * Returns TRUE if the config parses. On failure, up to errlen-1 bytes of
 * the parser's complaints are copied into err.
 */
static bool validate_config(const char *path, char *err, size_t errlen,
	unsigned long *objects)
{
	int fds[2];
	pid_t pid;
	int status = 0;
	size_t used = 0;
	ssize_t got;

	if (err != NULL && errlen > 0)
		err[0] = '\0';
	if (objects != NULL)
		*objects = 0;

	if (pipe(fds) == -1)
	{
		snprintf(err, errlen, "cannot create a pipe to validate: %s",
			strerror(errno));
		return FALSE;
	}

	pid = fork();
	if (pid == -1)
	{
		close(fds[0]);
		close(fds[1]);
		snprintf(err, errlen, "cannot fork to validate: %s", strerror(errno));
		return FALSE;
	}

	if (pid == 0)
	{
		struct all_elements_list *tree, *walk;
		unsigned long n = 0;

		/*
		 * Child. Everything the parser complains about goes to stderr
		 * (parser_error uses print_err(1, ...)), so point stderr at the
		 * pipe and let the parent read it.
		 */
		close(fds[0]);
		dup2(fds[1], STDERR_FILENO);
		close(fds[1]);

		badconfig = FALSE;
		tree = loadconfig((char *)path);
		if (badconfig)
			_exit(1);
		if (tree == NULL)
		{
			fprintf(stderr, "the config declares nothing to monitor\n");
			_exit(1);
		}

		/*
		 * A named root that does not exist is the expensive mistake:
		 * every object becomes unreachable from the root, the whole
		 * dependency tree stops meaning anything, and the config still
		 * "parses". The daemon knows the answer here, so it says so
		 * rather than accepting a delivery that would silently gut the
		 * dependency model.
		 */
		if (configed_root == NULL)
		{
			fprintf(stderr, "root object \"%s\" is not defined in this config\n",
				parser_root != NULL ? parser_root : "");
			_exit(1);
		}

		for (walk = tree; walk != NULL; walk = walk->next)
			n++;
		fprintf(stderr, "SYSMOND-OBJECTS %lu\n", n);
		_exit(0);
	}

	close(fds[1]);
	while (errlen > 1 && used < errlen - 1)
	{
		got = read(fds[0], err + used, errlen - 1 - used);
		if (got <= 0)
			break;
		used += (size_t)got;
	}
	if (err != NULL && errlen > 0)
		err[used] = '\0';
	/* Drain the rest so the child is never blocked writing. */
	{
		char sink[512];
		while (read(fds[0], sink, sizeof(sink)) > 0)
			;
	}
	close(fds[0]);

	/*
	 * The child's last line is how many objects the config describes.
	 * That number is what the canary compares against expectation - a
	 * config can parse perfectly and still have dropped four hundred
	 * hosts - so it comes back out of band rather than being buried in
	 * the parser's chatter.
	 */
	if (err != NULL)
	{
		char *marker = strstr(err, "SYSMOND-OBJECTS ");

		if (marker != NULL)
		{
			if (objects != NULL)
				*objects = strtoul(marker + 16, NULL, 10);
			*marker = '\0';
		}
	}

	while (waitpid(pid, &status, 0) == -1 && errno == EINTR)
		;

	if (WIFEXITED(status) && WEXITSTATUS(status) == 0)
		return TRUE;

	if (err != NULL && errlen > 0 && err[0] == '\0')
	{
		if (WIFSIGNALED(status))
			snprintf(err, errlen, "the parser died on signal %d",
				WTERMSIG(status));
		else
			snprintf(err, errlen, "the config was rejected");
	}
	return FALSE;
}

/* ------------------------------------------------------------------ */
/* Applying a delivered generation                                      */
/* ------------------------------------------------------------------ */

/*
 * Write the delivered files into a fresh generation directory, parse them
 * there, and only then make that directory the live one.
 *
 * Nothing that is currently running is touched until the last two lines.
 * A rejected delivery leaves the running config on disk exactly as it was,
 * the in-memory tree exactly as it was, and a directory to remove.
 */
bool confgen_apply(unsigned long generation,
	struct confgen_file *files, int nfiles,
	char *err, size_t errlen, unsigned long *objects)
{
	char dir[PATH_MAX], path[PATH_MAX + 160], entry[PATH_MAX + 160];
	unsigned long prev = running_generation;
	bool has_main = FALSE;
	int i, j;

	if (err != NULL && errlen > 0)
		err[0] = '\0';

	if (nfiles <= 0)
	{
		snprintf(err, errlen, "no files were delivered");
		return FALSE;
	}
	if (generation == 0)
	{
		snprintf(err, errlen, "generation 0 means \"running the seed config\" "
			"and cannot be delivered");
		return FALSE;
	}

	/*
	 * Names, not paths. Nothing the other end sends is used to build a
	 * directory - only the last component of a filename this side has
	 * already decided is acceptable.
	 */
	for (i = 0; i < nfiles; i++)
	{
		if (!flat_name(files[i].name))
		{
			snprintf(err, errlen,
				"\"%s\" is not a plain filename; a delivery names files, not paths",
				files[i].name != NULL ? files[i].name : "");
			return FALSE;
		}
		for (j = 0; j < i; j++)
		{
			if (strcmp(files[i].name, files[j].name) == 0)
			{
				snprintf(err, errlen, "\"%s\" appears twice in one delivery",
					files[i].name);
				return FALSE;
			}
		}
		if (gen_mainname[0] != '\0' && strcmp(files[i].name, gen_mainname) == 0)
			has_main = TRUE;
	}

	/* First delivery on a box whose entry name is not recorded yet. */
	if (gen_mainname[0] == '\0')
	{
		const char *base = strrchr(configfile, '/');

		snprintf(gen_mainname, sizeof(gen_mainname), "%s",
			(base != NULL) ? base + 1 : configfile);
		for (i = 0; i < nfiles; i++)
		{
			if (strcmp(files[i].name, gen_mainname) == 0)
				has_main = TRUE;
		}
	}
	if (!has_main)
	{
		snprintf(err, errlen, "the delivery does not include \"%s\", "
			"which is the file this daemon reads", gen_mainname);
		return FALSE;
	}

	gendir_path(dir, sizeof(dir), generation);
	remove_gen_dir(dir); /* a previous attempt at this number, if any */
	if (mkdir(dir, 0750) == -1)
	{
		snprintf(err, errlen, "cannot create %s: %s", dir, strerror(errno));
		return FALSE;
	}

	for (i = 0; i < nfiles; i++)
	{
		snprintf(path, sizeof(path), "%s/%s", dir, files[i].name);
		if (write_whole(path, files[i].data, files[i].len) == -1)
		{
			snprintf(err, errlen, "cannot write %s: %s", path, strerror(errno));
			remove_gen_dir(dir);
			return FALSE;
		}
	}

	/* Record the load order alongside them, so this generation can still
	   be hashed - and therefore rolled back to and reported - long after
	   the delivery that carried it. */
	{
		FILE *order;

		snprintf(path, sizeof(path), "%s/%s", dir, GEN_ORDER_FILE);
		order = fopen(path, "w");
		if (order == NULL)
		{
			snprintf(err, errlen, "cannot write %s: %s", path, strerror(errno));
			remove_gen_dir(dir);
			return FALSE;
		}
		for (i = 0; i < nfiles; i++)
			fprintf(order, "%s\n", files[i].name);
		if (fclose(order) != 0)
		{
			snprintf(err, errlen, "cannot write %s", path);
			remove_gen_dir(dir);
			return FALSE;
		}
	}

	snprintf(entry, sizeof(entry), "%s/%s", dir, gen_mainname);
	if (!validate_config(entry, err, errlen, objects))
	{
		print_err(1, "confgen: generation %lu rejected; nothing changed",
			generation);
		remove_gen_dir(dir);
		return FALSE;
	}

	/*
	 * The swap. previous first: if the machine dies between these two,
	 * current still points at the generation that was running, which is
	 * the config that was working.
	 */
	if (prev > 0)
		point_link("previous", prev);
	save_mainname();
	if (!point_link("current", generation))
	{
		snprintf(err, errlen, "cannot point %s/current at generation %lu",
			confgen_statedir(), generation);
		remove_gen_dir(dir);
		return FALSE;
	}

	running_generation = generation;
	prune_generations();

	print_err(1, "confgen: generation %lu accepted, reloading", generation);
	gotsighup = TRUE; /* the main loop reloads at the top of the next pass */
	return TRUE;
}

/*
 * Roll back to the generation kept alongside the live one.
 *
 * The files are already on the box, so this needs nothing from the
 * network - which matters, because a config that broke the link to the
 * aggregator is exactly the one you most need to undo.
 */
bool confgen_rollback(char *err, size_t errlen)
{
	unsigned long prev, cur;
	char entry[PATH_MAX + 160];

	if (err != NULL && errlen > 0)
		err[0] = '\0';

	cur = running_generation;
	prev = linked_generation("previous");
	if (prev == 0 || prev == cur)
	{
		snprintf(err, errlen, "no previous generation is held on this box");
		return FALSE;
	}

	snprintf(entry, sizeof(entry), "%s/gen-%010lu/%s",
		confgen_statedir(), prev, gen_mainname);
	/*
	 * It parsed once, so it should parse again - but "should" is not a
	 * thing to bet a monitoring box on, and if the copy has been damaged
	 * the daemon keeps running what it has and says so.
	 */
	if (!validate_config(entry, err, errlen, NULL))
	{
		print_err(1, "confgen: the rollback copy does not parse; "
			"keeping the running config");
		return FALSE;
	}

	if (!point_link("current", prev))
	{
		snprintf(err, errlen, "cannot point current at generation %lu", prev);
		return FALSE;
	}
	if (cur > 0)
		point_link("previous", cur);

	running_generation = prev;
	print_err(1, "confgen: rolled back to generation %lu, reloading", prev);
	gotsighup = TRUE;
	return TRUE;
}

/*
 * Stop being managed: drop the managed copy and go back to the seed.
 *
 * This is the way out, and it needs to exist. Without it, adopting a box
 * once would mean its /etc config is inert forever with no way back short
 * of an operator working out what this directory is for. The generations
 * are left on disk; only the pointer to them goes.
 */
bool confgen_revert(char *err, size_t errlen)
{
	char path[PATH_MAX];
	char scratch[1024];

	if (err != NULL && errlen > 0)
		err[0] = '\0';

	if (running_generation == 0)
	{
		snprintf(err, errlen, "this box is already running %s", configfile);
		return FALSE;
	}
	if (!validate_config(configfile, scratch, sizeof(scratch), NULL))
	{
		snprintf(err, errlen, "%s does not parse, so reverting to it would "
			"leave this box with nothing to monitor", configfile);
		return FALSE;
	}

	statepath(path, sizeof(path), "current");
	if (unlink(path) == -1 && errno != ENOENT)
	{
		snprintf(err, errlen, "cannot remove %s: %s", path, strerror(errno));
		return FALSE;
	}

	running_generation = 0;
	print_err(1, "confgen: reverted to %s, reloading", configfile);
	gotsighup = TRUE;
	return TRUE;
}

/* ------------------------------------------------------------------ */
/* The wire                                                             */
/* ------------------------------------------------------------------ */

/*
 * Base64 goes out in fixed-width chunks rather than one enormous line,
 * because sendline() writes a line with a single write() and a multi-
 * megabyte one would be at the mercy of a partial write.
 */
#define B64_LINE 960

/*
 * CONFIG-GET: every file this daemon is running, byte for byte.
 *
 * This is how a box is adopted - sysmon-web takes what is really on the
 * box as the first desired generation, rather than asking someone to
 * paste a config in and hope it matches. It is privileged, because a
 * config carries community strings and contact addresses.
 */
void confgen_send(struct clientstatus *client)
{
	char line[B64_LINE + 128];
	char hash[80];
	unsigned char *content;
	char *b64;
	long len, off;
	int i;

	for (i = 0; i < confset_n; i++)
	{
		content = slurp(confset[i].path, &len);
		if (content == NULL)
		{
			snprintf(line, sizeof(line), "444 cannot read %s", confset[i].path);
			sendline(client->filedes, line);
			return;
		}
		b64 = confgen_b64encode(content, len);
		FREE(content);
		if (b64 == NULL)
		{
			sendline(client->filedes, "444 out of memory");
			return;
		}

		{
			char *nameb64 = confgen_b64encode(
				(const unsigned char *)confset[i].name,
				(long)strlen(confset[i].name));
			if (nameb64 == NULL)
			{
				FREE(b64);
				sendline(client->filedes, "444 out of memory");
				return;
			}
			snprintf(line, sizeof(line), "FILE %s %ld", nameb64, len);
			FREE(nameb64);
		}
		if (sendline(client->filedes, line) == -1)
		{
			FREE(b64);
			return;
		}

		for (off = 0; off < (long)strlen(b64); off += B64_LINE)
		{
			long n = (long)strlen(b64) - off;
			if (n > B64_LINE)
				n = B64_LINE;
			memcpy(line, b64 + off, (size_t)n);
			line[n] = '\0';
			if (sendline(client->filedes, line) == -1)
			{
				FREE(b64);
				return;
			}
		}
		FREE(b64);
		if (sendline(client->filedes, "ENDFILE") == -1)
			return;
	}

	if (!confgen_hash(hash, sizeof(hash)))
		snprintf(hash, sizeof(hash), "-");
	snprintf(line, sizeof(line), "333 %lu %s %d",
		running_generation, hash, confset_n);
	sendline(client->filedes, line);
}

/*
 * CONFIG-GEN: the one-line answer the poller asks for every cycle.
 *
 * The trailing word is why this box cannot be managed, when it cannot -
 * an include naming a path rather than a filename, most likely. Saying it
 * here means the operator finds out when they look at the fleet, not when
 * a delivery fails.
 */
void confgen_report(struct clientstatus *client)
{
	char line[512];
	char hash[80];
	char why[256];

	if (!confgen_hash(hash, sizeof(hash)))
	{
		if (confset_count() == 0)
			sendline(client->filedes, "444 no config is loaded");
		else
			sendline(client->filedes,
				"444 cannot hash this config - either sysmond was built "
				"without TLS, or one of its files is no longer readable");
		return;
	}
	if (!confgen_manageable(why, sizeof(why)))
	{
		snprintf(line, sizeof(line), "333 %lu %s %d unmanageable %s",
			running_generation, hash, confset_n, why);
	}
	else
	{
		snprintf(line, sizeof(line), "333 %lu %s %d",
			running_generation, hash, confset_n);
	}
	sendline(client->filedes, line);
}

/*
 * Read exactly len bytes. The delivery declares its own size so this can
 * read in chunks instead of a byte at a time - and, more importantly, so
 * it stops on the last byte of the payload rather than reading ahead into
 * whatever command follows.
 */
static unsigned char *read_exact(int fd, long len)
{
	unsigned char *buf;
	long got = 0;
	int stalls = 0;

	buf = MALLOC((size_t)len + 1, "confgen:read_exact");
	if (buf == NULL)
		return NULL;

	while (got < len)
	{
		int n;

		if (tls_pending(fd) <= 0 && data_waiting_read(fd, 10) <= 0)
		{
			stalls++;
			if (stalls > 3)
			{
				FREE(buf);
				return NULL;
			}
			continue;
		}
		n = tls_read(fd, buf + got, (int)(len - got));
		if (n <= 0)
		{
			FREE(buf);
			return NULL;
		}
		got += n;
		stalls = 0;
	}
	buf[len] = '\0';
	return buf;
}

static void free_files(struct confgen_file *files, int n)
{
	int i;

	for (i = 0; i < n; i++)
	{
		if (files[i].name != NULL)
			FREE(files[i].name);
		if (files[i].data != NULL)
			FREE(files[i].data);
	}
	FREE(files);
}

/*
 * CONFIG-PUT <generation> <payload-bytes>
 *
 * followed by exactly <payload-bytes> of:
 *
 *   FILE <base64 name> <content length>
 *   <base64 content, wrapped>
 *   ENDFILE
 *
 * Names and contents are base64 so a config containing anything at all -
 * a stray CR, a UTF-8 comment, a byte that is not text - survives the trip
 * unchanged. The hash both sides compare is over the original bytes, so
 * "survives unchanged" is not a nicety here, it is the entire mechanism.
 */
void confgen_receive(struct clientstatus *client, char *args)
{
	char reply[512];
	char err[1024];
	unsigned long generation = 0;
	long payload_len = 0;
	unsigned char *payload;
	struct confgen_file *files = NULL;
	int nfiles = 0, cap = 0;
	unsigned long objects = 0;
	char applied_hash[80] = "-";
	char *p, *end;
	bool ok;

	if (args == NULL || sscanf(args, "%lu %ld", &generation, &payload_len) != 2)
	{
		sendline(client->filedes,
			"444 usage: CONFIG-PUT <generation> <payload-bytes>");
		return;
	}
	if (payload_len <= 0 || payload_len > CONFGEN_MAX_PAYLOAD)
	{
		snprintf(reply, sizeof(reply),
			"444 payload of %ld bytes is outside 1..%d", payload_len,
			CONFGEN_MAX_PAYLOAD);
		sendline(client->filedes, reply);
		return;
	}

	payload = read_exact(client->filedes, payload_len);
	if (payload == NULL)
	{
		sendline(client->filedes, "444 the delivery was truncated");
		return;
	}

	/* Walk the payload a line at a time, in place. */
	p = (char *)payload;
	end = (char *)payload + payload_len;
	while (p < end)
	{
		char *nl, *nameb64, *sp;
		long declared = 0;
		char *body;
		long bodylen = 0;

		nl = memchr(p, '\n', (size_t)(end - p));
		if (nl == NULL)
			break;
		*nl = '\0';
		if (nl > p && nl[-1] == '\r')
			nl[-1] = '\0';

		if (strncmp(p, "FILE ", 5) != 0)
		{
			p = nl + 1;
			continue; /* blank line, or trailing junk */
		}

		nameb64 = p + 5;
		sp = strchr(nameb64, ' ');
		if (sp == NULL)
		{
			free_files(files, nfiles);
			FREE(payload);
			sendline(client->filedes, "444 malformed FILE header");
			return;
		}
		*sp = '\0';
		declared = strtol(sp + 1, NULL, 10);

		/* Gather the base64 body up to ENDFILE. */
		p = nl + 1;
		body = p;
		bodylen = 0;
		while (p < end)
		{
			nl = memchr(p, '\n', (size_t)(end - p));
			if (nl == NULL)
				nl = end;
			if ((size_t)(nl - p) == 7 && strncmp(p, "ENDFILE", 7) == 0)
				break;
			if ((size_t)(nl - p) == 8 && strncmp(p, "ENDFILE\r", 8) == 0)
				break;
			bodylen = (long)(nl - body);
			p = (nl < end) ? nl + 1 : end;
		}
		if (p >= end)
		{
			free_files(files, nfiles);
			FREE(payload);
			sendline(client->filedes, "444 a file was not terminated by ENDFILE");
			return;
		}
		/* p currently sits on the ENDFILE line; step past it. */
		nl = memchr(p, '\n', (size_t)(end - p));
		p = (nl != NULL) ? nl + 1 : end;

		if (nfiles == cap)
		{
			struct confgen_file *bigger;
			int newcap = (cap == 0) ? 8 : cap * 2;

			if (newcap > CONFSET_MAX)
				newcap = CONFSET_MAX;
			if (nfiles >= newcap)
			{
				free_files(files, nfiles);
				FREE(payload);
				sendline(client->filedes, "444 too many files in one delivery");
				return;
			}
			bigger = MALLOC(sizeof(struct confgen_file) * newcap,
				"confgen:files");
			if (bigger == NULL)
			{
				free_files(files, nfiles);
				FREE(payload);
				sendline(client->filedes, "444 out of memory");
				return;
			}
			memset(bigger, 0, sizeof(struct confgen_file) * newcap);
			if (files != NULL)
			{
				memcpy(bigger, files, sizeof(struct confgen_file) * nfiles);
				FREE(files);
			}
			files = bigger;
			cap = newcap;
		}

		{
			char saved = body[bodylen];
			long plen = 0, clen = 0;
			unsigned char *namebytes;

			body[bodylen] = '\0';
			files[nfiles].data = confgen_b64decode(body, &clen);
			body[bodylen] = saved;

			namebytes = confgen_b64decode(nameb64, &plen);
			if (namebytes == NULL || files[nfiles].data == NULL)
			{
				if (namebytes != NULL)
					FREE(namebytes);
				free_files(files, nfiles + 1);
				FREE(payload);
				sendline(client->filedes, "444 the delivery is not valid base64");
				return;
			}
			files[nfiles].name = (char *)namebytes;
			files[nfiles].len = clen;

			if (declared != clen)
			{
				snprintf(reply, sizeof(reply),
					"444 %s declared %ld bytes but carried %ld",
					files[nfiles].name, declared, clen);
				free_files(files, nfiles + 1);
				FREE(payload);
				sendline(client->filedes, reply);
				return;
			}
			nfiles++;
		}
	}
	FREE(payload);

	ok = confgen_apply(generation, files, nfiles, err, sizeof(err), &objects);
	if (ok && !confgen_hash_files(files, nfiles, applied_hash, sizeof(applied_hash)))
		snprintf(applied_hash, sizeof(applied_hash), "-");
	free_files(files, nfiles);

	if (!ok)
	{
		char *line = err, *nl;

		/* The parser's complaints go back verbatim, one line each. The
		   operator needs to see what their own daemon objected to, not a
		   summary written by whatever tried to deliver it. */
		while (line != NULL && *line != '\0')
		{
			nl = strchr(line, '\n');
			if (nl != NULL)
				*nl = '\0';
			if (*line != '\0')
				sendline(client->filedes, line);
			line = (nl != NULL) ? nl + 1 : NULL;
		}
		sendline(client->filedes, "444 config rejected, nothing changed");
		return;
	}

	/* The hash is of the bytes that were delivered, not of what is
	   loaded: the reload happens at the top of the next main-loop pass,
	   and hashing the loaded config here would report the generation this
	   box is leaving as though it were the one it is joining. */
	snprintf(reply, sizeof(reply), "333 %lu %s %lu",
		running_generation, applied_hash, objects);
	sendline(client->filedes, reply);
}

/*
 * CONFIG-ROLLBACK: put the previous generation back.
 */
void confgen_do_rollback(struct clientstatus *client)
{
	char err[1024], reply[512], hash[80];

	if (!confgen_rollback(err, sizeof(err)))
	{
		char *line = err, *nl;

		while (line != NULL && *line != '\0')
		{
			nl = strchr(line, '\n');
			if (nl != NULL)
				*nl = '\0';
			if (*line != '\0')
				sendline(client->filedes, line);
			line = (nl != NULL) ? nl + 1 : NULL;
		}
		sendline(client->filedes, "444 rollback failed");
		return;
	}

	/* Same reason as CONFIG-PUT: the reload has not happened yet, so this
	   is the hash of the generation now pointed at, read from disk. */
	if (!hash_generation(running_generation, hash, sizeof(hash)))
		snprintf(hash, sizeof(hash), "-");
	snprintf(reply, sizeof(reply), "333 %lu %s", running_generation, hash);
	sendline(client->filedes, reply);
}

/*
 * CONFIG-REVERT: stop being managed and go back to the seed config.
 */
void confgen_do_revert(struct clientstatus *client)
{
	char err[1024], reply[512];

	if (!confgen_revert(err, sizeof(err)))
	{
		char *line = err, *nl;

		while (line != NULL && *line != '\0')
		{
			nl = strchr(line, '\n');
			if (nl != NULL)
				*nl = '\0';
			if (*line != '\0')
				sendline(client->filedes, line);
			line = (nl != NULL) ? nl + 1 : NULL;
		}
		sendline(client->filedes, "444 revert failed");
		return;
	}

	snprintf(reply, sizeof(reply), "333 0 reverted to %s", configfile);
	sendline(client->filedes, reply);
}
