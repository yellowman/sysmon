/*
 * confgen.c - config generations: what this daemon is running, and how a
 * sysmon-web replaces it.
 *
 * The config file stays the source of truth on this box. sysmon-web holds
 * desired state, this daemon holds actual state, and these four commands
 * reconcile them:
 *
 *   CONFIG-GEN       what am I running?      -> generation number + hash
 *   CONFIG-GET       give me what you run    -> every file, byte for byte
 *   CONFIG-PUT       run this instead        -> validate, swap, reload
 *   CONFIG-ROLLBACK  undo the last PUT       -> restore, reload
 *
 * Three properties matter more than anything else here:
 *
 * 1. The running config is never replaced by one that does not parse.
 *    Validation is this daemon's own lexer, in a forked child, on the real
 *    files - not sysmon-web's Go parser, which is a second implementation
 *    of the same grammar and can disagree. The only opinion that counts is
 *    the one held by the process that has to run it.
 *
 * 2. A rejected config costs nothing. The in-memory tree is untouched
 *    until validation passes, so checks and pages carry on throughout, and
 *    the previous files are restored before the reply is even sent.
 *
 * 3. Nothing outside this daemon's own config directory can be written,
 *    whatever the other end asks for. An aggregator is trusted to manage
 *    the monitoring config; it is not trusted to write /etc/passwd.
 */

#include "config.h"

#include <sys/wait.h>

#ifdef HAVE_TLS
#include <openssl/evp.h>
#endif

/*
 * The set of files the parser actually opened, in load order. Recorded as
 * the config is read rather than re-derived by scanning for "include",
 * because the parser is the authority on what it followed - and a hash
 * over a guess is worse than no hash.
 */
#define CONFSET_MAX 64

static char *confset[CONFSET_MAX];
static int confset_n = 0;

/* Where generation state and the rollback copy live. */
static char *gen_statedir = NULL;

/* What we are running. Generation 0 means "never managed". */
static unsigned long running_generation = 0;

void confset_reset(void)
{
	int i;

	for (i = 0; i < confset_n; i++)
	{
		FREE(confset[i]);
		confset[i] = NULL;
	}
	confset_n = 0;
}

void confset_record(const char *path)
{
	char resolved[PATH_MAX];
	int i;

	if (path == NULL || *path == '\0')
		return;

	/*
	 * Absolute, always. A relative include is resolved against whatever
	 * the daemon's working directory happened to be when it parsed - and
	 * the daemon later moves to /, so the same string would name a
	 * different file, or no file at all. The hash and the write-
	 * containment check both key on this path, so it has to mean one
	 * thing forever.
	 */
	if (realpath(path, resolved) != NULL)
		path = resolved;

	/* An include pulled in twice is one file, and must be hashed once. */
	for (i = 0; i < confset_n; i++)
	{
		if (strcmp(confset[i], path) == 0)
			return;
	}

	if (confset_n >= CONFSET_MAX)
	{
		print_err(1, "confgen: more than %d config files; the rest are "
			"parsed but not tracked for fleet management", CONFSET_MAX);
		return;
	}

	confset[confset_n] = STRDUP((unsigned char *)path, "confgen:confset");
	if (confset[confset_n] != NULL)
		confset_n++;
}

int confset_count(void)
{
	return confset_n;
}

const char *confset_path(int i)
{
	if (i < 0 || i >= confset_n)
		return NULL;
	return confset[i];
}

/*
 * Read a whole file. Returns malloc'd bytes and sets *len; NULL on error.
 */
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

#ifdef HAVE_TLS

/*
 * The content hash both ends compare.
 *
 * SHA-256 over, for each file in load order: the path's length, the path,
 * the content's length, the content - each length as 8 bytes big-endian so
 * no concatenation of two different file sets can collide.
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
bool confgen_hash(char *out, size_t outlen)
{
	EVP_MD_CTX *ctx;
	unsigned char md[EVP_MAX_MD_SIZE];
	unsigned int mdlen = 0;
	unsigned char *content;
	long len;
	int i;
	unsigned int j;

	if (out == NULL || outlen < 65)
		return FALSE;
	out[0] = '\0';

	ctx = EVP_MD_CTX_new();
	if (ctx == NULL)
		return FALSE;
	if (EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) != 1)
	{
		EVP_MD_CTX_free(ctx);
		return FALSE;
	}

	for (i = 0; i < confset_n; i++)
	{
		content = slurp(confset[i], &len);
		if (content == NULL)
		{
			print_err(1, "confgen: cannot read %s to hash it", confset[i]);
			EVP_MD_CTX_free(ctx);
			return FALSE;
		}
		hash_u64(ctx, (unsigned long)strlen(confset[i]));
		EVP_DigestUpdate(ctx, confset[i], strlen(confset[i]));
		hash_u64(ctx, (unsigned long)len);
		EVP_DigestUpdate(ctx, content, (size_t)len);
		FREE(content);
	}

	if (EVP_DigestFinal_ex(ctx, md, &mdlen) != 1)
	{
		EVP_MD_CTX_free(ctx);
		return FALSE;
	}
	EVP_MD_CTX_free(ctx);

	for (i = 0, j = 0; j < mdlen; j++)
	{
		static const char hex[] = "0123456789abcdef";
		out[i++] = hex[(md[j] >> 4) & 0xf];
		out[i++] = hex[md[j] & 0xf];
	}
	out[i] = '\0';
	return TRUE;
}

#else /* !HAVE_TLS */

bool confgen_hash(char *out, size_t outlen)
{
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
/* Where state lives                                                    */
/* ------------------------------------------------------------------ */

/*
 * Default state directory is the config file's own directory, because
 * that is the one directory an operator has already decided this daemon
 * may own. "config generation-dir" moves it, which matters when the
 * config lives somewhere the dropped-privilege user cannot write.
 */
static const char *statedir(void)
{
	static char derived[PATH_MAX];
	char *slash;

	if (gen_statedir != NULL)
		return gen_statedir;

	snprintf(derived, sizeof(derived), "%s", configfile);
	slash = strrchr(derived, '/');
	if (slash == NULL)
		snprintf(derived, sizeof(derived), ".");
	else if (slash == derived)
		derived[1] = '\0';
	else
		*slash = '\0';
	return derived;
}

void confgen_set_statedir(const char *dir)
{
	if (gen_statedir != NULL)
		FREE(gen_statedir);
	gen_statedir = NULL;
	if (dir != NULL && *dir != '\0')
		gen_statedir = STRDUP((unsigned char *)dir, "confgen:statedir");
}

static void statepath(char *out, size_t outlen, const char *leaf)
{
	snprintf(out, outlen, "%s/%s", statedir(), leaf);
}

/*
 * The generation number survives a restart, so a box that reboots does not
 * come back claiming to be unmanaged and get re-delivered a config it is
 * already running.
 */
void confgen_load_state(void)
{
	char path[PATH_MAX];
	FILE *fh;
	unsigned long gen = 0;

	statepath(path, sizeof(path), "sysmon.generation");
	fh = fopen(path, "r");
	if (fh == NULL)
	{
		running_generation = 0;
		return;
	}
	if (fscanf(fh, "%lu", &gen) == 1)
		running_generation = gen;
	fclose(fh);
}

static void save_state(void)
{
	char path[PATH_MAX], tmp[PATH_MAX + 8];
	FILE *fh;

	statepath(path, sizeof(path), "sysmon.generation");
	snprintf(tmp, sizeof(tmp), "%s.new", path);

	fh = fopen(tmp, "w");
	if (fh == NULL)
	{
		print_err(1, "confgen: cannot write %s: %s", tmp, strerror(errno));
		return;
	}
	fprintf(fh, "%lu\n", running_generation);
	fclose(fh);
	if (rename(tmp, path) == -1)
	{
		print_err(1, "confgen: cannot replace %s: %s", path, strerror(errno));
		unlink(tmp);
	}
}

unsigned long confgen_generation(void)
{
	return running_generation;
}

/* ------------------------------------------------------------------ */
/* Containment                                                          */
/* ------------------------------------------------------------------ */

/*
 * May we write this path?
 *
 * Yes if it is a file the parser already opened - that is by definition
 * part of this daemon's config - or if it sits directly in the config
 * file's own directory. Anything else is refused, including anything with
 * a ".." in it, whatever the aggregator claims. The aggregator is trusted
 * with the monitoring config; it is not trusted with the filesystem.
 */
static bool path_allowed(const char *path)
{
	char dir[PATH_MAX];
	char *slash;
	size_t dirlen;
	int i;

	if (path == NULL || path[0] != '/')
		return FALSE;
	if (strstr(path, "/../") != NULL)
		return FALSE;
	if (strlen(path) >= 4 && strcmp(path + strlen(path) - 3, "/..") == 0)
		return FALSE;

	for (i = 0; i < confset_n; i++)
	{
		if (strcmp(confset[i], path) == 0)
			return TRUE;
	}

	snprintf(dir, sizeof(dir), "%s", configfile);
	slash = strrchr(dir, '/');
	if (slash == NULL)
		return FALSE;
	*slash = '\0';
	dirlen = strlen(dir);
	if (dirlen == 0)
		return FALSE;

	if (strncmp(path, dir, dirlen) != 0 || path[dirlen] != '/')
		return FALSE;
	/* directly inside it, not in a subdirectory */
	return strchr(path + dirlen + 1, '/') == NULL;
}

/* ------------------------------------------------------------------ */
/* Backup and restore                                                   */
/* ------------------------------------------------------------------ */

/*
 * The previous generation is kept on the box, not fetched to roll back.
 * A config that broke the daemon's ability to reach its aggregator is
 * exactly the config you most need to undo.
 */
static void backup_leaf(char *out, size_t outlen, int idx)
{
	snprintf(out, outlen, "%s/sysmon.prev.%03d", statedir(), idx);
}

static bool save_previous(void)
{
	char manifest[PATH_MAX], tmp[PATH_MAX + 8], leaf[PATH_MAX];
	FILE *mf;
	unsigned char *content;
	long len;
	int i;

	statepath(manifest, sizeof(manifest), "sysmon.prev.manifest");
	snprintf(tmp, sizeof(tmp), "%s.new", manifest);

	mf = fopen(tmp, "w");
	if (mf == NULL)
	{
		print_err(1, "confgen: cannot write %s: %s", tmp, strerror(errno));
		return FALSE;
	}

	for (i = 0; i < confset_n; i++)
	{
		content = slurp(confset[i], &len);
		if (content == NULL)
		{
			fclose(mf);
			unlink(tmp);
			return FALSE;
		}
		backup_leaf(leaf, sizeof(leaf), i);
		if (write_whole(leaf, content, len) == -1)
		{
			print_err(1, "confgen: cannot write %s: %s", leaf, strerror(errno));
			FREE(content);
			fclose(mf);
			unlink(tmp);
			return FALSE;
		}
		FREE(content);
		fprintf(mf, "%s\n", confset[i]);
	}
	fclose(mf);
	if (rename(tmp, manifest) == -1)
	{
		unlink(tmp);
		return FALSE;
	}
	return TRUE;
}

/*
 * Puts the saved copies back. Used both when validation rejects a delivery
 * and when an operator asks for a rollback.
 */
static bool restore_previous(void)
{
	char manifest[PATH_MAX], leaf[PATH_MAX], line[PATH_MAX];
	FILE *mf;
	unsigned char *content;
	long len;
	int i = 0;
	bool ok = TRUE;

	statepath(manifest, sizeof(manifest), "sysmon.prev.manifest");
	mf = fopen(manifest, "r");
	if (mf == NULL)
		return FALSE;

	while (fgets(line, sizeof(line), mf) != NULL)
	{
		char *nl = strchr(line, '\n');
		if (nl != NULL)
			*nl = '\0';
		if (line[0] == '\0')
			continue;

		backup_leaf(leaf, sizeof(leaf), i);
		i++;

		if (!path_allowed(line))
		{
			print_err(1, "confgen: refusing to restore %s", line);
			ok = FALSE;
			continue;
		}
		content = slurp(leaf, &len);
		if (content == NULL)
		{
			print_err(1, "confgen: rollback copy %s is missing", leaf);
			ok = FALSE;
			continue;
		}
		if (write_whole(line, content, len) == -1)
		{
			print_err(1, "confgen: cannot restore %s: %s", line, strerror(errno));
			ok = FALSE;
		}
		FREE(content);
	}
	fclose(mf);
	return ok;
}

/* ------------------------------------------------------------------ */
/* Validation                                                           */
/* ------------------------------------------------------------------ */

/*
 * Parse the config that is now on disk, in a child process, and collect
 * whatever the parser complained about.
 *
 * A child rather than an in-process parse for two reasons: the lexer and
 * its globals are not re-entrant against a live tree, and a config bad
 * enough to take the parser down takes the child down instead of the
 * daemon that is still paging people.
 *
 * Returns TRUE if the config parses. On failure, up to errlen-1 bytes of
 * the parser's complaints are copied into err.
 */
static bool validate_on_disk(char *err, size_t errlen, unsigned long *objects)
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
		unsigned long objects = 0;

		/*
		 * Child. Everything the parser complains about goes to stderr
		 * (parser_error uses print_err(1, ...)), so point stderr at the
		 * pipe and let the parent read it.
		 */
		close(fds[0]);
		dup2(fds[1], STDERR_FILENO);
		close(fds[1]);

		badconfig = FALSE;
		tree = loadconfig(configfile);
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
			objects++;
		fprintf(stderr, "SYSMOND-OBJECTS %lu\n", objects);
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
 * Write the delivered files, validate, and either keep them or put the old
 * ones back.
 *
 * The order is deliberate: back up, write, validate, decide. The running
 * daemon has not reloaded at any point in that sequence, so a config that
 * fails to parse costs nothing but the seconds the files were on disk -
 * and they are put back before this function returns.
 */
bool confgen_apply(unsigned long generation,
	struct confgen_file *files, int nfiles,
	char *err, size_t errlen, unsigned long *objects)
{
	int i;

	if (err != NULL && errlen > 0)
		err[0] = '\0';

	if (nfiles <= 0)
	{
		snprintf(err, errlen, "no files were delivered");
		return FALSE;
	}

	for (i = 0; i < nfiles; i++)
	{
		if (!path_allowed(files[i].path))
		{
			snprintf(err, errlen,
				"refusing to write %s: outside this daemon's config directory",
				files[i].path);
			return FALSE;
		}
	}

	/* The main config file must be among them, or we would be validating
	   a set that does not include the thing the daemon actually reads. */
	{
		bool has_main = FALSE;
		for (i = 0; i < nfiles; i++)
		{
			if (strcmp(files[i].path, configfile) == 0)
				has_main = TRUE;
		}
		if (!has_main)
		{
			snprintf(err, errlen, "the delivery does not include %s", configfile);
			return FALSE;
		}
	}

	if (!save_previous())
	{
		snprintf(err, errlen,
			"cannot save a rollback copy in %s - refusing to change anything",
			statedir());
		return FALSE;
	}

	for (i = 0; i < nfiles; i++)
	{
		char tmp[PATH_MAX + 16];

		snprintf(tmp, sizeof(tmp), "%s.sysmond-new", files[i].path);
		if (write_whole(tmp, files[i].data, files[i].len) == -1 ||
			rename(tmp, files[i].path) == -1)
		{
			snprintf(err, errlen, "cannot write %s: %s",
				files[i].path, strerror(errno));
			unlink(tmp);
			restore_previous();
			return FALSE;
		}
	}

	if (!validate_on_disk(err, errlen, objects))
	{
		print_err(1, "confgen: generation %lu rejected, restoring previous config",
			generation);
		restore_previous();
		return FALSE;
	}

	running_generation = generation;
	save_state();

	print_err(1, "confgen: generation %lu accepted, reloading", generation);
	gotsighup = TRUE; /* the main loop reloads at the top of the next pass */
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
		content = slurp(confset[i], &len);
		if (content == NULL)
		{
			snprintf(line, sizeof(line), "444 cannot read %s", confset[i]);
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
			char *pathb64 = confgen_b64encode(
				(const unsigned char *)confset[i], (long)strlen(confset[i]));
			if (pathb64 == NULL)
			{
				FREE(b64);
				sendline(client->filedes, "444 out of memory");
				return;
			}
			snprintf(line, sizeof(line), "FILE %s %ld", pathb64, len);
			FREE(pathb64);
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
 */
void confgen_report(struct clientstatus *client)
{
	char line[160];
	char hash[80];

	if (!confgen_hash(hash, sizeof(hash)))
	{
		sendline(client->filedes,
			"444 this sysmond was built without TLS, so it cannot hash its config");
		return;
	}
	snprintf(line, sizeof(line), "333 %lu %s %d",
		running_generation, hash, confset_n);
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
		if (files[i].path != NULL)
			FREE(files[i].path);
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
 *   FILE <base64 path> <content length>
 *   <base64 content, wrapped>
 *   ENDFILE
 *
 * Paths and contents are base64 so a config containing anything at all -
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
		char *nl, *pathb64, *sp;
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

		pathb64 = p + 5;
		sp = strchr(pathb64, ' ');
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
			unsigned char *pathbytes;

			body[bodylen] = '\0';
			files[nfiles].data = confgen_b64decode(body, &clen);
			body[bodylen] = saved;

			pathbytes = confgen_b64decode(pathb64, &plen);
			if (pathbytes == NULL || files[nfiles].data == NULL)
			{
				if (pathbytes != NULL)
					FREE(pathbytes);
				free_files(files, nfiles + 1);
				FREE(payload);
				sendline(client->filedes, "444 the delivery is not valid base64");
				return;
			}
			files[nfiles].path = (char *)pathbytes;
			files[nfiles].len = clen;

			if (declared != clen)
			{
				snprintf(reply, sizeof(reply),
					"444 %s declared %ld bytes but carried %ld",
					files[nfiles].path, declared, clen);
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
		sendline(client->filedes, "444 config rejected, previous config restored");
		return;
	}

	{
		char hash[80];

		if (!confgen_hash(hash, sizeof(hash)))
			snprintf(hash, sizeof(hash), "-");
		snprintf(reply, sizeof(reply), "333 %lu %s %lu",
			running_generation, hash, objects);
	}
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

	if (!confgen_hash(hash, sizeof(hash)))
		snprintf(hash, sizeof(hash), "-");
	snprintf(reply, sizeof(reply), "333 %lu %s", running_generation, hash);
	sendline(client->filedes, reply);
}

/*
 * Roll back to the copy kept on the box.
 *
 * The restored config is validated too. It parsed once, so it should parse
 * again - but "should" is not a thing to bet a monitoring box on, and if
 * the restore itself is broken the daemon keeps running what it has in
 * memory and says so.
 */
bool confgen_rollback(char *err, size_t errlen)
{
	if (err != NULL && errlen > 0)
		err[0] = '\0';

	if (!restore_previous())
	{
		snprintf(err, errlen, "no rollback copy is held on this box");
		return FALSE;
	}
	if (!validate_on_disk(err, errlen, NULL))
	{
		print_err(1, "confgen: the rollback copy does not parse; "
			"keeping the running config in memory");
		return FALSE;
	}

	if (running_generation > 0)
		running_generation--;
	save_state();

	print_err(1, "confgen: rolled back to generation %lu, reloading",
		running_generation);
	gotsighup = TRUE;
	return TRUE;
}
