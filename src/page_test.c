/* Exercise page.c with real pipes and children, but a local fake mailer.
 * Faults replace only the OS boundary, not notification policy. */
#include <sys/types.h>
#include <sys/wait.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <pwd.h>
#include <limits.h>
#include <errno.h>

static char test_mailer[PATH_MAX];
static pid_t last_child;
static int fail_fork, fail_popen, fail_identity, fail_stream, bad_stream;
static pid_t test_fork(void);
static FILE *test_popen(const char *, const char *);
static FILE *test_fdopen(int, const char *);
static struct passwd *test_getpwuid(uid_t);

#undef MAIL
#define MAIL test_mailer
#define fork test_fork
#define popen test_popen
#define fdopen test_fdopen
#define getpwuid test_getpwuid
#include "page.c"
#undef fork
#undef popen
#undef fdopen
#undef getpwuid

static int failures;
static char directory[PATH_MAX];
static void check(int ok, const char *why)
{
	if (!ok) {
		fprintf(stderr, "FAIL: %s\n", why);
		failures++;
	}
}

static pid_t test_fork(void)
{
	pid_t p;
	if (fail_fork) { errno = EAGAIN; return -1; }
	p = fork();
	if (p > 0) last_child = p;
	return p;
}

static FILE *test_popen(const char *command, const char *mode)
{
	if (fail_popen) { errno = EMFILE; return NULL; }
	return popen(command, mode);
}

static FILE *test_fdopen(int fd, const char *mode)
{
	if (fail_stream) { errno = EMFILE; return NULL; }
	if (bad_stream) {
		/* The real child sees EOF. The parent gets a stream on which
		 * writing fails, even though the child successfully exits. */
		close(fd);
		return fopen("/dev/null", "r");
	}
	return fdopen(fd, mode);
}

static struct passwd *test_getpwuid(uid_t uid)
{
	if (fail_identity) { errno = ENOENT; return NULL; }
	return getpwuid(uid);
}

static void init_host(struct hostinfo *h)
{
	memset(h, 0, sizeof(*h));
	h->hostname = (unsigned char *)"127.0.0.1";
	h->type = SYSM_TYPE_TCP;
	h->contact = (unsigned char *)"recipient@example.invalid";
	h->unique_id = (unsigned char *)"notification-test";
	h->contact_when = SYSM_CONTACT_DOWN;
	h->lastcheck = SYSM_CONNREF;
	h->lastcontacted = 123;
	h->lastmsgid = (unsigned char *)strdup("previous");
	h->pmesg = (unsigned char *)"first\n.\nlast";
	subject = "test subject";
	sender = "a sender;not-a-shell-command@example.invalid";
	donotify = TRUE;
	fail_fork = fail_popen = fail_identity = fail_stream = bad_stream = 0;
}

static void pending(struct hostinfo *h, const char *why)
{
	check(!h->contacted && h->lastcontacted == 123 &&
	    strcmp((char *)h->lastmsgid, "previous") == 0, why);
}

static void make_mailer(int status)
{
	FILE *f = fopen(test_mailer, "w");
	check(f != NULL, "create fake sendmail executable");
	if (f == NULL) exit(1);
	fprintf(f, "#!/bin/sh\nprintf '%%s\\n' \"$@\" > \"$PAGE_TEST_DIR/args\"\n"
	    "cat > \"$PAGE_TEST_DIR/body\"\nexit %d\n", status);
	check(fclose(f) == 0, "write fake mailer");
	check(chmod(test_mailer, 0700) == 0, "make fake mailer executable");
}

static void file_contains(const char *leaf, const char *needle, const char *why)
{
	char path[PATH_MAX + 32], text[8192];
	size_t n;
	FILE *f;
	snprintf(path, sizeof(path), "%s/%s", directory, leaf);
	f = fopen(path, "r");
	if (f == NULL) { check(FALSE, why); return; }
	n = fread(text, 1, sizeof(text) - 1, f);
	text[n] = '\0';
	fclose(f);
	check(strstr(text, needle) != NULL, why);
}

static void direct_mail(void)
{
	struct hostinfo h;
	char saved[PATH_MAX];
	init_host(&h);
	make_mailer(0);
	page_someone(&h, SYSM_CONTACT_DOWN, 456);
	check(h.contacted && h.lastcontacted == 456 &&
	    strcmp((char *)h.lastmsgid, "previous") != 0, "successful handoff commits paging state");
	file_contains("args", "-oi\n-t\n-f\na sender;not-a-shell-command@example.invalid\n",
	    "mailer path with spaces and sender are passed without a shell");
	file_contains("body", "Subject: test subject\n\nfirst\n.\nlast\n",
	    "subject is separated from body and a dot does not end the body");
	file_contains("body", "In-Reply-To: <previous@sysmon>", "existing message thread is referenced");
	free(h.lastmsgid);

	init_host(&h);
	make_mailer(42);
	page_someone(&h, SYSM_CONTACT_DOWN, 456);
	pending(&h, "nonzero sendmail exit leaves state unchanged");
	free(h.lastmsgid);

	init_host(&h);
	memcpy(saved, test_mailer, sizeof(saved));
	test_mailer[0] = '\0';
	page_someone(&h, SYSM_CONTACT_DOWN, 456);
	pending(&h, "no configured mailer leaves notification pending");
	memcpy(test_mailer, saved, sizeof(saved));
	free(h.lastmsgid);

	init_host(&h);
	unlink(test_mailer);
	page_someone(&h, SYSM_CONTACT_DOWN, 456);
	pending(&h, "exec failure leaves notification pending");
	free(h.lastmsgid);

	init_host(&h);
	make_mailer(0);
	fail_fork = 1;
	page_someone(&h, SYSM_CONTACT_DOWN, 456);
	pending(&h, "sendmail fork failure leaves notification pending");
	free(h.lastmsgid);

	init_host(&h);
	fail_stream = 1;
	page_someone(&h, SYSM_CONTACT_DOWN, 456);
	pending(&h, "fdopen failure closes pipe and reaps mailer");
	free(h.lastmsgid);

	init_host(&h);
	bad_stream = 1;
	page_someone(&h, SYSM_CONTACT_DOWN, 456);
	pending(&h, "stream error cannot be accepted even if sendmail exits zero");
	free(h.lastmsgid);

	init_host(&h);
	sender = NULL;
	fail_identity = 1;
	page_someone(&h, SYSM_CONTACT_DOWN, 456);
	pending(&h, "identity lookup failure leaves notification pending");
	free(h.lastmsgid);

	init_host(&h);
	subject = NULL;
	page_someone(&h, SYSM_CONTACT_DOWN, 456);
	check(h.contacted, "nosubject handoff succeeds");
	file_contains("body", "\n\nfirst\n.\nlast\n", "nosubject still separates headers and body");
	free(h.lastmsgid);

	init_host(&h);
	donotify = FALSE;
	page_someone(&h, SYSM_CONTACT_DOWN, 456);
	pending(&h, "disabled notifications do not mark a delivery");
	free(h.lastmsgid);
}

static void collect_worker(int expected)
{
	int status = 0;
	pid_t got;
	do { got = waitpid(last_child, &status, 0); } while (got < 0 && errno == EINTR);
	check(got == last_child && WIFEXITED(status) && WEXITSTATUS(status) == expected,
	    "notification worker terminates with its own status");
}

static void command_mail(void)
{
	struct hostinfo h;
	char saved[PATH_MAX], marker[PATH_MAX + 32];
	init_host(&h);
	h.command = (unsigned char *)"echo command-body";
	fail_fork = 1;
	page_someone(&h, SYSM_CONTACT_DOWN, 456);
	pending(&h, "failed worker fork is not a handoff");
	free(h.lastmsgid);

	init_host(&h);
	h.command = (unsigned char *)"echo command-body";
	fail_popen = 1;
	page_someone(&h, SYSM_CONTACT_DOWN, 456);
	check(h.contacted, "async contract records a launched worker, not eventual command success");
	collect_worker(1);
	free(h.lastmsgid);

	init_host(&h);
	h.command = (unsigned char *)"echo command-body";
	sender = NULL;
	fail_identity = 1;
	page_someone(&h, SYSM_CONTACT_DOWN, 456);
	collect_worker(1); /* The old code returned into a duplicate daemon. */
	free(h.lastmsgid);

	init_host(&h);
	h.command = (unsigned char *)"echo command-body";
	page_someone(&h, SYSM_CONTACT_DOWN, 456);
	collect_worker(0);
	file_contains("body", "Subject: test subject\n\ncommand-body\n",
	    "command output is the mail body, not additional headers");
	free(h.lastmsgid);

	init_host(&h);
	memcpy(saved, test_mailer, sizeof(saved));
	test_mailer[0] = '\0';
	h.command = (unsigned char *)"echo ran > \"$PAGE_TEST_DIR/ran\"";
	page_someone(&h, SYSM_CONTACT_DOWN, 456);
	collect_worker(1); /* Optional mail failed, but the command MUST run. */
	file_contains("ran", "ran", "missing sendmail does not prevent primary command action");
	memcpy(test_mailer, saved, sizeof(saved));
	free(h.lastmsgid);

	init_host(&h);
	h.contact = NULL;
	h.command = (unsigned char *)"exit 0";
	sender = NULL;
	fail_identity = 1;
	page_someone(&h, SYSM_CONTACT_DOWN, 456);
	collect_worker(0);
	free(h.lastmsgid);
	snprintf(marker, sizeof(marker), "%s/ran", directory);
	unlink(marker);
}

int main(void)
{
	char tmp[] = "/tmp/sysmon-page-XXXXXX", path[PATH_MAX + 32];
	const char *leaves[] = {"args", "body"};
	size_t i;
	if (mkdtemp(tmp) == NULL) return 1;
	snprintf(directory, sizeof(directory), "%s", tmp);
	snprintf(test_mailer, sizeof(test_mailer), "%s/mailer with spaces", tmp);
	setenv("PAGE_TEST_DIR", tmp, 1);
	do_syslog = FALSE;
	signal(SIGPIPE, SIG_IGN);
	alarm(30); /* A test failure must not leave CI blocked on a child. */
	direct_mail();
	command_mail();
	unlink(test_mailer);
	for (i = 0; i < sizeof(leaves) / sizeof(leaves[0]); i++) {
		snprintf(path, sizeof(path), "%s/%s", tmp, leaves[i]);
		unlink(path);
	}
	rmdir(tmp);
	if (failures != 0) return 1;
	puts("page: all checks passed");
	return 0;
}
