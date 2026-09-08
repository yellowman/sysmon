/* $Id: page.c,v 1.59 2006/09/22 19:43:45 jared Exp $ */
#include "config.h"

/* Honor configure's sendmail path; an empty path means no mailer. */
#ifndef MAIL
#define MAIL ""
#endif

/*
 *
 */
char *translate_string(char *str, struct hostinfo *svc, char *myhostname)
{
	int x;
        time_t t; /* used to get the time */
	/* Increase buffer size to reduce overflow risk */
	char out[LARGE_TEMPBUF_SIZE];
	char tmp[TEMPBUF_SIZE];
	float value;
	float tmp1;
	float tmp2;
	struct my_hostent *hp;
	/* Track current string length to prevent overflow */
	size_t current_len = 0;

	/* Safe append macro - only appends if there's room */
	#define SAFE_APPEND(str_to_append) do { \
		const char *_s = (str_to_append); \
		if (_s) { \
			size_t _len = strlen(_s); \
			if (current_len + _len < sizeof(out)) { \
				strncat(out, _s, sizeof(out) - current_len - 1); \
				current_len += _len; \
			} \
		} \
	} while(0)

	if (str == NULL)
	{
		return NULL;
	}
	time(&t);

	memset(out, 0, sizeof(out));	/* zero it out */

        /* parse str as follows:             */
        /* %m = My host Name                 */
	/* %H = dns name of %h               */
        /* %s = Service                      */
	/* %p = port number (numeric)	     */
	/* %T = Current Time hh:mm:ss        */
        /* %t = Current Time mmm dd hh:mm:ss */
        /* %d = downtime dd:hh:mm            */
        /* %D = downtime dd:hh:mm:ss         */
	/* %G = group name                   */
        /* %i = unique id for outage         */
	/* %I = IP of host down              */
        /* %w = warning/what                 */
        /* %u = translates error type 
		to string describing it      */
        /* %h = hostname with failure        */
	/* %r = reliability %                */
	/* %V = Verbose History              */
	/* %c = Downtime Count		     */
	/* %C = Uptime Count		     */
	/* %l = Last recovery time dd:hh:mm  */
	/* %U = Service state (up or down)   */
        /*                                   */

	hp = my_gethostbyname(svc->hostname, -1);

        /* convert to page */
        for (x=0; x < strlen(str);x++)
        {
		/* Handle C style newline and CR for sending to
			e-mail */
		if (str[x] == '\\')
		{
			x++;
			switch(str[x])
			{
				case 'n':
					SAFE_APPEND("\n");
					break;
				case 'r':
					SAFE_APPEND("\r");
					break;
			}
			continue;
		} else if (str[x] == '%')
                {
                        x++;
                        switch (str[x])
                        {
                                case 'm':
                                        SAFE_APPEND(myhostname);
                                        break;
				case 'H':
					SAFE_APPEND(hp != NULL ? get_hostname(hp) : (char *)svc->hostname);
					break;
                                case 'd': /* downtime */
                                        SAFE_APPEND(str_difftime(svc->deathtime,t));
                                        break;
                                case 'l': /* uptime */
                                        SAFE_APPEND(str_difftime(svc->last_up,t));
                                        break;
                                case 'D': /* downtime 2 */
                                        SAFE_APPEND(str_difftime_sec(svc->deathtime, t));
                                        break;
				case 'G':
					snprintf(tmp, sizeof(tmp), "%s%s", out, svc->group);
					/* BUG FIX: Use sizeof(tmp) not sizeof(out) to avoid reading beyond tmp buffer */
					memcpy(out,tmp,sizeof(tmp)); current_len = strlen(out);
					break;
                                case 'i':
                                        snprintf(tmp, sizeof(tmp), "%s%ld%p", out,
						svc->deathtime, svc);
					/* BUG FIX: Use sizeof(tmp) not sizeof(out) to avoid reading beyond tmp buffer */
					memcpy(out,tmp,sizeof(tmp)); current_len = strlen(out);
                                        break;
				case 'I':
					snprintf(tmp, sizeof(tmp), "%s%s", out,
						hp != NULL ? get_ip(hp) : (char *)svc->hostname);
					/* BUG FIX: Use sizeof(tmp) not sizeof(out) to avoid reading beyond tmp buffer */
					memcpy(out,tmp,sizeof(tmp)); current_len = strlen(out);
					break;
				case 'c':
					snprintf(tmp, sizeof(tmp), "%s %ld", out,
						svc->downct);
					/* BUG FIX: Use sizeof(tmp) not sizeof(out) to avoid reading beyond tmp buffer */
					memcpy(out,tmp,sizeof(tmp)); current_len = strlen(out);
					break;
				case 'C':
					snprintf(tmp, sizeof(tmp), "%s %ld", out,
						svc->upct);
					/* BUG FIX: Use sizeof(tmp) not sizeof(out) to avoid reading beyond tmp buffer */
					memcpy(out,tmp,sizeof(tmp)); current_len = strlen(out);
					break;
				case 'p':
					snprintf(tmp, sizeof(tmp), "%s %d", out,
						svc->port);
					/* BUG FIX: Use sizeof(tmp) not sizeof(out) to avoid reading beyond tmp buffer */
					memcpy(out,tmp,sizeof(tmp)); current_len = strlen(out);
					break;
				case 'r':
			                tmp1 = svc->totaldown;
			                tmp2 = svc->totalchecked;
			                /* BUG FIX: Check for divide-by-zero BEFORE division */
			                if (tmp2==0) {
			                	value=100.00;
			                } else {
			                	value = (100.0000-((tmp1/tmp2) * 100));
			                	if (value<0) value=0.000;
			                }
					snprintf(tmp, sizeof(tmp), "%s %10.6f%%", out,
						value);
					/* BUG FIX: Use sizeof(tmp) not sizeof(out) to avoid reading beyond tmp buffer */
					memcpy(out,tmp,sizeof(tmp)); current_len = strlen(out);
					break;
                                case 's':
                                        SAFE_APPEND( type_to_name(svc->type));
                                        break;
				case 'T':
					{
						char time_str[16];
						strftime(time_str, sizeof(time_str), "%H:%M:%S", localtime(&t));
						SAFE_APPEND(time_str);
					}
					break;
                                case 't':
					{
						char date_str[32];
						strftime(date_str, sizeof(date_str), "%b %d %H:%M:%S", localtime(&t));
						SAFE_APPEND(date_str);
					}
                                        /* time */
                                        break;
                                case 'U':
					SAFE_APPEND( svc->lastcheck ?
					  "down" : "up");
					break;
                                case 'u':
                                        SAFE_APPEND( errtostr(svc->lastcheck));
                                        break;
                                case 'w':
                                        SAFE_APPEND( svc->message);
                                        break;
				case 'V':
					/* add to out the following:

						% reliability
						last outage time (prior to this)
						times checked, times failed
					*/
					break;
                                case 'h':
                                        SAFE_APPEND( svc->hostname);
                                        break;
                        }
                } else {
			if (current_len + 1 < sizeof(out)) {
				strncat(out, str+x, 1);
				current_len++;
			}
		}
        }

	return strdup(out);
}

/*
 *
 */
void gen_msgid(char *our_msgid)
{
	gen_rand_ascii(our_msgid, 26);
}

/* Mail goes to one executable, not a shell command. A sender containing
 * whitespace or shell metacharacters is one -f argument, and a configured
 * executable path containing spaces is still the path configure found. */
struct mail_pipe {
	FILE *stream;
	pid_t pid;
};

static int wait_child(pid_t pid)
{
	int status;
	pid_t got;
	do {
		got = waitpid(pid, &status, 0);
	} while (got < 0 && errno == EINTR);
	if (got != pid || !WIFEXITED(status) || WEXITSTATUS(status) != 0)
		return FALSE;
	return TRUE;
}

static int open_mail(struct mail_pipe *mail)
{
	int fds[2], error;
	pid_t child;

	mail->stream = NULL;
	mail->pid = -1;
	if (MAIL[0] == '\0') {
		errno = ENOENT;
		return FALSE;
	}
	if (pipe(fds) < 0) return FALSE;
	child = fork();
	if (child < 0) {
		error = errno;
		close(fds[0]);
		close(fds[1]);
		errno = error;
		return FALSE;
	}
	if (child == 0) {
		char *args[7];
		int n = 0;
		close(fds[1]);
		if (fds[0] != STDIN_FILENO) {
			if (dup2(fds[0], STDIN_FILENO) < 0) _exit(127);
			close(fds[0]);
		}
		args[n++] = (char *)MAIL;
		args[n++] = "-oi"; /* A line containing '.' is message data. */
		args[n++] = "-t";
		if (sender != NULL && *sender != '\0') {
			args[n++] = "-f";
			args[n++] = sender;
		}
		args[n] = NULL;
		execv(MAIL, args);
		_exit(127);
	}
	close(fds[0]);
	mail->stream = fdopen(fds[1], "w");
	if (mail->stream == NULL) {
		error = errno;
		close(fds[1]);
		(void)wait_child(child);
		errno = error;
		return FALSE;
	}
	mail->pid = child;
	return TRUE;
}

static int close_mail(struct mail_pipe *mail)
{
	int failed = ferror(mail->stream);
	int accepted;
	if (fflush(mail->stream) != 0) failed = TRUE;
	if (fclose(mail->stream) != 0) failed = TRUE;
	mail->stream = NULL;
	accepted = wait_child(mail->pid);
	return !failed && accepted;
}

static void mail_headers(FILE *mail, struct hostinfo *svc, struct passwd *pw)
{
	if (sender != NULL)
		fprintf(mail, "From: %s\n", sender);
	else
		fprintf(mail, "From: System Monitor <%s@localhost>\n", pw->pw_name);
	fprintf(mail, "X-SysMon-Unique-ID: %s\n", svc->unique_id != NULL ? (char *)svc->unique_id : "");
	fprintf(mail, "X-SysMon-Host: %s\n", svc->hostname);
	fprintf(mail, "X-SysMon-Uptime: %lu\n", svc->system_uptime);
	if (svc->hdr != NULL)
		fprintf(mail, "%s: %s\n", svc->hdr, svc->hdrval != NULL ? (char *)svc->hdrval : "");
	fprintf(mail, "To: %s\n", svc->contact);
	if (errorsto != NULL) fprintf(mail, "Errors-To: %s\n", errorsto);
	if (replyto != NULL) fprintf(mail, "Reply-To: %s\n", replyto);
}

/* A command notification is asynchronous. TRUE means the worker was
 * launched, NOT that the command or its optional mail eventually succeeded.
 * Eventual completion cannot update the parent's hostinfo without a separate
 * IPC/reaping design; do not pretend a fork made that guarantee. */
static bool run_command_and_mail_output(struct hostinfo *svc, char *myhostname)
{
	struct mail_pipe mail;
	FILE *cmd;
	struct passwd *pw;
	char *runme, *subjectline;
	char buff[512];
	pid_t child;
	int status, failed, have_mail;

	runme = translate_string((char *)svc->command, svc, myhostname);
	if (runme == NULL) return FALSE;
	child = fork();
	if (child != 0) {
		free(runme);
		if (child < 0) perror("page: fork notification worker");
		return child > 0;
	}
	/* Every child path terminates here, never in the daemon event loop. */
	if (svc->contact == NULL || *svc->contact == '\0') {
		status = system(runme);
		free(runme);
		if (status != 0) print_err(1, "page: notification command failed");
		_exit(status == 0 ? 0 : 1);
	}
	cmd = popen(runme, "r");
	free(runme);
	if (cmd == NULL) {
		perror("page: open notification command");
		_exit(1);
	}
	pw = sender == NULL ? getpwuid(getuid()) : NULL;
	subjectline = subject != NULL ? translate_string(subject, svc, myhostname) : NULL;
	have_mail = (sender != NULL || pw != NULL) &&
	    (subject == NULL || subjectline != NULL) && open_mail(&mail);
	if (have_mail) {
		mail_headers(mail.stream, svc, pw);
		if (subjectline != NULL) fprintf(mail.stream, "Subject: %s\n", subjectline);
		fputc('\n', mail.stream); /* Required even when a Subject was written. */
	} else
		print_err(1, "page: cannot mail command output; running command without mail");
	free(subjectline);
	/* Drain even if mailing failed: the command may itself be the pager
	 * action, and a missing sendmail must not prevent that action running. */
	while (fgets(buff, sizeof(buff), cmd) != NULL)
		if (have_mail) fputs(buff, mail.stream);
	failed = ferror(cmd);
	status = pclose(cmd);
	if (have_mail && !close_mail(&mail)) failed = TRUE;
	if (!have_mail || failed || status != 0) {
		print_err(1, "page: notification command/mail worker failed");
		_exit(1);
	}
	_exit(0);
}

void page_someone(struct hostinfo *svc, int newstate, time_t now_t)
{
	struct mail_pipe mail;
	struct passwd *pw;
	char myhostname[80] = "localhost", msgid[256];
	char *out, *subjectline, *nextmsgid;

	if (svc == NULL) return;
	if (gethostname(myhostname, sizeof(myhostname)) < 0)
		snprintf(myhostname, sizeof(myhostname), "localhost");
	myhostname[sizeof(myhostname) - 1] = '\0';
	out = translate_string(svc->pmesg != NULL ? (char *)svc->pmesg :
	    (pmesg != NULL ? pmesg : PMESG), svc, myhostname);
	if (out == NULL) return;
	syslogmsg(out, now_t);
	if (!donotify || !(svc->contact_when & newstate)) {
		free(out);
		return;
	}
	if (svc->command != NULL) {
		if (run_command_and_mail_output(svc, myhostname)) {
			svc->lastcontacted = now_t;
			svc->contacted = TRUE;
			object_changed(svc);
		}
		free(out);
		return;
	}
	if (svc->contact == NULL || *svc->contact == '\0') {
		/* No external recipient: record the locally handled event. */
		svc->lastcontacted = now_t;
		svc->contacted = TRUE;
		object_changed(svc);
		free(out);
		return;
	}
	pw = sender == NULL ? getpwuid(getuid()) : NULL;
	if (sender == NULL && pw == NULL) {
		print_err(1, "page: cannot look up local mail identity; notification remains pending");
		free(out);
		return;
	}
	subjectline = subject != NULL ? translate_string(subject, svc, myhostname) : NULL;
	gen_msgid(msgid);
	nextmsgid = strdup(msgid);
	if ((subject != NULL && subjectline == NULL) || nextmsgid == NULL) {
		free(out);
		free(subjectline);
		free(nextmsgid);
		return;
	}
	if (!open_mail(&mail)) {
		print_err(1, "page: cannot open configured sendmail; notification remains pending");
		free(out);
		free(subjectline);
		free(nextmsgid);
		return;
	}
	mail_headers(mail.stream, svc, pw);
	fprintf(mail.stream, "Message-Id: <%s@sysmon>\n", msgid);
	if (svc->lastmsgid != NULL)
		fprintf(mail.stream, "In-Reply-To: <%s@sysmon>\n", svc->lastmsgid);
	if (subjectline != NULL) fprintf(mail.stream, "Subject: %s\n", subjectline);
	fprintf(mail.stream, "\n%s\n", out);
	free(subjectline);
	free(out);
	if (!close_mail(&mail)) {
		print_err(1, "page: sendmail failed for %s; notification remains pending", svc->hostname);
		free(nextmsgid);
		return;
	}
	/* Successful local handoff, not proof of delivery to the recipient. */
	if (svc->lastmsgid != NULL) FREE(svc->lastmsgid);
	svc->lastmsgid = (unsigned char *)nextmsgid;
	svc->lastcontacted = now_t;
	svc->contacted = TRUE;
	object_changed(svc);
}
