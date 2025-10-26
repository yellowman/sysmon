/* $Id: page.c,v 1.59 2006/09/22 19:43:45 jared Exp $ */
#include "config.h"

/* Override empty MAIL definition from configure when sendmail not found */
#ifdef MAIL
#undef MAIL
#endif
#define MAIL "/usr/sbin/sendmail"

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
	if (hp == NULL)
	{
		snprintf(out, sizeof(out), "translate_string() error with %s", svc->hostname);
		return strdup(out);
	}

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
					SAFE_APPEND(get_hostname(hp));
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
						get_ip(hp));
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
			                value = (100.0000-((tmp1/tmp2) * 100));
			                if (value<0) value=0.000;
			                if (tmp2==0) value=100.00;
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

/*
 *
 */
void run_command_and_mail_output(struct hostinfo *svc, char *myhostname)
{
	FILE *mail;
	FILE *cmd;
        struct passwd *pw; /* password structure */
	char *runme;
	uid_t myuid;
	char mailcmd[512];
	char buff[200];

	memset(buff, 0, 200);
	memset(mailcmd, 0, 512);

	if (fork() != 0)
	{
		return;
	}

	myuid = getuid();
	errno = 0;
	pw = getpwuid(myuid);

	if (pw == NULL)
	{
		perror("page.c:run_command_and_mail_output:getpwuid");
		return;
	}

	runme = translate_string(svc->command, svc, myhostname);
	snprintf(mailcmd, 510, "%s -t", MAIL);

	if ((svc->contact == NULL) || (strlen(svc->contact) == 0))
	{
		system(runme);
		free(runme);
		exit(0);
	}

	if (debug)
	{
		print_err(0, "popening \"%s\"", runme);
	}

	errno = 0;
	cmd = popen(runme, "r");
	if (cmd == NULL)
	{
		perror("page.c:run_command_and_mail_output:popen cmd");
	}
	errno = 0;
	mail = popen(mailcmd, "w");
	if (mail == NULL)
	{
		perror("page.c:run_command_and_mail_output:popen mail");
        }

	/* The message */
	if (sender == NULL)
	{
		fprintf(mail, "From: System Monitor <%s@localhost>\n", 
			pw->pw_name);
	} else {
		fprintf(mail, "From: %s\n", sender);
	}
	fprintf(mail, "X-Sysmon-unique-id: %s\n", svc->unique_id);
	if (svc->hdr != NULL)
	{
		if (svc->hdrval != NULL)
			fprintf(mail, "%s: %s\n", svc->hdr, svc->hdrval);
		else
			fprintf(mail, "%s:\n", svc->hdr);
	}
	fprintf(mail, "To: %s\n", svc->contact);
	/* Insert Errors-To: headder if necessary */
	if (errorsto != NULL)
		fprintf(mail, "Errors-To: %s\n", errorsto);
	if (replyto != NULL)
		fprintf(mail, "Reply-To: %s\n", replyto);
	/* Insert Subject line */
	if (subject != NULL)
	{
		fprintf(mail, "Subject: %s is %s\n", svc->hostname, 
			errtostr(svc->lastcheck));
	} else {
		fprintf(mail, "\n");
	}

	/* Body of message */
	while (fgets(buff, 190, cmd) != NULL)
	{
		fprintf(mail, "%s", buff);
	}

	pclose(cmd);
	pclose(mail);
	free(runme);
	exit(0);
}

/* Tell someone that the host is down */
void page_someone(struct hostinfo *svc, int newstate, time_t now_t)
{
        FILE *fp; /* file handle used with popen */
	char command[512]; /* command for popen */
        struct passwd *pw; /* password structure */
        char *out;
	uid_t myuid;
	char myhostname[80]; /* my hostname */
	char msgid[256]; /* Our message-id */
	char *subjectline;

	/* bug check */
	if (svc == NULL)
		return;

	/* Getuid can never fail per man page */
	myuid = getuid();

	if (gethostname(myhostname, 80) == -1)
	{
		perror("page.c:page_someone:gethostname");
		print_err(0, "page.c:page_someone:gethostname - unable to get our host name");
	}

	/* If no locally configured pmesg */
	if (svc->pmesg == NULL)
	{
		/* If no global default configured pmesg */
		if (pmesg == NULL)
		{
			/* Use config.h default */
			out = translate_string(PMESG, svc, myhostname);
		} else {
			/* use configured pmesg */
			out = translate_string(pmesg, svc, myhostname);
		}
	} else {
		/* use object specific pmesg */
		out = translate_string(svc->pmesg, svc, myhostname);
	}

        syslogmsg(out, now_t);

	snprintf(command, sizeof(command),
	  "contact when %d/%d", svc->contact_when, newstate);

	if (debug)
		print_err(0, "%s\n", command);

	if (svc->command != NULL && donotify &&
	  (svc->contact_when & newstate))
	{
		if (debug)
		{
			print_err(0, "We need to execute %s", 
				translate_string(svc->command, svc, myhostname));
		}

		run_command_and_mail_output(svc, myhostname);
		time(&svc->lastcontacted);
		svc->contacted = TRUE;
		free(out);
		return;
	}

	if (svc->contact == NULL || strlen (svc->contact) == 0)
	{
		if (debug) print_err(1,"page.c:page_someone:nobody to contact");
		svc->contacted = TRUE;
		free(out);
		return;
	}

        if (donotify && (svc->contact_when & newstate))
        {
		errno = 0;
                pw = getpwuid(myuid);
		if (pw == NULL)
		{
			perror("page.c:page_someone:getpwuid");
			return;
		}

		/* set the time */
		time(&svc->lastcontacted);
                /* Set contacted */
                svc->contacted = TRUE;


		/* setup the command to call (sendmail) */
		snprintf(command, 500, "%s -t", MAIL);
		if (sender != NULL)
		{
			snprintf(command, 500, "%s -f%s -t", MAIL, sender);
		}

		errno = 0;
		/* open a connection to sendmail */
                fp = popen(command, "w");

		if (fp == NULL)
		{
			perror("page.c:page_someone:popen fp");
			free(out);
			return;
		}

		if (sender == NULL)
		{
			fprintf(fp, "From: System Monitor <%s@localhost>\n", 
				pw->pw_name);
		} else {
			fprintf(fp, "From: %s\n", sender);
		}
		fprintf (fp, "X-SysMon-Unique-ID: %s\n", svc->unique_id);
		fprintf (fp, "X-SysMon-Host: %s\n", svc->hostname);
		fprintf (fp, "X-SysMon-Uptime: %ld\n", svc->system_uptime);
	        if (svc->hdr != NULL)
	        {
			if (svc->hdrval != NULL)
				fprintf(fp, "%s: %s\n", svc->hdr, svc->hdrval);
			else
				fprintf(fp, "%s:\n", svc->hdr);
	        }

                fprintf(fp, "To: %s\n", svc->contact);
		/* Insert Errors-To: headder if necessary */
		if (errorsto != NULL)
		{
			fprintf(fp, "Errors-To: %s\n", errorsto);
		}
		if (replyto != NULL)
		{
			fprintf(fp, "Reply-To: %s\n", replyto);
		}

	/* Generate our own message-id for use in headders
	 * such that threading mail clients can be used easier
	 */
		gen_msgid(msgid);

		fprintf(fp, "Message-Id: <%s@%s>\n", msgid, "sysmon");
		if (svc->lastmsgid != NULL)
		{
			fprintf(fp, "In-Reply-To: <%s@%s>\n", svc->lastmsgid,
				"sysmon");
			FREE(svc->lastmsgid);
		}
		svc->lastmsgid = strdup(msgid);

		subjectline = translate_string(subject, svc, myhostname);
		/* Insert Subject line */
		if (subject != NULL)
		{
			fprintf(fp, "Subject: %s\n", subjectline);
		} else {
			fprintf(fp, "\n");
		}

		if (subjectline != NULL)
		{
			free (subjectline);
		}

		/* Body of message */
                fprintf(fp, "%s\n.\n", out);

		/* Close the PIPE */
                pclose(fp);

        }
	free(out);

	return;
}

