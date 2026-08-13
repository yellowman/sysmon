/* $Id: textfile.c,v 1.29 2011/09/08 18:26:08 jared Exp $ */

#include "config.h"

/*
 * Copy a file when rename() fails (e.g. cross-device)
 * Returns 0 on success, -1 on failure
 */
static int
copy_file(const char *src, const char *dst)
{
	FILE *in, *out;
	char buf[4096];
	size_t n;

	in = fopen(src, "r");
	if (in == NULL)
		return -1;

	out = fopen(dst, "w");
	if (out == NULL)
	{
		fclose(in);
		return -1;
	}

	while ((n = fread(buf, 1, sizeof(buf), in)) > 0)
	{
		if (fwrite(buf, 1, n, out) != n)
		{
			fclose(in);
			fclose(out);
			return -1;
		}
	}

	fclose(in);
	if (fclose(out) != 0)
		return -1;

	return 0;
}

/*
 * dump the currently broken network devices/services to the filename
 * specified
 *
 * overwrite it if it exists, do not follow symlinks
 * use the umask specified for file creation
 * html = 0 (text) html = 1 (dump in html format)
 *
 */
void
dump_to_file(char *filename, int html, time_t now)
{
	FILE *fh; /* filehandle for writing out status */

	char newfname[512], updated_at[128];
	char *basename_ptr;

        struct tm *ltm;

	/* Check filename parameter early to prevent null pointer dereference */
	if (filename == NULL)
	{
		print_err(1, "textfile.c:Error! dump_to_file called with filename == NULL\n");
		return;
	}

        ltm = localtime(&now);
        strftime(updated_at, 127,
	  parser_dateformat == NULL ? "%x %X" : parser_dateformat, ltm);
/*	snprintf(updated_at, 127,
                "%d/%d/%d @ %02d:%02d:%02d\n",
                ltm->tm_mon + 1,
                ltm->tm_mday,
                ltm->tm_year + 1900,
                ltm->tm_hour,
                ltm->tm_min,
                ltm->tm_sec); */


	/* Use statustempdir if configured, otherwise use same dir as final file */
	if (statustempdirname != NULL && statustempdirname[0] != '\0')
	{
		/* Extract basename from filename for temp file */
		basename_ptr = strrchr(filename, '/');
		if (basename_ptr != NULL)
			basename_ptr++;  /* Skip the '/' */
		else
			basename_ptr = filename;  /* No path component */

		/* Create temp file in configured temp directory */
		snprintf(newfname, 511, "%s/%s.%d", statustempdirname, basename_ptr, getpid());
	}
	else
	{
		/* Legacy behavior: create temp file in same directory as final file */
		snprintf(newfname, 511, "%s%d", filename, getpid());
	}

	/* Delete anything that might be in our way */
	if(unlink(newfname) == -1)
	{
		if (debug)
		{
			print_err(1, "textfile.c:dump_to_file:unlink newfilename");
		}
	}

	fh = fopen(newfname, "w");

	if (fh == NULL)
	{
		print_err(1, "dump_to_file:fopen(%s) failed: %s", newfname, strerror(errno));
		return;
	}

	if (html) /* html format */
	{
		fprintf(fh, "<HTML>\n<HEAD>\n");
		fprintf(fh, "<TITLE>sysmon %s Network Summary</TITLE>\n", SYSM_VERS);
                fprintf(fh, "<META HTTP-EQUIV=\"Refresh\" CONTENT=%d>\n",
			parser_html_refresh);
		fprintf(fh, "<META HTTP-EQUIV=\"Pragma\" CONTENT=\"no-cache\">\n");
		fprintf(fh, "<STYLE TYPE=\"text/css\" MEDIA=\"all\">\n");
		if (cssfilename) {
			fprintf(fh, "@import url(%s);\n", cssfilename);
		} else {
			fprintf(fh, "body {\n");
			fprintf(fh, "\tbackground-color: #ffffff;\n");
			fprintf(fh, "color: #000000;\n");
			fprintf(fh, "}\n");
			fprintf(fh, ".up {\n");
			fprintf(fh, "\tbackground-color: #%s;\n", upcolor);
			fprintf(fh, "\tcolor: #000000;\n");
			fprintf(fh, "}\n");
			fprintf(fh, ".down {\n");
			fprintf(fh, "\tbackground-color: #%s;\n", downcolor);
			fprintf(fh, "\tcolor: #000000;\n");
			fprintf(fh, "}\n");
			fprintf(fh, ".recent {\n");
			fprintf(fh, "\tbackground-color: #%s;\n", recentcolor);
			fprintf(fh, "\tcolor: #000000;\n");
			fprintf(fh, "}\n");
		}
		fprintf(fh, "</STYLE>\n");
		fprintf(fh, "</HEAD>\n");
		fprintf(fh, "<h2><a href=\"http://puck.nether.net/sysmon/\">sysmon</a> %s Network Summary</h2><p>\n", SYSM_VERS);
		if (paused)
		{
			fprintf(fh, "Monitoring disabled by user request<p>\n");
		}
		fprintf(fh, "\n<BODY BGCOLOR=\"#ffffff\">\n");
		fprintf(fh, "<TABLE BORDER=\"1\">\n");
		fprintf(fh, "<TR>\n");
                fprintf(fh,
			"<TD COLSPAN=12>Last Updated:<TT>%s</TT></TD>\n",
			updated_at);
                fprintf(fh, "<TR>\n");
		fprintf(fh, "<TD>HostName</TD>\n");
		fprintf(fh, "<TD>Description</td>\n");
		fprintf(fh, "<TD>Type</TD>\n");
		fprintf(fh, "<TD>Port</TD>\n");
		fprintf(fh, "<TD>Down N</TD>\n");
		fprintf(fh, "<TD>Up N</TD>\n");
		fprintf(fh, "<TD>Notified</TD>\n");
		fprintf(fh, "<TD>Status</TD>\n");
		fprintf(fh, "<TD>Time Up</TD>\n");
		fprintf(fh, "<TD>Time Failed</TD>\n");
		fprintf(fh, "<TD>Last Outage</TD>\n");
		fprintf(fh, "<TD>Uptime</TD>\n");
		fprintf(fh, "</TR>\n");

	} else { /* non html */
		fprintf(fh,"Network Summary     sysmon %s\n", SYSM_VERS);
	        fprintf(fh,"%-25s%-6s%-5s%-6s%-6s%-6s%-15s%s\n",
			 "Hostname", "Type", "Port", "DownN", "UpN",
			"Notified", "Stat", "Time Failed");
	}

	/* Insure the visited flag is not set */
	clear_visited();

	/* print the hosts that are down and stuff */
	dump_to_file_walk_this_way(fh, configed_root, html, now);

	if (html) /* html end of stuff */
	{
		fprintf(fh, "</TABLE>\n");
		fprintf(fh, "\n</BODY>\n");
		fprintf(fh, "\n</HTML>\n");
	} else {  /* ascii trailer */
		/* not used */

	}

	fclose(fh); /* close the file handle -- don't leak it */

	chmod(newfname, 0644);

	if (rename(newfname, filename) != 0)
	{
		if (errno == EXDEV)
		{
			/*
			 * Cross-device rename (statustempdir is on another
			 * filesystem than the status file). Copy into a temp
			 * file *in the destination directory* and rename that
			 * onto the target - the second rename is same-filesystem
			 * so it's atomic, and readers never see a partially
			 * written status file.
			 */
			char desttmp[512];
			snprintf(desttmp, sizeof(desttmp), "%s.tmp", filename);

			if (copy_file(newfname, desttmp) == 0)
			{
				chmod(desttmp, 0644);
				if (rename(desttmp, filename) != 0)
				{
					print_err(1, "dump_to_file: rename %s to %s failed: %s",
						desttmp, filename, strerror(errno));
					unlink(desttmp);
				}
				unlink(newfname);
			}
			else
			{
				print_err(1, "dump_to_file: copy %s to %s failed", newfname, desttmp);
				unlink(desttmp);
				unlink(newfname);
			}
		}
		else
		{
			print_err(1, "dump_to_file: rename %s to %s failed: %s",
				newfname, filename, strerror(errno));
			unlink(newfname);
		}
	}

	return;
}

void	add_line(FILE *fh, struct hostinfo down, int html, time_t now)
{
        char *downdata = timedata(down.deathtime);
        char *updata = timedata(down.last_up);
        float value, tmp1, tmp2;
        char tmp[1024];
	int in_flaptime_window = 0;

	/* Check if we're within flaptime window after recovery.
	 * If flaptime is enabled and the host recovered recently,
	 * display it as green to prevent flapping appearance. */
	if (flaptime > 0 && down.last_recovery > 0)
	{
		time_t elapsed = now - down.last_recovery;
		if (elapsed < (flaptime * 60))
		{
			in_flaptime_window = 1;
		}
	}

	if (html == 1)
	{
		if (in_flaptime_window)
		{
			/* Within flaptime window - show as up (green) */
			fprintf(fh, "<TR class=\"up\">\n");
		}
		else if (down.lastcheck != SYSM_OK)
		{
			if (!down.contacted)
			{
			   fprintf(fh, "<TR class=\"recent\">\n");
			} else {
			   fprintf(fh, "<TR class=\"down\">\n");
			}
		} else {
			fprintf(fh, "<TR class=\"up\">\n");
		}
                tmp1 = down.totaldown;
                tmp2 = down.totalchecked;
		if (tmp2 != 0)
	                value = (100.0000-((tmp1/tmp2) * 100));
		else
			value = 100;
                if (value<0) value=0.000;
                snprintf(tmp, 1024, "%10.2f%%",value);

		fprintf(fh, 
"<TD>%s</TD><TD>%s</TD><TD>%s</TD><TD>%d</TD><TD>%ld</TD><TD>%ld</TD><TD>%s</TD><TD>%s</TD><TD>%s</TD><TD>%s</TD><TD>%s</TD><TD>%s</TD>\n", 
			down.hostname, down.message, type_to_name(down.type), 
			down.port, down.downct, down.upct,
			yes_no(down.contacted), errtostr(down.lastcheck),
			updata, downdata, str_difftime(down.last_up, now),tmp);
		fprintf(fh, "</TR>\n");
	} else { /* ascii */
		fprintf(fh,"%-25s%-6s%-5d%-5ld%-6ld%-6s%-15s%s\n",
		  down.hostname, type_to_name(down.type), down.port,
		  down.downct, down.upct, yes_no(down.contacted),
		  errtostr(down.lastcheck), 
		  downdata);
	}
	FREE(downdata);
	FREE(updata);
}

/* 
 * BUG: if parent is down, we display children
 */
void	dump_to_file_walk_this_way(FILE *fh, struct graph_elements *here, 
		int html, time_t now)
{
	int x;
	int added = 0;

	if (here == NULL)
		return;
	if (here->visit)
		return;
        if (here->data == NULL)
                return;
        /* Set the visited flag */
        here->visit = TRUE;

	/* Walk element list, display down hosts unless showupalso
	 * is set, then we show all hosts */
	/* BUG: Need ability to sort */

	/* Only display hosts that meet minnumfailures threshold.
	 * If minnumfailures is set, a host must have failed at least
	 * that many times before appearing in the output. This prevents
	 * transient failures from triggering alerts. */
        if ((here->data->lastcheck != 0 && here->data->downct >= minnumfailures) || showupalso)
        {
		add_line(fh, *(here->data), html, now);
		added = 1;
	} 
	/* if showupalso OR not added (ie: down) */
	if (showupalso || (!added)) 
	{
		for (x = 0; x < here->tot_nei; x++)
		{
			dump_to_file_walk_this_way(fh, here->neighbors[x], html, now);
		}
	}

}

