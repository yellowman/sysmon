/* $Id: lib.c,v 1.61 2006/10/06 20:54:13 jared Exp $ */

#include "config.h"

extern int facility;
extern bool mallocdebug;
#ifndef HAVE_SNPRINTF
int
snprintf(char *str, size_t size, const char *format, ...);
#endif

/*
 * use the start and end time to determine if the function ran
 * longer than secs.  if it did, log a message, and return that it did
 */
int check_runtime(struct timeval start, struct timeval end, char *functname, int secs)
{
	float diff = mydifftime(start, end);

        if (diff > (secs+0.1))
        {
                print_err(0,"check_runtime:%s ran for %10.6f seconds!", 
			functname, diff);
		return 1;
        }
	return 0;
}

/*
 * return a random char that isalnum() for use
 */
char randchar()
{
        int x;

        x = rand() % 124;

        while (1)
        {
                if (isalnum(x))
                {
                        return x;
                }
                x = x + (rand() % 124);
                x = x % 124;
        }
}

/*
 * generate a random string of characters to the specified
 * length for use.  string buffer is already allocated to
 * size
 */
void
gen_rand_ascii(char *string, int len)
{
	int x;

	for (x = 0;len > x ;x++)
	{
		string[x] = randchar();
	}
	string[x] = '\0';
}



/* 
 * difftime 
 *
 * Find the time difference between the first time and the second
 * time such that it can be compared directly against a float or an
 * integer 
 */

float	mydifftime(struct timeval first, struct timeval second)
{
	float mine = 0;
	float sec, usec;
	
	sec = (second.tv_sec - first.tv_sec);
	usec = (second.tv_usec - first.tv_usec);
	if (usec < 0)
	{
		sec--;
		usec = usec+ 1000000;
	}
	
	mine = sec + (usec * 0.000001);
	return mine;
}

/*
 *
 */
char	*str_difftime_sec(time_t timedown, time_t now)
{
        static char buff[15];

	int ss = 0, mm = 0, hh = 0, dd = 0;

        if (timedown == 0)
	{
		strncpy(buff, "Never", 14);
		return buff;
	}

        dd = ((now-timedown) / 86400) % 86400;
        hh = ((now-timedown- (dd*86400)) / 3600) % 3600;
        mm = ((now-timedown-(dd*86400+hh*3600)) / 60) % 60;
	ss = ((now-timedown) %60);

        snprintf(buff, 15, "%-2.2dd%-2.2dh%-2.2dm%-2.2ds", dd,hh,mm,ss);

        return buff;
}

/*
 *
 */
char	*str_difftime(time_t timedown, time_t now)
{
        static char buff[10];
        int mm = 0, hh = 0, dd = 0;

	if (timedown == 0)
	{
		return "Never";
	}

        dd = ((now-timedown) / 86400) % 86400;
        hh = ((now-timedown- (dd*86400)) / 3600) % 3600;
        mm = ((now-timedown-(dd*86400+hh*3600)) / 60) % 60;

        snprintf(buff, 10, "%-2.2d:%-2.2d:%-2.2d", dd,hh,mm);

        return buff;
}

/* 
 * convert internal error number to a string 
 */
char	*errtostr( int value )
{
	switch(value)
	{
		/* Don't need breaks here because we're returning -msa */
		case SYSM_CONNREF:
			return "Conn Ref";
		case SYSM_NETUNRCH:
			return "Net Unrch";
		case SYSM_HOSTDOWN:
			return "Host Down";
		case SYSM_TIMEDOUT:
			return "Conn Timed Out";
		case SYSM_NODNS:
			return "No DNS Entry";
		case SYSM_UNPINGABLE:
			return "Unpingable";
		case SYSM_THROTTLED:
			return "Thrttl";
		case SYSM_NOAUTH:
			return "No Auth";
		case SYSM_NORESP:
			return "No Srvr Resp";
		case SYSM_INPROG:
			return "Conn in prog";
		case SYSM_BAD_AUTH:
			return "Bad Auth";
		case SYSM_BAD_RESP:
			return "Bad Resp";
		case X500_WEDGED:
			return "Wedged";
		case SYSM_KILLED:
			return "Internal-Killed"; /* Internal use only */
		case SYSM_OK:
			return "up";
		case SYSM_RTT_HIGH:
			return "RTT too high";
		case SYSM_SNMP_REBOOT:
			return "hostRebooted";
		case SYSM_SNMP_HIGH:
			return "HIGH";
		case SYSM_SNMP_LOW:
			return "LOW";
		case SYSM_SNMP_OOR:
			return "Out Of Range";
		case SYSM_SNMP_NOTEXACT:
			return "Not Exact";
			/* Unexpected? */
			/* invalid? */
		case SYSM_SNMP_HIGHRATE:
			return "High Rate";
		case SYSM_PKTLOSS_EXCEED:
			return "Pkt Loss High";
		default:
			return "ERROR";
	}
}

/*
 *
 */
int errno_to_error(int err)
{
	switch(err)
	{
		case ECONNREFUSED:
                case EINTR:
                	return SYSM_CONNREF;
		case ENETUNREACH:
			return SYSM_NETUNRCH;
		case EHOSTDOWN:
		case EHOSTUNREACH:
			return SYSM_HOSTDOWN;
		case ETIMEDOUT:
			return SYSM_TIMEDOUT;
		case EALREADY:
		case EINPROGRESS:
			return SYSM_INPROG;
		default: return -1;
	}
}

/*
 * We want to catch interesting things, and abort, and possibly write
 * some sort of a log saying that we died.
 */
void ABORT()
{
	char my_dir[PATH_MAX];
	signal(SIGABRT, SIG_DFL);
	getcwd(my_dir, PATH_MAX);
	print_err(1, "about to abort and dump core (i think in %s)", my_dir);
	abort();
}

/*
 * my malloc -- if we have memory leaks, we can turn it on
 */
void	*MALLOC(size_t size, char *description)
{
	void *retval = malloc(size);
	
	memset(retval, 0x00, size);
	if (mallocdebug)
	{
		print_err(0, "DMEM-Allocated %d at %p for \"%s\"", size, retval, description);
	}
	return retval;
}

/*
 * my strdup -- if we have memory leaks, we can turn it on
 */
void	*STRDUP(char * content, char *description)
{
	void *retval = strdup (content);
	
	if (mallocdebug)
	{
		print_err(0, "DMEM-Copying %d at %p for \"%s\"",
		  strlen (content), retval, description);
	}
	return retval;
}

/*
 * my free -- Free memory, logging it if debug is on
 */
void	FREE(void *freeme)
{
	if (freeme == NULL)
	{
		print_err(1, "lib.c:FREE:Bug: Attempting to free NULL?!?");
		ABORT();
		return;
	}
	if (mallocdebug == TRUE)
	{
                print_err(0, "DMEM-Freeing at %p", freeme);
	}
	free(freeme);
}
		
/*
 * return yes if true, no if false
 */
char	*yes_no(int value)
{
        if (value == 1)
                return "Yes";
        return "No";
}

#ifdef OLD_SOURCE
/*
 * free parsed structure
 */
void free_parsed(struct parsed *this)
{
        int x;

	if (this == NULL)
		return;
        for (x = 0; x < this->count;x++)
                FREE(this->data[x]);
        FREE(this->data);
	this->count = 0;
	this = NULL;

	return;
}
#endif /* OLD_SOURCE */


/* 
 * Count the number of occourances of the char "val" in
 * "string"
 */
int str_cnt(const char *string, const char val)
{
	int count = 0;
	int idx;
	for (idx=0;strlen(string)>=idx ;idx++)
		if (string[idx] == val)
			count++;
	return count;
}

#ifdef OLD_SOURCE
/*
 * parse the string str, and return it in the parsed structure
 * for use -- we need to free_parsed() after we are done with it
 * otherwise we will leak memory
 */
int parse (char *str, struct parsed *parsed)
{
        int points[MAX_ARGS][2];
        int pts = 0;
        int x=0;
        int start=0;
        int end= 0;
        char qt = '\0';
        parsed->count = 0;

        for (x=0;x < strlen(str);x++)
        {
                /* skip whitespace at beginning */
                if (isspace(str[x]) && pts == 0)
                        continue;
                if (str[x] == '"' || str[x] == '\'')
                {
                        qt = str[x];
                        if (debug)
			{
                                print_err(0, "lib.c:parse:quote found @ %d", x);
			}
                        start = x+1;
                        x++;
                        end = 0;
                        for (;x < strlen(str);x++)
                        {
                                if (str[x] == qt)
                                {
                                        end = x;
                                        break;
                                }
                        }
                        if (end == 0)
			{
                                print_err(0, "lib.c:parse:error in string!");
				return -1;
			}
                        if (debug)
                                print_err(0,"end found @ %d", x);
                        points[pts][0] = start;
                        points[pts][1] = (end-start);
			if (debug)
	                        print_err(0, "lib.c:parse:done parsing quoted part");
                        pts++;
                        continue;
                } else if (!isspace(str[x]))
                {
                        start = x;
                        for (;x<strlen(str);x++)
                        {
                                if (isspace(str[x]))
                                {
                                        break;
                                }
                        }
                        end = x;
                        points[pts][0] = start;
                        points[pts][1] = (end-start);
                        pts++;
                        continue;
                }
        }
        if (debug)
                print_err(0, "lib.c:pts = %d", pts);
        parsed->count = pts;
        parsed->data = MALLOC(sizeof(char *) * pts, "parsed->data");
        for (x =0;x < pts; x++)
        {
                if (debug)
                        print_err(0, "lib.c:points[%d][start] = %d  points[%d][end] = %d",
                                x,points[x][0],x, points[x][1]);
                parsed->data[x] = MALLOC(points[x][1]+1, "parsed->data[]");
                strncpy(parsed->data[x], str+points[x][0], points[x][1]);
                if (debug)
                        print_err(0, "lib.c:parsed->data[%d] = %s", x, parsed->data[x]);
        }
	return 0;
}
#endif /* OLD_SOURCE */


char *snmp_type_to_name(int snmp_type)
{
	switch (snmp_type)
	{
		case 1: 
			return "reboot";
		case 2:
			return "high";
		case 3:
			return "low";
		case 4:
			return "range";
		case 5:
			return "exact";
		case 6:
			return "compare";
		case 7:
			return "rate";
		default:
			return "snmp_type_to_name(ERROR)";
	}
	return "snmp_type_to_name(ERROR2)";
}
/*
 * high low exact reboot range
 */
short int name_to_snmp_type(char *sent_type)
{
	short int len;
	char type[256];
	char *i_ret;
	
	i_ret = (char *)index(sent_type, ':');
	if (i_ret != NULL)
	{
		if (debug)
		print_err(0, "i_ret = %p, sent_type = %p, diff = %d\n",
			i_ret, sent_type, (i_ret - sent_type));
		memset(type, 0, 256);
		strncpy(type, sent_type, (i_ret - sent_type));
	} else {
		strncpy(type, sent_type, 250);
	}

	len = strlen(type);

	switch (len) {
		case 3:
                        if (strcmp(type, "low") == 0)
                                return SYSM_SNMP_TYPE_LOW;
			break;
		case 4:
			if (strcmp(type, "high") == 0)
				return SYSM_SNMP_TYPE_HIGH;
			if (strcmp(type, "rate") == 0)
				return SYSM_SNMP_TYPE_RATE;
			break;
		case 5:
			if (strcmp(type, "exact") == 0)
				return SYSM_SNMP_TYPE_EXACT;
			if (strcmp(type, "range") == 0)
				return SYSM_SNMP_TYPE_RANGE;
			break;
		case 6:
			if (strcmp(type, "reboot") == 0)
				return SYSM_SNMP_TYPE_REBOOT;
			break;
		case 7:	
			if (strcmp(type, "compare") == 0)
				return SYSM_SNMP_TYPE_COMPARE;
			break;
		default:
			break;
	}
		
	return -1;
}

/* 
 * Used by loadconfig.c to change types in config file to internal numbers 
 */
short int name_to_type(char *sent_type)
{
	short int len;
	char type[256];
	char *i_ret;
	
	i_ret = (char *)index(sent_type, ':');
	if (i_ret != NULL)
	{
		if (debug)
		print_err(0, "i_ret = %p, sent_type = %p, diff = %d\n",
			i_ret, sent_type, (i_ret - sent_type));
		memset(type, 0, 256);
		strncpy(type, sent_type, (i_ret - sent_type));
	} else {
		strncpy(type, sent_type, 250);
	}

	len = strlen(type);

	switch (len) {
		case 3:
			if (strcmp(type, "tcp") == 0)
				return SYSM_TYPE_TCP;
			if (strcmp(type, "udp") == 0)
				return SYSM_TYPE_UDP;
                        if (strcmp(type, "dns") == 0)
                                return SYSM_TYPE_DNS;
                        if (strcmp(type, "www") == 0)
                                return SYSM_TYPE_WWW;
                        if (strcmp(type, "ssh") == 0)
                                return SYSM_TYPE_SSHD;
			break;
		case 4:
			if (strcmp(type, "imap") == 0)
				return SYSM_TYPE_IMAP;
			if (strcmp(type, "http") == 0)
				return SYSM_TYPE_WWW;
			if ((strcmp(type, "ping") == 0 || strcmp(type, "pingv4") == 0) && (!disable_icmp))
				return SYSM_TYPE_PING;
                        if (strcmp(type, "ping6") == 0 && (!disable_icmp))
                                return SYSM_TYPE_PINGv6;
                        if (strcmp(type, "icmp6") == 0 && (!disable_icmp))
                                return SYSM_TYPE_PINGv6;
			if (strcmp(type, "rtt") == 0 && (!disable_icmp))
				return SYSM_TYPE_PING_LATENCY;
#ifdef ENABLE_SNMP
			if (strcmp(type, "snmp") == 0)
				return SYSM_TYPE_SNMP;
#endif /* ENABLE_SNMP */
			if (strcmp(type, "nntp") == 0)
				return SYSM_TYPE_NNTP;
                        if (strcmp(type, "pop2") == 0)
                                return SYSM_TYPE_POP2;
			if (strcmp(type, "smtp") == 0)
				return SYSM_TYPE_SMTP;
			if (strcmp(type, "pop3") == 0)
				return SYSM_TYPE_POP3;
			if (strcmp(type, "ircd") == 0)
				return SYSM_TYPE_IRCD;
			break;
		case 5:
                        if (strcmp(type, "bootp") == 0)
                                return SYSM_TYPE_BOOTP;
			break;
                        if (strcmp(type, "https") == 0)
                                return SYSM_TYPE_HTTPS;
		case 6:
                        if (strcmp(type, "radius") == 0)
                                return SYSM_TYPE_RADIUS;
                        if (strcmp(type, "sysmon") == 0)
                                return SYSM_TYPE_SYSM;
			if (strcmp(type, "pingv6") == 0 && (!disable_icmp))
				return SYSM_TYPE_PINGv6;
			break;
		case 9:
			if (strcmp(type, "umichx500") == 0)
				return SYSM_TYPE_X500;
			break;
	}

	return -1;
}


char *type_to_name(int type)
{
	switch(type)
	{
		case SYSM_TYPE_TCP:
			return "tcp";
		case SYSM_TYPE_UDP:
			return "udp";
		case SYSM_TYPE_PING:
			return "ping";
		case SYSM_TYPE_SNMP:
			return "snmp";
		case SYSM_TYPE_NNTP:
			return "nntp";
		case SYSM_TYPE_SMTP:
			return "smtp";
		case SYSM_TYPE_IMAP:
			return "imap";
		case SYSM_TYPE_POP3:
			return "pop3";
		case SYSM_TYPE_X500:
			return "x500";
		case SYSM_TYPE_POP2:
			return "pop2";
		case SYSM_TYPE_BOOTP:
			return "bootp";
		case SYSM_TYPE_DNS:
			return "dns";
		case SYSM_TYPE_WWW:
			return "www";
		case SYSM_TYPE_RADIUS:
			return "radius";
		case SYSM_TYPE_HTTPS:
			return "https";
		case SYSM_TYPE_SYSM:
			return "sysmon";
		case SYSM_TYPE_SSHD:
			return "ssh";
		case SYSM_TYPE_IRCD:
			return "ircd";
		case SYSM_TYPE_PINGv6:
			return "pingv6";
		case SYSM_TYPE_PKTLOSS:
			return "pktloss";
		default:
			return "ERROR";
	}
}

char	*timedata(time_t t)
{
        char *nfo = MALLOC(30, "timedata");

	if (nfo == NULL)
	{
		print_err(1, "lib.c:timedata - nfo malloced = NULL");
		return NULL;
	}
	
	if (t == 0)
	{
		strncpy(nfo, "Never", 29);
		return nfo;
	}

        strncpy(nfo,ctime(&t)+4, 29); /* convert it to a string, copy to buffer */
        nfo[strlen(nfo) -5] = '\0';

        return nfo;
}

int	nextfd()
{
	int fd;
	
	fd = open("/dev/zero", O_RDONLY);
	if (fd == -1)
		return -1;
	if (close(fd) == -1)
		return -1;
	return fd;
}

void print_err (int output, const char *fmt, ...)
{
	static pid_t myPid = 0;
	time_t now;
	char buffer[256], secs[40];
	va_list ap;

	if (myPid == 0)
		myPid = getpid ();

	va_start (ap, fmt);
	vsprintf (buffer, fmt, ap);
	va_end (ap);
        time (&now);
	syslogmsg(buffer, now);
	if (debug || output) {
		strftime (secs, sizeof (secs), "%X", localtime (&now));
		fprintf(stderr, "sysmond: %s %s\n", secs, buffer);
	}
}

void	syslogmsg(char *message, time_t now)
{
	FILE *fh;
	struct tm *tm_val;
	char buff[256];

	if (!do_syslog)
		return;
	if (message == NULL)
	{
		syslogmsg("ATTEMPTED TO SYSLOG A NULL MESSAGE", now);
		return;
	}

	if (facility == -2) /* no logging requested by user */
	{
		return;
	}
	if (facility == -3)
	{
		fh = fopen(log_file, "a+");
		if (fh != NULL)
		{
			tm_val = localtime(&now);
			strftime(buff, 250, "%b %d %Y-%T", tm_val);
			fprintf(fh, "%s : %s\n", buff, message);
			fclose(fh);
		}
	} else {
        	openlog(myname, LOG_NDELAY, facility);
	        syslog(3, message, strlen(message));
		closelog();
	}
}

#ifndef HAVE_GETHOSTBYNAME2
/*
* gethostbyname2() -- an RFC2133-compatible get-host-by-name-two function
* to get AF_INET and AF_INET6 addresses from host names,
* using the RFC2553-compatible getipnodebyname() function
*/

extern struct hostent *
gethostbyname2(nm, prot)
const char *nm; /* host name */
int prot; /* protocol -- AF_INET or AF_INET6 */
{
int err;
static struct hostent *hep = (struct hostent *)NULL;

if (hep)
(void) freehostent(hep);
return((hep = getipnodebyname(nm, prot, 0, &err)));
}
#endif /* ! HAVE_GETHOSTBYNAME2 */

#ifndef HAVE_SNPRINTF

#define MINUS_FLAG 0x1
#define PLUS_FLAG 0x2
#define SPACE_FLAG 0x4
#define HASH_FLAG 0x8
#define CONV_TO_SHORT 0x10
#define IS_LONG_INT 0x20
#define IS_LONG_DOUBLE 0x40
#define X_UPCASE 0x80
#define IS_NEGATIVE 0x100
#define UNSIGNED_DEC 0x200
#define ZERO_PADDING 0x400

/* Extract a formatting directive from str. Str must point to a '%'. 
   Returns number of characters used or zero if extraction failed. */

int
snprintf_get_directive(const char *str, int *flags, int *width,
                       int *precision, char *format_char, va_list *ap)
{
  int length, value;
  const char *orig_str = str;

  *flags = 0; 
  *width = 0;
  *precision = 0;
  *format_char = (char)0;

  if (*str == '%')
    {
      /* Get the flags */
      str++;
      while (*str == '-' || *str == '+' || *str == ' ' 
             || *str == '#' || *str == '0')
        {
          switch (*str)
            {
            case '-':
              *flags |= MINUS_FLAG;
              break;
            case '+':
              *flags |= PLUS_FLAG;
              break;
            case ' ':
              *flags |= SPACE_FLAG;
              break;
            case '#':
              *flags |= HASH_FLAG;
              break;
            case '0':
              *flags |= ZERO_PADDING;
              break;
            }
          str++;
        }

      /* Don't pad left-justified numbers withs zeros */
      if ((*flags & MINUS_FLAG) && (*flags & ZERO_PADDING))
        *flags &= ~ZERO_PADDING;
        
      /* Is width field present? */
      if (isdigit(*str))
        {
          for (value = 0; *str && isdigit(*str); str++)
            value = 10 * value + *str - '0';
          *width = value;
        }
      else
        if (*str == '*')
          {
            *width = va_arg(*ap, int);
            str++;
          }

      /* Is the precision field present? */
      if (*str == '.')
        {
          str++;
          if (isdigit(*str))
            {
              for (value = 0; *str && isdigit(*str); str++)
                value = 10 * value + *str - '0';
              *precision = value;
            }
          else
            if (*str == '*')
              {
                *precision = va_arg(*ap, int);
                str++;
              }
            else
              *precision = 0;
        }

      /* Get the optional type character */
      if (*str == 'h')
        {
          *flags |= CONV_TO_SHORT;
          str++;
        }
      else
        {
          if (*str == 'l')
            {
              *flags |= IS_LONG_INT;
              str++;
            }
          else
            {
              if (*str == 'L')
                {
                  *flags |= IS_LONG_DOUBLE;
                  str++;
                }
            }
        }

      /* Get and check the formatting character */

      *format_char = *str;
      str++;
      length = str - orig_str;

      switch (*format_char)
        {
        case 'i': case 'd': case 'o': case 'u': case 'x': case 'X': 
        case 'f': case 'e': case 'E': case 'g': case 'G': 
        case 'c': case 's': case 'p': case 'n':
          if (*format_char == 'X')
            *flags |= X_UPCASE;
          if (*format_char == 'o')
            *flags |= UNSIGNED_DEC;
          return length;

        default:
          return 0;
        }
    }
  else
    {
      return 0;
    }
}

/* Convert a integer from unsigned long int representation 
   to string representation. This will insert prefixes if needed 
   (leading zero for octal and 0x or 0X for hexadecimal) and
   will write at most buf_size characters to buffer.
   tmp_buf is used because we want to get correctly truncated
   results.
   */

int
snprintf_convert_ulong(char *buffer, size_t buf_size, int base, char *digits,
                       unsigned long int ulong_val, int flags, int width,
                       int precision)
{
  int tmp_buf_len = 100 + width, len;
  char *tmp_buf, *tmp_buf_ptr, prefix[2];
  tmp_buf = MALLOC(tmp_buf_len, "snprintf_convert_ulong");

  prefix[0] = '\0';
  prefix[1] = '\0';
  
  /* Make tmp_buf_ptr point just past the last char of buffer */
  tmp_buf_ptr = tmp_buf + tmp_buf_len;

  /* Main conversion loop */
  do 
    {
      *--tmp_buf_ptr = digits[ulong_val % base];
      ulong_val /= base;
      precision--;
    } 
  while ((ulong_val != 0 || precision > 0) && tmp_buf_ptr > tmp_buf);
 
  /* Get the prefix */
  if (!(flags & IS_NEGATIVE))
    {
      if (base == 16 && (flags & HASH_FLAG))
      {
          if (flags & X_UPCASE)
            {
              prefix[0] = 'x';
              prefix[1] = '0';
            }
          else
            {
              prefix[0] = 'X';
              prefix[1] = '0';
            }
      }
      
      if (base == 8 && (flags & HASH_FLAG))
          prefix[0] = '0';
      
      if (base == 10 && !(flags & UNSIGNED_DEC) && (flags & PLUS_FLAG))
          prefix[0] = '+';
      else
        if (base == 10 && !(flags & UNSIGNED_DEC) && (flags & SPACE_FLAG))
          prefix[0] = ' ';
    }
  else
      prefix[0] = '-';

  if (prefix[0] != '\0' && tmp_buf_ptr > tmp_buf)
    {
      *--tmp_buf_ptr = prefix[0];
      if (prefix[1] != '\0' && tmp_buf_ptr > tmp_buf)
        *--tmp_buf_ptr = prefix[1];
    }
  
  len = (tmp_buf + tmp_buf_len) - tmp_buf_ptr;

  if (len <= buf_size)
    {
      if (len < width)
        {
          if (width > (tmp_buf_ptr - tmp_buf))
            width = (tmp_buf_ptr - tmp_buf);
          if (flags & MINUS_FLAG)
            {
              memcpy(buffer, tmp_buf_ptr, len);
              memset(buffer + len, (flags & ZERO_PADDING)?'0':' ',
                     width - len);
              len = width;
            }
          else
            {
              memset(buffer, (flags & ZERO_PADDING)?'0':' ',
                     width - len);
              memcpy(buffer + width - len, tmp_buf_ptr, len);
              len = width;
            }
        }
      else
        {
          memcpy(buffer, tmp_buf_ptr, len);
        }
      FREE(tmp_buf);
      return len;
    }
  else
    {
      memcpy(buffer, tmp_buf_ptr, buf_size);
      FREE(tmp_buf);
      return buf_size;
    }
}

#ifndef KERNEL

int
snprintf_convert_float(char *buffer, size_t buf_size,
                       double dbl_val, int flags, int width,
                       int precision, char format_char)
{
  char print_buf[160], print_buf_len = 0;
  char format_str[80], *format_str_ptr;
  size_t remaining_format_size;

  format_str_ptr = format_str;

  if (width > 155) width = 155;
  if (precision <= 0)
    precision = 6;
  if (precision > 120)
    precision = 120;

  /* Construct the formatting string and let system's sprintf
     do the real work. */
  
  *format_str_ptr++ = '%';

  if (flags & MINUS_FLAG)
    *format_str_ptr++ = '-';
  if (flags & PLUS_FLAG)
    *format_str_ptr++ = '+';
  if (flags & SPACE_FLAG)
    *format_str_ptr++ = ' ';
  if (flags & ZERO_PADDING)
    *format_str_ptr++ = '0';
  if (flags & HASH_FLAG)
    *format_str_ptr++ = '#';

  remaining_format_size = sizeof(format_str) - (format_str_ptr - format_str);
  snprintf(format_str_ptr, remaining_format_size, "%d.%d", width, precision);
  format_str_ptr += strlen(format_str_ptr);

  if (flags & IS_LONG_DOUBLE)
    *format_str_ptr++ = 'L';
  *format_str_ptr++ = format_char;
  *format_str_ptr++ = '\0';

  snprintf(print_buf, sizeof(print_buf), format_str, dbl_val);
  print_buf_len = strlen(print_buf);

  if (print_buf_len > buf_size)
    print_buf_len = buf_size;
  strncpy(buffer, print_buf, print_buf_len);
  return print_buf_len;
}

#endif /* KERNEL */

int
vsnprintf(char *str, size_t size, const char *format, va_list ap);

int
snprintf(char *str, size_t size, const char *format, ...)
{
  int ret;
  va_list ap;
  va_start(ap, format);
  ret = vsnprintf(str, size, format, ap);
  va_end(ap);

  return ret;
}

int
vsnprintf(char *str, size_t size, const char *format, va_list ap)
{
  int status, left = (int)size - 1;
  const char *format_ptr = format;
  int flags, width, precision, i;
  char format_char, *orig_str = str;
  int *int_ptr;
  long int long_val;
  unsigned long int ulong_val;
  char *str_val;
#ifndef KERNEL
  double dbl_val;
#endif /* KERNEL */

  flags = 0;
  while (format_ptr < format + strlen(format))
    {
      if (*format_ptr == '%')
        {
          if (format_ptr[1] == '%' && left > 0)
            {
              *str++ = '%';
              left--;
              format_ptr += 2;
            }
          else
            {
              if (left <= 0)
                {
                  *str = '\0';
                  return size;
                }
              else
                {
                  status = snprintf_get_directive(format_ptr, &flags, &width,
                                                  &precision, &format_char, 
                                                  &ap);
                  if (status == 0)
                    {
                      *str = '\0';
                      return 0;
                    }
                  else
                    {
                      format_ptr += status;
                      /* Print a formatted argument */
                      switch (format_char)
                        {
                        case 'i': case 'd':
                          /* Convert to unsigned long int before
                             actual conversion to string */
                          if (flags & IS_LONG_INT)
                            long_val = va_arg(ap, long int);
                          else
                            long_val = (long int) va_arg(ap, int);
                          
                          if (long_val < 0)
                            {
                              ulong_val = (unsigned long int) -long_val;
                              flags |= IS_NEGATIVE;
                            }
                          else
                            {
                              ulong_val = (unsigned long int) long_val;
                            }
                          status = snprintf_convert_ulong(str, left, 10,
                                                          "0123456789",
                                                          ulong_val, flags,
                                                          width, precision);
                          str += status;
                          left -= status;
                          break;

                        case 'x':
                          if (flags & IS_LONG_INT)
                            ulong_val = va_arg(ap, unsigned long int);
                          else
                            ulong_val = 
                              (unsigned long int) va_arg(ap, unsigned int);

                          status = snprintf_convert_ulong(str, left, 16,
                                                          "0123456789abcdef",
                                                          ulong_val, flags,
                                                          width, precision);
                          str += status;
                          left -= status;
                          break;

                        case 'X':
                          if (flags & IS_LONG_INT)
                            ulong_val = va_arg(ap, unsigned long int);
                          else
                            ulong_val = 
                              (unsigned long int) va_arg(ap, unsigned int);

                          status = snprintf_convert_ulong(str, left, 16,
                                                          "0123456789ABCDEF",
                                                          ulong_val, flags,
                                                          width, precision);
                          str += status;
                          left -= status;
                          break;

                        case 'o':
                          if (flags & IS_LONG_INT)
                            ulong_val = va_arg(ap, unsigned long int);
                          else
                            ulong_val = 
                              (unsigned long int) va_arg(ap, unsigned int);

                          status = snprintf_convert_ulong(str, left, 8,
                                                          "01234567",
                                                          ulong_val, flags,
                                                          width, precision);
                          str += status;
                          left -= status;
                          break;

                        case 'u':
                          if (flags & IS_LONG_INT)
                            ulong_val = va_arg(ap, unsigned long int);
                          else
                            ulong_val = 
                              (unsigned long int) va_arg(ap, unsigned int);

                          status = snprintf_convert_ulong(str, left, 10,
                                                          "0123456789",
                                                          ulong_val, flags,
                                                          width, precision);
                          str += status;
                          left -= status;
                          break;

                        case 'p':
                          break;
                          
                        case 'c':
                          if (flags & IS_LONG_INT)
                            ulong_val = va_arg(ap, unsigned long int);
                          else
                            ulong_val = 
                              (unsigned long int) va_arg(ap, unsigned int);
                          *str++ = (unsigned char)ulong_val;
                          left--;
                          break;

                        case 's':
                          str_val = va_arg(ap, char *);

                          if (str_val == NULL)
                            str_val = "(null)";
                          
                          if (precision == 0)
                            precision = strlen(str_val);
                          else
                            {
                              if (memchr(str_val, 0, precision) != NULL)
                                precision = strlen(str_val);
                            }
                          if (precision > left)
                            precision = left;

                          if (width > left)
                            width = left;
                          if (width < precision)
                            width = precision;
                          i = width - precision;

                          if (flags & MINUS_FLAG)
                            {
                              strncpy(str, str_val, precision);
                              memset(str + precision,
                                     (flags & ZERO_PADDING)?'0':' ', i);
                            }
                          else
                            {
                              memset(str, (flags & ZERO_PADDING)?'0':' ', i);
                              strncpy(str + i, str_val, precision);
                            }
                          str += width;
                          left -= width;
                          break;

                        case 'n':
                          int_ptr = va_arg(ap, int *);
                          *int_ptr = str - orig_str;
                          break;

#ifndef KERNEL
                        case 'f': case 'e': case 'E': case 'g': case 'G':
                          if (flags & IS_LONG_DOUBLE)
                            dbl_val = (double) va_arg(ap, long double);
                          else
                            dbl_val = va_arg(ap, double);
                          status =
                            snprintf_convert_float(str, left, dbl_val, flags,
                                                   width, precision,
                                                   format_char);
                          str += status;
                          left -= status;
                          break;
#endif /* KERNEL */
                          
                        default:
                          break;
                        }
                    }
                }
            }
        }
      else
        {
          if (left > 0)
            {
              *str++ = *format_ptr++;
              left--;
            }
          else
            {
              *str = '\0';
              return size;
            }
        }
    }
  *str = '\0';
  return (size - left - 1);
}

#endif /* HAVE_SNPRINTF */


/*
   qsort.c

   J. L. Bentley and M. D. McIlroy. Engineering a sort function.
   Software---Practice and Experience, 23(11):1249-1265.
*/
typedef long WORD;
#define W sizeof(WORD)   /* must be a power of 2 */
#define SWAPINIT(a, es) swaptype =                \
   (a-(char*)0 | es) % W ? 2 : es > W ? 1 : 0

#define exch(a, b, t) (t = a, a = b, b = t);
#define swap(a, b)                                \
   swaptype != 0 ? swapfunc(a, b, es, swaptype) : \
   (void)exch(*(WORD*)(a), *(WORD*)(b), t)

#define vecswap(a, b, n) if (n > 0) swapfunc(a, b, n, swaptype)

#include <stddef.h>
static void swapfunc(char *a, char *b, size_t n, int swaptype)
{
   if (swaptype <= 1) {
      WORD t;
      for( ; n > 0; a += W, b += W, n -= W)
         exch(*(WORD*)a, *(WORD*)b, t);
   } else {
      char t;
      for( ; n > 0; a += 1, b += 1, n -= 1)
         exch(*a, *b, t);
   }
}

#define PVINIT(pv, pm)                          \
   if (swaptype != 0) { pv = a; swap(pv, pm); } \
   else { pv = (char*)&v; v = *(WORD*)pm; }

#define min(a, b) ((a) < (b) ? (a) : (b))

static char *med3(char *a, char *b, char *c, int (*cmp) ())
{   return cmp(a, b) < 0 ?
       (cmp(b, c) < 0 ? b : cmp(a, c) < 0 ? c : a)
     : (cmp(b, c) > 0 ? b : cmp(a, c) > 0 ? c : a);
}

void quicksort(char *a, size_t n, size_t es, int (*cmp) ())
{
   char *pa, *pb, *pc, *pd, *pl, *pm, *pn, *pv;
   int r, swaptype;
   WORD t, v;
   size_t s;

   SWAPINIT(a, es);
   if (n < 7) {       /* Insertion sort on smallest arrays */
      for (pm = a + es; pm < a + n*es; pm += es)
         for (pl = pm; pl > a && cmp(pl-es, pl) > 0; pl -= es)
            swap(pl, pl-es);
      return;
   }
   pm = a + (n/2)*es;      /* Small arrays, middle element */
   if (n > 7) {
      pl = a;
      pn = a + (n-1)*es;
      if (n > 40) {       /* Big arrays, pseudomedian of 9 */
         s = (n/8)*es;
         pl = med3(pl, pl+s, pl+2*s, cmp);
         pm = med3(pm-s, pm, pm+s, cmp);
         pn = med3(pn-2*s, pn-s, pn, cmp);
      }
      pm = med3(pl, pm, pn, cmp);    /* Mid-size, med of 3 */
   }
   PVINIT(pv, pm);         /* pv points to partition value */
   pa = pb = a;
   pc = pd = a + (n-1)*es;
   for (;;) {
      while (pb <= pc && (r = cmp(pb, pv)) <= 0) {
         if (r == 0) { swap(pa, pb); pa += es; }
         pb += es;
      }
      while (pc >= pb && (r = cmp(pc, pv)) >= 0) {
         if (r == 0) { swap(pc, pd); pd -= es; }
         pc -= es;
      }
      if (pb > pc) break;
      swap(pb, pc);
      pb += es;
      pc -= es;
   }
   pn = a + n*es;
   s = min(pa-a,  pb-pa   ); vecswap(a,  pb-s, s);
   s = min(pd-pc, pn-pd-es); vecswap(pb, pn-s, s);
   if ((s = pb-pa) > es) quicksort(a,    s/es, es, cmp);
   if ((s = pd-pc) > es) quicksort(pn-s, s/es, es, cmp);
}
