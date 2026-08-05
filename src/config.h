/* $Id: config.h,v 1.232 2014/07/09 16:32:35 jared Exp $ */

#include "defines.h"

/* change define -> undef if sysmond cores for you */
#define QSORT_WAY
#include <signal.h>
#include <stdio.h> 
#include <ctype.h>
#include <stdlib.h>
#include <time.h>  
#include <netdb.h>
#include <string.h>
#include <pwd.h>
#include <limits.h>
#if (defined(__svr4__) || defined(unixware))   /* slo-laris */
#include <sys/filio.h>
#endif
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/param.h>
#ifdef _AIX32
#include <fcntl.h>
#else /* _AIX32 */
#include <sys/fcntl.h>
#endif /* _AIX32 */
#include <errno.h>
#include <unistd.h>
#ifdef HAVE_PATHS_H
#include <paths.h>
#endif
#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>

#ifdef HAVE_NETINET_ICMP6_H
#define HAVE_IPv6
#include <netinet/icmp6.h>
#endif /* ENABLE_IPV6 */

#include <arpa/inet.h>
#include <syslog.h>
#include <stdarg.h>
#include <sys/utsname.h>
#include <sys/wait.h>
#include <strings.h>

#ifdef HAVE_LIBWRAP
#ifdef HAVE_TCPD_H
#include <tcpd.h>
#define ALLOWSEVERITY LOG_INFO;
#define DENYSEVERITY LOG_NOTICE;
#define DAEMONNAME "sysmond\0"
#endif /* HAVE_TCPD_H */
#endif /* HAVE_LIBWRAP */

#ifdef HAVE_LIBPTHREAD
#include <pthread.h>
#endif /* HAVE_LIBPTHREAD */

#ifdef HAVE_LIBNCURSES
#define NICEINTERFACE  /* define for ncurses interface in client */
#endif /* HAVE_LIBNCURSES */

#ifdef HAVE_LIBCURSES
#define NICEINTERFACE  /* define for ncurses interface in client */
#endif /* HAVE_LIBNCURSES */

#ifdef NICEINTERFACE
#ifdef sgi
#include "/usr/local/include/ncurses.h"
#else
#include <curses.h>
#endif /* sgi */
#endif /* NICEINTERFACE */

/* SNMP is built in - sysmond speaks it itself, so there is nothing to
   detect and no way to end up without it. */
#define ENABLE_SNMP


#define SYSM_VERS	"v0.94"
#ifdef _PATH_VARRUN
#define PIDFILE		_PATH_VARRUN "sysmond.pid"
#else
#define PIDFILE		"/etc/sysmond.pid"
#endif
#define PMESG		"%H (%I) %w is %u %d\0"
#define SUBJECT		"%h is %u\0"
#define UPCOLOR		"77ff77" /* green  */
#define RECENTCOLOR	"ffff00" /* yellow */
#define DOWNCOLOR	"ff5500" /* sumthin */

#define SYSMON_PORTNUM		1345
/* Where sysmon-web listens for daemons dialling in. */
#define SYSMON_AGG_PORTNUM	1347
#define	MAX_ARGS		100
#define MAX_STRLEN		32768

/* Buffer size constants for security */
#define IP_ADDR_STR_SIZE	20	/* Enough for "xxx.xxx.xxx.xxx\0" (16 chars + margin) */
#define TEMPBUF_SIZE		1024	/* Standard temporary buffer */
#define LARGE_TEMPBUF_SIZE	4096	/* Large temporary buffer */
#define SERVER_NAME_SIZE	1024	/* Server hostname buffer */
#define TIME_STR_SIZE		32	/* Time string buffer */
#define NETWORK_LINE_SIZE	256	/* Network line read buffer (getline_tcp) */
#define OBJECT_NAME_SIZE	128	/* Object/hostname identifier buffer */
#define PROTO_RESPONSE_SIZE	255	/* Protocol response buffer (pop3, smtp, etc) */

/* the following should be read from /etc/services */

/* SSH Remote Login Protocol */
#define SSH_PORTNUM 22

/* Per rfc */
#define SMTP_PORTNUM 25

/* per assigned ports */
#define SNMP_PORTNUM 161
#define SNMP_TRAP_PORTNUM 162
#define SNMP_SYSTEM_SYSUPTIME ".1.3.6.1.2.1.1.3.0"

/* per rfc */
#define HTTP_PORTNUM 80

/* per rfc */
#define IMAP_PORTNUM 143

/* per rfc */
#define NNTP_PORTNUM 119

/* per rfc? */
#define POP2_PORTNUM 109

/* per rfc? */
#define POP3_PORTNUM 110

/* */
#define DNS_PORTNUM 53

/* Radius */
#define RADIUS_PORTNUM 1645

/* SSL Http */
#define HTTPS_PORTNUM 443

/* Bootp */
#define BOOTP_CLIENT 68
#define BOOTP_SERVER 67

#ifdef    HAVE_IPv6
#ifndef   ICMPV6_ECHO_REQUEST
#define   ICMPV6_ECHO_REQUEST             128
#endif /* ICMPV6_ECHO_REQUEST */
#ifndef   ICMPV6_ECHO_REPLY
#define   ICMPV6_ECHO_REPLY               129
#endif /* ICMPV6_ECHO_REPLY */
#endif /* HAVE_IPv6 */

#ifndef bool
#define bool char
#endif

#ifndef MAX
#define MAX(a,b) (((a)>(b))?(a):(b))
#endif /* MAX */

#define ICMP_PACKET_SIZE 	64	/* packet size */
#define ICMP_HOLD_PACKETS	1500	/* number of packets in the air */
#define ICMP_HOLD_LEN		5	/* 5 seconds worth of packets */
#define ICMP_HOLD_QUEUE (ICMP_PACKET_SIZE*ICMP_HOLD_PACKETS*ICMP_HOLD_LEN)

#define ICMP_PHDR_LEN   sizeof(struct timeval)


#ifndef FALSE
#define FALSE 0
#endif
#ifndef TRUE
#define TRUE 1
#endif

/* Check Types */
#define SYSM_TYPE_TCP	1 /* TCP Checks */
#define	SYSM_TYPE_UDP	2 /* UDP Checks */
#define SYSM_TYPE_PING	3 /* Ping */
#define	SYSM_TYPE_SNMP	4 /* Snmp based checks */
#define	SYSM_TYPE_NNTP	5 /* nntp checks */
#define SYSM_TYPE_SMTP	6 /* smtp checks */
#define SYSM_TYPE_IMAP	7 /* imap check */
#define	SYSM_TYPE_POP3	8 /* pop3 check */
#define SYSM_TYPE_X500	9 /* umichX500 check */
#define SYSM_TYPE_POP2	10 /* pop2 check */
#define SYSM_TYPE_BOOTP	11 /* bootp check */
#define	SYSM_TYPE_DNS	12 /* check dns server */
#define SYSM_TYPE_WWW	13 /* www content check */
#define SYSM_TYPE_RADIUS 14 /* radius server check */
#define SYSM_TYPE_HTTPS	15 /* https content check */
#define SYSM_TYPE_SYSM	16 /* check another sysmond */
#define SYSM_TYPE_SSHD	17 /* sshd check */
#define SYSM_TYPE_IRCD	18 /* ircd check - connect, send quit */
#define SYSM_TYPE_PING_LATENCY 19 /* latency - stick timeval in packet */
#define SYSM_TYPE_PINGv6 20 /* IPv6 PING */
#define SYSM_TYPE_UDP_RTT 21 /* udp rtt packet timeval coolness */
#define SYSM_TYPE_PKTLOSS 22 /* packet loss monitoring with history */

/* Return Values */
#define SYSM_ERR	-2
#define SYSM_OK 	0
#define SYSM_CONNREF 	1
#define SYSM_NETUNRCH 	2
#define SYSM_HOSTDOWN	3
#define SYSM_TIMEDOUT 	4
#define SYSM_NODNS	5
#define SYSM_UNPINGABLE	6
#define SYSM_THROTTLED	7
#define SYSM_NOAUTH	8
#define SYSM_NORESP	9
#define SYSM_INPROG	10
#define SYSM_BAD_AUTH 	11
#define SYSM_BAD_RESP 	12
#define X500_WEDGED 	13
#define SYSM_PKTLOSS_EXCEED 23 /* packet loss exceeds tolerance */
#define SYSM_SNMP_TRAP  24 /* SNMP trap received */
#define SYSM_JITTER_HIGH 25 /* jitter exceeds threshold */
#define SYSM_KILLED	14 /* killed locally */
#define SYSM_HOSTUNRCH	15
#define SYSM_RTT_HIGH   16
#define SYSM_SNMP_REBOOT 17
#define SYSM_SNMP_HIGH	18
#define SYSM_SNMP_LOW	19
#define SYSM_SNMP_OOR	20
#define SYSM_SNMP_NOTEXACT 21
#define SYSM_SNMP_HIGHRATE 22

/* SNMP subTYPES */

#define SYSM_SNMP_TYPE_REBOOT   1 /* if system.sysUpTime.0 goes down */
#define SYSM_SNMP_TYPE_HIGH     2
#define SYSM_SNMP_TYPE_LOW      3 
#define SYSM_SNMP_TYPE_RANGE	4
#define SYSM_SNMP_TYPE_EXACT    5
#define SYSM_SNMP_TYPE_COMPARE	6 /* compare two oid values if eq */
#define SYSM_SNMP_TYPE_RATE	7 /* have a rate in val/sec, if avg
					exceeds, gen alert */

/* when to contact */
#define SYSM_CONTACT_DOWN	1
#define SYSM_CONTACT_UP		2

/* RTT probe pacing (type rtt): ms between the probes of one check.
   Configurable per object as "rtt_interval N;". The floor keeps the
   knob meaning something (back-to-back probes measure one instant and
   call it a trend); the ceiling bounds how long one check can hold a
   queue slot, since rtt_samples * rtt_interval is the check's wall
   time. */
#define RTT_DEFAULT_INTERVAL_MS	100
#define RTT_MIN_INTERVAL_MS	10
#define RTT_MAX_INTERVAL_MS	5000

/* Packet loss monitoring constants */
#define PKTLOSS_HISTORY_SIZE     1440  /* 24 hours @ 1 minute intervals */
#define PKTLOSS_DEFAULT_HISTORY  24    /* Default hours to keep */
#define PKTLOSS_MAX_HISTORY      168   /* Max 7 days (1 week) */

/* Forward declaration for pingdata (defined in icmp.c) */
struct pingdata;

/* Packet loss history sample */
struct pktloss_sample {
	time_t timestamp;           /* When this sample was taken */
	unsigned int sent;          /* Packets sent this cycle */
	unsigned int received;      /* Packets received this cycle */
	unsigned int lost;          /* Packets lost (sent - received) */
};

/* Packet loss tracking data (stored in monitorent->monitordata) */
struct pktloss_data {
	struct pktloss_sample history[PKTLOSS_HISTORY_SIZE];
	unsigned int history_head;      /* Circular buffer head index */
	unsigned int history_count;     /* Number of valid samples */
	unsigned long long total_sent;      /* Running total (64-bit for long runs) */
	unsigned long long total_received;  /* Running total */
	unsigned long long total_lost;      /* Running total */

	/* Reuse pingdata for actual ICMP operations */
	struct pingdata *ping;
};

struct hostinfo {
        unsigned char *hostname; /* name of system to check */
	unsigned char *ipv4_str; /* what hostname resolved to when this
		object was loaded, as dotted quad, or NULL if it has no v4
		address. The config says who to watch; this says where they
		were. Recorded because the name is already resolved once at
		load to decide whether the object is usable at all, and
		throwing that answer away means anything later that has an
		address in hand - an arriving snmp trap - has no way back to
		the object except by resolving the whole config again. */
        unsigned int type; /* 1 = tcp, 2 = udp, 3 = ping, 4 = snmp, 5 = nntp
		6 = smtp, 7 = imap, 8 = pop3 9 = umichX500 10 = pop2
		11 = bootp 12 = dns 13 = www-content, 14 = radius,
		15 = https, 16 = sysmon, 17 = ssh, 18=ircd,
		19= latency, 20 = ping6, 21 = rtt, 22 = pktloss */
        unsigned int port; /* only relevant for tcp/udp */
        unsigned char *message; /* message to print for outages */
        unsigned char *contact; /* e-mail contact for this */
	unsigned char *snmp_community; /* snmp community */
	int snmp_version; /* SNMP_VERSION_2C by default; _1 for old agents */
	unsigned char *snmp_oid; /* OID to query - can be numerical 
					or textual*/
	unsigned char *snmp_oid_sec; /* used in snmp compare two values chk */
	unsigned char *snmp_up_msg; /* message for snmp up */
	unsigned char *snmp_down_msg; /* pmesg for snmp down */
	unsigned char *pmesg; /* custom per-object pmesg */
	unsigned int snmp_test_type; /* 1 = sysUpTime.0/reboot,
		2 = high threshold (ie: alert if it goes above that value)
		3 = low threshold (ie: alert if it goes below that value)
		4 = range threshold (ie: specify a high+low and alert if
			it is out of range 
		5 = exact threshold (ie: alert if it is != our value) */
	unsigned long snmp_low, snmp_high, snmp_exact;
	unsigned long snmp_rate; /* rate/sec */
	bool snmp_octets; /* is rate in octets? true/false */
	unsigned long system_uptime; /* system.sysUpTime.0 or last snmp value */
	time_t last_snmp_resptime;
	unsigned char *dns_query; /* name to do dns query of */
	bool dns_aa; /* require AA response */
	bool dns_recursion; /* perform recursive query */
        unsigned int lastcheck; /* lastchecked status  0 = ok,  1 = conn ref
		2 = ENETUNREACH, 3 = EHOSTDOWN||EHOSTUNREACH,
		4 = ETIMEDOUT, 5 = no dns entry, 6 = unpingable,
		7 = Throttled, 8 = no auth, 9 = no response 
		10 = connection in progress, 11 = bad auth 
		12 = bad remote response, 13 = x500 error */
	unsigned char *username; /* for pop3, imap, etc */
	unsigned char *password; /* for pop3, imap, etc */
	unsigned char *hdr;
	unsigned char *hdrval;
	unsigned char *secret; /* used for RADIUS */
	unsigned char *lastmsgid; /* Message ID */
	unsigned char *unique_id; /* Unique id created by loadconfig
			never to change even if we catch sighup, and be
			unique enough between sysmon respawns */
	unsigned char *url; /* url for www */
	unsigned char *url_text; /* text to find within url */
	unsigned char *command; /* command to run on failure */
	unsigned char *group; /* group of object */
	unsigned char *notes; /* user attached notes for object */
	unsigned long totalchecked; /* total times checked */
	unsigned long totaldown; /* total times checked as down */
	unsigned long downct; /* number of times counted as down.. */
	unsigned long upct; /* number of times counted as down.. */
	unsigned long max_down; /* max times down before we contact someone */

	unsigned long queuetime; /* per-object check-interval in seconds */
	time_t next_queuetime; /* next time object should be queued */
	int pageinterval; /* per-object page interval in minutes (-1 = use global) */

	unsigned int send_pings; /* number of pings to send to host */
	unsigned int min_pings; /* min number of pings to require for
		host to be up */

	/* Packet loss specific configuration */
	unsigned int pktloss_tolerance;     /* Max packets that can be lost before alert */
	unsigned int pktloss_history_hours; /* Hours of history to keep (default 24) */
	time_t pktloss_last_check;          /* Last time we evaluated packet loss */

	/* RTT/Jitter configuration (SAA-lite) */
	unsigned int rtt_threshold;         /* Max RTT in milliseconds before alert */
	unsigned int jitter_threshold;      /* Max jitter in milliseconds before alert */
	unsigned int rtt_samples;           /* Number of samples for rolling average */
	unsigned int rtt_interval;          /* ms between probes of one check */

	/* SNMP trap alert configuration */
	bool trap_alert; /* If true, send alert when SNMP trap received from this IP */

	/* Bumped from a single global counter every time something a client
	   would care about changes on this object - state, contacted, ack,
	   notes. Lets CONF hand back only what moved since the caller last
	   asked, instead of every object every second. */
	unsigned long change_seq;

	/* Wakeup/stale check configuration */
	unsigned int max_wakeup_retries;    /* Max times to retry waking stale check (0 = unlimited) */

	bool reverse; /* if true then {if down, follow siblings}, else
			behave as we do otherwise */
	bool contacted; /* true if mailed contact -- false if not */
	bool acked; /* true if someone has acked the alert */
	time_t lastcontacted; /* last time we "contacted" someone */

	int contact_when; /* page someone when it comes up */
	
	bool queued; /* 0 if not, 1 if in queue */
	bool warnlog; /* 0 if already done warnlog, 1 if not */
	bool trace; /* 1 if object should be have debugging enabled for it */

	time_t lchecktime; /* time last checked */
	time_t check_start; /* time of start of check */
	time_t deathtime; /* time of death ;-) */
	time_t last_up; /* time it last came back */
	time_t last_recovery; /* time when host recovered (for flaptime) */

        } ;


/* New structures for monitoring */

/* Spawn command definitions for spawns {} block */
struct spawn_def {
	char *name;           /* Spawn command name (e.g., "pagechris") */
	char *command;        /* Actual command to execute (e.g., "/usr/bin/page.sh %s %i") */
	struct spawn_def *next;
};

struct nei_list {
	unsigned char *nei_name;
	struct graph_elements *g_element;
	struct nei_list *next;
};

struct graph_elements {
	unsigned char *unique_name;
	struct hostinfo *data;
	unsigned short int num_dep;
	unsigned char **dep_txt_name;
	unsigned short int tot_nei;
	struct graph_elements **neighbors;
	bool visit;
};

struct all_elements_list {
	struct graph_elements *value;
	struct all_elements_list *next;
};
  

/* for lib.c:parse() */
struct parsed {
	int count;
	unsigned char **data;
	} ;

/*
 * perhaps we should move the filedes used in monitordata->
 * into here to aide in select()
 */
struct monitorent {
	struct hostinfo *checkent;
	unsigned char *unique_name;
        struct monitorent *next;
	struct timeval queueat; /* time we got queued at */
	struct timeval lastserv; /* time we got last serviced */
	int filedes;		/* filedes used in check */
	int fd_state;		/* 1 = fd waiting for rd, otherwise wr */
	short int started; /* is the check actually started yet */
	short int retval; /* set to the return val, or -1 if check not
			done yet */
	void *monitordata; /* should be free'ed when retval is set */

	/* Wakeup tracking for stale check management */
	unsigned int wakeup_count;      /* How many times woken up */
	time_t last_wakeup_time;        /* When last woken up */
	};

/*
 * A cursor over a BER buffer, shared by the trap decoder and the SNMP
 * client. pos is always <= len; every read is bounds-checked.
 */
struct ber_cursor {
	const unsigned char *buf;
	size_t len;
	size_t pos;
};

/*
 * One value out of a GetResponse.
 */
struct snmp_value {
	bool have_value;		/* FALSE => exception or no varbind */
	unsigned long value;		/* integers, counters, gauges, ticks */
	char type[16];			/* INTEGER, Counter64, ... */
	char oid[192];			/* the varbind's OID, as returned */
	int error_status;		/* PDU error-status, 0 = noError */
	char exception[24];		/* noSuchObject etc, when the agent said so */
};

/*
 * Decoded SNMP trap content (trapdecode.c).
 *
 * Sizes are fixed and small on purpose: this is filled from a UDP packet
 * anybody can send, so there is nothing to allocate, nothing to free, and
 * a hard ceiling on the work one packet can cause.
 */
#define TRAP_MAX_VARBIND	16	/* varbinds kept per trap */
#define TRAP_OID_LEN		192	/* dotted OID string */
#define TRAP_VAL_LEN		160	/* varbind value / description */
#define TRAP_NAME_LEN		48	/* trap or varbind short name */
#define TRAP_HISTORY_MAX	128	/* traps remembered for the web UI */

struct trap_varbind {
	char oid[TRAP_OID_LEN];
	char name[TRAP_NAME_LEN];	/* friendly name, when we know the OID */
	char type[16];			/* INTEGER, STRING, TimeTicks, ... */
	char value[TRAP_VAL_LEN];
	char note[TRAP_VAL_LEN];	/* decoded meaning, eg "down" for a 2 */
};

struct trap_content {
	int version;			/* 0 = v1, 1 = v2c, 3 = v3 */
	bool decoded;			/* FALSE => we could not read the packet */
	bool alertable;			/* TRUE => this really was an SNMP trap */
	bool inform;			/* TRUE => InformRequest, not a trap */
	char community[64];
	char trap_oid[TRAP_OID_LEN];	/* snmpTrapOID.0, or the v1 equivalent */
	char enterprise[TRAP_OID_LEN];
	char agent[IP_ADDR_STR_SIZE];	/* v1 agent-addr: the device's own idea */
	char name[TRAP_NAME_LEN];	/* linkDown, coldStart, ... */
	char description[TRAP_VAL_LEN];
	char severity[16];		/* critical | warning | informational */
	char category[24];		/* link | restart | security | ... */
	char vendor[32];
	char iface[64];			/* interface the trap names, if any */
	int ifindex;			/* -1 when the trap named none */
	int generic;			/* v1 generic trap number, -1 if n/a */
	int specific;			/* v1 specific trap number */
	unsigned long uptime;		/* sysUpTime in hundredths of a second */
	int nvarbinds;
	struct trap_varbind vb[TRAP_MAX_VARBIND];
};

struct trap_record {
	unsigned long seq;		/* monotonic, 1-based, since daemon start */
	char source[IP_ADDR_STR_SIZE];	/* who sent the packet */
	time_t when;
	int bytes;
	char matched[OBJECT_NAME_SIZE];	/* object this source maps to, if any */
	bool alert_enabled;		/* object had trap_alert set */
	bool alert_sent;
	struct trap_content content;
};

/* client status */
struct clientstatus {
	time_t lastactivity;
	short int filedes;
	unsigned char *un; /* username */
	unsigned char *ip;
	int authlvl;
	int clientver;
	bool outage_log;
	bool xml;
	struct clientstatus *next;
};

/* my version of struct hostent -- used in dnscache.c */
struct my_hostent {
	unsigned char *h_name;	/* Official name of host */
	int h_addrtype_v4;               /* Host address type.  */
	int h_length_v4;                 /* Length of address.  */
	unsigned char *my_h_addr_v4;           /* List of v4 addresses from dns  */
	int h_addrtype_v6;
	int h_length_v6;
	unsigned char *my_h_addr_v6;           /* List of v6 addresses from dns*/
};


/* the actual dns cache list */
struct dnscache {
	unsigned char *hostname;
	struct my_hostent *hp;
	time_t lastquery;
	struct dnscache *next;
};

#ifdef USE_BOOTP
/* we should use this someday */
struct bootp_pkt {
        unsigned char   bp_op;          /* packet opcode type */
        unsigned char   bp_htype;       /* hardware addr type */
        unsigned char   bp_hlen;        /* hardware addr length */
        unsigned char   bp_hops;        /* gateway hops */
        unsigned long	bp_xid;         /* transaction ID */
        unsigned short  bp_secs;        /* seconds since boot began */
        unsigned short  bp_unused;
        struct in_addr  bp_ciaddr;      /* client IP address */
        struct in_addr  bp_yiaddr;      /* 'your' IP address */
        struct in_addr  bp_siaddr;      /* server IP address */
        struct in_addr  bp_giaddr;      /* gateway IP address */
        unsigned char   bp_chaddr[16];  /* client hardware address */
        unsigned char   bp_sname[64];   /* server host name */
        unsigned char   bp_file[128];   /* boot file name */
        unsigned char   bp_vend[64];    /* vendor-specific area */
};


#define BOOTP_REQUEST 1
#define BOOTP_REPLY 2
#endif /* USE_BOOTP */

/* Maximum times to try if you get a connection refused */
#define MAX_TRIES       7
/* Minimum ping responses required to declare host up */
#define MIN_PING_RESP	1

/* ****************************************** *
 * NO USER SERVICABLE PARTS BEYOND THIS POINT *
 * ****************************************** */

#define HEARTBEAT_HOST "204.42.254.5"
#define HEARTBEAT_PORT 1345

/* xml tags */
#define XML_OBJECT		"Object"
#define XML_SYSMON_STATUS	"SysmonStatus"
#define XML_OBJECT_STATUS	"ObjectStatus"
#define XML_HOSTNAME		"HostName"
#define XML_OBJECT_TYPE		"ObjectType"
#define XML_OBJECT_PORT		"ObjectPort"
#define XML_OBJECT_MESSAGE	"ObjectMessage"
#define XML_OBJECT_CONTACT	"ObjectContact"
#define XML_SNMP_COMMUNITY	"ObjectSNMPCommunity"
#define XML_SNMP_VERSION	"ObjectSNMPVersion"
#define XML_SITE_NAME		"SiteName"
#define XML_SITE_DESC		"SiteDescription"
#define XML_SNMP_OID		"ObjectSNMPoid"
#define XML_SNMP_TYPE		"ObjectSNMPType"
#define XML_SNMP_LOW		"ObjectSNMPLowThresh"
#define XML_SNMP_HIGH		"ObjectSNMPHighThresh"
#define XML_SNMP_EXACT		"ObjectSNMPExactThresh"
#define XML_SNMP_SysUpTime	"ObjectSNMPObjectSysUpTime"
#define XML_SNMP_RATE		"ObjectSNMPRate"
#define XML_SNMP_OCTETS		"ObjectSNMPOctets"
#define XML_SNMP_LASTRESP	"ObjectSNMPLastResponseTime"
#define XML_OBJECT_STATE	"ObjectLastcheckState"
#define XML_AUTH_USER		"ObjectAuthUsername"
#define XML_AUTH_PASSWD		"ObjectAuthPassword"
#define XML_HEADER		"ObjectHeader"
#define XML_HEADER_VAL		"ObjectHeaderValue"
#define XML_RADIUS_SECRET	"ObjectRadiusSecret"
#define XML_MESSAGE_ID		"ObjectMessageID"
#define XML_UNIQUE_ID		"ObjectUniqueID"
#define XML_OBJECT_GROUP	"ObjectGroup"
#define XML_OBJECT_NOTES        "ObjectNotes"
#define XML_OBJ_URL		"ObjectURL"
#define XML_OBJ_URL_TEXT	"ObjectURLText"
#define XML_OBJ_EXEC		"ObjectExecCmd"
#define XML_TOT_CHECKED		"ObjectTotalChecked"
#define XML_TOT_DOWN		"ObjectTotalDown"
#define XML_DOWN_CT		"ObjectDownCt"
#define XML_UP_CT		"ObjectUpCt"
#define XML_MAX_DOWN		"ObjectMaxDown"
#define XML_QUEUE_INT		"ObjectQueueInterval"
#define XML_SEND_PING		"ObjectSendPings"
#define XML_MIN_PING		"ObjectMinPings"
#define XML_OBJ_REVERSED	"ObjectReversed"
#define XML_OBJ_CONTACTED	"ObjectContacted"
#define XML_OBJ_CONTACTEDAT	"ObjectContactedAt"
#define XML_CONTACT_UP		"ObjectContactOnUp"
#define XML_QUEUED		"ObjectQueued"
#define XML_LASTCHECK		"ObjectLastChecked"
#define XML_CHECK_START		"ObjectCheckStarted"
#define XML_OUTAGE_TIME		"ObjectOutageTime"
#define XML_LAST_TIME_UP	"ObjectLastTimeUp"
#define XML_PACKET_LOSS_THRESHOLD	"ObjectPacketLossThreshold"
#define XML_RTT_THRESHOLD	"ObjectRTTThreshold"
#define XML_JITTER_THRESHOLD	"ObjectJitterThreshold"
#define XML_WAKEUP_CHECK	"ObjectWakeupCheck"
#define XML_WAKEUP_RETRIES	"ObjectWakeupRetries"
#define XML_WAKEUP_INTERVAL	"ObjectWakeupInterval"
#define XML_TRAP_ALERT		"ObjectTrapAlert"
#define XML_MATCHED_HOST	"ObjectMatchedHost"
#define XML_PACKET_LOSS		"ObjectPacketLoss"
#define XML_AVG_RTT		"ObjectAvgRTT"
#define XML_JITTER		"ObjectJitter"

/* Extended XML tags for comprehensive monitoring */
#define XML_SNMP_OID_SEC       "ObjectSNMPOidSecondary"
#define XML_SNMP_UP_MSG        "ObjectSNMPUpMessage"
#define XML_SNMP_DOWN_MSG      "ObjectSNMPDownMessage"
#define XML_DNS_QUERY          "ObjectDNSQuery"
#define XML_DNS_REQ_AA         "ObjectDNSRequireAA"
#define XML_DNS_RECURSION      "ObjectDNSRecursion"
#define XML_PAGE_MESSAGE       "ObjectPageMessage"
#define XML_PKTLOSS_HIST_HRS   "ObjectPacketLossHistoryHours"
#define XML_PKTLOSS_LAST_CHK   "ObjectPacketLossLastCheck"
#define XML_RTT_SAMPLES        "ObjectRTTSamples"
#define XML_RTT_INTERVAL       "ObjectRTTInterval"
#define XML_NEXT_QUEUE_TIME    "ObjectNextQueueTime"
#define XML_TRACE_ENABLED      "ObjectTraceEnabled"
#define XML_ACKED              "ObjectAcked"
#define XML_CHANGE_SEQ         "ObjectChangeSeq"
#define XML_CHECK_QUEUED_AT    "CheckQueuedAt"
#define XML_CHECK_LAST_SERV    "CheckLastServiced"
#define XML_CHECK_FD           "CheckFileDescriptor"
#define XML_CHECK_STARTED      "CheckStarted"
#define XML_CHECK_RETVAL       "CheckReturnValue"
#define XML_CHECK_WAKEUP_CNT   "CheckWakeupCount"
#define XML_CHECK_WAKEUP_TIME  "CheckLastWakeupTime"
#define XML_PKTLOSS_TOTAL_SENT "PacketLossTotalSent"
#define XML_PKTLOSS_TOTAL_RECV "PacketLossTotalReceived"
#define XML_PKTLOSS_TOTAL_LOST "PacketLossTotalLost"
#define XML_PKTLOSS_HIST_SAMP  "PacketLossHistorySamples"
#define XML_PKTLOSS_HISTORY    "PacketLossHistory"

/* snmp trap history (TRAPS command) */
#define XML_TRAPS		"SysmonTraps"
#define XML_TRAP		"Trap"
#define XML_TRAP_SOURCE		"TrapSource"
#define XML_TRAP_TIME		"TrapTime"
#define XML_TRAP_BYTES		"TrapBytes"
#define XML_TRAP_VERSION	"TrapVersion"
#define XML_TRAP_COMMUNITY	"TrapCommunity"
#define XML_TRAP_OID		"TrapOID"
#define XML_TRAP_ENTERPRISE	"TrapEnterprise"
#define XML_TRAP_AGENT		"TrapAgentAddress"
#define XML_TRAP_NAME		"TrapName"
#define XML_TRAP_DESC		"TrapDescription"
#define XML_TRAP_SEVERITY	"TrapSeverity"
#define XML_TRAP_CATEGORY	"TrapCategory"
#define XML_TRAP_VENDOR		"TrapVendor"
#define XML_TRAP_IFACE		"TrapInterface"
#define XML_TRAP_IFINDEX	"TrapIfIndex"
#define XML_TRAP_UPTIME		"TrapUptime"
#define XML_TRAP_DECODED	"TrapDecoded"
#define XML_TRAP_MATCHED	"TrapMatchedHost"
#define XML_TRAP_ALERT_EN	"TrapAlertEnabled"
#define XML_TRAP_ALERT_SENT	"TrapAlertSent"
#define XML_TRAP_VARBIND	"Varbind"
#define XML_TRAP_VB_OID		"VarbindOID"
#define XML_TRAP_VB_NAME	"VarbindName"
#define XML_TRAP_VB_TYPE	"VarbindType"
#define XML_TRAP_VB_VALUE	"VarbindValue"
#define XML_TRAP_VB_NOTE	"VarbindNote"
#define XML_TRAP_SEQ		"TrapSeq"


/* misc defines for any/all external functions */
extern char *myname; /* my called name when I startup */
extern char *statefile;
extern bool mallocdebug;
extern bool stop_daemon;
extern char *errorsto;
extern char *authkey;
/* Identity of this daemon within a fleet. sitename is the key half of
   every "site:object" a client stores and is restricted accordingly;
   sitedesc is the label a person reads and keys nothing. */
extern char *sitename;
extern char *sitedesc;
/* Aggregator link (aggregator.c). NULL host = standalone. */
extern char *aggregator_host;
extern int aggregator_port;
extern char *aggregator_token;
extern char *aggregator_ca;
extern char *path_savestate;
extern char *replyto;
extern char *downcolor, *upcolor, *recentcolor;
extern char *statusfilename;
extern char *statustempdirname;
extern char *cssfilename;
extern bool quiet;
extern time_t boottime; /* does a time() when program starts */
extern bool debug;
extern int dnsexpire;
extern bool donotify;
extern time_t dnslog_last_log;
extern int dnslog;
extern int facility;
extern char *log_file;
extern int globtimeout, globtimeoutlen;
extern char *globhdr, *globhdrval;
extern bool gotsighup;
extern bool heartbeat;
extern int html;
extern unsigned short disable_icmp;
extern int glob_icmp_fd; /* icmp.c + syswatch.c */
extern int glob_icmpv6_fd; /* pingv6.c */
extern int snmp_trap_fd; /* loadconfig.c + snmp.c + syswatch.c */
extern bool paused; /* syswatch.c + srvclient.c + textfile.c */
extern unsigned long glob_change_seq; /* lib.c - see object_changed() */
extern int inactivetime;
extern int numfailures;
extern int minnumfailures; /* minimum failures before yellow status */
extern int flaptime; /* minutes to show green after recovery */
extern int numqueued; /* num of elements in the queue */
extern unsigned long queuetime;
extern int pageinterval;
extern bool showupalso;
extern bool not_started_yet;
extern struct clientstatus *clienthead;
extern struct monitorent *queuehead;
extern struct dnscache *dnshead;
extern struct all_elements_list *currenthead;
extern struct spawn_def *spawn_defs_head; /* Head of spawn command definitions list */
extern struct hostinfo *first;
extern struct protoent *icmpproto;
extern unsigned char *ident_hash;
extern char *pmesg;
extern char *subject;
extern char *sender;
extern int maxqueued;
extern int cieling_max_queued;
extern bool ckconfigonly;
extern bool badconfig;
extern struct graph_elements *configed_root;
extern struct all_elements_list *parser_head;
extern bool do_syslog;
extern int yylex( void );
extern FILE *yyin, *yyout;

#ifdef HAVE_LIBPTHREAD
extern pthread_mutex_t Sysmon_Giant;
#endif /* HAVE_LIBPTHREAD */

/* parser.l externs */
extern char *parser_name;
extern char *parser_pmesg;
extern char *parser_ip;
extern char *parser_root;
extern int line_no;
extern char *parser_type;
extern int  parser_i_type;
extern char *parser_port;
extern int  parser_i_port;
extern char *parser_numfailures;
extern int parser_i_numfailures;
extern char *parser_minnumfailures;
extern int parser_i_minnumfailures;
extern char *parser_flaptime;
extern int parser_i_flaptime;
extern char *parser_desc;
extern char *parser_group;
extern char *parser_spawn;
extern char *parser_contact;
extern char *parser_child;
extern bool parser_reverse;
extern char *parser_sender;
extern char *parser_subject;
extern char *parser_upcolor;
extern char *parser_downcolor;
extern char *parser_recentcolor;
extern char *parser_replyto;
extern char *parser_errorsto;
extern char *parser_header;
extern char *parser_authkey;
extern char *parser_savestate;
extern char *parser_statusfile;
extern char *parser_statustempdir;
extern char *parser_cssfile;
extern char *parser_pidfile;
extern char *parser_logging;
extern int parser_logging_fac;
extern int parser_statusfile_type;
extern char *parser_dateformat;
extern struct nei_list *parser_dep;
extern struct nei_list *parser_dep_tmp;
extern char *parser_page;
extern char *parser_also;
extern char *parser_secret;
extern char *parser_sitename;
extern char *parser_aggregator;
extern char *parser_agg_token;
extern char *parser_agg_ca;
extern char *parser_statedir;
extern int parser_listenport;
extern char *parser_sitedesc;
extern bool parser_catch_snmptrap;
extern char *parser_username;
extern char *parser_password;
extern char *parser_url;
extern char *parser_urltext;
extern char *parser_include;
extern int parser_i_queuetime;
extern char *parser_queuetime;
extern int parser_i_dnsexpire;
extern char *parser_dnsexpire;
extern int parser_i_dnslog;
extern char *parser_dnslog;
extern int parser_i_pageinterval;
extern int parser_obj_i_pageinterval;
extern char *parser_pageinterval;
extern int parser_i_maxqueued;
extern char *parser_maxqueued;
extern int parser_showupalso; /*  */
extern int parser_nologconnects;
extern int parser_nosubject;
extern int parser_html_refresh;
extern char *current_parsing_filename;
/* parser.l functions */
void use_logging_now();

/* new routine names */


extern bool nologconnects;

/* in sysmon.c */
void start_check_sysmon(struct monitorent *, time_t);
void service_check_sysmon(struct monitorent *, time_t);
void stop_check_sysmon(struct monitorent *);

void start_test_dns(struct monitorent *);
void service_test_dns(struct monitorent *);

void start_test_bootp(struct monitorent *);
void service_test_bootp(struct monitorent *);
void start_test_www(struct monitorent *, time_t);
void service_test_www(struct monitorent *, time_t);
void start_test_https(struct monitorent *);
void service_test_https(struct monitorent *);

/* parser.l */
void initalize_parser();
void free_struct_nei_list(struct nei_list *);

/* icmp.c */
void setup_icmp_fd();
void handle_icmp_responses();
void start_test_ping(struct monitorent *);
void service_test_ping(struct monitorent *, struct timeval *);
void start_test_pktloss(struct monitorent *);
void service_test_pktloss(struct monitorent *, struct timeval *);
void pktloss_add_sample(struct pktloss_data *, time_t, unsigned int, unsigned int);
void start_test_rtt(struct monitorent *);
void service_test_rtt(struct monitorent *, struct timeval *);
void stop_test_rtt(struct monitorent *);
unsigned short int generate_ident();
unsigned short in_cksum(u_short *, int);


/* pingv6.c */
void handle_pingv6_responses();
void setup_icmpv6_fd();

/* imap.c */
void start_test_imap(struct monitorent *, time_t);
void service_test_imap(struct monitorent *, time_t);

/* nntp.c */
void start_test_nntp(struct monitorent *, time_t);
void service_test_nntp(struct monitorent *, time_t);

/* pop3.c */
void start_test_pop3(struct monitorent *, time_t);
void service_test_pop3(struct monitorent *, time_t);

void start_test_radius(struct monitorent *, time_t);
void service_test_radius(struct monitorent *, time_t);

void start_test_smtp(struct monitorent *, time_t);
void service_test_smtp(struct monitorent *, time_t);
void start_test_tcp(struct monitorent *, time_t);
void service_test_tcp(struct monitorent *, time_t);
void start_test_udp(struct monitorent *, time_t);
void service_test_udp(struct monitorent *, time_t);
void start_test_x500(struct monitorent *, time_t);
void service_test_x500(struct monitorent *);

void start_test_sshd(struct monitorent *, time_t);
void service_test_sshd(struct monitorent *here, time_t);

void stop_test_tcp(struct monitorent *);
void stop_test_udp(struct monitorent *);
void stop_test_ping(struct monitorent *);
void stop_test_pktloss(struct monitorent *);
void stop_test_snmp(struct monitorent *);
void process_snmp_trap(int);
void stop_test_nntp(struct monitorent *);
void stop_test_smtp(struct monitorent *);
void stop_test_imap(struct monitorent *);
void stop_test_pop3(struct monitorent *);
void stop_test_x500(struct monitorent *);
void stop_test_pop2(struct monitorent *);
void stop_test_bootp(struct monitorent *);
void stop_test_dns(struct monitorent *);
void stop_test_www(struct monitorent *);
void stop_test_radius(struct monitorent *);
void stop_test_https(struct monitorent *);
void stop_test_sysm(struct monitorent *);
void stop_test_sshd(struct monitorent *);


/* if v6 was detected, we should define the testing functions
 * to prevent compiler warnings 
 */
#ifdef HAVE_IPv6
void start_test_pingv6(struct monitorent *);
void service_test_pingv6(struct monitorent *);
void stop_test_pingv6(struct monitorent *);
#endif /* HAVE_IPv6 */

int is_open(int);
void set_defaults();
void free_tree(struct all_elements_list *);
void stop_it();
void service_this(struct monitorent *, struct timeval *, time_t);
void print_queue(int );
void reload_config();
struct all_elements_list *sync_after_sighup(struct all_elements_list *, char *);
float mydifftime(struct timeval, struct timeval);
void blocktillready(int, int);
void expire_dns(time_t );

/* in lib.c: */
int str_cnt(const char *, const char);
char *snmp_type_to_name(int);
char randchar();
void gen_rand_ascii(char *, int);
int check_runtime(struct timeval, struct timeval, char *, int); /* Logs funcs that suck time */
int errno_to_error(int);
void print_err (int, const char *, ...);
void ABORT();

int um_x500_monitor(char *, int);
void do_tree_periodic();
int tcp_open_sock(int);
int nextfd();
int udp_open_sock();
int init_tcp_socket(int);
int init_udp_socket(int);
int icmp_open_sock(int);

/* dnscache.c */
struct my_hostent *my_gethostbyname(unsigned char *, int);
char *get_ip(struct my_hostent *);
char *get_hostname(struct my_hostent *);
void warn_dnscache_lameness();

int test_udp(char*, int);
int test_tcp(char*, int);

/* talktcp.c */
int sendline(int , char *);

/* tlsio.c - TLS on the aggregator link only; every other descriptor looks
   itself up, finds nothing, and behaves exactly as it always has. */
int tls_connect(const char *, int, const char *);
void tls_disconnect(int);
void tls_forget(int);
int tls_pending(int);
int tls_read(int, void *, int);
int tls_write(int, const void *, int);

/* aggregator.c */
void aggregator_poll(time_t);
void aggregator_set_target(const char *);

/* confgen.c - config generations.

   The seed config named by -f (or CFILE) is read-only to this daemon,
   always. A managed box keeps its running copy and its rollback copy in a
   directory it owns - see "config generation-dir" - so nothing here ever
   needs /etc to be writable by the user the daemon drops to.

   confset_* records what the parser actually opened, which is what gets
   hashed: a hash over a guess about which files are included would be
   worse than none. */
extern char configfile[]; /* the seed config file, from syswatch.c */

/* A file of a config, identified by its name - the string in the include
   directive, or the main file's basename. Never a path: nothing the far
   end sends is ever used to build a filename. */
struct confgen_file {
	char *name;
	unsigned char *data;
	long len;
};

/* A config delivery is bounded: this is a monitoring daemon, and an
   unbounded read on the aggregator link is a way to make it stop. */
#define CONFGEN_MAX_PAYLOAD (8 * 1024 * 1024)

void confset_reset(void);
void confset_record(const char *, const char *);
int confset_count(void);
const char *confset_name(int);
const char *confset_path(int);
bool confgen_manageable(char *, size_t);

void confgen_report(struct clientstatus *);
void confgen_send(struct clientstatus *);
void confgen_receive(struct clientstatus *, char *);
void confgen_do_rollback(struct clientstatus *);
void confgen_do_revert(struct clientstatus *);

bool confgen_hash(char *, size_t);
bool confgen_hash_files(struct confgen_file *, int, char *, size_t);
unsigned long confgen_generation(void);
const char *confgen_statedir(void);
const char *confgen_active_config(void);
bool confgen_is_managed_file(const char *);
void confgen_set_statedir(const char *);
void confgen_lock_statedir(void);

/* Everything the daemon writes, derived from the state directory rather
   than configured file by file. */
const char *sysmon_pidfile(void);
const char *sysmon_logfile(void);
const char *sysmon_statefile(void);

/* savestate.c - check state across a restart. Only the runtime fields
   hard_copy() already carries across a SIGHUP; nothing structural and
   nothing secret. */
void save_state(const char *);
void load_state(const char *);
const char *sysmon_ca_file(void);
void confgen_prepare(uid_t, gid_t);
void confgen_prepare_as_root(void);
struct passwd *sysmon_drop_user(void);
bool confgen_apply(unsigned long, struct confgen_file *, int, char *, size_t,
	unsigned long *);
bool confgen_rollback(char *, size_t);
bool confgen_revert(char *, size_t);
char *confgen_b64encode(const unsigned char *, long);
unsigned char *confgen_b64decode(const char *, long *);

void hard_copy(struct hostinfo *old, struct hostinfo *new);
void dump_to_file(char *, int, time_t );
void add_line(FILE *, struct hostinfo, int, time_t);
int data_waiting_read(int, int);
void dump_to_file_walk_this_way(FILE *, struct graph_elements*, int, time_t);
void timeout_clients();
void dead_client_cleanup();
int ping(struct hostinfo *);
char *str_difftime(time_t, time_t);
char *str_difftime_sec(time_t, time_t);
void page_someone(struct hostinfo*, int, time_t);
struct hostinfo *parseline(int *, int*, char*, FILE*);
int test_pop3(char*,char*,char*);
int check_http(char*,char*, char*);
char *yes_no(int);
int getline_tcp(int , char *);
void set_nonblock(int);
int can_write(int, int);
/* loadconfig.c */
void do_set(unsigned char *, unsigned char *);
unsigned char *do_set_replace(unsigned char *);
unsigned char *gen_unique_id();
struct all_elements_list *loadconfig(char *);
struct graph_elements *find_object_by_name(char *);
void update_globs_from_parser();
void clear_visited();
int parse(char *, struct parsed *);
void free_parsed(struct parsed *);
int match_facility(char *);

/* Spawn command management */
void add_spawn_def(char *name, char *command);
char *lookup_spawn_command(char *name);
void free_spawn_defs();

int open_host(char*, int, int*, int);
int open_sock();
char *errtostr(int);
char *type_to_name(int);
char *timedata(time_t);
void syslogmsg(char *, time_t);
void send_heartbeat(char *);

/* auth dns check */
int gethost(char *,struct sockaddr_in *);
int check_authdns(char *,char *);
int chk_ns(char *, char *,int,int ,int , int ,int );

/* dns.c */
void start_check_dns(struct monitorent *);
void service_check_dns(struct monitorent *);
void stop_check_dns(struct monitorent *);

/* snmp.c */
void service_test_snmp(struct monitorent *);
void start_test_snmp(struct monitorent *);
struct graph_elements *find_trap_source(char *);
double rtt_ms_until_next_probe(struct monitorent *, struct timeval *);
void send_trap_alert(struct graph_elements *, char *, struct trap_content *);

/* trapdecode.c - BER reading, shared with the SNMP client */
void snmp_ber_open(struct ber_cursor *, const unsigned char *, size_t);
bool snmp_ber_next(struct ber_cursor *, unsigned char *, const unsigned char **, size_t *);
long snmp_ber_int(const unsigned char *, size_t);
unsigned long snmp_ber_uint(const unsigned char *, size_t);
void snmp_ber_oid_str(const unsigned char *, size_t, char *, size_t);

bool decode_snmp_trap(const unsigned char *, size_t, struct trap_content *);

/* snmpget.c - the SNMP client sysmond polls agents with */
#define SNMP_VERSION_1		0
#define SNMP_VERSION_2C		1
int snmp_build_get(unsigned char *, size_t, int, const char *, unsigned long, const char *);
bool snmp_parse_response(const unsigned char *, size_t, unsigned long, struct snmp_value *);
int snmp_open_query(const char *, int, int, const char *, unsigned long, const char *);
bool snmp_read_response(int, unsigned long, struct snmp_value *);
void trap_history_add(const char *, time_t, int, struct trap_content *,
	const char *, bool, bool);
int trap_history_count(void);
unsigned long trap_history_total(void);
unsigned long trap_history_oldest_seq(void);
struct trap_record *trap_history_get(int);

/* radius check */
void start_check_radius(struct monitorent *, time_t);
void service_check_radius(struct monitorent *, time_t);
void stop_check_radius(struct monitorent *);
void md5_calc (unsigned char *, unsigned char *, unsigned int);

/* srvclient.c */
void send_object_xml(int, FILE*, struct graph_elements *);
void send_traps(struct clientstatus *, unsigned long);
void send_site(struct clientstatus *);
void client_send_statechange(char *, int , int);
int send_conf(struct clientstatus *, unsigned long);

/* in lib.c */
void *MALLOC(size_t, char *);
void *STRDUP(char *, char *);
void FREE(void *);
void object_changed(struct hostinfo *);
bool valid_sitename(const char *);
short int name_to_type(char *);
short int name_to_snmp_type(char *);
void quicksort(char *, size_t, size_t, int (*)(const void *, const void *));
/* end lib.c */

#if (defined(HAVE_LIBNCURSES) || defined(HAVE_LIBCURSES))
void pretty_print_down(struct hostinfo*);
void update_screen();
void setup_screen();
#endif

#if (defined(linux)) /* || defined(unixware)) */
#define ICMPHDR icmphdr
#define ICMP_TYPE type
#define ICMP_CHECKSUM checksum
#define ICMP_CODE code
#define IPHDR iphdr
#define IHL ihl
#define ICMP_SEQ un.echo.sequence
#define ICMP_ECHO_ID un.echo.id
#ifndef RLIMIT_OFILE   
#define RLIMIT_OFILE RLIMIT_NOFILE
#endif            
#endif

#if (defined(unixware) || defined(__APPLE_CC__))
#define RLIMIT_OFILE RLIMIT_NOFILE
#define ICMPHDR icmp
#define ICMP_CHECKSUM icmp_cksum
#define ICMP_TYPE icmp_type
#define ICMP_CODE icmp_code
#define IPHDR ip
#define IHL ip_hl
#define ICMP_SEQ icmp_seq
#define ICMP_ECHO_ID icmp_id
#endif


#if (defined(__NetBSD__) || defined(__FreeBSD) || defined(sgi)|| \
	defined(FreeBSD) || defined(__FreeBSD__) || defined(__bsdi__) || \
	defined(__OpenBSD__))

#if (defined(sgi) || defined(__NetBSD__) || defined(__OpenBSD__))
#define RLIMIT_OFILE RLIMIT_NOFILE
#endif
#define ICMPHDR icmp
#define ICMP_CHECKSUM icmp_cksum
#define ICMP_TYPE icmp_type
#define ICMP_CODE icmp_code
#define IPHDR ip
#define IHL ip_hl
#define ICMP_SEQ icmp_seq
#define ICMP_ECHO_ID icmp_id
#endif

#if (defined(sun) && defined(unix))   /* sunos, solaris, should work for most all */
#define ICMPHDR icmp
#define ICMP_CHECKSUM icmp_cksum
#define ICMP_TYPE icmp_type
#define ICMP_CODE icmp_code
#define IPHDR ip
#define IHL ip_hl
#define ICMP_SEQ icmp_seq
#define ICMP_ECHO_ID icmp_id
#endif

/*
 * this came from an OSF/1 machine
 */
#if (defined(__osf__) && defined(__alpha__))
#define ICMPHDR icmp
#define ICMP_CHECKSUM icmp_cksum
#define ICMP_TYPE icmp_type
#define ICMP_CODE icmp_code
#define IPHDR ip
#define IHL ip_vhl
#define ICMP_SEQ icmp_seq
#define ICMP_ECHO_ID icmp_id
#define RLIMIT_OFILE RLIMIT_NOFILE

#endif

#ifdef _AIX /* AIX */
#define ICMPHDR icmp
#define ICMP_CHECKSUM icmp_cksum
#define ICMP_TYPE icmp_type
#define ICMP_CODE icmp_code
#define IPHDR ip
#define IHL ip_vhl
#define ICMP_SEQ icmp_seq
#define ICMP_ECHO_ID icmp_id

#endif


#ifndef hpux
#ifdef _HPUX_SOURCE
#define hpux
#endif /* _HPUX_SOURCE */
#endif /* hpux */

#ifdef hpux
#define ICMPHDR icmp
#define ICMP_CHECKSUM icmp_cksum
#define ICMP_TYPE icmp_type
#define ICMP_CODE icmp_code
#define IPHDR ip
#define IHL ip_hl
#define ICMP_SEQ icmp_seq
#define ICMP_ECHO_ID icmp_id
#define RLIMIT_OFILE RLIMIT_NOFILE
#endif

