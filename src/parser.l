/* fix solaris lex issues we hope */
%option noyywrap
%e 6500
%p 6500
%n 6500
%{

#define YY_DECL int sysmon_conf_yylex(void)


/* include our config header.  nothing else should be #included here */
#include "config.h"

/* parser global variables required */
char *parser_pos1, *parser_pos2;
char *parser_name = NULL;
char *parser_pmesg = NULL;
char *parser_obj_pmesg = NULL;
char *parser_ip = NULL;
char *parser_root = NULL;
char *parser_type = NULL;
int  parser_i_type = 0;
char *parser_port;
int  parser_i_port = 0;
char *parser_numfailures = NULL;
int parser_i_numfailures = -1;
int parser_obj_i_numfailures = -1;
char *parser_minnumfailures = NULL;
int parser_i_minnumfailures = -1;
char *parser_flaptime = NULL;
int parser_i_flaptime = -1;
char *parser_desc = NULL;
char *parser_group = NULL;
char *parser_dns_query = NULL;
char *parser_spawn = NULL;
char *parser_contact = NULL;
int parser_when = SYSM_CONTACT_DOWN | SYSM_CONTACT_UP;
char *parser_child = NULL;
int parser_html_refresh = 60;
bool parser_reverse = FALSE;
bool parser_snmp_octets = FALSE;
bool parser_catch_snmptrap = FALSE;
bool parser_trap_alert = FALSE;
char *parser_rtt_threshold = NULL;
int parser_i_rtt_threshold = 0;
char *parser_jitter_threshold = NULL;
int parser_i_jitter_threshold = 0;
char *parser_rtt_samples = NULL;
int parser_i_rtt_samples = 5;  /* Default: 5 samples */
char *parser_sender = NULL;
char *parser_subject = NULL;
char *parser_upcolor = NULL;
char *parser_downcolor = NULL;
char *parser_recentcolor = NULL;
char *parser_replyto = NULL;
char *parser_errorsto = NULL;
char *parser_header = NULL;
char *parser_authkey = NULL;
char *parser_savestate = NULL;
char *parser_statusfile = NULL;
char *parser_statustempdir = NULL;
char *parser_cssfile = NULL;
char *parser_pidfile = NULL;
char *parser_logging = NULL;
int parser_logging_fac;
int parser_statusfile_type;
char *parser_dateformat = NULL;
struct nei_list *parser_dep = NULL;
struct nei_list *parser_dep_tmp = NULL;   /* Used when adding new elements */
char *parser_page = NULL;
char *parser_also = NULL;
char *parser_secret = NULL;
char *parser_username = NULL;
char *parser_community = NULL;
char *parser_oid = NULL;
char *parser_snmp_type = NULL;
int parser_i_snmp_type = -1;
char *parser_snmp_low = NULL;
char *parser_snmp_high = NULL;
char *parser_snmp_exact = NULL;
char *parser_snmp_rate = NULL;
unsigned long parser_i_snmp_low;
unsigned long parser_i_snmp_high;
unsigned long parser_i_snmp_exact;
unsigned long parser_i_snmp_rate;
char *parser_password = NULL;
char *parser_url = NULL;
char *parser_urltext = NULL;
char *parser_include = NULL;
char *parser_value = NULL;
char *parser_eq = NULL;
int parser_i_queuetime = -1;
int parser_obj_i_queuetime = -1;
char *parser_queuetime = NULL;
int parser_i_dnsexpire;
char *parser_dnsexpire = NULL;
int parser_i_dnslog;
char *parser_dnslog = NULL;
int parser_i_pageinterval;
int parser_obj_i_pageinterval = -1;
char *parser_pageinterval = NULL;
int parser_i_maxqueued;
char *parser_maxqueued = NULL;
int parser_showupalso; /*  */
int parser_nologconnects;
int parser_nosubject;
int temp_int;
int line_no;
char *temp_char;
char *current_parsing_filename;

/* end parser global variables */

/* Function definitions that are found later in the program */
void add_object();
void open_new_file(char *, FILE *);
void free_struct_nei_list(struct nei_list *);
void fixup_lineno();
void parser_error(char *file_name, int line, char *msg);

/* end function predefs */

/* external variables not found in config.h */

extern struct all_elements_list *parser_head;

/* end external declarations not found in config.h */


%}

WS	[\t ]

%%

[;#].*\n	{ if (debug) print_err(1, "ignoring line %d - comments", line_no); line_no++; }	/* Ignore comments */

[\t ]+       /* ignore whitespace */


[\n]    { 
	if (debug) 
		print_err(1, "ignoring line %d - newline", line_no); 
	line_no++;
}   /* ignore newlines */


set[\t ]+[^;]+{WS}*;       {

  /* Search for extra newlines that are not being counted */
  fixup_lineno();
  parser_pos1 = strchr( yytext, '"' );
  if (parser_pos1 == NULL)
  {
	print_err(1, "missing quotes on line %d in %s", line_no, current_parsing_filename);
	break;
  }
  parser_pos1 = parser_pos1+1;
  parser_pos2 = strchr( parser_pos1, '"' );
  if (parser_pos2 == NULL)
  {
	print_err(1, "misbalanced quotes on line %d in %s", line_no, current_parsing_filename);
	break;
  }
  if (parser_eq != NULL)
  {
        FREE(parser_eq);
  }
  parser_eq = MALLOC((parser_pos2-parser_pos1)+1, "parse.l:parser_eq");
  strncpy( parser_eq, parser_pos1, parser_pos2 - parser_pos1 );

  parser_eq[ parser_pos2 - parser_pos1 ] = '\0';


  parser_pos1 = strchr( yytext, ' ' );
  if (parser_pos1 == NULL)
  {
	print_err(1, "missing space on line %d in %s", line_no, current_parsing_filename);
	break;
  }
  parser_pos1=parser_pos1+1;
  parser_pos2 = strchr( parser_pos1, ' ' );
  if (parser_value != NULL)
  {
        FREE(parser_value);
  }
  parser_value = MALLOC((parser_pos2-parser_pos1)+1, "parse.l:parser_value");
  strncpy( parser_value, parser_pos1, parser_pos2 - parser_pos1 );

  parser_value[ parser_pos2 - parser_pos1 ] = '\0';

  if (debug) 
    print_err(0, "value equals : \"%s\" = \"%s\"", parser_value, parser_eq); 

  /* Set the variable */
  do_set(parser_value, parser_eq);
}

include\ [^;]+{WS}*;          {

  /* Search for extra newlines that are not being counted */
  fixup_lineno();
  parser_pos1 = strchr( yytext, '"' );
  if (parser_pos1 == NULL)
  {
	print_err(1, "missing quotes on line %d in %s", line_no, current_parsing_filename);
	break;
  }
  parser_pos1=parser_pos1+1;
  parser_pos2 = strchr( parser_pos1, '"' );
  if (parser_pos2 == NULL)
  {
	print_err(1, "misbalanced quotes on line %d in %s", line_no, current_parsing_filename);
	break;
  }
 if (parser_include != NULL)
  {
        FREE(parser_include);
  }
  parser_include = MALLOC((parser_pos2-parser_pos1)+1, "parse.l:parser_include");

  strncpy( parser_include, parser_pos1, parser_pos2 - parser_pos1 );
  parser_include[ parser_pos2 - parser_pos1 ] = '\0';

  if (debug)
    print_err(0, "parser.l:including file : %s", parser_include); 
  open_new_file(parser_include, yyin);
}

reverse{WS}*;	{
	if (parser_name == NULL)
		print_err(1, "Warning, reverse specified when not inside an object %d", line_no);
	parser_reverse = TRUE;

}

trap_alert{WS}*;	{
	if (parser_name == NULL)
		print_err(1, "Warning, trap_alert specified when not inside an object at line %d", line_no);
	parser_trap_alert = TRUE;
	if (debug)
		print_err(0, "parser.l: enabling trap alerts for this object");
}

snmp-octets{WS}*;   {
        if (parser_name == NULL)
                print_err(1, "Warning, snmp-octets specified when not inside an object %d", line_no);
        parser_snmp_octets = TRUE;

}


config{WS}snmp-trap{WS}*;	{
	parser_catch_snmptrap = TRUE;
	if (debug)
		print_err(0, "parser.l:enabling catching snmp traps");
}

config\ showupalso{WS}*;	{
	parser_showupalso = TRUE;
}

config\ nologconnects{WS}*;	{
	parser_nologconnects = TRUE;
}

config{WS}noheartbeat{WS}*;	{
	heartbeat = FALSE;
}

config{WS}nosubject{WS}*;	{
	parser_nosubject = TRUE;
}

config{WS}statusfile{WS}html{WS}[^;]+{WS}*;       {
  /* Search for extra newlines that are not being counted */
  fixup_lineno();
  parser_pos1 = strchr(yytext, '"' );
  if (parser_pos1 == NULL)
  {
    print_err(1, "missing quotes on line %d in %s", line_no, current_parsing_filename);
    break;
  } else {
    parser_pos1=parser_pos1+1;
  }
  parser_pos2 = strchr( parser_pos1, '"' );
   if (parser_pos2 == NULL)
  {
	print_err(1, "misbalanced quotes on line %d in %s", line_no, current_parsing_filename);
	break;
  }
 if (parser_statusfile != NULL)
  {
        FREE(parser_statusfile);
  }
  parser_statusfile = MALLOC((parser_pos2-parser_pos1)+1, "parse.l:parser_name");
  strncpy( parser_statusfile, parser_pos1, parser_pos2 - parser_pos1 );

  parser_statusfile[ parser_pos2 - parser_pos1 ] = '\0';
  parser_statusfile_type = 1;

  if (debug)
    print_err(0, "statusfile : %s", parser_statusfile); 
}

config\ statusfile\ text\ [^;]+{WS}*;       {
  parser_pos1 = strchr( yytext, '"' );

  /* Search for extra newlines that are not being counted */
  fixup_lineno();

  if (parser_pos1 == NULL)
  {
	print_err(1, "missing quotes on line %d in %s", line_no, current_parsing_filename);
	break;
  } else {
    parser_pos1=parser_pos1+1;
  }
  parser_pos2 = strchr( parser_pos1, '"' );
  if (parser_pos2 == NULL)
  {
	print_err(1, "misbalanced quotes on line %d in %s", line_no, current_parsing_filename);
	break;
  }
  if (parser_statusfile != NULL)
  {
        FREE(parser_statusfile);
  }
  parser_statusfile = MALLOC((parser_pos2-parser_pos1)+1, "parse.l:parser_name");
  strncpy( parser_statusfile, parser_pos1, parser_pos2 - parser_pos1 );

  parser_statusfile[ parser_pos2 - parser_pos1 ] = '\0';

  if (debug)
    print_err(0, "statusfile : %s", parser_statusfile);
}

config{WS}statustempdir{WS}[^;]+{WS}*;       {
  /* Search for extra newlines that are not being counted */
  fixup_lineno();
  parser_pos1 = strchr(yytext, '"' );
  if (parser_pos1 == NULL)
  {
    print_err(1, "missing quotes on line %d in %s", line_no, current_parsing_filename);
    break;
  } else {
    parser_pos1=parser_pos1+1;
  }
  parser_pos2 = strchr( parser_pos1, '"' );
  if (parser_pos2 == NULL)
  {
    print_err(1, "misbalanced quotes on line %d in %s", line_no, current_parsing_filename);
    break;
  }
  if (parser_statustempdir != NULL)
  {
    FREE(parser_statustempdir);
  }
  parser_statustempdir = MALLOC((parser_pos2-parser_pos1)+1, "parse.l:parser_statustempdir");
  strncpy( parser_statustempdir, parser_pos1, parser_pos2 - parser_pos1 );

  parser_statustempdir[ parser_pos2 - parser_pos1 ] = '\0';

  if (debug)
    print_err(0, "statustempdir : %s", parser_statustempdir);
}

config{WS}cssfile{WS}[^;]+{WS}*;       {
  /* Search for extra newlines that are not being counted */
  fixup_lineno();
  parser_pos1 = strchr(yytext, '"' );
  if (parser_pos1 == NULL)
  {
    print_err(1, "missing quotes on line %d in %s", line_no, current_parsing_filename);
    break;
  } else {
    parser_pos1=parser_pos1+1;
  }
  parser_pos2 = strchr( parser_pos1, '"' );
   if (parser_pos2 == NULL)
  {
	print_err(1, "misbalanced quotes on line %d in %s", line_no, current_parsing_filename);
	break;
  }
 if (parser_cssfile != NULL)
  {
        FREE(parser_cssfile);
  }
  parser_cssfile = MALLOC((parser_pos2-parser_pos1)+1, "parse.l:parser_name");
  strncpy( parser_cssfile, parser_pos1, parser_pos2 - parser_pos1 );

  parser_cssfile[ parser_pos2 - parser_pos1 ] = '\0';

  if (debug)
    print_err(0, "cssfile : %s", parser_cssfile); 
}

config\ logging\ file\ [^;]+{WS}*;       {
  /* Search for extra newlines that are not being counted */
  fixup_lineno();

  parser_pos1 = strchr( yytext, '"' );
  if (parser_pos1 == NULL)
  {
	print_err(1, "missing quotes on line %d in %s", line_no, current_parsing_filename);
	break;
  } else {
	parser_pos1 = parser_pos1+1;
  }
  parser_pos2 = strchr( parser_pos1, '"' );
  if (parser_pos2 == NULL)
  {
	print_err(1, "misbalanced quotes on line %d in %s", line_no, current_parsing_filename);
	break;
  }
  if (parser_logging != NULL)
  {
        FREE(parser_logging);
  }
  parser_logging = MALLOC((parser_pos2-parser_pos1)+1, "parse.l:parser_name");
  strncpy( parser_logging, parser_pos1, parser_pos2 - parser_pos1 );

  parser_logging[ parser_pos2 - parser_pos1 ] = '\0';
  if (debug)
    print_err(0, "logging : %s", parser_logging); 

  parser_logging_fac = -3;
  if (not_started_yet == TRUE)
	use_logging_now();
}

config\ logging\ syslog\ [^;]+{WS}*;       {
  /* Search for extra newlines that are not being counted */
  fixup_lineno();

  parser_pos1 = strchr( yytext, '"' );
  if (parser_pos1 == NULL)
  {
	print_err(1, "missing quotes on line %d in %s", line_no, current_parsing_filename);
	break;
  } else {
	parser_pos1 = parser_pos1 +1;
  }
  parser_pos2 = strchr( parser_pos1, '"' );
  if (parser_pos2 == NULL)
  {
	print_err(1, "misbalanced quotes on line %d in %s", line_no, current_parsing_filename);
	break;
  }
  if (parser_logging != NULL)
  {
        FREE(parser_logging);
  }
  parser_logging = MALLOC((parser_pos2-parser_pos1)+1, "parse.l:parser_logging");
  strncpy( parser_logging, parser_pos1, parser_pos2 - parser_pos1 );

  parser_logging[ parser_pos2 - parser_pos1 ] = '\0';
  if (debug)
    print_err(0, "logging : %s", parser_logging); 

  parser_logging_fac = match_facility(parser_logging);
  if (parser_logging_fac == -1)
  {
	print_err(0, "invalid facility %s specified", parser_logging);
	FREE(parser_logging);
	parser_logging = NULL;
  }
  if (not_started_yet == TRUE)
	use_logging_now();
}

config\ pidfile\ [^;]+{WS}*;       {
  /* Search for extra newlines that are not being counted */
  fixup_lineno();

  parser_pos1 = strchr( yytext, '"' );
  if (parser_pos1 == NULL)
  {
	print_err(1, "missing quotes on line %d (pidfile) in %s", line_no, current_parsing_filename);
	break;
  } else {
	parser_pos1 = parser_pos1 +1;
  }
  parser_pos2 = strchr( parser_pos1, '"' );
  if (parser_pos2 == NULL)
  {
	print_err(1, "misbalanced quotes on line %d (pidfile) in %s", line_no, current_parsing_filename);
	break;
  }
  if (parser_pidfile != NULL)
  {
        FREE(parser_pidfile);
  }
  parser_pidfile = MALLOC((parser_pos2-parser_pos1)+1, "parse.l:parser_logging");
  strncpy( parser_pidfile, parser_pos1, parser_pos2 - parser_pos1 );

  parser_pidfile[ parser_pos2 - parser_pos1 ] = '\0';
  if (debug)
    print_err(0, "pidfile : %s", parser_pidfile); 
}

config\ date\ [^;]+{WS}*;       {
  /* Search for extra newlines that are not being counted */
  fixup_lineno();

  parser_pos1 = strchr( yytext, '"' );
  if (parser_pos1 == NULL)
  {
	print_err(1, "missing quotes on line %d (pidfile) in %s", line_no, current_parsing_filename);
	break;
  } else {
	parser_pos1 = parser_pos1 +1;
  }
  parser_pos2 = strchr( parser_pos1, '"' );
  if (parser_pos2 == NULL)
  {
	print_err(1, "misbalanced quotes on line %d (pidfile) in %s", line_no);
	break;
  }
  if (parser_dateformat != NULL)
  {
        FREE(parser_dateformat);
  }
  parser_dateformat = MALLOC((parser_pos2-parser_pos1)+1, "parse.l:parser_logging");
  strncpy( parser_dateformat, parser_pos1, parser_pos2 - parser_pos1 );

  parser_dateformat[ parser_pos2 - parser_pos1 ] = '\0';
  if (! strcmp (parser_dateformat, "ISO")) {
  	FREE(parser_dateformat);
	parser_dateformat = STRDUP("%F %T", "date format");
  }
  if (! strcmp (parser_dateformat, "DEC")) {
  	FREE(parser_dateformat);
	parser_dateformat = STRDUP("%T %d-%b-%Y", "date format");
  }
  if (debug)
    print_err(0, "date format : %s", parser_dateformat); 
}

root*[^;]+{WS}*;       {
  /* Search for extra newlines that are not being counted */
  fixup_lineno();

  parser_pos1 = strchr( yytext, '"' );
  if (parser_pos1 == NULL)
  {
	print_err(1, "No quotes on line %d, some are needed to enclose root name", line_no);
	break;
  }
  parser_pos1 = parser_pos1+1;
  parser_pos2 = strchr( parser_pos1, '"' );
  if (parser_pos2 == NULL)
  {
    print_err(1, "misbalanced quotes on line %d in %s", line_no, current_parsing_filename);
    break;
  }

  if (parser_root != NULL)
  {
	print_err(1, "WARNING: More than one configured root, %s (was our old configured root)", parser_root);
        FREE(parser_root);
  }
  parser_root = MALLOC((parser_pos2-parser_pos1)+1, "parse.l:parser_name");
  strncpy( parser_root, parser_pos1, parser_pos2 - parser_pos1 );

  parser_root[ parser_pos2 - parser_pos1 ] = '\0';

  temp_char = do_set_replace(parser_root);
  if (temp_char != NULL)
  {
        FREE(parser_root);
        parser_root = temp_char;
  }

  if (debug)
  {
    print_err(0, "root : %s", parser_root); 
  }
}

object[^\{]+{WS}+\{	{
  /* Search for extra newlines that are not being counted */
  fixup_lineno();

  parser_reverse = FALSE;
  parser_snmp_octets = FALSE;
  parser_trap_alert = FALSE;
  for (temp_int=6;strlen(yytext)> temp_int;temp_int++)
  {
	if (!isspace(yytext[temp_int]))
		break;
  }
  parser_pos1 = yytext + temp_int;
  for (;strlen(yytext)> temp_int;temp_int++)
  {
	if (isspace(yytext[temp_int]))
		break;
  }
  parser_pos2 = yytext + temp_int;
 
  if (parser_pos2 == NULL)
  {
	print_err(1, "missing space/value on line %d in %s", line_no, current_parsing_filename);
	break;
  }

  if (parser_name != NULL)
  {
	FREE(parser_name);
  }
  parser_name = MALLOC((parser_pos2-parser_pos1)+1, "parse.l:parser_name");
  strncpy( parser_name, parser_pos1, parser_pos2 - parser_pos1 );
  parser_name[parser_pos2 - parser_pos1] = '\0';
  if (parser_port != NULL)
  {
	FREE(parser_port);
	parser_port = NULL;
  }

  if (debug)
    print_err(0, "object : %s {", parser_name); 

}

ip\ [^;]+{WS}*;	{
  /* Search for extra newlines that are not being counted */
  fixup_lineno();

  if (parser_name == NULL)
	print_err(1, "WARNING: ip specified when not inside an object in line %d", line_no);


  parser_pos1 = strchr( yytext, '"' );
  if (parser_pos1 == NULL)
  {
	print_err(1, "missing quotes on line %d in %s", line_no, current_parsing_filename);
	break;
  }
  parser_pos1=parser_pos1+1;
  parser_pos2 = strchr( parser_pos1, '"' );
  if (parser_pos2 == NULL)
  {
	print_err(1, "misbalanced quotes on line %d in %s", line_no, current_parsing_filename);
	break;
  }
 if (parser_ip != NULL)
  {
        FREE(parser_ip);
  }
  parser_ip = MALLOC((parser_pos2-parser_pos1)+1, "parse.l:parser_ip");

  strncpy( parser_ip, parser_pos1, parser_pos2 - parser_pos1 );
  parser_ip[ parser_pos2 - parser_pos1 ] = '\0';

  if (index(parser_ip, ' ') != NULL)
  {
	print_err(1, "WARNING: hostname contains whitespace in %s:%d", current_parsing_filename, line_no);
  }
  /* FIXME: Check IP to verify it is valid */

  if (debug)  
    print_err(0, "ip : %s", parser_ip); 
};


type\ [^;]+{WS}*;          {

  if (parser_name == NULL)
	print_err(1, "WARNING: type specified when not inside an object at line %d", line_no);

  /* Search for extra newlines that are not being counted */
  fixup_lineno();

  parser_pos1 = strchr( yytext, ' ' );
  if (parser_pos1 == NULL)
  {
	print_err(1, "missing space/value on line %d in %s", line_no, current_parsing_filename);
	break;
  }
  parser_pos1=parser_pos1+1;
  parser_pos2 = strchr( parser_pos1, ';' );
  if (parser_pos2 == NULL)
  {
	print_err(1, "misbalanced quotes on line %d in %s", line_no, current_parsing_filename);
	break;
  }

  if (parser_type != NULL)
  {
        FREE(parser_type);
	parser_i_type = -1;
  }
  parser_type = MALLOC((parser_pos2-parser_pos1)+1, "parse.l:parser_type");

  strncpy( parser_type, parser_pos1, parser_pos2 - parser_pos1 );
  parser_type[ parser_pos2 - parser_pos1 ] = '\0';

  parser_i_type = name_to_type(parser_type);
  if (parser_i_type == -1)
  {
	print_err(1, "Invalid type specified in %s line %d", 
		current_parsing_filename, line_no);
  }
  if (debug)
    print_err(0, "type : %s/%d ", parser_type, parser_i_type); 

};

config\ html\ refresh\ [^;]+{WS}*;          {
  /* Search for extra newlines that are not being counted */
  fixup_lineno();

  parser_pos1 = strrchr( yytext, ' ' );
  if (parser_pos1 == NULL)
  {
	print_err(1, "missing space/value on line %d in %s", line_no, current_parsing_filename);
	break;
  }
  parser_pos1=parser_pos1+1;
  parser_pos2 = strchr( parser_pos1, ';' );
  if (parser_pos2 == NULL)
  {
	print_err(1, "missing semicolon on line %d in %s", line_no, current_parsing_filename);
	break;
  }

  parser_html_refresh = atol(parser_pos1);
  if (parser_html_refresh < 1)
  {
	print_err(1, "Invalid HTML refresh time specified in %s line %d", 
		current_parsing_filename, line_no);
	parser_html_refresh = 60;
  }
  if (debug)
    print_err(0, "HTML refresh : %d ", parser_html_refresh);
};

config\ queuetime\ [^;]+{WS}*;          {
  /* Search for extra newlines that are not being counted */
  fixup_lineno();

  parser_pos1 = strrchr( yytext, ' ' );
  if (parser_pos1 == NULL)
  {
	print_err(1, "missing space/value on line %d in %s", line_no, current_parsing_filename);
	break;
  }
  parser_pos1=parser_pos1+1;
  parser_pos2 = strchr( parser_pos1, ';' );
  if (parser_pos2 == NULL)
  {
	print_err(1, "misbalanced quotes on line %d in %s", line_no, current_parsing_filename);
	break;
  }

  if (parser_queuetime != NULL)
  {
        FREE(parser_queuetime);
	parser_queuetime = NULL;
	parser_i_queuetime = -1;
  }
  parser_queuetime = MALLOC((parser_pos2-parser_pos1)+1, "parse.l:parser_queuetime");

  strncpy( parser_queuetime, parser_pos1, parser_pos2 - parser_pos1 );
  parser_queuetime[ parser_pos2 - parser_pos1 ] = '\0';

  /* If we are inside an object, apply this information
   * only to this object
   */
  if (parser_name != NULL)
  {
        parser_obj_i_queuetime = atol(parser_queuetime);
  } else {
    parser_i_queuetime = atol(parser_queuetime);
    if (parser_i_queuetime == -1)
    {
          print_err(1, "Invalid queuetime specified in %s line %d",
                  current_parsing_filename, line_no);
    }
    parser_obj_i_queuetime = -1;
    if (debug)
      print_err(0, "queuetime : %s/%d ", parser_queuetime, parser_i_queuetime); 
  }
};


config\ dnsexpire\ [^;]+{WS}*;          {
  /* Search for extra newlines that are not being counted */
  fixup_lineno();

  parser_pos1 = strrchr( yytext, ' ' );
  if (parser_pos1 == NULL)
  {
	print_err(1, "missing space/value on line %d in %s", line_no, current_parsing_filename);
	break;
  }
  parser_pos1=parser_pos1+1;
  parser_pos2 = strchr( parser_pos1, ';' );
  if (parser_pos2 == NULL)
  {
	print_err(1, "misbalanced quotes on line %d in %s", line_no, current_parsing_filename);
	break;
  }

  if (parser_dnsexpire != NULL)
  {
        FREE(parser_dnsexpire);
	parser_i_dnsexpire = -1;
  }
  parser_dnsexpire = MALLOC((parser_pos2-parser_pos1)+1, "parse.l:parser_dnsexpire");

  strncpy( parser_dnsexpire, parser_pos1, parser_pos2 - parser_pos1 );
  parser_dnsexpire[ parser_pos2 - parser_pos1 ] = '\0';

  parser_i_dnsexpire = atol(parser_dnsexpire);
  if (parser_i_dnsexpire == -1)
  {
	print_err(1, "Invalid dnsexpire specified in %s line %d", 
		current_parsing_filename, line_no);
  }
  if (debug)
    print_err(0, "dnsexpire : %s/%d ", parser_dnsexpire, parser_i_dnsexpire); 
};


config\ dnslog\ [^;]+{WS}*;          {
  /* Search for extra newlines that are not being counted */
  fixup_lineno();

  parser_pos1 = strrchr( yytext, ' ' );
  if (parser_pos1 == NULL)
  {
	print_err(1, "missing space/value on line %d in %s", line_no, current_parsing_filename);
	break;
  }
  parser_pos1=parser_pos1+1;
  parser_pos2 = strchr( parser_pos1, ';' );
  if (parser_pos2 == NULL)
  {
	print_err(1, "misbalanced quotes on line %d in %s", line_no, current_parsing_filename);
	break;
  }

  if (parser_dnslog != NULL)
  {
        FREE(parser_dnslog);
	parser_i_dnslog = -1;
  }
  parser_dnslog = MALLOC((parser_pos2-parser_pos1)+1, "parse.l:parser_dnslog");

  strncpy( parser_dnslog, parser_pos1, parser_pos2 - parser_pos1 );
  parser_dnslog[ parser_pos2 - parser_pos1 ] = '\0';

  parser_i_dnslog = atol(parser_dnslog);
  if (parser_i_dnslog == -1)
  {
	print_err(1, "Invalid dnslog specified in %s line %d", 
		current_parsing_filename, line_no);
  }
  if (debug)
    print_err(0, "dnslog : %s/%d ", parser_dnslog, parser_i_dnslog); 
};

config\ pageinterval\ [^;]+;          {
  /* Search for extra newlines that are not being counted */
  fixup_lineno();

  parser_pos1 = strrchr( yytext, ' ' );
  if (parser_pos1 == NULL)
  {
	print_err(1, "missing space/value on line %d in %s", line_no, current_parsing_filename);
	break;
  }
  parser_pos1=parser_pos1+1;
  parser_pos2 = strchr( parser_pos1, ';' );
  if (parser_pos2 == NULL)
  {
	print_err(1, "misbalanced quotes on line %d in %s", line_no, current_parsing_filename);
	break;
  }

  if (parser_pageinterval != NULL)
  {
        FREE(parser_pageinterval);
	parser_i_pageinterval = -1;
  }
  parser_pageinterval = MALLOC((parser_pos2-parser_pos1)+1, "parse.l:parser_pageinterval");

  strncpy( parser_pageinterval, parser_pos1, parser_pos2 - parser_pos1 );
  parser_pageinterval[ parser_pos2 - parser_pos1 ] = '\0';

  /* If we are inside an object, apply this information
   * only to this object
   */
  if (parser_name != NULL)
  {
        parser_obj_i_pageinterval = atol(parser_pageinterval);
  } else {
    parser_i_pageinterval = atol(parser_pageinterval);
    if (parser_i_pageinterval == -1)
    {
          print_err(1, "Invalid pageinterval specified in %s line %d",
                  current_parsing_filename, line_no);
    }
    parser_obj_i_pageinterval = -1;
    if (debug)
      print_err(0, "pageinterval : %s/%d ", parser_pageinterval, parser_i_pageinterval);
  }
};

config\ maxqueued\ [^;]+;          {
  /* Search for extra newlines that are not being counted */
  fixup_lineno();

  parser_pos1 = strrchr( yytext, ' ' );
  if (parser_pos1 == NULL)
  {
	print_err(1, "missing space/value on line %d in %s", line_no, current_parsing_filename);
	break;
  }
  parser_pos1=parser_pos1+1;
  parser_pos2 = strchr( parser_pos1, ';' );
  if (parser_pos2 == NULL)
  {
	print_err(1, "misbalanced quotes on line %d in %s", line_no, current_parsing_filename);
	break;
  }

  if (parser_maxqueued != NULL)
  {
        FREE(parser_maxqueued);
	parser_i_maxqueued = -1;
  }
  parser_maxqueued = MALLOC((parser_pos2-parser_pos1)+1, "parse.l:parser_maxqueued");

  strncpy( parser_maxqueued, parser_pos1, parser_pos2 - parser_pos1 );
  parser_maxqueued[ parser_pos2 - parser_pos1 ] = '\0';

  parser_i_maxqueued = atol(parser_maxqueued);
  if (parser_i_maxqueued == -1)
  {
	print_err(1, "Invalid maxqueued specified in %s line %d", 
		current_parsing_filename, line_no);
  }
  if (debug)
    print_err(0, "maxqueued : %s/%d ", parser_maxqueued, parser_i_maxqueued); 
};

config\ numfailures\ [^;]+;          {
  /* Search for extra newlines that are not being counted */
  fixup_lineno();

  parser_pos1 = strrchr( yytext, ' ' );
  if (parser_pos1 == NULL)
  {
	print_err(1, "missing space/value on line %d in %s", line_no, current_parsing_filename);
	break;
  }
  parser_pos1=parser_pos1+1;
  parser_pos2 = strchr( parser_pos1, ';' );
  if (parser_pos2 == NULL)
  {
	print_err(1, "misbalanced quotes on line %d in %s", line_no, current_parsing_filename);
	break;
  }

  if (parser_numfailures != NULL)
  {
        FREE(parser_numfailures);
	parser_i_numfailures = -1;
  }
  parser_numfailures = MALLOC((parser_pos2-parser_pos1)+1, "parse.l:parser_numfailures");

  strncpy( parser_numfailures, parser_pos1, parser_pos2 - parser_pos1 );
  parser_numfailures[ parser_pos2 - parser_pos1 ] = '\0';

  parser_i_numfailures = atol(parser_numfailures);
  if (parser_i_numfailures == -1)
  {
	print_err(1, "Invalid numfailures specified in %s line %d", 
		current_parsing_filename, line_no);
  }
  /* If we are inside an object, apply this information
   * only to this object
   */
  if (parser_name != NULL)
  {
	parser_obj_i_numfailures = parser_i_numfailures;
  } else {
	parser_obj_i_numfailures = -1;
  }
  if (debug)
    print_err(0, "numfailures : %s/%d ", parser_numfailures, parser_i_numfailures);

};

config\ minnumfailures\ [^;]+;          {
  /* Search for extra newlines that are not being counted */
  fixup_lineno();

  parser_pos1 = strrchr( yytext, ' ' );
  if (parser_pos1 == NULL)
  {
	print_err(1, "missing space/value on line %d in %s", line_no, current_parsing_filename);
	break;
  }
  parser_pos1=parser_pos1+1;
  parser_pos2 = strchr( parser_pos1, ';' );
  if (parser_pos2 == NULL)
  {
	print_err(1, "misbalanced quotes on line %d in %s", line_no, current_parsing_filename);
	break;
  }

  if (parser_minnumfailures != NULL)
  {
        FREE(parser_minnumfailures);
	parser_i_minnumfailures = -1;
  }
  parser_minnumfailures = MALLOC((parser_pos2-parser_pos1)+1, "parse.l:parser_minnumfailures");

  strncpy( parser_minnumfailures, parser_pos1, parser_pos2 - parser_pos1 );
  parser_minnumfailures[ parser_pos2 - parser_pos1 ] = '\0';

  parser_i_minnumfailures = atol(parser_minnumfailures);
  if (parser_i_minnumfailures < 1)
  {
	print_err(1, "Invalid minnumfailures specified in %s line %d (must be >= 1)",
		current_parsing_filename, line_no);
	parser_i_minnumfailures = 1;
  }
  if (debug)
    print_err(0, "minnumfailures : %s/%d ", parser_minnumfailures, parser_i_minnumfailures);

};

config\ flaptime\ [^;]+;          {
  /* Search for extra newlines that are not being counted */
  fixup_lineno();

  parser_pos1 = strrchr( yytext, ' ' );
  if (parser_pos1 == NULL)
  {
	print_err(1, "missing space/value on line %d in %s", line_no, current_parsing_filename);
	break;
  }
  parser_pos1=parser_pos1+1;
  parser_pos2 = strchr( parser_pos1, ';' );
  if (parser_pos2 == NULL)
  {
	print_err(1, "misbalanced quotes on line %d in %s", line_no, current_parsing_filename);
	break;
  }

  if (parser_flaptime != NULL)
  {
        FREE(parser_flaptime);
	parser_i_flaptime = -1;
  }
  parser_flaptime = MALLOC((parser_pos2-parser_pos1)+1, "parse.l:parser_flaptime");

  strncpy( parser_flaptime, parser_pos1, parser_pos2 - parser_pos1 );
  parser_flaptime[ parser_pos2 - parser_pos1 ] = '\0';

  parser_i_flaptime = atol(parser_flaptime);
  if (parser_i_flaptime < 0)
  {
	print_err(1, "Invalid flaptime specified in %s line %d (must be >= 0)",
		current_parsing_filename, line_no);
	parser_i_flaptime = 0;
  }
  if (debug)
    print_err(0, "flaptime : %s/%d ", parser_flaptime, parser_i_flaptime);

};

config\ pmesg\ [^;]+;          {
  /* Search for extra newlines that are not being counted */
  fixup_lineno();

  parser_pos1 = strchr( yytext, '"' );
  if (parser_pos1 == NULL)
  {
	print_err(1, "missing quotes on line %d in %s", line_no, current_parsing_filename);
	break;
  }
  parser_pos1=parser_pos1+1;
  parser_pos2 = strchr( parser_pos1, '"' );
   if (parser_pos2 == NULL)
  {
	print_err(1, "misbalanced quotes on line %d in %s", line_no, current_parsing_filename);
	break;
  }
 if (parser_pmesg != NULL)
  {
        FREE(parser_pmesg);
  }
  parser_pmesg = MALLOC((parser_pos2-parser_pos1)+1, "parse.l:parser_pmesg");

  strncpy( parser_pmesg, parser_pos1, parser_pos2 - parser_pos1 );
  parser_pmesg[ parser_pos2 - parser_pos1 ] = '\0';

  if (debug)
    print_err(0, "global_pmesg : %s", parser_pmesg); 

};

pmesg\ [^;]+;          {
  /* per object pmesg comes after to prevent duplicate match */
  /* Search for extra newlines that are not being counted */
  fixup_lineno();

  parser_pos1 = strchr( yytext, '"' );
  if (parser_pos1 == NULL)
  {
        print_err(1, "missing quotes on line %d in %s", line_no, current_parsing_filename);
        break;
  }
  parser_pos1=parser_pos1+1;
  parser_pos2 = strchr( parser_pos1, '"' );
   if (parser_pos2 == NULL)
  {
        print_err(1, "misbalanced quotes on line %d in %s", line_no, current_parsing_filename);
        break;
  }
 if (parser_obj_pmesg != NULL)  
  {
        FREE(parser_obj_pmesg);
  }
  parser_obj_pmesg = MALLOC((parser_pos2-parser_pos1)+1, "parse.l:parser_obj_pmesg");

  strncpy( parser_obj_pmesg, parser_pos1, parser_pos2 - parser_pos1 );
  parser_obj_pmesg[ parser_pos2 - parser_pos1 ] = '\0';

  if (debug)
    print_err(0, "obj_pmesg : %s", parser_obj_pmesg);

};

config\ (from|sender)\ [^;]+;          {
  /* Search for extra newlines that are not being counted */
  fixup_lineno();

  parser_pos1 = strchr( yytext, '"' );
  if (parser_pos1 == NULL)
  {
	print_err(1, "missing quotes on line %d in %s", line_no, current_parsing_filename);
	break;
  }
  parser_pos1=parser_pos1+1;
  parser_pos2 = strchr( parser_pos1, '"' );
   if (parser_pos2 == NULL)
  {
	print_err(1, "misbalanced quotes on line %d in %s", line_no, current_parsing_filename);
	break;
  }
 if (parser_sender != NULL)
  {
        FREE(parser_sender);
  }
  parser_sender = MALLOC((parser_pos2-parser_pos1)+1, "parse.l:parser_sender");

  strncpy( parser_sender, parser_pos1, parser_pos2 - parser_pos1 );
  parser_sender[ parser_pos2 - parser_pos1 ] = '\0';

  if (debug)
    print_err(0, "sender : %s", parser_sender); 

};

config\ subject\ [^;]+;          {
  /* Search for extra newlines that are not being counted */
  fixup_lineno();

  parser_pos1 = strchr( yytext, '"' );
  if (parser_pos1 == NULL)
  {
	print_err(1, "missing quotes on line %d in %s", line_no, current_parsing_filename);
	break;
  }
  parser_pos1=parser_pos1+1;
  parser_pos2 = strchr( parser_pos1, '"' );
  if (parser_pos2 == NULL)
  {
	print_err(1, "misbalanced quotes on line %d in %s", line_no, current_parsing_filename);
	break;
  }
  if (parser_subject != NULL)
  {
        FREE(parser_subject);
  }
  parser_subject = MALLOC((parser_pos2-parser_pos1)+1, "parse.l:parser_subject");

  strncpy( parser_subject, parser_pos1, parser_pos2 - parser_pos1 );
  parser_subject[ parser_pos2 - parser_pos1 ] = '\0';

  if (debug)
    print_err(0, "subject : %s", parser_subject); 

};

config\ upcolor\ [^;]+;          {
  /* Search for extra newlines that are not being counted */
  fixup_lineno();

  parser_pos1 = strchr( yytext, '"' );
  if (parser_pos1 == NULL)
  {
	print_err(1, "missing quotes on line %d in %s", line_no, current_parsing_filename);
	break;
  }
  parser_pos1=parser_pos1+1;
  parser_pos2 = strchr( parser_pos1, '"' );
  if (parser_pos2 == NULL)
  {
	print_err(1, "misbalanced quotes on line %d in %s", line_no, current_parsing_filename);
	break;
  }
  if (parser_upcolor != NULL)
  {
        FREE(parser_upcolor);
  }
  parser_upcolor = MALLOC((parser_pos2-parser_pos1)+1, "parse.l:parser_upcolor");

  strncpy( parser_upcolor, parser_pos1, parser_pos2 - parser_pos1 );
  parser_upcolor[ parser_pos2 - parser_pos1 ] = '\0';

  if (debug)
    print_err(0, "upcolor : %s", parser_upcolor); 

};


config\ downcolor\ [^;]+;          {
  /* Search for extra newlines that are not being counted */
  fixup_lineno();

  parser_pos1 = strchr( yytext, '"' );
  if (parser_pos1 == NULL)
  {
	print_err(1, "missing quotes on line %d in %s", line_no, current_parsing_filename);
	break;
  }
  parser_pos1=parser_pos1+1;
  parser_pos2 = strchr( parser_pos1, '"' );
  if (parser_pos2 == NULL)
  {
	print_err(1, "misbalanced quotes on line %d in %s", line_no, current_parsing_filename);
	break;
  }
  if (parser_downcolor != NULL)
  {
        FREE(parser_downcolor);
  }
  parser_downcolor = MALLOC((parser_pos2-parser_pos1)+1, "parse.l:parser_downcolor");

  strncpy( parser_downcolor, parser_pos1, parser_pos2 - parser_pos1 );
  parser_downcolor[ parser_pos2 - parser_pos1 ] = '\0';

  if (debug)
    print_err(0, "downcolor : %s", parser_downcolor); 

};


config\ recentcolor\ [^;]+;          {
  /* Search for extra newlines that are not being counted */
  fixup_lineno();

  parser_pos1 = strchr( yytext, '"' );
  if (parser_pos1 == NULL)
  {
	print_err(1, "missing quotes on line %d in %s", line_no, current_parsing_filename);
	break;
  }
  parser_pos1=parser_pos1+1;
  parser_pos2 = strchr( parser_pos1, '"' );
  if (parser_pos2 == NULL)
  {
	print_err(1, "misbalanced quotes on line %d in %s", line_no, current_parsing_filename);
	break;
  }
  if (parser_recentcolor != NULL)
  {
        FREE(parser_recentcolor);
  }
  parser_recentcolor = MALLOC((parser_pos2-parser_pos1)+1, "parse.l:parser_recentcolor");

  strncpy( parser_recentcolor, parser_pos1, parser_pos2 - parser_pos1 );
  parser_recentcolor[ parser_pos2 - parser_pos1 ] = '\0';

  if (debug)
    print_err(0, "recentcolor : %s", parser_recentcolor); 

}

config\ replyto\ [^;]+;          {
  /* Search for extra newlines that are not being counted */
  fixup_lineno();

  parser_pos1 = strchr( yytext, '"' );
  if (parser_pos1 == NULL)
  {
	print_err(1, "missing quotes on line %d in %s", line_no, current_parsing_filename);
	break;
  }
  parser_pos1=parser_pos1+1;
  parser_pos2 = strchr( parser_pos1, '"' );
  if (parser_pos2 == NULL)
  {
	print_err(1, "misbalanced quotes on line %d in %s", line_no, current_parsing_filename);
	break;
  }
  if (parser_replyto != NULL)
  {
        FREE(parser_replyto);
  }
  parser_replyto = MALLOC((parser_pos2-parser_pos1)+1, "parse.l:parser_replyto");

  strncpy( parser_replyto, parser_pos1, parser_pos2 - parser_pos1 );
  parser_replyto[ parser_pos2 - parser_pos1 ] = '\0';

  if (debug)
    print_err(0, "replyto : %s", parser_replyto); 

};

config\ errorsto\ [^;]+;          {
  /* Search for extra newlines that are not being counted */
  fixup_lineno();

  parser_pos1 = strchr( yytext, '"' );
  if (parser_pos1 == NULL)
  {
	print_err(1, "missing quotes on line %d in %s", line_no, current_parsing_filename);
	break;
  }
  parser_pos1=parser_pos1+1;
  parser_pos2 = strchr( parser_pos1, '"' );
  if (parser_pos2 == NULL)
  {
	print_err(1, "misbalanced quotes on line %d in %s", line_no, current_parsing_filename);
	break;
  }
  if (parser_errorsto != NULL)
  {
        FREE(parser_errorsto);
  }
  parser_errorsto = MALLOC((parser_pos2-parser_pos1)+1, "parse.l:parser_errorsto");

  strncpy( parser_errorsto, parser_pos1, parser_pos2 - parser_pos1 );
  parser_errorsto[ parser_pos2 - parser_pos1 ] = '\0';

  if (debug)
    print_err(0, "errorsto : %s", parser_errorsto); 

};

config\ header\ [^;]+;          {
  /* Search for extra newlines that are not being counted */
  fixup_lineno();

  parser_pos1 = strchr( yytext, '"' );
  if (parser_pos1 == NULL)
  {
	print_err(1, "missing quotes on line %d in %s", line_no, current_parsing_filename);
	break;
  }
  parser_pos1=parser_pos1+1;
  parser_pos2 = strchr( parser_pos1, '"' );
  if (parser_pos2 == NULL)
  {
	print_err(1, "misbalanced quotes on line %d in %s", line_no, current_parsing_filename);
	break;
  }
  if (parser_header != NULL)
  {
        FREE(parser_header);
  }
  parser_header = MALLOC((parser_pos2-parser_pos1)+1, "parse.l:parser_header");

  strncpy( parser_header, parser_pos1, parser_pos2 - parser_pos1 );
  parser_header[ parser_pos2 - parser_pos1 ] = '\0';

  if (debug)
    print_err(0, "header : %s", parser_header); 

};

config\ authkey\ [^;]+;          {
  /* Search for extra newlines that are not being counted */
  fixup_lineno();

  parser_pos1 = strchr( yytext, '"' );
  if (parser_pos1 == NULL)
  {
	print_err(1, "missing quotes on line %d in %s", line_no, current_parsing_filename);
	break;
  }
  parser_pos1=parser_pos1+1;
  parser_pos2 = strchr( parser_pos1, '"' );
  if (parser_pos2 == NULL)
  {
	print_err(1, "misbalanced quotes on line %d in %s", line_no, current_parsing_filename);
	break;
  }
  if (parser_authkey != NULL)
  {
        FREE(parser_authkey);
  }
  parser_authkey = MALLOC((parser_pos2-parser_pos1)+1, "parse.l:parser_authkey");

  strncpy( parser_authkey, parser_pos1, parser_pos2 - parser_pos1 );
  parser_authkey[ parser_pos2 - parser_pos1 ] = '\0';

  if (debug)
    print_err(0, "authkey : %s", parser_authkey); 

};

config\ savestate\ [^;]+;          {
  /* Search for extra newlines that are not being counted */
  fixup_lineno();

  parser_pos1 = strchr( yytext, '"' );
  if (parser_pos1 == NULL)
  {
        print_err(1, "missing quotes on line %d in %s", line_no, current_parsing_filename);
        break;
  }
  parser_pos1=parser_pos1+1;
  parser_pos2 = strchr( parser_pos1, '"' );
  if (parser_pos2 == NULL)
  {
        print_err(1, "misbalanced quotes on line %d in %s", line_no, current_parsing_filename);
        break;
  }
  if (parser_savestate != NULL)
  {
        FREE(parser_savestate);
  }
  parser_savestate = MALLOC((parser_pos2-parser_pos1)+1, "parse.l:parser_savestate");

  strncpy( parser_savestate, parser_pos1, parser_pos2 - parser_pos1 );
  parser_savestate[ parser_pos2 - parser_pos1 ] = '\0';

  if (debug)
    print_err(0, "savestate : %s", parser_savestate);

};


port\ [^;]+;          {
  if (parser_name == NULL)
	print_err(1, "WARNING: port specified when not inside an object at line %d", line_no);
  /* Search for extra newlines that are not being counted */
  fixup_lineno();

  parser_pos1 = strchr( yytext, ' ' );
  if (parser_pos1 == NULL)
  {
	print_err(1, "missing space/value on line %d in %s", line_no, current_parsing_filename);
	break;
  }
  parser_pos1=parser_pos1+1;
  parser_pos2 = strchr( parser_pos1, ';' );
  if (parser_pos2 == NULL)
  {
	print_err(1, "misbalanced quotes on line %d in %s", line_no, current_parsing_filename);
	break;
  }

  if (parser_port != NULL)
  {
        FREE(parser_port);
	parser_i_port = -1;
  }
  parser_port = MALLOC((parser_pos2-parser_pos1)+1, "parse.l:parser_port");

  strncpy( parser_port, parser_pos1, parser_pos2 - parser_pos1 );
  parser_port[ parser_pos2 - parser_pos1 ] = '\0';

  parser_i_port = atol(parser_port);
  if (parser_i_port == -1)
  {
	print_err(1, "Invalid port specified in %s line %d",
		current_parsing_filename, line_no);
  }
  if (debug)
    print_err(0, "port : %s/%d ", parser_port, parser_i_port);

}

rtt_threshold\ [^;]+;          {
  if (parser_name == NULL)
	print_err(1, "WARNING: rtt_threshold specified when not inside an object at line %d", line_no);
  fixup_lineno();

  parser_pos1 = strchr( yytext, ' ' );
  if (parser_pos1 == NULL)
  {
	print_err(1, "missing space/value on line %d in %s", line_no, current_parsing_filename);
	break;
  }
  parser_pos1=parser_pos1+1;
  parser_pos2 = strchr( parser_pos1, ';' );
  if (parser_pos2 == NULL)
  {
	print_err(1, "missing semicolon on line %d in %s", line_no, current_parsing_filename);
	break;
  }

  if (parser_rtt_threshold != NULL)
  {
        FREE(parser_rtt_threshold);
  }
  parser_rtt_threshold = MALLOC((parser_pos2-parser_pos1)+1, "parse.l:parser_rtt_threshold");

  strncpy( parser_rtt_threshold, parser_pos1, parser_pos2 - parser_pos1 );
  parser_rtt_threshold[ parser_pos2 - parser_pos1 ] = '\0';

  parser_i_rtt_threshold = atol(parser_rtt_threshold);
  if (debug)
    print_err(0, "rtt_threshold : %s/%d ", parser_rtt_threshold, parser_i_rtt_threshold);

}

jitter_threshold\ [^;]+;          {
  if (parser_name == NULL)
	print_err(1, "WARNING: jitter_threshold specified when not inside an object at line %d", line_no);
  fixup_lineno();

  parser_pos1 = strchr( yytext, ' ' );
  if (parser_pos1 == NULL)
  {
	print_err(1, "missing space/value on line %d in %s", line_no, current_parsing_filename);
	break;
  }
  parser_pos1=parser_pos1+1;
  parser_pos2 = strchr( parser_pos1, ';' );
  if (parser_pos2 == NULL)
  {
	print_err(1, "missing semicolon on line %d in %s", line_no, current_parsing_filename);
	break;
  }

  if (parser_jitter_threshold != NULL)
  {
        FREE(parser_jitter_threshold);
  }
  parser_jitter_threshold = MALLOC((parser_pos2-parser_pos1)+1, "parse.l:parser_jitter_threshold");

  strncpy( parser_jitter_threshold, parser_pos1, parser_pos2 - parser_pos1 );
  parser_jitter_threshold[ parser_pos2 - parser_pos1 ] = '\0';

  parser_i_jitter_threshold = atol(parser_jitter_threshold);
  if (debug)
    print_err(0, "jitter_threshold : %s/%d ", parser_jitter_threshold, parser_i_jitter_threshold);

}

rtt_samples\ [^;]+;          {
  if (parser_name == NULL)
	print_err(1, "WARNING: rtt_samples specified when not inside an object at line %d", line_no);
  fixup_lineno();

  parser_pos1 = strchr( yytext, ' ' );
  if (parser_pos1 == NULL)
  {
	print_err(1, "missing space/value on line %d in %s", line_no, current_parsing_filename);
	break;
  }
  parser_pos1=parser_pos1+1;
  parser_pos2 = strchr( parser_pos1, ';' );
  if (parser_pos2 == NULL)
  {
	print_err(1, "missing semicolon on line %d in %s", line_no, current_parsing_filename);
	break;
  }

  if (parser_rtt_samples != NULL)
  {
        FREE(parser_rtt_samples);
  }
  parser_rtt_samples = MALLOC((parser_pos2-parser_pos1)+1, "parse.l:parser_rtt_samples");

  strncpy( parser_rtt_samples, parser_pos1, parser_pos2 - parser_pos1 );
  parser_rtt_samples[ parser_pos2 - parser_pos1 ] = '\0';

  parser_i_rtt_samples = atol(parser_rtt_samples);
  if (parser_i_rtt_samples < 1)
  {
	print_err(1, "Invalid rtt_samples (must be >= 1) in %s line %d",
		current_parsing_filename, line_no);
	parser_i_rtt_samples = 5;  /* Default to 5 */
  }
  if (debug)
    print_err(0, "rtt_samples : %s/%d ", parser_rtt_samples, parser_i_rtt_samples);

}

desc\ [^;]+;          {
  if (parser_name == NULL)
        print_err(1, "WARNING: description specified when not inside an object at line %d", line_no);
  /* Search for extra newlines that are not being counted */
  fixup_lineno();

  parser_pos1 = strchr( yytext, '"' );
  if (parser_pos1 == NULL)
  {
	print_err(1, "missing quotes on line %d in %s", line_no, current_parsing_filename);
	break;
  }
  parser_pos1=parser_pos1+1;
  parser_pos2 = strchr( parser_pos1, '"' );
  if (parser_pos2 == NULL)
  {
	print_err(1, "misbalanced quotes on line %d in %s", line_no, current_parsing_filename);
	break;
  }
  if (parser_desc != NULL)
  {
        FREE(parser_desc);
  }
  parser_desc = MALLOC((parser_pos2-parser_pos1)+1, "parse.l:parser_desc");

  strncpy( parser_desc, parser_pos1, parser_pos2 - parser_pos1 );
  parser_desc[ parser_pos2 - parser_pos1 ] = '\0';

  if (debug)
    print_err(0, "desc : %s", parser_desc); 

}

group\ [^;]+;          {
  if (parser_name == NULL)
        print_err(1, "WARNING: group specified when not inside an object at line %d", line_no);
  /* Search for extra newlines that are not being counted */
  fixup_lineno();

  parser_pos1 = strchr( yytext, '"' );
  if (parser_pos1 == NULL)
  {
        print_err(1, "missing quotes on line %d in %s", line_no, current_parsing_filename);
        break;
  }
  parser_pos1=parser_pos1+1;
  parser_pos2 = strchr( parser_pos1, '"' );
  if (parser_pos2 == NULL)
  {
        print_err(1, "misbalanced quotes on line %d in %s", line_no, current_parsing_filename);
        break;
  }

  if (parser_group != NULL)
  {
        FREE(parser_group);
  }
  parser_group = MALLOC((parser_pos2-parser_pos1)+1, "parse.l:parser_group");

  strncpy( parser_group, parser_pos1, parser_pos2 - parser_pos1 );
  parser_group[ parser_pos2 - parser_pos1 ] = '\0';


#warning Need to add and store group
	
#ifdef DEBUG
  if (debug)
    print_err(0, "group : %s", parser_group);
#endif /*DEBUG */

}


dns-query\ [^;]+;          {
  if (parser_name == NULL)
        print_err(1, "WARNING: dns-query specified when not inside an object at line %d", line_no);
  /* Search for extra newlines that are not being counted */
  fixup_lineno();

  parser_pos1 = strchr( yytext, '"' );
  if (parser_pos1 == NULL)
  {
        print_err(1, "missing quotes on line %d in %s", line_no, current_parsing_filename);
        break;
  }
  parser_pos1=parser_pos1+1;
  parser_pos2 = strchr( parser_pos1, '"' );
  if (parser_pos2 == NULL)
  {
        print_err(1, "misbalanced quotes on line %d in %s", line_no, current_parsing_filename);
        break;
  }
  if (parser_dns_query != NULL)
  {
        FREE(parser_dns_query);
  }
  parser_dns_query = MALLOC((parser_pos2-parser_pos1)+1, "parse.l:parser_dns_query");

  strncpy( parser_dns_query, parser_pos1, parser_pos2 - parser_pos1 );
  parser_dns_query[ parser_pos2 - parser_pos1 ] = '\0';

  if (debug)
    print_err(0, "dns_query : %s", parser_dns_query);

}


secret\ [^;]+;          {
  if (parser_name == NULL)
        print_err(1, "WARNING: radius secret specified when not inside an object at line %d", line_no);

  /* Search for extra newlines that are not being counted */
  fixup_lineno();

  parser_pos1 = strchr( yytext, '"' );
  if (parser_pos1 == NULL)
  {
	print_err(1, "missing quotes on line %d in %s", line_no, current_parsing_filename);
	break;
  }
  parser_pos1=parser_pos1+1;
  parser_pos2 = strchr( parser_pos1, '"' );
  if (parser_pos2 == NULL)
  {
	print_err(1, "misbalanced quotes on line %d in %s", line_no, current_parsing_filename);
	break;
  }
  if (parser_secret != NULL)
  {
        FREE(parser_secret);
  }
  parser_secret = MALLOC((parser_pos2-parser_pos1)+1, "parse.l:parser_secret");

  strncpy( parser_secret, parser_pos1, parser_pos2 - parser_pos1 );
  parser_secret[ parser_pos2 - parser_pos1 ] = '\0';

  if (debug)
    print_err(0, "radius-secret: %s", parser_secret); 

}

url\ [^;]+;          {
  if (parser_name == NULL)
        print_err(1, "WARNING: url specified when not inside an object at line %d", line_no);

  /* Search for extra newlines that are not being counted */
  fixup_lineno();

  parser_pos1 = strchr( yytext, '"' );
  if (parser_pos1 == NULL)
  {
	print_err(1, "missing quotes on line %d in %s", line_no, current_parsing_filename);
	break;
  }
  parser_pos1=parser_pos1+1;
  parser_pos2 = strchr( parser_pos1, '"' );
  if (parser_pos2 == NULL)
  {
	print_err(1, "misbalanced quotes on line %d in %s", line_no, current_parsing_filename);
	break;
  }
  if (parser_url != NULL)
  {
        FREE(parser_url);
  }
  parser_url = MALLOC((parser_pos2-parser_pos1)+1, "parse.l:parser_url");

  strncpy( parser_url, parser_pos1, parser_pos2 - parser_pos1 );
  parser_url[ parser_pos2 - parser_pos1 ] = '\0';

  if (debug)
    print_err(0, "url : %s", parser_url); 

}

urltext\ [^;]+;          {
  if (parser_name == NULL)
        print_err(1, "WARNING: urltext specified when not inside an object at line %d", line_no);

  /* Search for extra newlines that are not being counted */
  fixup_lineno();

  parser_pos1 = strchr( yytext, '"' );
  if (parser_pos1 == NULL)
  {
	print_err(1, "missing quotes on line %d in %s", line_no, current_parsing_filename);
	break;
  }
  parser_pos1=parser_pos1+1;
  parser_pos2 = strchr( parser_pos1, '"' );
  if (parser_pos2 == NULL)
  {
	print_err(1, "misbalanced quotes on line %d in %s", line_no, current_parsing_filename);
	break;
  }
  if (parser_urltext != NULL)
  {
        FREE(parser_urltext);
  }
  parser_urltext = MALLOC((parser_pos2-parser_pos1)+1, "parse.l:parser_urltext");

  strncpy( parser_urltext, parser_pos1, parser_pos2 - parser_pos1 );
  parser_urltext[ parser_pos2 - parser_pos1 ] = '\0';

  if (debug)
    print_err(0, "urltext : %s", parser_urltext); 

}

password\ [^;]+;          {
  if (parser_name == NULL)
        print_err(1, "WARNING: password specified when not inside an object at line %d", line_no);

  /* Search for extra newlines that are not being counted */
  fixup_lineno();

  parser_pos1 = strchr( yytext, '"' );
  if (parser_pos1 == NULL)
  {
	print_err(1, "missing quotes on line %d in %s", line_no, current_parsing_filename);
	break;
  }
  parser_pos1=parser_pos1+1;
  parser_pos2 = strchr( parser_pos1, '"' );
  if (parser_pos2 == NULL)
  {
	print_err(1, "misbalanced quotes on line %d in %s", line_no, current_parsing_filename);
	break;
  }
  if (parser_password != NULL)
  {
        FREE(parser_password);
  }
  parser_password = MALLOC((parser_pos2-parser_pos1)+1, "parse.l:parser_password");

  strncpy( parser_password, parser_pos1, parser_pos2 - parser_pos1 );
  parser_password[ parser_pos2 - parser_pos1 ] = '\0';

  if (debug)
    print_err(0, "password : %s", parser_password); 

}

username\ [^;]+;          {
  if (parser_name == NULL)
        print_err(1, "WARNING: username specified when not inside an object at line %d", line_no);

  /* Search for extra newlines that are not being counted */
  fixup_lineno();

  parser_pos1 = strchr( yytext, '"' );
  if (parser_pos1 == NULL)
  {
	print_err(1, "missing quotes on line %d in %s", line_no, current_parsing_filename);
	break;
  }
  parser_pos1=parser_pos1+1;
  parser_pos2 = strchr( parser_pos1, '"' );
  if (parser_pos2 == NULL)
  {
	print_err(1, "misbalanced quotes on line %d in %s", line_no, current_parsing_filename);
	break;
  }
  if (parser_username != NULL)
  {
        FREE(parser_username);
  }
  parser_username = MALLOC((parser_pos2-parser_pos1)+1, "parse.l:parser_username");

  strncpy( parser_username, parser_pos1, parser_pos2 - parser_pos1 );
  parser_username[ parser_pos2 - parser_pos1 ] = '\0';

  if (debug)
    print_err(0, "username : %s", parser_username); 

}

community\ [^;]+;          {
  if (parser_name == NULL)
        print_err(1, "WARNING: community specified when not inside an object at line %d", line_no);

  /* Search for extra newlines that are not being counted */
  fixup_lineno();

  parser_pos1 = strchr( yytext, '"' );
  if (parser_pos1 == NULL)
  {
	print_err(1, "missing quotes on line %d in %s", line_no, current_parsing_filename);
	break;
  }
  parser_pos1=parser_pos1+1;
  parser_pos2 = strchr( parser_pos1, '"' );
  if (parser_pos2 == NULL)
  {
	print_err(1, "misbalanced quotes on line %d in %s", line_no, current_parsing_filename);
	break;
  }
  if (parser_community != NULL)
  {
        FREE(parser_community);
  }
  parser_community = MALLOC((parser_pos2-parser_pos1)+1, "parse.l:parser_community");

  strncpy( parser_community, parser_pos1, parser_pos2 - parser_pos1 );
  parser_community[ parser_pos2 - parser_pos1 ] = '\0';

  if (debug)
    print_err(0, "community : %s", parser_community); 

}

oid\ [^;]+;          {
  if (parser_name == NULL)
        print_err(1, "WARNING: oid specified when not inside an object at line %d", line_no);

  /* Search for extra newlines that are not being counted */
  fixup_lineno();

  parser_pos1 = strchr( yytext, '"' );
  if (parser_pos1 == NULL)
  {
	print_err(1, "missing quotes on line %d in %s", line_no, current_parsing_filename);
	break;
  }
  parser_pos1=parser_pos1+1;
  parser_pos2 = strchr( parser_pos1, '"' );
  if (parser_pos2 == NULL)
  {
	print_err(1, "misbalanced quotes on line %d in %s", line_no, current_parsing_filename);
	break;
  }
  if (parser_oid != NULL)
  {
        FREE(parser_oid);
  }
  parser_oid = MALLOC((parser_pos2-parser_pos1)+1, "parse.l:parser_oid");

  strncpy( parser_oid, parser_pos1, parser_pos2 - parser_pos1 );
  parser_oid[ parser_pos2 - parser_pos1 ] = '\0';

  if (debug)
    print_err(0, "oid : %s", parser_oid); 

}

snmp-type\ [^;]+;          {
  if (parser_name == NULL)
        print_err(1, "WARNING: snmp-type specified when not inside an object at line %d", line_no);

  /* Search for extra newlines that are not being counted */
  fixup_lineno();

  parser_pos1 = strchr( yytext, '"' );
  if (parser_pos1 == NULL)
  {
	print_err(1, "missing quotes on line %d in %s", line_no, current_parsing_filename);
	break;
  }
  parser_pos1=parser_pos1+1;
  parser_pos2 = strchr( parser_pos1, '"' );
  if (parser_pos2 == NULL)
  {
	print_err(1, "misbalanced quotes on line %d in %s", line_no, current_parsing_filename);
	break;
  }
  if (parser_snmp_type != NULL)
  {
        FREE(parser_snmp_type);
  }
  parser_snmp_type = MALLOC((parser_pos2-parser_pos1)+1, "parse.l:parser_snmp_type");

  strncpy( parser_snmp_type, parser_pos1, parser_pos2 - parser_pos1 );
  parser_snmp_type[ parser_pos2 - parser_pos1 ] = '\0';

  parser_i_snmp_type = name_to_snmp_type(parser_snmp_type);
  if (parser_i_snmp_type == -1)
  {
        print_err(1, "Invalid type specified in %s line %d",
                current_parsing_filename, line_no);
  }

  if (debug)
    print_err(0, "snmp-type : %s/%d", parser_snmp_type, parser_i_snmp_type); 
}

snmp-high\ [^;]+;          {
  if (parser_name == NULL)
	print_err(1, "WARNING: snmp_high specified when not inside an object at line %d", line_no);
  /* Search for extra newlines that are not being counted */
  fixup_lineno();

  parser_pos1 = strchr( yytext, '"' );
  if (parser_pos1 == NULL)
  {
	print_err(1, "missing space/value on line %d in %s", line_no, current_parsing_filename);
	break;
  }
  parser_pos1=parser_pos1+1;
  parser_pos2 = strchr( parser_pos1, ';' );
  if (parser_pos2 == NULL)
  {
	print_err(1, "misbalanced quotes on line %d in %s", line_no, current_parsing_filename);
	break;
  }

  if (parser_snmp_high != NULL)
  {
        FREE(parser_snmp_high);
	parser_i_snmp_high = -1;
  }
  parser_snmp_high = MALLOC((parser_pos2-parser_pos1)+1, "parse.l:parser_snmp_high");

  strncpy( parser_snmp_high, parser_pos1, parser_pos2 - parser_pos1 );
  parser_snmp_high[ parser_pos2 - parser_pos1 ] = '\0';

  parser_i_snmp_high = atol(parser_snmp_high);
  if (parser_i_snmp_high == -1)
  {
	print_err(1, "Invalid snmp_high specified in %s line %d", 
		current_parsing_filename, line_no);
  }
  if (debug)
    print_err(0, "snmp_high : %s/%d ", parser_snmp_high, parser_i_snmp_high); 

}

snmp-low\ [^;]+;          {
  if (parser_name == NULL)
        print_err(1, "WARNING: snmp_low specified when not inside an object at line %d", line_no);
  /* Search for extra newlines that are not being counted */
  fixup_lineno();

  parser_pos1 = strchr( yytext, '"' );
  if (parser_pos1 == NULL)
  {
        print_err(1, "missing space/value on line %d in %s", line_no, current_parsing_filename);
        break;
  }
  parser_pos1=parser_pos1+1;
  parser_pos2 = strchr( parser_pos1, ';' );
  if (parser_pos2 == NULL)
  {
        print_err(1, "misbalanced quotes on line %d in %s", line_no, current_parsing_filename);
        break;
  }

  if (parser_snmp_low != NULL)
  {
        FREE(parser_snmp_low);
        parser_i_snmp_low = -1;
  }
  parser_snmp_low = MALLOC((parser_pos2-parser_pos1)+1, "parse.l:parser_snmp_low");

  strncpy( parser_snmp_low, parser_pos1, parser_pos2 - parser_pos1 );
  parser_snmp_low[ parser_pos2 - parser_pos1 ] = '\0';

  parser_i_snmp_low = atol(parser_snmp_low);
  if (parser_i_snmp_low == -1)
  {
        print_err(1, "Invalid snmp-low specified in %s line %d",
                current_parsing_filename, line_no);
  }
  if (debug)
    print_err(0, "snmp-low : %s/%d ", parser_snmp_low, parser_i_snmp_low);

}

snmp-rate\ [^;]+;          {
  if (parser_name == NULL)
	print_err(1, "WARNING: snmp_rate specified when not inside an object at line %d", line_no);
  /* Search for extra newlines that are not being counted */
  fixup_lineno();

  parser_pos1 = strchr( yytext, '"' );
  if (parser_pos1 == NULL)
  {
	print_err(1, "missing space/value on line %d in %s", line_no, current_parsing_filename);
	break;
  }
  parser_pos1=parser_pos1+1;
  parser_pos2 = strchr( parser_pos1, ';' );
  if (parser_pos2 == NULL)
  {
	print_err(1, "misbalanced quotes on line %d in %s", line_no, current_parsing_filename);
	break;
  }

  if (parser_snmp_rate != NULL)
  {
        FREE(parser_snmp_rate);
	parser_i_snmp_rate = -1;
  }
  parser_snmp_rate = MALLOC((parser_pos2-parser_pos1)+1, "parse.l:parser_snmp_rate");

  strncpy( parser_snmp_rate, parser_pos1, parser_pos2 - parser_pos1 );
  parser_snmp_rate[ parser_pos2 - parser_pos1 ] = '\0';

  parser_i_snmp_rate = atol(parser_snmp_rate);
  if (parser_i_snmp_rate == -1)
  {
	print_err(1, "Invalid snmp-low specified in %s line %d", 
		current_parsing_filename, line_no);
  }
  if (debug)
    print_err(0, "snmp-rate : %s/%d ", parser_snmp_rate, parser_i_snmp_rate); 

}

snmp-exact\ [^;]+;          {
  if (parser_name == NULL)
	print_err(1, "WARNING: snmp_exact specified when not inside an object at line %d", line_no);
  /* Search for extra newlines that are not being counted */
  fixup_lineno();

  parser_pos1 = strchr( yytext, '"' );
  if (parser_pos1 == NULL)
  {
	print_err(1, "missing space/value on line %d in %s", line_no, current_parsing_filename);
	break;
  }
  parser_pos1=parser_pos1+1;
  parser_pos2 = strchr( parser_pos1, ';' );
  if (parser_pos2 == NULL)
  {
	print_err(1, "misbalanced quotes on line %d in %s", line_no, current_parsing_filename);
	break;
  }

  if (parser_snmp_exact != NULL)
  {
        FREE(parser_snmp_exact);
	parser_i_snmp_exact = -1;
  }
  parser_snmp_exact = MALLOC((parser_pos2-parser_pos1)+1, "parse.l:parser_snmp_exact");

  strncpy( parser_snmp_exact, parser_pos1, parser_pos2 - parser_pos1 );
  parser_snmp_exact[ parser_pos2 - parser_pos1 ] = '\0';

  parser_i_snmp_exact = atol(parser_snmp_exact);
  if (parser_i_snmp_exact == -1)
  {
	print_err(1, "Invalid snmp_exact specified in %s line %d", 
		current_parsing_filename, line_no);
  }
  if (debug)
    print_err(0, "snmp_exact : %s/%d ", parser_snmp_exact, parser_i_snmp_exact);
}

spawn\ [^;]+;         {
  if (parser_name == NULL)
        print_err(1, "WARNING: spawn specified when not inside an object at line %d", line_no);

  /* Search for extra newlines that are not being counted */
  fixup_lineno();

  parser_pos1 = strchr( yytext, '"' );
  if (parser_pos1 == NULL)
  {
	print_err(1, "missing quotes on line %d in %s", line_no, current_parsing_filename);
	break;
  }
  parser_pos1=parser_pos1+1;
  parser_pos2 = strchr( parser_pos1, '"' );
  if (parser_pos2 == NULL)
  {
	print_err(1, "misbalanced quotes on line %d in %s", line_no, current_parsing_filename);
	break;
  }
  if (parser_spawn != NULL)
  {
        FREE(parser_spawn);
  }
  parser_spawn = MALLOC((parser_pos2-parser_pos1)+1, "parse.l:parser_spawn");

  strncpy( parser_spawn, parser_pos1, parser_pos2 - parser_pos1 );
  parser_spawn[ parser_pos2 - parser_pos1 ] = '\0';

  if (debug)
    print_err(0, "spawn : %s", parser_spawn); 
}

contact_on\ [^;]+;       {
  if (parser_name == NULL)
        print_err(1, "WARNING: contact_on specified when not inside an object at line %d", line_no);

  /* Search for extra newlines that are not being counted */
  fixup_lineno();

  parser_pos1 = strchr( yytext, ' ' );
  if (parser_pos1 == NULL)
  {
	print_err(1, "missing space after keyword on line %d in %s", line_no, current_parsing_filename);
	break;
  }
  while (* parser_pos1 && isspace (* parser_pos1))
  	++ parser_pos1;
  parser_pos2 = strchr( parser_pos1, ';' );
  if (parser_pos2 == NULL)
  {
	print_err(1, "misbalanced quotes on line %d in %s", line_no, current_parsing_filename);
	break;
  }
  temp_char = MALLOC((parser_pos2-parser_pos1)+1, "parse.l:parser_when");
  strncpy( temp_char, parser_pos1, parser_pos2 - parser_pos1 );
  temp_char[ parser_pos2 - parser_pos1 ] = '\0';
  if (! strcasecmp (temp_char, "up") ||
    ! strcasecmp (temp_char, "recover"))
	parser_when = SYSM_CONTACT_UP;
  else if (! strcasecmp (temp_char, "down") ||
    ! strcasecmp (temp_char, "fail"))
	parser_when = SYSM_CONTACT_DOWN;
  else if (! strcasecmp (temp_char, "both") ||
    ! strcasecmp (temp_char, "all"))
	parser_when = SYSM_CONTACT_DOWN | SYSM_CONTACT_UP;
  else {
	print_err(1, "incomprehensible service state boundary name on line %d in %s", line_no, current_parsing_filename);
	break;
  }
  if (debug)
    print_err(0, "contact_on : 0x%X", parser_when); 
}

contact\ [^;]+;       {
  if (parser_name == NULL)
        print_err(1, "WARNING: contact specified when not inside an object at line %d", line_no);

  /* Search for extra newlines that are not being counted */
  fixup_lineno();

  parser_pos1 = strchr( yytext, '"' );
  if (parser_pos1 == NULL)
  {
	print_err(1, "missing quotes on line %d in %s", line_no, current_parsing_filename);
	break;
  }
  parser_pos1=parser_pos1+1;
  parser_pos2 = strchr( parser_pos1, '"' );
  if (parser_pos2 == NULL)
  {
	print_err(1, "misbalanced quotes on line %d in %s", line_no, current_parsing_filename);
	break;
  }
  if (parser_contact != NULL)
  {
        FREE(parser_contact);
  }
  parser_contact = MALLOC((parser_pos2-parser_pos1)+1, "parse.l:parser_contact");
  strncpy( parser_contact, parser_pos1, parser_pos2 - parser_pos1 );

  parser_contact[ parser_pos2 - parser_pos1 ] = '\0';
  temp_char = do_set_replace(parser_contact);
  if (temp_char != NULL)
  {
	FREE(parser_contact);
	parser_contact = temp_char;
  }

  if (debug)
    print_err(0, "contact : %s", parser_contact); 
}

child\ [^;]+;         {
  if (parser_name == NULL)
        print_err(1, "WARNING: child specified when not inside an object at line %d", line_no);

  /* Search for extra newlines that are not being counted */
  fixup_lineno();

  parser_pos1 = strchr( yytext, '"' );
  if (parser_pos1 == NULL)
  {
	print_err(1, "missing quotes on line %d in %s", line_no, current_parsing_filename);
	break;
  }
  parser_pos1=parser_pos1+1;
  parser_pos2 = strchr( parser_pos1, '"' );
  if (parser_pos2 == NULL)
  {
	print_err(1, "misbalanced quotes on line %d in %s", line_no, current_parsing_filename);
	break;
  }
  if (parser_child != NULL)
  {
        FREE(parser_child);
  }
  parser_child = MALLOC((parser_pos2-parser_pos1)+1, "parse.l:parser_child");

  strncpy( parser_child, parser_pos1, parser_pos2 - parser_pos1 );
  parser_child[ parser_pos2 - parser_pos1 ] = '\0';

  if (debug)
    print_err(0, "child : %s", parser_child); 
#warning child does not do anything
}


(dep|parent)\ [^;]+;           {
  if (parser_name == NULL)
        print_err(1, "WARNING: dep/parent specified when not inside an object at line %d", line_no);

  /* Search for extra newlines that are not being counted */
  fixup_lineno();

  parser_pos1 = strchr( yytext, '"' );
  if (parser_pos1 == NULL)
  {
	print_err(1, "missing quote on line %d in %s", line_no, current_parsing_filename);
        break;
  }
  parser_pos1 = parser_pos1+1;
  parser_pos2 = strchr( parser_pos1, '"' );
  if (parser_pos2 == NULL)
  {
        print_err(1, "missing close quote on line %d in %s", line_no, current_parsing_filename);
	break;
  }
  parser_dep_tmp = MALLOC(sizeof(struct nei_list), "parser.l:parser_dep");

  /* Extract the textual name and save it */
  parser_dep_tmp->nei_name = MALLOC((parser_pos2-parser_pos1)+1, "parse.l:parser_dep");

  strncpy( parser_dep_tmp->nei_name, parser_pos1, parser_pos2 - parser_pos1 );
  parser_dep_tmp->nei_name[ parser_pos2 - parser_pos1 ] = '\0';

  if (debug)
    print_err(0, "dep : %s", parser_dep_tmp->nei_name); 

  /* Link it in with other elements */
  parser_dep_tmp->next = parser_dep;

  /* move head */
  parser_dep = parser_dep_tmp;
}


page\ [^;]+;          {
  if (parser_name == NULL)
        print_err(1, "WARNING: page specified when not inside an object at line %d", line_no);

  /* Search for extra newlines that are not being counted */
  fixup_lineno();

  parser_pos1 = strchr( yytext, '"' );
  if (parser_pos1 == NULL)
  {
	print_err(1, "missing quotes on line %d in %s", line_no, current_parsing_filename);
	break;
  }
  parser_pos1=parser_pos1+1;
  parser_pos2 = strchr( parser_pos1, '"' );
  if (parser_pos2 == NULL)
  {
	print_err(1, "misbalanced quotes on line %d in %s", line_no, current_parsing_filename);
	break;
  }
  if (parser_pos2 == NULL)
  {
	print_err(1, "misbalanced quotes on line %d in %s", line_no, current_parsing_filename);
	break;
  }
  if (parser_page != NULL)
  {
        FREE(parser_page);
  }
  parser_page = MALLOC((parser_pos2-parser_pos1)+1, "parse.l:parser_page");

  strncpy( parser_page, parser_pos1, parser_pos2 - parser_pos1 );
  parser_page[ parser_pos2 - parser_pos1 ] = '\0';

  if (debug)
    print_err(0, "page : %s", parser_page); 
}

also-notify\ [^;]+;   {
  if (parser_name == NULL)
        print_err(1, "WARNING: also-notify specified when not inside an object at line %d", line_no);

  /* Search for extra newlines that are not being counted */
  fixup_lineno();

  parser_pos1 = strchr( yytext, '"' );
  if (parser_pos1 == NULL)
  {
	print_err(1, "missing quotes on line %d in %s", line_no, current_parsing_filename);
	break;
  }
  parser_pos1=parser_pos1+1;
  parser_pos2 = strchr( parser_pos1, '"' );
  if (parser_pos2 == NULL)
  {
	print_err(1, "misbalanced quotes on line %d in %s", line_no, current_parsing_filename);
	break;
  }
 if (parser_also != NULL)
  {
        FREE(parser_also);
  }
  parser_also = MALLOC((parser_pos2-parser_pos1)+1, "parse.l:parser_name");

  strncpy( parser_also, parser_pos1, parser_pos2 - parser_pos1 );
  parser_also[ parser_pos2 - parser_pos1 ] = '\0';

  if (debug)
    print_err(0, "also-notify : %s", parser_also); 
}


\}{WS}*;                   {
  /* Search for extra newlines that are not being counted */
  fixup_lineno();

  if (debug)
    print_err(0, "close object: %s", yytext);
  add_object();

}

.            {
	print_err(1, "Unknown information %c found in line %s:%d", yytext[0], current_parsing_filename, line_no);
}


%%

/*
 * Log parser error messages for unified format
 */
void parser_error(char *file_name, int cfg_line_no, char *msg)
{
	print_err(1, "%s:%d %s", file_name, cfg_line_no, msg);
}

void open_new_file(char *filename, FILE *current_file)
{
	FILE *local_save;
	FILE *new_file;
	char *save_current_parsing_filename;
	YY_BUFFER_STATE include_stack;
	int templn;
	
	local_save = current_file;
	save_current_parsing_filename = current_parsing_filename;
	include_stack = YY_CURRENT_BUFFER;

	new_file = fopen(filename, "r");
	if (new_file == NULL)
	{
                perror(filename);
                return;
	}
	yyin = new_file;
	yy_switch_to_buffer(yy_create_buffer( yyin, YY_BUF_SIZE ) );
/* 	yyrestart(new_file); */
	templn = line_no;
	line_no = 1;
	current_parsing_filename = filename;

	sysmon_conf_yylex();

	line_no = templn;
	fclose(new_file);
	yy_delete_buffer( YY_CURRENT_BUFFER );

	yyin = local_save;
	yy_switch_to_buffer(include_stack);

	return;
}

/*
 * Fix line number if there is an embedded newline
 *
 */
void fixup_lineno()
{
  int fixup;
  /* Search for extra newlines that are not being counted */

  fixup = str_cnt(yytext, '\n');
  if (fixup)
    print_err(1, "WARNING: Possible missing ; in object between lines %d and %d", line_no, line_no+fixup);

  line_no=line_no+fixup;

}


void add_object()
{
	int valid_obj = 1;
	struct all_elements_list *new_ele = NULL;
	struct my_hostent *hp = NULL;

	if (parser_name == NULL)
	{
		print_err(1, "ending object that was never begun? %d ", 
			line_no);
		valid_obj = 0;
		return;
	}
	if (find_object_by_name(parser_name) != NULL)
	{
		print_err(1, "WARNING: more than one object named %s - Results may not be as expected", parser_name);
	}

	if (parser_ip == NULL)
	{
		print_err(1, "no ip/dns name specified for object %s", 
			parser_name);
		valid_obj = 0;
	}
	hp = my_gethostbyname(parser_ip, -1);
	if (hp == NULL)
	{
		print_err(1, "%s is not a valid dns name, not monitoring", parser_ip);
		valid_obj = 0;
	}

	if (parser_i_type == -1)
	{
		print_err(1, "unable to determine check type for object %s", 
			parser_name);
		valid_obj = 0;
	}
	if (parser_port == NULL)
	{
		if (parser_i_type == SYSM_TYPE_RADIUS)
		{
			parser_i_port = RADIUS_PORTNUM;
		} else {
			parser_i_port = 0;
		}
	}

	if (parser_i_type == SYSM_TYPE_WWW)
	{
		if (parser_url == NULL || parser_urltext == NULL)
		{
			print_err(1, "No url or URLText specified for http check of %s object", parser_name);
			valid_obj=0;
		}
		/* Set default port, unless specified */
		if (parser_port == NULL)
		{
			parser_i_port = 80;
		}
	}
	if ( (parser_i_type == SYSM_TYPE_IMAP) || 
		(parser_i_type == SYSM_TYPE_POP3) ||
		(parser_i_type == SYSM_TYPE_POP2) || 
		(parser_i_type == SYSM_TYPE_RADIUS) )
	{
		if (parser_username == NULL)
		{
			print_err(1, "no username specified for object %s\n",
				parser_name);
			valid_obj = 0;
		}
		if (parser_password == NULL)
		{
			print_err(1, "no password specified for object %s\n",
				parser_name);
			valid_obj = 0;
		}
		if (parser_secret == NULL && 
			parser_i_type == SYSM_TYPE_RADIUS)
		{
			print_err(1, "no radius secret specified for object %s\n",
				parser_name);
			valid_obj = 0;
		}
	}
	if (parser_i_type == SYSM_TYPE_DNS)
	{
		if (parser_dns_query == NULL)
		{
			print_err(1, "no dns-query specified for object %s\n",
				parser_name);
			valid_obj =0;
		}
	}

	if (parser_i_type == SYSM_TYPE_SNMP) 
	{
		if (parser_oid == NULL)
		{
			if (parser_i_snmp_type != SYSM_SNMP_TYPE_REBOOT)
			{
	                        print_err(1, "no oid specified for object %s\n",
					parser_name);
				valid_obj = 0;
			}
		}
		if (parser_i_snmp_type == -1)
		{
			print_err(1, "no (valid) snmp-type for object %s\n", 
				parser_name);
			valid_obj = 0;
		}
		if (parser_community == NULL)
		{
                        print_err(1, "no community specified for object %s\n",
                                parser_name);
                        valid_obj = 0;
		}
	}

	/* should we require a description?  if so, uncomment this:
	if (parser_desc == NULL)
	{
		print_err(1, "no description specified for object %s", 
			parser_name);
		valid_obj = 0;
	}
	 */

	/* not required arguments:
		parser_spawn, parser_contact, parser_dep, parser_page, 
		parser_also 
	 */

	if (valid_obj)
	{
		if (debug)
		{
		  print_err(0, "valid object, so ADDING OBJECT: %s", 
		    parser_name);
		}
		new_ele = MALLOC(sizeof(struct all_elements_list), "parser.l:new_ele");
		new_ele->next = NULL;
		new_ele->value = MALLOC(sizeof(struct graph_elements), "parser.l:new_ele->value");

		/* NULL this out, otherwise we will FREE it above */
		new_ele->value->unique_name = parser_name;
		new_ele->value->tot_nei = 0;
		new_ele->value->num_dep = 0;
		parser_name = NULL;

		new_ele->value->data = MALLOC(sizeof(struct hostinfo), "parser.l:new_ele->value->data");

		/* LOAD DATA into structure */
		new_ele->value->data->hostname = STRDUP(parser_ip, "hostname");
		new_ele->value->data->type = parser_i_type;
		new_ele->value->data->port = parser_i_port;
		new_ele->value->data->reverse = parser_reverse;
		new_ele->value->data->snmp_octets = parser_snmp_octets;
		new_ele->value->data->trap_alert = parser_trap_alert;
		new_ele->value->data->rtt_threshold = parser_i_rtt_threshold;
		new_ele->value->data->jitter_threshold = parser_i_jitter_threshold;
		new_ele->value->data->rtt_samples = parser_i_rtt_samples;
		new_ele->value->data->max_wakeup_retries = 0;  /* 0 = use DEFAULT_MAX_WAKEUP_RETRIES */
		new_ele->value->data->contact_when = parser_when;
		new_ele->value->data->unique_id = gen_unique_id();
		if (parser_desc == NULL)
		{
			print_err(1, "WARNING: object has no descripton near line %d", line_no);
			new_ele->value->data->message = NULL;
		}
		else
			new_ele->value->data->message = STRDUP(parser_desc,"message");
                if (parser_group == NULL)
                {
                        new_ele->value->data->group = NULL;
                }
                else
                        new_ele->value->data->group = STRDUP(parser_group,"group");
		new_ele->value->data->snmp_community = NULL;
		new_ele->value->data->snmp_oid = NULL;
		new_ele->value->data->snmp_oid_sec = NULL;
		new_ele->value->data->snmp_up_msg = NULL;
		new_ele->value->data->snmp_down_msg = NULL;
		if (parser_obj_pmesg != NULL)
		{
			new_ele->value->data->pmesg = STRDUP(parser_obj_pmesg, "obj_pmesg");
		} else {
			new_ele->value->data->pmesg = NULL;
		}
		new_ele->value->data->hdrval = NULL;
		new_ele->value->data->hdr = NULL;
		new_ele->value->data->lastmsgid = NULL;
		new_ele->value->data->lastcheck = 0;
		new_ele->value->data->totaldown = 0;
		new_ele->value->data->totalchecked = 0;
		new_ele->value->data->downct = 0;
		new_ele->value->data->upct = 0;
		new_ele->value->data->next_queuetime = 0;
		new_ele->value->data->contacted = FALSE;
		new_ele->value->data->queued = FALSE;
		new_ele->value->data->trace = FALSE;
		if (parser_queuetime != NULL)
		{
			if (parser_obj_i_queuetime != -1)
			{
				new_ele->value->data->queuetime = parser_obj_i_queuetime;
			} else {
				new_ele->value->data->queuetime = parser_i_queuetime;
			}
		} else {
			if (parser_i_queuetime == -1)
			{
				new_ele->value->data->queuetime = queuetime;
			} else {
				new_ele->value->data->queuetime = parser_i_queuetime;
			}
		}
		if (debug)
		{
			print_err(1, "%s : obj->queuetime = %d / dflt %d",
				new_ele->value->unique_name,
				new_ele->value->data->queuetime, queuetime);
		}

		/* Set per-object pageinterval or use global default */
		if (parser_pageinterval != NULL)
		{
			if (parser_obj_i_pageinterval != -1)
			{
				new_ele->value->data->pageinterval = parser_obj_i_pageinterval;
			} else {
				new_ele->value->data->pageinterval = parser_i_pageinterval;
			}
		} else {
			/* Use -1 to indicate "use global pageinterval" */
			new_ele->value->data->pageinterval = -1;
		}
		if (debug)
		{
			print_err(1, "%s : obj->pageinterval = %d / global %d",
				new_ele->value->unique_name,
				new_ele->value->data->pageinterval, pageinterval);
		}

		new_ele->value->data->lastcontacted = 0;
		new_ele->value->data->send_pings = MAX_TRIES;
		new_ele->value->data->min_pings = MIN_PING_RESP;
		new_ele->value->data->lchecktime = 0;
		new_ele->value->data->check_start = 0;
		new_ele->value->data->deathtime = 0;
		new_ele->value->data->last_up = 0;
		new_ele->value->data->last_recovery = 0;
		new_ele->value->data->system_uptime = 0;

		if (parser_contact != NULL)
		{
			new_ele->value->data->contact = STRDUP(parser_contact,"contact");
			FREE(parser_contact);
			parser_contact = NULL;
		} else {
			new_ele->value->data->contact = NULL;
		}
		if (parser_i_type ==SYSM_TYPE_RADIUS && (parser_secret != NULL))
		{
			new_ele->value->data->secret = STRDUP(parser_secret,"secret");
			FREE(parser_secret);
			parser_secret = NULL;
		} else {
			new_ele->value->data->secret = NULL;
		}
		if (parser_i_type == SYSM_TYPE_PKTLOSS)
		{
			/* Initialize packet loss defaults */
			new_ele->value->data->pktloss_tolerance = 0;  /* Alert on any loss by default */
			new_ele->value->data->pktloss_history_hours = PKTLOSS_DEFAULT_HISTORY;
			new_ele->value->data->pktloss_last_check = 0;
		}
		if (parser_numfailures != NULL)
		{
			if (parser_obj_i_numfailures == -1)
			{
				new_ele->value->data->max_down = parser_i_numfailures;
			} else {
				new_ele->value->data->max_down = parser_obj_i_numfailures;
			}
		} else {
			new_ele->value->data->max_down = numfailures;
		}
		/* clear it since this is a per-obj setting */
		parser_obj_i_numfailures = -1;

		/* If snmp test and configured oid, use it */
		if ((parser_i_type == SYSM_TYPE_SNMP) && (parser_oid != NULL))
		{
			new_ele->value->data->snmp_oid = STRDUP(parser_oid, "OID");
                        FREE(parser_oid);
                        parser_oid = NULL;
		} else {
			new_ele->value->data->snmp_oid = NULL;
		}

		if (parser_snmp_type != NULL)
		{
			new_ele->value->data->snmp_test_type = parser_i_snmp_type;
		}

		if (parser_i_snmp_type == SYSM_SNMP_TYPE_REBOOT)
		{
			if (new_ele->value->data->snmp_oid != NULL)
				FREE(new_ele->value->data->snmp_oid);
			new_ele->value->data->snmp_oid = STRDUP(SNMP_SYSTEM_SYSUPTIME, "uptime oid");
			new_ele->value->data->max_down = 1;
		}
		if (parser_snmp_high != NULL)
		{
			new_ele->value->data->snmp_high = parser_i_snmp_high;
		}
		if (parser_snmp_low != NULL)
		{
			new_ele->value->data->snmp_low = parser_i_snmp_low;
		}
		if (parser_snmp_exact != NULL)
		{
			new_ele->value->data->snmp_exact = parser_i_snmp_exact;
		}
		if (parser_snmp_rate != NULL)
		{
			new_ele->value->data->snmp_rate = parser_i_snmp_rate;
		}


		if (parser_community != NULL)
		{
			new_ele->value->data->snmp_community = STRDUP(parser_community,"community");
                        FREE(parser_community);
                        parser_community = NULL;

		} else {
			new_ele->value->data->snmp_community = NULL;
		}

		if (parser_dns_query != NULL)
		{
			new_ele->value->data->dns_query = STRDUP(parser_dns_query, "new_ele:dns_query");
                        FREE(parser_dns_query);
                        parser_dns_query = NULL;
		} else {
			new_ele->value->data->dns_query = NULL;
		}

		if (parser_username != NULL)
		{
			new_ele->value->data->username = STRDUP(parser_username,"username");
		} else {
			new_ele->value->data->username = NULL;
		}
		if (parser_password != NULL)
		{
			new_ele->value->data->password = STRDUP(parser_password,"password");
                        FREE(parser_password);
                        parser_password = NULL;
		} else {
			new_ele->value->data->password = NULL;
		}
		if (parser_url != NULL)
		{
			new_ele->value->data->url = STRDUP(parser_url,"URL");
			FREE(parser_url);
			parser_url = NULL;
		} else {
			new_ele->value->data->url = NULL;
		}
		if (parser_urltext != NULL)
		{
			new_ele->value->data->url_text = STRDUP(parser_urltext,"URL text");
			FREE(parser_urltext);
			parser_urltext = NULL;
		} else {
			new_ele->value->data->url_text = NULL;
		}
		if (parser_spawn != NULL)
		{
			new_ele->value->data->command = STRDUP(parser_spawn,"spawn command");
			FREE(parser_spawn);
			parser_spawn = NULL;
		} else {
			new_ele->value->data->command = NULL;
		}
		/* Done Loading data */

		/* Count dependencies */
		new_ele->value->num_dep = 0; /* init */
		for (parser_dep_tmp = parser_dep;
			parser_dep_tmp != NULL;
			parser_dep_tmp = parser_dep_tmp->next )
		{
			new_ele->value->num_dep++;
		}

		temp_int = 0;
		if (new_ele->value->num_dep)
		{
			/* XXX/BUG: leaking */
			new_ele->value->dep_txt_name = MALLOC(sizeof(char *) * new_ele->value->num_dep, "nei_txt_name[]");

                	for (parser_dep_tmp = parser_dep;
	                        parser_dep_tmp != NULL;
	                        parser_dep_tmp = parser_dep_tmp->next )
	                {
	                        new_ele->value->dep_txt_name[temp_int] = STRDUP(parser_dep_tmp->nei_name,"NEI name");
				temp_int++;
	                }
		}

		new_ele->value->neighbors = NULL;

		new_ele->value->visit = FALSE;

		/* Perform an insert-new-at-top-addition */
		if (parser_head == NULL)
		{
			parser_head = new_ele;
		} else {
			new_ele->next = parser_head;
			parser_head = new_ele;
		}

	} else {
		print_err(1, "did not add object %s as it was not valid", parser_name);
	}

	if (parser_dep != NULL)
	{
		/* Free parser_dep linked list */
		free_struct_nei_list(parser_dep);
		parser_dep = NULL;
	}
	parser_dep_tmp = NULL;

}

void free_struct_nei_list(struct nei_list *freethis)
{
	struct nei_list *last = NULL;
	struct nei_list *here = NULL;
	
	here = freethis;
	
	while (here != NULL)
	{
		if (last != NULL)
		{
			if (last->nei_name != NULL)
				FREE(last->nei_name);
			FREE(last);
			last = NULL;
		}
		last = here;
		here=here->next;
	}
	if (last != NULL)
	{
		if (last->nei_name != NULL)
			FREE(last->nei_name);
		FREE(last);
	}
}

void initalize_parser()
{
	if (parser_name != NULL)
		FREE(parser_name);
	if (parser_pmesg != NULL)
		FREE(parser_pmesg);
	if (parser_obj_pmesg != NULL)
		FREE(parser_obj_pmesg);
	if (parser_ip != NULL)
		FREE(parser_ip);
	if (parser_root != NULL)
		FREE(parser_root);
	if (parser_type != NULL)
		FREE(parser_type);
	if (parser_port != NULL)
		FREE(parser_port);
	if (parser_numfailures != NULL)
		FREE(parser_numfailures);
	if (parser_desc != NULL)
		FREE(parser_desc);
        if (parser_group != NULL)
                FREE(parser_group);
	if (parser_dns_query != NULL)
		FREE(parser_dns_query);
	if (parser_spawn != NULL)
		FREE(parser_spawn);
	if (parser_contact != NULL)
		FREE(parser_contact);
	if (parser_child != NULL)
		FREE(parser_child);
	if (parser_sender != NULL)
		FREE(parser_sender);
	if (parser_subject != NULL)
		FREE(parser_subject);
	if (parser_upcolor != NULL)
		FREE(parser_upcolor);
	if (parser_downcolor != NULL)
		FREE(parser_downcolor);
	if (parser_recentcolor != NULL)
		FREE(parser_recentcolor);
	if (parser_replyto != NULL)
		FREE(parser_replyto);
	if (parser_errorsto != NULL)
		FREE(parser_errorsto);
	if (parser_header != NULL)
		FREE(parser_header);
	if (parser_authkey != NULL)
		FREE(parser_authkey);
	if (parser_savestate != NULL)
		FREE(parser_savestate);
	if (parser_pidfile != NULL)
		FREE(parser_pidfile);
	if (parser_statusfile != NULL)
		FREE(parser_statusfile);
	if (parser_statustempdir != NULL)
		FREE(parser_statustempdir);
	if (parser_logging != NULL)
		FREE(parser_logging);
	if (parser_page != NULL)
		FREE(parser_page);
	if (parser_also != NULL)
		FREE(parser_also);
	if (parser_secret != NULL)
		FREE(parser_secret);
	if (parser_username != NULL)
		FREE(parser_username);
	if (parser_password != NULL)
		FREE(parser_password);
	if (parser_url != NULL)
		FREE(parser_url);
	if (parser_urltext != NULL)
		FREE(parser_urltext);
	if (parser_include != NULL)
		FREE(parser_include);
	if (parser_queuetime != NULL)
		FREE(parser_queuetime);
	if (parser_dnsexpire != NULL)
		FREE(parser_dnsexpire);
	if (parser_dnslog != NULL)
		FREE(parser_dnslog);
	if (parser_pageinterval != NULL)
		FREE(parser_pageinterval);
	if (parser_maxqueued != NULL)
		FREE(parser_maxqueued);
	if (parser_eq != NULL)
		FREE(parser_eq);
	if (parser_value != NULL)
		FREE(parser_value);
	if (parser_snmp_type != NULL)
		FREE(parser_snmp_type);
	if (parser_snmp_low != NULL)
		FREE(parser_snmp_low);
	if (parser_snmp_high != NULL)
		FREE(parser_snmp_high);
	if (parser_snmp_exact != NULL)
		FREE(parser_snmp_exact);
	if (parser_dateformat != NULL)
		FREE(parser_dateformat);
	if (parser_community != NULL)
		FREE(parser_community);
	if (parser_oid != NULL)
		FREE(parser_community);

/* null stuff out */
	parser_value = NULL;
	parser_eq = NULL;
	parser_name = NULL;
	parser_pmesg = NULL;
	parser_obj_pmesg = NULL;
	parser_ip = NULL;
	parser_root = NULL;
	parser_type = NULL;
	parser_port = NULL;
	parser_i_port = 0;
	parser_numfailures = NULL;
	parser_desc = NULL;
	parser_group = NULL;
	parser_dns_query = NULL;
	parser_spawn = NULL;
	parser_contact = NULL;
	parser_child = NULL;
	parser_sender = NULL;
	parser_subject = NULL;
	parser_upcolor = NULL;
	parser_downcolor = NULL;
	parser_recentcolor = NULL;
	parser_replyto = NULL;
	parser_errorsto = NULL;
	parser_header = NULL;
	parser_authkey = NULL;
	parser_savestate = NULL;
	parser_statusfile = NULL;
	parser_statustempdir = NULL;
	parser_pidfile = STRDUP (PIDFILE, "default PID file name");
	parser_logging = NULL;
	parser_page = NULL;
	parser_also = NULL;
	parser_secret = NULL;
	parser_username = NULL;
	parser_password = NULL;
	parser_url = NULL;
	parser_urltext = NULL;
	parser_include = NULL;
	parser_queuetime = NULL;
	parser_obj_i_queuetime = -1;
	parser_obj_i_pageinterval = -1;
	parser_obj_i_numfailures = -1;
	parser_dnsexpire = NULL;
	parser_dnslog = NULL;
	parser_pageinterval = NULL;
	parser_maxqueued = NULL;
	parser_showupalso = FALSE;
	parser_nologconnects = FALSE;
	parser_nosubject = FALSE;
	parser_catch_snmptrap = 0;
	parser_trap_alert = FALSE;
	parser_rtt_threshold = NULL;
	parser_i_rtt_threshold = 0;
	parser_jitter_threshold = NULL;
	parser_i_jitter_threshold = 0;
	parser_rtt_samples = NULL;
	parser_i_rtt_samples = 5;  /* Default: 5 samples */
	parser_html_refresh = 60;
	parser_snmp_type = NULL;
	parser_snmp_low = NULL;
	parser_snmp_high = NULL;
	parser_snmp_exact = NULL;
	parser_community = NULL;
	parser_oid = NULL;
	parser_dateformat = NULL;
}

void cleanup_after_parser()
{
	/* Same as initalizing the parser currently */

	initalize_parser();
}


void use_logging_now()
{
	facility = parser_logging_fac;
	if (facility == -3)
	{
		if (log_file != NULL)
			FREE(log_file);
		log_file = STRDUP(parser_logging,"log file name");
	}
}

