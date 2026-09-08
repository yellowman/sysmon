/* All parser-owned state is enumerated once so a rejected reload can
 * restore it without dangling strings or stale per-object settings.
 * This is internal to parser.l; other files use the snapshot API. */
#ifndef SYSMON_PARSER_STATE_H
#define SYSMON_PARSER_STATE_H

#define PARSER_FIELDS(X) \
	X(char *, parser_pos1, NULL, NONE) \
	X(char *, parser_pos2, NULL, NONE) \
	X(char *, parser_name, NULL, STRING) \
	X(char *, parser_pmesg, NULL, STRING) \
	X(char *, parser_obj_pmesg, NULL, STRING) \
	X(char *, parser_ip, NULL, STRING) \
	X(char *, parser_root, NULL, STRING) \
	X(char *, parser_type, NULL, STRING) \
	X(int, parser_i_type, -1, NONE) \
	X(char *, parser_port, NULL, STRING) \
	X(int, parser_i_port, 0, NONE) \
	X(char *, parser_numfailures, NULL, STRING) \
	X(int, parser_i_numfailures, -1, NONE) \
	X(int, parser_obj_i_numfailures, -1, NONE) \
	X(char *, parser_minnumfailures, NULL, STRING) \
	X(int, parser_i_minnumfailures, -1, NONE) \
	X(char *, parser_flaptime, NULL, STRING) \
	X(int, parser_i_flaptime, -1, NONE) \
	X(char *, parser_desc, NULL, STRING) \
	X(char *, parser_group, NULL, STRING) \
	X(char *, parser_dns_query, NULL, STRING) \
	X(bool, parser_dns_aa, FALSE, NONE) \
	X(bool, parser_dns_recursion, FALSE, NONE) \
	X(char *, parser_spawn, NULL, STRING) \
	X(char *, parser_contact, NULL, STRING) \
	X(int, parser_when, SYSM_CONTACT_DOWN | SYSM_CONTACT_UP, NONE) \
	X(char *, parser_child, NULL, STRING) \
	X(int, parser_html_refresh, 60, NONE) \
	X(bool, parser_reverse, FALSE, NONE) \
	X(bool, parser_snmp_octets, FALSE, NONE) \
	X(bool, parser_catch_snmptrap, FALSE, NONE) \
	X(bool, parser_trap_alert, FALSE, NONE) \
	X(char *, parser_rtt_threshold, NULL, STRING) \
	X(int, parser_i_rtt_threshold, RTT_DEFAULT_THRESHOLD_MS, NONE) \
	X(char *, parser_pktloss_tolerance, NULL, STRING) \
	X(int, parser_i_pktloss_tolerance, -1, NONE) \
	X(char *, parser_jitter_threshold, NULL, STRING) \
	X(int, parser_i_jitter_threshold, 0, NONE) \
	X(char *, parser_rtt_samples, NULL, STRING) \
	X(int, parser_i_rtt_samples, 5, NONE) \
	X(char *, parser_rtt_interval, NULL, STRING) \
	X(int, parser_i_rtt_interval, RTT_DEFAULT_INTERVAL_MS, NONE) \
	X(char *, parser_sender, NULL, STRING) \
	X(char *, parser_subject, NULL, STRING) \
	X(char *, parser_upcolor, NULL, STRING) \
	X(char *, parser_downcolor, NULL, STRING) \
	X(char *, parser_recentcolor, NULL, STRING) \
	X(char *, parser_replyto, NULL, STRING) \
	X(char *, parser_errorsto, NULL, STRING) \
	X(char *, parser_header, NULL, STRING) \
	X(char *, parser_authkey, NULL, STRING) \
	X(char *, parser_sitename, NULL, STRING) \
	X(char *, parser_aggregator, NULL, STRING) \
	X(char *, parser_agg_token, NULL, STRING) \
	X(char *, parser_agg_ca, NULL, STRING) \
	X(char *, parser_statedir, NULL, STRING) \
	X(int, parser_listenport, -1, NONE) \
	X(char *, parser_sitedesc, NULL, STRING) \
	X(char *, parser_savestate, NULL, STRING) \
	X(char *, parser_statusfile, NULL, STRING) \
	X(char *, parser_statustempdir, NULL, STRING) \
	X(char *, parser_cssfile, NULL, STRING) \
	X(char *, parser_pidfile, NULL, STRING) \
	X(char *, parser_logging, NULL, STRING) \
	X(int, parser_logging_fac, 0, NONE) \
	X(int, parser_statusfile_type, 0, NONE) \
	X(char *, parser_dateformat, NULL, STRING) \
	X(struct nei_list *, parser_dep, NULL, NEIGHBORS) \
	X(struct nei_list *, parser_dep_tmp, NULL, NONE) \
	X(char *, parser_page, NULL, STRING) \
	X(char *, parser_also, NULL, STRING) \
	X(char *, parser_secret, NULL, STRING) \
	X(char *, parser_username, NULL, STRING) \
	X(char *, parser_community, NULL, STRING) \
	X(char *, parser_oid, NULL, STRING) \
	X(char *, parser_snmp_oid_sec, NULL, STRING) \
	X(char *, parser_snmp_type, NULL, STRING) \
	X(int, parser_snmp_version, SNMP_VERSION_2C, NONE) \
	X(int, parser_i_snmp_type, -1, NONE) \
	X(char *, parser_snmp_low, NULL, STRING) \
	X(char *, parser_snmp_high, NULL, STRING) \
	X(char *, parser_snmp_exact, NULL, STRING) \
	X(char *, parser_snmp_rate, NULL, STRING) \
	X(unsigned long, parser_i_snmp_low, 0, NONE) \
	X(unsigned long, parser_i_snmp_high, 0, NONE) \
	X(unsigned long, parser_i_snmp_exact, 0, NONE) \
	X(unsigned long, parser_i_snmp_rate, 0, NONE) \
	X(char *, parser_password, NULL, STRING) \
	X(char *, parser_url, NULL, STRING) \
	X(char *, parser_urltext, NULL, STRING) \
	X(char *, parser_include, NULL, STRING) \
	X(char *, parser_value, NULL, STRING) \
	X(char *, parser_eq, NULL, STRING) \
	X(int, parser_i_queuetime, -1, NONE) \
	X(int, parser_obj_i_queuetime, -1, NONE) \
	X(char *, parser_queuetime, NULL, STRING) \
	X(int, parser_i_dnsexpire, 0, NONE) \
	X(char *, parser_dnsexpire, NULL, STRING) \
	X(int, parser_i_dnslog, 0, NONE) \
	X(char *, parser_dnslog, NULL, STRING) \
	X(int, parser_i_pageinterval, 0, NONE) \
	X(int, parser_obj_i_pageinterval, -1, NONE) \
	X(char *, parser_pageinterval, NULL, STRING) \
	X(int, parser_i_maxqueued, 0, NONE) \
	X(char *, parser_maxqueued, NULL, STRING) \
	X(int, parser_showupalso, 0, NONE) \
	X(int, parser_nologconnects, 0, NONE) \
	X(int, parser_nosubject, 0, NONE) \
	X(int, temp_int, 0, NONE) \
	X(int, line_no, 0, NONE) \
	X(char *, temp_char, NULL, NONE) \
	X(char *, current_parsing_filename, NULL, NONE) \
	X(bool, parser_in_spawns_block, FALSE, NONE) \
	X(char *, parser_spawn_name, NULL, STRING) \
	X(char *, parser_spawn_command, NULL, STRING) \
	X(bool, parser_heartbeat, TRUE, NONE)

#endif
