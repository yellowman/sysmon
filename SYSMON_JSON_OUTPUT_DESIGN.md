# Sysmon JSON Output Mode - Design Document

## Overview

Add a JSON output mode to sysmon that dumps the complete current monitoring state in a structured format. This enables the web UI (and other tools) to consume sysmon data without fragile text parsing.

## Goals

1. **Complete State Export** - All monitoring data in one JSON response
2. **Backwards Compatible** - Keep existing text output for CLI users
3. **Efficient** - Minimal overhead, reuse existing data structures
4. **Extensible** - Easy to add new fields without breaking clients
5. **Real-time** - Reflect current state from the monitoring queue

## Command Protocol

### Text Output (Existing - Keep for CLI)
```
Client: "status\n"
Server: <text output>
```

### JSON Output (New)
```
Client: "status --json\n"
Server: <JSON output>
```

or

```
Client: "json\n"
Server: <JSON output>
```

## JSON Output Format

### Top-Level Structure

```json
{
  "version": "1.0",
  "timestamp": "2025-01-25T10:30:00Z",
  "daemon": {
    "pid": 1234,
    "uptime_seconds": 604800,
    "uptime_human": "7 days, 0 hours",
    "started_at": "2025-01-18T10:30:00Z",
    "config_file": "/etc/sysmon.conf",
    "config_loaded_at": "2025-01-18T10:30:00Z"
  },
  "summary": {
    "total_hosts": 25,
    "total_checks": 87,
    "hosts_by_status": {
      "ok": 22,
      "warning": 0,
      "critical": 3,
      "unknown": 0
    },
    "checks_by_type": {
      "ping": 25,
      "tcp": 32,
      "http": 18,
      "https": 5,
      "smtp": 3,
      "snmp": 4
    },
    "checks_by_status": {
      "ok": 82,
      "warning": 2,
      "critical": 3,
      "pending": 0,
      "timeout": 0
    }
  },
  "hosts": [
    {
      "hostname": "web01.example.com",
      "contact": "admin@example.com",
      "status": "ok",
      "last_check": "2025-01-25T10:29:55Z",
      "next_check": "2025-01-25T10:30:55Z",
      "checks": [
        {
          "id": "ping",
          "type": "ping",
          "status": "ok",
          "interval": 60,
          "timeout": 5,
          "last_run": "2025-01-25T10:29:55Z",
          "next_run": "2025-01-25T10:30:55Z",
          "duration_ms": 12.3,
          "result": {
            "rtt_ms": 12.3,
            "packet_loss": 0
          }
        },
        {
          "id": "http-80",
          "type": "http",
          "status": "ok",
          "interval": 300,
          "timeout": 30,
          "port": 80,
          "last_run": "2025-01-25T10:25:00Z",
          "next_run": "2025-01-25T10:30:00Z",
          "duration_ms": 234.5,
          "result": {
            "status_code": 200,
            "response_time_ms": 234.5,
            "content_length": 4567
          }
        },
        {
          "id": "https-443",
          "type": "https",
          "status": "ok",
          "interval": 300,
          "timeout": 30,
          "port": 443,
          "url": "/health",
          "last_run": "2025-01-25T10:25:00Z",
          "next_run": "2025-01-25T10:30:00Z",
          "duration_ms": 312.1,
          "result": {
            "status_code": 200,
            "response_time_ms": 312.1,
            "ssl_days_remaining": 89
          }
        }
      ],
      "metadata": {
        "description": "Primary web server",
        "trap_alert": true,
        "max_wakeup_retries": 3
      }
    },
    {
      "hostname": "db01.example.com",
      "contact": "dba@example.com",
      "status": "critical",
      "last_check": "2025-01-25T10:29:50Z",
      "next_check": "2025-01-25T10:30:50Z",
      "checks": [
        {
          "id": "tcp-3306",
          "type": "tcp",
          "status": "critical",
          "interval": 60,
          "timeout": 30,
          "port": 3306,
          "last_run": "2025-01-25T10:29:50Z",
          "next_run": "2025-01-25T10:30:50Z",
          "duration_ms": 30000,
          "error": "Connection timeout after 30s",
          "result": null
        }
      ],
      "metadata": {
        "description": "MySQL database server"
      }
    },
    {
      "hostname": "router01.example.com",
      "contact": "netops@example.com",
      "status": "ok",
      "last_check": "2025-01-25T10:29:58Z",
      "next_check": "2025-01-25T10:34:58Z",
      "checks": [
        {
          "id": "ping",
          "type": "ping",
          "status": "ok",
          "interval": 300,
          "timeout": 5,
          "last_run": "2025-01-25T10:29:58Z",
          "next_run": "2025-01-25T10:34:58Z",
          "duration_ms": 8.7,
          "result": {
            "rtt_ms": 8.7,
            "packet_loss": 0
          }
        },
        {
          "id": "snmp",
          "type": "snmp",
          "status": "ok",
          "interval": 300,
          "timeout": 10,
          "oid": ".1.3.6.1.2.1.2.2.1.10.1",
          "community": "public",
          "last_run": "2025-01-25T10:29:58Z",
          "next_run": "2025-01-25T10:34:58Z",
          "duration_ms": 45.2,
          "result": {
            "value": 1234567890,
            "type": "counter64"
          }
        },
        {
          "id": "rtt",
          "type": "rtt",
          "status": "ok",
          "interval": 60,
          "timeout": 30,
          "rtt_threshold": 50,
          "jitter_threshold": 10,
          "samples": 10,
          "last_run": "2025-01-25T10:29:30Z",
          "next_run": "2025-01-25T10:30:30Z",
          "duration_ms": 150.0,
          "result": {
            "rtt_min_ms": 7.2,
            "rtt_avg_ms": 8.5,
            "rtt_max_ms": 11.3,
            "jitter_ms": 2.1,
            "samples": 10
          }
        }
      ],
      "metadata": {
        "description": "Core router",
        "trap_alert": true
      }
    }
  ],
  "alerts": [
    {
      "hostname": "db01.example.com",
      "check": "tcp-3306",
      "status": "critical",
      "message": "Connection timeout after 30s",
      "first_failure": "2025-01-25T10:15:00Z",
      "consecutive_failures": 15,
      "last_notified": "2025-01-25T10:25:00Z",
      "contact": "dba@example.com"
    }
  ],
  "queue": {
    "size": 12,
    "pending": 3,
    "running": 9,
    "max_check_interval": 300,
    "kill_after": 61,
    "warn_after": 45
  },
  "stats": {
    "checks_completed": 45678,
    "checks_failed": 234,
    "checks_timed_out": 12,
    "total_check_time_ms": 123456789,
    "avg_check_time_ms": 2701.6
  }
}
```

### Type-Specific Result Formats

**PING:**
```json
{
  "rtt_ms": 12.3,
  "packet_loss": 0
}
```

**TCP:**
```json
{
  "connected": true,
  "connection_time_ms": 5.2
}
```

**HTTP/HTTPS:**
```json
{
  "status_code": 200,
  "response_time_ms": 234.5,
  "content_length": 4567,
  "ssl_days_remaining": 89  // HTTPS only
}
```

**SMTP:**
```json
{
  "smtp_code": 220,
  "response_time_ms": 123.4,
  "message": "smtp.example.com ESMTP"
}
```

**POP3/IMAP:**
```json
{
  "response_code": "+OK",
  "response_time_ms": 98.7,
  "message": "POP3 ready"
}
```

**DNS:**
```json
{
  "query": "example.com",
  "query_type": "A",
  "response_time_ms": 15.3,
  "answers": [
    "192.0.2.1",
    "192.0.2.2"
  ],
  "authoritative": true
}
```

**SNMP:**
```json
{
  "oid": ".1.3.6.1.2.1.2.2.1.10.1",
  "value": 1234567890,
  "type": "counter64"
}
```

**RTT/Jitter:**
```json
{
  "rtt_min_ms": 7.2,
  "rtt_avg_ms": 8.5,
  "rtt_max_ms": 11.3,
  "jitter_ms": 2.1,
  "samples": 10
}
```

## Implementation in Sysmon

### Location in Code

Add JSON output to the existing client handler in `src/srvclient.c` (or `src/client.c` depending on file organization).

### New Function

```c
/*
 * output_status_json - Output monitoring status in JSON format
 *
 * Walks the monitoring queue and outputs a complete JSON representation
 * of the current monitoring state.
 */
void output_status_json(int fd)
{
    struct monitorent *walker;
    time_t now;
    struct timeval now_tv;
    char timestamp_buf[64];
    char started_buf[64];
    char config_loaded_buf[64];
    int first_host, first_check;
    int host_count = 0;

    time(&now);
    gettimeofday(&now_tv, NULL);

    /* Format timestamps */
    strftime(timestamp_buf, sizeof(timestamp_buf),
             "%Y-%m-%dT%H:%M:%SZ", gmtime(&now));
    strftime(started_buf, sizeof(started_buf),
             "%Y-%m-%dT%H:%M:%SZ", gmtime(&boottime));
    strftime(config_loaded_buf, sizeof(config_loaded_buf),
             "%Y-%m-%dT%H:%M:%SZ", gmtime(&config_load_time));

    /* Write JSON header */
    dprintf(fd, "{\n");
    dprintf(fd, "  \"version\": \"1.0\",\n");
    dprintf(fd, "  \"timestamp\": \"%s\",\n", timestamp_buf);

    /* Daemon info */
    dprintf(fd, "  \"daemon\": {\n");
    dprintf(fd, "    \"pid\": %d,\n", getpid());
    dprintf(fd, "    \"uptime_seconds\": %ld,\n", now - boottime);
    dprintf(fd, "    \"uptime_human\": \"%s\",\n", format_uptime(now - boottime));
    dprintf(fd, "    \"started_at\": \"%s\",\n", started_buf);
    dprintf(fd, "    \"config_file\": \"%s\",\n", configfile);
    dprintf(fd, "    \"config_loaded_at\": \"%s\"\n", config_loaded_buf);
    dprintf(fd, "  },\n");

    /* Summary statistics */
    output_summary_json(fd);

    /* Hosts array */
    dprintf(fd, "  \"hosts\": [\n");

    first_host = 1;
    for (walker = queuehead; walker != NULL; walker = walker->next) {
        if (walker->checkent == NULL) continue;

        if (!first_host) {
            dprintf(fd, ",\n");
        }
        first_host = 0;

        output_host_json(fd, walker);
        host_count++;
    }

    dprintf(fd, "\n  ],\n");

    /* Active alerts */
    output_alerts_json(fd);

    /* Queue stats */
    dprintf(fd, "  \"queue\": {\n");
    dprintf(fd, "    \"size\": %d,\n", numqueued);
    dprintf(fd, "    \"pending\": %d,\n", count_pending_checks());
    dprintf(fd, "    \"running\": %d,\n", count_running_checks());
    dprintf(fd, "    \"max_check_interval\": %d,\n", max_check_interval);
    dprintf(fd, "    \"kill_after\": %d,\n", killafter);
    dprintf(fd, "    \"warn_after\": %d\n", warnafter);
    dprintf(fd, "  },\n");

    /* Stats */
    dprintf(fd, "  \"stats\": {\n");
    dprintf(fd, "    \"checks_completed\": %lu,\n", total_checks_completed);
    dprintf(fd, "    \"checks_failed\": %lu,\n", total_checks_failed);
    dprintf(fd, "    \"checks_timed_out\": %lu\n", total_checks_timedout);
    dprintf(fd, "  }\n");

    dprintf(fd, "}\n");
}

/*
 * output_host_json - Output single host in JSON format
 */
void output_host_json(int fd, struct monitorent *mon)
{
    struct hostinfo *host = mon->checkent;
    char last_check_buf[64];
    char next_check_buf[64];
    const char *status_str;
    int first_check;

    /* Format timestamps */
    format_timestamp(last_check_buf, sizeof(last_check_buf), &mon->lastserv);
    format_next_check(next_check_buf, sizeof(next_check_buf), mon);

    /* Determine host status from check results */
    status_str = get_host_status_string(mon);

    dprintf(fd, "    {\n");
    dprintf(fd, "      \"hostname\": \"%s\",\n", host->hostname);
    dprintf(fd, "      \"contact\": \"%s\",\n",
            host->primarycontact ? host->primarycontact->name : "none");
    dprintf(fd, "      \"status\": \"%s\",\n", status_str);
    dprintf(fd, "      \"last_check\": \"%s\",\n", last_check_buf);
    dprintf(fd, "      \"next_check\": \"%s\",\n", next_check_buf);

    /* Checks array */
    dprintf(fd, "      \"checks\": [\n");

    first_check = 1;

    /* Output each check based on type */
    if (host->pingtype == SYSM_PING) {
        if (!first_check) dprintf(fd, ",\n");
        output_check_json(fd, mon, "ping");
        first_check = 0;
    }

    if (host->tcpport > 0) {
        if (!first_check) dprintf(fd, ",\n");
        output_check_json(fd, mon, "tcp");
        first_check = 0;
    }

    if (host->httptype == SYSM_HTTP || host->httptype == SYSM_HTTPS) {
        if (!first_check) dprintf(fd, ",\n");
        output_check_json(fd, mon,
                         host->httptype == SYSM_HTTPS ? "https" : "http");
        first_check = 0;
    }

    /* ... other check types ... */

    dprintf(fd, "\n      ],\n");

    /* Metadata */
    dprintf(fd, "      \"metadata\": {\n");
    if (host->description) {
        dprintf(fd, "        \"description\": \"%s\",\n", host->description);
    }
    dprintf(fd, "        \"trap_alert\": %s", host->trap_alert ? "true" : "false");
    if (host->max_wakeup_retries > 0) {
        dprintf(fd, ",\n        \"max_wakeup_retries\": %d", host->max_wakeup_retries);
    }
    dprintf(fd, "\n      }\n");

    dprintf(fd, "    }");
}

/*
 * output_check_json - Output single check in JSON format
 */
void output_check_json(int fd, struct monitorent *mon, const char *check_type)
{
    struct hostinfo *host = mon->checkent;
    char last_run_buf[64];
    char next_run_buf[64];
    const char *status_str;
    double duration_ms = 0.0;

    format_timestamp(last_run_buf, sizeof(last_run_buf), &mon->lastserv);
    format_next_check(next_run_buf, sizeof(next_run_buf), mon);

    status_str = get_check_status_string(mon);

    /* Calculate check duration */
    if (mon->checkent->lastchecktime > 0) {
        duration_ms = mon->checkent->lastchecktime * 1000.0;
    }

    dprintf(fd, "        {\n");
    dprintf(fd, "          \"id\": \"%s", check_type);

    /* Add port to ID if applicable */
    if (strcmp(check_type, "tcp") == 0) {
        dprintf(fd, "-%d", host->tcpport);
    } else if (strcmp(check_type, "http") == 0 || strcmp(check_type, "https") == 0) {
        dprintf(fd, "-%d", host->httpport);
    }

    dprintf(fd, "\",\n");
    dprintf(fd, "          \"type\": \"%s\",\n", check_type);
    dprintf(fd, "          \"status\": \"%s\",\n", status_str);
    dprintf(fd, "          \"interval\": %d,\n", host->queuetime);
    dprintf(fd, "          \"timeout\": %d,\n", host->timeout);

    /* Type-specific fields */
    if (strcmp(check_type, "tcp") == 0) {
        dprintf(fd, "          \"port\": %d,\n", host->tcpport);
    } else if (strcmp(check_type, "http") == 0 || strcmp(check_type, "https") == 0) {
        dprintf(fd, "          \"port\": %d,\n", host->httpport);
        if (host->httpurl) {
            dprintf(fd, "          \"url\": \"%s\",\n", host->httpurl);
        }
    } else if (strcmp(check_type, "snmp") == 0) {
        if (host->snmp_oid) {
            dprintf(fd, "          \"oid\": \"%s\",\n", host->snmp_oid);
        }
        if (host->snmp_community) {
            dprintf(fd, "          \"community\": \"%s\",\n", host->snmp_community);
        }
    } else if (strcmp(check_type, "rtt") == 0) {
        dprintf(fd, "          \"rtt_threshold\": %u,\n", host->rtt_threshold);
        dprintf(fd, "          \"jitter_threshold\": %u,\n", host->jitter_threshold);
        dprintf(fd, "          \"samples\": %u,\n", host->rtt_samples);
    }

    dprintf(fd, "          \"last_run\": \"%s\",\n", last_run_buf);
    dprintf(fd, "          \"next_run\": \"%s\",\n", next_run_buf);
    dprintf(fd, "          \"duration_ms\": %.1f", duration_ms);

    /* Result or error */
    if (mon->retval == SYSM_OK) {
        dprintf(fd, ",\n");
        output_check_result_json(fd, mon, check_type);
    } else if (mon->error_message) {
        dprintf(fd, ",\n");
        dprintf(fd, "          \"error\": \"%s\",\n", mon->error_message);
        dprintf(fd, "          \"result\": null\n");
    } else {
        dprintf(fd, "\n");
    }

    dprintf(fd, "        }");
}

/*
 * output_check_result_json - Output check result based on type
 */
void output_check_result_json(int fd, struct monitorent *mon, const char *check_type)
{
    struct pingdata *ping;
    struct rtt_data *rtt;
    struct snmpdata *snmp;

    dprintf(fd, "          \"result\": {\n");

    if (strcmp(check_type, "ping") == 0) {
        ping = (struct pingdata *)mon->monitordata;
        if (ping) {
            dprintf(fd, "            \"rtt_ms\": %.1f,\n",
                   calculate_rtt_ms(&ping->lastsentat, &mon->lastserv));
            dprintf(fd, "            \"packet_loss\": 0\n");
        }
    } else if (strcmp(check_type, "rtt") == 0) {
        rtt = (struct rtt_data *)mon->monitordata;
        if (rtt) {
            dprintf(fd, "            \"rtt_min_ms\": %.1f,\n", rtt->rtt_min);
            dprintf(fd, "            \"rtt_avg_ms\": %.1f,\n", rtt->rtt_avg);
            dprintf(fd, "            \"rtt_max_ms\": %.1f,\n", rtt->rtt_max);
            dprintf(fd, "            \"jitter_ms\": %.1f,\n", rtt->jitter_current);
            dprintf(fd, "            \"samples\": %u\n", rtt->rtt_count);
        }
    } else if (strcmp(check_type, "http") == 0 || strcmp(check_type, "https") == 0) {
        /* Extract HTTP status code and response time from monitordata */
        dprintf(fd, "            \"status_code\": 200,\n");
        dprintf(fd, "            \"response_time_ms\": %.1f\n",
               mon->checkent->lastchecktime * 1000.0);
    } else if (strcmp(check_type, "snmp") == 0) {
        snmp = (struct snmpdata *)mon->monitordata;
        if (snmp && snmp->snmp_response) {
            dprintf(fd, "            \"value\": %lu,\n", snmp->snmp_retval);
            dprintf(fd, "            \"type\": \"counter\"\n");
        }
    } else if (strcmp(check_type, "tcp") == 0) {
        dprintf(fd, "            \"connected\": true,\n");
        dprintf(fd, "            \"connection_time_ms\": %.1f\n",
               mon->checkent->lastchecktime * 1000.0);
    }

    dprintf(fd, "          }\n");
}

/*
 * output_summary_json - Output summary statistics
 */
void output_summary_json(int fd)
{
    int total_hosts = 0;
    int total_checks = 0;
    int hosts_ok = 0, hosts_warn = 0, hosts_crit = 0;
    int checks_ping = 0, checks_tcp = 0, checks_http = 0;
    int checks_ok = 0, checks_warn = 0, checks_crit = 0;
    struct monitorent *walker;

    /* Count everything */
    for (walker = queuehead; walker != NULL; walker = walker->next) {
        if (walker->checkent == NULL) continue;

        total_hosts++;

        /* Determine host status */
        if (walker->retval == SYSM_OK) {
            hosts_ok++;
        } else if (walker->retval == SYSM_WARNING) {
            hosts_warn++;
        } else {
            hosts_crit++;
        }

        /* Count check types */
        if (walker->checkent->pingtype == SYSM_PING) {
            checks_ping++;
            total_checks++;
            if (walker->retval == SYSM_OK) checks_ok++;
        }

        if (walker->checkent->tcpport > 0) {
            checks_tcp++;
            total_checks++;
        }

        if (walker->checkent->httptype) {
            checks_http++;
            total_checks++;
        }

        /* ... count other types ... */
    }

    dprintf(fd, "  \"summary\": {\n");
    dprintf(fd, "    \"total_hosts\": %d,\n", total_hosts);
    dprintf(fd, "    \"total_checks\": %d,\n", total_checks);

    dprintf(fd, "    \"hosts_by_status\": {\n");
    dprintf(fd, "      \"ok\": %d,\n", hosts_ok);
    dprintf(fd, "      \"warning\": %d,\n", hosts_warn);
    dprintf(fd, "      \"critical\": %d,\n", hosts_crit);
    dprintf(fd, "      \"unknown\": 0\n");
    dprintf(fd, "    },\n");

    dprintf(fd, "    \"checks_by_type\": {\n");
    dprintf(fd, "      \"ping\": %d,\n", checks_ping);
    dprintf(fd, "      \"tcp\": %d,\n", checks_tcp);
    dprintf(fd, "      \"http\": %d\n", checks_http);
    dprintf(fd, "    },\n");

    dprintf(fd, "    \"checks_by_status\": {\n");
    dprintf(fd, "      \"ok\": %d,\n", checks_ok);
    dprintf(fd, "      \"warning\": %d,\n", checks_warn);
    dprintf(fd, "      \"critical\": %d\n", checks_crit);
    dprintf(fd, "    }\n");

    dprintf(fd, "  },\n");
}

/*
 * output_alerts_json - Output active alerts
 */
void output_alerts_json(int fd)
{
    struct monitorent *walker;
    int first_alert = 1;
    char first_fail_buf[64];
    char last_notified_buf[64];

    dprintf(fd, "  \"alerts\": [\n");

    for (walker = queuehead; walker != NULL; walker = walker->next) {
        if (walker->checkent == NULL) continue;
        if (walker->retval == SYSM_OK) continue;  /* Only failures */

        if (!first_alert) {
            dprintf(fd, ",\n");
        }
        first_alert = 0;

        format_timestamp(first_fail_buf, sizeof(first_fail_buf),
                        &walker->first_failure_time);
        format_timestamp(last_notified_buf, sizeof(last_notified_buf),
                        &walker->last_notify_time);

        dprintf(fd, "    {\n");
        dprintf(fd, "      \"hostname\": \"%s\",\n", walker->checkent->hostname);
        dprintf(fd, "      \"check\": \"%s\",\n", get_check_type_string(walker));
        dprintf(fd, "      \"status\": \"%s\",\n", get_check_status_string(walker));
        if (walker->error_message) {
            dprintf(fd, "      \"message\": \"%s\",\n", walker->error_message);
        }
        dprintf(fd, "      \"first_failure\": \"%s\",\n", first_fail_buf);
        dprintf(fd, "      \"consecutive_failures\": %d,\n", walker->consecutive_failures);
        dprintf(fd, "      \"last_notified\": \"%s\",\n", last_notified_buf);
        dprintf(fd, "      \"contact\": \"%s\"\n",
               walker->checkent->primarycontact ?
               walker->checkent->primarycontact->name : "none");
        dprintf(fd, "    }");
    }

    dprintf(fd, "\n  ],\n");
}
```

### Integration with Existing Client Handler

In `src/srvclient.c` (or similar), update the command handler:

```c
void handle_client_command(int client_fd, char *command)
{
    char *cmd = strtok(command, " \n");

    if (cmd == NULL) {
        return;
    }

    /* Check for JSON flag */
    char *flag = strtok(NULL, " \n");
    int json_output = 0;

    if (flag != NULL && (strcmp(flag, "--json") == 0 || strcmp(flag, "-j") == 0)) {
        json_output = 1;
    }

    if (strcmp(cmd, "status") == 0) {
        if (json_output) {
            output_status_json(client_fd);
        } else {
            output_status_text(client_fd);  /* Existing function */
        }
    } else if (strcmp(cmd, "json") == 0) {
        /* Shorthand for "status --json" */
        output_status_json(client_fd);
    } else if (strcmp(cmd, "help") == 0) {
        dprintf(client_fd, "Commands:\n");
        dprintf(client_fd, "  status          - Show status (text format)\n");
        dprintf(client_fd, "  status --json   - Show status (JSON format)\n");
        dprintf(client_fd, "  json            - Show status (JSON format)\n");
        dprintf(client_fd, "  quit            - Close connection\n");
    }
    /* ... other commands ... */
}
```

## Updated Web UI Design

### Go Backend - Simplified Status Service

```go
package service

import (
    "encoding/json"
    "fmt"
    "net"
    "time"
)

type StatusService struct {
    sysmonHost string  // default: "localhost:3355"
}

// SysmonStatus represents the JSON response from sysmon
type SysmonStatus struct {
    Version   string         `json:"version"`
    Timestamp time.Time      `json:"timestamp"`
    Daemon    DaemonInfo     `json:"daemon"`
    Summary   StatusSummary  `json:"summary"`
    Hosts     []HostStatus   `json:"hosts"`
    Alerts    []Alert        `json:"alerts"`
    Queue     QueueStats     `json:"queue"`
    Stats     GlobalStats    `json:"stats"`
}

type DaemonInfo struct {
    PID            int       `json:"pid"`
    UptimeSeconds  int64     `json:"uptime_seconds"`
    UptimeHuman    string    `json:"uptime_human"`
    StartedAt      time.Time `json:"started_at"`
    ConfigFile     string    `json:"config_file"`
    ConfigLoadedAt time.Time `json:"config_loaded_at"`
}

type StatusSummary struct {
    TotalHosts     int            `json:"total_hosts"`
    TotalChecks    int            `json:"total_checks"`
    HostsByStatus  map[string]int `json:"hosts_by_status"`
    ChecksByType   map[string]int `json:"checks_by_type"`
    ChecksByStatus map[string]int `json:"checks_by_status"`
}

type HostStatus struct {
    Hostname  string        `json:"hostname"`
    Contact   string        `json:"contact"`
    Status    string        `json:"status"`
    LastCheck time.Time     `json:"last_check"`
    NextCheck time.Time     `json:"next_check"`
    Checks    []CheckStatus `json:"checks"`
    Metadata  HostMetadata  `json:"metadata"`
}

type CheckStatus struct {
    ID         string                 `json:"id"`
    Type       string                 `json:"type"`
    Status     string                 `json:"status"`
    Interval   int                    `json:"interval"`
    Timeout    int                    `json:"timeout"`
    Port       int                    `json:"port,omitempty"`
    URL        string                 `json:"url,omitempty"`
    LastRun    time.Time              `json:"last_run"`
    NextRun    time.Time              `json:"next_run"`
    DurationMs float64                `json:"duration_ms"`
    Error      string                 `json:"error,omitempty"`
    Result     map[string]interface{} `json:"result"`
}

type HostMetadata struct {
    Description      string `json:"description,omitempty"`
    TrapAlert        bool   `json:"trap_alert"`
    MaxWakeupRetries int    `json:"max_wakeup_retries,omitempty"`
}

type Alert struct {
    Hostname            string    `json:"hostname"`
    Check               string    `json:"check"`
    Status              string    `json:"status"`
    Message             string    `json:"message,omitempty"`
    FirstFailure        time.Time `json:"first_failure"`
    ConsecutiveFailures int       `json:"consecutive_failures"`
    LastNotified        time.Time `json:"last_notified"`
    Contact             string    `json:"contact"`
}

type QueueStats struct {
    Size             int `json:"size"`
    Pending          int `json:"pending"`
    Running          int `json:"running"`
    MaxCheckInterval int `json:"max_check_interval"`
    KillAfter        int `json:"kill_after"`
    WarnAfter        int `json:"warn_after"`
}

type GlobalStats struct {
    ChecksCompleted uint64  `json:"checks_completed"`
    ChecksFailed    uint64  `json:"checks_failed"`
    ChecksTimedOut  uint64  `json:"checks_timed_out"`
}

// GetStatus gets JSON status from sysmon daemon
func (s *StatusService) GetStatus() (*SysmonStatus, error) {
    // Connect to sysmon client port
    conn, err := net.DialTimeout("tcp", s.sysmonHost, 5*time.Second)
    if err != nil {
        return nil, fmt.Errorf("failed to connect to sysmon: %w", err)
    }
    defer conn.Close()

    // Send JSON command
    _, err = fmt.Fprintf(conn, "json\n")
    if err != nil {
        return nil, fmt.Errorf("failed to send command: %w", err)
    }

    // Decode JSON response directly
    var status SysmonStatus
    decoder := json.NewDecoder(conn)
    if err := decoder.Decode(&status); err != nil {
        return nil, fmt.Errorf("failed to decode JSON: %w", err)
    }

    // Add color coding for frontend
    s.addColorCoding(&status)

    return &status, nil
}

// addColorCoding adds status_color fields for frontend display
func (s *StatusService) addColorCoding(status *SysmonStatus) {
    for i := range status.Hosts {
        host := &status.Hosts[i]

        // Host-level color
        switch host.Status {
        case "ok":
            host.StatusColor = "green"
        case "warning":
            host.StatusColor = "yellow"
        case "critical":
            host.StatusColor = "red"
        default:
            host.StatusColor = "gray"
        }

        // Check-level colors
        for j := range host.Checks {
            check := &host.Checks[j]

            switch check.Status {
            case "ok":
                check.StatusColor = "green"
            case "warning":
                check.StatusColor = "yellow"
            case "critical":
                check.StatusColor = "red"
            default:
                check.StatusColor = "gray"
            }
        }
    }
}
```

**Much Simpler!** No text parsing, just deserialize JSON.

## Benefits of JSON Output

1. **Structured Data** - No fragile text parsing
2. **Type Safety** - Direct deserialization into Go structs
3. **Extensible** - Add new fields without breaking clients
4. **Complete State** - All monitoring data in one response
5. **Performance** - No regex parsing, direct JSON decode
6. **Maintainable** - Changes to sysmon output format are explicit
7. **Multiple Consumers** - Any tool can consume JSON (not just web UI)
8. **Backwards Compatible** - Keep text output for CLI users

## CLI Compatibility

The text output remains default for CLI users:

```bash
$ sysmon                          # Text output (existing)
$ sysmon --json                   # JSON output (new)
$ echo "status" | nc localhost 3355         # Text (existing)
$ echo "json" | nc localhost 3355           # JSON (new)
```

## Testing the JSON Output

```bash
# Connect to sysmon and request JSON
$ echo "json" | nc localhost 3355 | jq .

# Pretty-print just the summary
$ echo "json" | nc localhost 3355 | jq .summary

# Get all failing hosts
$ echo "json" | nc localhost 3355 | jq '.hosts[] | select(.status != "ok")'

# Count checks by type
$ echo "json" | nc localhost 3355 | jq '.summary.checks_by_type'
```

## Migration Path

1. **Phase 1** - Add JSON output to sysmon (this design)
2. **Phase 2** - Update web UI to use JSON instead of text parsing
3. **Phase 3** - Keep both outputs indefinitely (backwards compatibility)

## Summary

Adding JSON output mode to sysmon provides:

✅ **Complete state dump** - All monitoring data in one structured response
✅ **No text parsing** - Web UI just deserializes JSON
✅ **Backwards compatible** - Text output remains for CLI users
✅ **Extensible** - Easy to add new fields
✅ **Multiple consumers** - Any tool can use JSON output
✅ **Maintainable** - Changes explicit, not hidden in text format
✅ **Type safe** - Direct mapping to Go/TypeScript structs

The implementation is straightforward - walk the existing monitoring queue and output structured JSON instead of formatted text. The web UI becomes much simpler since it doesn't need text parsing logic.
