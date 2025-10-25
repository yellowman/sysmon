# Sysmon XML Output Enhancement Analysis

## Executive Summary

This document analyzes sysmon's internal data structures (C code) and identifies **ALL** information that can be added to XML output for comprehensive monitoring visibility.

## Current XML Output Fields (Baseline)

From `send_object_xml()` in `src/srvclient.c`, currently outputs 50+ fields:

### Basic Object Info
- `<Object>` - Unique object name
- `<HostName>` - Target hostname
- `<ObjectPort>` - Port number
- `<ObjectType>` - Check type (ping, tcp, http, snmp, etc.)
- `<ObjectMessage>` - Outage message
- `<ObjectContact>` - Email contact
- `<ObjectGroup>` - Object group
- `<ObjectNotes>` - User-attached notes

### SNMP-Specific Fields
- `<ObjectSNMPCommunity>` - SNMP community string
- `<ObjectSNMPoid>` - SNMP OID to query
- `<ObjectSNMPType>` - Test type (reboot, high, low, range, exact, rate)
- `<ObjectSNMPLowThresh>` - Low threshold
- `<ObjectSNMPHighThresh>` - High threshold
- `<ObjectSNMPExactThresh>` - Exact value threshold
- `<ObjectSNMPObjectSysUpTime>` - System uptime from SNMP
- `<ObjectSNMPRate>` - Rate threshold (val/sec)
- `<ObjectSNMPOctets>` - Is rate in octets
- `<ObjectSNMPLastResponseTime>` - Last SNMP response time

### Authentication & Headers
- `<ObjectAuthUsername>` - Username for checks (POP3, IMAP, etc.)
- `<ObjectAuthPassword>` - Password for checks
- `<ObjectHeader>` - HTTP header name
- `<ObjectHeaderValue>` - HTTP header value
- `<ObjectRadiusSecret>` - RADIUS secret
- `<ObjectMessageID>` - Message ID
- `<ObjectUniqueID>` - Unique persistent ID

### HTTP/Web Checks
- `<ObjectURL>` - URL for web content check
- `<ObjectURLText>` - Text to find in URL response
- `<ObjectExecCmd>` - Command to run on failure

### Statistics
- `<ObjectTotalChecked>` - Total times checked
- `<ObjectTotalDown>` - Total times down
- `<ObjectDownCt>` - Current consecutive down count
- `<ObjectUpCt>` - Current consecutive up count
- `<ObjectMaxDown>` - Max failures before alert

### Timing & Queue Info
- `<ObjectQueueInterval>` - Check interval in seconds
- `<ObjectLastChecked>` - Time last checked
- `<ObjectCheckStarted>` - Time check started
- `<ObjectOutageTime>` - Time of death (when it went down)
- `<ObjectLastTimeUp>` - Time it last came back up

### Ping Configuration
- `<ObjectSendPings>` - Number of pings to send
- `<ObjectMinPings>` - Minimum pings required for up

### Alert Configuration
- `<ObjectReversed>` - Reverse dependency logic flag
- `<ObjectContacted>` - Has contact been notified
- `<ObjectContactedAt>` - Time contact was notified
- `<ObjectContactOnUp>` - Notify on recovery

### Advanced Monitoring (Recently Added)
- `<ObjectPacketLossThreshold>` - Max packets that can be lost
- `<ObjectRTTThreshold>` - Max RTT in milliseconds
- `<ObjectJitterThreshold>` - Max jitter in milliseconds
- `<ObjectWakeupRetries>` - Max wakeup retry attempts
- `<ObjectTrapAlert>` - Send alert on SNMP trap

### Runtime State
- `<ObjectQueued>` - Is check currently queued
- `<ObjectLastcheckState>` - Last check result (0=OK, 1=connref, etc.)

---

## MISSING DATA - Available But Not in XML

### Category 1: SNMP Extended Configuration

**From:** `struct hostinfo` (config.h:284-381)

| Field | XML Tag (NEW) | Type | Description | Priority |
|-------|--------------|------|-------------|----------|
| `snmp_oid_sec` | `<ObjectSNMPOidSecondary>` | string | Secondary OID for compare checks | HIGH |
| `snmp_up_msg` | `<ObjectSNMPUpMessage>` | string | Custom message when SNMP check recovers | MEDIUM |
| `snmp_down_msg` | `<ObjectSNMPDownMessage>` | string | Custom message when SNMP check fails | MEDIUM |

**Rationale:** SNMP compare checks use two OIDs but only first is exposed. Custom messages provide better alerts.

---

### Category 2: DNS-Specific Configuration

**From:** `struct hostinfo` (config.h:313-314)

| Field | XML Tag (NEW) | Type | Description | Priority |
|-------|--------------|------|-------------|----------|
| `dns_query` | `<ObjectDNSQuery>` | string | Hostname to query in DNS check | HIGH |
| `dns_aa` | `<ObjectDNSRequireAA>` | bool | Require authoritative answer | MEDIUM |
| `dns_recursion` | `<ObjectDNSRecursion>` | bool | Perform recursive query | MEDIUM |

**Rationale:** DNS checks have configuration that's invisible in current XML.

---

### Category 3: Per-Object Custom Messages

**From:** `struct hostinfo` (config.h:300)

| Field | XML Tag (NEW) | Type | Description | Priority |
|-------|--------------|------|-------------|----------|
| `pmesg` | `<ObjectPageMessage>` | string | Custom per-object page message (overrides global) | MEDIUM |

**Rationale:** Objects can have custom page messages that differ from global template.

---

### Category 4: Packet Loss Extended Data

**From:** `struct hostinfo` (config.h:349-351)

| Field | XML Tag (NEW) | Type | Description | Priority |
|-------|--------------|------|-------------|----------|
| `pktloss_history_hours` | `<ObjectPacketLossHistoryHours>` | uint | Hours of history to keep (default 24) | HIGH |
| `pktloss_last_check` | `<ObjectPacketLossLastCheck>` | time_t | Last time packet loss was evaluated | HIGH |

**Rationale:** Important for understanding packet loss monitoring configuration and state.

---

### Category 5: RTT/Jitter Extended Data

**From:** `struct hostinfo` (config.h:354-356)

| Field | XML Tag (NEW) | Type | Description | Priority |
|-------|--------------|------|-------------|----------|
| `rtt_samples` | `<ObjectRTTSamples>` | uint | Number of samples for rolling average | HIGH |

**Rationale:** Critical for understanding how RTT averaging works.

---

### Category 6: Queue Scheduling

**From:** `struct hostinfo` (config.h:342)

| Field | XML Tag (NEW) | Type | Description | Priority |
|-------|--------------|------|-------------|----------|
| `next_queuetime` | `<ObjectNextQueueTime>` | time_t | Next scheduled queue time | CRITICAL |

**Rationale:** Shows when check will next run - essential for debugging scheduling.

---

### Category 7: Debug & Diagnostics

**From:** `struct hostinfo` (config.h:373-374)

| Field | XML Tag (NEW) | Type | Description | Priority |
|-------|--------------|------|-------------|----------|
| `trace` | `<ObjectTraceEnabled>` | bool | Is per-object debugging enabled | CRITICAL |
| `warnlog` | `<ObjectWarnLogDone>` | bool | Has warning been logged | LOW |
| `acked` | `<ObjectAcked>` | bool | Has alert been acknowledged | CRITICAL |

**Rationale:**
- `trace` shows if TRACE is active (critical for UI to display state)
- `acked` shows if someone acknowledged the alert (missing from XML!)

---

### Category 8: Runtime Check State

**From:** `struct monitorent` (config.h:418-434)

| Field | XML Tag (NEW) | Type | Description | Priority |
|-------|--------------|------|-------------|----------|
| `queueat` | `<CheckQueuedAt>` | timeval | Time check was queued | HIGH |
| `lastserv` | `<CheckLastServiced>` | timeval | Time check was last serviced | HIGH |
| `filedes` | `<CheckFileDescriptor>` | int | File descriptor in use (-1 if none) | LOW |
| `started` | `<CheckStarted>` | bool | Has check actually started | MEDIUM |
| `retval` | `<CheckReturnValue>` | int | Return value (-1 if not done) | MEDIUM |
| `wakeup_count` | `<CheckWakeupCount>` | uint | Times woken up (stale check tracking) | HIGH |
| `last_wakeup_time` | `<CheckLastWakeupTime>` | time_t | When last woken up | HIGH |

**Rationale:** Provides deep visibility into runtime check execution state.

**CHALLENGE:** These fields are in `monitorent` (queue entry) not `graph_elements` (config).
- Need to find the monitorent for this object in the queue
- Only available if object is currently queued

---

### Category 9: Packet Loss Historical Data

**From:** `struct pktloss_data` (config.h:272-282)

| Field | XML Tag (NEW) | Type | Description | Priority |
|-------|--------------|------|-------------|----------|
| `history[]` | `<PacketLossHistory>` | array | Array of samples (timestamp, sent, received, lost) | CRITICAL |
| `history_count` | `<PacketLossHistorySamples>` | uint | Number of valid samples | HIGH |
| `total_sent` | `<PacketLossTotalSent>` | uint64 | Running total packets sent | HIGH |
| `total_received` | `<PacketLossTotalReceived>` | uint64 | Running total packets received | HIGH |
| `total_lost` | `<PacketLossTotalLost>` | uint64 | Running total packets lost | HIGH |

**Rationale:** Historical data for packet loss - HUGE value for trending and analysis.

**CHALLENGE:** This data is in `obj->monitordata` which is type `void*` and only valid for PKTLOSS checks.
- Need to cast to `struct pktloss_data*`
- Only available if:
  1. Check type is SYSM_TYPE_PKTLOSS (22)
  2. Check has been run at least once
  3. monitordata is not NULL

---

### Category 10: Global Daemon State

**From:** Global variables in `syswatch.c`

These could be added to a new `<DaemonStatus>` section (separate from object XML):

| Field | XML Tag (NEW) | Type | Description | Priority |
|-------|--------------|------|-------------|----------|
| `boottime` | `<DaemonBootTime>` | time_t | Daemon start time | HIGH |
| `numqueued` | `<DaemonQueuedChecks>` | int | Current queue size | CRITICAL |
| `elements_to_monitor` | `<DaemonTotalObjects>` | ulong | Total objects configured | HIGH |
| `killed` | `<DaemonKilledChecks>` | ushort | Checks killed for timeout | MEDIUM |
| `killafter` | `<DaemonKillAfter>` | ushort | Kill threshold (seconds) | MEDIUM |
| `warnafter` | `<DaemonWarnAfter>` | ushort | Warn threshold (seconds) | MEDIUM |
| `paused` | `<DaemonPaused>` | bool | Is monitoring paused | CRITICAL |
| `debug` | `<DaemonDebug>` | bool | Is debug logging enabled | MEDIUM |

**Rationale:** System-wide state information valuable for dashboard and diagnostics.

**NOTE:** This would enhance the `/api/monitoring/status` endpoint's daemon section.

---

## Implementation Plan

### Phase 1: Easy Additions (Immediate Value)

Add fields from `struct hostinfo` that are always available:

```c
// In send_object_xml() after existing fields:

// SNMP extended
if (obj->data->snmp_oid_sec != NULL) {
    snprintf(buffer, sizeof(buffer), "<%s>%s</%s>",
        "ObjectSNMPOidSecondary", obj->data->snmp_oid_sec, "ObjectSNMPOidSecondary");
    do_send_xml(fd, fh, buffer);
}

// DNS configuration
if (obj->data->dns_query != NULL) {
    snprintf(buffer, sizeof(buffer), "<%s>%s</%s>",
        "ObjectDNSQuery", obj->data->dns_query, "ObjectDNSQuery");
    do_send_xml(fd, fh, buffer);

    snprintf(buffer, sizeof(buffer), "<%s>%d</%s>",
        "ObjectDNSRequireAA", obj->data->dns_aa, "ObjectDNSRequireAA");
    do_send_xml(fd, fh, buffer);

    snprintf(buffer, sizeof(buffer), "<%s>%d</%s>",
        "ObjectDNSRecursion", obj->data->dns_recursion, "ObjectDNSRecursion");
    do_send_xml(fd, fh, buffer);
}

// Per-object custom message
if (obj->data->pmesg != NULL) {
    snprintf(buffer, sizeof(buffer), "<%s>%s</%s>",
        "ObjectPageMessage", obj->data->pmesg, "ObjectPageMessage");
    do_send_xml(fd, fh, buffer);
}

// Packet loss extended
if (obj->data->pktloss_history_hours > 0) {
    snprintf(buffer, sizeof(buffer), "<%s>%u</%s>",
        "ObjectPacketLossHistoryHours", obj->data->pktloss_history_hours,
        "ObjectPacketLossHistoryHours");
    do_send_xml(fd, fh, buffer);
}

if (obj->data->pktloss_last_check > 0) {
    snprintf(buffer, sizeof(buffer), "<%s>%ld</%s>",
        "ObjectPacketLossLastCheck", obj->data->pktloss_last_check,
        "ObjectPacketLossLastCheck");
    do_send_xml(fd, fh, buffer);
}

// RTT samples
if (obj->data->rtt_samples > 0) {
    snprintf(buffer, sizeof(buffer), "<%s>%u</%s>",
        "ObjectRTTSamples", obj->data->rtt_samples, "ObjectRTTSamples");
    do_send_xml(fd, fh, buffer);
}

// Queue scheduling
if (obj->data->next_queuetime > 0) {
    snprintf(buffer, sizeof(buffer), "<%s>%ld</%s>",
        "ObjectNextQueueTime", obj->data->next_queuetime, "ObjectNextQueueTime");
    do_send_xml(fd, fh, buffer);
}

// Debug state
snprintf(buffer, sizeof(buffer), "<%s>%d</%s>",
    "ObjectTraceEnabled", obj->data->trace, "ObjectTraceEnabled");
do_send_xml(fd, fh, buffer);

snprintf(buffer, sizeof(buffer), "<%s>%d</%s>",
    "ObjectAcked", obj->data->acked, "ObjectAcked");
do_send_xml(fd, fh, buffer);
```

**Estimated Lines:** ~60 lines of C code
**Risk:** LOW - All fields always available in `struct hostinfo`
**Value:** HIGH - Exposes configuration and state info

---

### Phase 2: Runtime Check State (Medium Complexity)

Find the `monitorent` for this object and add runtime state:

```c
// In send_object_xml(), after Phase 1 additions:

// Find this object in the queue
extern struct monitorent *queuehead;
struct monitorent *qent = queuehead;
struct monitorent *found_qent = NULL;

while (qent != NULL) {
    if (qent->checkent == obj->data) {
        found_qent = qent;
        break;
    }
    qent = qent->next;
}

if (found_qent != NULL) {
    // Object is currently in queue - add runtime state

    snprintf(buffer, sizeof(buffer), "<%s>%ld.%06ld</%s>",
        "CheckQueuedAt",
        found_qent->queueat.tv_sec, found_qent->queueat.tv_usec,
        "CheckQueuedAt");
    do_send_xml(fd, fh, buffer);

    snprintf(buffer, sizeof(buffer), "<%s>%ld.%06ld</%s>",
        "CheckLastServiced",
        found_qent->lastserv.tv_sec, found_qent->lastserv.tv_usec,
        "CheckLastServiced");
    do_send_xml(fd, fh, buffer);

    snprintf(buffer, sizeof(buffer), "<%s>%d</%s>",
        "CheckFileDescriptor", found_qent->filedes, "CheckFileDescriptor");
    do_send_xml(fd, fh, buffer);

    snprintf(buffer, sizeof(buffer), "<%s>%d</%s>",
        "CheckStarted", found_qent->started, "CheckStarted");
    do_send_xml(fd, fh, buffer);

    if (found_qent->retval != -1) {
        snprintf(buffer, sizeof(buffer), "<%s>%d</%s>",
            "CheckReturnValue", found_qent->retval, "CheckReturnValue");
        do_send_xml(fd, fh, buffer);
    }

    if (found_qent->wakeup_count > 0) {
        snprintf(buffer, sizeof(buffer), "<%s>%u</%s>",
            "CheckWakeupCount", found_qent->wakeup_count, "CheckWakeupCount");
        do_send_xml(fd, fh, buffer);

        snprintf(buffer, sizeof(buffer), "<%s>%ld</%s>",
            "CheckLastWakeupTime", found_qent->last_wakeup_time,
            "CheckLastWakeupTime");
        do_send_xml(fd, fh, buffer);
    }
}
```

**Estimated Lines:** ~50 lines of C code
**Risk:** MEDIUM - Requires queue traversal (but queue is always consistent)
**Value:** HIGH - Shows real-time check execution state

---

### Phase 3: Packet Loss Historical Data (Complex)

Add historical packet loss data for PKTLOSS check types:

```c
// In send_object_xml(), after Phase 2:

// Add packet loss history for PKTLOSS checks
if (obj->data->type == SYSM_TYPE_PKTLOSS && found_qent != NULL &&
    found_qent->monitordata != NULL) {

    struct pktloss_data *pld = (struct pktloss_data *)found_qent->monitordata;

    // Running totals
    snprintf(buffer, sizeof(buffer), "<%s>%llu</%s>",
        "PacketLossTotalSent", pld->total_sent, "PacketLossTotalSent");
    do_send_xml(fd, fh, buffer);

    snprintf(buffer, sizeof(buffer), "<%s>%llu</%s>",
        "PacketLossTotalReceived", pld->total_received, "PacketLossTotalReceived");
    do_send_xml(fd, fh, buffer);

    snprintf(buffer, sizeof(buffer), "<%s>%llu</%s>",
        "PacketLossTotalLost", pld->total_lost, "PacketLossTotalLost");
    do_send_xml(fd, fh, buffer);

    snprintf(buffer, sizeof(buffer), "<%s>%u</%s>",
        "PacketLossHistorySamples", pld->history_count, "PacketLossHistorySamples");
    do_send_xml(fd, fh, buffer);

    // History array
    if (pld->history_count > 0) {
        snprintf(buffer, sizeof(buffer), "<%s>", "PacketLossHistory");
        do_send_xml(fd, fh, buffer);

        // Output up to last 24 hours (or less if not available)
        unsigned int samples_to_output = pld->history_count;
        if (samples_to_output > 1440) samples_to_output = 1440; // Max 24h @ 1min

        for (unsigned int i = 0; i < samples_to_output; i++) {
            // Calculate actual index in circular buffer
            unsigned int idx = (pld->history_head + PKTLOSS_HISTORY_SIZE - samples_to_output + i)
                              % PKTLOSS_HISTORY_SIZE;

            struct pktloss_sample *sample = &pld->history[idx];

            snprintf(buffer, sizeof(buffer),
                "<Sample timestamp=\"%ld\" sent=\"%u\" received=\"%u\" lost=\"%u\"/>",
                sample->timestamp, sample->sent, sample->received, sample->lost);
            do_send_xml(fd, fh, buffer);
        }

        snprintf(buffer, sizeof(buffer), "</%s>", "PacketLossHistory");
        do_send_xml(fd, fh, buffer);
    }
}
```

**Estimated Lines:** ~60 lines of C code
**Risk:** MEDIUM-HIGH - Pointer casting, circular buffer logic
**Value:** CRITICAL - Historical trending data is extremely valuable

---

## XML Tag Definitions to Add

Add to `config.h` after existing XML defines (line 566):

```c
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
#define XML_NEXT_QUEUE_TIME    "ObjectNextQueueTime"
#define XML_TRACE_ENABLED      "ObjectTraceEnabled"
#define XML_ACKED              "ObjectAcked"
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
```

---

## Summary

### Total New Fields: 30+

**By Priority:**
- **CRITICAL (8):** next_queuetime, trace, acked, queue runtime state, packet loss history
- **HIGH (12):** DNS config, SNMP secondary OID, RTT samples, packet loss config/totals
- **MEDIUM (8):** Custom messages, wakeup tracking, check FD state
- **LOW (2):** warnlog, check file descriptor

### Implementation Effort:
- **Phase 1 (Easy):** ~2 hours - 60 lines of code
- **Phase 2 (Medium):** ~3 hours - 50 lines of code
- **Phase 3 (Complex):** ~4 hours - 60 lines of code

**Total:** ~9 hours, ~170 lines of C code

### Risk Assessment:
- Phase 1: LOW risk - straightforward field access
- Phase 2: MEDIUM risk - queue traversal
- Phase 3: MEDIUM-HIGH risk - pointer casting, circular buffer

### Value Delivered:
- **Configuration Visibility:** DNS, SNMP, RTT complete config exposed
- **Runtime Insight:** See exactly what checks are doing RIGHT NOW
- **Historical Data:** Packet loss trending over 24 hours
- **Debug Support:** Trace state, wakeup tracking, queue timing

---

## UI Design Implications

With this comprehensive data, the UI can display:

### Collapsible Sections:
1. **Basic Info** (always visible)
   - Status, hostname, type, contact

2. **Check Configuration** (expandable)
   - Type-specific: SNMP OIDs/thresholds, DNS query, HTTP URL
   - Timing: queue interval, next queue time
   - Ping: send/min pings

3. **Thresholds & Alerts** (expandable)
   - Max down, packet loss tolerance
   - RTT/jitter thresholds
   - Contact settings

4. **Statistics** (expandable with graphs)
   - Total checked/down, up/down counts
   - Packet loss: current % + 24h trend chart
   - RTT: current avg + samples count

5. **Runtime State** (expandable - live data)
   - Is queued, queue position
   - Check started, FD in use
   - Time queued, last serviced
   - Wakeup count (if stale)

6. **Historical Data** (expandable - graphs)
   - Packet loss history: 24h line chart
   - Sent/received/lost over time

7. **Debug & Advanced** (expandable - muted gray)
   - Trace enabled toggle
   - Alert acknowledged
   - Unique ID, custom messages

### Color Coding (Muted Pastels):
- **Status:** Light green (#d1f7d6), light yellow (#fff9c4), light red (#ffcdd2), light orange (#ffe0b2)
- **Sections:** Light blue headers (#e3f2fd)
- **Borders:** Soft gray (#e0e0e0)
- **Rounded corners:** 8-12px border radius
- **Shadows:** Subtle box-shadow for depth

This will look professional, organized, and provide incredible visibility into sysmon's operations!
