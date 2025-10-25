# RTT and Jitter Implementation Design

## Overview

Combined implementation of:
1. **RTT Check** - Measure network latency (ICMP-based)
2. **SAA-lite** - Add jitter measurement for VoIP/quality monitoring

This provides the core value of both WISHLIST items in a practical, integrated solution.

---

## Features

### RTT (Round-Trip Time)
- Measure ICMP echo request/reply latency
- Alert if RTT exceeds threshold
- Rolling average over N samples
- Per-host configuration

### Jitter (Packet Delay Variation)
- Measure variation in RTT between consecutive packets
- Key metric for VoIP quality assessment
- Alert if jitter exceeds threshold
- RFC 3550 algorithm (similar to RTP)

### Combined Value
This implements "SAA-lite" - the most valuable SAA metrics without full Cisco IP SLA complexity.

---

## Configuration Syntax

```
object wan-router {
    ip "remote-office.example.com";
    type rtt;
    rtt_threshold 150;      # Alert if RTT > 150ms
    jitter_threshold 30;    # Alert if jitter > 30ms (VoIP quality)
    rtt_samples 5;          # Average over 5 measurements
    contact "netops@example.com";
    desc "Remote office WAN link";
};
```

**Configuration Options:**
- `type rtt` - Enable RTT/jitter monitoring
- `rtt_threshold N` - Max acceptable RTT in milliseconds (required)
- `jitter_threshold N` - Max acceptable jitter in milliseconds (optional)
- `rtt_samples N` - Number of samples for rolling average (default: 5)

---

## Data Structures

### struct rtt_data (src/icmp.c)

```c
struct rtt_data {
    struct pingdata *ping;              /* Reuse existing ICMP infrastructure */

    /* RTT tracking */
    double rtt_current;                  /* Current RTT in milliseconds */
    double rtt_min;                      /* Minimum RTT seen */
    double rtt_max;                      /* Maximum RTT seen */
    double rtt_avg;                      /* Rolling average RTT */
    double rtt_sum;                      /* Sum for averaging */
    unsigned int rtt_count;              /* Number of RTT samples */

    /* Jitter tracking (RFC 3550 algorithm) */
    double jitter_current;               /* Current jitter in milliseconds */
    double rtt_previous;                 /* Previous RTT for jitter calc */

    /* Timing */
    struct timeval last_send_time;       /* When we sent last packet */
};
```

### struct hostinfo additions (src/config.h)

```c
struct hostinfo {
    // ... existing fields ...

    /* RTT/Jitter configuration */
    unsigned int rtt_threshold;          /* Max RTT in ms before alert */
    unsigned int jitter_threshold;       /* Max jitter in ms before alert */
    unsigned int rtt_samples;            /* Number of samples for average */
};
```

---

## Error Codes

### Existing (Reuse)
```c
#define SYSM_RTT_HIGH 16  /* RTT exceeds threshold */
```

### New
```c
#define SYSM_JITTER_HIGH 25  /* Jitter exceeds threshold */
```

### Error Strings
```c
case SYSM_RTT_HIGH:
    return "RTT too high";
case SYSM_JITTER_HIGH:
    return "Jitter too high";
```

---

## Algorithm

### RTT Calculation

```
1. Send ICMP echo request
2. Record send time: T_send = gettimeofday()
3. Receive ICMP echo reply
4. Record receive time: T_recv = gettimeofday()
5. Calculate: RTT = (T_recv - T_send) in milliseconds
6. Update statistics:
   - rtt_current = RTT
   - rtt_min = min(rtt_min, RTT)
   - rtt_max = max(rtt_max, RTT)
   - rtt_sum += RTT
   - rtt_count++
   - rtt_avg = rtt_sum / rtt_count
```

### Jitter Calculation (RFC 3550)

```
1. Calculate current RTT (as above)
2. Calculate difference from previous:
   D = |RTT_current - RTT_previous|
3. Update jitter (smoothed average):
   jitter = jitter + (D - jitter) / 16
4. Store for next iteration:
   RTT_previous = RTT_current
```

**Why RFC 3550 algorithm?**
- Industry standard (used in RTP/VoIP)
- Smooths out spikes
- Simple to implement
- Matches user expectations

### Threshold Checking

```
After each RTT measurement:

1. Check RTT threshold:
   if (rtt_avg > rtt_threshold) {
       return SYSM_RTT_HIGH;
   }

2. Check jitter threshold (if configured):
   if (jitter_threshold > 0 && jitter_current > jitter_threshold) {
       return SYSM_JITTER_HIGH;
   }

3. If both OK:
   return SYSM_OK;
```

---

## Implementation

### Function Signatures

```c
/* In src/icmp.c */
void start_test_rtt(struct monitorent *here);
void service_test_rtt(struct monitorent *here, struct timeval *now_timeval);
void stop_test_rtt(struct monitorent *here);
double calculate_rtt_ms(struct timeval *send, struct timeval *recv);
void update_jitter(struct rtt_data *data, double rtt);
```

### start_test_rtt()

```c
void start_test_rtt(struct monitorent *here)
{
    struct rtt_data *rttdata;

    /* Check ICMP socket available */
    if (glob_icmp_fd == -1) {
        here->retval = SYSM_OK;
        return;
    }

    /* Allocate RTT tracking structure */
    rttdata = MALLOC(sizeof(struct rtt_data), "rtt_data");
    if (rttdata == NULL) {
        here->retval = SYSM_ERR;
        return;
    }
    memset(rttdata, 0, sizeof(struct rtt_data));

    /* Allocate embedded pingdata */
    rttdata->ping = MALLOC(sizeof(struct pingdata), "rtt_pingdata");
    if (rttdata->ping == NULL) {
        FREE(rttdata);
        here->retval = SYSM_ERR;
        return;
    }
    memset(rttdata->ping, 0, sizeof(struct pingdata));

    /* Initialize statistics */
    rttdata->rtt_min = 999999.0;  /* Large initial value */
    rttdata->rtt_max = 0.0;
    rttdata->rtt_avg = 0.0;
    rttdata->rtt_sum = 0.0;
    rttdata->rtt_count = 0;
    rttdata->jitter_current = 0.0;
    rttdata->rtt_previous = 0.0;

    /* Setup ICMP (similar to PING) */
    setup_ping_packet(rttdata->ping, here);

    /* Send first packet */
    gettimeofday(&rttdata->last_send_time, NULL);
    send_icmp_packet(rttdata->ping, glob_icmp_fd);

    here->monitordata = rttdata;
    here->retval = -1;  /* Pending */
}
```

### service_test_rtt()

```c
void service_test_rtt(struct monitorent *here, struct timeval *now_timeval)
{
    struct rtt_data *rttdata = here->monitordata;
    struct pingdata *ping;
    struct timeval recv_time;
    double rtt_ms;
    int received;

    if (rttdata == NULL) return;

    ping = rttdata->ping;

    /* Check for ICMP reply */
    received = check_icmp_reply(ping, glob_icmp_fd);

    if (received) {
        /* Calculate RTT */
        gettimeofday(&recv_time, NULL);
        rtt_ms = calculate_rtt_ms(&rttdata->last_send_time, &recv_time);

        /* Update RTT statistics */
        rttdata->rtt_current = rtt_ms;
        if (rtt_ms < rttdata->rtt_min) rttdata->rtt_min = rtt_ms;
        if (rtt_ms > rttdata->rtt_max) rttdata->rtt_max = rtt_ms;
        rttdata->rtt_sum += rtt_ms;
        rttdata->rtt_count++;
        rttdata->rtt_avg = rttdata->rtt_sum / rttdata->rtt_count;

        /* Update jitter (if we have previous RTT) */
        if (rttdata->rtt_count > 1) {
            update_jitter(rttdata, rtt_ms);
        }
        rttdata->rtt_previous = rtt_ms;

        /* Check if we have enough samples */
        if (rttdata->rtt_count >= here->checkent->rtt_samples) {
            /* Threshold checking */
            if (rttdata->rtt_avg > here->checkent->rtt_threshold) {
                here->retval = SYSM_RTT_HIGH;
            } else if (here->checkent->jitter_threshold > 0 &&
                       rttdata->jitter_current > here->checkent->jitter_threshold) {
                here->retval = SYSM_JITTER_HIGH;
            } else {
                here->retval = SYSM_OK;
            }

            /* Log statistics */
            if (debug) {
                print_err(1, "RTT stats for %s: avg=%.2fms min=%.2fms max=%.2fms jitter=%.2fms",
                    here->checkent->hostname, rttdata->rtt_avg, rttdata->rtt_min,
                    rttdata->rtt_max, rttdata->jitter_current);
            }

            /* Cleanup */
            FREE(ping->packet);
            FREE(ping);
            FREE(rttdata);
            here->monitordata = NULL;
            return;
        }

        /* Send another packet */
        gettimeofday(&rttdata->last_send_time, NULL);
        send_icmp_packet(ping, glob_icmp_fd);
    }

    /* Check for timeout */
    if (check_timeout(now_timeval, &rttdata->last_send_time, 30)) {
        here->retval = SYSM_TIMEDOUT;
        FREE(ping->packet);
        FREE(ping);
        FREE(rttdata);
        here->monitordata = NULL;
    }
}
```

### Helper Functions

```c
double calculate_rtt_ms(struct timeval *send, struct timeval *recv)
{
    double elapsed;

    elapsed = (recv->tv_sec - send->tv_sec) * 1000.0;
    elapsed += (recv->tv_usec - send->tv_usec) / 1000.0;

    return elapsed;
}

void update_jitter(struct rtt_data *data, double rtt)
{
    double diff;

    /* RFC 3550 jitter calculation */
    diff = fabs(rtt - data->rtt_previous);
    data->jitter_current = data->jitter_current + (diff - data->jitter_current) / 16.0;
}
```

---

## Parser Integration

### src/parser.l additions

```
Add parser variables:
- parser_i_rtt_threshold
- parser_i_jitter_threshold
- parser_i_rtt_samples

Add parser rules for:
- rtt_threshold <number>
- jitter_threshold <number>
- rtt_samples <number>

Initialize in object creation.
```

### src/lib.c

```c
/* In name_to_type() - already exists */
case 3:
    if (strcmp(type, "rtt") == 0 && (!disable_icmp))
        return SYSM_TYPE_PING_LATENCY;  /* Existing type */
```

---

## Integration Points

### src/syswatch.c

Add switch cases:
```c
case SYSM_TYPE_PING_LATENCY:
    start_test_rtt(here);
    break;

case SYSM_TYPE_PING_LATENCY:
    service_test_rtt(here, now_timeval);
    break;

case SYSM_TYPE_PING_LATENCY:
    stop_test_rtt(here);
    break;
```

---

## VoIP Quality Metrics

### Jitter Thresholds (ITU-T G.114)

| Jitter | Quality | Use Case |
|--------|---------|----------|
| < 20ms | Excellent | High-quality VoIP |
| 20-30ms | Good | Acceptable VoIP |
| 30-50ms | Fair | Marginal VoIP |
| > 50ms | Poor | Unacceptable VoIP |

**Recommended:** `jitter_threshold 30` for VoIP monitoring

### RTT Thresholds (ITU-T G.114)

| RTT | Quality | Use Case |
|-----|---------|----------|
| < 150ms | Excellent | Interactive voice |
| 150-300ms | Good | Acceptable for most |
| 300-400ms | Fair | Noticeable delay |
| > 400ms | Poor | Unacceptable |

**Recommended:** `rtt_threshold 150` for VoIP monitoring

---

## Example Configurations

### VoIP Gateway Monitoring

```
object voip-gateway {
    ip "voip.example.com";
    type rtt;
    rtt_threshold 150;      # ITU-T G.114 recommendation
    jitter_threshold 30;    # Max for good VoIP quality
    rtt_samples 10;         # More samples for stable average
    contact "voice-team@example.com";
    desc "Main VoIP gateway";
};
```

### WAN Link Quality

```
object branch-office {
    ip "router.branch.example.com";
    type rtt;
    rtt_threshold 100;      # Strict for business apps
    jitter_threshold 20;    # Low jitter requirement
    rtt_samples 5;
    contact "netops@example.com";
    desc "Branch office WAN link";
};
```

### API Performance

```
object payment-api {
    ip "api.payment.example.com";
    type rtt;
    rtt_threshold 200;      # Acceptable API latency
    contact "api-team@example.com";
    desc "Payment processing API";
};
```
*Note: No jitter_threshold - not relevant for HTTP APIs*

### Database Monitoring

```
object db-server {
    ip "db.example.com";
    type rtt;
    rtt_threshold 50;       # Low latency for queries
    jitter_threshold 10;    # Stable performance
    rtt_samples 5;
    contact "dba-team@example.com";
    desc "Primary database server";
};
```

---

## Alert Messages

### Example Alerts

**RTT Alert:**
```
Subject: sysmon alert - voip-gateway (RTT too high)
From: sysmon@example.com

voip-gateway (voip.example.com) status changed to: RTT too high

Statistics:
  Current RTT: 180.5ms
  Average RTT: 175.2ms (threshold: 150ms)
  Min RTT: 145.0ms
  Max RTT: 210.3ms
  Samples: 10
```

**Jitter Alert:**
```
Subject: sysmon alert - voip-gateway (Jitter too high)
From: sysmon@example.com

voip-gateway (voip.example.com) status changed to: Jitter too high

Statistics:
  Current Jitter: 35.8ms (threshold: 30ms)
  Average RTT: 145.2ms (threshold: 150ms)
  VoIP Quality: POOR - voice quality may be degraded
```

---

## Advantages Over Full SAA

| Feature | Full Cisco SAA | Our Implementation |
|---------|----------------|-------------------|
| RTT | ✅ | ✅ |
| Jitter | ✅ | ✅ |
| Packet Loss | ✅ | ✅ (separate feature) |
| Setup | Complex | Simple keyword |
| Dependencies | Cisco equipment | None |
| Agent Required | Sometimes | No |
| Development Time | N/A (vendor) | 16-20 hours |
| Maintenance | Vendor | Minimal |

**Our advantage:** Simple, integrated, vendor-independent solution with the most valuable metrics.

---

## Testing Plan

1. **Unit Tests:**
   - RTT calculation accuracy
   - Jitter calculation (RFC 3550)
   - Threshold comparison
   - Rolling average

2. **Integration Tests:**
   - ICMP packet send/receive
   - Timeout handling
   - Multiple samples
   - Statistics tracking

3. **Real-world Tests:**
   - Monitor localhost (should be <1ms)
   - Monitor remote host (typical RTT)
   - Monitor unreachable host (timeout)
   - Test threshold alerts

4. **VoIP Scenarios:**
   - Good link: RTT<150ms, jitter<20ms → OK
   - Marginal link: RTT<150ms, jitter=35ms → JITTER_HIGH
   - Poor link: RTT=200ms, jitter=40ms → RTT_HIGH

---

## Future Enhancements

### Phase 2 (Not in this implementation)

- **Packet loss integration:** Combine RTT + jitter + loss = complete quality view
- **Historical tracking:** Store RTT/jitter trends
- **MOS score calculation:** Mean Opinion Score for VoIP
- **Path MTU discovery:** Detect MTU issues
- **Asymmetric delay detection:** Different up/down latency

---

## Implementation Effort

- **RTT measurement:** 8-10 hours
- **Jitter calculation:** 2-3 hours
- **Parser integration:** 2-3 hours
- **Testing:** 2-3 hours
- **Documentation:** 1-2 hours

**Total:** ~16-20 hours

---

## Status

Ready for implementation.
