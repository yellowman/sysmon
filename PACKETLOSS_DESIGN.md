# Packet Loss Feature - Analysis, Design & Implementation Plan

## Analysis of Existing ICMP Implementation

### Current Ping Infrastructure

**Existing Data Structures:**
```c
struct pingdata {
    struct sockaddr_in *to;
    struct ICMPHDR *icp;
    struct IPHDR *ip;
    int hlen;
    struct my_hostent *hp;
    unsigned char *datap, *packet;
    int counter;
    int ident;
    int packetsent;             // Current: tracks packets sent
    struct sockaddr ping_target;
    unsigned char outpack[128];
    char rcvd_tbl[8192];        // Bit array for tracking received packets
    int nreceived;              // Current: tracks packets received
    struct timeval lastsentat;
} icmp_temp;
```

**Configuration (struct hostinfo):**
```c
unsigned int send_pings;  // Number of pings to send (already exists)
unsigned int min_pings;   // Minimum pings required for "up" (already exists)
```

### Current Behavior

1. **Sends** up to `send_pings` ICMP echo requests
2. **Receives** replies and tracks count in `nreceived`
3. **Decision**: If `nreceived >= min_pings`, mark as UP
4. **Limitation**: Only tracks current check cycle, no history

### Security Issues Found

✅ **Already Fixed** (from previous security work):
- All sprintf → snprintf
- All hardcoded sizes → macros/sizeof()
- MALLOC has NULL checks
- inet_ntoa → inet_ntop

⚠️ **Additional Concerns**:
1. **outpack[128]** - hardcoded size, should use macro
2. **rcvd_tbl[8192]** - hardcoded size, should use macro
3. **No overflow protection** in generate_ident() - just increments forever
4. **Global icmp_temp** - not thread-safe (but sysmon isn't threaded)

---

## Design: Packet Loss Tracking Feature

### Requirements (from WISHLIST)

```
Example config:
far-away-site pktloss 15 1 2 "far-site" mail@site

Parameters:
- 15 pings to send
- 1 minute interval
- 2 tolerance (alert if >2 lost)
- "far-site" group name
- mail@site contact
```

**Functional Requirements:**
1. Send N pings per check (configurable)
2. Track packet loss over 24 hours (configurable)
3. Alert if packet loss exceeds tolerance in a period
4. Report as DOWN if total loss (100%)
5. Maintain per-host history
6. Configurable globally and per-host

### Design Decisions

#### 1. Data Structure Design

**New Type:** `SYSM_TYPE_PKTLOSS` (type 22)

**Enhanced ping configuration (add to struct hostinfo):**
```c
// Packet loss specific fields
unsigned int pktloss_tolerance;     // Max packets that can be lost before alert
unsigned int pktloss_history_hours; // Hours of history to keep (default 24)
time_t pktloss_last_check;          // Last time we evaluated packet loss
```

**Packet Loss History Structure:**
```c
#define PKTLOSS_HISTORY_SIZE 1440  // 24 hours @ 1 minute intervals

struct pktloss_sample {
    time_t timestamp;         // When this sample was taken
    unsigned int sent;        // Packets sent this cycle
    unsigned int received;    // Packets received this cycle
    unsigned int lost;        // Packets lost (sent - received)
};

struct pktloss_data {
    struct pktloss_sample history[PKTLOSS_HISTORY_SIZE];
    unsigned int history_head;     // Circular buffer head index
    unsigned int history_count;    // Number of valid samples
    unsigned long total_sent;      // Running total
    unsigned long total_received;  // Running total
    unsigned long total_lost;      // Running total
};
```

#### 2. History Storage Mechanism

**Circular Buffer:**
- Fixed size: PKTLOSS_HISTORY_SIZE samples
- Each sample = one ping check cycle
- Overwrites oldest when full
- Efficient O(1) insert, O(n) query

**Memory Usage:**
```
sizeof(struct pktloss_sample) = 16 bytes (timestamp + 3 ints)
1440 samples * 16 bytes = 23,040 bytes per host (~23KB)
```

**Storage Location:**
- Allocated in `monitorent->monitordata` (like existing pingdata)
- Persists across check cycles
- Freed when service removed or type changed

#### 3. Tolerance Checking Logic

**Algorithm:**
```
For current check cycle:
1. Send pktloss_send_pings packets
2. Receive and count replies
3. Calculate: lost = sent - received
4. Store in history buffer
5. Check tolerance:
   if (lost > pktloss_tolerance):
       if (lost == sent):  // 100% loss
           status = DOWN (SYSM_UNPINGABLE)
       else:
           status = DEGRADED (new status code)
   else:
       status = OK
```

**Historical Analysis** (optional enhancement):
```
Calculate moving average over last N minutes:
- Count total lost in window
- If avg_loss_rate > threshold%, alert
```

#### 4. Configuration Syntax

**New parser syntax:**
```
object-name pktloss send_count interval tolerance "group" contact
```

**Example:**
```
far-away-site pktloss 15 1 2 "far-site" admin@example.com
```

**Parsed as:**
- hostname: far-away-site
- type: SYSM_TYPE_PKTLOSS (22)
- send_pings: 15
- queuetime: 60 (1 minute = 60 seconds)
- pktloss_tolerance: 2
- group: "far-site"
- contact: admin@example.com

**Backward Compatibility:**
- Existing "ping" type unchanged
- New "pktloss" type for enhanced monitoring
- Shared code where possible

---

## Implementation Plan

### Phase 1: Data Structures (config.h)

```c
// Add to config.h

#define SYSM_TYPE_PKTLOSS 22       // New type constant
#define PKTLOSS_HISTORY_SIZE 1440  // 24 hours @ 1 min intervals
#define PKTLOSS_DEFAULT_HISTORY 24 // Default hours

struct pktloss_sample {
    time_t timestamp;
    unsigned int sent;
    unsigned int received;
    unsigned int lost;
};

struct pktloss_data {
    struct pktloss_sample history[PKTLOSS_HISTORY_SIZE];
    unsigned int history_head;
    unsigned int history_count;
    unsigned long total_sent;
    unsigned long total_received;
    unsigned long total_lost;
};

// Add to struct hostinfo:
unsigned int pktloss_tolerance;
unsigned int pktloss_history_hours;
time_t pktloss_last_check;
```

### Phase 2: Parser Extension (parser.l / parser.c)

Add parsing for:
```
PKTLOSS hostname send_count interval tolerance group contact
```

### Phase 3: ICMP Extension (icmp.c)

**New Functions:**
```c
void start_test_pktloss(struct monitorent *here);
void service_test_pktloss(struct monitorent *here, struct timeval *now);
void stop_test_pktloss(struct monitorent *here);
void pktloss_add_sample(struct pktloss_data *data, time_t ts,
                        unsigned int sent, unsigned int rcvd);
int pktloss_check_tolerance(struct monitorent *here);
```

**Logic:**
1. Reuse existing ping infrastructure (pinger_v4, ICMP socket)
2. Enhanced tracking with history buffer
3. Tolerance checking after each cycle
4. Status reporting (OK, DEGRADED, DOWN)

### Phase 4: Display & Reporting (lib.c, srvclient.c)

**New error string:**
```c
case SYSM_PKTLOSS_EXCEED:
    return "Packet Loss Exceeds Tolerance";
```

**XML output** (for client):
```xml
<pktloss_sent>15</pktloss_sent>
<pktloss_received>12</pktloss_received>
<pktloss_lost>3</pktloss_lost>
<pktloss_rate>20.0</pktloss_rate>
```

### Phase 5: Security Hardening

**All allocations:**
```c
data = MALLOC(sizeof(struct pktloss_data), "pktloss_data");
if (data == NULL) {
    print_err(1, "pktloss: MALLOC failed");
    return SYSM_ERROR;
}
memset(data, 0, sizeof(struct pktloss_data));
```

**Bounds checking:**
```c
if (data->history_count >= PKTLOSS_HISTORY_SIZE) {
    // Circular buffer overflow protection
}
```

**Integer overflow protection:**
```c
if (data->total_sent > ULONG_MAX - sent) {
    // Reset counters or use 64-bit
}
```

---

## Security Considerations

### Buffer Sizes

**Use macros (no hardcoded sizes):**
```c
#define PKTLOSS_HISTORY_SIZE  1440
#define PKTLOSS_MAX_SAMPLES   2880  // Upper bound
```

### Memory Management

**Allocation pattern:**
```c
// Allocate
struct pktloss_data *data = MALLOC(sizeof(struct pktloss_data), "pktloss");
if (data == NULL) return ERROR;

// Initialize
memset(data, 0, sizeof(struct pktloss_data));

// Free on cleanup
FREE(data);
here->monitordata = NULL;
```

### Input Validation

**Config validation:**
```c
if (tolerance > send_pings) {
    print_err(1, "pktloss tolerance (%u) cannot exceed send_pings (%u)",
              tolerance, send_pings);
    return ERROR;
}

if (history_hours > PKTLOSS_MAX_HISTORY) {
    print_err(1, "pktloss history (%u hours) exceeds maximum (%u)",
              history_hours, PKTLOSS_MAX_HISTORY);
    return ERROR;
}
```

### Integer Overflow Protection

**Counter rollover:**
```c
// Use 64-bit for long-running totals
unsigned long long total_sent;    // Can track billions of packets
unsigned long long total_received;
```

---

## Testing Plan

### Unit Tests

1. **Circular buffer:**
   - Fill buffer completely
   - Verify overwrites oldest
   - Check boundary conditions

2. **Tolerance checking:**
   - 0 loss → OK
   - loss <= tolerance → OK
   - loss > tolerance → DEGRADED
   - 100% loss → DOWN

3. **Memory management:**
   - Allocation/deallocation
   - NULL pointer handling
   - Buffer overflow protection

### Integration Tests

1. **Real network:**
   - Monitor stable host (low loss)
   - Monitor unreliable host (high loss)
   - Verify alerts trigger correctly

2. **Configuration:**
   - Parse valid configs
   - Reject invalid configs
   - Default values work

3. **Performance:**
   - Memory usage under load
   - CPU usage per check
   - No memory leaks (valgrind)

---

## Configuration Examples

### Basic Packet Loss Monitor
```
# Alert if >2 of 10 pings lost
server1 pktloss 10 1 2 "critical-servers" admin@example.com
```

### Strict Monitoring
```
# Alert if >0 packets lost (no tolerance)
database-primary pktloss 5 1 0 "databases" dba@example.com
```

### Lenient Monitoring
```
# Alert only if >5 of 15 lost (33% loss)
remote-office pktloss 15 2 5 "remote-sites" netops@example.com
```

### Long History
```
# Keep 48 hours of history (custom parser needed)
important-link pktloss 20 1 3 "wan-links" noc@example.com history 48
```

---

## Migration Path

### Phase 1: Basic Implementation
- Core pktloss type
- Simple tolerance checking
- 24-hour fixed history

### Phase 2: Enhanced Features
- Configurable history length
- Historical analysis (moving averages)
- Trend detection

### Phase 3: Advanced Analysis
- Packet loss graphs
- Statistics export
- Alerting on trends

---

## Performance Impact

### Memory

**Per host with pktloss monitoring:**
- pktloss_data: ~23 KB
- Existing hostinfo: ~500 bytes
- Total: ~24 KB per monitored host

**For 1000 hosts:**
- ~24 MB total memory

### CPU

**Per check cycle:**
- Send pings: existing overhead
- Record sample: O(1) - ~1μs
- Check tolerance: O(1) - ~1μs
- Negligible impact

### Disk

**State file (if implemented):**
- Would add ~24 KB per host to state
- Optional: can rebuild from monitoring

---

## Documentation Needs

1. **Config file syntax**
2. **Parameter descriptions**
3. **Example configurations**
4. **Migration guide** (ping → pktloss)
5. **Troubleshooting guide**

---

## Summary

**Design Goals:**
✅ Minimal changes to existing code
✅ Reuse existing ping infrastructure
✅ Secure by design (all macros, bounds checking)
✅ Efficient (circular buffer, O(1) operations)
✅ Configurable per-host
✅ Backward compatible

**Next Steps:**
1. Implement data structures
2. Add parser support
3. Extend ICMP code
4. Add display/reporting
5. Test thoroughly
6. Document
