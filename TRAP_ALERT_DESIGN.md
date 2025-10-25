# SNMP Trap Alert Feature Design

## Overview

Add per-object configuration to trigger alerts when SNMP traps are received from specific devices.

## Use Case

**Problem:** Currently, SNMP traps are only logged but don't trigger alerts.

**Solution:** Allow administrators to configure specific critical devices so that any trap from those devices triggers an immediate alert/page.

**Example Scenario:**
- Core router configured with `trap_alert`
- Router sends linkDown trap
- Sysmon immediately pages network team
- No waiting for next polling cycle

## Configuration Syntax

```
object core-router {
    ip "192.168.1.1";
    type ping;              # Can be any type
    trap_alert;             # Enable trap-based alerting
    contact "netops@example.com";
    desc "Core datacenter router";
};
```

**Keyword:** `trap_alert` (boolean flag, no parameters)

## Implementation Architecture

### 1. Data Structure Changes

**File:** `src/config.h`

Add to `struct hostinfo`:
```c
bool trap_alert;  /* If true, send alert when trap received from this IP */
```

### 2. Parser Changes

**File:** `src/parser.l`

Add parser rule:
```
trap_alert{WS}*;  {
    if (parser_name == NULL)
        print_err(1, "trap_alert specified outside object context");
    else
        parser_trap_alert = TRUE;
}
```

Initialize in object creation section:
```c
if (parser_trap_alert) {
    new_ele->value->data->trap_alert = TRUE;
} else {
    new_ele->value->data->trap_alert = FALSE;
}
```

### 3. Trap Processing Changes

**File:** `src/snmp.c`

Enhance `process_snmp_trap()`:

```c
void process_snmp_trap(int skt)
{
    char buffer[4096];
    int len;
    struct sockaddr_in from;
    socklen_t fromlen = sizeof(from);
    struct in_addr trap_source;
    struct graph_elements *obj;

    // Receive trap
    len = recvfrom(skt, buffer, 4095, 0, (struct sockaddr*)&from, &fromlen);

    // Extract source IP
    trap_source = from.sin_addr;

    // Always log
    print_err(1, "caught a snmp trap from %s that was %d bytes",
              inet_ntoa(trap_source), len);

    if (debug) {
        print_in_hex(buffer, len);
    }

    // NEW: Check if any object matches this IP and has trap_alert enabled
    obj = find_object_by_ip(inet_ntoa(trap_source));

    if (obj != NULL && obj->data->trap_alert) {
        // Trigger alert
        send_trap_alert(obj, trap_source);
    }
}
```

### 4. Helper Functions

**New function:** `find_object_by_ip()`

```c
struct graph_elements *find_object_by_ip(char *ip_string)
{
    struct all_elements_list *walker;
    struct hostent *he;
    char ip_addr[INET_ADDRSTRLEN];

    // Walk through all objects
    for (walker = all_elements; walker != NULL; walker = walker->next) {
        // Resolve object's hostname/IP
        he = gethostbyname(walker->value->data->hostname);
        if (he != NULL) {
            inet_ntop(AF_INET, he->h_addr_list[0], ip_addr, sizeof(ip_addr));

            // Compare IPs
            if (strcmp(ip_addr, ip_string) == 0) {
                return walker->value;
            }
        }

        // Also check if hostname matches IP directly
        if (strcmp(walker->value->data->hostname, ip_string) == 0) {
            return walker->value;
        }
    }

    return NULL;  // Not found
}
```

**New function:** `send_trap_alert()`

```c
void send_trap_alert(struct graph_elements *obj, struct in_addr source)
{
    char message[1024];

    snprintf(message, sizeof(message),
        "SNMP trap received from %s (%s)",
        obj->data->hostname,
        inet_ntoa(source));

    // Use existing alert infrastructure
    page_someone(obj->data, message, SYSM_SNMP_TRAP);
}
```

### 5. Error Code

**File:** `src/config.h`

Add new error code:
```c
#define SYSM_SNMP_TRAP  24  /* SNMP trap received */
```

Add to `errtostr()` in `src/lib.c`:
```c
case SYSM_SNMP_TRAP:
    return "SNMP Trap";
```

## Behavior

### When Trap Arrives:

1. **Trap from monitored device WITH trap_alert:**
   - Logs trap (as before)
   - Sends immediate alert via email/pager
   - Message: "SNMP trap received from [hostname]"
   - Uses object's configured contact

2. **Trap from monitored device WITHOUT trap_alert:**
   - Only logs trap (current behavior)
   - No alert sent

3. **Trap from unknown device:**
   - Only logs trap
   - No alert sent

### Alert Frequency Control

Uses existing sysmon alert throttling:
- `lastcontacted` timestamp prevents spam
- Multiple traps within short time = single alert
- Configurable via global/per-object settings

## Configuration Requirements

**Global:** Enable trap listening
```
config snmp-trap;
```

**Per-object:** Enable trap alerts
```
object device {
    trap_alert;
}
```

## Advantages

✅ **Simple:** Minimal code changes
✅ **Selective:** Only alerts for critical devices
✅ **Backwards compatible:** Existing configs work unchanged
✅ **No parsing:** Doesn't need to parse trap PDU structure
✅ **Immediate:** No polling delay
✅ **Uses existing infrastructure:** Leverages page_someone()

## Limitations

⚠️ **No trap content parsing:** Can't differentiate trap types
⚠️ **IP-based only:** Can't match by trap OID or severity
⚠️ **All-or-nothing:** Either alert on all traps or none
⚠️ **No trap-to-state mapping:** Doesn't update object state

## Future Enhancements

### Phase 2: Trap Type Filtering
```
object device {
    trap_alert linkDown coldStart;  # Only alert on specific traps
}
```

### Phase 3: Trap-Based State Updates
```
object device {
    trap_update;  # Update object state based on traps
}
```

### Phase 4: Custom Trap Messages
```
object device {
    trap_alert;
    trap_message "Critical device sent trap!";
}
```

## Testing Plan

1. **Unit test:** Parser accepts `trap_alert` keyword
2. **Integration test:** Trap triggers alert
3. **Negative test:** Trap without trap_alert doesn't alert
4. **Throttle test:** Multiple traps = single alert
5. **Unknown device test:** Trap from unconfigured IP

## Documentation Updates

- Man page: `sysmon.conf.5` - Add `trap_alert` keyword
- Example config: Add trap_alert example
- README: Document trap alert feature

## Estimated Effort

- **Implementation:** 4-6 hours
- **Testing:** 2-3 hours
- **Documentation:** 1-2 hours
- **Total:** ~1 day of work

## Dependencies

- Requires `config snmp-trap;` to be enabled
- Requires SNMP support compiled in (ENABLE_SNMP)

## Alternatives Considered

### Alternative 1: Global trap alerts
```
config trap-alert-all;
```
**Rejected:** Too noisy, would alert on every trap

### Alternative 2: Trap severity filtering
```
config trap-alert-severity critical;
```
**Rejected:** Requires trap PDU parsing (more complex)

### Alternative 3: Pattern matching
```
object device {
    trap_alert_pattern "linkDown";
}
```
**Deferred:** Good for phase 2, requires parsing

---

## Implementation Status

- [ ] Add trap_alert to struct hostinfo
- [ ] Add parser keyword and rules
- [ ] Implement find_object_by_ip()
- [ ] Implement send_trap_alert()
- [ ] Add SYSM_SNMP_TRAP error code
- [ ] Update process_snmp_trap()
- [ ] Test implementation
- [ ] Update documentation
