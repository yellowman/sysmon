# Comprehensive Security Analysis: Memory Leaks, Buffer Overflows, and Bugs

## Executive Summary

This analysis covers security vulnerabilities beyond the strcpy/strcat issues already fixed. Analysis found:
- **15+ sprintf() calls** - unsafe, should use snprintf()
- **Multiple MALLOC/strdup calls** - potential memory leaks
- **Buffer overflow risks** in formatting operations
- **Potential NULL pointer dereferences**

---

## 1. Buffer Overflow Risks - sprintf() Usage

### Overview
Found 15+ instances of `sprintf()` which doesn't check buffer bounds. All should be replaced with `snprintf()`.

### Critical Instances

#### src/client.c:110 - Format String Buffer Overflow
```c
char tempbuff[1024];
sprintf(tempbuff, "%-25.24s%-6s%-5d%-6d%-6s%-15s%s\n", down.hostname,
        type_to_name(down.type), down.port, down.downct,
        yes_no(down.notified), errtostr(down.lastcheck), data);
```
**Risk**: HIGH - If combined strings exceed 1024 bytes, buffer overflow occurs
**Fix**:
```c
snprintf(tempbuff, sizeof(tempbuff), "%-25.24s%-6s%-5d%-6d%-6s%-15s%s\n", ...);
```

#### src/client.c:153-154 - Server Name Display
```c
sprintf(tempbuff, "Server: %-30s%-20s%-20s", server,
    "     Current Time: ", nfo);
```
**Risk**: MEDIUM - server variable can be up to 1024 bytes
**Fix**:
```c
snprintf(tempbuff, sizeof(tempbuff), "Server: %-30s%-20s%-20s", server,
    "     Current Time: ", nfo);
```

#### src/client.c:157-159 - Column Headers
```c
sprintf(tempbuff, "%-25s%-6s%-5s%-6s%-6s%-15s%s\n",
    "Hostname", "Type", "Port",
    "Count", "Notif", "Stat", "Time Failed");
```
**Risk**: LOW - fixed strings, but poor practice
**Fix**:
```c
snprintf(tempbuff, sizeof(tempbuff), "%-25s%-6s%-5s%-6s%-6s%-15s%s\n", ...);
```

#### src/client.c:359-361 - Connection Message
```c
sprintf(tempbuf,
    "Connecting to server %s and getting inital data...\n",
    server);
```
**Risk**: HIGH - server can be 1024 bytes, message + server could exceed tempbuf
**Fix**:
```c
snprintf(tempbuf, sizeof(tempbuf),
    "Connecting to server %s and getting inital data...\n",
    server);
```

#### src/lib.c:1026 - Format String Construction
```c
sprintf(format_str_ptr, "%d.%d", width, precision);
```
**Risk**: MEDIUM - Integer values unbounded
**Fix**:
```c
snprintf(format_str_ptr, remaining_size, "%d.%d", width, precision);
```

### Recommendation
**Replace ALL sprintf() with snprintf() using sizeof(buffer)**

---

## 2. Memory Leak Analysis

### MALLOC/FREE Pattern Analysis

The codebase uses custom `MALLOC()` and `FREE()` macros. Need to verify each MALLOC has corresponding FREE.

#### Potential Memory Leaks

##### src/srvclient.c:826-828
```c
thisclient->ip = MALLOC(20, "thisclient_ip");
snprintf(thisclient->ip, 20, "%s", inet_ntoa(remote.sin_addr));
```
**Issue**: Need to verify `thisclient->ip` is freed when client disconnects
**Recommendation**: Audit client cleanup code for FREE(thisclient->ip)

##### src/syswatch.c:447
```c
clienthead = MALLOC(sizeof(struct clientstatus), "clienthead");
```
**Issue**: Global allocation - never freed
**Risk**: LOW - intentional global data structure
**Recommendation**: Document as intentional

##### src/syswatch.c:521
```c
newentry = MALLOC(sizeof(struct monitorent), "new entry - monitorent in queue_check");
```
**Issue**: Need to verify queue entries are freed when processed
**Recommendation**: Audit queue processing for FREE(newentry)

##### src/syswatch.c:769
```c
queue_list = MALLOC(alloc_size, "queue_list");
```
**Issue**: Dynamic allocation - verify freed after use
**Recommendation**: Search for FREE(queue_list) in same function

##### src/syswatch.c:1834
```c
ident_hash = MALLOC(0xffff, "ident_hash");
```
**Issue**: Large allocation (65535 bytes) - never freed
**Risk**: LOW - appears to be global hash table
**Recommendation**: Document as intentional global

### strdup() Analysis

Found 9 files using `strdup()`. Each strdup allocates memory that must be freed.

#### src/page.c - Multiple strdup Returns
```c
return strdup(out);  // Line 197
```
**Issue**: Caller must free this memory
**Recommendation**: Audit all callers of translate_string() for memory leaks

#### src/loadconfig.c - strdup in Variable Replacement
```c
return STRDUP(new_string,"config variable replacement value");
```
**Issue**: Uses custom STRDUP macro - verify freed
**Recommendation**: Check callers for proper FREE()

---

## 3. NULL Pointer Dereference Risks

### Unchecked Return Values

#### inet_ntoa() Usage
```c
snprintf(thisclient->ip, 20, "%s", inet_ntoa(remote.sin_addr));
```
**Risk**: LOW - inet_ntoa() returns static buffer, won't be NULL
**But**: Not thread-safe, returns pointer to static storage

#### MALLOC() Failures
```c
thisclient->ip = MALLOC(20, "thisclient_ip");
// No NULL check before use
```
**Risk**: MEDIUM - If MALLOC fails, NULL dereference occurs
**Fix**: Check if MALLOC implementation handles failures

---

## 4. Race Conditions and Thread Safety

### Non-Thread-Safe Functions

#### ctime() Usage (ALREADY FIXED)
- Fixed in strcpy/strcat patches
- Now uses thread-safe strftime()

#### inet_ntoa() Usage
```c
inet_ntoa(remote.sin_addr)
```
**Risk**: Returns pointer to static buffer - not thread-safe
**Fix**: Use inet_ntop() instead:
```c
char ip_str[INET_ADDRSTRLEN];
inet_ntop(AF_INET, &remote.sin_addr, ip_str, sizeof(ip_str));
```

---

## 5. Integer Overflow Risks

### Array Indexing

#### src/syswatch.c:1834
```c
ident_hash = MALLOC(0xffff, "ident_hash");
```
**Issue**: Hardcoded size - what if index exceeds 0xffff?
**Recommendation**: Add bounds checking on hash index

---

## 6. Format String Vulnerabilities

### User-Controlled Format Strings

Need to verify no user input is passed as format string to printf-family functions.

**Search Pattern**: Look for `printf(..., user_input, ...)`

---

## 7. Additional Security Concerns

### Signal Handler Safety

Check signal handlers for:
- Async-signal-safe functions only
- No malloc/free in handlers
- Minimal operations

### File Descriptor Leaks

Search for:
- `open()` without corresponding `close()`
- `socket()` without corresponding `close()`
- `fopen()` without corresponding `fclose()`

### Command Injection

Search for:
- `system()` calls with user input
- `popen()` calls with user input
- Unvalidated shell command construction

---

## Summary of Findings

| Issue Type | Count | Severity | Priority |
|------------|-------|----------|----------|
| sprintf() calls | 15+ | HIGH | 1 |
| MALLOC without visible FREE | 5+ | MEDIUM | 2 |
| strdup without visible free | 9+ | MEDIUM | 2 |
| inet_ntoa (thread-unsafe) | 1+ | LOW | 3 |
| NULL pointer checks missing | Multiple | MEDIUM | 2 |

---

## Recommended Actions

### Immediate (Priority 1)

1. **Replace all sprintf() with snprintf()**
   ```bash
   # Find all sprintf calls
   grep -rn "sprintf(" src/

   # Replace pattern:
   sprintf(buf, ...) → snprintf(buf, sizeof(buf), ...)
   ```

2. **Add NULL checks after MALLOC**
   ```c
   ptr = MALLOC(size, "description");
   if (ptr == NULL) {
       // Handle error
       return ERROR;
   }
   ```

### Short-term (Priority 2)

3. **Memory leak audit**
   - Review all MALLOC calls for corresponding FREE
   - Use valgrind to detect runtime leaks
   - Document intentional global allocations

4. **Replace inet_ntoa with inet_ntop**
   ```c
   char ip_str[INET_ADDRSTRLEN];
   inet_ntop(AF_INET, &addr, ip_str, sizeof(ip_str));
   ```

### Long-term (Priority 3)

5. **Static analysis**
   ```bash
   # Run static analyzers
   cppcheck --enable=all src/
   flawfinder src/
   clang-tidy src/*.c
   ```

6. **Dynamic analysis**
   ```bash
   # Compile with sanitizers
   CFLAGS="-fsanitize=address,undefined -g" make

   # Run with valgrind
   valgrind --leak-check=full ./syswatch
   ```

7. **Fuzz testing**
   - Test with malformed inputs
   - Test with overly long strings
   - Test with unexpected data types

---

## Testing Checklist

- [ ] Replace all sprintf() with snprintf()
- [ ] Verify MALLOC/FREE pairing
- [ ] Add NULL checks after allocations
- [ ] Run valgrind for memory leaks
- [ ] Run AddressSanitizer
- [ ] Test with maximum-length inputs
- [ ] Verify no format string vulnerabilities
- [ ] Check signal handler safety
- [ ] Audit file descriptor usage
- [ ] Review command execution for injection

---

## References

- CWE-120: Buffer Copy without Checking Size of Input
- CWE-134: Use of Externally-Controlled Format String
- CWE-401: Missing Release of Memory after Effective Lifetime
- CWE-476: NULL Pointer Dereference
- CWE-362: Concurrent Execution using Shared Resource

---

**Report Generated:** 2025-10-24
**Analysis Type:** Comprehensive security audit
**Codebase:** sysmon
**Previous Fixes:** strcpy/strcat vulnerabilities (26 instances fixed)
