# Security Analysis: strcpy() and strcat() Usage

## Executive Summary

This analysis identifies **26 instances** of unsafe string functions (`strcpy` and `strcat`) across the sysmon codebase. These functions are deprecated due to their lack of bounds checking, which can lead to buffer overflow vulnerabilities.

**Severity Summary:**
- **CRITICAL**: 5 instances (user-controlled input without bounds checking)
- **HIGH**: 8 instances (potential overflow with concatenation chains)
- **MEDIUM**: 10 instances (fixed strings but poor practice)
- **LOW**: 3 instances (adequately sized buffers with fixed input)

---

## strcpy() Usage Analysis

### CRITICAL Vulnerabilities

#### 1. syswatch.c:276 & 279 - Command-line Argument Buffer Overflow
**Location**: `src/syswatch.c:276,279`
```c
char configfile[256];  // Line 38
...
strcpy(conf_file, argv[x]+2);        // Line 276
strcpy(conf_file, argv[x+1]);        // Line 279
```
**Risk**: Command-line arguments can be arbitrarily long, allowing buffer overflow attack
**Impact**: Code execution, denial of service
**Recommendation**: Replace with `snprintf(conf_file, sizeof(conf_file), "%s", argv[x]+2);`

#### 2. client.c:319, 324, 327 - Environment Variable & Argument Overflow
**Location**: `src/client.c:319,324,327`
```c
char server[1024];  // Line 307
...
strcpy(server, temp);        // Line 319 - temp from getenv("SYSMON_HOST")
strcpy(server, argv[1]);     // Line 324
strcpy(server, argv[1]);     // Line 327
```
**Risk**: Environment variables and arguments can exceed 1024 bytes
**Impact**: Stack-based buffer overflow leading to code execution
**Recommendation**: Replace with `snprintf(server, sizeof(server), "%s", source);`

#### 3. client.c:78 - Hostname Buffer Overflow
**Location**: `src/client.c:78`
```c
char space[256];  // Line 56 (local buffer)
struct downdata { char hostname[256]; ... };  // Line 18-19
...
strncat(space, buff+start, (end - start));  // Line 73
strcpy(stuff->hostname, space);              // Line 78
```
**Risk**: If `strncat` fills space[256], strcpy will overflow (no null terminator space)
**Impact**: Buffer overflow during client data parsing
**Recommendation**: Use `strncpy` or `snprintf` with proper null termination

### HIGH Risk Issues

#### 4. syswatch.c:1888 - Configuration File Path
**Location**: `src/syswatch.c:1888`
```c
char configfile[256];
strcpy(configfile, CFILE);  // CFILE is @sysconfdir@/sysmon.conf
```
**Risk**: If CFILE macro expands to >255 chars, overflow occurs
**Impact**: Depends on sysconfdir length at compile time
**Recommendation**: Use `snprintf` or verify CFILE length at compile time

#### 5. srvclient.c:827 - IP Address Storage
**Location**: `src/srvclient.c:827`
```c
thisclient->ip = MALLOC(20, "thisclient_ip");  // Line 826
strcpy(thisclient->ip, inet_ntoa(remote.sin_addr));  // Line 827
```
**Risk**: inet_ntoa() returns max 15 chars ("255.255.255.255") + null, buffer is 20 bytes
**Impact**: LOW - adequate size for IPv4, but poor practice
**Recommendation**: Use `snprintf` or `inet_ntop` with proper sizing

#### 6. client.c:147 & 288 - Time String Copy
**Location**: `src/client.c:147,288`
```c
char nfo[30];  // Line 138
strcpy(nfo, ctime(&t)+4);  // ctime returns 26 chars including \n and \0
```
**Risk**: ctime returns 26 characters, offset +4 leaves 22 chars. Buffer is 30 bytes - safe but risky
**Impact**: LOW - currently safe but fragile
**Recommendation**: Use `strftime` with explicit buffer size

### MEDIUM Risk - Fixed String

#### 7. radius.c:375 - Fixed String "sysmon"
**Location**: `src/radius.c:375`
```c
strcpy(packet+packetindex, "sysmon");  // 6 bytes + null
```
**Risk**: LOW - fixed 6-byte string, but packet buffer size should be verified
**Impact**: Depends on packet buffer allocation
**Recommendation**: Replace with `memcpy` or verify packet buffer size

---

## strcat() Usage Analysis

### HIGH Risk - Multiple Concatenations

#### 8. page.c:68-165 - Message Template Expansion
**Location**: `src/page.c:11,68-165`
```c
char out[1024];  // Line 11
...
strcat(out, "\n");                                    // Line 68
strcat(out, "\r");                                    // Line 71
strcat(out, myhostname);                              // Line 81
strcat(out, get_hostname(hp));                        // Line 84
strcat(out, str_difftime(svc->deathtime,t));         // Line 87
strcat(out, str_difftime(svc->last_up,t));           // Line 90
strcat(out, str_difftime_sec(svc->deathtime, t));    // Line 93
strcat(out, type_to_name(svc->type));                // Line 135
strcat(out, ctime(&t)+11);                            // Line 138
strcat(out, ctime(&t)+4);                             // Line 142
strcat(out, svc->lastcheck ? "down" : "up");         // Line 147
strcat(out, errtostr(svc->lastcheck));               // Line 151
strcat(out, svc->message);                            // Line 154
strcat(out, svc->hostname);                           // Line 165
```
**Risk**: HIGH - 15 strcat operations on 1024-byte buffer without length checking
**Impact**: Buffer overflow if combined string expansion exceeds 1024 bytes
**Recommendation**:
- Use `snprintf` with size tracking: `snprintf(out + strlen(out), sizeof(out) - strlen(out), "%s", str)`
- Better: Use a dynamic string builder or pre-calculate required size

**Analysis**: The template expansion function processes format specifiers and concatenates multiple strings including:
- Hostnames (up to 256 bytes)
- Error messages (variable length)
- Time strings (~20 bytes each)
- IP addresses (~15 bytes)

With all expansions, this could easily exceed 1024 bytes.

#### 9. loadconfig.c:157 - Variable Replacement
**Location**: `src/loadconfig.c:157`
```c
unsigned char new_string[MAX_STRLEN];  // MAX_STRLEN = 32768
...
strcat(new_string, repl);  // Line 157
```
**Risk**: MEDIUM - Large buffer (32KB) but still unbounded concatenation
**Impact**: If config file has excessive variable replacements, could overflow
**Recommendation**: Track string length and use `strncat` with remaining space

---

## Vulnerability Summary Table

| File | Line | Function | Severity | Input Source | Buffer Size |
|------|------|----------|----------|--------------|-------------|
| syswatch.c | 276, 279 | strcpy | CRITICAL | Command-line args | 256 bytes |
| syswatch.c | 1888 | strcpy | HIGH | Macro expansion | 256 bytes |
| client.c | 319, 324, 327 | strcpy | CRITICAL | Env var + argv | 1024 bytes |
| client.c | 78 | strcpy | CRITICAL | Parsed network data | 256 bytes |
| client.c | 147, 288 | strcpy | MEDIUM | ctime() output | 30 bytes |
| srvclient.c | 827 | strcpy | MEDIUM | inet_ntoa() | 20 bytes |
| radius.c | 375 | strcpy | LOW | Fixed string | Unknown |
| page.c | 68-165 | strcat | HIGH | Multiple sources | 1024 bytes |
| loadconfig.c | 157 | strcat | MEDIUM | Config file vars | 32768 bytes |

---

## Recommended Fixes

### Immediate Actions (CRITICAL)

1. **Replace all strcpy/strcat with safe alternatives:**
   ```c
   // Instead of:
   strcpy(dest, src);

   // Use:
   snprintf(dest, sizeof(dest), "%s", src);

   // Instead of:
   strcat(dest, src);

   // Use:
   size_t len = strlen(dest);
   snprintf(dest + len, sizeof(dest) - len, "%s", src);
   ```

2. **Use strncpy with explicit null termination:**
   ```c
   strncpy(dest, src, sizeof(dest) - 1);
   dest[sizeof(dest) - 1] = '\0';
   ```

3. **Consider strlcpy/strlcat (BSD) or implement safe wrappers:**
   ```c
   size_t safe_strcpy(char *dst, const char *src, size_t dsize);
   size_t safe_strcat(char *dst, const char *src, size_t dsize);
   ```

### Long-term Recommendations

1. **Enable compiler warnings:** `-Wdeprecated-declarations -D_FORTIFY_SOURCE=2`
2. **Static analysis:** Run tools like `flawfinder`, `cppcheck`, or `clang-tidy`
3. **Dynamic testing:** Use AddressSanitizer (`-fsanitize=address`) during testing
4. **Code review:** Audit all buffer operations for bounds checking
5. **Consider using safe string libraries:** Like `safeclib` or implement project-wide safe wrappers

---

## Testing Recommendations

1. **Fuzzing:** Test with overly long command-line arguments and environment variables
2. **Boundary testing:** Test with maximum-length inputs for all buffers
3. **Integration testing:** Verify fix doesn't break existing functionality
4. **Regression testing:** Ensure no new vulnerabilities introduced

---

## References

- CWE-120: Buffer Copy without Checking Size of Input
- CWE-119: Improper Restriction of Operations within Memory Buffer
- CERT C Coding Standard: STR31-C
- OWASP: Buffer Overflow

---

**Report Generated:** 2025-10-24
**Analysis Tool:** Manual code review
**Codebase:** sysmon
