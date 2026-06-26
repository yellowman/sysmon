package main

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"syscall"
)

// resolveUser returns the uid AND primary gid of the first username in
// names that exists on the system. Empty names are skipped. Returning the
// user's own primary gid (rather than guessing a group of the same name)
// is what makes the defaults portable: the "nobody" user's primary group
// is "nogroup" on Debian but "nobody" on OpenBSD/RHEL — deriving the gid
// from the user sidesteps that entirely.
func resolveUser(names ...string) (uid, gid int, name string, ok bool) {
	for _, n := range names {
		if n == "" {
			continue
		}
		u, err := user.Lookup(n)
		if err != nil {
			continue
		}
		id, err := strconv.Atoi(u.Uid)
		if err != nil {
			continue
		}
		g, err := strconv.Atoi(u.Gid)
		if err != nil {
			continue
		}
		return id, g, n, true
	}
	return -1, -1, "", false
}

// resolveGroup returns the gid of the first group name that exists. Used
// only for an explicit -group / -socket-group override; the default group
// comes from resolveUser's primary gid.
func resolveGroup(names ...string) (gid int, ok bool) {
	for _, n := range names {
		if n == "" {
			continue
		}
		g, err := user.LookupGroup(n)
		if err != nil {
			continue
		}
		id, err := strconv.Atoi(g.Gid)
		if err != nil {
			continue
		}
		return id, true
	}
	return -1, false
}

// prepareRuntimeDirs (run as root, before dropping) ensures the state and
// backup directories and the audit log exist and are owned by the target
// uid/gid, so the soon-to-be-unprivileged process can open its bbolt
// stores, write backups, and append to the audit log. Errors are
// returned — not swallowed — so main can fail loudly while it still has
// root and a working diagnostics channel, rather than dropping and then
// hitting an opaque "permission denied" deep in init.
//
// The socket's parent directory is handled separately by the bind path.
func prepareRuntimeDirs(stateDir, backupDir, auditLog string, uid, gid int) error {
	for _, dir := range []string{stateDir, backupDir} {
		if dir == "" {
			continue
		}
		if err := os.MkdirAll(dir, 0o750); err != nil {
			return fmt.Errorf("create %s: %w", dir, err)
		}
		if err := os.Chown(dir, uid, gid); err != nil {
			return fmt.Errorf("chown %s to %d:%d: %w", dir, uid, gid, err)
		}
	}
	if auditLog == "" {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(auditLog), 0o755); err != nil {
		return fmt.Errorf("create audit dir %s: %w", filepath.Dir(auditLog), err)
	}
	switch info, err := os.Stat(auditLog); {
	case errors.Is(err, fs.ErrNotExist):
		// Create it so the dropped process can append, then hand it over.
		f, ferr := os.OpenFile(auditLog, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o640)
		if ferr != nil {
			return fmt.Errorf("create audit log %s: %w", auditLog, ferr)
		}
		f.Close()
		if cerr := os.Chown(auditLog, uid, gid); cerr != nil {
			return fmt.Errorf("chown audit log %s: %w", auditLog, cerr)
		}
	case err != nil:
		return fmt.Errorf("stat audit log %s: %w", auditLog, err)
	case info.Mode().IsRegular():
		// Existing regular file (e.g. from a prior root run): re-own it so
		// the dropped process can keep appending.
		if cerr := os.Chown(auditLog, uid, gid); cerr != nil {
			return fmt.Errorf("chown audit log %s: %w", auditLog, cerr)
		}
	default:
		// Exists but not a regular file (e.g. /dev/null, a fifo) — leave
		// its ownership alone.
	}
	return nil
}

// dropPrivileges lowers the whole process to uid/gid: clear supplementary
// groups, then setgid, then setuid, then verify the drop stuck and that
// root cannot be regained. Go (>=1.16) applies these across all threads.
// Order matters — gid before uid, since after setuid we can no longer
// change groups.
func dropPrivileges(uid, gid int) error {
	if err := syscall.Setgroups([]int{gid}); err != nil {
		return fmt.Errorf("setgroups: %w", err)
	}
	if err := syscall.Setgid(gid); err != nil {
		return fmt.Errorf("setgid(%d): %w", gid, err)
	}
	if err := syscall.Setuid(uid); err != nil {
		return fmt.Errorf("setuid(%d): %w", uid, err)
	}
	if syscall.Getuid() != uid || syscall.Geteuid() != uid {
		return fmt.Errorf("uid did not drop to %d", uid)
	}
	if syscall.Getgid() != gid || syscall.Getegid() != gid {
		return fmt.Errorf("gid did not drop to %d", gid)
	}
	// Defence in depth: if we can become root again, the drop is a lie.
	if uid != 0 && syscall.Setuid(0) == nil {
		return fmt.Errorf("root privileges could be regained after drop")
	}
	return nil
}
