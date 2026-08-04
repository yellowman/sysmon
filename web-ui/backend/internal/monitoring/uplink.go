package monitoring

import (
	"fmt"
	"sort"
	"strings"

	"sysmon-web/internal/settings"
)

// The directives that decide where a box reports, and why this process
// will not edit them.
//
// sysmond reads "config aggregator" and "config aggregator-token" from
// whatever config it is running, so a delivered config can move a box to
// a different sysmon-web, or to nowhere. The daemon keeps that ability on
// purpose - a box behind NAT may one day need to be pointed somewhere
// else - but it is not usable from here today, because moving a box also
// needs the certificate for the new destination, and this process has no
// way to put that on the box.
//
// So the capability stays in the daemon and is refused in the editor. A
// half-usable version of it costs a box: the delivery succeeds, the reply
// comes back on the old connection, and the daemon then reloads and
// dials somewhere that cannot answer. From here that looks the same as a
// network fault, and the repair is a drive to the console.
//
// Changing it stays possible where it is safe: in the seed config, by
// somebody who is already on the box.

// uplinkDirectives are matched at the start of a config line, after
// leading whitespace and with internal whitespace collapsed.
var uplinkDirectives = []string{
	"config aggregator",
	"config aggregator-token",
}

// uplinkLines returns the connection directives a config carries, in a
// stable order so two configs can be compared.
//
// Comments are ignored, because a commented-out directive does nothing,
// and whitespace is collapsed, because re-indenting a line does not
// change where the box reports.
func uplinkLines(files []settings.GenFile) []string {
	var out []string

	for _, f := range files {
		for _, raw := range strings.Split(string(f.Content), "\n") {
			line := strings.TrimSpace(raw)
			if line == "" || strings.HasPrefix(line, "#") ||
				strings.HasPrefix(line, ";") {
				continue
			}
			line = strings.Join(strings.Fields(line), " ")

			for _, d := range uplinkDirectives {
				// "config aggregator-token" must not match as
				// "config aggregator" with a stray suffix, so the
				// character after the directive has to be a separator.
				if !strings.HasPrefix(line, d) {
					continue
				}
				rest := line[len(d):]
				if rest != "" && rest[0] != ' ' && rest[0] != '"' &&
					rest[0] != ';' {
					continue
				}
				out = append(out, line)
				break
			}
		}
	}
	sort.Strings(out)
	return out
}

// checkUplinkUnchanged refuses an edit that would move the box.
//
// Comparing against the generation this process already holds is the
// right baseline: that is what the box is running, or is about to be
// given, and it is the same thing an operator sees in the editor before
// they change anything.
func checkUplinkUnchanged(was, now []settings.GenFile) error {
	before := uplinkLines(was)
	after := uplinkLines(now)

	if len(before) == len(after) {
		same := true
		for i := range before {
			if before[i] != after[i] {
				same = false
				break
			}
		}
		if same {
			return nil
		}
	}

	return fmt.Errorf(
		"this edit changes where the box reports (%s), which cannot be done "+
			"from here: moving a box also needs the certificate for its new "+
			"destination, and there is no way to put that on the box from this "+
			"side. Edit %s on the box itself.\n  now:   %s\n  after: %s",
		strings.Join(uplinkDirectives, " / "),
		"the seed config",
		describeUplink(before), describeUplink(after))
}

// describeUplink keeps a token out of the message. The value proves a box
// to this process, and an error string is the last place it should turn
// up - errors go to logs, to screens, and into tickets.
func describeUplink(lines []string) string {
	if len(lines) == 0 {
		return "(none)"
	}
	out := make([]string, len(lines))
	for i, l := range lines {
		if strings.HasPrefix(l, "config aggregator-token") {
			out[i] = "config aggregator-token <hidden>"
			continue
		}
		out[i] = l
	}
	return strings.Join(out, ", ")
}
