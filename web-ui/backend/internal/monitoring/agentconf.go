package monitoring

import (
	"fmt"
	"strings"
)

// The config lines a new monitoring box needs.
//
// The admin page, the API and the command line all hand these to a
// person who is setting up a box. One function writes them, so the three
// cannot drift apart and give different advice about the same server.
//
// The block is only the lines a box needs. Instructions belong where the
// person is - on the page, or on standard error - not in the file they
// paste. Commented-out directives are worse still: they are text to read
// and decide about in a config that was supposed to need no decisions.

// AgentConfigBlock returns those lines, ready to copy.
//
// dial is what the box puts in "config aggregator": use DialTarget, or
// AgentDialTarget in the running server. label may be empty.
func AgentConfigBlock(site, label, dial, token string) string {
	if label == "" {
		label = site
	}

	var b strings.Builder
	fmt.Fprintf(&b, "# sysmond -> sysmon-web, for site %q.\n", site)
	fmt.Fprintf(&b, "config sitename  %q;\n", site)
	fmt.Fprintf(&b, "config sitedesc  %q;\n", label)
	fmt.Fprintf(&b, "config aggregator %q;\n", dial)
	fmt.Fprintf(&b, "config aggregator-token %q;\n", token)

	return b.String()
}
