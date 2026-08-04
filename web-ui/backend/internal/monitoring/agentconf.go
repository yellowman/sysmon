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
// The block is complete on purpose. A person who pastes it into
// /etc/sysmon.conf and puts the certificate in place has a working box.
// There is nothing more to look up, and nothing to fill in.

// agentStateDir is the daemon's default state directory. It is
// GENDIR_DEFAULT in src/confgen.c. The block names it in a comment,
// because the certificate goes there.
const agentStateDir = "/var/db/sysmon"

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
	b.WriteString("# Add these lines to /etc/sysmon.conf, then start sysmond.\n")
	b.WriteString("# The token is shown one time. The server keeps only a hash of it.\n\n")

	fmt.Fprintf(&b, "config sitename  %q;\n", site)
	fmt.Fprintf(&b, "config sitedesc  %q;\n", label)
	fmt.Fprintf(&b, "config aggregator %q;\n", dial)
	fmt.Fprintf(&b, "config aggregator-token %q;\n", token)

	fmt.Fprintf(&b, `
# sysmond writes its files in this directory. The line shows the default,
# so remove the comment mark only if you want a different directory.
# Put the CA certificate there, with the name aggregator-ca.pem.
#config statedir %q;

# sysmond opens no port. Remove the comment mark if the sysmon client
# must connect to this box directly.
#config listen 1345;
`, agentStateDir)

	return b.String()
}
