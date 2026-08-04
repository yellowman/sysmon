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
	label = fitForConfig(label)
	if label == "" {
		label = site
	}

	// Not %q. Go escaping means nothing to the sysmond lexer: it takes a
	// string as the text between two quote characters, and a backslash is
	// just a character. The label is made safe above; the other fields
	// cannot hold a quote - the site name is validated, the token is hex,
	// and the dial target comes from this server's own flags.
	var b strings.Builder
	fmt.Fprintf(&b, "# sysmond -> sysmon-web, for site %q.\n", site)
	fmt.Fprintf(&b, "config sitename  \"%s\";\n", site)
	fmt.Fprintf(&b, "config sitedesc  \"%s\";\n", label)
	fmt.Fprintf(&b, "config aggregator \"%s\";\n", dial)
	fmt.Fprintf(&b, "config aggregator-token \"%s\";\n", token)

	return b.String()
}

// fitForConfig makes free text safe inside a quoted sysmond config value.
//
// The lexer ends a string at the next quote and a directive at the next
// semicolon, with no escape for either. So a label like `rack "A"; east`
// cannot be written as the person typed it - the choice is to bend the
// text or to emit a config that parses wrongly, and a silently wrong
// sitedesc on every box is the worse of the two.
func fitForConfig(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch {
		case r == '"':
			b.WriteByte('\'')
		case r == ';':
			b.WriteByte(',')
		case r < 0x20 || r == 0x7f:
			b.WriteByte(' ')
		default:
			b.WriteRune(r)
		}
	}
	return strings.TrimSpace(b.String())
}
