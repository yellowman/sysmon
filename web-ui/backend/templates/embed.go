// Package webtemplates ships the UI inside the binary.
//
// The templates used to be read from disk at startup, auto-detecting an
// installed directory - which meant a freshly installed binary happily
// rendered whatever stale copy a previous install had left there, and
// every UI fix in it was invisible. The binary is the unit of upgrade;
// the pages now travel inside it. The -templates flag still points at a
// directory for development, where editing a file and restarting beats
// recompiling.
package webtemplates

import "embed"

//go:embed *.html
var Files embed.FS
