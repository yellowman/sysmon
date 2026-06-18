//go:build !openbsd

package main

// Default FastCGI socket path on non-OpenBSD systems (Linux/nginx etc.).
const defaultSocket = "/var/run/sysmon-web.sock"
