//go:build openbsd

package main

// On OpenBSD, httpd(8) runs chrooted in /var/www, so the FastCGI socket
// must live inside that chroot. httpd.conf then references it
// chroot-relative as "/run/sysmon-web.sock".
const defaultSocket = "/var/www/run/sysmon-web.sock"
