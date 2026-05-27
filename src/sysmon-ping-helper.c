/* sysmon-ping-helper.c
 *
 * Setuid root helper for sending raw ICMP/ICMPv6 packets.
 *
 * Security design:
 * - Sanitize environment and file descriptors immediately on entry
 * - Read one request from stdin (pipe from parent sysmond)
 * - Validate all fields before use
 * - Create raw socket, drop to real UID, then send
 * - Exit immediately — no loops, no interactive input
 *
 * Exit codes:
 *   0 - Success
 *   1 - Invalid request / validation failure
 *   2 - Socket creation failed
 *   3 - Send failed
 *   4 - Security check failed
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/icmp6.h>
#include <arpa/inet.h>

#include "ping-helper.h"

static void sanitize_environment(void)
{
	/* Clear dangerous environment variables that affect dynamic linking */
	unsetenv("LD_PRELOAD");
	unsetenv("LD_LIBRARY_PATH");
	unsetenv("LD_AUDIT");
	unsetenv("LD_DEBUG");
	unsetenv("LD_DEBUG_OUTPUT");
	unsetenv("LD_PROFILE");
	unsetenv("LD_SHOW_AUXV");
	unsetenv("LD_DYNAMIC_WEAK");
	unsetenv("TMPDIR");
	unsetenv("IFS");
}

static void sanitize_fds(void)
{
	int fd;

	/* Close all file descriptors except stdin (0).
	 * stdout and stderr are reopened to /dev/null so fprintf
	 * calls don't write to attacker-controlled descriptors. */
	for (fd = 3; fd < 256; fd++)
		close(fd);

	/* Reopen stdout and stderr to /dev/null */
	fd = open("/dev/null", O_WRONLY);
	if (fd >= 0) {
		if (fd != STDOUT_FILENO)
			dup2(fd, STDOUT_FILENO);
		if (fd != STDERR_FILENO)
			dup2(fd, STDERR_FILENO);
		if (fd > STDERR_FILENO)
			close(fd);
	}
}

static void drop_to_real_uid(void)
{
	uid_t real_uid = getuid();
	gid_t real_gid = getgid();

	if (geteuid() == real_uid)
		return;

	if (setgid(real_gid) != 0)
		_exit(4);
	if (setuid(real_uid) != 0)
		_exit(4);

	/* Verify */
	if (geteuid() == 0 || getegid() == 0)
		_exit(4);
}

int main(int argc, char **argv)
{
	struct ping_helper_request req;
	int icmp_fd;
	ssize_t bytes_read;
	ssize_t bytes_sent;
	int socket_family;
	int socket_protocol;
	struct sockaddr *dest_addr;
	socklen_t dest_len;

	/* --- SECURITY: sanitize before anything else --- */
	sanitize_environment();
	sanitize_fds();

	/* Must be setuid root */
	if (geteuid() != 0)
		_exit(2);

	/* Reject command-line arguments (not expected) */
	if (argc > 1)
		_exit(1);

	/* Read exactly one request from stdin */
	bytes_read = read(STDIN_FILENO, &req, sizeof(req));
	if (bytes_read != (ssize_t)sizeof(req))
		_exit(1);

	/* Validate address family */
	if (req.address_family != HELPER_AF_INET &&
	    req.address_family != HELPER_AF_INET6)
		_exit(1);

	/* Validate packet length */
	if (req.packet_len < 8 || req.packet_len > MAX_PING_PACKET_SIZE)
		_exit(1);

	/* Validate sockaddr fields match address family */
	if (req.address_family == HELPER_AF_INET) {
		if (req.dest.v4.sin_family != AF_INET)
			_exit(1);
		socket_family = AF_INET;
		socket_protocol = IPPROTO_ICMP;
		dest_addr = (struct sockaddr *)&req.dest.v4;
		dest_len = sizeof(req.dest.v4);
	} else {
		if (req.dest.v6.sin6_family != AF_INET6)
			_exit(1);
		socket_family = AF_INET6;
		socket_protocol = IPPROTO_ICMPV6;
		dest_addr = (struct sockaddr *)&req.dest.v6;
		dest_len = sizeof(req.dest.v6);
	}

	/* Create raw socket while still root */
	icmp_fd = socket(socket_family, SOCK_RAW | SOCK_CLOEXEC, socket_protocol);
	if (icmp_fd < 0)
		_exit(2);

	/* --- DROP PRIVILEGES BEFORE SENDING --- */
	drop_to_real_uid();

	/* Send the packet (now running as unprivileged user) */
	bytes_sent = sendto(icmp_fd, req.packet, req.packet_len, 0,
	                    dest_addr, dest_len);
	close(icmp_fd);

	if (bytes_sent != req.packet_len)
		_exit(3);

	_exit(0);
}
