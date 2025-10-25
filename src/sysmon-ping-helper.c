/* sysmon-ping-helper.c
 *
 * Setuid root helper for sending raw socket packets (ICMP, ICMPv6)
 *
 * This program is intentionally minimal to reduce attack surface.
 * It ONLY sends raw packets - no parsing, no network operations.
 *
 * Security model:
 * - Runs setuid root (only way to send raw packets on most systems)
 * - Reads packet data from stdin (controlled by parent sysmond)
 * - Sends one packet (IPv4/IPv6, ICMP/ICMPv6)
 * - Drops privileges immediately
 * - Exits
 *
 * Communication protocol:
 * - Parent writes struct ping_helper_request to stdin
 * - Helper reads request, sends packet, exits with status
 *
 * Exit codes:
 *   0 - Success
 *   1 - Invalid request
 *   2 - Socket creation failed
 *   3 - Send failed
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/icmp6.h>
#include <arpa/inet.h>

#include "ping-helper.h"

/* Drop privileges to nobody/daemon */
static void drop_privileges(void)
{
	uid_t real_uid = getuid();

	/* If we're not setuid, nothing to do */
	if (geteuid() == real_uid) {
		return;
	}

	/* Drop to real UID (the user who ran sysmond) */
	if (setuid(real_uid) != 0) {
		perror("setuid");
		exit(1);
	}

	/* Verify drop worked */
	if (geteuid() == 0 || getuid() == 0) {
		fprintf(stderr, "CRITICAL: Failed to drop root privileges!\n");
		exit(1);
	}
}

int main(int argc, char **argv)
{
	struct ping_helper_request req;
	int icmp_fd;
	ssize_t bytes_read;
	ssize_t bytes_sent;

	/* Validate we're running correctly */
	if (geteuid() != 0) {
		fprintf(stderr, "ping-helper: Must be setuid root or run as root\n");
		fprintf(stderr, "ping-helper: Current euid=%d\n", geteuid());
		exit(2);
	}

	/* Read request from stdin (from parent sysmond) */
	bytes_read = read(STDIN_FILENO, &req, sizeof(req));
	if (bytes_read != sizeof(req)) {
		fprintf(stderr, "ping-helper: Invalid request size: %zd (expected %zu)\n",
		        bytes_read, sizeof(req));
		exit(1);
	}

	/* Validate request */
	if (req.packet_len < 8 || req.packet_len > MAX_PING_PACKET_SIZE) {
		fprintf(stderr, "ping-helper: Invalid packet length: %d\n", req.packet_len);
		exit(1);
	}

	if (req.address_family != HELPER_AF_INET && req.address_family != HELPER_AF_INET6) {
		fprintf(stderr, "ping-helper: Invalid address family: %d\n", req.address_family);
		exit(1);
	}

	/* Determine socket parameters based on address family */
	int socket_family;
	int socket_protocol;
	struct sockaddr *dest_addr;
	socklen_t dest_len;

	if (req.address_family == HELPER_AF_INET) {
		socket_family = AF_INET;
		socket_protocol = IPPROTO_ICMP;
		dest_addr = (struct sockaddr *)&req.dest.v4;
		dest_len = sizeof(req.dest.v4);
	} else {  /* HELPER_AF_INET6 */
		socket_family = AF_INET6;
		socket_protocol = IPPROTO_ICMPV6;
		dest_addr = (struct sockaddr *)&req.dest.v6;
		dest_len = sizeof(req.dest.v6);
	}

	/* Create raw ICMP/ICMPv6 socket (requires root/CAP_NET_RAW) */
	icmp_fd = socket(socket_family, SOCK_RAW, socket_protocol);
	if (icmp_fd < 0) {
		perror("ping-helper: socket");
		exit(2);
	}

	/* Send the ICMP/ICMPv6 packet */
	bytes_sent = sendto(icmp_fd, req.packet, req.packet_len, 0,
	                    dest_addr, dest_len);

	if (bytes_sent < 0) {
		perror("ping-helper: sendto");
		close(icmp_fd);
		exit(3);
	}

	if (bytes_sent != req.packet_len) {
		fprintf(stderr, "ping-helper: Partial send: %zd/%d bytes\n",
		        bytes_sent, req.packet_len);
		close(icmp_fd);
		exit(3);
	}

	/* Close socket */
	close(icmp_fd);

	/* Drop privileges before exit (defense in depth) */
	drop_privileges();

	/* Success */
	exit(0);
}
