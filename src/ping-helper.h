/* ping-helper.h
 *
 * Shared definitions for sysmon-ping-helper communication
 *
 * The ping helper is a setuid root program that sends raw socket packets
 * (ICMP, ICMPv6, etc.) on behalf of unprivileged sysmond.
 */

#ifndef PING_HELPER_H
#define PING_HELPER_H

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>

/* Maximum packet size we'll handle */
#define MAX_PING_PACKET_SIZE 256

/* Path to ping helper (can be overridden at compile time) */
#ifndef PING_HELPER_PATH
#define PING_HELPER_PATH "/usr/local/libexec/sysmon-ping-helper"
#endif

/* Address family types we support */
#define HELPER_AF_INET   2    /* IPv4 */
#define HELPER_AF_INET6  10   /* IPv6 */

/* Protocol types */
#define HELPER_PROTO_ICMP    1   /* ICMP (IPv4) */
#define HELPER_PROTO_ICMPV6  58  /* ICMPv6 (IPv6) */

/* Request structure for ping helper (protocol-agnostic) */
struct ping_helper_request {
	int address_family;                /* HELPER_AF_INET or HELPER_AF_INET6 */
	int protocol;                      /* HELPER_PROTO_ICMP or HELPER_PROTO_ICMPV6 */

	/* Destination address (use appropriate union member based on address_family) */
	union {
		struct sockaddr_in  v4;    /* For AF_INET */
		struct sockaddr_in6 v6;    /* For AF_INET6 */
		unsigned char raw[128];    /* Generic storage */
	} dest;

	unsigned char packet[MAX_PING_PACKET_SIZE];  /* Packet data */
	int packet_len;                              /* Length of packet */
};

#endif /* PING_HELPER_H */
