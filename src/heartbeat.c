/* $Id: heartbeat.c,v 1.4 2003/04/17 03:47:07 jared Exp $ */
#include "config.h"

/* send a heartbeat packet to a host */

void	send_heartbeat(char *myhostname)
{
        struct my_hostent *hp = NULL;
        struct sockaddr_in name;
	struct utsname myunamedata;
	char message[1024];
	int errcode = 0, msg_sock = 0;

	msg_sock = udp_open_sock(msg_sock);
        name.sin_family = AF_INET;      /* yeah, that internet stuff */
        name.sin_addr.s_addr = INADDR_ANY; /* like the www, right? */

	if (uname(&myunamedata) == -1)
		return;

	hp = my_gethostbyname(HEARTBEAT_HOST, AF_INET);

	if (hp == 0)	/* We canna find it Jim! */
		return;

        memcpy((char*)&name.sin_addr, (char*)hp->my_h_addr_v4, hp->h_length_v4);
        name.sin_port = htons(HEARTBEAT_PORT);

        errcode = connect(msg_sock, (struct sockaddr*)&name, sizeof(name));

	memset(message, 0,  sizeof(message)); /* zero it out */
	
	snprintf(message, 1000, "Hostname: %s Vers: %s running %s\n", 
		myhostname, SYSM_VERS, myunamedata.sysname);

	errcode = send (msg_sock, message, strlen(message)+2, 0);

	if (close(msg_sock) == -1)
		return;
}
