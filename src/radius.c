/* The long-awaited radius check */

#include "config.h"
#include "strl.h"

/* our local structure that we deal with */
struct radius_data {
	unsigned char seq;
	int packetsent;
	time_t lastsent;
	}; 

/* see rfc 2138, section 3 */

struct radius_packet_head {
	unsigned char code;
	unsigned char identifier;
	unsigned short int length;
	unsigned char authenticator[16];
 };

void send_radius_packet(int, struct monitorent *, int);

unsigned char rad_seq = 1;

#define RADIUS_Access_Request	1
#define RADIUS_Access_Accept	2
#define RADIUS_Access_Reject	3

void print_in_hex(unsigned char *message, int msgsize)
{
        int x;
        for (x =0;x<msgsize;x++)
        {
                if ((message[x] > 0) && (message[x] < 26))
                        fprintf(stderr, "0x%-2.2x ", message[x]);
                else if (message[x] == 0)
                        fprintf(stderr, "0x%-2.2x ", message[x]);
                else
                        fprintf(stderr, "0x%-2.2x ", message[x]);
                if ((x != 0) && (((x+1) %16) == 0))
                        fprintf(stderr, "\n");
        }
        fprintf(stderr, "\n");

}


/*
 * Do the setup and initalization of the radius check
 */
void start_check_radius(struct monitorent *here, time_t now_t)
{
	struct radius_data *localstruct = NULL;
	struct my_hostent *hp = NULL;
	struct sockaddr_in name;
	int serrno = -1;
	int errcode = 0;

	hp = my_gethostbyname(here->checkent->hostname, AF_INET);

	if (hp == NULL)
	{
		here->retval = SYSM_NODNS;
                return;
        }

	/* Allocate our memory */
	here->monitordata = MALLOC(sizeof(struct radius_data), "radius localstruct");
	if (here->monitordata == NULL)
	{
		print_err(1, "radius.c: MALLOC failed");
		return;
	}
	memset(here->monitordata, 0, sizeof(struct radius_data));
	localstruct = here->monitordata;

	here->filedes = udp_open_sock();
	if (here->filedes == -1)
	{
		print_err(1, "radius.c: udp_open_sock() failed while checking %s", here->checkent->hostname);
		FREE(here->monitordata);
		here->retval = here->checkent->lastcheck;
		return;
	}

	/* setup the name structure */
	memset(&name, 0, sizeof(name));
	
	/* copy the remote address into the strcture */
	memcpy((char*)&name.sin_addr, (char*)hp->my_h_addr_v4, hp->h_length_v4);

	/* internet, what is that? */
	name.sin_family = AF_INET;

	/* radius can use a few different port numbers.. allow
		them to specify in conf file */

	name.sin_port = htons(here->checkent->port);

	errcode = connect(here->filedes, (struct sockaddr *)&name,
		sizeof(struct sockaddr_in));

	serrno = errno;

	if (errcode != 0)
	{
		perror("radius.c: connect");
		close(here->filedes);
		FREE(here->monitordata);
		switch (serrno)
		{
                        case ECONNREFUSED:
                        case EINTR:
                                here->retval = SYSM_CONNREF;
                                break;
                        case ENETUNREACH:
                                here->retval = SYSM_NETUNRCH;
                                break;
                        case EHOSTDOWN:
                        case EHOSTUNREACH:
                                here->retval = SYSM_HOSTDOWN;
                                break;
                        case ETIMEDOUT:
                                here->retval = SYSM_TIMEDOUT;
                                break;
                }
		return;
	}

	localstruct->seq = rad_seq++;

	/* send radius-access-request packet */
	send_radius_packet(here->filedes, here, localstruct->seq);
	localstruct->packetsent++;
	localstruct->lastsent = now_t;
	/* If this return is reached, service_check_radius will be
	   called later */
	return;
}

void service_check_radius(struct monitorent *here, time_t now_t)
{
	struct radius_data *localstruct = NULL;

	unsigned char response[4096];
	int ret;

	localstruct = here->monitordata;
	if (now_t-localstruct->lastsent < 1)
	{
		return;
	}

	if (localstruct->packetsent > 10)
	{
		here->retval = SYSM_NORESP;
		close(here->filedes);
		FREE(localstruct);
		here->monitordata = NULL;
		return;
	}


	if (data_waiting_read(here->filedes, 0))
	{
		ret = read(here->filedes, response, 4096);

		if (ret == -1)
		{
	                switch (errno)
			{
				case ECONNREFUSED:
				case EINTR:
	                                here->retval = SYSM_CONNREF;
	                                break;
				case ENETUNREACH:
	                                here->retval = SYSM_NETUNRCH;
	                                break;
				case EHOSTDOWN:
				case EHOSTUNREACH:
	                                here->retval = SYSM_HOSTDOWN;
	                                break;
				case ETIMEDOUT:
	                                here->retval = SYSM_TIMEDOUT;
	                                break;
				default:
					perror("radius.c:read");
					print_err(0, "radius.c:reading radius response");
					print_err(0, "radius.c:leaving state alone");
					here->retval = here->checkent->lastcheck;
			}
		} else if (ret > 0) {
			if (response[0] == 2)
			{
				here->retval = SYSM_OK;
			} else if (response[0] == 3) {
				here->retval = SYSM_BAD_AUTH;
			} else {
				print_err(0, "radius.c:Unknown response");
				print_in_hex(response, ret);
			}
		}
		close(here->filedes);
		FREE(localstruct);
		return;
	}
	/* send_packet */

	send_radius_packet(here->filedes, here, localstruct->seq);

	/* increment packetsent */

	localstruct->packetsent++;
        localstruct->lastsent = now_t;


	return;
}

/*
 * Stop the check, and free any pending memory to be
 * returned to the main processor pool
 */
void stop_check_radius(struct monitorent *here)
{
	struct radius_data *localstruct = NULL;

	localstruct = here->monitordata;
	if (localstruct != NULL)
	{
		close(here->filedes);
		FREE(localstruct);
		here->monitordata = NULL;
	}
	return;
}

/*
 * Do the md5 sum of the RA stuff for the packet
 *
 */
void calculate_RA(unsigned char *RA, unsigned char *packet, 
	unsigned int packetlen, unsigned char *Secret)
{
        unsigned char buffer[256];
        unsigned char temp_pkt[4096];
        int secretlen;
        int md5sumlen;

        secretlen = strlen(Secret);
        md5sumlen = (secretlen+packetlen);

        memset(buffer, 0, 256);
        memset(temp_pkt, 0, 4096);

        memcpy(temp_pkt, packet, packetlen);
        memcpy(temp_pkt+packetlen, Secret, secretlen);

        md5_calc(RA, temp_pkt, md5sumlen);

}

void gen_passwd(unsigned char *passwd_resp, int *resp_len, char *cleartext_pw,
	char *secret, unsigned char *request_authenticator)
{
	unsigned char *ptr;
	int pw_len;
	int secretlen = strlen(secret);
	unsigned char md5buf[130];
	unsigned char pw_digest[17];
	int i;
	int pass;
	int passes;
	
	/* Allocate temp space to work on pw, because of  following,
		excerpted from rfc2138 5.2

      On transmission, the password is hidden.  The password is first
      padded at the end with nulls to a multiple of 16 octets.  A one-
      way MD5 hash is calculated over a stream of octets consisting of
      the shared secret followed by the Request Authenticator.  This
      value is XORed with the first 16 octet segment of the password and
      placed in the first 16 octets of the String field of the User-
      Password Attribute.

	*/

	pw_len = strlen(cleartext_pw);
	if (pw_len > 255)
		pw_len = 255;

	passes = MAX(1, (pw_len+15)/16);
		
	memset(passwd_resp, 0, 256);
	memcpy(passwd_resp, cleartext_pw, strlen(cleartext_pw));

        memcpy(md5buf, secret, secretlen);
	memcpy(md5buf+secretlen, request_authenticator, 16);

        ptr = (char *) passwd_resp;

        for (pass = 0; pass < passes; pass++)
        {
                md5_calc (pw_digest, md5buf, secretlen + 16);
                for (i = 0; i < 16; i++)
                {
                        ptr[i] ^= pw_digest[i];
                }
                memcpy ((char *) md5buf + secretlen, (char *) ptr, 16);
                ptr += 16;
        }
	memset(md5buf, 0, secretlen);
	*resp_len = (pass*16);
	
}

void gen_ra(char *data, int len)
{
	int x;
	for (x = 0; x < len ; x++)
		data[x] = rand();
}


/* 
 * Form and send the access-request packet 
 */
void send_radius_packet(int filedes, struct monitorent *here, int seq)
{
	/* Send the Packet */
	unsigned char packet[1024];
	struct radius_packet_head *radpkt;
	int packetindex = 0;
	int ret;
	int pwlen = 0;

	memset(packet, 0, 1024);
	radpkt = (struct radius_packet_head *)&packet;
	
	radpkt->code = RADIUS_Access_Request;
	radpkt->identifier = seq;
	gen_ra(packet+4, 16);
	
	packetindex = 20;
	/* add username */
	
	packet[20]  = 1;
	packet[21] = (strlen(here->checkent->username)+2);
	memcpy(packet+packetindex+2, here->checkent->username, (packet[21]-2));
	packetindex = packetindex+ packet[21];

	/* add password */
	packet[packetindex] = 2;
	gen_passwd(packet+packetindex+2, &pwlen, here->checkent->password,
		here->checkent->secret, packet+4);
	packet[packetindex+1] = 2+pwlen;
	packetindex = packetindex+2+pwlen;

        /* set service-type = 8 - authenticate-only */

        packet[packetindex] = 6;
        packetindex++;
        packet[packetindex] = 6;
        packetindex++;
        packet[packetindex] = 0;
        packet[packetindex+1] = 0;
        packet[packetindex+2] = 0;
        packet[packetindex+3] = 8;
        packetindex = packetindex+4;

	packet[packetindex] = 32;
	packetindex++;
	packet[packetindex] = 8;
	packetindex++;
	strlcpy((char*)(packet+packetindex), "sysmon", 1024 - packetindex);
	packetindex += 6;

	packet[packetindex] = 61;
	packetindex++;
	packet[packetindex] = 6;
	packetindex++;
	packet[packetindex] = 0;
	packetindex++;
	packet[packetindex] = 0;
	packetindex++;
	packet[packetindex] = 0;
	packetindex++;
	packet[packetindex] = 5;
	packetindex++;

	packet[3] = packetindex;
	
	
	ret = write(filedes, packet, packetindex);
	if (ret == -1)
	{
		perror("write");
	}

	/* send packet */

}

