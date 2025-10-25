/* $Id: dns.c,v 1.9 2006/05/09 02:46:03 jared Exp $ */
/*
 * dns packet format 
 *
 * HEADER:
 * bytes 0-1 (request id, unsigned short int)
 * byte 2 (bitmask)
 *    bit    7 - clear = query, set = response
 *    bits 6-3 - opcode (0 - query, 2 - status req)
 *    bit    2 - AA (set = AA, clear in anything other than response)
 *    bit    1 - Truncation (set if truncated)
 *    bit    0 - recursion denied (set in query if we want recurion)
 * byte 3
 *    bit    7 - recursion available - only matters in response
 *    bits 6-4 - 'Z field' - always 0
 *    bits 3-0 - response code - only valid in responses.  usually 0
 * bytes 4-5 (qdcount) - # of questions in payload (usually 1)
 * bytes 6-7 (ancount) - # of answers in payload - 0 in query.
 * bytes 8-9 (nscount) - number of auth resource records for question
 *                       0 in query
 * bytes 10-11 (arcount) - additional resource records in resp.  0 in query
 * 
 * PAYLOAD:
 * 3 fields - QNAME, QTYPE, QCLASS
 * QNAME: eg: sysmon.org. encodes as 6,'s','y','s','m','o','n',3,'o','r','g',0
 *        eg: yahoo.com.  encodes as 5,'y','a','h','o','o',3,'c','o','m',0
 * QTYPE: 2 bytes - query type for A record = 1
 * QCLASS:2 bytes - query type for IN record = 1
 */

#include "config.h"

struct dns_data {
	unsigned short int sent;
	time_t lastsent;
	unsigned char *pkt_sent;
	unsigned short int pkt_len;
};

unsigned char *dns_make_qname(unsigned char *domainname, unsigned int *q_len)
{
	int x = 0;
	int y = 0;
	int idx = 0;
	int alloc_len;
	char *encoded = NULL;

	if (domainname == NULL)
	{
		*q_len = 0;
		return NULL;
	}
	alloc_len = strlen(domainname) + 2;

	encoded = malloc(alloc_len);
	memset(encoded, 0, alloc_len);
	while (x < strlen(domainname))
	{
		for (;x<strlen(domainname);x++)
			if (domainname[x] == '.') 
				break;
		encoded[idx] = (x-y);
		idx++;
		memcpy(encoded+idx, domainname+y, (x-y));
		idx =+ idx+(x-y);
		x++;
		y=x;
	}
	
	*q_len = alloc_len;
	return encoded;
}

/*
 * domainname = domain to query
 * aa = check for authoratitive answer
 * rec = request recursive lookup
 */

unsigned char *dns_packet(unsigned char *domain, bool aa, bool rec, unsigned short int *pkt_len)
{
	unsigned short int request_id; /*bytes 0-1 */
	unsigned char byte_2 = 0;
	unsigned char byte_3 = 0;
	unsigned short int qdcount = 1;  /*bytes 4-5 */
	unsigned short int ancount = 0;  /* bytes 6-7 */
	unsigned short int nscount = 0; /* bytes 8-9 */
	unsigned short int arcount = 0; /* bytes 10-11 */
	unsigned char *req_qname = NULL;
	unsigned short qtype = 1;  /* IN */
	unsigned short qclass = 1; /* IN */
	unsigned char *full_packet; /* formed packet */
	unsigned int qname_len= 0;
	unsigned int hdr_length = 12;
	unsigned short int full_length;
	unsigned short temp;

	request_id = generate_ident();

	byte_2 = 0x00; /* clear bit 7 - query */
	if (aa)
	{
		byte_2 = byte_2 | 0x04; /* AA response requested */
	}
	if (rec)
	{
		byte_2 = byte_2 | 0x01; /* recursion requested */
	}
	byte_3 = 0; /* used in responses only as of 20030126 */

	req_qname = dns_make_qname(domain, &qname_len);


	full_length = hdr_length+qname_len+4;
	full_packet=malloc(full_length);
	
	/* htons */
        temp=htons(request_id);
        memcpy(full_packet, &temp, 2);

	full_packet[2] = byte_2;
	full_packet[3] = byte_3;
	temp=htons(qdcount);
	memcpy(full_packet+4, &temp, 2);
	temp=htons(ancount);
	memcpy(full_packet+6, &temp, 2);
	temp=htons(nscount);
	memcpy(full_packet+8, &temp, 2);
	temp=htons(arcount);
	memcpy(full_packet+10, &temp, 2);

	/* pack in qname */
	memcpy(full_packet+12, req_qname, qname_len);
	free(req_qname);

        temp=htons(qtype);
        memcpy(full_packet+12+qname_len, &temp, 2);
        temp=htons(qclass);
        memcpy(full_packet+12+qname_len+2, &temp, 2);

	*pkt_len = full_length;

	return full_packet;
}

/* start the test */

void start_check_dns(struct monitorent *here)
{
	struct  dns_data *localstruct = NULL;
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
        here->monitordata = MALLOC(sizeof(struct dns_data), "dns localstruct");
        if (here->monitordata == NULL)
        {
                print_err(1, "dns.c: MALLOC failed");
                return;
        }
        memset(here->monitordata, 0, sizeof(struct dns_data));
        localstruct = here->monitordata;

	here->filedes = udp_open_sock();
        if (here->filedes == -1)
        {
                print_err(1, "dns.c: udp_open_sock() failed while checking %s", here->checkent->hostname);
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

        /* dns tends to use UDP/53 */

        name.sin_port = htons(53);

        errcode = connect(here->filedes, (struct sockaddr *)&name,
                sizeof(struct sockaddr_in));

        serrno = errno;

        if (errcode != 0)
        {
                perror("dns.c: connect");
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

	/* form the dns packet */
	localstruct->pkt_sent = dns_packet(here->checkent->dns_query, 
		here->checkent->dns_aa, here->checkent->dns_recursion,
		&localstruct->pkt_len);

	return;
}

void service_check_dns(struct monitorent *here)
{
        struct dns_data *localstruct = NULL;
	unsigned char response[4096];
	int ret;
	int serrno = -1;
	time_t now_t;

	if (here->monitordata == NULL)
		return;
	localstruct = here->monitordata;
	
	time(&now_t);
        if (now_t - localstruct->lastsent < 1)
        {
                return;
        }

        if (localstruct->sent > 10)
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
                                        perror("dns.c:read");
                                        print_err(0, "dns.c:reading dns response");
                                        print_err(0, "dns.c:leaving state alone");
                                        here->retval = here->checkent->lastcheck;
                        }
                } else if (ret > 0) {
			/* got dns response -- need to parse it */
			here->retval = SYSM_OK;
                }
                close(here->filedes);
                FREE(localstruct);
                return;
        }


        ret = write(here->filedes, localstruct->pkt_sent, localstruct->pkt_len);
	serrno = errno;
	if (ret == -1)
	{
		print_err(1, "dns.c: write()");
	} else {
	        localstruct->sent++;
	        localstruct->lastsent = now_t;
	}

}

/*
 * stop the test
 */
void stop_check_dns(struct monitorent *here)
{
        struct dns_data *localstruct = NULL;

        /* don't leak the fd */
        close(here->filedes);

        if (here->monitordata == NULL)
                return;

        localstruct = here->monitordata;

	/* don't leak memory */
        FREE(localstruct);
        here->monitordata = NULL;
        return;
}

