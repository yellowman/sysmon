/* $Id: block.c,v 1.3 1999/12/09 09:42:30 jared Exp $ */
#include "config.h"

char *myname;
int dnslog = 0, dnsexpire = 1500, facility =-2;
int queuetime = 60;
bool debug = FALSE;
bool mallocdebug = FALSE;
unsigned short disable_icmp = 0;
struct dnscache *dnshead = NULL;
struct clientstatus *clienthead = NULL;

void	client_poll (int l_timeout)
{
}

int	main(int argc, char **argv)
{
	int ret, fd = -1;
	char *hostname, buffer[128];
	struct timeval start, stop;
	struct my_hostent *hp;

	myname = argv[0];

	if (argc > 1)
		hostname = argv[1];

	else 
	{
		fprintf(stderr, "Usage: %s hostname\n", argv[0]);
		exit(0);
	}

	if ( !(hp = my_gethostbyname(hostname)) )
	{
		fprintf(stderr, "unable to find %s in DNS\n", hostname);
		return 0;
	}
	
	gettimeofday(&start, NULL);
	if ( (ret = open_host(hostname, 1345, &fd, 20)) )
	{
		fprintf(stderr, "While connecting, got %s\n", errtostr(ret));
		exit(1);
	}
	gettimeofday(&stop, NULL);
	fprintf(stdout, "open_host: diff: %10.6f\n", mydifftime(start, stop));

        gettimeofday(&start, NULL);
	ret = getline_tcp(fd, buffer);
	if (ret == -1)
		fprintf(stdout, "getline_tcp returned error\n");
        gettimeofday(&stop, NULL);
        fprintf(stdout, "getline_tcp:   diff: %10.6f\n", 
		mydifftime(start, stop));
	
        gettimeofday(&start, NULL);
        ret = sendline(fd, "QUIT");
        gettimeofday(&stop, NULL);
        fprintf(stdout, "open_host: diff: %10.6f\n", mydifftime(start, stop));
	ret=getline_tcp(fd, buffer);
	if (close(fd) == -1)
		return 0;

	return 0;
}
