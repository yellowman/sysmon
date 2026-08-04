/*
 * tlsio.c - TLS for the connection sysmond makes to an aggregator.
 *
 * sysmond's client protocol is line-oriented over a file descriptor, and
 * every command it serves reads with one read() in getline_tcp() and
 * writes with one write() in sendline(). So rather than thread an SSL
 * handle through every call site, this keeps a small fd -> SSL table and
 * those two functions consult it. A plain socket looks the table up, finds
 * nothing, and behaves exactly as it always has - which is what keeps the
 * inbound listener, and every existing client of it, untouched.
 *
 * Dialect is OpenSSL 1.1.1 / LibreSSL, deliberately: that is what OpenBSD
 * ships and what long-lived Linux installs have. Nothing here uses the
 * 3.0-only surface (no providers, no EVP_MAC, no SSL_CTX_set_ciphersuites),
 * and peer-name verification goes through X509_VERIFY_PARAM_set1_host()
 * and set1_ip_asc(), which exist across 1.0.2, 1.1.x, 3.x and LibreSSL
 * alike.
 */

#include "config.h"

#ifdef HAVE_TLS

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/x509v3.h>

/*
 * At most a handful of TLS descriptors exist at once - one aggregator
 * connection, and room to spare - so a small table beats a hash.
 */
#define TLS_MAX_FDS 8

static struct {
	int fd;
	SSL *ssl;
} tls_table[TLS_MAX_FDS];

static SSL_CTX *tls_ctx = NULL;

/*
 * Look up the TLS handle for a descriptor. NULL means "an ordinary
 * socket", which is the answer for everything except the aggregator link.
 */
SSL *tls_for_fd(int fd)
{
	int i;

	if (fd < 0)
		return NULL;

	for (i = 0; i < TLS_MAX_FDS; i++)
	{
		if (tls_table[i].fd == fd)
			return tls_table[i].ssl;
	}
	return NULL;
}

static void tls_register(int fd, SSL *ssl)
{
	int i;

	for (i = 0; i < TLS_MAX_FDS; i++)
	{
		if (tls_table[i].ssl == NULL)
		{
			tls_table[i].fd = fd;
			tls_table[i].ssl = ssl;
			return;
		}
	}
	print_err(1, "tlsio: no room to track another TLS connection");
}

void tls_forget(int fd)
{
	int i;

	for (i = 0; i < TLS_MAX_FDS; i++)
	{
		if (tls_table[i].fd == fd && tls_table[i].ssl != NULL)
		{
			SSL_free(tls_table[i].ssl);
			tls_table[i].ssl = NULL;
			tls_table[i].fd = -1;
			return;
		}
	}
}

/*
 * How many bytes TLS already holds that select() will never tell us about.
 * getline_tcp() reads a byte at a time, so without this a record that
 * arrived whole would stall waiting for a readability event that has
 * already been consumed.
 */
int tls_pending(int fd)
{
	SSL *ssl = tls_for_fd(fd);

	return ssl != NULL ? SSL_pending(ssl) : 0;
}

static void tls_log_error(const char *what)
{
	unsigned long e;
	char buf[256];

	while ((e = ERR_get_error()) != 0)
	{
		ERR_error_string_n(e, buf, sizeof(buf));
		print_err(1, "tlsio: %s: %s", what, buf);
	}
}

/*
 * Build the client context once. Verification is on and not optional:
 * an aggregator connection carries this daemon's whole config, and a
 * monitoring system that would take that from anyone who answers is worse
 * than one that will not start.
 */
static bool tls_setup_ctx(const char *cafile)
{
	if (tls_ctx != NULL)
		return TRUE;

#if OPENSSL_VERSION_NUMBER < 0x10100000L
	SSL_library_init();
	SSL_load_error_strings();
#endif

	tls_ctx = SSL_CTX_new(TLS_client_method());
	if (tls_ctx == NULL)
	{
		tls_log_error("SSL_CTX_new");
		return FALSE;
	}

	/* TLS 1.2 floor: 1.0/1.1 are dead, and pinning the minimum here
	   rather than by cipher string is the portable way to say so. */
	if (SSL_CTX_set_min_proto_version(tls_ctx, TLS1_2_VERSION) != 1)
	{
		tls_log_error("SSL_CTX_set_min_proto_version");
		SSL_CTX_free(tls_ctx);
		tls_ctx = NULL;
		return FALSE;
	}

	SSL_CTX_set_verify(tls_ctx, SSL_VERIFY_PEER, NULL);

	if (cafile != NULL && *cafile != '\0')
	{
		if (SSL_CTX_load_verify_locations(tls_ctx, cafile, NULL) != 1)
		{
			print_err(1, "tlsio: cannot read CA file %s", cafile);
			tls_log_error("load_verify_locations");
			SSL_CTX_free(tls_ctx);
			tls_ctx = NULL;
			return FALSE;
		}
	} else if (SSL_CTX_set_default_verify_paths(tls_ctx) != 1) {
		tls_log_error("set_default_verify_paths");
		SSL_CTX_free(tls_ctx);
		tls_ctx = NULL;
		return FALSE;
	}

	return TRUE;
}

/*
 * tls_connect - dial an aggregator and complete the handshake.
 *
 * Returns the connected descriptor, or -1. The descriptor is registered in
 * the table, so from here on sendline() and getline_tcp() speak TLS on it
 * without knowing they do.
 */
int tls_connect(const char *host, int port, const char *cafile)
{
	struct my_hostent *hp;
	struct sockaddr_in name;
	X509_VERIFY_PARAM *param;
	SSL *ssl;
	int fd;

	if (!tls_setup_ctx(cafile))
		return -1;

	hp = my_gethostbyname((unsigned char *)host, AF_INET);
	if (hp == NULL || hp->my_h_addr_v4 == NULL)
	{
		print_err(1, "tlsio: cannot resolve aggregator %s", host);
		return -1;
	}

	fd = socket(AF_INET, SOCK_STREAM, 0);
	if (fd == -1)
	{
		perror("tlsio:socket");
		return -1;
	}

	memset(&name, 0, sizeof(name));
	name.sin_family = AF_INET;
	name.sin_port = htons(port);
	memcpy((char *)&name.sin_addr, (char *)hp->my_h_addr_v4, hp->h_length_v4);

	if (connect(fd, (struct sockaddr *)&name, sizeof(name)) == -1)
	{
		print_err(1, "tlsio: cannot reach aggregator %s:%d: %s",
			host, port, strerror(errno));
		close(fd);
		return -1;
	}

	ssl = SSL_new(tls_ctx);
	if (ssl == NULL)
	{
		tls_log_error("SSL_new");
		close(fd);
		return -1;
	}

	/*
	 * Verify the name we asked for, not merely that some CA signed
	 * something. Without this the whole chain check proves nothing.
	 *
	 * An address needs the IP variant: set1_host() matches DNS names and
	 * a certificate's IP addresses live in a different kind of SAN, so
	 * dialling an aggregator by address would be rejected against a
	 * certificate that names that very address.
	 */
	param = SSL_get0_param(ssl);
	X509_VERIFY_PARAM_set_hostflags(param, X509_CHECK_FLAG_NO_PARTIAL_WILDCARDS);

	{
		struct in_addr v4;
		struct in6_addr v6;
		bool is_ip = (inet_pton(AF_INET, host, &v4) == 1) ||
			(inet_pton(AF_INET6, host, &v6) == 1);

		if (is_ip)
		{
			if (X509_VERIFY_PARAM_set1_ip_asc(param, host) != 1)
			{
				tls_log_error("set1_ip");
				SSL_free(ssl);
				close(fd);
				return -1;
			}
			/* No SNI for a literal address - RFC 6066 forbids it, and
			   some servers reject the handshake outright. */
		}
		else
		{
			if (X509_VERIFY_PARAM_set1_host(param, host, 0) != 1)
			{
				tls_log_error("set1_host");
				SSL_free(ssl);
				close(fd);
				return -1;
			}
			SSL_set_tlsext_host_name(ssl, host);	/* SNI */
		}
	}

	if (SSL_set_fd(ssl, fd) != 1)
	{
		tls_log_error("SSL_set_fd");
		SSL_free(ssl);
		close(fd);
		return -1;
	}

	if (SSL_connect(ssl) != 1)
	{
		long v = SSL_get_verify_result(ssl);

		if (v != X509_V_OK)
		{
			print_err(1, "tlsio: aggregator %s certificate rejected: %s",
				host, X509_verify_cert_error_string(v));
		} else {
			tls_log_error("SSL_connect");
		}
		SSL_free(ssl);
		close(fd);
		return -1;
	}

	tls_register(fd, ssl);
	print_err(0, "tlsio: connected to %s:%d (%s)", host, port, SSL_get_version(ssl));
	return fd;
}

/*
 * The two calls the line protocol actually makes. A descriptor with no
 * TLS handle falls through to ordinary socket I/O, which is every
 * descriptor except the aggregator link.
 */
int tls_read(int fd, void *buf, int len)
{
	SSL *ssl = tls_for_fd(fd);

	if (ssl == NULL)
		return (int)read(fd, buf, (size_t)len);

	return SSL_read(ssl, buf, len);
}

int tls_write(int fd, const void *buf, int len)
{
	SSL *ssl = tls_for_fd(fd);

	if (ssl == NULL)
		return (int)write(fd, buf, (size_t)len);

	return SSL_write(ssl, buf, len);
}

/* Shut a TLS connection down and stop tracking it. */
void tls_disconnect(int fd)
{
	SSL *ssl = tls_for_fd(fd);

	if (ssl != NULL)
	{
		SSL_shutdown(ssl);
		tls_forget(fd);
	}
	if (fd >= 0)
		close(fd);
}

#else /* !HAVE_TLS */

/*
 * Built without OpenSSL: every descriptor is a plain socket, and dialling
 * an aggregator is refused rather than silently done in the clear.
 */
int tls_pending(int fd) { (void)fd; return 0; }
int tls_read(int fd, void *buf, int len) { return (int)read(fd, buf, (size_t)len); }
int tls_write(int fd, const void *buf, int len) { return (int)write(fd, buf, (size_t)len); }
void tls_forget(int fd) { (void)fd; }
void tls_disconnect(int fd) { if (fd >= 0) close(fd); }

int tls_connect(const char *host, int port, const char *cafile)
{
	(void)host; (void)port; (void)cafile;
	print_err(1, "config aggregator: this sysmond was built without TLS support");
	return -1;
}

#endif /* HAVE_TLS */
