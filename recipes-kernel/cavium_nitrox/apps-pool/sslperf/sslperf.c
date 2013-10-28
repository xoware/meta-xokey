#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <openssl/ssl.h>
#include <openssl/engine.h>

#define	err(_x, ...)		fprintf (stderr, _x, ## __VA_ARGS__)
#define	err_exit(_x, ...)	{					\
					err (_x, ## __VA_ARGS__);	\
					exit (-1);			\
				}
#define	serr(_x, ...)		{					\
					BIO_printf (bioerr, _x, 	\
					    ## __VA_ARGS__);		\
					ERR_print_errors (bioerr);	\
				}
#define	serr_exit(_x, ...)	{					\
					serr (_x, ## __VA_ARGS__);	\
					exit (-1);			\
				}

static	const char *options = "hsi:p:c:v:t:k:w:b:n:f:ra";
static	char *saddr = "192.168.48.1";
static	short port = 4433;
static	char *cipher = "RC4-MD5";
static	int sslver = 1;
static	char *cert = NULL;
static	char *key = NULL;
static	char *passwd = "passwd";
static	int buflen = 4096;
static	int intr = 2;
static	int ncli = 4;
static	int tps = 0;
static	int wapache = 0;
static	BIO *bioerr = NULL;
static	unsigned char *rwbuf;
static	struct timeval sttime;
static	double readb;
static	int cpipe;
static	struct cinfo {
	int	pid;
	int	rpipe;
} *cinfo;

static	int server ();
static	int client ();
static	int s_accept (int);
static	int c_connect ();
static	void help ();
static	SSL_CTX *ctx_get (int, const char *, const char *, const char *);
static	int passwdcb (char *, int, int, void *);
static	void sigchld (int);
static	void sigusr1 (int);

int
main (argc, argv)
	int	argc;
	char	**argv;
{
	signed char	option;
	int	isserver = 0;
	int	ret;
#ifdef USE_CAVIUM_ENGINE
	ENGINE *e = NULL;
#endif

	while ((option = getopt (argc, argv, options)) != -1) {
		switch (option) {
		case 'h':
			help ();
			exit (0);
		case 's':
			isserver = 1;
			break;
		case 'i':
			saddr = strdup (optarg);
			break;
		case 'p':
			port = atoi (optarg);
			break;
		case 'c':
			cipher = strdup (optarg);
			break;
		case 'v':
			sslver = atoi (optarg);
			if (sslver < 1 || sslver > 3) {
				err_exit ("ssl version should be either 1, 2 "
				    "or 3\n");
			}
			break;
		case 't':
			cert = strdup (optarg);
			break;
		case 'k':
			key = strdup (optarg);
			break;
		case 'w':
			passwd = strdup (optarg);
			break;
		case 'b':
			buflen = atoi (optarg);
			break;
		case 'n':
			intr = atoi (optarg);
			break;
		case 'f':
			ncli = atoi (optarg);
			break;
		case 'r':
			tps = 1;
			break;
		case 'a':
			wapache = 1;
			break;
		case '?':
		default:
			if (strchr (options, option) != NULL)
				err ("option %c needs an argument\n", option);
			exit (-1);
		}
	}
	SSL_library_init ();
	SSL_load_error_strings ();
#ifdef USE_CAVIUM_ENGINE
	printf("Using cavium engine\n");
	ENGINE_load_builtin_engines();
	e = ENGINE_by_id("cavium");
	if(!e) 
    {
		printf("Failed to load engine\n");
		 exit(-1);
    }		  
	if(!ENGINE_set_default(e, ENGINE_METHOD_ALL))
     {	
			BIO_printf(bioerr,"can't use that engine\n");
			ERR_print_errors(bioerr);
			ENGINE_free(e);
			return NULL;
	  }
	  ENGINE_free(e); 

#if 0	
	e = ENGINE_by_id("dynamic");
	if (e) {
		//if (!ENGINE_ctrl_cmd_string(e, "SO_PATH",                                                     "/usr/local/ssl/lib/engines/libcavium.so", 0) ||                      !ENGINE_ctrl_cmd_string(e, "ID", "cavium", 0) ||                                !ENGINE_ctrl_cmd_string(e, "LOAD", NULL, 0)) {
		if (!ENGINE_ctrl_cmd_string(e, "SO_PATH",                                                     "cavium", 0) ||                                                       !ENGINE_ctrl_cmd_string(e, "ID", "cavium", 0) ||                                !ENGINE_ctrl_cmd_string(e, "LOAD", NULL, 0)) {
			printf("Failed to load engine\n");
			ENGINE_free(e);
			exit(-1);
		}
		if (!ENGINE_set_default(e, ENGINE_METHOD_ALL)) {
			printf("Unable to initialize the engine\n");
			exit(-1);
		}
	}
	//e = ENGINE_by_id("cavium");
	#endif
#endif /* USE_CAVIUM_ENGINE */
        bioerr = BIO_new_fp (stderr, BIO_NOCLOSE);
	if (bioerr == NULL)
		err_exit ("unable to create err BIO object\n");
	if (isserver) {
		if (cert == NULL)
			cert = "server.pem";
		if (key == NULL)
			key = "server.key";
		ret = server ();
	}
	else {
		if (cert == NULL)
			cert = "client.pem";
		if (key == NULL)
			key = "client.key";
		ret = client ();
	}
	BIO_free (bioerr);
	return ret;
}

int
server ()
{
	int	fd;
	int	cd;
	struct	sockaddr_in saddr;
	struct	sockaddr_in paddr;
	int	plen;

	signal (SIGCHLD, SIG_IGN);
	if ((fd = socket (AF_INET, SOCK_STREAM, 0)) == -1) {
		err ("socket error (%s)\n", strerror (errno));
		return -1;
	}
	memset (&saddr, 0, sizeof saddr);
	saddr.sin_family = AF_INET;
	saddr.sin_addr.s_addr = INADDR_ANY;
	saddr.sin_port = htons (port);
	if (bind (fd, (struct sockaddr *) &saddr, sizeof saddr) == -1) {
		err ("bind error (%s)\n", strerror (errno));
		goto err;
	}
	listen (fd, 64);
	if (tps) {
		fork ();
		fork ();
		fork ();
		fork ();
		fork ();
		fork ();
		fork ();
		fork ();
	}
	while (1) {
		plen = sizeof paddr;
		cd = accept (fd, (struct sockaddr *) &paddr, &plen);
		if (cd == -1) {
			err ("accept error (%s)\n", strerror (errno));
			break;
		}
		if (tps) {
			s_accept (cd);
		}
		else {
			switch (fork ()) {
			case 0:
				return s_accept (cd);
			case -1:
				err ("unable to spawn\n");
			default:
				close (cd);
				break;
			}
		}
	}
err:
	close (fd);
	return -1;
}

int
client ()
{
	int	i;
	int	tpipe[2];
	int	nc;
	double	tperf;
	double	cperf;

	signal (SIGCHLD, sigchld);
	if ((cinfo = calloc (ncli, sizeof (struct cinfo))) == NULL) {
		err ("unable to allocate client db\n");
		return -1;
	}
	for (i = 0; i < ncli; ++i) {
		if (pipe (tpipe) != 0) {
			while (--i >= 0)
				kill (cinfo[i].pid, SIGKILL);
			return -1;
		}
		switch (cinfo[i].pid = fork ()) {
		case 0:
			cpipe = tpipe[1];
			close (tpipe[0]);
			return c_connect ();
		default:
			cinfo[i].rpipe = tpipe[0];
			close (tpipe[1]);
		}
	}
	while (1) {
		sleep (intr);
		nc = 0;
		for (i = 0; i < ncli; ++i)
			if (cinfo[i].pid != 0) {
				kill (cinfo[i].pid, SIGUSR1);
				read (cinfo[i].rpipe, &cperf, sizeof cperf);
				tperf += cperf;
				nc++;
			}
		printf ("\rwith %d clients, ", nc);
		if (tps)
			printf ("transactions/sec = %f", tperf);
		else
			printf ("throughput = %f Mbps", tperf);
		fflush (stdout);
		tperf = 0;
	}
}

int
s_accept (fd)
	int	fd;
{
	SSL_CTX	*ctx = NULL;
	SSL	*ssl = NULL;
	BIO	*sbio = NULL;

	if ((ctx = ctx_get (sslver, cipher, cert, key)) == NULL)
		goto err;
	if ((ssl = SSL_new (ctx)) == NULL) {
		serr ("SSL_new failed\n");
		goto err;
	}
	if ((sbio = BIO_new_socket (fd, BIO_NOCLOSE)) == NULL) {
		serr ("BIO_new_socket failed\n");
		goto err;
	}
	SSL_set_bio (ssl, sbio, sbio);
	if (SSL_accept (ssl) <= 0) {
		serr ("SSL_accept failed\n");
		goto err;
	}
	if (!tps) {
		if ((rwbuf = calloc (buflen, sizeof (char))) == NULL) {
			err ("unable to allocate read/write buffer\n");
			goto done;
		}
		while (1)
			if (SSL_write (ssl, rwbuf, buflen) != buflen) {
				serr ("SSL_write failed to write all bytes\n");
				goto done;
			}
	}
done:
	SSL_shutdown (ssl);
err:
	if (ssl)
		SSL_free (ssl);
	if (ctx)
		SSL_CTX_free (ctx);
	close (fd);
	return -1;
}

int
c_connect ()
{
	SSL_CTX	*ctx = NULL;
	SSL	*ssl = NULL;
	BIO	*sbio = NULL;
	int	fd;
	struct	sockaddr_in addr;
	int	c;

	signal (SIGUSR1, sigusr1);
	readb = 0;
	gettimeofday (&sttime, NULL);
reconn:
	if ((fd = socket (AF_INET, SOCK_STREAM, 0)) == -1) {
		err ("socket error (%s)\n", strerror (errno));
		return -1;
	}
	memset (&addr, 0, sizeof addr);
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = inet_addr (saddr);
	addr.sin_port = htons (port);
	if (connect (fd, (struct sockaddr *) &addr, sizeof addr) == -1) {
		err ("connect error (%s)\n", strerror (errno));
		goto err;
	}
	if ((ctx = ctx_get (sslver, cipher, cert, key)) == NULL)
		goto err;
	if ((ssl = SSL_new (ctx)) == NULL) {
		serr ("SSL_new failed\n");
		goto err;
	}
	if ((sbio = BIO_new_socket (fd, BIO_NOCLOSE)) == NULL) {
		serr ("BIO_new_socket failed\n");
		goto err;
	}
	SSL_set_bio (ssl, sbio, sbio);
	if (SSL_connect (ssl) <= 0) {
		serr ("SSL_connect failed\n");
		goto err;
	}
	if (tps) {
		if (!wapache) {
			/* bug: should be SSL_read */
			while (read (fd, rwbuf, buflen) > 0)
				;
		}
		readb++;
	}
	else {
		if (wapache) {
			char	req[128];

			snprintf (req, 128, "GET /%d.html\n\n", buflen);
			SSL_write (ssl, req, strlen (req));
		}
		if ((rwbuf = malloc (buflen)) == NULL) {
			err ("unable to allocate read/write buffer\n");
			goto err;
		}
		readb = 0;
		gettimeofday (&sttime, NULL);
		while (1) {
			/* bug: should be SSL_read */
			if ((c = read (fd, rwbuf, buflen)) <= 0)
				break;
			readb += c;
		}
	}
	SSL_shutdown (ssl);
	close (fd);
err:
	if (ssl)
		SSL_free (ssl);
	if (ctx)
		SSL_CTX_free (ctx);
	if (tps)
		goto reconn;
	return -1;
}

void
help ()
{
	err ("sslperf   [-h] [-s] [-i serverip] [-p server|client port]\n");
	err ("          [-c cipher] [-v ssl version] [-t server certificate]\n");
	err ("          [-k server private key] [-w pass phrase]\n");
	err ("          [-b response buffer size]\n");
	err ("          [-n stats display interval] [-f number of clients]\n");
	err ("          [-r] [-a]\n\n");
	err ("          -h show help\n");
	err ("          -s run as a server\n");
	err ("          -i server ip address [default is 192.168.48.1]\n");
	err ("          -p server | client port [default is 4433]\n");
	err ("          -c cipher [default is RC4-MD5]\n");
	err ("          -v ssl version, 1 = TLSv1, 2 = SSLv2, 3 = SSLv3\n");
	err ("             [default is 1, TLSv1]\n");
	err ("          -t server certificate [default is server.pem for\n");
	err ("             server and client.pem for client]\n");
	err ("          -k server key [default is server.key for server\n");
	err ("             and client.key for client]\n");
	err ("          -w pass phrase [default is passwd]\n");
	err ("          -b server response buffer size [default 4096]\n");
	err ("          -n interval for stats display [default 2 secs]\n");
	err ("          -f number of clients to run [default 4]\n");
	err ("          -r run in TPS mode [default off]\n");
	err ("          -a remote server is apache [default no]\n");
}

SSL_CTX *
ctx_get (version, cipher, cert, key)
	int	version;
	const	char *cipher;
	const	char *cert;
	const	char *key;
{
	SSL_CTX		*ctx;
	SSL_METHOD	*method;

	switch (version) {
	case 1:
		method = TLSv1_method ();
		break;
	case 2:
		method = SSLv2_method ();
		break;
	case 3:
		method = SSLv3_method ();
		break;
	defualt:
		err ("never (%s:%d)\n", __FILE__, __LINE__);
		return NULL;
	}
	if ((ctx = SSL_CTX_new (method)) == NULL) {
		serr ("SSL_CTX_new failed\n");
		return NULL;
	}
	if (SSL_CTX_use_certificate_file (ctx, cert, SSL_FILETYPE_PEM) != 1) {
		serr ("SSL_CTX_use_certificate_file failed\n");
		goto err;
	}
	SSL_CTX_set_default_passwd_cb (ctx, passwdcb);
	if (SSL_CTX_use_PrivateKey_file (ctx, key, SSL_FILETYPE_PEM) != 1) {
		serr ("SSL_CTX_use_PrivateKey_file failed\n");
		goto err;
	}
	if (SSL_CTX_set_cipher_list (ctx, cipher) == 0) {
		serr ("SSL_CTX_set_cipher_list failed\n");
		goto err;
	}
	return ctx;
err:
	SSL_CTX_free (ctx);
	return NULL;
}

int
passwdcb (buf, len, flag, udd)
	char	*buf;
	int	len;
	int	flag;
	void	*udd;
{
	int	plen = strlen (passwd);

	if (len < plen + 1)
		return 0;
	strcpy (buf, passwd);
	return plen;
}

void
sigchld (no)
	int	no;
{
	int	i;
	int	pid;

	pid = wait (&i);
	for (i = 0; i < ncli; ++i)
		if (cinfo[i].pid == pid) {
			cinfo[i].pid = 0;
			break;
		}
}

void
sigusr1 (no)
	int	no;
{
	struct	timeval ctime;
	int	delt;

	gettimeofday (&ctime, NULL);
	delt = (ctime.tv_sec - sttime.tv_sec) +
	    (ctime.tv_usec - sttime.tv_usec) / 1000000;
	if (tps == 0)
		readb = readb * 8 / 1000000 / delt;
	else
		readb /= delt;
	write (cpipe, &readb, sizeof readb);
	readb = 0;
	gettimeofday (&sttime, NULL);
}
