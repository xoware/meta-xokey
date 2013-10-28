
/* Copyright (c) 2003-2005 Cavium Networks (support@cavium.com) All rights reserved. 
 *
 * Redistribution and use in source and binary forms, with or without modification,
 * are permitted provided that the following conditions are met:

 * 1. Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice, 
 * this list of conditions and the following disclaimer in the documentation and/or 
 * other materials provided with the distribution.
 *
 * 3. Cavium Networks name may not be used to endorse or promote products derived 
 * from this software without specific prior written permission.
 *
 * This Software, including technical data, may be subject to U.S. export control laws, 
 * including the U.S. Export Administration Act and its associated regulations, and may be
 * subject to export or import regulations in other countries. You warrant that You will comply 
 * strictly in all respects with all such regulations and acknowledge that you have the responsibility 
 * to obtain licenses to export, re-export or import the Software.
 *
 * TO THE MAXIMUM EXTENT PERMITTED BY LAW, THE SOFTWARE IS PROVIDED "AS IS" AND WITH ALL FAULTS 
 * AND CAVIUM MAKES NO PROMISES, REPRESENTATIONS OR WARRANTIES, EITHER EXPRESS, IMPLIED, STATUTORY,
 * OR OTHERWISE, WITH RESPECT TO THE SOFTWARE, INCLUDING ITS CONDITION, ITS CONFORMITY TO ANY 
 * REPRESENTATION OR DESCRIPTION, OR THE EXISTENCE OF ANY LATENT OR PATENT DEFECTS, AND CAVIUM
 * SPECIFICALLY DISCLAIMS ALL IMPLIED (IF ANY) WARRANTIES OF TITLE, MERCHANTABILITY, NONINFRINGEMENT, 
 * FITNESS FOR A PARTICULAR PURPOSE, LACK OF VIRUSES, ACCURACY OR COMPLETENESS, QUIET ENJOYMENT, 
 * QUIET POSSESSION OR CORRESPONDENCE TO DESCRIPTION. THE ENTIRE RISK ARISING OUT OF USE OR PERFORMANCE 
 * OF THE SOFTWARE LIES WITH YOU.
*/
#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/time.h>
#include <signal.h>

#include "openssl/e_os2.h"
#include "openssl/ssl.h"
#include "openssl/cav_debug.h"



#define			MAX_CLIENT_ST				20

/* defines for ch_state */
#define			CH_ST_INVALID			-1	
#define			CH_ST_NONE				0
#define			CH_ST_BEFORE_ACCEPT		1
#define			CH_ST_IN_ACCEPT			2
#define			CH_ST_AFTER_ACCEPT		3
#define			CH_ST_IN_DECRYPT		4
#define			CH_ST_AFTER_DECRYPT		5
#define			CH_ST_IN_ENCRYPT		6
#define			CH_ST_AFTER_ENCRYPT		7

char *state_str[] = {
	"CH_ST_NONE",
	"CH_ST_BEFORE_ACCEPT",
	"CH_ST_IN_ACCEPT",
	"CH_ST_AFTER_ACCEPT",
	"CH_ST_IN_DECRYPT",
	"CH_ST_AFTER_DECRYPT",
	"CH_ST_IN_ENCRYPT",
	"CH_ST_AFTER_ENCRYPT"
};

struct client_hdl_sts {
	int ch_index;
	int ch_id;
	int ch_sfd;
	int ch_state;
	char ch_rbuf[512];
	char ch_wbuf[1024];
	int ch_wlen;
	SSL *ch_sslptr;
};
struct client_hdl_sts client_hdl_st[MAX_CLIENT_ST];
int reqs_processed;


struct client_hdl_sts *get_avail_client_st(struct client_hdl_sts *cl_startp);
void sleep_for(int usec);
int process_client_req(struct client_hdl_sts *cwptr);
int process_requests(struct client_hdl_sts *cl_startp);
void free_pending_req(struct client_hdl_sts *cwptr);
void free_all_pending_reqs();

int verify_callback(int ok, X509_STORE_CTX *ctx)
{
    char buf[256];
    X509 *err_cert;
    int err,depth;
	int verify_depth = 0 ;
	int verify_error=X509_V_OK;

    err_cert=X509_STORE_CTX_get_current_cert(ctx);
    err=    X509_STORE_CTX_get_error(ctx);
    depth=  X509_STORE_CTX_get_error_depth(ctx);

    X509_NAME_oneline(X509_get_subject_name(err_cert),buf,sizeof buf);
    if (!ok)
    {
        if (verify_depth >= depth)
        {
            ok=1;
            verify_error=X509_V_OK;
        }
        else
        {
            ok=0;
            verify_error=X509_V_ERR_CERT_CHAIN_TOO_LONG;
        }
    }
    switch (ctx->error)
    {
        case X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT:
            X509_NAME_oneline(X509_get_issuer_name(ctx->current_cert),buf,sizeof buf);
		    cav_fprintf(cav_nb_fp,"UNABLE TO GET THE ISSUER NAME \n"); 
            break;

        case X509_V_ERR_CERT_NOT_YET_VALID:
        case X509_V_ERR_ERROR_IN_CERT_NOT_BEFORE_FIELD:
		    cav_fprintf(cav_nb_fp,"NOT A VALID CERTIFICATE \n"); 
            break;

        case X509_V_ERR_CERT_HAS_EXPIRED:
		case X509_V_ERR_ERROR_IN_CERT_NOT_AFTER_FIELD:
			cav_fprintf(cav_nb_fp,"CERTIFICATE EXPIRED \n"); 
            break;
    }
    return(ok);
}


void  sigalarm_hdlr(int val)
{
	    //printf("sigalarm_hdlr(): entry\n");
}


static RSA *tmp_rsa_cb(SSL *s, int is_export, int keylength)
{
	static RSA *rsa_tmp=NULL;

	if (rsa_tmp == NULL)
		rsa_tmp=RSA_generate_key(keylength,RSA_F4,NULL,NULL);
	return(rsa_tmp);
}


int main(int argc, char *argv[])
{
	int rc;
	struct sockaddr_in saddr;
	int i;
	int err=0;
	int s;
	int port=4433;
	int nbflag = 0;
	int len;
	SSL_CTX *ctx;
	int cpid;
	int sock_nb_flag;
	int crypto_nb_flag;
	int rc4_flag;
	int ClntAuth_flag = 0 ;
	int nr_of_processes;
	int optval = 1;
	struct client_hdl_sts *cwptr;
	char cav_nb_fname[100];
	int new_conn_count;
	char temp_wbuf[1024];
	int verify_depth = 0 ;
	int cache_flag;
	static int s_server_verify=SSL_VERIFY_NONE;
	X509_STORE *store = NULL;
	int session_id_context = 1;

#ifdef CAVIUM_MULTICARD_API
    int dev_cnt = 0;
    int dev_id=0;
#endif

	SSL_library_init();
	SSL_load_error_strings();

#ifdef CAV_DEBUG
	if ( cav_nb_fp == NULL ) {
		sprintf(cav_nb_fname, "cav_nb.log.%d", getpid());
		if ((cav_nb_fp = fopen(cav_nb_fname, "w+")) == NULL ) {
			cav_fprintf(cav_nb_fp,"pkp_init(): fopen(%s) failed %s <%d>\n",
				cav_nb_fname, sys_errlist[errno], errno);
		}
		setbuf(cav_nb_fp, NULL);
	}
#endif


	if(argc < 9) {
		cav_fprintf(cav_nb_fp, "%s: %s %s\n",
			argv[0], "certfile keyfile ",
			"sock_nb_flag crypto_nb_flag RC4_flag nr_of_processes cache_on ClntAuth_flag\n");
		printf("%s: %s %s\n",
			argv[0], "certfile keyfile ",
			"sock_nb_flag crypto_nb_flag RC4_flag nr_of_processes cache_on ClntAuth_flag\n");
		exit(1);
	}

	if (atoi(argv[8]) == 1) {
			
		if (argc < 10) {

			printf("%s: %s %s\n", argv[0], "certfile keyfile ",
					"sock_nb_flag crypto_nb_flag RC4_flag nr_of_processes cache_on ClntAuth_flag cacertfile \n");
			exit(1);
		}
	}

	sock_nb_flag = atoi(argv[3]);

	crypto_nb_flag = atoi(argv[4]);

	rc4_flag = atoi(argv[5]);

	nr_of_processes = atoi(argv[6]);
	
	cache_flag = atoi(argv[7]);
 
	ClntAuth_flag = atoi(argv[8]);

	cav_fprintf(cav_nb_fp,"%s sock_nb_flag = %d\n", argv[0], sock_nb_flag);

	cav_fprintf(cav_nb_fp,"%s crypto_nb_flag = %d\n", argv[0], crypto_nb_flag);

	cav_fprintf(cav_nb_fp,"%s rc4_flag = %d\n",argv[0], rc4_flag);

	cav_fprintf(cav_nb_fp,"%s nr_of_processes = %d\n", argv[0], nr_of_processes);

	setbuf(stdout, NULL);

	signal(SIGALRM, sigalarm_hdlr);
	signal(SIGPIPE, SIG_IGN);

	ctx = SSL_CTX_new(SSLv23_server_method());

	if (ctx == NULL) {
		cav_fprintf(cav_nb_fp,"main(): SSL_CTX_new() failed\n");
		exit(1);
	}
	rc = SSL_CTX_use_certificate_file(ctx, argv[1],SSL_FILETYPE_PEM);
	if (rc <= 0) {
		cav_fprintf(cav_nb_fp,
			"main(): SSL_CTX_use_certificate_file() failed\n");
		free_all_pending_reqs();
		SSL_CTX_free(ctx);
		exit(1);
	}

	rc = SSL_CTX_use_PrivateKey_file(ctx,argv[2],SSL_FILETYPE_PEM);
	if (rc <= 0) {
		cav_fprintf(cav_nb_fp,
			"main(): SSL_CTX_use_PrivateKey_file() failed\n");
		free_all_pending_reqs();
		SSL_CTX_free(ctx);
		exit(1);
	}

	rc = SSL_CTX_check_private_key(ctx);
	if (!rc) {
		cav_fprintf(cav_nb_fp,
			"main(): SSL_CTX_check_private_key() failed\n");
		free_all_pending_reqs();
		SSL_CTX_free(ctx);
		exit(1);
	}
	if ( ClntAuth_flag)
	{
		rc = SSL_CTX_load_verify_locations(ctx,argv[9],argv[9]);
		if (rc) {
			if(SSL_CTX_set_default_verify_paths(ctx))
            {
				s_server_verify=SSL_VERIFY_PEER|
								SSL_VERIFY_FAIL_IF_NO_PEER_CERT|
								SSL_VERIFY_CLIENT_ONCE;
				verify_depth=10;
			}
			else
			{
				cav_fprintf(cav_nb_fp,
						"main(): SSL_CTX_default_verify_paths() failed\n");
				free_all_pending_reqs();
				SSL_CTX_free(ctx);
				exit(1);
			}
		}
		else
		{
			cav_fprintf(cav_nb_fp,
				"main(): SSL_CTX_load_verify_locations() failed\n");
			free_all_pending_reqs();
			SSL_CTX_free(ctx);
			exit(1);
		}		

		store = SSL_CTX_get_cert_store(ctx);
        X509_STORE_set_flags(store, 0);

		SSL_CTX_set_verify(ctx,s_server_verify,verify_callback);
	}
	 
	if(!cache_flag)
		SSL_CTX_set_session_cache_mode(ctx, SSL_SESS_CACHE_OFF);
	else	
		SSL_CTX_set_session_id_context(ctx, (void *)&session_id_context, sizeof session_id_context);

	SSL_CTX_set_tmp_rsa_callback(ctx, tmp_rsa_cb);

	if ( rc4_flag ) {
		rc = SSL_CTX_set_cipher_list(ctx, "RC4-MD5");
		if ( rc != 1 ) {
			cav_fprintf(cav_nb_fp,"main(): %s\n",
			        "SSL_CTX_set_cipher_list(RC4-MD5) failed");
		}
	}

	s = socket(AF_INET, SOCK_STREAM, 0);
	if (s == -1) {
		cav_fprintf(cav_nb_fp,"main(): socket() failed, %d <%s>\n",
				errno, sys_errlist[errno]);
		free_all_pending_reqs();
		SSL_CTX_free(ctx);
		exit(1);
	}

	memset(&saddr,0x00,sizeof(saddr));
	saddr.sin_addr.s_addr=INADDR_ANY;
	saddr.sin_family = AF_INET;
	saddr.sin_port = htons(port);

	rc = setsockopt(s,SOL_SOCKET,SO_REUSEADDR,&optval,sizeof(optval));
	if (rc == -1) {
		cav_fprintf(cav_nb_fp,"main(): setsockopt() failed, %d <%s>\n",
				errno, sys_errlist[errno]);
		free_all_pending_reqs();
		SSL_CTX_free(ctx);
		exit(1);
	}

	rc = bind(s, (struct sockaddr *)&saddr,sizeof(saddr));
	if (rc == -1) {
		cav_fprintf(cav_nb_fp,"main(): bind() failed, %d <%s>\n",
				errno, sys_errlist[errno]);
		free_all_pending_reqs();
		SSL_CTX_free(ctx);
		exit(1);
	}

	rc = listen(s, SOMAXCONN);
	if (rc == -1) {
		cav_fprintf(cav_nb_fp,"main(): listen() failed, %d <%s>\n",
				errno, sys_errlist[errno]);
		free_all_pending_reqs();
		SSL_CTX_free(ctx);
		exit(1);
	}

#if 1
	cav_fprintf(cav_nb_fp,"main(): making listen socket non-blocking\n");

	if ( (rc = fcntl(s, F_GETFL, 0)) == -1 ) {
		cav_fprintf(cav_nb_fp,"main(): fcntl(F_GETFL) failed, %d <%s>\n",
				errno, sys_errlist[errno]);
		free_all_pending_reqs();
		SSL_CTX_free(ctx);
		exit(1);
	}

	rc |= O_NONBLOCK;
	if ( (rc = fcntl(s, F_SETFL, rc)) == -1 ) {
		cav_fprintf(cav_nb_fp,"main(): fcntl(F_SETFL) failed, %d <%s>\n",
				errno, sys_errlist[errno]);
		free_all_pending_reqs();
		SSL_CTX_free(ctx);
		exit(1);
	}
#endif
	
	for ( i = 0; i < MAX_CLIENT_ST; i++ ) {
		cwptr = &client_hdl_st[i];
		cwptr->ch_index = i;
		sprintf(cwptr->ch_wbuf, "%s%s%s",
				"HTTP/1.0 200 ok\r\n",
				"Content-type: text/html\r\n\r\n",
				"<HTML>Hello World!</HTML>\r\n");
		cwptr->ch_wlen = strlen(cwptr->ch_wbuf);

	}
		
	for ( i = 0; i < nr_of_processes; i++) {

		cpid = fork();

		if ( cpid == 0 ) 
			break;
		else if ( cpid == -1 ) {
			fprintf(stderr,"fork() failed %d\n", errno);
			free_all_pending_reqs();
			SSL_CTX_free(ctx);
			exit(1);
		}
	}

	while ( 1 ) {
		
		// loop for accept */
		new_conn_count = 0;
		while (  1 ) {
			
			cwptr = get_avail_client_st(&client_hdl_st[0]);

			if ( cwptr == NULL ) {
				cav_fprintf(cav_nb_fp,
					"main(): get_avail_client_st() no more client handles\n");
				break;
			}

			cwptr->ch_sfd = accept(s, NULL ,NULL);
			if ( cwptr->ch_sfd == -1 ) {
				if ( errno == EAGAIN ) {
					break;
				}
			}
			else {

				// got a client conn
				cwptr->ch_id = reqs_processed;
				reqs_processed++;
				cwptr->ch_state = CH_ST_BEFORE_ACCEPT;
				cav_fprintf(cav_nb_fp,"====>main(): %d accept() done, fd = %d\n", cwptr->ch_id, cwptr->ch_sfd);

				cwptr->ch_sslptr = SSL_new( ctx );

				if (cwptr->ch_sslptr == NULL){
					err = ERR_get_error();
					cav_fprintf(cav_nb_fp,"main(): %d SSL_new error. %s\n",
						cwptr->ch_id, ERR_error_string(err, NULL));
					free_all_pending_reqs();
					SSL_CTX_free(ctx);
					exit(1);
				}

				// set non-blocking mode for cryto calls
				if ( crypto_nb_flag ) {
					// make crypto non-blocking
					cav_fprintf(cav_nb_fp,
						"main(): %d making crypto non-blocking\n", cwptr->ch_id);
					cav_set_nb_mode(cwptr->ch_sslptr,1);
				}

				if (sock_nb_flag == 1) {

					if ( (rc = fcntl(cwptr->ch_sfd, F_GETFL, 0)) == -1 ) {
						cav_fprintf(cav_nb_fp,
							"main(): %d fcntl(F_GETFL) failed, %d <%s>\n",
							cwptr->ch_id, errno, sys_errlist[errno]);
						free_all_pending_reqs();
						SSL_CTX_free(ctx);
						exit(1);
					}

					rc |= O_NONBLOCK;
					if ( (rc = fcntl(cwptr->ch_sfd, F_SETFL, rc)) == -1 ) {
						cav_fprintf(cav_nb_fp,
							"main(): %d fcntl(F_SETFL) failed, %d <%s>\n",
							cwptr->ch_id, errno, sys_errlist[errno]);
						free_all_pending_reqs();
						SSL_CTX_free(ctx);
						exit(1);
					}
					cav_fprintf(cav_nb_fp,
						"main(): %d making socket i/o non-blocking\n", 
						cwptr->ch_id);
				}

				SSL_set_fd(cwptr->ch_sslptr , cwptr->ch_sfd);

				rc = my_ssl_accept(cwptr);
				while ((rc == -2 )||(rc == -EAGAIN))
					rc = my_ssl_accept(cwptr); 
				if (rc == -1 )  {
					cav_fprintf(cav_nb_fp,
						"%d main(): my_ssl_accept() failed\n", cwptr->ch_id);
				}
				else {
					cav_fprintf(cav_nb_fp,
						"%d main(): my_ssl_accept() worked\n", cwptr->ch_id);
				} // end else ... SSL_accept

			} // end else .. got client conn

		} // end while 

		if ( got_work(&client_hdl_st[0]) ) {
			//printf("main(): got work\n");
			rc = process_requests(&client_hdl_st[0]);
		}
		else {
			// sleep for a while
			//printf("main(): should sleep\n");
			sleep_for(100);
		}

	} // end outter while loop

}


/*
 * Returns:
 *		-1 on error (and the connection is shut-down
 *		 0 if WANTS something
 *		 1 if request is complete
 */
int my_ssl_accept(struct client_hdl_sts *cwptr)
{
	char *fname = "my_ssl_accept()";
	int rc;
	int err;


	cav_fprintf(cav_nb_fp,"%d %s: entry\n", cwptr->ch_id, fname);

	cav_print_state(cwptr->ch_sslptr, "my_ssl_accept");

#if 1
	if ( cwptr->ch_sslptr->cav_crypto_state == CAV_ST_IN_HANDSHAKE) {
		cav_print_state(cwptr->ch_sslptr, "my_ssl_accept in Handshake");
#ifdef CAVIUM_MULTICARD_API
		rc = Csp1CheckForCompletion(cwptr->ch_sslptr->cav_req_id,cwptr->ch_sslptr->dev_id);
#else
		rc = Csp1CheckForCompletion(cwptr->ch_sslptr->cav_req_id);
#endif
		if ( rc == EAGAIN ) {
			cav_fprintf(cav_nb_fp,"my_ssl_accept(): %s\n",
					"Csp1CheckForCompletion() EAGAIN");
			return(-EAGAIN);
		}
		else if ( rc == 0 ) {
				// cmd has completed 
			cav_fprintf(cav_nb_fp,"my_ssl_accept(): %s\n",
					"Csp1CheckForCompletion() cmd has completed");
			cwptr->ch_sslptr->cav_req_id_check_done = 1;

		}
		else {
			cav_fprintf(cav_nb_fp,"my_ssl_accept(): %s %d\n",
					"Csp1CheckForCompletion() returned error", rc);
				//free_pending_req(cwptr);
				//my_ssl_shutdown(cwptr);
				//SSL_free(cwptr->ch_sslptr);
				//close(cwptr->ch_sfd);
				//cwptr->ch_state = CH_ST_NONE;
				cwptr->ch_state = CH_ST_AFTER_ENCRYPT;
				return(-1);
			}
	} // end if cav state

#endif
	cav_fprintf(cav_nb_fp, "%d: %s: calling SSL_accept() \n", cwptr->ch_id, fname);

	if ( (err = SSL_accept(cwptr->ch_sslptr)) == 1 ) {
		// handshake done
		cav_fprintf(cav_nb_fp, "%d: %s: SSL_accept() handshake done\n",
				cwptr->ch_id, fname);
		cwptr->ch_state = CH_ST_AFTER_ACCEPT;
		return(1);	// done
	}

	cav_fprintf(cav_nb_fp, "%d: %s: done SSL_accept() with err %d \n", cwptr->ch_id, fname, err);
	rc = SSL_get_error(cwptr->ch_sslptr, err);

	switch (rc) {

		case SSL_ERROR_NONE:
		// cannot happen, since there was an error
			cav_fprintf(cav_nb_fp,
				"%d %s(): invalid SSL_ERROR_NONE case, rc = %d\n", 
			cwptr->ch_id, fname, rc);
			cwptr->ch_state = CH_ST_AFTER_ENCRYPT;
			return(-1);
		
		case SSL_ERROR_ZERO_RETURN:
		// connection was closed
			cav_fprintf(cav_nb_fp,"%d %s(): connection was closed\n",
				cwptr->ch_id, fname);
			cwptr->ch_state = CH_ST_AFTER_ENCRYPT;
			return(-1);

		case SSL_ERROR_WANT_READ:
		// need to call SSL_accept again
			cav_fprintf(cav_nb_fp,"%d %s: SSL_ERROR_WANT_READ case\n",
					cwptr->ch_id, fname);
			cwptr->ch_state = CH_ST_IN_ACCEPT;
			return(0);
		
		case SSL_ERROR_WANT_WRITE:
		// need to call SSL_accept again
			cav_fprintf(cav_nb_fp,"%d %s: SSL_ERROR_WANT_WRITE case\n",
					cwptr->ch_id, fname);
			cwptr->ch_state = CH_ST_IN_ACCEPT;
			return(0);

		case SSL_ERROR_WANT_CAVIUM_CRYPTO:
		// need to call SSL_accept again
			cav_fprintf(cav_nb_fp,"%d %s: SSL_ERROR_WANT_CAVIUM_CRYPTO case\n",
					cwptr->ch_id, fname);
		cwptr->ch_state = CH_ST_IN_ACCEPT;
		return(-2);
	
	default:
		cav_fprintf(cav_nb_fp,
				"%d %s: invalid default case, err = %d, rc = %d\n", 
				cwptr->ch_id, fname, err, rc);
		cav_fprintf(cav_nb_fp,"%d %s: sslptr->cav_crypto_state = %d\n",
				cwptr->ch_id, fname, cwptr->ch_sslptr->cav_crypto_state);

		if ( cwptr->ch_sslptr->state == CAV_ST_IN_HANDSHAKE ) {
			// call SSL_accept() again. */
			cav_fprintf(cav_nb_fp,"%d %s(): will call SSL_accept() again\n",
				cwptr->ch_id, fname);
			cwptr->ch_state = CH_ST_IN_ACCEPT;
			return(0);
		}

		ERR_get_error();
		cwptr->ch_state = CH_ST_AFTER_ENCRYPT;
		return(-1);
			
	} // end switch

	cav_fprintf(cav_nb_fp,"%d %s(): invalid program flow\n",
				cwptr->ch_id, fname);
	cwptr->ch_state = CH_ST_AFTER_ENCRYPT;

	return(-1);

} // end my_ssl_accept()


/*
 * Returns:
 *		-1 on error (and the connection is shut-down
 *		 0 if WANTS something
 *		 1 if request is complete
 */
int my_ssl_read(struct client_hdl_sts *cwptr)
{
	char *fname = "my_ssl_read()";
	int rc;
	int err;
	int len;


	cav_fprintf(cav_nb_fp,"%d %s(): entry\n", cwptr->ch_id, fname);


	cav_fprintf(cav_nb_fp,"%d %s: entry\n", cwptr->ch_id, fname);

#if 1
	if ( cwptr->ch_sslptr->cav_crypto_state == CAV_ST_IN_DECRYPT) {
#ifdef CAVIUM_MULTICARD_API
		rc = Csp1CheckForCompletion(cwptr->ch_sslptr->cav_req_id,cwptr->ch_sslptr->dev_id);
#else
		rc = Csp1CheckForCompletion(cwptr->ch_sslptr->cav_req_id);
#endif
		if ( rc == EAGAIN ) {
			cav_fprintf(cav_nb_fp,"my_ssl_read(): %s\n",
					"Csp1CheckForCompletion() EAGAIN");
			return(0);
		}
		else if ( rc == 0 ) {
				// cmd has completed 
			cav_fprintf(cav_nb_fp,"my_ssl_read(): %s\n",
					"Csp1CheckForCompletion() cmd has completed");
			cwptr->ch_sslptr->cav_req_id_check_done = 1;
		}
		else {
			cav_fprintf(cav_nb_fp,"my_ssl_read(): %s %d\n",
				"Csp1CheckForCompletion() returned error", rc);
				cwptr->ch_state = CH_ST_AFTER_ENCRYPT;
			return(-1);
		}
	}
#endif

	if ( (err = SSL_read(cwptr->ch_sslptr,cwptr->ch_rbuf,100)) > 0 ) {
		*(cwptr->ch_rbuf + err) = '\0';
		cav_fprintf(cav_nb_fp,"%d %s: SSL_read() worked, got %d bytes <%s>\n", 
				cwptr->ch_id, fname, err, cwptr->ch_rbuf);
		//printf("%s",cwptr->ch_rbuf);
		cwptr->ch_state = CH_ST_AFTER_DECRYPT;
		return(1);	// done
	}

	rc = SSL_get_error(cwptr->ch_sslptr, err);

	switch (rc) {

	case SSL_ERROR_NONE:
		// cannot happen, since there was an error
		cav_fprintf(cav_nb_fp,"%d %s: invalid SSL_ERROR_NONE case\n",
				cwptr->ch_id, fname);
		cwptr->ch_state = CH_ST_AFTER_ENCRYPT;
		return(-1);
		
	case SSL_ERROR_ZERO_RETURN:
		// connection was closed
		cav_fprintf(cav_nb_fp,"%d %s: connection was closed\n",
				cwptr->ch_id, fname);
		cwptr->ch_state = CH_ST_AFTER_ENCRYPT;
		return(-1);


	case SSL_ERROR_WANT_READ:
		// need to call SSL_accept again
		cav_fprintf(cav_nb_fp,"%d %s: SSL_ERROR_WANT_READ case\n",
				cwptr->ch_id, fname);
		cwptr->ch_state = CH_ST_IN_DECRYPT;
		return(0);
		
	case SSL_ERROR_WANT_WRITE:
		// need to call SSL_accept again
		cav_fprintf(cav_nb_fp,"%d %s: SSL_ERROR_WANT_WRITE case\n",
				cwptr->ch_id, fname);
		cwptr->ch_state = CH_ST_IN_DECRYPT;
		return(0);
	
	case SSL_ERROR_WANT_CAVIUM_CRYPTO:
		// need to call SSL_accept again
		cav_fprintf(cav_nb_fp,"%d %s: SSL_ERROR_WANT_CAVIUM_CRYPTO case\n",
				cwptr->ch_id, fname);

		cwptr->ch_state = CH_ST_IN_DECRYPT;
		return(0);

		
	default:
		cav_fprintf(cav_nb_fp,"%d %s: invalid default case, err = %d,rc=%d\n",
				cwptr->ch_id, fname, err, rc);
		cwptr->ch_state = CH_ST_AFTER_ENCRYPT;
		return(-1);
				
	} // end switch

	cav_fprintf(cav_nb_fp,"%d %s: invalid program flow\n",
				cwptr->ch_id, fname);

	cwptr->ch_state = CH_ST_AFTER_ENCRYPT;

	return(-1);

}

/*
 * Returns:
 *		-1 on error (and the connection is shut-down
 *		 0 if WANTS something
 *		 1 if request is complete
 */
int my_ssl_write(struct client_hdl_sts *cwptr)
{
	char *fname = "my_ssl_write()";
	int rc;
	int err;
	int len;


	cav_fprintf(cav_nb_fp,"my_ssl_write(): entry\n");

#if 1
	if ( cwptr->ch_sslptr->cav_crypto_state == CAV_ST_IN_DECRYPT) {
#ifdef CAVIUM_MULTICARD_API
		rc = Csp1CheckForCompletion(cwptr->ch_sslptr->cav_req_id,cwptr->ch_sslptr->dev_id);
#else
		rc = Csp1CheckForCompletion(cwptr->ch_sslptr->cav_req_id);
#endif
		if ( rc == EAGAIN ) {
			cav_fprintf(cav_nb_fp,"my_ssl_write(): %s\n",
					"Csp1CheckForCompletion() EAGAIN");
			return(0);
		}
		else if ( rc == 0 ) {
			// cmd has completed 
			cav_fprintf(cav_nb_fp,"my_ssl_write(): %s\n",
				"Csp1CheckForCompletion() cmd has completed");
			cwptr->ch_sslptr->cav_req_id_check_done = 1;
		}
		else {
			cav_fprintf(cav_nb_fp,"my_ssl_write(): %s %d\n",
					"Csp1CheckForCompletion() returned error", rc);
			cwptr->ch_state = CH_ST_AFTER_ENCRYPT;
			return(-1);
		}
	}
#endif

	if ( (err = SSL_write(cwptr->ch_sslptr,cwptr->ch_wbuf,cwptr->ch_wlen)) > 0 ) {
		cav_fprintf(cav_nb_fp,"%d %s: SSL_write() worked, wrote %d bytes\n", 
				cwptr->ch_id, fname, err);
		cwptr->ch_state = CH_ST_AFTER_ENCRYPT;
		cav_print_state(cwptr->ch_sslptr, "my_ssl_write(): SSL_write() done");
		cav_fprintf(cav_nb_fp,"%d %s: cav_crypto_state = %d\n",
			cwptr->ch_id, fname, cwptr->ch_sslptr->cav_crypto_state);
		return(1);	// done
	}

	rc = SSL_get_error(cwptr->ch_sslptr, err);

	switch (rc) {

	case SSL_ERROR_NONE:
		// cannot happen, since there was an error
		cav_fprintf(cav_nb_fp,"%d %s: invalid SSL_ERROR_NONE case\n",
				cwptr->ch_id, fname);
		cwptr->ch_state = CH_ST_AFTER_ENCRYPT;
		return(-1);
		
	case SSL_ERROR_ZERO_RETURN:
		// connection was closed
		cav_fprintf(cav_nb_fp,"%d %s: connection was closed\n",
				cwptr->ch_id, fname);
		cwptr->ch_state = CH_ST_AFTER_ENCRYPT;
		return(-1);

	case SSL_ERROR_WANT_READ:
		// need to call SSL_accept again
		cav_fprintf(cav_nb_fp,"%d %s: SSL_ERROR_WANT_READ case\n",
				cwptr->ch_id, fname);
		cwptr->ch_state = CH_ST_IN_ENCRYPT;
		return(0);

	case SSL_ERROR_WANT_WRITE:
		// need to call SSL_accept again
		cav_fprintf(cav_nb_fp,"%d %s: SSL_ERROR_WANT_WRITE case\n",
				cwptr->ch_id, fname);
		cwptr->ch_state = CH_ST_IN_ENCRYPT;
		return(0);
	
	case SSL_ERROR_WANT_CAVIUM_CRYPTO:
		// need to call SSL_accept again
		cav_fprintf(cav_nb_fp,"%d %s: SSL_ERROR_WANT_CAVIUM_CRYPTO case\n",
				cwptr->ch_id, fname);
		cwptr->ch_state = CH_ST_IN_ENCRYPT;
		return(0);

	default:
		cav_fprintf(cav_nb_fp,"%d %s: invalid default case\n",
				cwptr->ch_id, fname);
		cwptr->ch_state = CH_ST_AFTER_ENCRYPT;
		return(-1);
			
	} // end switch

	cav_fprintf(cav_nb_fp,"%d %s: invalid program flow\n",
				cwptr->ch_id, fname);

	free_pending_req(cwptr);
	cwptr->ch_state = CH_ST_AFTER_ENCRYPT;

	return(-1);

}


int my_ssl_shutdown(struct client_hdl_sts *cwptr)
{
	char *fname = "my_ssl_shutdown";
	int rc;
	int err;
	int len;
	SSL *sslptr;

	sslptr = cwptr->ch_sslptr;

	cav_fprintf(cav_nb_fp,"====>%d %s: fd = %d for index = %d\n",
			cwptr->ch_id, fname, cwptr->ch_sfd, cwptr->ch_index);

	if ( (err = SSL_shutdown(sslptr)) > 0 ) {
		cav_fprintf(cav_nb_fp,"%d %s: SSL_shutdown() worked\n",
			cwptr->ch_id, fname);
		cwptr->ch_state = CH_ST_NONE;
		free_pending_req(cwptr);
		SSL_free(cwptr->ch_sslptr);
		close(cwptr->ch_sfd);
		return(1);	// done
	}

	rc = SSL_get_error(sslptr, err);

	switch (rc) {

	case SSL_ERROR_NONE:
		// cannot happen, since there was an error
		cav_fprintf(cav_nb_fp,"%d %s: invalid SSL_ERROR_NONE case\n",
			cwptr->ch_id, fname);
		free_pending_req(cwptr);
		cwptr->ch_state = CH_ST_NONE;
		SSL_free(cwptr->ch_sslptr);
		close(cwptr->ch_sfd);
		return(-1);
		
	case SSL_ERROR_ZERO_RETURN:
		// connection was closed
		cav_fprintf(cav_nb_fp,"%d %s: connection was closed\n",
				cwptr->ch_id, fname);
		free_pending_req(cwptr);
		cwptr->ch_state = CH_ST_NONE;
		SSL_free(cwptr->ch_sslptr);
		close(cwptr->ch_sfd);
		return(-1);

	case SSL_ERROR_WANT_READ:
		// need to call SSL_shutdown again
		cav_fprintf(cav_nb_fp,"%d %s: SSL_ERROR_WANT_READ case\n",
			cwptr->ch_id, fname);
		return(0);
		
	case SSL_ERROR_WANT_WRITE:
		// need to call SSL_shutdown again
		cav_fprintf(cav_nb_fp,"%d %s: SSL_ERROR_WANT_WRITE case\n",
			cwptr->ch_id, fname);
		return(0);
	
	case SSL_ERROR_WANT_CAVIUM_CRYPTO:
		// need to call SSL_shutdown again
		cav_fprintf(cav_nb_fp,"%d %s: SSL_ERROR_WANT_CAVIUM_CRYPTO case\n",
			cwptr->ch_id, fname);
		return(0);

	default:
		cav_fprintf(cav_nb_fp,"%d %s: invalid default case\n",
			cwptr->ch_id, fname);
		free_pending_req(cwptr);
		cwptr->ch_state = CH_ST_NONE;
		SSL_free(cwptr->ch_sslptr);
		close(cwptr->ch_sfd);
		return(-1);
			
	} // end switch

	cav_fprintf(cav_nb_fp,"%d %s: invalid program flow\n",
				cwptr->ch_id, fname);

	free_pending_req(cwptr);
	cwptr->ch_state = CH_ST_NONE;
	SSL_free(cwptr->ch_sslptr);
	close(cwptr->ch_sfd);

	return(-1);

}


struct client_hdl_sts *get_avail_client_st(struct client_hdl_sts *cl_startp)
{
	
	struct client_hdl_sts *cwptr;
	int i;

	for ( i = 0; i < MAX_CLIENT_ST; i++ ) {
		cwptr = cl_startp + i;
		if ( cwptr->ch_state == CH_ST_NONE )
			return(cwptr);
	}
	return(NULL);
}


int got_work(struct client_hdl_sts *cl_startp)
{
	
	struct client_hdl_sts *cwptr;
	int i;

	for ( i = 0; i < MAX_CLIENT_ST; i++ ) {
		cwptr = cl_startp + i;
		if ( cwptr->ch_state != CH_ST_NONE )
			return(1);
	}
	return(0);
}


int process_requests(struct client_hdl_sts *cl_startp)
{
	char *fname = "process_request()";
	int i;
	int rc;
	struct client_hdl_sts *cwptr;


	//printf("process_requests(): entry\n");


	if ((rc == accept_processor(&client_hdl_st[0])) == -1 ) {
		cav_printf("%s: accept_processor() failed\n", fname);
		;	
	}

	if ((rc == read_processor(&client_hdl_st[0])) == -1 ) {
		cav_printf("%s: read_processor() failed\n", fname);
		;
	}

	if ((rc == write_processor(&client_hdl_st[0])) == -1 ) {
		cav_printf("%s: write_processor() failed\n", fname);
		;
	}

	if ((rc == shutdown_processor(&client_hdl_st[0])) == -1 ) {
		cav_printf("%s: shutdown_processor() failed\n", fname);
		;	
	}

	return(0);

}


int accept_processor(struct client_hdl_sts *cl_startp)
{
	char *fname = "accept_processor";
	int i;
	int rc;
	int done = 0;
	int left_count;	
	int saved_ch_state;
	int state_change_occured;
	struct client_hdl_sts *cwptr;



	while ( ! done ) {

		left_count = 0;
		state_change_occured = 0;

		for ( i = 0; i < MAX_CLIENT_ST; i++ ) {

			cwptr = cl_startp + i;
			if ( cwptr->ch_state != CH_ST_BEFORE_ACCEPT &&
				 cwptr->ch_state != CH_ST_IN_ACCEPT ) {
				 continue;
			}
			saved_ch_state = cwptr->ch_state;

			if ( (rc = my_ssl_accept(cwptr)) == -1 )  {
				cav_fprintf(cav_nb_fp,"%d %s: my_ssl_accept() failed\n",
					cwptr->ch_id, fname);
				continue;
			}
			else if ( rc == 0 ) {
				cav_fprintf(cav_nb_fp,"%d %s: my_ssl_accept() in process\n",
					cwptr->ch_id, fname);
			} // end else ... SSL_accept
			else {
				cav_fprintf(cav_nb_fp,"%d %s: my_ssl_accept() worked\n",
					cwptr->ch_id, fname);
			} // end else ... SSL_accept
				
			/* check if this client conn is done with accept */
			if ( cwptr->ch_state == CH_ST_BEFORE_ACCEPT ||
				 cwptr->ch_state == CH_ST_IN_ACCEPT ) {
				left_count++;
			}

			if ( saved_ch_state != cwptr->ch_state ) {
				state_change_occured = 1;
			}

			cav_fprintf(cav_nb_fp,"%s: left_count = %d\n", fname, left_count);
		
		} // end for 
		
		if ( left_count == 0 )
			done = 1;

		if ( state_change_occured == 0 )
			done = 1;


	} // end while

} // end accept_processor()



int read_processor(struct client_hdl_sts *cl_startp)
{
	char *fname = "read_processor";
	int i;
	int rc;
	int done = 0;
	int left_count;	
	int saved_ch_state;
	int state_change_occured;
	struct client_hdl_sts *cwptr;



	while ( ! done ) {

		left_count = 0;

		state_change_occured = 0;

		for ( i = 0; i < MAX_CLIENT_ST; i++ ) {

			cwptr = cl_startp + i;

			if ( cwptr->ch_state != CH_ST_AFTER_ACCEPT &&
				 cwptr->ch_state != CH_ST_IN_DECRYPT ) {

				 continue;

			}
			saved_ch_state = cwptr->ch_state;
				
			if ( (rc = my_ssl_read(cwptr)) == -1 )  {
				cav_fprintf(cav_nb_fp,"%d %s: my_ssl_read() failed\n",
					cwptr->ch_id, fname);
				continue;
			}
			else if ( rc == 0 ) {
				cav_fprintf(cav_nb_fp,"%d %s: my_ssl_read() in process\n",
					cwptr->ch_id, fname);
			} // end else 
			else {
				cav_fprintf(cav_nb_fp,"%d %s: my_ssl_read() worked\n",
					cwptr->ch_id, fname);
			} // end else 

			/* check if this client conn is done with accept */
			if ( cwptr->ch_state == CH_ST_AFTER_ACCEPT ||
				 cwptr->ch_state == CH_ST_IN_DECRYPT ) {
				left_count++;
			}

			if ( saved_ch_state != cwptr->ch_state ) {
				state_change_occured = 1;
			}

			cav_fprintf(cav_nb_fp,"%s: left_count = %d\n", fname, left_count);
		
		} // end for 
		
		if ( left_count == 0 )
			done = 1;

		if ( state_change_occured == 0 )
			done = 1;

	} // end while

} // end read_processor()


int write_processor(struct client_hdl_sts *cl_startp)
{
	char *fname = "write_processor";
	int i;
	int rc;
	int done = 0;
	int left_count;	
	int saved_ch_state;
	int state_change_occured;
	struct client_hdl_sts *cwptr;



	while ( ! done ) {

		left_count = 0;

		state_change_occured = 0;

		for ( i = 0; i < MAX_CLIENT_ST; i++ ) {

			cwptr = cl_startp + i;

			if ( cwptr->ch_state != CH_ST_AFTER_DECRYPT &&
				 cwptr->ch_state != CH_ST_IN_ENCRYPT ) {

				 continue;

			}
			saved_ch_state = cwptr->ch_state;
				
			if ( (rc = my_ssl_write(cwptr)) == -1 )  {
				cav_fprintf(cav_nb_fp,"%d %s: my_ssl_write() failed\n",
					cwptr->ch_id, fname);
				continue;
			}
			else if (rc == 0 ) {
				cav_fprintf(cav_nb_fp,"%d %s: my_ssl_write() in process\n",
					cwptr->ch_id, fname);
			} // end else 
			else {
				cav_fprintf(cav_nb_fp,"%d %s: my_ssl_write() worked\n",
					cwptr->ch_id, fname);
			} // end else 

			/* check if this client conn is done with write */
			if ( cwptr->ch_state == CH_ST_AFTER_DECRYPT ||
				 cwptr->ch_state == CH_ST_IN_ENCRYPT ) {
				left_count++;
			}

			if ( saved_ch_state != cwptr->ch_state ) {
				state_change_occured = 1;
			}

			cav_fprintf(cav_nb_fp,"%s: left_count = %d\n", fname, left_count);
		
		} // end for 
		
		if ( left_count == 0 )
			done = 1;

		if ( state_change_occured == 0 )
			done = 1;

	} // end while

} // end write_processor()


int shutdown_processor(struct client_hdl_sts *cl_startp)
{
	char *fname = "shutdown_processor";
	int i;
	int rc;
	int done = 0;
	int left_count;	
	int saved_ch_state;
	int state_change_occured;
	struct client_hdl_sts *cwptr;



	while ( ! done ) {

		left_count = 0;

		state_change_occured = 0;

		for ( i = 0; i < MAX_CLIENT_ST; i++ ) {

			cwptr = cl_startp + i;

			if ( cwptr->ch_state != CH_ST_AFTER_ENCRYPT ) {
				 continue;
			}
			saved_ch_state = cwptr->ch_state;
				
			if ( (rc = my_ssl_shutdown(cwptr)) == -1 )  {
				cav_fprintf(cav_nb_fp,"%d %s: my_ssl_shutdown() failed\n",
					cwptr->ch_id, fname);
				continue;
			}
			else if ( rc == 0 ) {
				cav_fprintf(cav_nb_fp,"%d %s: my_ssl_shutdown() in process\n",
					cwptr->ch_id, fname);
			}
			else {
				cav_fprintf(cav_nb_fp,"%d %s: my_ssl_shutdown() worked\n",
					cwptr->ch_id, fname);
			} // end else 

			/* check if this client conn is done with write */
			if ( cwptr->ch_state == CH_ST_AFTER_ENCRYPT ) {
				left_count++;
			}

			if ( saved_ch_state != cwptr->ch_state ) {
				state_change_occured = 1;
			}

			cav_fprintf(cav_nb_fp,"%s: left_count = %d\n", fname, left_count);
		
		} // end for 
		
		if ( left_count == 0 )
			done = 1;

		if ( state_change_occured == 0 )
			done = 1;

	} // end while

}

void sleep_for(int usec)
{
	int rc;
	struct itimerval t;
	struct itimerval old_t;

	t.it_interval.tv_sec = 0;
	t.it_interval.tv_usec = 0;

	t.it_value.tv_sec = 0;
	t.it_value.tv_usec = usec;

	if ( (rc = setitimer(ITIMER_REAL, &t, &old_t)) == -1 ) {
		printf("setitimer() failed <%s>\n", strerror(errno));
		exit(1);
	}

	//pause();
	sleep(1);

}


void free_pending_req(struct client_hdl_sts *cwptr)
{
	if ( cwptr->ch_state == CH_ST_NONE )
		return;	// there is no pending req

	if ( cwptr->ch_sslptr->cav_crypto_state == 0 )
		return;	// there is no pending req

	if ( cwptr->ch_sslptr->cav_req_id_check_done == 1 )
		return;	// pending req was already checked by app

	/* flush pending req */
#ifdef CAVIUM_MULTICARD_API
	Csp1FlushRequest(cwptr->ch_sslptr->cav_req_id,cwptr->ch_sslptr->dev_id);
#else
	Csp1FlushRequest(cwptr->ch_sslptr->cav_req_id);
#endif

	cwptr->ch_state = CH_ST_NONE;
	cwptr->ch_sslptr->cav_req_id_check_done = 1;
	cwptr->ch_sslptr->cav_crypto_state = CAV_ST_NONE;

	return;

} // end free_pending_req()


void free_all_pending_reqs()
{
#ifdef CAVIUM_MULTICARD_API
	Csp1FlushAllRequests(0);
#else
	Csp1FlushAllRequests();
#endif
}

