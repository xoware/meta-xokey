
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
#include <memory.h>
#include <errno.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/socket.h>

#include <openssl/crypto.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/err.h>

#include "openssl/ssl.h"
#include "openssl/cav_debug.h"

BIO *bio_err=NULL ;
void Exit ( int val)
{
	if ( val == -1 )
		printf (" \nFAILURE \n");
	else 
		printf ("\n SUCCESS \n");

	exit(1);
}

int set_cert_stuff(SSL_CTX *ctx, char *cert_file, char *key_file)
	{
	if (cert_file != NULL)
		{

		if (SSL_CTX_use_certificate_file(ctx,cert_file,
			SSL_FILETYPE_PEM) <= 0)
			{
			cav_fprintf(cav_nb_fp,"set_cert_stuff: unable to get certificate from '%s'\n",cert_file);
			return 0;
			}
		if (key_file == NULL) key_file=cert_file;

		if (SSL_CTX_use_PrivateKey_file(ctx,key_file,
			SSL_FILETYPE_PEM) <= 0)
			{
			cav_fprintf(cav_nb_fp,"set_cert_stuff: unable to get private key from '%s'\n",key_file);
			return 0;
			}

		if (!SSL_CTX_check_private_key(ctx))
			{
			cav_fprintf(cav_nb_fp,"set_cert_stuff: Private key does not match the certificate public key\n");
			return 0;
			}
		}
	return(1);
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
	 int err=0; 
 	 int sd = -1;
	 struct sockaddr_in sa;
	 SSL_CTX* ctx; 
	 SSL*     ssl;
	 SSL_METHOD *meth;  
	 int crypto_nb_flag;
	 char cav_nb_fname[100];
	 int reconnect ;
	 int recon ;
	 int rc ;
	 int flag = 0;
	 int reneg = 0;	
	 int version ;
	 int cnt = 0;	

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
		cav_fprintf(cav_nb_fp, "%s:%s \n",argv[0]," ipaddr port cipher crypto_nb_flag reconnect Reneg ssl3/tls1 clientcertflag \n");
		printf("%s: %s \n",argv[0], "ipaddr port cipher crypto_nb_flag reconnect Reneg ssl3/tls1 clientcertflag\n");
		Exit(-1);
	}

	if (atoi(argv[8]) == 1) {
                                                                                                                             
                        if (argc < 10) {
                                                                                                                             
				printf("%s: %s \n",argv[0], "ipaddr port cipher crypto_nb_flag reconnect Reneg ssl3/tls1 clientcertflag clientcert\n");
				Exit(-1);
                        }
        }

	 crypto_nb_flag = atoi(argv[4]);
	 reconnect = atoi(argv[5]);
	 reneg = atoi (argv[6]);
	 version = atoi(argv[7]);

	 if (reconnect){
		 recon = 5;	
	 }	

	 SSLeay_add_ssl_algorithms(); 
	 SSL_library_init();
	 SSL_load_error_strings();

	if(version == 0){
		 meth = SSLv3_client_method(); 
	}
	else if(version == 1){
		 meth = TLSv1_client_method(); 
	}

	ctx = SSL_CTX_new (meth);

	 if (ctx == NULL) {
		cav_fprintf(cav_nb_fp,"main(): SSL_CTX_new() failed\n");
		Exit(-1);
	 }

	SSL_CTX_set_tmp_rsa_callback(ctx, tmp_rsa_cb);

	if (atoi(argv[8]) == 1 ) {
		if (!set_cert_stuff(ctx,argv[9],NULL)){
			cav_fprintf(cav_nb_fp,"main(): Error setting in client certificate\n");
			SSL_CTX_free (ctx);
			Exit(-1);
		}
	}

	if (argv[3] != NULL) {
		if(!SSL_CTX_set_cipher_list(ctx,argv[3])) {
			cav_fprintf(cav_nb_fp,"main(): Error setting in cpher list \n");
			Exit(-1);
		}
	}

	 if (!SSL_CTX_set_options(ctx, SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3)) {

		cav_fprintf(cav_nb_fp,"main(): set_ctx_options() failed \n");
	  	SSL_free (ssl); 
		SSL_CTX_free (ctx);
		Exit(-1);
	}

	 	ssl = SSL_new (ctx);  

		if (ssl == NULL) {
			cav_fprintf(cav_nb_fp,"main(): SSL_CTX_new() failed\n");
			SSL_CTX_free(ctx);
			Exit(-1);
	  	 }

		// set non-blocking mode for cryto calls
		if ( crypto_nb_flag ) {
				cav_set_nb_mode(ssl,1);
		}

again:				
		if (sd == -1 ) {
			sd = socket (AF_INET, SOCK_STREAM, 0); 
			if (sd < 0) {
				Exit(-1);
			}
        		memset (&sa, '\0', sizeof(sa));
		        sa.sin_family      = AF_INET; 
		        sa.sin_addr.s_addr = inet_addr (argv[1]);  /* Server IP */ 
			sa.sin_port        = htons     (atoi(argv[2]));   /* Server Port number */ 
			err = connect(sd, (struct sockaddr*) &sa,   
			             sizeof(sa));      

			if (err == -1 ){
				cav_fprintf(cav_nb_fp,"main(): connect failed, %d <%s>\n",errno, sys_errlist[errno]);
				printf ("Connect failed \n");
				Exit(-1);
			}
		}

		SSL_set_fd (ssl, sd);

		if (crypto_nb_flag){
			int k = 2;
			 while (k != 1) {
				k = my_ssl_connect(ssl);
				if (k == -1 )
					Exit(-1);
			}
		}
		else {
			rc = my_ssl_connect(ssl);
			if ( rc  == -1 )  {
				cav_fprintf(cav_nb_fp,"%d main(): my_ssl_connect() failed\n");
				Exit(-1);
			}
		}
					
		if (reconnect) {
			if (recon == 0){
				reconnect = 0;
				goto try;
			}
			else {
				recon -- ;
				rc = my_ssl_shutdown(ssl);	
				while (rc != 1){
					rc = my_ssl_shutdown(ssl);	
					if (rc == -1 )
						Exit(-1);
				}
				SSL_set_connect_state(ssl);
				close(sd);
				sd = -1;
				goto again;
			}
		}

try:		if (reneg == 1 ) {
			SSL_renegotiate(ssl);	
			 rc = my_ssl_write(ssl);
			 while ( rc != 1 ){
				rc = my_ssl_write(ssl);
				if (rc == -1)
					Exit(-1);
			}
			cnt = 1;
		}
		
		if (cnt != 1){
			rc = my_ssl_write(ssl);
			 while ( rc != 1 ){
				rc = my_ssl_write(ssl);
				if (rc == -1)
					Exit(-1);
			}
		}
			
		rc = my_ssl_read(ssl) ;
		 while ( rc != 1 ){
			rc = my_ssl_read(ssl);
			if (rc == -1)
				Exit(-1);
		}

		rc = my_ssl_shutdown(ssl);	
		 while ( rc != 1 ){
			rc = my_ssl_shutdown(ssl);
			if (rc == -1)
				Exit(-1);
		}

		SSL_free(ssl);
		Exit(1);
}

int my_ssl_connect(SSL *ssl)
{
	char *fname = "my_ssl_connect()";
	X509*    server_cert;
	char*    str;
	int rc;
	int err;


#if 1
		if ( ssl->cav_crypto_state == CAV_ST_IN_HANDSHAKE ){
#ifdef CAVIUM_MULTICARD_API
		      rc = Csp1CheckForCompletion(ssl->cav_req_id,ssl->dev_id);
#else
		      rc = Csp1CheckForCompletion(ssl->cav_req_id);
#endif
			//printf ("check for completion returned :%d \n ", rc );

			if ( rc == EAGAIN ) {
				cav_fprintf(cav_nb_fp,"my_ssl_accept(): %s\n",
					"Csp1CheckForCompletion() EAGAIN");
				return(0);
			}
			else if ( rc == 0 ) {
				// cmd has completed 
				cav_fprintf(cav_nb_fp,"my_ssl_accept(): %s\n",
					"Csp1CheckForCompletion() cmd has completed");
				ssl->cav_req_id_check_done = 1;

			}
			else {
				cav_fprintf(cav_nb_fp,"my_ssl_accept(): %s %d\n",
					"Csp1CheckForCompletion() returned error", rc);
				return(-1);
			}
	} // end if cav state

#endif

	if ( (err = SSL_connect(ssl)) >= 0 ) {
		
			 server_cert = SSL_get_peer_certificate (ssl); 
			 if (server_cert == NULL) {
				cav_fprintf(cav_nb_fp,"main(): SSL_get_peer_certificate() failed\n");
				Exit(-1);
	 		 }

			 str = X509_NAME_oneline (X509_get_subject_name (server_cert),0,0);

			 if (str == NULL) {
				cav_fprintf(cav_nb_fp,"main(): X509_Name_online() failed\n");
				Exit(-1);
	 		 }

			 OPENSSL_free (str);
			 str = X509_NAME_oneline (X509_get_issuer_name  (server_cert),0,0); 

			 if (str == NULL) {
				cav_fprintf(cav_nb_fp,"main(): X509_Name_online for issuer() failed\n");
				Exit(-1);
	 		 }

			OPENSSL_free(str); 
			if (ssl->state == 4560)
				return -1;
			return(err);	// done
		}

	rc = SSL_get_error(ssl,err);


	switch (rc) {

	case SSL_ERROR_NONE:
		return(-1);
		
	case SSL_ERROR_ZERO_RETURN:
		return(-1);

	case SSL_ERROR_WANT_READ:
		return(0);
		
	case SSL_ERROR_WANT_WRITE:
		return(0);

	case SSL_ERROR_WANT_CAVIUM_CRYPTO:
		return(0);

	default:
		cav_fprintf(cav_nb_fp," sslptr->cav_crypto_state = %d\n",
				ssl->cav_crypto_state);

		if ( ssl->state == CAV_ST_IN_HANDSHAKE ) {
			return(0);
		}

		ERR_get_error();
		return(-1);
			
	} // end switch

	return(-1);

} // end my_ssl_connect()



int my_ssl_read(SSL *ssl)
{
	char *fname = "my_ssl_read()";
	char buf [4096];
	int rc;
	int err;
	int len;



#if 1
		if ( ssl->cav_crypto_state == CAV_ST_IN_DECRYPT) {
#ifdef CAVIUM_MULTICARD_API
		      rc = Csp1CheckForCompletion(ssl->cav_req_id,ssl->dev_id);
#else
		      rc = Csp1CheckForCompletion(ssl->cav_req_id);
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
				ssl->cav_req_id_check_done = 1;
			}
			else {
				cav_fprintf(cav_nb_fp,"my_ssl_read(): %s %d\n",
					"Csp1CheckForCompletion() returned error", rc);
				return(-1);
			}
	}
#endif
		memset(buf, 0, sizeof(buf));
		if ( err = SSL_read (ssl, buf, sizeof(buf) - 1) > 0 ) { 
		printf ("Data Read is %s \n", buf);
		cav_print_state(ssl, "my_ssl_read(): SSL_read() done");
		cav_fprintf(cav_nb_fp,"cav_crypto_state = %d\n",ssl->cav_crypto_state);
		return(1);	// done
	}

	rc = SSL_get_error(ssl, err);

	switch (rc) {

	case SSL_ERROR_NONE:
		return(-1);
		
	case SSL_ERROR_ZERO_RETURN:
		return(-1);

	case SSL_ERROR_WANT_READ:
		return(0);
		
	case SSL_ERROR_WANT_WRITE:
		return(0);
	
	case SSL_ERROR_WANT_CAVIUM_CRYPTO:
		return(0);
		
	default:
		return(-1);
				
	} // end switch
	return(-1);
}



/*
 * Returns:
 *		-1 on error (and the connection is shut-down
 *		 0 if WANTS something
 *		 1 if request is complete
 */
int my_ssl_write(SSL *ssl)
{
	char *fname = "my_ssl_write()";
	char buf [4096];
	int rc;
	int err;
	int len;


#if 1
		 if ( ssl->cav_crypto_state == CAV_ST_IN_ENCRYPT) {
#ifdef CAVIUM_MULTICARD_API
		       rc = Csp1CheckForCompletion(ssl->cav_req_id,ssl->dev_id);
#else
		       rc = Csp1CheckForCompletion(ssl->cav_req_id);
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
				ssl->cav_req_id_check_done = 1;
			}
			else {
				cav_fprintf(cav_nb_fp,"my_ssl_write(): %s %d\n",
					"Csp1CheckForCompletion() returned error", rc);
				return(-1);
			}
	}
#endif

	if ( (err = SSL_write(ssl,"GET \n",(sizeof("GET \n")))) > 0 ) {
		cav_print_state(ssl, "my_ssl_write(): SSL_write() done");
		cav_fprintf(cav_nb_fp,"cav_crypto_state = %d\n",ssl->cav_crypto_state);
		return(1);	// done
	}

	rc = SSL_get_error(ssl, err);

	switch (rc) {

	case SSL_ERROR_NONE:
		// cannot happen, since there was an error
		cav_fprintf(cav_nb_fp,"%s: invalid SSL_ERROR_NONE case\n", fname);
		return(-1);
		
	case SSL_ERROR_ZERO_RETURN:
		// connection was closed
		cav_fprintf(cav_nb_fp,"%s: connection was closed\n", fname);
		return(-1);

	case SSL_ERROR_WANT_READ:
		// need to call SSL_accept again
		cav_fprintf(cav_nb_fp,"%s: SSL_ERROR_WANT_READ case\n", fname);
		ssl->cav_crypto_state == CAV_ST_IN_ENCRYPT ;
		return(0);

	case SSL_ERROR_WANT_WRITE:
		// need to call SSL_accept again
		cav_fprintf(cav_nb_fp," %s: SSL_ERROR_WANT_WRITE case\n", fname);
		ssl->cav_crypto_state == CAV_ST_IN_ENCRYPT ;
		return(0);
	
	case SSL_ERROR_WANT_CAVIUM_CRYPTO:
		// need to call SSL_accept again
		cav_fprintf(cav_nb_fp," %s: SSL_ERROR_WANT_CAVIUM_CRYPTO case\n", fname);
		ssl->cav_crypto_state == CAV_ST_IN_ENCRYPT ;
		return(0);

	default:
		cav_fprintf(cav_nb_fp,"%s: invalid default case\n", fname);
		return(-1);
			
	} // end switch

	cav_fprintf(cav_nb_fp," %s: invalid program flow\n", fname);

	return(-1);

}

int my_ssl_shutdown(SSL *ssl)
{
	char *fname = "my_ssl_shutdown";
	int rc;
	int err;
	int len;

	if ((err = SSL_shutdown(ssl)) > 0 ) {
		cav_fprintf(cav_nb_fp,"%s: SSL_shutdown() worked\n",
			 fname);
		return(1);	// done
	}

	rc = SSL_get_error(ssl, err);

	switch (rc) {
	
	case SSL_ERROR_NONE:
                return(-1);
                                                                                                                             
        case SSL_ERROR_ZERO_RETURN:
                return(-1);
                                                                                                                             
        case SSL_ERROR_WANT_READ:
                return(0);
                                                                                                                             
        case SSL_ERROR_WANT_WRITE:
                return(0);

	case SSL_ERROR_WANT_CAVIUM_CRYPTO:
		// need to call SSL_shutdown again
		cav_fprintf(cav_nb_fp,"%s: SSL_ERROR_WANT_CAVIUM_CRYPTO case\n",
			fname);
		return(0);

	default:
		return(1);
			
	} // end switch

	return(-1);
}

