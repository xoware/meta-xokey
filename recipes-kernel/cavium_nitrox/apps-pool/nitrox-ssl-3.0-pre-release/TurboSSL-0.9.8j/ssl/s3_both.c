/* ssl/s3_both.c */
/* Copyright (C) 1995-1998 Eric Young (eay@cryptsoft.com)
 * All rights reserved.
 *
 * This package is an SSL implementation written
 * by Eric Young (eay@cryptsoft.com).
 * The implementation was written so as to conform with Netscapes SSL.
 * 
 * This library is free for commercial and non-commercial use as long as
 * the following conditions are aheared to.  The following conditions
 * apply to all code found in this distribution, be it the RC4, RSA,
 * lhash, DES, etc., code; not just the SSL code.  The SSL documentation
 * included with this distribution is covered by the same copyright terms
 * except that the holder is Tim Hudson (tjh@cryptsoft.com).
 * 
 * Copyright remains Eric Young's, and as such any Copyright notices in
 * the code are not to be removed.
 * If this package is used in a product, Eric Young should be given attribution
 * as the author of the parts of the library used.
 * This can be in the form of a textual message at program startup or
 * in documentation (online or textual) provided with the package.
 * 
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *    "This product includes cryptographic software written by
 *     Eric Young (eay@cryptsoft.com)"
 *    The word 'cryptographic' can be left out if the rouines from the library
 *    being used are not cryptographic related :-).
 * 4. If you include any Windows specific code (or a derivative thereof) from 
 *    the apps directory (application code) you must include an acknowledgement:
 *    "This product includes software written by Tim Hudson (tjh@cryptsoft.com)"
 * 
 * THIS SOFTWARE IS PROVIDED BY ERIC YOUNG ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 * 
 * The licence and distribution terms for any publically available version or
 * derivative of this code cannot be changed.  i.e. this code cannot simply be
 * copied and put under another distribution licence
 * [including the GNU Public Licence.]
 */
/* ====================================================================
 * Copyright (c) 1998-2002 The OpenSSL Project.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer. 
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. All advertising materials mentioning features or use of this
 *    software must display the following acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit. (http://www.openssl.org/)"
 *
 * 4. The names "OpenSSL Toolkit" and "OpenSSL Project" must not be used to
 *    endorse or promote products derived from this software without
 *    prior written permission. For written permission, please contact
 *    openssl-core@openssl.org.
 *
 * 5. Products derived from this software may not be called "OpenSSL"
 *    nor may "OpenSSL" appear in their names without prior written
 *    permission of the OpenSSL Project.
 *
 * 6. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit (http://www.openssl.org/)"
 *
 * THIS SOFTWARE IS PROVIDED BY THE OpenSSL PROJECT ``AS IS'' AND ANY
 * EXPRESSED OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE OpenSSL PROJECT OR
 * ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 * ====================================================================
 *
 * This product includes cryptographic software written by Eric Young
 * (eay@cryptsoft.com).  This product includes software written by Tim
 * Hudson (tjh@cryptsoft.com).
 *
 */
/* ====================================================================
 * Copyright 2002 Sun Microsystems, Inc. ALL RIGHTS RESERVED.
 * ECC cipher suite support in OpenSSL originally developed by 
 * SUN MICROSYSTEMS, INC., and contributed to the OpenSSL project.
 */

#include <limits.h>
#include <string.h>
#include <stdio.h>
#include "ssl_locl.h"
#include <openssl/buffer.h>
#include <openssl/rand.h>
#include <openssl/objects.h>
#include <openssl/evp.h>
#include <openssl/x509.h>
#ifdef CAVIUM_SSL

#include "ssl_engine.h"
#ifdef CAVIUM_FIPS
#include "luna_common.h"
#include "luna_ssl.h"
#else
#include "cavium_common.h"
#include "cavium_ssl.h"
#endif
#include "openssl/cav_debug.h"

#ifdef linux
#include <sys/mman.h>
#endif
#ifndef CAVIUM_NOMMAP
extern int CSP1_driver_handle;
#endif

#endif

/* send s->init_buf in records of type 'type' (SSL3_RT_HANDSHAKE or SSL3_RT_CHANGE_CIPHER_SPEC) */
int ssl3_do_write(SSL *s, int type)
	{
	int ret;
#ifdef CAVIUM_SSL	
    cav_fprintf(cav_nb_fp, "ssl3_do_write(): before ssl3_write_bytes!\n");
    cav_print_state(s, "ssl3_dowrite(): ");
#endif	
	ret=ssl3_write_bytes(s,type,&s->init_buf->data[s->init_off],
	                     s->init_num);
#ifdef CAVIUM_SSL	
    cav_fprintf(cav_nb_fp,
                      "ssl3_do_write(): after ssl3_write_bytes! : %d \n" , ret);
    cav_print_state(s, "ssl3_dowrite(): ");
#endif	

	if (ret < 0) return(-1);
	if (type == SSL3_RT_HANDSHAKE)
		/* should not be done for 'Hello Request's, but in that case
		 * we'll ignore the result anyway */
		ssl3_finish_mac(s,(unsigned char *)&s->init_buf->data[s->init_off],ret);
	
	if (ret == s->init_num)
		{
#ifdef CAVIUM_SSL	
		if( s->state == SSL3_ST_CW_FINISHED_B || 
			s->state == SSL3_ST_SW_FINISHED_B )
	        	s->init_buf->data[0] = SSL3_MT_FINISHED;
#endif

		if (s->msg_callback)
			s->msg_callback(1, s->version, type, s->init_buf->data, (size_t)(s->init_off + s->init_num), s, s->msg_callback_arg);
		return(1);
		}
	s->init_off+=ret;
	s->init_num-=ret;
	return(0);
	}

int ssl3_send_finished(SSL *s, int a, int b, const char *sender, int slen)
	{
	unsigned char *p,*d;
	int i;
	unsigned long l;

	if (s->state == a)
		{
		d=(unsigned char *)s->init_buf->data;
		p= &(d[4]);

		i=s->method->ssl3_enc->final_finish_mac(s,
			&(s->s3->finish_dgst1),
			&(s->s3->finish_dgst2),
			sender,slen,s->s3->tmp.finish_md);
		s->s3->tmp.finish_md_len = i;
		memcpy(p, s->s3->tmp.finish_md, i);
		p+=i;
		l=i;

#ifdef OPENSSL_SYS_WIN16
		/* MSVC 1.5 does not clear the top bytes of the word unless
		 * I do this.
		 */
		l&=0xffff;
#endif

		*(d++)=SSL3_MT_FINISHED;
		l2n3(l,d);
		s->init_num=(int)l+4;
		s->init_off=0;

		s->state=b;
		}

	/* SSL3_ST_SEND_xxxxxx_HELLO_B */
	return(ssl3_do_write(s,SSL3_RT_HANDSHAKE));
	}

int ssl3_get_finished(SSL *s, int a, int b)
	{
	int al=0,i,ok;
	long n;
	unsigned char *p;
#ifdef CAVIUM_SSL
    int rc = 0;
    int ret = 0;
    int ttmp =0, ttmp1 =0, ttmp2 =0 , ttmp3= 0 , ttmp4 =0;
    unsigned char  dec_peer_client_finished[80];
    unsigned short peer_len=0;
#ifdef CAVIUM_FIPS
    Uint32 req_id;
#endif
#endif

	/* the mac has already been generated when we received the
	 * change cipher spec message and is in s->s3->tmp.peer_finish_md
	 */ 
#ifdef CAVIUM_SSL
    if (s->cav_renego > 0 && s->cav_nb_mode == 1 ) {

        if (s->cav_crypto_state == CAV_ST_IN_ENCRYPT){

            if (s->server) {

                s->state=SSL3_ST_SW_CHANGE_B;
                rc = ssl3_do_write(s,SSL3_RT_CHANGE_CIPHER_SPEC);

                if ( rc == 0 ) {
                    s->state = SSL3_ST_SR_FINISHED_A ;
                    return(0);
                }
                s->write_cipher_active = 0;
                goto reneg ;
            }
        }
    }
    if (s->cav_crypto_state == CAV_ST_IN_CHK_DEC_PEER_2) {

        rc = check_dec_peer_completion(s,
                                        &ttmp,
                                        &ttmp1,
                                        &ttmp2,
                                        &ttmp3,
                                        &ttmp4,
                                        &peer_len,
                                        (char *)dec_peer_client_finished);
        if (rc == 1) {
            s->peer_len = peer_len ;
            if((s->session->cipher->id == TLS1_CK_RSA_WITH_AES_128_SHA) ||
                    (s->session->cipher->id == TLS1_CK_RSA_WITH_AES_256_SHA))

                if(s->server){
                    goto dec_peer1;
                }
                else    goto dec_peer3;
            else
                if(s->server){
                    goto dec_peer;
                }
                else   goto dec_peer2;
        }

        if ( rc == 0 ) {
            cav_fprintf(cav_nb_fp,"ssl3_get_finished(): %s\n",
                  "check_dec_peer_completion() not completed");
            return(0);
        }
        else if ( rc == -1 ) {
            cav_fprintf(cav_nb_fp,"ssl3_get_finished(): %s\n",
                    "ERROR check_dec_peer_completion() failed");
            return(-1);
        }

    } /* end if .. CAV_ST_IN_HANDSHAKE */
#endif

	n=s->method->ssl_get_message(s,
		a,
		b,
		SSL3_MT_FINISHED,
		64, /* should actually be 36+4 :-) */
		&ok);

	if (!ok) return((int)n);

	/* If this occurs, we have missed a message */
	if (!s->s3->change_cipher_spec)
		{
		al=SSL_AD_UNEXPECTED_MESSAGE;
		SSLerr(SSL_F_SSL3_GET_FINISHED,SSL_R_GOT_A_FIN_BEFORE_A_CCS);
		goto f_err;
		}
	s->s3->change_cipher_spec=0;

#ifdef CAVIUM_SSL

	if(s->cipher_support)
	{
		p = (unsigned char *)s->init_msg;

		if(s->server)
		{
			if(s->hit)
			{
				/* Since it is a hit and CAVIUM_SSL is defined so we compare the
                   client finish with the locally calculated message handshake 
                   hashes. Local handshake hashes were caluculated when change 
                   cipher spec was sent to client */
				int cipher_type, digest_type;
				const EVP_MD *hash;
				const EVP_CIPHER *c;
				SSL_COMP *comp;
				HashType hash_type;
				SslVersion ssl_version;

				/* now replace first four bytes of client finish message.*/
				memcpy(&(s->hs_msgs[s->client_finish_msg_offset]),s->peer_finish_first_four,4);

				if((s->session->cipher->id == SSL3_CK_RSA_DES_192_CBC3_SHA)
										 ||
				 (s->session->cipher->id == TLS1_CK_RSA_EXPORT1024_WITH_DES_CBC_SHA)
			 							 ||
				 (s->session->cipher->id == SSL3_CK_RSA_DES_40_CBC_SHA)
			 							 ||
				 (s->session->cipher->id == SSL3_CK_RSA_DES_64_CBC_SHA))
				{

					if (!ssl_cipher_get_evp(s->session,&c,&hash,&comp))
						{
						SSLerr(SSL_F_SSL3_SETUP_KEY_BLOCK,SSL_R_CIPHER_OR_HASH_UNAVAILABLE);
						ret = 0;
						goto f_err;
						}

					digest_type = EVP_MD_type(hash);
					cipher_type = EVP_CIPHER_nid(c);

					if(digest_type == NID_md5)   
						hash_type = MD5_TYPE;

					else if(digest_type == NID_sha1) 
						hash_type = SHA1_TYPE;

					else
					{
					   ret = 0;
					   goto f_err;
					}

					if(s->version > SSL3_VERSION)
					{
						ssl_version = VER_TLS;
					}
					else
					{
						ssl_version = VER3_0;
					}

					/* decrypt the received client finished */
					if(ssl_version == VER_TLS)
					{
						if (memcmp(&s->hs_msgs[s->client_finish_msg_offset], s->client_finished, n) != 0)
						{
							ret =0;
							al=SSL_AD_DECRYPT_ERROR;
							SSLerr(SSL_F_SSL3_GET_FINISHED,SSL_R_DIGEST_CHECK_FAILED);
							goto f_err;
						}
					}
					else
					{
#ifdef CAVIUM_FIPS
				        i = Cfm1DecryptRecord3DesRecover(OP_BLOCKING,
									 s->context_pointer, 
									 hash_type, 
									 ssl_version, 
									 SSL_SERVER,
									 HANDSHAKE,
									 (short)(s->hs_msgs_len - s->client_finish_msg_offset),  
									 &s->hs_msgs[s->client_finish_msg_offset], 
									 &peer_len, 
									 dec_peer_client_finished,
									 &req_id
									 );
#else
#ifndef MC2
					    i = Csp1DecryptRecord3DesRecover
#else
					    i = Csp1DecryptRecord3Des
#endif
									(
								         s->cav_nb_mode	,
									 s->context_pointer, 
									 hash_type, 
									 ssl_version, 
									 SSL_SERVER,
									 HANDSHAKE,
									 (short)(s->hs_msgs_len - s->client_finish_msg_offset),  
									 &s->hs_msgs[s->client_finish_msg_offset], 
									 &s->peer_len, 
									 s->dec_peer_client_finished,

#ifdef CAVIUM_MULTICARD_API
									 &s->cav_req_id,s->dev_id
#else
									 &s->cav_req_id
#endif
                                   );
#endif
						if ( i== 0 ){
			                memcpy (dec_peer_client_finished, s->dec_peer_client_finished,s->peer_len);
                     	}

				        if ( i == EAGAIN ) {
                         	cav_fprintf(cav_nb_fp,"pkp_resume_handshake(): %s\n",
		                        	"ssl3_get_finished() EAGAIN");
	        		        s->cav_crypto_state = CAV_ST_IN_CHK_DEC_PEER_2;
			                s->cav_saved_state = s->state;
                                        s->state = CAV_ST_IN_RESUME_HANDSHAKE;
                	        s->cav_req_id_check_done = 0;
		                    s->rwstate = SSL_NITROX_BUSY;
                		}
	                    if ( i != 0)
		        	    {
                	        ret = 0 ;
                		    return ret;
                        }


dec_peer:				if( memcmp(dec_peer_client_finished, s->client_finished,s->peer_len) != 0)
						{
                            cav_fprintf(cav_nb_fp,"pkp_resume_handshake(): %s\n",
		                        	"ssl3_get_finished() FAILED");
							ret =0;
							al=SSL_AD_DECRYPT_ERROR;
							SSLerr(SSL_F_SSL3_GET_FINISHED,SSL_R_DIGEST_CHECK_FAILED);
							goto f_err;
						}
					}
				}
				else if(
				 (s->session->cipher->id == TLS1_CK_RSA_WITH_AES_128_SHA)
				 ||
				 (s->session->cipher->id == TLS1_CK_RSA_WITH_AES_256_SHA)
				 	)
				{

					if (!ssl_cipher_get_evp(s->session,&c,&hash,&comp))
						{
						SSLerr(SSL_F_SSL3_SETUP_KEY_BLOCK,SSL_R_CIPHER_OR_HASH_UNAVAILABLE);
						ret = 0;
						goto f_err;
						}

					digest_type = EVP_MD_type(hash);
					cipher_type = EVP_CIPHER_nid(c);

					if(digest_type == NID_md5)   
						hash_type = MD5_TYPE;

					else if(digest_type == NID_sha1) 
						hash_type = SHA1_TYPE;

					else
					{
					    ret = 0;
					    goto f_err;
					}

					if(s->version > SSL3_VERSION)
					{
						ssl_version = VER_TLS;
					}
					else
					{
						ssl_version = VER3_0;
					}

					/* decrypt the received client finished */
					if(ssl_version == VER_TLS)
					{
						if (memcmp(&s->hs_msgs[s->client_finish_msg_offset], s->client_finished, n) != 0)
						{
							ret =0;
							al=SSL_AD_DECRYPT_ERROR;
							SSLerr(SSL_F_SSL3_GET_FINISHED,SSL_R_DIGEST_CHECK_FAILED);
							goto f_err;
						}
					}
					else
					{
						AesType aes_type = get_Aes_type(s->session->cipher->id);
#ifdef CAVIUM_FIPS

						i = Cfm1DecryptRecordAesRecover(
									 OP_BLOCKING,
									 s->context_pointer, 
									 hash_type, 
									 ssl_version, 
									 SSL_SERVER,
									 aes_type,
									 HANDSHAKE,
									 (short)(s->hs_msgs_len - s->client_finish_msg_offset),  
									 &s->hs_msgs[s->client_finish_msg_offset], 
									 &s->peer_len, 
									 s->dec_peer_client_finished,
									 &req_id
									 );
#else						
#ifndef MC2
						i = Csp1DecryptRecordAesRecover
#else
						i = Csp1DecryptRecordAes
#endif

									(
								         s->cav_nb_mode	,
									 s->context_pointer, 
									 hash_type, 
									 ssl_version, 
									 SSL_SERVER,
									 aes_type,
									 HANDSHAKE,
									 (short)(s->hs_msgs_len - s->client_finish_msg_offset),  
									 &s->hs_msgs[s->client_finish_msg_offset], 
									 &s->peer_len, 
									 s->dec_peer_client_finished,

#ifdef CAVIUM_MULTICARD_API
									 &s->cav_req_id,s->dev_id
#else
									 &s->cav_req_id
#endif
                                                                 );
#endif
						
						if ( i== 0 ){
                            memcpy (dec_peer_client_finished, s->dec_peer_client_finished, s->peer_len);
                        }

                        if ( i == EAGAIN ) {
                            cav_fprintf(cav_nb_fp,"pkp_resume_handshake(): %s\n",
                                    "ssl3_get_finished() EAGAIN");
                            s->cav_crypto_state = CAV_ST_IN_CHK_DEC_PEER_2;
                            s->cav_saved_state = s->state;
                            s->state = CAV_ST_IN_RESUME_HANDSHAKE;
                            s->cav_req_id_check_done = 0;
                            s->rwstate = SSL_NITROX_BUSY;
                        }
                        if ( i != 0)
                        {
                            ret = 0 ;
                            return ret;
                        }


dec_peer1:				if( memcmp(dec_peer_client_finished, s->client_finished,s->peer_len ) != 0)
						{
							cav_fprintf(cav_nb_fp, "%s %s\n",
								"ssl3_get_finished(): memcmp after ",
								"server side Csp1DecryptRecordAesRecover() failed");
							ret =0;
							al=SSL_AD_DECRYPT_ERROR;
							SSLerr(SSL_F_SSL3_GET_FINISHED,SSL_R_DIGEST_CHECK_FAILED);
							goto f_err;
						}
					}

				}
				else
				{
					if (memcmp(&s->hs_msgs[s->client_finish_msg_offset], s->client_finished, n) != 0)
						{
						cav_fprintf(cav_nb_fp, "%s %s\n",
							"ssl3_get_finished(): memcmp after ",
								"RC4 FAILED");
						ret =0;
						al=SSL_AD_DECRYPT_ERROR;
						SSLerr(SSL_F_SSL3_GET_FINISHED,SSL_R_DIGEST_CHECK_FAILED);
						goto f_err;
						}
				}
				s->read_cipher_active = 1;
				ret = 1;
			} // end s->hit
			else
			{
reneg:			if(!(SSL_get_verify_mode(s) & SSL_VERIFY_PEER))
				{
					if(s->s3->tmp.use_rsa_tmp){
						ret = pkp_ephemeral_handshake(s);
					}
					else {
						// call chip for handshake
						cav_print_state(s, 
							"ssl3_get_finished(): before pkp_handshake");
						ret = pkp_handshake(s);
						if ( ret > 0 ) {
							cav_fprintf(cav_nb_fp,
								"ssl3_get_finished(): %s %d\n",
								"pkp_handshake() is done, ret = ",
								ret);
						}
						else {
							cav_fprintf(cav_nb_fp,
								"ssl3_get_finished(): %s %d\n",
								"pkp_handshake() is NOT done, ret = ",
								ret);
						}
					}
				}

				else 
					ret = pkp_handshake_client_auth(s);
					
			} /* if no hit */
		} /* if server */

		else /* if client */
		{
			if(s->hit)
			{
				if( pkp_client_resume_handshake(s))
				{
					s->read_cipher_active = 1;
					ret = 1;
				}
				else
				{
					ret = 0;
					if (s->cav_nb_mode == 1 ) {
						s->read_cipher_active = 1;
						return ret ;
					}
					else {
						al=SSL_AD_DECRYPT_ERROR;
						SSLerr(SSL_F_SSL3_GET_FINISHED,SSL_R_DIGEST_CHECK_FAILED);
						goto f_err;
					}
				}
			}
			else
			{
				int cipher_type, digest_type;
				const EVP_MD *hash;
				const EVP_CIPHER *c;
				SSL_COMP *comp;
				HashType hash_type;
				SslVersion ssl_version;
				unsigned char *p1;

				p1 = &s->hs_msgs[s->server_finish_msg_offset];

				/* now replace first four bytes of server finish message.*/
				memcpy(p1,s->peer_finish_first_four,4);

				if((s->session->cipher->id == SSL3_CK_RSA_DES_192_CBC3_SHA)
										 ||
				 (s->session->cipher->id == TLS1_CK_RSA_EXPORT1024_WITH_DES_CBC_SHA)
			 							 ||
				 (s->session->cipher->id == SSL3_CK_RSA_DES_40_CBC_SHA)
			 							 ||
				 (s->session->cipher->id == SSL3_CK_RSA_DES_64_CBC_SHA))
				{

					if (!ssl_cipher_get_evp(s->session,&c,&hash,&comp))
						{
						SSLerr(SSL_F_SSL3_SETUP_KEY_BLOCK,SSL_R_CIPHER_OR_HASH_UNAVAILABLE);
						ret = 0;
						goto f_err;
						}

					digest_type = EVP_MD_type(hash);
					cipher_type = EVP_CIPHER_nid(c);

					if(digest_type == NID_md5)   
						hash_type = MD5_TYPE;

					else if(digest_type == NID_sha1) 
						hash_type = SHA1_TYPE;

					else
					{
					 ret = 0;
					 goto f_err;
					}

					if(s->version > SSL3_VERSION)
					{
						ssl_version = VER_TLS;
					}
					else
					{
						ssl_version = VER3_0;
					}

					/* decrypt the received finished */
					if(ssl_version == VER_TLS)
					{
						if (memcmp(&s->hs_msgs[s->server_finish_msg_offset], s->server_finished, n) != 0)
						{
							ret =0;
							al=SSL_AD_DECRYPT_ERROR;
							SSLerr(SSL_F_SSL3_GET_FINISHED,SSL_R_DIGEST_CHECK_FAILED);
							goto f_err;
						}
					}
					else
					{
#ifdef CAVIUM_FIPS
					i = Cfm1DecryptRecord3DesRecover(
									 OP_BLOCKING,
									 s->context_pointer, 
									 hash_type, 
									 ssl_version, 
									 SSL_CLIENT,
									 HANDSHAKE,
									 (short)(s->hs_msgs_len - s->server_finish_msg_offset),  
									 &s->hs_msgs[s->server_finish_msg_offset], 
									 &s->peer_len,
									 s->dec_peer_client_finished,
									 &req_id
									 );
#else
#ifndef MC2
					i = Csp1DecryptRecord3DesRecover
#else
					i = Csp1DecryptRecord3Des
#endif
								   (
									 s->cav_nb_mode,
									 s->context_pointer, 
									 hash_type, 
									 ssl_version, 
									 SSL_CLIENT,
									 HANDSHAKE,
									 (short)(s->hs_msgs_len - s->server_finish_msg_offset),  
									 &s->hs_msgs[s->server_finish_msg_offset], 
									 &s->peer_len,
									 s->dec_peer_client_finished,

#ifdef CAVIUM_MULTICARD_API
									 &s->cav_req_id,s->dev_id
#else
									 &s->cav_req_id
#endif
                                                               );

#endif
					if ( i== 0 ){
			             memcpy (dec_peer_client_finished, s->dec_peer_client_finished,s->peer_len);
                    }
				    if ( i == EAGAIN ) {
                        cav_fprintf(cav_nb_fp,"pkp_client_handshake(): %s\n",
		                       	"ssl3_get_finished() EAGAIN");
	        		    s->cav_crypto_state = CAV_ST_IN_CHK_DEC_PEER_2;
			            s->cav_saved_state = s->state;
                                    s->state = CAV_ST_IN_RESUME_HANDSHAKE;
                	        s->cav_req_id_check_done = 0;
		                    s->rwstate = SSL_NITROX_BUSY;
                	}
					
                    if ( i != 0)
                    {
                        ret = 0 ;
                        return ret;
                    }

dec_peer2:
					if( memcmp(dec_peer_client_finished, s->server_finished,s->peer_len) != 0)
					{

						cav_fprintf(cav_nb_fp, "%s %s\n",
							"ssl3_get_finished(): memcmp after ",
							"client side Csp1DecryptRecordDesRecover() failed");
						ret =0;
						al=SSL_AD_DECRYPT_ERROR;
						SSLerr(SSL_F_SSL3_GET_FINISHED,SSL_R_DIGEST_CHECK_FAILED);
						goto f_err;
						}
					}

				} // end if ... DES
				else if(
				 (s->session->cipher->id == TLS1_CK_RSA_WITH_AES_128_SHA)
				 ||
				 (s->session->cipher->id == TLS1_CK_RSA_WITH_AES_256_SHA)
				 	)
				{

					if (!ssl_cipher_get_evp(s->session,&c,&hash,&comp))
						{
						SSLerr(SSL_F_SSL3_SETUP_KEY_BLOCK,SSL_R_CIPHER_OR_HASH_UNAVAILABLE);
						ret = 0;
						goto f_err;
						}

					digest_type = EVP_MD_type(hash);
					cipher_type = EVP_CIPHER_nid(c);

					if(digest_type == NID_md5)   
						hash_type = MD5_TYPE;

					else if(digest_type == NID_sha1) 
						hash_type = SHA1_TYPE;

					else
					{
					    ret = 0;
					    goto f_err;
					}

					if(s->version > SSL3_VERSION)
					{
						ssl_version = VER_TLS;
					}
					else
					{
						ssl_version = VER3_0;
					}

					/* decrypt the received finished */
					if(ssl_version == VER_TLS)
					{
						if (memcmp(&s->hs_msgs[s->server_finish_msg_offset], s->server_finished, n) != 0)
						{
							ret =0;
							al=SSL_AD_DECRYPT_ERROR;
							SSLerr(SSL_F_SSL3_GET_FINISHED,SSL_R_DIGEST_CHECK_FAILED);
							goto f_err;
						}
					}
					else
					{
						AesType aes_type = get_Aes_type(s->session->cipher->id);
#ifdef CAVIUM_FIPS
						i = Cfm1DecryptRecordAesRecover(
									 OP_BLOCKING,
									 s->context_pointer, 
									 hash_type, 
									 ssl_version, 
									 SSL_CLIENT,
									 aes_type,
									 HANDSHAKE,
									 (short)(s->hs_msgs_len - s->server_finish_msg_offset),  
									 &s->hs_msgs[s->server_finish_msg_offset], 
									 &s->peer_len,
									 s->dec_peer_client_finished,
									 &req_id
									 );
#else
#ifndef MC2
 
						i = Csp1DecryptRecordAesRecover
#else
						i = Csp1DecryptRecordAes
#endif
							(
									 s->cav_nb_mode,
									 s->context_pointer, 
									 hash_type, 
									 ssl_version, 
									 SSL_CLIENT,
									 aes_type,
									 HANDSHAKE,
									 (short)(s->hs_msgs_len - s->server_finish_msg_offset),  
									 &s->hs_msgs[s->server_finish_msg_offset], 
									 &s->peer_len,
									 s->dec_peer_client_finished,
#ifdef CAVIUM_MULTICARD_API
									 &s->cav_req_id,s->dev_id
#else
									 &s->cav_req_id
#endif
                                                                    );
#endif

					if ( i== 0 ){
			            memcpy (dec_peer_client_finished, s->dec_peer_client_finished,s->peer_len);
                                                                                                                             
                    }
				    if ( i == EAGAIN ) {
                       	cav_fprintf(cav_nb_fp,"pkp_client_handshake(): %s\n",
		                           	"ssl3_get_finished() EAGAIN");
	        		    s->cav_crypto_state = CAV_ST_IN_CHK_DEC_PEER_2;
			            s->cav_saved_state = s->state;
                                    s->state = CAV_ST_IN_RESUME_HANDSHAKE;
                	        s->cav_req_id_check_done = 0;
		                    s->rwstate = SSL_NITROX_BUSY;
                	}
					
                    if ( i != 0)
                    {
                        ret = 0 ;
                        return ret;
                    }

dec_peer3:			
					if( memcmp(dec_peer_client_finished, s->server_finished,s->peer_len) != 0)
					{
						ret =0;
						al=SSL_AD_DECRYPT_ERROR;
						SSLerr(SSL_F_SSL3_GET_FINISHED,SSL_R_DIGEST_CHECK_FAILED);
						goto f_err;
					}
				}

				} // end else ... AES
				else
				{
					if (memcmp(p1, s->server_finished, n+4) != 0)
					{
						ret =0;
						al=SSL_AD_DECRYPT_ERROR;
						SSLerr(SSL_F_SSL3_GET_FINISHED,SSL_R_DIGEST_CHECK_FAILED);
						goto f_err;
					}
				}

				s->read_cipher_active = 1;
				ret = 1;

			} /* if no hit */

		}/* if client */
	}
	else {
		// In 0.96g turbossl it was:
		//p = (unsigned char *)s->init_buf->data;
		p = (unsigned char *)s->init_msg;
		i = s->s3->tmp.peer_finish_md_len;

		if (i != n)
			{
			al=SSL_AD_DECODE_ERROR;
			SSLerr(SSL_F_SSL3_GET_FINISHED,SSL_R_BAD_DIGEST_LENGTH);
			goto f_err;
			}

		if (memcmp(p, s->s3->tmp.peer_finish_md, i) != 0)
			{
			al=SSL_AD_DECRYPT_ERROR;
			SSLerr(SSL_F_SSL3_GET_FINISHED,SSL_R_DIGEST_CHECK_FAILED);
			goto f_err;
			}
		ret = 1;

	}

	/* finally */

	return (ret);
#else
	p = (unsigned char *)s->init_msg;
	i = s->s3->tmp.peer_finish_md_len;

	if (i != n)
		{
		al=SSL_AD_DECODE_ERROR;
		SSLerr(SSL_F_SSL3_GET_FINISHED,SSL_R_BAD_DIGEST_LENGTH);
		goto f_err;
		}

	if (memcmp(p, s->s3->tmp.peer_finish_md, i) != 0)
		{
		al=SSL_AD_DECRYPT_ERROR;
		SSLerr(SSL_F_SSL3_GET_FINISHED,SSL_R_DIGEST_CHECK_FAILED);
		goto f_err;
		}
#endif
	return(1);
f_err:
	ssl3_send_alert(s,SSL3_AL_FATAL,al);
	return(0);
	}

/* for these 2 messages, we need to
 * ssl->enc_read_ctx			re-init
 * ssl->s3->read_sequence		zero
 * ssl->s3->read_mac_secret		re-init
 * ssl->session->read_sym_enc		assign
 * ssl->session->read_compression	assign
 * ssl->session->read_hash		assign
 */
int ssl3_send_change_cipher_spec(SSL *s, int a, int b)
	{ 
	unsigned char *p;

	if (s->state == a)
		{
		p=(unsigned char *)s->init_buf->data;
		*p=SSL3_MT_CCS;
		s->init_num=1;
		s->init_off=0;

		s->state=b;
		}

	/* SSL3_ST_CW_CHANGE_B */
	return(ssl3_do_write(s,SSL3_RT_CHANGE_CIPHER_SPEC));
	}

unsigned long ssl3_output_cert_chain(SSL *s, X509 *x)
	{
	unsigned char *p;
	int n,i;
	unsigned long l=7;
	BUF_MEM *buf;
	X509_STORE_CTX xs_ctx;
	X509_OBJECT obj;

	int no_chain;

	if ((s->mode & SSL_MODE_NO_AUTO_CHAIN) || s->ctx->extra_certs)
		no_chain = 1;
	else
		no_chain = 0;

	/* TLSv1 sends a chain with nothing in it, instead of an alert */
	buf=s->init_buf;
	if (!BUF_MEM_grow_clean(buf,10))
		{
		SSLerr(SSL_F_SSL3_OUTPUT_CERT_CHAIN,ERR_R_BUF_LIB);
		return(0);
		}
	if (x != NULL)
		{
		if(!no_chain && !X509_STORE_CTX_init(&xs_ctx,s->ctx->cert_store,NULL,NULL))
			{
			SSLerr(SSL_F_SSL3_OUTPUT_CERT_CHAIN,ERR_R_X509_LIB);
			return(0);
			}

		for (;;)
			{
			n=i2d_X509(x,NULL);
			if (!BUF_MEM_grow_clean(buf,(int)(n+l+3)))
				{
				SSLerr(SSL_F_SSL3_OUTPUT_CERT_CHAIN,ERR_R_BUF_LIB);
				return(0);
				}
			p=(unsigned char *)&(buf->data[l]);
			l2n3(n,p);
			i2d_X509(x,&p);
			l+=n+3;

			if (no_chain)
				break;

			if (X509_NAME_cmp(X509_get_subject_name(x),
				X509_get_issuer_name(x)) == 0) break;

			i=X509_STORE_get_by_subject(&xs_ctx,X509_LU_X509,
				X509_get_issuer_name(x),&obj);
			if (i <= 0) break;
			x=obj.data.x509;
			/* Count is one too high since the X509_STORE_get uped the
			 * ref count */
			X509_free(x);
			}
		if (!no_chain)
			X509_STORE_CTX_cleanup(&xs_ctx);
		}

	/* Thawte special :-) */
	if (s->ctx->extra_certs != NULL)
	for (i=0; i<sk_X509_num(s->ctx->extra_certs); i++)
		{
		x=sk_X509_value(s->ctx->extra_certs,i);
		n=i2d_X509(x,NULL);
		if (!BUF_MEM_grow_clean(buf,(int)(n+l+3)))
			{
			SSLerr(SSL_F_SSL3_OUTPUT_CERT_CHAIN,ERR_R_BUF_LIB);
			return(0);
			}
		p=(unsigned char *)&(buf->data[l]);
		l2n3(n,p);
		i2d_X509(x,&p);
		l+=n+3;
		}

	l-=7;
	p=(unsigned char *)&(buf->data[4]);
	l2n3(l,p);
	l+=3;
	p=(unsigned char *)&(buf->data[0]);
	*(p++)=SSL3_MT_CERTIFICATE;
	l2n3(l,p);
	l+=4;
	return(l);
	}

/* Obtain handshake message of message type 'mt' (any if mt == -1),
 * maximum acceptable body length 'max'.
 * The first four bytes (msg_type and length) are read in state 'st1',
 * the body is read in state 'stn'.
 */
long ssl3_get_message(SSL *s, int st1, int stn, int mt, long max, int *ok)
	{
	unsigned char *p;
	unsigned long l;
	long n;
	int i,al;

	if (s->s3->tmp.reuse_message)
		{
		s->s3->tmp.reuse_message=0;
		if ((mt >= 0) && (s->s3->tmp.message_type != mt))
			{
			al=SSL_AD_UNEXPECTED_MESSAGE;
			SSLerr(SSL_F_SSL3_GET_MESSAGE,SSL_R_UNEXPECTED_MESSAGE);
			goto f_err;
			}
		*ok=1;
		s->init_msg = s->init_buf->data + 4;
		s->init_num = (int)s->s3->tmp.message_size;
		return s->init_num;
		}

	p=(unsigned char *)s->init_buf->data;

	if (s->state == st1) /* s->init_num < 4 */
		{
		int skip_message;

		do
			{
			while (s->init_num < 4)
				{
				i=s->method->ssl_read_bytes(s,SSL3_RT_HANDSHAKE,
					&p[s->init_num],4 - s->init_num, 0);
				if (i <= 0)
					{
					s->rwstate=SSL_READING;
					*ok = 0;
					return i;
					}
				s->init_num+=i;
				}
			
			skip_message = 0;
			if (!s->server)
				if (p[0] == SSL3_MT_HELLO_REQUEST)
					/* The server may always send 'Hello Request' messages --
					 * we are doing a handshake anyway now, so ignore them
					 * if their format is correct. Does not count for
					 * 'Finished' MAC. */
					if (p[1] == 0 && p[2] == 0 &&p[3] == 0)
						{
						s->init_num = 0;
						skip_message = 1;

						if (s->msg_callback)
							s->msg_callback(0, s->version, SSL3_RT_HANDSHAKE, p, 4, s, s->msg_callback_arg);
						}
			}
		while (skip_message);

		/* s->init_num == 4 */

		if ((mt >= 0) && (*p != mt))
			{
			al=SSL_AD_UNEXPECTED_MESSAGE;
			SSLerr(SSL_F_SSL3_GET_MESSAGE,SSL_R_UNEXPECTED_MESSAGE);
			goto f_err;
			}
		if ((mt < 0) && (*p == SSL3_MT_CLIENT_HELLO) &&
					(st1 == SSL3_ST_SR_CERT_A) &&
					(stn == SSL3_ST_SR_CERT_B))
			{
			/* At this point we have got an MS SGC second client
			 * hello (maybe we should always allow the client to
			 * start a new handshake?). We need to restart the mac.
			 * Don't increment {num,total}_renegotiations because
			 * we have not completed the handshake. */
			ssl3_init_finished_mac(s);
			}

		s->s3->tmp.message_type= *(p++);

		n2l3(p,l);
		if (l > (unsigned long)max)
			{
			al=SSL_AD_ILLEGAL_PARAMETER;
			SSLerr(SSL_F_SSL3_GET_MESSAGE,SSL_R_EXCESSIVE_MESSAGE_SIZE);
			goto f_err;
			}
		if (l > (INT_MAX-4)) /* BUF_MEM_grow takes an 'int' parameter */
			{
			al=SSL_AD_ILLEGAL_PARAMETER;
			SSLerr(SSL_F_SSL3_GET_MESSAGE,SSL_R_EXCESSIVE_MESSAGE_SIZE);
			goto f_err;
			}
		if (l && !BUF_MEM_grow_clean(s->init_buf,(int)l+4))
			{
			SSLerr(SSL_F_SSL3_GET_MESSAGE,ERR_R_BUF_LIB);
			goto err;
			}
		s->s3->tmp.message_size=l;
		s->state=stn;

		s->init_msg = s->init_buf->data + 4;
		s->init_num = 0;
		}

	/* next state (stn) */
	p = s->init_msg;
	n = s->s3->tmp.message_size - s->init_num;
	while (n > 0)
		{
		i=s->method->ssl_read_bytes(s,SSL3_RT_HANDSHAKE,&p[s->init_num],n,0);
		if (i <= 0)
			{
			s->rwstate=SSL_READING;
			*ok = 0;
			return i;
			}
		s->init_num += i;
		n -= i;
		}
	ssl3_finish_mac(s, (unsigned char *)s->init_buf->data, s->init_num + 4);
	if (s->msg_callback)
		s->msg_callback(0, s->version, SSL3_RT_HANDSHAKE, s->init_buf->data, (size_t)s->init_num + 4, s, s->msg_callback_arg);
	*ok=1;
	return s->init_num;
f_err:
	ssl3_send_alert(s,SSL3_AL_FATAL,al);
err:
	*ok=0;
	return(-1);
	}

int ssl_cert_type(X509 *x, EVP_PKEY *pkey)
	{
	EVP_PKEY *pk;
	int ret= -1,i;

	if (pkey == NULL)
		pk=X509_get_pubkey(x);
	else
		pk=pkey;
	if (pk == NULL) goto err;

	i=pk->type;
	if (i == EVP_PKEY_RSA)
		{
		ret=SSL_PKEY_RSA_ENC;
		}
	else if (i == EVP_PKEY_DSA)
		{
		ret=SSL_PKEY_DSA_SIGN;
		}
#ifndef OPENSSL_NO_EC
	else if (i == EVP_PKEY_EC)
		{
		ret = SSL_PKEY_ECC;
		}
#endif

err:
	if(!pkey) EVP_PKEY_free(pk);
	return(ret);
	}

int ssl_verify_alarm_type(long type)
	{
	int al;

	switch(type)
		{
	case X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT:
	case X509_V_ERR_UNABLE_TO_GET_CRL:
	case X509_V_ERR_UNABLE_TO_GET_CRL_ISSUER:
		al=SSL_AD_UNKNOWN_CA;
		break;
	case X509_V_ERR_UNABLE_TO_DECRYPT_CERT_SIGNATURE:
	case X509_V_ERR_UNABLE_TO_DECRYPT_CRL_SIGNATURE:
	case X509_V_ERR_UNABLE_TO_DECODE_ISSUER_PUBLIC_KEY:
	case X509_V_ERR_ERROR_IN_CERT_NOT_BEFORE_FIELD:
	case X509_V_ERR_ERROR_IN_CERT_NOT_AFTER_FIELD:
	case X509_V_ERR_ERROR_IN_CRL_LAST_UPDATE_FIELD:
	case X509_V_ERR_ERROR_IN_CRL_NEXT_UPDATE_FIELD:
	case X509_V_ERR_CERT_NOT_YET_VALID:
	case X509_V_ERR_CRL_NOT_YET_VALID:
	case X509_V_ERR_CERT_UNTRUSTED:
	case X509_V_ERR_CERT_REJECTED:
		al=SSL_AD_BAD_CERTIFICATE;
		break;
	case X509_V_ERR_CERT_SIGNATURE_FAILURE:
	case X509_V_ERR_CRL_SIGNATURE_FAILURE:
		al=SSL_AD_DECRYPT_ERROR;
		break;
	case X509_V_ERR_CERT_HAS_EXPIRED:
	case X509_V_ERR_CRL_HAS_EXPIRED:
		al=SSL_AD_CERTIFICATE_EXPIRED;
		break;
	case X509_V_ERR_CERT_REVOKED:
		al=SSL_AD_CERTIFICATE_REVOKED;
		break;
	case X509_V_ERR_OUT_OF_MEM:
		al=SSL_AD_INTERNAL_ERROR;
		break;
	case X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT:
	case X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN:
	case X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY:
	case X509_V_ERR_UNABLE_TO_VERIFY_LEAF_SIGNATURE:
	case X509_V_ERR_CERT_CHAIN_TOO_LONG:
	case X509_V_ERR_PATH_LENGTH_EXCEEDED:
	case X509_V_ERR_INVALID_CA:
		al=SSL_AD_UNKNOWN_CA;
		break;
	case X509_V_ERR_APPLICATION_VERIFICATION:
		al=SSL_AD_HANDSHAKE_FAILURE;
		break;
	case X509_V_ERR_INVALID_PURPOSE:
		al=SSL_AD_UNSUPPORTED_CERTIFICATE;
		break;
	default:
		al=SSL_AD_CERTIFICATE_UNKNOWN;
		break;
		}
	return(al);
	}

int ssl3_setup_buffers(SSL *s)
	{
	unsigned char *p;
	unsigned int extra;
	size_t len;

	if (s->s3->rbuf.buf == NULL)
		{
		if (s->options & SSL_OP_MICROSOFT_BIG_SSLV3_BUFFER)
			extra=SSL3_RT_MAX_EXTRA;
		else
			extra=0;
		len = SSL3_RT_MAX_PACKET_SIZE + extra;
#ifdef CAVIUM_SSL

#if !defined  (CAVIUM_NO_MMAP) && !defined (CAVIUM_FIPS)
        p = (unsigned char *)mmap(NULL, (5*4096), PROT_READ|PROT_WRITE,
                        MAP_SHARED , CSP1_driver_handle, 0);
        if((unsigned long)p == -1)
        {
            goto err;
        }
        s->s3->o_rbuf_buf=p;
        s->s3->rbuf.buf=p+3;
        s->s3->rbuf.buf[0]=1;
        cav_fprintf(cav_nb_fp, "ssl3_setup_buffers(): %s %p\n",
                             "mmap'ed s->s3->o_rbuf_buf = ", s->s3->o_rbuf_buf);
#else
        if ((p=OPENSSL_malloc(len)) == NULL)
            goto err;
        s->s3->rbuf.buf = p;
#endif  // end ifndef CAVIUM_NOMMAP

#else
		if ((p=OPENSSL_malloc(len)) == NULL)
			goto err;
		s->s3->rbuf.buf = p;
#endif
		s->s3->rbuf.len = len;
		}

	if (s->s3->wbuf.buf == NULL)
		{
		len = SSL3_RT_MAX_PACKET_SIZE;
		len += SSL3_RT_HEADER_LENGTH + 256; /* extra space for empty fragment */
#ifdef CAVIUM_SSL

#if !defined  (CAVIUM_NO_MMAP) && !defined (CAVIUM_FIPS)
        p = (unsigned char *)mmap(NULL, (5*4096), PROT_READ|PROT_WRITE,
                MAP_SHARED  , CSP1_driver_handle, 0);
        if((unsigned long)p == -1)
        {
            goto err;
        }
        s->s3->o_wbuf_buf=p;
        s->s3->wbuf.buf=p+3;
        s->s3->wbuf.buf[0]=1;
        cav_fprintf(cav_nb_fp, "ssl3_setup_buffers(): %s %p\n",
                             "mmap'ed s->s3->o_wbuf_buf = ", s->s3->o_wbuf_buf);
#else
        if ((p=OPENSSL_malloc(len)) == NULL)
            goto err;
        s->s3->wbuf.buf = p;
#endif  // end ifndef CAVIUM_NOMMAP

#else
		if ((p=OPENSSL_malloc(len)) == NULL)
			goto err;
		s->s3->wbuf.buf = p;
#endif
		s->s3->wbuf.len = len;
		}
	s->packet= &(s->s3->rbuf.buf[0]);
#ifdef CAVIUM_SSL

    /* If CAVEO-SSL is defined then allocate hs_msgs buffer and initialize 
       offsets. It is initialzed to CH_SR_MSGS_LEN, defined in ssl.h but at 
       run-time reallocates more memory if required */

    if(s->in_handshake && s->hs_msgs == NULL)
    {
        if ((s->hs_msgs = OPENSSL_malloc(CH_SR_MSGS_LEN)) == NULL)
            goto err;
        s->hs_msgs_len = 0;
        s->hs_msgs_total_len = CH_SR_MSGS_LEN;
        /*
         ** Renegotiation fix
         **/
        cav_fprintf(cav_nb_fp,
               "ssl3_setup_buffers(): s->cav_renego is :  %d\n", s->cav_renego);

        if ( s->cav_renego == 0 ) {
            cav_fprintf(cav_nb_fp,
            "ssl3_setup_buffers(): s->cav_renego is 0\n");
            s->read_cipher_active=0;
            s->write_cipher_active=0;
            s->cipher_support = 0;
            s->handshake_support = 0;
            s->record_process = 0;
        }
        else {
            cav_fprintf(cav_nb_fp,
                    "ssl3_setup_buffers(): s->cav_renego is 1\n");
        }

        /* Following two buffers are only used in session resumption */
        /*These are not rellocated as finish messages are always 40 bytes in size.
        MD5 digest : 16 B
        SHA1 digest: 20 B
        header     :  4 B
        */

    }
#endif
	return(1);
err:
	SSLerr(SSL_F_SSL3_SETUP_BUFFERS,ERR_R_MALLOC_FAILURE);
	return(0);
	}
