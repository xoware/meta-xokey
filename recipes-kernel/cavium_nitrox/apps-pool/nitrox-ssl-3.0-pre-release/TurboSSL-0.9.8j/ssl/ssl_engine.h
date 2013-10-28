/* ssl_engine.h */
/*
 * Copyright (c) 2003-2005, Cavium Networks. All rights reserved.
 *
 * This Software is the property of Cavium Networks. The Software and all
 * accompanying documentation are copyrighted. The Software made available
 * here constitutes the proprietary information of Cavium Networks. You agree
 * to take reasonable steps to prevent the disclosure, unauthorized use or
 * unauthorized distribution of the Software. You shall use this Software
 * solely with Cavium hardware.
 *
 * Except as expressly permitted in a separate Software License Agreement
 * between You and Cavium Networks, You shall not modify, decompile,
 * disassemble, extract, or otherwise reverse engineer this Software. You
 * shall not make any copy of the Software or its accompanying documentation,
 * except for copying incident to the ordinary and intended use of the
 * Software and the Underlying Program and except for the making of a single
 * archival copy.
 *
 * This Software, including technical data, may be subject to U.S. export
 * control laws, including the U.S. Export Administration Act and its
 * associated regulations, and may be subject to export or import regulations
 * in other countries. You warrant that You will comply strictly in all
 * respects with all such regulations and acknowledge that you have the
 * responsibility to obtain licenses to export, re-export or import the
 * Software.
 *
 * TO THE MAXIMUM EXTENT PERMITTED BY LAW, THE SOFTWARE IS PROVIDED "AS IS"
 * AND WITH ALL FAULTS AND CAVIUM MAKES NO PROMISES, REPRESENTATIONS OR
 * WARRANTIES, EITHER EXPRESS, IMPLIED, STATUTORY, OR OTHERWISE, WITH RESPECT
 * TO THE SOFTWARE, INCLUDING ITS CONDITION, ITS CONFORMITY TO ANY
 * REPRESENTATION OR DESCRIPTION, OR THE EXISTENCE OF ANY LATENT OR PATENT
 * DEFECTS, AND CAVIUM SPECIFICALLY DISCLAIMS ALL IMPLIED (IF ANY) WARRANTIES
 * OF TITLE, MERCHANTABILITY, NONINFRINGEMENT, FITNESS FOR A PARTICULAR
 * PURPOSE, LACK OF VIRUSES, ACCURACY OR COMPLETENESS, QUIET ENJOYMENT, QUIET
 * POSSESSION OR CORRESPONDENCE TO DESCRIPTION. THE ENTIRE RISK ARISING OUT
 * OF USE OR PERFORMANCE OF THE SOFTWARE LIES WITH YOU.
 *
 */
/*
 *	Author	:	Imran Badr
 			Cavium Networks
 *	
 */


#ifndef __SSL_ENGINE_H_
#define __SSL_ENGINE_H_

#ifndef CAVIUM_BROWSER_ISSUE
#define CAVIUM_BROWSER_ISSUE
#endif

#ifndef CAVIUM_NB_CRYPTO
#define CAVIUM_NB_CRYPTO
#endif

#ifndef CAVIUM_CRT_MOD_EX
#define CAVIUM_CRT_MOD_EX
#endif

#define PKP_RANDOM_BUFFER_SIZE		128

/* Context Data structure in NLite
 * 
 * Refer NITROX 1000 SSL Instruction Set Manual
 * 2.6 RSA Server Key Exchange Instructions
 *   
 *  offset        
 *    0      Handshake Hash Context
 *    16     Master Secret
 *    22     cryptographic context (RC4/AES/DES)-(MD5/SHA)
 *    
 *    RC4 --- OPAD, IPAD, SequenceNumber, State
 *    DES --- OPAD, IPAD, sequenceNUmber, IV, DES key
 *    AES --- OPAD, IPAD, sequenceNumber, IV, AES key
 * 
 * */

#define MAX_CRYPTO_CTX_SIZE 640       // RC4--640 bytes , DES--192 bytes, AES---256 bytes
#define CRYPTO_OFFSET_IN_CTX 22*8


int check_dec_peer_completion(
                SSL *s,
		int *ip,
                int *lenp,
                int *md_sizep,
                int *finish_sizep,
		int *is_blockp,
		unsigned short *peer_lenp,
                char *dec_peer_client_finishedp);

AesType get_Aes_type(unsigned long id);
void pkp_init(void);
#ifdef CAVIUM_MULTICARD_API
int store_pkey(EVP_PKEY *pkey, Uint64 *key_handle,Uint32 dev_id);
#else
int store_pkey(EVP_PKEY *pkey, Uint64 *key_handle);
#endif
int pkp_get_random(char *out, int len, SSL *s);
int pkp_encrypt_record(SSL *s);
int pkp_decrypt_record(SSL *s);
int pkp_handshake(SSL *s);
int pkp_resume_handshake(SSL *s);
int pkp_handshake_client_auth(SSL *s);
int pkp_ephemeral_handshake(SSL *s);

int pkp_cert_verify_mac(SSL *s);

/* walks down the list of suported ciphers and returns 1 on success and 0 on failure */
int find_cipher(SSL *s, unsigned long cipher_id);

/* initializes the supported cipher list */
int init_supported_cipher_list(SSL *s);

extern void pkp_leftfill(unsigned char input[], int length, unsigned char output[], int finallength );

Rc4Type get_Rc4_type(unsigned long id);
DesType get_Des_type(unsigned long id);


int pkp_handshake_20(SSL *s);
int pkp_resume_handshake_20(SSL *s);
int pkp_handshake_client_auth_20(SSL *s);
int pkp_encrypt_record_20(SSL *s);
int pkp_decrypt_record_20(SSL *s);
int pkp_client_handshake(SSL *s);
int pkp_client_resume_handshake(SSL *s);
//int pkp_client_cert_verify_mac(unsigned char *mac, SSL *s);
int pkp_client_cert_verify_mac(SSL *s);
int pkp_client_handshake_client_auth(SSL *s);

extern int check_pre_master_completion (SSL *s,
#ifdef MC2
					 Uint16 *out_len,
#else
					 Uint64 *out_len,
#endif
					 char *result);

#endif

// For Handshake offloading

int pkp_read_ssl_session_context(SSL *);
int pkp_write_updated_ssl_session_context(SSL *); // Renegotiation

// For Record Process offloading

int pkp_write_ssl_session_context(SSL *s);
int pkp_read_updated_ssl_session_context(SSL *s); // Renegotiation


