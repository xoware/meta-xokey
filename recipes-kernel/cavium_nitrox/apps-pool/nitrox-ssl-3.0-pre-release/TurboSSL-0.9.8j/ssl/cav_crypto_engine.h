
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
#ifndef CAV_CRYPTO_ENGINE_H
#define CAV_CRYPTO_ENGINE_H

#include <openssl/bn.h>
#include <openssl/rsa.h>
#ifdef CAVIUM_FIPS

int cav_mod_exp(BIGNUM *r, BIGNUM *a, BIGNUM *p, BIGNUM *m);
int pkp_rsa_public_decrypt(int flen, unsigned char *from, unsigned char *to, RSA * rsa, int is_key_handle);
int pkp_rsa_private_decrypt(int flen, unsigned char *from, unsigned char *to, RSA * rsa, int is_key_handle);
int pkp_rsa_public_encrypt(int flen, unsigned char *from, unsigned char *to, RSA * rsa, int is_key_handle);
int pkp_rsa_private_encrypt(int flen, unsigned char *from, unsigned char *to, RSA * rsa, int is_key_handle);

int add_pkcs5_padding(unsigned char* key, unsigned long *size);
int fips_import_private_key(RSA* rsa, unsigned long long *key_handle);
int fips_import_public_key(RSA* rsa, unsigned long long *key_handle);
# else
int cav_mod_exp(BIGNUM *r, BIGNUM *a, BIGNUM *p, BIGNUM *m);
int pkp_rsa_public_decrypt_cav(void *s,int flen, unsigned char *from, unsigned char *to, RSA * rsa);
int pkp_rsa_private_decrypt(int flen, unsigned char *from, unsigned char *to, RSA * rsa);
int pkp_rsa_public_decrypt(int flen, unsigned char *from, unsigned char *to, RSA * rsa);
int pkp_rsa_private_decrypt(int flen, unsigned char *from, unsigned char *to, RSA * rsa);
int pkp_rsa_private_decrypt_cav(void *s,int flen, unsigned char *from, unsigned char *to, RSA * rsa);
int pkp_rsa_public_encrypt(int flen, unsigned char *from, unsigned char *to, RSA * rsa);
int pkp_rsa_public_encrypt_cav(void *s,int flen, unsigned char *from, unsigned char *to, RSA * rsa);
int pkp_rsa_private_encrypt(int flen, unsigned char *from, unsigned char *to, RSA * rsa);
int pkp_rsa_private_encrypt_cav(void *s,int flen, unsigned char *from, unsigned char *to, RSA * rsa);
#endif

#endif
