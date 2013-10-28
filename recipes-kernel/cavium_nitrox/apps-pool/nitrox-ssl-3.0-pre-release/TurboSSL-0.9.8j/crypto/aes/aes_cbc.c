/* crypto/aes/aes_cbc.c -*- mode:C; c-file-style: "eay" -*- */
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
 */

#ifndef AES_DEBUG
# ifndef NDEBUG
#  define NDEBUG
# endif
#endif
#include <assert.h>

#include <openssl/aes.h>
#include "aes_locl.h"
#ifdef CAVIUM_SSL
#ifdef CAVIUM_FIPS
#include "luna_common.h"
#include "luna_ssl.h"
#include "luna_api.h"
#else
#include "cavium_common.h"
#include "cavium_ssl.h"
#endif
#endif

#ifdef CAVIUM_SSL
static int pkp_device_state=1;
#endif

#if !defined(OPENSSL_FIPS_AES_ASM)
void AES_cbc_encrypt(const unsigned char *in, unsigned char *out,
		     const unsigned long length, const AES_KEY *key,
		     unsigned char *ivec, const int enc) 
{
#ifdef CAVIUM_SSL
#ifndef CAVIUM_FIPS
#ifdef MC2
	       unsigned long n;
	       unsigned long len = length;
	       unsigned char tmp[AES_BLOCK_SIZE];
#endif	
#endif	
		int driver_ready =-1;
#ifndef MC2
		Uint64 tmp_ctx;
#endif
#ifdef CAVIUM_FIPS
		Uint64 hWrapper;
		Uint64 hkey_handle;
		Uint8 enc_key_out[50];
		Uint8 local_iv[8]={0x67, 0xC6, 0x69, 0x73, 0x51, 0xFF, 0x4A, 0xEC };
		int i;
#endif
//#if !defined(MC2) || (defined(MC2) && defined(CNLITE)) 
#if !defined(MC2) || (defined(MC2))  
		Uint32 req_id;
		unsigned char *iv;
		unsigned char aes_key[50];
		AesType aes_type=0;
		int bs=16;
		unsigned char *iiv;
		unsigned char saved_iv[24];
		int ret;
		memcpy(aes_key,(Uint8*)key->key,key->bytes);
		iv=ivec;
		if(key->bytes == 16)
			aes_type = AES_128;
		if(key->bytes == 24)
			aes_type = AES_192;
		if(key->bytes == 32)
			aes_type = AES_256;
#endif


		if(enc){
			ret = Csp1EncryptAes( CAVIUM_BLOCKING,
						0, //(Uint64)NULL,
						CAVIUM_NO_UPDATE,
						aes_type,
						length,
						(Uint8 *)in,
						(Uint8 *)out,
						(Uint8 *)iv,
						(Uint8 *)aes_key,
#ifdef CAVIUM_MULTICARD_API
						&req_id,CAVIUM_DEV_ID
#else
						&req_id
#endif
                                             );
			iiv=(Uint8 *) ((Uint8 *)out+length-bs);
		}else
		{
			iiv= (Uint8 *)((Uint8 *)in+length-bs);
			memcpy(saved_iv,iiv,bs);
			ret = Csp1DecryptAes( CAVIUM_BLOCKING,
						0, //(Uint64)NULL,
						CAVIUM_NO_UPDATE,
						aes_type,
						length,
						(Uint8 *)in,
						(Uint8 *)out,
						(Uint8 *)iv,
						(Uint8 *)aes_key,
#ifdef CAVIUM_MULTICARD_API
						&req_id,CAVIUM_DEV_ID
#else
						&req_id
#endif
                                             );
			iiv = saved_iv;
		}
		iv = ivec;
		memcpy(iv,iiv,bs);

        return;
#endif /*CAVIUM_SSL*/
   {

	unsigned long n;
	unsigned long len = length;
	unsigned char tmp[AES_BLOCK_SIZE];
	const unsigned char *iv = ivec;

	assert(in && out && key && ivec);
	assert((AES_ENCRYPT == enc)||(AES_DECRYPT == enc));

	if (AES_ENCRYPT == enc) {
		while (len >= AES_BLOCK_SIZE) {
			for(n=0; n < AES_BLOCK_SIZE; ++n)
				out[n] = in[n] ^ iv[n];
			AES_encrypt(out, out, key);
			iv = out;
			len -= AES_BLOCK_SIZE;
			in += AES_BLOCK_SIZE;
			out += AES_BLOCK_SIZE;
		}
		if (len) {
			for(n=0; n < len; ++n)
				out[n] = in[n] ^ iv[n];
			for(n=len; n < AES_BLOCK_SIZE; ++n)
				out[n] = iv[n];
			AES_encrypt(out, out, key);
			iv = out;
		}
		memcpy(ivec,iv,AES_BLOCK_SIZE);
	} else if (in != out) {
		while (len >= AES_BLOCK_SIZE) {
			AES_decrypt(in, out, key);
			for(n=0; n < AES_BLOCK_SIZE; ++n)
				out[n] ^= iv[n];
			iv = in;
			len -= AES_BLOCK_SIZE;
			in  += AES_BLOCK_SIZE;
			out += AES_BLOCK_SIZE;
		}
		if (len) {
			AES_decrypt(in,tmp,key);
			for(n=0; n < len; ++n)
				out[n] = tmp[n] ^ iv[n];
			iv = in;
		}
		memcpy(ivec,iv,AES_BLOCK_SIZE);
	} else {
		while (len >= AES_BLOCK_SIZE) {
			memcpy(tmp, in, AES_BLOCK_SIZE);
			AES_decrypt(in, out, key);
			for(n=0; n < AES_BLOCK_SIZE; ++n)
				out[n] ^= ivec[n];
			memcpy(ivec, tmp, AES_BLOCK_SIZE);
			len -= AES_BLOCK_SIZE;
			in += AES_BLOCK_SIZE;
			out += AES_BLOCK_SIZE;
		}
		if (len) {
			memcpy(tmp, in, AES_BLOCK_SIZE);
			AES_decrypt(tmp, out, key);
			for(n=0; n < len; ++n)
				out[n] ^= ivec[n];
			for(n=len; n < AES_BLOCK_SIZE; ++n)
				out[n] = tmp[n];
			memcpy(ivec, tmp, AES_BLOCK_SIZE);
		}
	}
   } /*software aes*/
} /*end function*/
#endif
