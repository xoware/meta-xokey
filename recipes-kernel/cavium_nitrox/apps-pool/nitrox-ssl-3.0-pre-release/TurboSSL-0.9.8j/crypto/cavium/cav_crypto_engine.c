
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
#if defined(linux)
   #include <alloca.h>
   #include <malloc.h>
#elif defined(__FreeBSD__)
   #include <stdlib.h>
#endif

#include <netinet/in.h>
#include <string.h>
#include <openssl/md5.h>
#include <openssl/sha.h>
#include <openssl/ssl.h>
#include <openssl/bn.h>

#ifdef CAVIUM_FIPS
#include "luna_common.h"
#include "luna_ssl.h"
#include "luna_api.h"
#else
#include "cavium_common.h"
#include "cavium_ssl.h"
#include <openssl/cav_debug.h>
#endif /* CAVIUM_FIPS */

void pkp_leftfill(unsigned char input[], int length, unsigned char output[], int finallength )
{
  int i;
  int j;
  memset(output,0,finallength);
  j = finallength-1;
  for (i=length-1; i>=0; i--) 
  {
    output[j] = input[i];
    j = j-1;
  }
}

#ifndef MC2

static void swap_word_openssl(unsigned char *d, unsigned char *s, int len)
{
  int i,j;
  Uint64 *ps;
  Uint64 *pd;

  j=0;

  ps = (Uint64 *)s;
  pd = (Uint64 *)d;

  for(i=(len>>3)-1; i>=0; i--)
   {
     pd[j] = ps[i];
     j++;      
   }

}
#endif


#ifdef CAVIUM_FIPS

/*
 * Appends pkcs5 padding to a buffer (for 3DES in this case)
 */
int add_pkcs5_padding(unsigned char* key, unsigned long *size)
{
  int pad_len = 0x0;
  int i=0;

  if ((*size % 8) == 0x0) 
  {
      pad_len = 0x8;
  }
  else
  {
      pad_len = (((*size/8)+1)*8) - *size;
  }

  for (i=0; i<pad_len; i++) key[*size+i] = pad_len;

  *size += pad_len;

  return (0);
}



/*
 * imports private key
 *
 * returns 0 on success, else failure
 *
 * returned error codes:
 *
 *   1 - not enough memory
 *   2 - rsa to pkey conversion failed
 *   3 - pkey to pkcs8 inf conversion failed
 *   4 - pkcs8 inf to pkcs8 conversion failed
 *   5 - invalid pkcs8 converted blob size
 *   6 - generate symmetric key failed
 *   7 - alloc context failed
 *   8 - init 3DES failed
 *   9 - encrypt 3DES failed
 *  10 - import private key failed
 */
int fips_import_private_key(RSA* rsa, unsigned long long *key_handle)
{
   int ret = 0;
   EVP_PKEY *pkey = NULL;
   PKCS8_PRIV_KEY_INFO *p8inf=NULL;
   int p8_broken = PKCS8_OK;
   BIO *pkcs8_bio = NULL;
   char* ptr = NULL;
   char* lcl_key = NULL;
   char* lcl_key_enc = NULL;
   unsigned long pkcs8_size = 0;
   Uint64 h3DesKey = 0;
   Uint64 context_handle = 0;
   Uint8 iv[8] = "12345678";


   /* do all the initializations */
   pkey = EVP_PKEY_new();
   if (pkey == NULL)
   {
       ret = 1;
       goto end_import_prv_key;
   }

   pkcs8_bio = BIO_new(BIO_s_mem());
   if (pkcs8_bio == NULL)
   {
       ret = 1;
       goto end_import_prv_key;
   }


   /* step 1 : convert rsa key to PKEY */
   ret = EVP_PKEY_set1_RSA(pkey, rsa);
   if (!ret)
   {
       ret = 2;
       goto end_import_prv_key;
   }

   /* step 2 : convert pkey to pkcs8 inf format */
   if (!(p8inf = EVP_PKEY2PKCS8_broken(pkey, p8_broken))) 
   {
       ret = 3;
       goto end_import_prv_key;
   }

   /* step 3 : convert the pkcs8 inf to pkcs8 format */
   ret = i2d_PKCS8_PRIV_KEY_INFO_bio(pkcs8_bio, p8inf);
   if (!ret)
   {
       ret = 4;
       goto end_import_prv_key;
   }

   /* step 4 : get the size and ptr of the converted key */
   pkcs8_size = BIO_get_mem_data(pkcs8_bio, &ptr);
   if (pkcs8_size == 0)
   {
       ret = 5;
       goto end_import_prv_key;
   }

   /* step 5 : copy the key to a local buffer, and add pkcs5 padding */
   lcl_key = (char*)malloc(pkcs8_size+32);
   lcl_key_enc = (char*)malloc(pkcs8_size+32);
   if ((lcl_key == NULL) || (lcl_key_enc == NULL))
   {
       ret = 1;
       goto end_import_prv_key;
   }

   memcpy(lcl_key, ptr, pkcs8_size);
   add_pkcs5_padding((unsigned char *)lcl_key, &pkcs8_size);


  /* step 6 : generate a symmetric key (3DES) and init the 3DES engine */
  ret = Cfm1GenerateSymmetricKey(LUNA_KEY_DES3, 24, (Uint8 *)"3DES", 4, &h3DesKey);
  if(ret)
  {
      ret = 6;
      goto end_import_prv_key;
  }

  ret = Cfm1AllocContext(OP_BLOCKING, &context_handle, NULL);
  if(ret)
  {
      ret = 7;
      goto end_import_prv_key;
  }

  ret = Cfm1Initialize3DES(OP_BLOCKING, context_handle, iv, &h3DesKey, NULL);
  if(ret)
  {
      ret = 8;
      goto end_import_prv_key;
  }

  /* step 7 : encrypt the pkcs8 encoded key */
  memset(lcl_key_enc, 0x0, sizeof(lcl_key_enc));

  ret = Cfm1Encrypt3Des(OP_BLOCKING, context_handle, NO_UPDATE, pkcs8_size, (Uint8 *)lcl_key, (Uint8 *)lcl_key_enc, NULL);
  if (ret)
  {
      ret = 9;
      goto end_import_prv_key;
  }


  /* step 8 : import the encrypted key */
  ret = Cfm1ImportRSAPrivateKey(h3DesKey, (Uint8 *)lcl_key_enc, pkcs8_size,(Uint8 *) "PRV_KEY_IMPORT", 14, iv, key_handle);
  if (ret)
  {
      ret = 10;
      goto end_import_prv_key;
  }

  ret = 0;

end_import_prv_key:

   if (pkey)            EVP_PKEY_free(pkey);
   if (pkcs8_bio)       BIO_free_all(pkcs8_bio);
   if (p8inf)	        PKCS8_PRIV_KEY_INFO_free (p8inf);
   if (lcl_key)         free(lcl_key);
   if (lcl_key_enc)     free(lcl_key_enc);
   if (context_handle)  Cfm1FreeContext(OP_BLOCKING, context_handle, NULL);
   if (h3DesKey)        Cfm1DeleteKey(h3DesKey);

   return (ret);
}


/*
 * imports public key
 *
 * returns 0 on success, 1 on failure
 */
int fips_import_public_key(RSA* rsa, unsigned long long *key_handle)
{
   Uint8 *modulus = NULL, *exponent = NULL;
   Uint32 modulus_size = 0, exp_size = 0;
   Uint32 pub_exponent = 0;
   int ret = 1, size = 0;
   Uint8* ptr = (Uint8*)&pub_exponent;

   modulus_size = BN_num_bytes(rsa->n);
   exp_size = BN_num_bytes(rsa->e);

   if((modulus_size&0x7)!=0)
   {
       goto end_import_pub_key;
   }

   if (exp_size > (sizeof(Uint32)))
   {
       goto end_import_pub_key;
   }

   modulus = (Uint8*)malloc(modulus_size);
   exponent = (Uint8*)malloc(sizeof(Uint32));
   if (modulus == NULL)
   {
       goto end_import_pub_key;
   }

   memset(modulus, 0, modulus_size);
   memset(exponent, 0, sizeof(Uint32));

   BN_bn2bin(rsa->n, modulus);
   size = BN_bn2bin(rsa->e, exponent);
   memmove(ptr + ((sizeof(Uint32)) - size), exponent, size);

   pub_exponent = htobe32(pub_exponent);

   ret = Cfm1CreateRSAPublicKey(modulus, modulus_size, pub_exponent, (Uint8 *)"PUB_KEY_IMPORT", 14, key_handle);
   if (ret)
   {
       goto end_import_pub_key;
   }

   ret = 0;

end_import_pub_key:

   if (modulus)   free(modulus);
   if (exponent)  free(exponent);

   return (ret);
}







#ifdef CAVIUM_MODEX_DEBUG
#include <stdio.h>
#endif

int cav_mod_exp(BIGNUM *r, BIGNUM *a, BIGNUM *p, BIGNUM *m)
{

  /* for fips mode, the control should never get here */
  printf("cav_mod_exp : mod exp can only be done using a key handle imported earlier\n");
  return (1);

}


/*
 * is_key_handle flag is set only in FIPS mode calls when the key handle is passed
 *
 * note : when the is_key_handle flag is set in fips mode, the RSA* is actually an
 *        SSL* which includes the key handle and its size, so type casting is
 *        is required to access the SSL* data structure
 */
int pkp_rsa_public_decrypt(int flen, unsigned char *from, unsigned char *to, RSA * rsa, int is_key_handle)
{

	int i,ret=0;
        Uint64 dummy_context_pointer = 0;
	int modulus_size;
	Uint32 req_id;
        unsigned char *from_b=NULL, *temp=NULL;
	Uint64 out_length=0;

        Uint64 key_handle = 0;

	if (is_key_handle)
	{
            SSL *s = (SSL*)rsa;
            modulus_size = s->ctx->pkey_info.size;
            key_handle = s->key_handle;
	}
	else
	{
            ret = fips_import_public_key(rsa, &key_handle);
	    if (ret) return(0);

	    modulus_size  = BN_num_bytes(rsa->n);
	}

    //    if(((modulus_size&0x7)!=0)||(modulus_size<24)||(modulus_size>256))
	if(((modulus_size&0x7)!=0)||(modulus_size<24)||(modulus_size>512))
	{
	    if (!is_key_handle) Cfm1DeleteKey(key_handle);
	    return(0);
	}

	from_b = alloca(modulus_size);
	if(from_b==NULL) 
	{
	    if (!is_key_handle) Cfm1DeleteKey(key_handle);
            return(0);
	}

	temp = alloca(modulus_size);
	if(temp==NULL)
	{
	    if (!is_key_handle) Cfm1DeleteKey(key_handle);
            return(0);
	}

        swap_word_openssl(temp, from, modulus_size);
        memcpy(from_b, temp, modulus_size);


        i = Cfm1Pkcs1v15Dec(OP_BLOCKING, 
                            RESULT_PTR,
                            dummy_context_pointer, 
                            &key_handle, 
                            BT1,
		            (unsigned short)modulus_size,
                            from_b,
		            to,
                            &out_length,
		            &req_id);

	if(i) ret=0;
	else  ret = (Uint32)out_length;

        if (!is_key_handle) Cfm1DeleteKey(key_handle);

	return (ret);

}



/*
 * is_key_handle flag is set only in FIPS mode calls when the key handle is passed
 *
 * note : when the is_key_handle flag is set in fips mode, the RSA* is actually an
 *        SSL* which includes the key handle and its size, so type casting is
 *        is required to access the SSL* data structure
 */
int pkp_rsa_private_decrypt(int flen, unsigned char *from, unsigned char *to, RSA * rsa, int is_key_handle)
{

	int i,ret=0;
        Uint64 dummy_context_pointer = 0;
	int modulus_size;
	Uint32 req_id;
        unsigned char *from_b=NULL, *temp=NULL;
	Uint64 out_length=0;

        Uint64 key_handle = 0;

	if (is_key_handle)
	{
            SSL *s = (SSL*)rsa;
            modulus_size = s->ctx->pkey_info.size;
            key_handle = s->key_handle;
	}
	else
	{
            ret = fips_import_private_key(rsa, &key_handle);
	    if (ret) return(0);

	    modulus_size  = BN_num_bytes(rsa->n);
	}

    //    if(((modulus_size&0x7)!=0)||(modulus_size<24)||(modulus_size>256))
	if(((modulus_size&0x7)!=0)||(modulus_size<24)||(modulus_size>512))
	{
	    if (!is_key_handle) Cfm1DeleteKey(key_handle);
	    return(0);
	}

	from_b = alloca(modulus_size);
	if(from_b==NULL) 
	{
	    if (!is_key_handle) Cfm1DeleteKey(key_handle);
            return(0);
	}

	temp = alloca(modulus_size);
	if(temp==NULL)
	{
	    if (!is_key_handle) Cfm1DeleteKey(key_handle);
            return(0);
	}

        swap_word_openssl(temp, from, modulus_size);
        memcpy(from_b, temp, modulus_size);


        i = Cfm1Pkcs1v15Dec(OP_BLOCKING, 
                            RESULT_PTR,
                            dummy_context_pointer, 
                            &key_handle, 
                            BT2,
		            (unsigned short)modulus_size,
                            from_b,
		            to,
                            &out_length,
		            &req_id);

	if(i) ret=0;
	else  ret = (Uint32)out_length;

        if (!is_key_handle) Cfm1DeleteKey(key_handle);

	return (ret);

}




/*
 * is_key_handle flag is set only in FIPS mode calls when the key handle is passed
 *
 * note : when the is_key_handle flag is set in fips mode, the RSA* is actually an
 *        SSL* which includes the key handle and its size, so type casting is
 *        is required to access the SSL* data structure
 */
int pkp_rsa_public_encrypt(int flen, unsigned char *from, unsigned char *to, RSA * rsa, int is_key_handle)
{

	int i,ret=0;
        Uint64 dummy_context_pointer = 0;
	int modulus_size;
	Uint32 req_id;

        Uint64 key_handle = 0;

	if (is_key_handle)
	{
            SSL *s = (SSL*)rsa;
            modulus_size = s->ctx->pkey_info.size;
            key_handle = s->key_handle;
	}
	else
	{
            ret = fips_import_public_key(rsa, &key_handle);
	    if (ret) return(0);

	    modulus_size  = BN_num_bytes(rsa->n);
	}

    //    if(((modulus_size&0x7)!=0)||(modulus_size<24)||(modulus_size>256))
	if(((modulus_size&0x7)!=0)||(modulus_size<24)||(modulus_size>512))
	{
	    if (!is_key_handle) Cfm1DeleteKey(key_handle);
	    return(0);
	}


        i = Cfm1Pkcs1v15Enc(OP_BLOCKING, 
                            RESULT_PTR,
                            dummy_context_pointer, 
                            &key_handle, 
                            BT2,
		            modulus_size,
                            flen, 
                            from,
		            to,
		            &req_id);

        if(i) ret=0;
	else ret = modulus_size;

        if (!is_key_handle) Cfm1DeleteKey(key_handle);

	return (ret);

}


/*
 * is_key_handle flag is set only in FIPS mode calls when the key handle is passed
 *
 * note : when the is_key_handle flag is set in fips mode, the RSA* is actually an
 *        SSL* which includes the key handle and its size, so type casting is
 *        is required to access the SSL* data structure
 */
int pkp_rsa_private_encrypt(int flen, unsigned char *from, unsigned char *to, RSA * rsa, int is_key_handle)
{

	int i,ret=0;
        Uint64 dummy_context_pointer = 0;
	int modulus_size;
	Uint32 req_id;
        Uint64 key_handle = 0;

	if (is_key_handle)
	{
            SSL *s = (SSL*)rsa;
            modulus_size = s->ctx->pkey_info.size;
            key_handle = s->key_handle;
	}
	else
	{
            ret = fips_import_private_key(rsa, &key_handle);
	    if (ret) return(0);

	    modulus_size  = BN_num_bytes(rsa->n);
	}

    //    if(((modulus_size&0x7)!=0)||(modulus_size<24)||(modulus_size>256))
	if(((modulus_size&0x7)!=0)||(modulus_size<24)||(modulus_size>512))
	{
	    if (!is_key_handle) Cfm1DeleteKey(key_handle);
	    return(0);
	}


        i = Cfm1Pkcs1v15Enc(OP_BLOCKING, 
                            RESULT_PTR,
                            dummy_context_pointer, 
                            &key_handle, 
                            BT1,
		            modulus_size,
                            flen, 
                            from,
		            to,
		            &req_id);

        if(i) ret=0;
	else ret = modulus_size;

        if (!is_key_handle) Cfm1DeleteKey(key_handle);

	return (ret);

}
#else 


int check_crypto_completion (SSL *s,
#ifdef MC2
				 Uint16 *ret
#else
				 Uint64 *ret
#endif
				 ) ;


#ifdef CAVIUM_MODEX_DEBUG
#include <stdio.h>
#endif

#ifdef MC2
int cav_mod_exp(BIGNUM *r, BIGNUM *a, BIGNUM *p, BIGNUM *m)
{
  unsigned char *ab, *pb, *mb, *rb;
  int sizep,sizem,sizea;
  int driver_ready=-1;
  int ret = 0;
  Uint32 req_id;


  sizem = BN_num_bytes(m);
  if( (sizem < 24) || (sizem>256) ) return 0;

#ifdef CAVIUM_MULTICARD_API
  driver_ready = Csp1GetDriverState(CAVIUM_DEV_ID);
#else
  driver_ready = Csp1GetDriverState();
#endif
  if(driver_ready == -1)
  {

#ifdef CAVIUM_MULTICARD_API
	  if(Csp1Initialize(CAVIUM_DIRECT,CAVIUM_DEV_ID))
#else
	  if(Csp1Initialize(CAVIUM_DIRECT))
#endif
		  return 0;
  }

  sizea = BN_num_bytes(a);
  sizep = BN_num_bytes(p);

  mb = alloca(sizem);
  if(mb==NULL)
  {
	  ret= 0;
	  goto mod_exp_cleanup;
  }
  memset(mb,0,sizem);

  ab = alloca(sizea);
  if(ab==NULL)
  {
	  ret= 0;
	  goto mod_exp_cleanup;
  }
  memset(ab,0,sizea);

  pb = alloca(sizep);
  if(pb==NULL)
  {
	  ret= 0;
	  goto mod_exp_cleanup;
  }
  memset(pb,0,sizep);   

  rb = alloca(sizem); 
  if(rb==NULL)
  {
	  ret= 0;
	  goto mod_exp_cleanup;
  }
  memset(rb,0,sizem);

  BN_bn2bin(a,ab); 

  BN_bn2bin(p,pb); 

  BN_bn2bin(m,mb); 

#ifdef CAVIUM_MULTICARD_API
  if (Csp1Me(CAVIUM_BLOCKING,sizem, sizep, sizea, mb, pb,ab, rb, &req_id,CAVIUM_DEV_ID))
#else
  if (Csp1Me(CAVIUM_BLOCKING,sizem, sizep, sizea, mb, pb,ab, rb, &req_id))
#endif
   {
	  ret= 0;
	  goto mod_exp_cleanup;
   }
  

  BN_bin2bn(rb,sizem,r); 
  ret = 1;

mod_exp_cleanup:
  if(driver_ready == -1)
#ifdef CAVIUM_MULTICARD_API
	  Csp1Shutdown(CAVIUM_DEV_ID);
#else
	  Csp1Shutdown();
#endif
  return ret;

}

#ifdef CAVIUM_SSL
int pkp_rsa_public_decrypt_cav(void *s1,int flen, unsigned char *from, unsigned char *to, RSA * rsa)

{

	int i,ret=0;
	unsigned char *modulus_b=NULL, *exponent_b=NULL, *from_b=NULL;
	int modulus_size, exponent_size;
	Uint16 out_length=0;
	int driver_ready = -1;
	int rc;

	SSL *s = (SSL *)s1;
	
	if (s->cav_crypto_state == CAV_ST_IN_PRE_MASTER_KEY){
		
		rc = check_crypto_completion (s,
						  &out_length	
						  );	


		if (rc == 1) {
			memcpy (to, s->pre_master_result,flen);
			return out_length;
		}
		else if(rc == -EAGAIN) 
		  	return rc;
		else{
			return 0;
		}
	}
	
#ifdef CAVIUM_MULTICARD_API
	driver_ready = Csp1GetDriverState(CAVIUM_DEV_ID);
#else
	driver_ready = Csp1GetDriverState();
#endif
	if(driver_ready == -1)
	{
#ifdef CAVIUM_MULTICARD_API
          if(Csp1Initialize(CAVIUM_DIRECT,CAVIUM_DEV_ID))
#else
          if(Csp1Initialize(CAVIUM_DIRECT))
#endif
		  return 0;
	}

	modulus_size  = BN_num_bytes(rsa->n);
	//if((modulus_size<17)||(modulus_size>256))
	if((modulus_size<17)||(modulus_size>512))
		goto rsa_pub_dec_cleanup;

	exponent_size = BN_num_bytes(rsa->e);

	modulus_b = alloca(modulus_size);
	if(modulus_b==NULL)
	{
		ret=0;
		goto rsa_pub_dec_cleanup;
	}
	memset(modulus_b,0,modulus_size);

	exponent_b = alloca(exponent_size);
	if(exponent_b==NULL)
	{
		ret=0;
		goto rsa_pub_dec_cleanup;
	}
	memset(exponent_b,0,exponent_size);

	from_b = alloca(modulus_size);
	if(from_b==NULL)
	{
		ret=0;
		goto rsa_pub_dec_cleanup;
	}

	memcpy(from_b,from,modulus_size);
	BN_bn2bin(rsa->n,modulus_b); 
	BN_bn2bin(rsa->e,exponent_b);
	s->cryp_flen = flen;

	i = Csp1Pkcs1v15Dec(s->cav_nb_mode,
					BT1,
				(Uint16)modulus_size, 
				(Uint16)exponent_size,
	   			 modulus_b, 
			   	 exponent_b, 
				 from_b,
				&(s->pre_master_len),
				 s->pre_master_result,
#ifdef CAVIUM_MULTICARD_API
				 &(s->cav_req_id),s->dev_id
#else
				 &(s->cav_req_id)
#endif
                             );

	if ( i == EAGAIN)
	{
		cav_fprintf(cav_nb_fp,"rsa_public_decrypt(): %s\n",
                                        "Csp1Pkcs1v15De() EAGAIN");

                s->cav_crypto_state = CAV_ST_IN_PRE_MASTER_KEY;
                s->cav_saved_state = s->state;

		if (s->state == SSL3_ST_CR_KEY_EXCH_B)
			s->state = SSL3_ST_CR_KEY_EXCH_B ;
		else
                	s->state = CAV_ST_IN_PRE_MASTER_KEY;

                s->cav_req_id_check_done = 0;
                s->rwstate = SSL_NITROX_BUSY;
		return -EAGAIN;
	}
        if(i) {
		ret = 0;
		return ret;
	}
	else {
	 	ret = (Uint32)ntohs(s->pre_master_len); 
		memcpy (to, s->pre_master_result,flen);
	}

rsa_pub_dec_cleanup:
	if(driver_ready == -1)
#ifdef CAVIUM_MULTICARD_API
          Csp1Shutdown(CAVIUM_DEV_ID);
#else
          Csp1Shutdown();
#endif

  
	return ret;
}/*pkp_rsa_public_decrypt*/
#endif

int pkp_rsa_public_decrypt(int flen, unsigned char *from, unsigned char *to, RSA * rsa)
{
	int i,ret=0;
	unsigned char *modulus_b=NULL, *exponent_b=NULL, *from_b=NULL;
	int modulus_size, exponent_size;
	Uint16 out_length=0;
	Uint32 req_id;
	int driver_ready = -1;

#ifdef CAVIUM_MULTICARD_API
        driver_ready = Csp1GetDriverState(CAVIUM_DEV_ID);
#else
        driver_ready = Csp1GetDriverState();
#endif

	if(driver_ready == -1)
	{
#ifdef CAVIUM_MULTICARD_API
          if(Csp1Initialize(CAVIUM_DIRECT,CAVIUM_DEV_ID))
#else
          if(Csp1Initialize(CAVIUM_DIRECT))
#endif
		  return 0;
	}

	modulus_size  = BN_num_bytes(rsa->n);
	//if((modulus_size<17)||(modulus_size>256))
	if((modulus_size<17)||(modulus_size>512))
		goto rsa_pub_dec_cleanup;

	exponent_size = BN_num_bytes(rsa->e);

	modulus_b = alloca(modulus_size);
	if(modulus_b==NULL)
	{
		ret=0;
		goto rsa_pub_dec_cleanup;
	}
	memset(modulus_b,0,modulus_size);

	exponent_b = alloca(exponent_size);
	if(exponent_b==NULL)
	{
		ret=0;
		goto rsa_pub_dec_cleanup;
	}
	memset(exponent_b,0,exponent_size);

	from_b = alloca(modulus_size);
	if(from_b==NULL)
	{
		ret=0;
		goto rsa_pub_dec_cleanup;
	}

	memcpy(from_b,from,modulus_size);
	BN_bn2bin(rsa->n,modulus_b); 
	BN_bn2bin(rsa->e,exponent_b);
	
	i = Csp1Pkcs1v15Dec(CAVIUM_BLOCKING,
		BT1,
		(Uint16)modulus_size, 
		(Uint16)exponent_size,
	   	 modulus_b, 
	   	 exponent_b, 
		 from_b,
		&out_length,
		to,
#ifdef CAVIUM_MULTICARD_API
                &req_id,CAVIUM_DEV_ID
#else
                &req_id
#endif
                );


	if(i) ret=0;
	else ret = (Uint32)ntohs(out_length);

rsa_pub_dec_cleanup:
	if(driver_ready == -1)
#ifdef CAVIUM_MULTICARD_API
          Csp1Shutdown(CAVIUM_DEV_ID);
#else
          Csp1Shutdown();
#endif

  
	return ret;
}/*pkp_rsa_public_decrypt*/


int pkp_rsa_private_decrypt(int flen, unsigned char *from, unsigned char *to, RSA * rsa)
{

	int i,ret=0;
	unsigned char *modulus_b=NULL, *exponent_b=NULL, *from_b=NULL;
	int modulus_size, exponent_size;
	Uint16 out_length=0;
	int driver_ready = -1;
	Uint32 req_id;

#ifdef CAVIUM_MULTICARD_API
        driver_ready = Csp1GetDriverState(CAVIUM_DEV_ID);
#else
        driver_ready = Csp1GetDriverState();
#endif

	
	if(driver_ready == -1)
	{
#ifdef CAVIUM_MULTICARD_API
          if(Csp1Initialize(CAVIUM_DIRECT,CAVIUM_DEV_ID))
#else
          if(Csp1Initialize(CAVIUM_DIRECT))
#endif
		  return 0;
	}

	modulus_size  = BN_num_bytes(rsa->n);
	//if((modulus_size<17)||(modulus_size>256))
	if((modulus_size<17)||(modulus_size>512))
		goto rsa_priv_dec_cleanup;

	exponent_size = BN_num_bytes(rsa->d);

	modulus_b = alloca(modulus_size);
	if(modulus_b==NULL)
	{
		ret = 0;
		goto rsa_priv_dec_cleanup;
	}
	memset(modulus_b,0,modulus_size);

	exponent_b = alloca(exponent_size);
	if(exponent_b==NULL)
	{
		ret = 0;
		goto rsa_priv_dec_cleanup;
	}
	memset(exponent_b,0,exponent_size);

	from_b = alloca(modulus_size);
	if(from_b==NULL)
	{
		ret = 0;
		goto rsa_priv_dec_cleanup;
	}
	memcpy(from_b,from,modulus_size);

	BN_bn2bin(rsa->n,modulus_b); 
	BN_bn2bin(rsa->d,exponent_b);

   	i = Csp1Pkcs1v15Dec(CAVIUM_BLOCKING,
				BT2,
			    (Uint16)modulus_size, 
				(Uint16)exponent_size,
			    modulus_b, 
			    exponent_b, 
			    from_b,
				&out_length,
				to,
#ifdef CAVIUM_MULTICARD_API
                                 &req_id,CAVIUM_DEV_ID
#else
                                 &req_id
#endif
                             );


	if(i) ret=0;
	else ret = (Uint32)ntohs(out_length);

rsa_priv_dec_cleanup:
	if(driver_ready == -1)
#ifdef CAVIUM_MULTICARD_API
          Csp1Shutdown(CAVIUM_DEV_ID);
#else
          Csp1Shutdown();
#endif

  
	return ret;
}

#ifdef CAVIUM_SSL
int pkp_rsa_public_encrypt_cav(void *s1 , int flen, unsigned char *from, unsigned char *to, RSA * rsa)
{
	int i,ret=0;
	unsigned char *modulus_b=NULL, *exponent_b=NULL, *from_b=NULL;
	int modulus_size, exponent_size, data_size;
	int driver_ready = -1;
	Uint16 out_length=0;
	int rc ;

	SSL *s = (SSL *)s1;

	if (s->cav_crypto_state == CAV_ST_IN_PRE_MASTER_KEY){
		
		rc = check_crypto_completion (s,
						  &out_length	
						  );	

		if (rc == 1) {
	                modulus_size  = BN_num_bytes(rsa->n);
			memcpy (to, s->pre_master_result,modulus_size);
			return s->cryp_flen;
		}
		else if(rc == -EAGAIN) 
		  	return rc;
		else
			return 0;
	}

#ifdef CAVIUM_MULTICARD_API
        driver_ready = Csp1GetDriverState(CAVIUM_DEV_ID);
#else
        driver_ready = Csp1GetDriverState();
#endif

	if(driver_ready == -1)
	{
#ifdef CAVIUM_MULTICARD_API
          if(Csp1Initialize(CAVIUM_DIRECT,CAVIUM_DEV_ID))
#else
          if(Csp1Initialize(CAVIUM_DIRECT))
#endif
		  return 0;
	}

	modulus_size  = BN_num_bytes(rsa->n);
	//if((modulus_size<17)||(modulus_size>256))
	if((modulus_size<17)||(modulus_size>512))
		goto rsa_pub_enc_cleanup;

	exponent_size = BN_num_bytes(rsa->e);

	modulus_b = alloca(modulus_size);
	if(modulus_b==NULL)
	{
		ret = 0;
		goto rsa_pub_enc_cleanup;
	}
	memset(modulus_b,0,modulus_size);

	exponent_b = alloca(exponent_size);
	if(exponent_b==NULL)
	{
		ret = 0;
		goto rsa_pub_enc_cleanup;
	}
	memset(exponent_b,0,exponent_size);

	data_size = flen;

	from_b = alloca(data_size);
	if(from_b==NULL)
	{
		ret = 0;
		goto rsa_pub_enc_cleanup;
	}

	memcpy(from_b,from,data_size);
	BN_bn2bin(rsa->n,modulus_b); 
	BN_bn2bin(rsa->e,exponent_b);
	s->cryp_flen = modulus_size;

	i = Csp1Pkcs1v15Enc(s->cav_nb_mode,
				BT2,
				(Uint16)modulus_size, 
				(Uint16)exponent_size,
				(Uint16)data_size, 
	   			 modulus_b, 
			   	 exponent_b, 
				 from_b,
				 s->pre_master_result,
#ifdef CAVIUM_MULTICARD_API
                                 &(s->cav_req_id),s->dev_id
#else
                                 &(s->cav_req_id)
#endif
                             );


	if ( i == EAGAIN)
	{
		cav_fprintf(cav_nb_fp,"rsa_public_encrypt(): %s\n",
                                        "Csp1Pkcs1v15Enc() EAGAIN");

                s->cav_crypto_state = CAV_ST_IN_PRE_MASTER_KEY;
                s->cav_saved_state = s->state;
		s->state = SSL3_ST_CW_KEY_EXCH_A;
                s->cav_req_id_check_done = 0;
                s->rwstate = SSL_NITROX_BUSY;
		return -EAGAIN;
	}

	if(i) {
		ret=0;
		return ret;
	}
	
	else {
		ret = modulus_size;
		memcpy(to,s->pre_master_result,ret);
	}

rsa_pub_enc_cleanup:
	if(driver_ready == -1)
#ifdef CAVIUM_MULTICARD_API
          Csp1Shutdown(CAVIUM_DEV_ID);
#else
          Csp1Shutdown();
#endif

  
	return ret;
}
#endif

int pkp_rsa_public_encrypt(int flen, unsigned char *from, unsigned char *to, RSA * rsa)
{
	int i,ret=0;
	unsigned char *modulus_b=NULL, *exponent_b=NULL, *from_b=NULL;
	int modulus_size, exponent_size, data_size;
	int driver_ready = -1;
	Uint32 req_id;


#ifdef CAVIUM_MULTICARD_API
        driver_ready = Csp1GetDriverState(CAVIUM_DEV_ID);
#else
        driver_ready = Csp1GetDriverState();
#endif

	if(driver_ready == -1)
	{

#ifdef CAVIUM_MULTICARD_API
          if(Csp1Initialize(CAVIUM_DIRECT,CAVIUM_DEV_ID))
#else
          if(Csp1Initialize(CAVIUM_DIRECT))
#endif
		  return 0;
	}

	modulus_size  = BN_num_bytes(rsa->n);
	//if((modulus_size<17)||(modulus_size>256))
	if((modulus_size<17)||(modulus_size>512))
		goto rsa_pub_enc_cleanup;

	exponent_size = BN_num_bytes(rsa->e);

	modulus_b = alloca(modulus_size);
	if(modulus_b==NULL)
	{
		ret = 0;
		goto rsa_pub_enc_cleanup;
	}
	memset(modulus_b,0,modulus_size);

	exponent_b = alloca(exponent_size);
	if(exponent_b==NULL)
	{
		ret = 0;
		goto rsa_pub_enc_cleanup;
	}
	memset(exponent_b,0,exponent_size);

	data_size = flen;

	from_b = alloca(data_size);
	if(from_b==NULL)
	{
		ret = 0;
		goto rsa_pub_enc_cleanup;
	}

	memcpy(from_b,from,data_size);
	BN_bn2bin(rsa->n,modulus_b); 
	BN_bn2bin(rsa->e,exponent_b);

   i = Csp1Pkcs1v15Enc(CAVIUM_BLOCKING,
			    BT2,
			    (Uint16)modulus_size, 
				(Uint16)exponent_size,
				(Uint16)data_size, 
			    modulus_b, 
			    exponent_b, 
			    from_b,
				to,
#ifdef CAVIUM_MULTICARD_API
                                 &req_id,CAVIUM_DEV_ID
#else
                                 &req_id
#endif
                             );


	if(i) ret=0;
	else ret = modulus_size;

rsa_pub_enc_cleanup:
	if(driver_ready == -1)
#ifdef CAVIUM_MULTICARD_API
          Csp1Shutdown(CAVIUM_DEV_ID);
#else
          Csp1Shutdown();
#endif

  
	return ret;
}

#ifdef CAVIUM_SSL
int pkp_rsa_private_encrypt_cav(void *s1,int flen, unsigned char *from, unsigned char *to, RSA * rsa)
{

	int i,ret=0;
	unsigned char *modulus_b=NULL, *exponent_b=NULL, *from_b=NULL;
	int modulus_size, exponent_size, data_size;
	int driver_ready = -1;
	Uint16 out_length=0;
	int rc ;


	SSL *s = (SSL *)s1;
	

	if (s->cav_crypto_state == CAV_ST_IN_PRE_MASTER_KEY){
		
		rc = check_crypto_completion (s,
						  &out_length	
						  );	


		if (rc == 1) {
	                modulus_size  = BN_num_bytes(rsa->n);
			memcpy (to, s->pre_master_result,modulus_size);
			return s->cryp_flen;
		}
		else if(rc == -EAGAIN) 
		  	return rc ;
		else
			return 0;
	}

#ifdef CAVIUM_MULTICARD_API
        driver_ready = Csp1GetDriverState(CAVIUM_DEV_ID);
#else
        driver_ready = Csp1GetDriverState();
#endif

	if(driver_ready == -1)
	{
#ifdef CAVIUM_MULTICARD_API
          if(Csp1Initialize(CAVIUM_DIRECT,CAVIUM_DEV_ID))
#else
          if(Csp1Initialize(CAVIUM_DIRECT))
#endif
		  return 0;
	}

	modulus_size  = BN_num_bytes(rsa->n);
	//if((modulus_size<17)||(modulus_size>256))
	if((modulus_size<17)||(modulus_size>512))
		goto rsa_priv_enc_cleanup;

	exponent_size = BN_num_bytes(rsa->d);

	modulus_b = alloca(modulus_size);
	if(modulus_b==NULL)
	{
		ret = 0;
		goto rsa_priv_enc_cleanup;
	}
	memset(modulus_b,0,modulus_size);

	exponent_b = alloca(exponent_size);
	if(exponent_b==NULL)
	{
		ret = 0;
		goto rsa_priv_enc_cleanup;
	}
	memset(exponent_b,0,exponent_size);

	data_size = flen;
	from_b = alloca(data_size);
	if(from_b==NULL)
	{
		ret = 0;
		goto rsa_priv_enc_cleanup;
	}


	memcpy(from_b,from,data_size);
	BN_bn2bin(rsa->n,modulus_b); 
	BN_bn2bin(rsa->d,exponent_b);
	s->cryp_flen = modulus_size;


	i = Csp1Pkcs1v15Enc(s->cav_nb_mode,
				BT1,
				(Uint16)modulus_size, 
				(Uint16)exponent_size,
				(Uint16)data_size, 
	   			 modulus_b, 
			   	 exponent_b, 
				 from_b,
				 s->pre_master_result,
#ifdef CAVIUM_MULTICARD_API
                                 &(s->cav_req_id),s->dev_id
#else
                                 &(s->cav_req_id)
#endif
                             );

	if ( i == EAGAIN)
	{
		cav_fprintf(cav_nb_fp,"rsa_private_encrypt(): %s\n",
                                        "Csp1Pkcs1v15Enc() EAGAIN");

                s->cav_crypto_state = CAV_ST_IN_PRE_MASTER_KEY;
                s->cav_saved_state = s->state;
	//	if (s->state == SSL3_ST_CW_CERT_VRFY_A )
                        s->state = CAV_ST_IN_PRE_MASTER_KEY;
          //      else
            //            s->state = SSL3_ST_CW_KEY_EXCH_A;

                s->cav_req_id_check_done = 0;
                s->rwstate = SSL_NITROX_BUSY;
		return -EAGAIN;
	}
	if(i) {
		ret=0;
		return ret;
	}	
	else {
		ret = modulus_size;
		memcpy(to,s->pre_master_result,ret);
	}		
rsa_priv_enc_cleanup:
	if(driver_ready == -1)
#ifdef CAVIUM_MULTICARD_API
          Csp1Shutdown(CAVIUM_DEV_ID);
#else
          Csp1Shutdown();
#endif

  
	return ret;
}
#endif

int pkp_rsa_private_encrypt(int flen, unsigned char *from, unsigned char *to, RSA * rsa)
{
	int i,ret=0;
	unsigned char *modulus_b=NULL, *exponent_b=NULL, *from_b=NULL;
	int modulus_size, exponent_size, data_size;
	int driver_ready = -1;
	Uint32 req_id;


#ifdef CAVIUM_MULTICARD_API
        driver_ready = Csp1GetDriverState(CAVIUM_DEV_ID);
#else
        driver_ready = Csp1GetDriverState();
#endif

	if(driver_ready == -1)
	{
#ifdef CAVIUM_MULTICARD_API
          if(Csp1Initialize(CAVIUM_DIRECT,CAVIUM_DEV_ID))
#else
          if(Csp1Initialize(CAVIUM_DIRECT))
#endif
		  return 0;
	}

	modulus_size  = BN_num_bytes(rsa->n);
	if((modulus_size<17)||(modulus_size>512))
	//if((modulus_size<17)||(modulus_size>256))
		goto rsa_priv_enc_cleanup;

	exponent_size = BN_num_bytes(rsa->d);

	modulus_b = alloca(modulus_size);
	if(modulus_b==NULL)
	{
		ret = 0;
		goto rsa_priv_enc_cleanup;
	}
	memset(modulus_b,0,modulus_size);

	exponent_b = alloca(exponent_size);
	if(exponent_b==NULL)
	{
		ret = 0;
		goto rsa_priv_enc_cleanup;
	}
	memset(exponent_b,0,exponent_size);

	data_size = flen;
	from_b = alloca(data_size);
	if(from_b==NULL)
	{
		ret = 0;
		goto rsa_priv_enc_cleanup;
	}


	memcpy(from_b,from,data_size);
	BN_bn2bin(rsa->n,modulus_b); 
	BN_bn2bin(rsa->d,exponent_b);

	i = Csp1Pkcs1v15Enc(CAVIUM_BLOCKING,
			    BT1,
			    (Uint16)modulus_size, 
				(Uint16)exponent_size,
				(Uint16)data_size, 
			    modulus_b, 
			    exponent_b, 
			    from_b,
				to,
#ifdef CAVIUM_MULTICARD_API
                                 &req_id,CAVIUM_DEV_ID
#else
                                 &req_id
#endif
                             );


	if(i) ret=0;
	else ret = modulus_size;

rsa_priv_enc_cleanup:
	if(driver_ready == -1)
#ifdef CAVIUM_MULTICARD_API
          Csp1Shutdown(CAVIUM_DEV_ID);
#else
          Csp1Shutdown();
#endif


	return ret;
}

#else
int cav_mod_exp(BIGNUM *r, BIGNUM *a, BIGNUM *p, BIGNUM *m)
{
  unsigned char *ab, *pb, *mb, *rb, *temp;
  int sizep,sizem,sizea,osizem;
  int driver_ready=-1;
  int ret = 0;
  Uint32 req_id;

#ifdef CAVIUM_MODEX_DEBUG
  int i; 
  FILE *fptr;
#endif

  osizem = BN_num_bytes(m);
  if( (osizem < 24) || (osizem>256) ) return 0;

#ifdef CAVIUM_MULTICARD_API
        driver_ready = Csp1GetDriverState(CAVIUM_DEV_ID);
#else
        driver_ready = Csp1GetDriverState();
#endif

  if(driver_ready == -1)
  {
#ifdef CAVIUM_MULTICARD_API
          if(Csp1Initialize(CAVIUM_DIRECT,CAVIUM_DEV_ID))
#else
          if(Csp1Initialize(CAVIUM_DIRECT))
#endif
		  return 0;
  }

  sizem = ((osizem+7)/8)*8;
  sizea = BN_num_bytes(a);
  sizep = BN_num_bytes(p);

  mb = alloca(sizem);
  if(mb==NULL)
  {
	  ret= 0;
	  goto mod_exp_cleanup;
  }
  memset(mb,0,sizem);

  ab = alloca(sizem);
  if(ab==NULL)
  {
	  ret= 0;
	  goto mod_exp_cleanup;
  }
  memset(ab,0,sizem);

  pb = alloca(sizem);
  if(pb==NULL)
  {
	  ret= 0;
	  goto mod_exp_cleanup;
  }
  memset(pb,0,sizem);   

  temp = alloca(sizem); 
  if(temp==NULL)
  {
	  ret= 0;
	  goto mod_exp_cleanup;
  }
  memset(temp,0,sizem);

  rb = alloca(sizem); 
  if(rb==NULL)
  {
	  ret= 0;
	  goto mod_exp_cleanup;
  }
  memset(rb,0,sizem);

  BN_bn2bin(a,ab); 

  BN_bn2bin(p,pb); 

  if(sizep < sizem)
   {
    pkp_leftfill(pb,sizep,temp,sizem);
    memcpy(pb,temp,sizem);
    memset(temp,0,sizem); 
   }

   if(sizea < sizem)
   {
    pkp_leftfill(ab,sizea,temp,sizem);
    memcpy(ab,temp,sizem);
    memset(temp,0,sizem); 
   }

  BN_bn2bin(m,mb); 
  if(sizem > osizem)
   {
    pkp_leftfill(mb,osizem,temp,sizem);
    memcpy(mb,temp,sizem);
    memset(temp,0,sizem); 
   }

#ifdef CAVIUM_MODEX_DEBUG
   fptr = fopen("me.tst", "a");
   fprintf(fptr, "\ndata:\n");
   for (i=0;i<sizem; i++)
     fprintf(fptr, "%02x ", ab[i]);
   fprintf(fptr, "\nexponent\n");
   for(i=0;i<sizem;i++)
    fprintf(fptr,"%02x ", pb[i]);
   fprintf(fptr,"\nmodulus:\n");
   for(i=0;i<sizem;i++)
     fprintf(fptr, "%02x ",mb[i]);
#endif
  
  swap_word_openssl(temp, ab, sizem);
  memcpy(ab,temp,sizem);
  memset(temp,0,sizem);

  swap_word_openssl(temp, pb, sizem);
  memcpy(pb,temp,sizem);
  memset(temp,0,sizem);

  swap_word_openssl(temp, mb, sizem);
  memcpy(mb,temp,sizem);
  memset(temp,0,sizem);

#ifdef CAVIUM_MODEX_DEBUG
  fprintf(fptr, "\ndata after swap :\n");
   for (i=0;i<sizem; i++)
     fprintf(fptr, "%02x ", ab[i]);
   fprintf(fptr, "\nexponent after swap\n");
   for(i=0;i<sizem;i++)
    fprintf(fptr,"%02x ", pb[i]);
   fprintf(fptr,"\nmodulus after swap:\n");
   for(i=0;i<sizem;i++)
     fprintf(fptr, "%02x ",mb[i]); 
#endif

#ifdef CAVIUM_MULTICARD_API
   if (Csp1Me(CAVIUM_BLOCKING,RESULT_PTR, (Uint64)NULL, sizem, ab, mb, pb, rb, &req_id,CAVIUM_DEV_ID))
#else
   if (Csp1Me(CAVIUM_BLOCKING,RESULT_PTR, (Uint64)NULL, sizem, ab, mb, pb, rb, &req_id))
#endif

   {
	  ret= 0;
	  goto mod_exp_cleanup;
   }


#ifdef CAVIUM_MODEX_DEBUG
   fprintf(fptr, "\nresult:\n");
   for(i=0;i<sizem;i++)
   {
    fprintf(fptr, "%02x ",rb[i]);
   }
  fclose(fptr);
#endif

  
  BN_bin2bn(rb,sizem,r); 
  ret = 1;

mod_exp_cleanup:
  if(driver_ready == -1)
#ifdef CAVIUM_MULTICARD_API
          Csp1Shutdown(CAVIUM_DEV_ID);
#else
          Csp1Shutdown();
#endif

  return ret;

}

#ifdef CAVIUM_SSL
int pkp_rsa_public_decrypt_cav(void *s1,int flen, unsigned char *from, unsigned char *to, RSA * rsa)
{

	int i,ret=0;
	unsigned char *modulus_b=NULL, *exponent_b=NULL, *from_b=NULL, *temp=NULL;
	int modulus_size, exponent_size;
	Uint64 out_length=0;
	int rc ;

	SSL *s = (SSL *)s1;

	/* I donot really need this variable here because I am going to get result back in user pointer*/
	Uint64 dummy_ctx_ptr = 0;
	Uint64 dummy_key_handle=0;
	int driver_ready = -1;

	if (s->cav_crypto_state == CAV_ST_IN_PRE_MASTER_KEY){
		
		rc = check_crypto_completion (s,
						  &out_length	
						  );	

		if (rc == 1) {
			memcpy (to, s->pre_master_result,s->cryp_flen);
			return (Uint32)out_length;
		}
		else if(rc == -EAGAIN) 
		  	return rc;
		else
			return 0;
	}
#ifdef CAVIUM_MULTICARD_API
        driver_ready = Csp1GetDriverState(CAVIUM_DEV_ID);
#else
        driver_ready = Csp1GetDriverState();
#endif

	if(driver_ready == -1)
	{
#ifdef CAVIUM_MULTICARD_API
          if(Csp1Initialize(CAVIUM_DIRECT,CAVIUM_DEV_ID))
#else
          if(Csp1Initialize(CAVIUM_DIRECT))
#endif
		  return 0;
	}

	modulus_size  = BN_num_bytes(rsa->n);
	if(((modulus_size&0x7)!=0)||(modulus_size<24)||(modulus_size>512))
//	if(((modulus_size&0x7)!=0)||(modulus_size<24)||(modulus_size>256))
		goto rsa_pub_dec_cleanup;

	exponent_size = BN_num_bytes(rsa->e);

	modulus_b = alloca(modulus_size);
	if(modulus_b==NULL)
	{
		ret=0;
		goto rsa_pub_dec_cleanup;
	}
	memset(modulus_b,0,modulus_size);


	temp = alloca(modulus_size);
	if(temp==NULL)
	{
		ret=0;
		goto rsa_pub_dec_cleanup;
	}
	memset(temp,0,modulus_size);


	exponent_b = alloca(modulus_size);
	if(exponent_b==NULL)
	{
		ret=0;
		goto rsa_pub_dec_cleanup;
	}
	memset(exponent_b,0,modulus_size);


	from_b = alloca(modulus_size);
	if(from_b==NULL)
	{
		ret=0;
		goto rsa_pub_dec_cleanup;
	}
	memcpy(from_b,from,modulus_size);


	BN_bn2bin(rsa->n,modulus_b); 
	BN_bn2bin(rsa->e,exponent_b);

    if(exponent_size < modulus_size)
    {
     pkp_leftfill(exponent_b,exponent_size,temp,modulus_size);
     memcpy(exponent_b,temp,modulus_size);
     memset(temp,0,modulus_size); 
    }


   swap_word_openssl(temp, modulus_b, modulus_size);
   memcpy(modulus_b,temp,modulus_size);
   memset(temp,0,modulus_size);

   swap_word_openssl(temp, exponent_b, modulus_size);
   memcpy(exponent_b,temp,modulus_size);
   memset(temp,0,modulus_size);

   swap_word_openssl(temp, from_b, modulus_size);
   memcpy(from_b,temp,modulus_size);
   memset(temp,0,modulus_size);

    s->cryp_flen = flen;
	
	i  =	Csp1Pkcs1v15Dec(s->cav_nb_mode,
						RESULT_PTR, /* got it ?? */
						dummy_ctx_ptr, 
						INPUT_DATA,
						dummy_key_handle, 
						BT1,
						(unsigned short)modulus_size, 
					    modulus_b, 
					    exponent_b, 
					    from_b,
						s->pre_master_result,
						&s->pre_master_len,
#ifdef CAVIUM_MULTICARD_API
                                 &(s->cav_req_id),s->dev_id
#else
                                 &(s->cav_req_id)
#endif
                             );



	if ( i == EAGAIN)
	{
		cav_fprintf(cav_nb_fp,"rsa_public_decrypt(): %s\n",
                                        "Csp1Pkcs1v15De() EAGAIN");

                s->cav_crypto_state = CAV_ST_IN_PRE_MASTER_KEY;
                s->cav_saved_state = s->state;

		if (s->state == SSL3_ST_CR_KEY_EXCH_B)
			s->state = SSL3_ST_CR_KEY_EXCH_B ;
		else	
                	s->state = CAV_ST_IN_PRE_MASTER_KEY;

                s->cav_req_id_check_done = 0;
                s->rwstate = SSL_NITROX_BUSY;
		return -EAGAIN;
	}
        if(i) {

		ret = 0;
		return ret;
	}
	else {
	 ret = (Uint32)(s->pre_master_len); 
	 memcpy (to, s->pre_master_result,s->cryp_flen);
	}

rsa_pub_dec_cleanup:
	if(driver_ready == -1)
#ifdef CAVIUM_MULTICARD_API
          Csp1Shutdown(CAVIUM_DEV_ID);
#else
          Csp1Shutdown();
#endif

  
	return ret;
}
#endif

int pkp_rsa_public_decrypt(int flen, unsigned char *from, unsigned char *to, RSA * rsa)
{

	int i,ret=0;
	unsigned char *modulus_b=NULL, *exponent_b=NULL, *from_b=NULL, *temp=NULL;
	int modulus_size, exponent_size;
	Uint64 out_length=0;
	Uint32 req_id;

	/* I donot really need this variable here because I am going to get result back in user pointer*/
	Uint64 dummy_ctx_ptr = 0;
	Uint64 dummy_key_handle=0;
	int driver_ready = -1;


#ifdef CAVIUM_MULTICARD_API
        driver_ready = Csp1GetDriverState(CAVIUM_DEV_ID);
#else
        driver_ready = Csp1GetDriverState();
#endif

	if(driver_ready == -1)
	{
#ifdef CAVIUM_MULTICARD_API
          if(Csp1Initialize(CAVIUM_DIRECT,CAVIUM_DEV_ID))
#else
          if(Csp1Initialize(CAVIUM_DIRECT))
#endif
		  return 0;
	}

	modulus_size  = BN_num_bytes(rsa->n);
	//if(((modulus_size&0x7)!=0)||(modulus_size<24)||(modulus_size>256))
	if(((modulus_size&0x7)!=0)||(modulus_size<24)||(modulus_size>512))
		goto rsa_pub_dec_cleanup;

	exponent_size = BN_num_bytes(rsa->e);

	modulus_b = alloca(modulus_size);
	if(modulus_b==NULL)
	{
		ret=0;
		goto rsa_pub_dec_cleanup;
	}
	memset(modulus_b,0,modulus_size);


	temp = alloca(modulus_size);
	if(temp==NULL)
	{
		ret=0;
		goto rsa_pub_dec_cleanup;
	}
	memset(temp,0,modulus_size);


	exponent_b = alloca(modulus_size);
	if(exponent_b==NULL)
	{
		ret=0;
		goto rsa_pub_dec_cleanup;
	}
	memset(exponent_b,0,modulus_size);


	from_b = alloca(modulus_size);
	if(from_b==NULL)
	{
		ret=0;
		goto rsa_pub_dec_cleanup;
	}
	memcpy(from_b,from,modulus_size);


	BN_bn2bin(rsa->n,modulus_b); 
	BN_bn2bin(rsa->e,exponent_b);

    if(exponent_size < modulus_size)
    {
     pkp_leftfill(exponent_b,exponent_size,temp,modulus_size);
     memcpy(exponent_b,temp,modulus_size);
     memset(temp,0,modulus_size); 
    }


   swap_word_openssl(temp, modulus_b, modulus_size);
   memcpy(modulus_b,temp,modulus_size);
   memset(temp,0,modulus_size);

   swap_word_openssl(temp, exponent_b, modulus_size);
   memcpy(exponent_b,temp,modulus_size);
   memset(temp,0,modulus_size);

   swap_word_openssl(temp, from_b, modulus_size);
   memcpy(from_b,temp,modulus_size);
   memset(temp,0,modulus_size);

	i=	Csp1Pkcs1v15Dec(CAVIUM_BLOCKING,
						RESULT_PTR, /* got it ?? */
						dummy_ctx_ptr, 
						INPUT_DATA,
						dummy_key_handle, 
						BT1,
						(unsigned short)modulus_size, 
					    modulus_b, 
					    exponent_b, 
					    from_b,
						to,
						&out_length,
#ifdef CAVIUM_MULTICARD_API
                                 &req_id,CAVIUM_DEV_ID
#else
                                 &req_id
#endif
                             );



	if(i) ret=0;
	else ret = (Uint32)out_length;

rsa_pub_dec_cleanup:
	if(driver_ready == -1)
#ifdef CAVIUM_MULTICARD_API
          Csp1Shutdown(CAVIUM_DEV_ID);
#else
          Csp1Shutdown();
#endif

  
	return ret;
}

int pkp_rsa_private_decrypt(int flen, unsigned char *from, unsigned char *to, RSA * rsa)
{

	int i,ret=0;
	unsigned char *modulus_b=NULL, *exponent_b=NULL, *from_b=NULL, *temp=NULL;
	int modulus_size, exponent_size;
	Uint64 out_length=0;

	/* I donot really need this variable here because I am going to get result back in user pointer*/
	Uint64 dummy_ctx_ptr = 0;
	Uint64 dummy_key_handle = 0;
	int driver_ready = -1;
	Uint32 req_id;


#ifdef CAVIUM_MULTICARD_API
        driver_ready = Csp1GetDriverState(CAVIUM_DEV_ID);
#else
        driver_ready = Csp1GetDriverState();
#endif

	if(driver_ready == -1)
	{
#ifdef CAVIUM_MULTICARD_API
          if(Csp1Initialize(CAVIUM_DIRECT,CAVIUM_DEV_ID))
#else
          if(Csp1Initialize(CAVIUM_DIRECT))
#endif
		  return 0;
	}

	modulus_size  = BN_num_bytes(rsa->n);
	//if(((modulus_size&0x7)!=0)||(modulus_size<24)||(modulus_size>256))
	if(((modulus_size&0x7)!=0)||(modulus_size<24)||(modulus_size>512))
		goto rsa_priv_dec_cleanup;

	exponent_size = BN_num_bytes(rsa->d);

	modulus_b = alloca(modulus_size);
	if(modulus_b==NULL)
	{
		ret = 0;
		goto rsa_priv_dec_cleanup;
	}
	memset(modulus_b,0,modulus_size);


	temp = alloca(modulus_size);
	if(temp==NULL)
	{
		ret = 0;
		goto rsa_priv_dec_cleanup;
	}
	memset(temp,0,modulus_size);


	exponent_b = alloca(modulus_size);
	if(exponent_b==NULL)
	{
		ret = 0;
		goto rsa_priv_dec_cleanup;
	}
	memset(exponent_b,0,modulus_size);

	from_b = alloca(modulus_size);
	if(from_b==NULL)
	{
		ret = 0;
		goto rsa_priv_dec_cleanup;
	}
	memcpy(from_b,from,modulus_size);



	BN_bn2bin(rsa->n,modulus_b); 
	BN_bn2bin(rsa->d,exponent_b);

    if(exponent_size < modulus_size)
    {
     pkp_leftfill(exponent_b,exponent_size,temp,modulus_size);
     memcpy(exponent_b,temp,modulus_size);
     memset(temp,0,modulus_size); 
    }


   swap_word_openssl(temp, modulus_b, modulus_size);
   memcpy(modulus_b,temp,modulus_size);
   memset(temp,0,modulus_size);

   swap_word_openssl(temp, exponent_b, modulus_size);
   memcpy(exponent_b,temp,modulus_size);
   memset(temp,0,modulus_size);

   swap_word_openssl(temp, from_b, modulus_size);
   memcpy(from_b,temp,modulus_size);
   memset(temp,0,modulus_size);

	i=	Csp1Pkcs1v15Dec(CAVIUM_BLOCKING,
	   					RESULT_PTR, /* got it ?? */
						dummy_ctx_ptr, 
						INPUT_DATA,
						dummy_key_handle, 
						BT2,
						(unsigned short)modulus_size, 
					    modulus_b, 
					    exponent_b, 
					    from_b,
						to,
						&out_length,
#ifdef CAVIUM_MULTICARD_API
                                 &req_id,CAVIUM_DEV_ID
#else
                                 &req_id
#endif
                             );



	if(i) ret=0;
	else ret = (Uint32)out_length;

rsa_priv_dec_cleanup:
	if(driver_ready == -1)
#ifdef CAVIUM_MULTICARD_API
          Csp1Shutdown(CAVIUM_DEV_ID);
#else
          Csp1Shutdown();
#endif

  
	return ret;
}

#ifdef CAVIUM_SSL
int pkp_rsa_public_encrypt_cav(void *s1,int flen, unsigned char *from, unsigned char *to, RSA * rsa)
{

	int i,ret=0;
	unsigned char *modulus_b=NULL, *exponent_b=NULL, *from_b=NULL, *temp=NULL;
	int modulus_size, exponent_size;

	/* I donot really need this variable here because I am going to get result back in user pointer*/
	Uint64 dummy_context_pointer = 0;
   	Uint64 dummy_key_handle = 0;
	int driver_ready = -1;
	Uint64 out_length=0;
	int rc ;


	SSL *s = (SSL *)s1;

	if (s->cav_crypto_state == CAV_ST_IN_PRE_MASTER_KEY){
		
		rc = check_crypto_completion (s,
						  &out_length	
						  );	

		if (rc == 1) {
	                modulus_size  = BN_num_bytes(rsa->n);
			memcpy (to,s->pre_master_result,modulus_size);
			return s->cryp_flen;
		}
		else if(rc == -EAGAIN) 
		  	return rc;
		else
			return 0;
	}


#ifdef CAVIUM_MULTICARD_API
        driver_ready = Csp1GetDriverState(CAVIUM_DEV_ID);
#else
        driver_ready = Csp1GetDriverState();
#endif

	if(driver_ready == -1)
	{
#ifdef CAVIUM_MULTICARD_API
          if(Csp1Initialize(CAVIUM_DIRECT,CAVIUM_DEV_ID))
#else
          if(Csp1Initialize(CAVIUM_DIRECT))
#endif
		  return 0;
	}

	modulus_size  = BN_num_bytes(rsa->n);
	//if(((modulus_size&0x7)!=0)||(modulus_size<24)||(modulus_size>256))
	if(((modulus_size&0x7)!=0)||(modulus_size<24)||(modulus_size>512))
		goto rsa_pub_enc_cleanup;

	exponent_size = BN_num_bytes(rsa->e);

	modulus_b = alloca(modulus_size);
	if(modulus_b==NULL)
	{
		ret = 0;
		goto rsa_pub_enc_cleanup;
	}
	memset(modulus_b,0,modulus_size);


	temp = alloca(modulus_size);
	if(temp==NULL)
	{
		ret = 0;
		goto rsa_pub_enc_cleanup;
	}
	memset(temp,0,modulus_size);


	exponent_b = alloca(modulus_size);
	if(exponent_b==NULL)
	{
		ret = 0;
		goto rsa_pub_enc_cleanup;
	}
	memset(exponent_b,0,modulus_size);

	from_b = alloca(modulus_size);
	if(from_b==NULL)
	{
		ret = 0;
		goto rsa_pub_enc_cleanup;
	}
	memset(from_b,0,modulus_size);
	memcpy(from_b, from,flen);



	BN_bn2bin(rsa->n,modulus_b); 
	BN_bn2bin(rsa->e,exponent_b);

    if(exponent_size < modulus_size)
    {
     pkp_leftfill(exponent_b,exponent_size,temp,modulus_size);
     memcpy(exponent_b,temp,modulus_size);
     memset(temp,0,modulus_size); 
    }
	
   swap_word_openssl(temp, modulus_b, modulus_size);
   memcpy(modulus_b,temp,modulus_size);
   memset(temp,0,modulus_size);

   swap_word_openssl(temp, exponent_b, modulus_size);
   memcpy(exponent_b,temp,modulus_size);
   memset(temp,0,modulus_size);
	
   s->cryp_flen = modulus_size;		

   i = Csp1Pkcs1v15Enc( s->cav_nb_mode,
   						RESULT_PTR, 
						dummy_context_pointer,
						INPUT_DATA,
						dummy_key_handle,
						BT2,
						(unsigned short)modulus_size, 
						modulus_b, 
						exponent_b, 
						(unsigned short)flen, 
						from_b,
						s->pre_master_result,
#ifdef CAVIUM_MULTICARD_API
                                 &(s->cav_req_id),s->dev_id
#else
                                 &(s->cav_req_id)
#endif
                             );



	if ( i == EAGAIN)
	{
		cav_fprintf(cav_nb_fp,"rsa_public_encrypt(): %s\n",
                                        "Csp1Pkcs1v15Enc() EAGAIN");

                s->cav_crypto_state = CAV_ST_IN_PRE_MASTER_KEY;
                s->cav_saved_state = s->state;
		s->state = SSL3_ST_CW_KEY_EXCH_A;
                s->cav_req_id_check_done = 0;
                s->rwstate = SSL_NITROX_BUSY;
		return -EAGAIN;
	}

	if(i) {
		ret=0;
		return ret;
	}
	
	else {
		ret = modulus_size;
		memcpy(to,s->pre_master_result,ret);
	}


rsa_pub_enc_cleanup:
	if(driver_ready == -1)
#ifdef CAVIUM_MULTICARD_API
          Csp1Shutdown(CAVIUM_DEV_ID);
#else
          Csp1Shutdown();
#endif

  
	return ret;
}
#endif

int pkp_rsa_public_encrypt(int flen, unsigned char *from, unsigned char *to, RSA * rsa)
{

	int i,ret=0;
	unsigned char *modulus_b=NULL, *exponent_b=NULL, *from_b=NULL, *temp=NULL;
	int modulus_size, exponent_size;

	/* I donot really need this variable here because I am going to get result back in user pointer*/
	Uint64 dummy_context_pointer = 0;
    Uint64 dummy_key_handle = 0;
	int driver_ready = -1;
	Uint32 req_id;


#ifdef CAVIUM_MULTICARD_API
        driver_ready = Csp1GetDriverState(CAVIUM_DEV_ID);
#else
        driver_ready = Csp1GetDriverState();
#endif

	if(driver_ready == -1)
	{
#ifdef CAVIUM_MULTICARD_API
          if(Csp1Initialize(CAVIUM_DIRECT,CAVIUM_DEV_ID))
#else
          if(Csp1Initialize(CAVIUM_DIRECT))
#endif
		  return 0;
	}

	modulus_size  = BN_num_bytes(rsa->n);
	//if(((modulus_size&0x7)!=0)||(modulus_size<24)||(modulus_size>256))
	if(((modulus_size&0x7)!=0)||(modulus_size<24)||(modulus_size>512))
		goto rsa_pub_enc_cleanup;

	exponent_size = BN_num_bytes(rsa->e);

	modulus_b = alloca(modulus_size);
	if(modulus_b==NULL)
	{
		ret = 0;
		goto rsa_pub_enc_cleanup;
	}
	memset(modulus_b,0,modulus_size);


	temp = alloca(modulus_size);
	if(temp==NULL)
	{
		ret = 0;
		goto rsa_pub_enc_cleanup;
	}
	memset(temp,0,modulus_size);


	exponent_b = alloca(modulus_size);
	if(exponent_b==NULL)
	{
		ret = 0;
		goto rsa_pub_enc_cleanup;
	}
	memset(exponent_b,0,modulus_size);

	from_b = alloca(modulus_size);
	if(from_b==NULL)
	{
		ret = 0;
		goto rsa_pub_enc_cleanup;
	}
	memset(from_b,0,modulus_size);
	memcpy(from_b, from,flen);



	BN_bn2bin(rsa->n,modulus_b); 
	BN_bn2bin(rsa->e,exponent_b);

    if(exponent_size < modulus_size)
    {
     pkp_leftfill(exponent_b,exponent_size,temp,modulus_size);
     memcpy(exponent_b,temp,modulus_size);
     memset(temp,0,modulus_size); 
    }
	
   swap_word_openssl(temp, modulus_b, modulus_size);
   memcpy(modulus_b,temp,modulus_size);
   memset(temp,0,modulus_size);

   swap_word_openssl(temp, exponent_b, modulus_size);
   memcpy(exponent_b,temp,modulus_size);
   memset(temp,0,modulus_size);

   i = Csp1Pkcs1v15Enc( CAVIUM_BLOCKING,
   						RESULT_PTR, 
						dummy_context_pointer,
						INPUT_DATA,
						dummy_key_handle,
						BT2,
						(unsigned short)modulus_size, 
						modulus_b, 
						exponent_b, 
						(unsigned short)flen, 
						from_b,
						to,
#ifdef CAVIUM_MULTICARD_API
                                 &req_id,CAVIUM_DEV_ID
#else
                                 &req_id
#endif
                             );




	if(i) ret=0;
	else ret = modulus_size;

rsa_pub_enc_cleanup:
	if(driver_ready == -1)
#ifdef CAVIUM_MULTICARD_API
          Csp1Shutdown(CAVIUM_DEV_ID);
#else
          Csp1Shutdown();
#endif

  
	return ret;
}

#ifdef CAVIUM_SSL
int pkp_rsa_private_encrypt_cav(void *s1,int flen, unsigned char *from, unsigned char *to, RSA * rsa)
{

	int i,ret=0;
	unsigned char *modulus_b=NULL, *exponent_b=NULL, *from_b=NULL, *temp=NULL;
	int modulus_size, exponent_size;

	/* I donot really need this variable here because I am going to get result back in user pointer*/
	Uint64 dummy_context_pointer = 0;
	Uint64 dummy_key_handle=0;
	int driver_ready = -1;
	Uint64 out_length=0;
	int rc ;



	SSL *s = (SSL *)s1;

	if (s->cav_crypto_state == CAV_ST_IN_PRE_MASTER_KEY){
		
		rc = check_crypto_completion (s,
						  &out_length	
						  );	

		if (rc == 1) {
	                modulus_size  = BN_num_bytes(rsa->n);
			memcpy (to,s->pre_master_result ,modulus_size);
			return s->cryp_flen;
		}
		else if(rc == -EAGAIN) 
		  	return rc;
		else
			return 0;
	}

#ifdef CAVIUM_MULTICARD_API
        driver_ready = Csp1GetDriverState(CAVIUM_DEV_ID);
#else
        driver_ready = Csp1GetDriverState();
#endif

	if(driver_ready == -1)
	{
#ifdef CAVIUM_MULTICARD_API
          if(Csp1Initialize(CAVIUM_DIRECT,CAVIUM_DEV_ID))
#else
          if(Csp1Initialize(CAVIUM_DIRECT))
#endif
		  return 0;
	}

	modulus_size  = BN_num_bytes(rsa->n);
	//if(((modulus_size&0x7)!=0)||(modulus_size<24)||(modulus_size>256))
	if(((modulus_size&0x7)!=0)||(modulus_size<24)||(modulus_size>512))
		goto rsa_priv_enc_cleanup;

	exponent_size = BN_num_bytes(rsa->d);

	modulus_b = alloca(modulus_size);
	if(modulus_b==NULL)
	{
		ret = 0;
		goto rsa_priv_enc_cleanup;
	}
	memset(modulus_b,0,modulus_size);


	temp = alloca(modulus_size);
	if(temp==NULL)
	{
		ret = 0;
		goto rsa_priv_enc_cleanup;
	}
	memset(temp,0,modulus_size);


	exponent_b = alloca(modulus_size);
	if(exponent_b==NULL)
	{
		ret = 0;
		goto rsa_priv_enc_cleanup;
	}
	memset(exponent_b,0,modulus_size);

	from_b = alloca(modulus_size);
	if(from_b==NULL)
	{
		ret = 0;
		goto rsa_priv_enc_cleanup;
	}
	memset(from_b,0,modulus_size);
	memcpy(from_b, from,flen);




	BN_bn2bin(rsa->n,modulus_b); 
	BN_bn2bin(rsa->d,exponent_b);

    if(exponent_size < modulus_size)
    {
     pkp_leftfill(exponent_b,exponent_size,temp,modulus_size);
     memcpy(exponent_b,temp,modulus_size);
     memset(temp,0,modulus_size); 
    }


   swap_word_openssl(temp, modulus_b, modulus_size);
   memcpy(modulus_b,temp,modulus_size);
   memset(temp,0,modulus_size);

   swap_word_openssl(temp, exponent_b, modulus_size);
   memcpy(exponent_b,temp,modulus_size);
   memset(temp,0,modulus_size);

   s->cryp_flen = modulus_size;	
	
   i = Csp1Pkcs1v15Enc( s->cav_nb_mode,
   						RESULT_PTR, 
						dummy_context_pointer,
						INPUT_DATA,
						dummy_key_handle,
						BT1,
						(unsigned short)modulus_size, 
						modulus_b, 
						exponent_b, 
						flen, 
						from_b,
						s->pre_master_result,
#ifdef CAVIUM_MULTICARD_API
                                 &(s->cav_req_id),s->dev_id
#else
                                 &(s->cav_req_id)
#endif
                             );




	if ( i == EAGAIN)
	{
		cav_fprintf(cav_nb_fp,"rsa_private_encrypt(): %s\n",
                                        "Csp1Pkcs1v15Enc() EAGAIN");

                s->cav_crypto_state = CAV_ST_IN_PRE_MASTER_KEY;
                s->cav_saved_state = s->state;
	//	if (s->state == SSL3_ST_CW_CERT_VRFY_A )
			s->state = CAV_ST_IN_PRE_MASTER_KEY;
	//	else
	//		s->state = SSL3_ST_CW_KEY_EXCH_A;
                s->cav_req_id_check_done = 0;
                s->rwstate = SSL_NITROX_BUSY;
		return -EAGAIN;
	}

	if(i) {
		ret=0;
		return ret;
	}
	
	else {
		ret = modulus_size;
		memcpy(to,s->pre_master_result,ret);
	}


rsa_priv_enc_cleanup:
	if(driver_ready == -1)
#ifdef CAVIUM_MULTICARD_API
          Csp1Shutdown(CAVIUM_DEV_ID);
#else
          Csp1Shutdown();
#endif

  
	return ret;
}
#endif


int pkp_rsa_private_encrypt(int flen, unsigned char *from, unsigned char *to, RSA * rsa)
{

	int i,ret=0;
	unsigned char *modulus_b=NULL, *exponent_b=NULL, *from_b=NULL, *temp=NULL;
	int modulus_size, exponent_size;

	/* I donot really need this variable here because I am going to get result back in user pointer*/
	Uint64 dummy_context_pointer = 0;
	Uint64 dummy_key_handle=0;
	int driver_ready = -1;
	Uint32 req_id;


#ifdef CAVIUM_MULTICARD_API
        driver_ready = Csp1GetDriverState(CAVIUM_DEV_ID);
#else
        driver_ready = Csp1GetDriverState();
#endif

	if(driver_ready == -1)
	{
#ifdef CAVIUM_MULTICARD_API
          if(Csp1Initialize(CAVIUM_DIRECT,CAVIUM_DEV_ID))
#else
          if(Csp1Initialize(CAVIUM_DIRECT))
#endif
		  return 0;
	}

	modulus_size  = BN_num_bytes(rsa->n);
	//if(((modulus_size&0x7)!=0)||(modulus_size<24)||(modulus_size>256))
	if(((modulus_size&0x7)!=0)||(modulus_size<24)||(modulus_size>512))
		goto rsa_priv_enc_cleanup;

	exponent_size = BN_num_bytes(rsa->d);

	modulus_b = alloca(modulus_size);
	if(modulus_b==NULL)
	{
		ret = 0;
		goto rsa_priv_enc_cleanup;
	}
	memset(modulus_b,0,modulus_size);


	temp = alloca(modulus_size);
	if(temp==NULL)
	{
		ret = 0;
		goto rsa_priv_enc_cleanup;
	}
	memset(temp,0,modulus_size);


	exponent_b = alloca(modulus_size);
	if(exponent_b==NULL)
	{
		ret = 0;
		goto rsa_priv_enc_cleanup;
	}
	memset(exponent_b,0,modulus_size);

	from_b = alloca(modulus_size);
	if(from_b==NULL)
	{
		ret = 0;
		goto rsa_priv_enc_cleanup;
	}
	memset(from_b,0,modulus_size);
	memcpy(from_b, from,flen);




	BN_bn2bin(rsa->n,modulus_b); 
	BN_bn2bin(rsa->d,exponent_b);

    if(exponent_size < modulus_size)
    {
     pkp_leftfill(exponent_b,exponent_size,temp,modulus_size);
     memcpy(exponent_b,temp,modulus_size);
     memset(temp,0,modulus_size); 
    }


   swap_word_openssl(temp, modulus_b, modulus_size);
   memcpy(modulus_b,temp,modulus_size);
   memset(temp,0,modulus_size);

   swap_word_openssl(temp, exponent_b, modulus_size);
   memcpy(exponent_b,temp,modulus_size);
   memset(temp,0,modulus_size);


   i = Csp1Pkcs1v15Enc( CAVIUM_BLOCKING,
   						RESULT_PTR, 
						dummy_context_pointer,
						INPUT_DATA,
						dummy_key_handle,
						BT1,
						(unsigned short)modulus_size, 
						modulus_b, 
						exponent_b, 
						flen, 
						from_b,
						to,
#ifdef CAVIUM_MULTICARD_API
                                 &req_id,CAVIUM_DEV_ID
#else
                                 &req_id
#endif
                             );




	if(i) ret=0;
	else ret = modulus_size;

rsa_priv_enc_cleanup:
	if(driver_ready == -1)
#ifdef CAVIUM_MULTICARD_API
          Csp1Shutdown(CAVIUM_DEV_ID);
#else
          Csp1Shutdown();
#endif

  
	return ret;
}
#endif /* MC2 else */

int check_crypto_completion (SSL *s,
#ifdef MC2
				  Uint16 *out_length	
#else
				  Uint64 *out_length	
#endif
				  ) {


	int rc ;

	s->state = s->cav_saved_state;
        if ( s->cav_req_id_check_done ) {
                cav_fprintf(cav_nb_fp,"check_crypto_completion(): %s\n",
                        "already checked, probably directly by app\n");
                rc = 0;
        }
        else {
#ifdef CAVIUM_MULTICARD_API
                rc = Csp1CheckForCompletion(s->cav_req_id,s->dev_id);
#else
                rc = Csp1CheckForCompletion(s->cav_req_id);
#endif
        }
        cav_fprintf(cav_nb_fp,
                "check_crypto_completion():Csp1CheckForCompletion() rc=%d\n",
                rc);

        switch(rc) {
                                                                                                                             
        case EAGAIN:
                cav_fprintf(cav_nb_fp,"check_crypto_completion(): %s\n",
                                "Csp1CheckForCompletion() EAGAIN");
                s->cav_saved_state = s->state;
                cav_fprintf(cav_nb_fp,"check_crypto_completion() s->state: %d\n",
                                s->state);


		if (s->state == SSL3_ST_CW_KEY_EXCH_A)
			s->state = SSL3_ST_CW_KEY_EXCH_A ;
		else if (s->state == SSL3_ST_CR_KEY_EXCH_B )
			s->state = SSL3_ST_CR_KEY_EXCH_B;
                else
	                s->state = CAV_ST_IN_PRE_MASTER_KEY;
		//else if (s->state == SSL3_ST_CW_CERT_VRFY_A )
                  //      s->state = CAV_ST_IN_PRE_MASTER_KEY;
		
                return(-EAGAIN);
        case 0:
                cav_fprintf(cav_nb_fp,"===>check_crypto_completion(): %s\n",
                                "Csp1CheckForCompletion() completed");
                                                                                                                             
                s->cav_crypto_state = 0;
                s->cav_req_id_check_done = 1;
                s->rwstate = SSL_NOTHING;
		#ifdef MC2
	 		*out_length = (Uint32)ntohs(s->pre_master_len); 
		#else
			*out_length = (Uint32)(s->pre_master_len); 
		#endif
		break;
         default:
                cav_fprintf(cav_nb_fp,"check_crypto_completion(): %s\n",
                                "Csp1CheckForCompletion() default case");
                /*
                 * should we reset the cav_crypto_state to 0 here
                 * to prevent an infinite loop
                 */
                s->cav_crypto_state = 0;
                s->cav_req_id_check_done = 1;
                s->rwstate = SSL_NOTHING;
                return(-1);
        } // end switch
        return(1);
}
#endif /* CAVIUM_FIPS */ 
