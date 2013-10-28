
/* cav_crypto_engine.c */
/*
 * Copyright (c) 2003-2006, Cavium Networks. All rights reserved.
 *
 * This Software is the property of Cavium Networks. The Software and all 
 * accompanying documentation are copyrighted. The Software made available here 
 * constitutes the proprietary information of Cavium Networks. You agree to take * 
 * reasonable steps to prevent the disclosure, unauthorized use or unauthorized 
 * distribution of the Software. You shall use this Software solely with Cavium 
 * hardware. 
 *
 * Except as expressly permitted in a separate Software License Agreement 
 * between You and Cavium Networks, You shall not modify, decompile, 
 * disassemble, extract, or otherwise reverse engineer this Software. You shall
 * not make any copy of the Software or its accompanying documentation, except 
 * for copying incident to the ordinary and intended use of the Software and 
 * the Underlying Program and except for the making of a single archival copy.
 *
 * This Software, including technical data, may be subject to U.S. export 
 * control laws, including the U.S. Export Administration Act and its 
 * associated regulations, and may be subject to export or import regulations 
 * in other countries. You warrant that You will comply strictly in all 
 * respects with all such regulations and acknowledge that you have the 
 * responsibility to obtain licenses to export, re-export or import the 
 * Software.
 *
 * TO THE MAXIMUM EXTENT PERMITTED BY LAW, THE SOFTWARE IS PROVIDED "AS IS" AND 
 * WITH ALL FAULTS AND CAVIUM MAKES NO PROMISES, REPRESENTATIONS OR WARRANTIES, 
 * EITHER EXPRESS,IMPLIED, STATUTORY,OR OTHERWISE, WITH RESPECT TO THE SOFTWARE,
 * INCLUDING ITS CONDITION,ITS CONFORMITY TO ANY REPRESENTATION OR DESCRIPTION, 
 * OR THE EXISTENCE OF ANY LATENT OR PATENT DEFECTS, AND CAVIUM SPECIFICALLY 
 * DISCLAIMS ALL IMPLIED (IF ANY) WARRANTIES OF TITLE, MERCHANTABILITY, 
 * NONINFRINGEMENT, FITNESS FOR A PARTICULAR PURPOSE,LACK OF VIRUSES,ACCURACY OR
 * COMPLETENESS, QUIET ENJOYMENT, QUIET POSSESSION OR CORRESPONDENCE TO 
 * DESCRIPTION. THE ENTIRE RISK ARISING OUT OF USE OR PERFORMANCE OF THE 
 * SOFTWARE LIES WITH YOU.
 *
 */
#if defined(linux)
   #include <alloca.h>
   #include <malloc.h>
#elif defined(__FreeBSD__)
   #include <stdlib.h>
#endif

#include <string.h>
#include <openssl/ssl.h>
#include <openssl/bn.h>
#include "cavium_common.h"
#include "cavium_ssl.h"


#define NITROX_PX
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

  driver_ready = Csp1GetDriverState();
  if(driver_ready == -1)
  {
#ifdef NPLUS
	  if(Csp1Initialize(CAVIUM_DIRECT, SSL_SPM_IDX))
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

  if (Csp1Me(CAVIUM_BLOCKING,sizem, sizep, sizea, mb, pb,ab, rb, &req_id))
   {
	  ret= 0;
	  goto mod_exp_cleanup;
   }
  

  BN_bin2bn(rb,sizem,r); 
  ret = 1;

mod_exp_cleanup:
  if(driver_ready == -1)
	  Csp1Shutdown();
  return ret;

}


int pkp_rsa_public_decrypt(int flen, unsigned char *from, unsigned char *to, RSA * rsa)
{
	int i,ret=0;
	unsigned char *modulus_b=NULL, *exponent_b=NULL, *from_b=NULL;
	int modulus_size, exponent_size;
	Uint16 out_length=0;
	Uint32 req_id;
	int driver_ready = -1;

	driver_ready = Csp1GetDriverState();
	if(driver_ready == -1)
	{
#ifdef NPLUS
	  if(Csp1Initialize(CAVIUM_DIRECT, SSL_SPM_IDX))
#else
	  if(Csp1Initialize(CAVIUM_DIRECT))
#endif
		  return 0;
	}

	modulus_size  = BN_num_bytes(rsa->n);
#ifdef NITROX_PX
	if((modulus_size<17)||(modulus_size>512))
#else
	if((modulus_size<17)||(modulus_size>256))
#endif
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
		&req_id);

	if(i) ret=0;
	else ret = (Uint32)ntohs(out_length);

rsa_pub_dec_cleanup:
	if(driver_ready == -1)
	  Csp1Shutdown();
  
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

	driver_ready = Csp1GetDriverState();
	if(driver_ready == -1)
	{
#ifdef NPLUS
	  if(Csp1Initialize(CAVIUM_DIRECT, SSL_SPM_IDX))
#else
	  if(Csp1Initialize(CAVIUM_DIRECT))
#endif
		  return 0;
	}

	modulus_size  = BN_num_bytes(rsa->n);
#ifdef NITROX_PX
	if((modulus_size<17)||(modulus_size>512))
#else
	if((modulus_size<17)||(modulus_size>256))
#endif
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
				&req_id);

	if(i) ret=0;
	else ret = (Uint32)ntohs(out_length);

rsa_priv_dec_cleanup:
	if(driver_ready == -1)
	  Csp1Shutdown();
  
	return ret;
}


int pkp_rsa_public_encrypt(int flen, unsigned char *from, unsigned char *to, RSA * rsa)
{
	int i,ret=0;
	unsigned char *modulus_b=NULL, *exponent_b=NULL, *from_b=NULL;
	int modulus_size, exponent_size, data_size;
	int driver_ready = -1;
	Uint32 req_id;


	driver_ready = Csp1GetDriverState();
	if(driver_ready == -1)
	{

#ifdef NPLUS
	  if(Csp1Initialize(CAVIUM_DIRECT, SSL_SPM_IDX))
#else
	  if(Csp1Initialize(CAVIUM_DIRECT))
#endif
		  return 0;
	}

	modulus_size  = BN_num_bytes(rsa->n);
#ifdef NITROX_PX
	if((modulus_size<17)||(modulus_size>512))
#else
	if((modulus_size<17)||(modulus_size>256))
#endif
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
			    &req_id);

	if(i) ret=0;
	else ret = modulus_size;

rsa_pub_enc_cleanup:
	if(driver_ready == -1)
	  Csp1Shutdown();
  
	return ret;
}


int pkp_rsa_private_encrypt(int flen, unsigned char *from, unsigned char *to, RSA * rsa)
{
	int i,ret=0;
	unsigned char *modulus_b=NULL, *exponent_b=NULL, *from_b=NULL;
	int modulus_size, exponent_size, data_size;
	int driver_ready = -1;
	Uint32 req_id;


	driver_ready = Csp1GetDriverState();
	if(driver_ready == -1)
	{
#ifdef NPLUS
	  if(Csp1Initialize(CAVIUM_DIRECT, SSL_SPM_IDX))
#else
	  if(Csp1Initialize(CAVIUM_DIRECT))
#endif
		  return 0;
	}

	modulus_size  = BN_num_bytes(rsa->n);
#ifdef NITROX_PX
	if((modulus_size<17)||(modulus_size>512))
#else
	if((modulus_size<17)||(modulus_size>256))
#endif
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
			    &req_id);

	if(i) ret=0;
	else ret = modulus_size;

rsa_priv_enc_cleanup:
	if(driver_ready == -1)
	  Csp1Shutdown();

	return ret;
}

#else
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

  driver_ready = Csp1GetDriverState();
  if(driver_ready == -1)
  {
#ifdef NPLUS
	  if(Csp1Initialize(CAVIUM_DIRECT, SSL_SPM_IDX))
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

   if (Csp1Me(CAVIUM_BLOCKING,RESULT_PTR, (Uint64)NULL, sizem, ab, mb, pb, rb, &req_id))
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
	  Csp1Shutdown();
  return ret;

}


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


	driver_ready = Csp1GetDriverState();
	if(driver_ready == -1)
	{
#ifdef NPLUS
	  if(Csp1Initialize(CAVIUM_DIRECT, SSL_SPM_IDX))
#else
	  if(Csp1Initialize(CAVIUM_DIRECT))
#endif
		  return 0;
	}

	modulus_size  = BN_num_bytes(rsa->n);
#ifdef NITROX_PX
	if(((modulus_size&0x7)!=0)||(modulus_size<24)||(modulus_size>512))
#else
	if(((modulus_size&0x7)!=0)||(modulus_size<24)||(modulus_size>256))
#endif
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
						&req_id);


	if(i) ret=0;
	else ret = (Uint32)out_length;

rsa_pub_dec_cleanup:
	if(driver_ready == -1)
	  Csp1Shutdown();
  
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


	driver_ready = Csp1GetDriverState();
	if(driver_ready == -1)
	{
#ifdef NPLUS
	  if(Csp1Initialize(CAVIUM_DIRECT, SSL_SPM_IDX))
#else
	  if(Csp1Initialize(CAVIUM_DIRECT))
#endif
		  return 0;
	}

	modulus_size  = BN_num_bytes(rsa->n);
#ifdef NITROX_PX
	if(((modulus_size&0x7)!=0)||(modulus_size<24)||(modulus_size>512))
#else
	if(((modulus_size&0x7)!=0)||(modulus_size<24)||(modulus_size>256))
#endif
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
						&req_id);


	if(i) ret=0;
	else ret = (Uint32)out_length;

rsa_priv_dec_cleanup:
	if(driver_ready == -1)
	  Csp1Shutdown();
  
	return ret;
}

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


	driver_ready = Csp1GetDriverState();
	if(driver_ready == -1)
	{
#ifdef NPLUS
	  if(Csp1Initialize(CAVIUM_DIRECT, SSL_SPM_IDX))
#else
	  if(Csp1Initialize(CAVIUM_DIRECT))
#endif
		  return 0;
	}

	modulus_size  = BN_num_bytes(rsa->n);
#ifdef NITROX_PX
	if(((modulus_size&0x7)!=0)||(modulus_size<24)||(modulus_size>512))
#else
	if(((modulus_size&0x7)!=0)||(modulus_size<24)||(modulus_size>256))
#endif
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
						&req_id);



	if(i) ret=0;
	else ret = modulus_size;

rsa_pub_enc_cleanup:
	if(driver_ready == -1)
	  Csp1Shutdown();
  
	return ret;
}



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


	driver_ready = Csp1GetDriverState();
	if(driver_ready == -1)
	{
#ifdef NPLUS
	  if(Csp1Initialize(CAVIUM_DIRECT, SSL_SPM_IDX))
#else
	  if(Csp1Initialize(CAVIUM_DIRECT))
#endif
		  return 0;
	}

	modulus_size  = BN_num_bytes(rsa->n);
#ifdef NITROX_PX
	if(((modulus_size&0x7)!=0)||(modulus_size<24)||(modulus_size>512))
#else
	if(((modulus_size&0x7)!=0)||(modulus_size<24)||(modulus_size>256))
#endif
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
						&req_id);



	if(i) ret=0;
	else ret = modulus_size;

rsa_priv_enc_cleanup:
	if(driver_ready == -1)
	  Csp1Shutdown();
  
	return ret;
}
#endif /* MC2 else */

                               
