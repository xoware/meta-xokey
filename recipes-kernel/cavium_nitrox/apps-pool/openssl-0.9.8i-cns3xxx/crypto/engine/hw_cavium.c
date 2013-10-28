
/* hw_cavium.c */
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

#include <stdio.h>
#include <string.h>
#include <openssl/crypto.h>
#include <openssl/engine.h>
#include <openssl/bn.h>
#include <openssl/rsa.h>
#include <openssl/objects.h>
#include <openssl/x509.h>
#include <openssl/evp.h>

#ifdef CAVIUM_ENGINE
#include "cav_crypto_engine.h"
#include <cavium_common.h>
#include <cavium_ssl.h>
#define ENGINE_SIG_LENGTH	36
#define MAX_SUPPORTED_CIPHERS	12
#define MAX_SUPPORTED_DIGESTS    5
#define SHA_DIGEST_LENGTH       20   
#define MD5_DIGEST_LENGTH       16   
#define MD5_CBLOCK	        64   

#define CAVIUM_CMD_SO_PATH		ENGINE_CMD_BASE
static const ENGINE_CMD_DEFN cavium_cmd_defns[] = {
	{CAVIUM_CMD_SO_PATH,
		"SO_PATH",
		"Specifies the path to the 'nuronssl' shared library",
		ENGINE_CMD_FLAG_STRING},
	{0, NULL, NULL, 0}
};
RSA_METHOD *default_rsa; 
/*engine static variables */
static const char *cavium_engine_id   = "cavium";
static const char *cavium_engine_name = "Cavium hardware engine support";

/* ENGINE routines */

static int cavium_init(ENGINE *e);
static int cavium_shutdown(ENGINE *e);

static const char *CAVIUM_LIBNAME = NULL;
static const char *get_CAVIUM_LIBNAME(void)
	{
	if(CAVIUM_LIBNAME)
		return CAVIUM_LIBNAME;
	return NULL;
	}

static void free_CAVIUM_LIBNAME(void)
	{
	if(CAVIUM_LIBNAME)
		OPENSSL_free((void*)CAVIUM_LIBNAME);
	CAVIUM_LIBNAME = NULL;
	}
static long set_CAVIUM_LIBNAME(const char *name)
	{
	free_CAVIUM_LIBNAME();
	return (((CAVIUM_LIBNAME = BUF_strdup(name)) != NULL) ? 1 : 0);
	}

static int cavium_ctrl(ENGINE *e, int cmd, long i, void *p, void (*f)())
	{
	switch(cmd)
		{
	case CAVIUM_CMD_SO_PATH:
		if(p == NULL)
			{
			return 0;
			}
		return set_CAVIUM_LIBNAME((const char *)p);
	default:
		break;
		}
	return 0;
}

/* RSA functions */

#ifndef OPENSSL_NO_RSA
static int cav_rsa_pub_enc(int flen,const unsigned char *from, unsigned char *to,RSA *rsa,int padding);
static int cav_rsa_pub_dec(int flen,const unsigned char *from, unsigned char *to,RSA *rsa,int padding);
static int cav_rsa_priv_dec(int flen,const unsigned char *from, unsigned char *to,RSA *rsa,int padding);
static int cav_rsa_priv_enc(int flen,const unsigned char *from, unsigned char *to,RSA *rsa,int padding);
int cav_bn_mod_exp(BIGNUM *r, const BIGNUM *a,const BIGNUM *p,const BIGNUM *m, BN_CTX *ctx,BN_MONT_CTX *m_ctx);
int cav_rsa_sign(int type, const unsigned char *m, unsigned int m_len,unsigned char *sigret, unsigned int *siglen, const RSA *rsa);
int cav_rsa_verify(int dtype, const unsigned char *m, unsigned int m_len,unsigned char *sigbuf, unsigned int siglen, const RSA *rsa);
#endif

#ifndef OPENSSL_NO_DSA
int cav_dsa_bn_mod_exp(DSA *dsa, BIGNUM *r, BIGNUM *a, const BIGNUM *p,const BIGNUM *m, BN_CTX *ctx,BN_MONT_CTX *m_ctx); 
#endif
#ifndef OPENSSL_NO_DH
int cav_dh_bn_mod_exp(const DH *dh, BIGNUM *r, const BIGNUM *a,const BIGNUM *p, const BIGNUM *m, BN_CTX *ctx,BN_MONT_CTX *m_ctx); 
#endif

/* random functions */

int cavium_rand_bytes(unsigned char *buf, int num);
/* Digest structures and functions */
#ifdef CAVIUM_DIGEST
struct digest_st{
	int len;
	int size;
	unsigned char *data;
};
static struct {
	int	id;
	int	nid;
} digests[] = {
	{ 1,		NID_sha1,  },
	{ 2,		NID_md5,  },
	{ 0,		NID_undef, },
};

int get_cavium_digests(const int **nids);
int cavium_digest_init(EVP_MD_CTX *);
int cavium_digest_update(EVP_MD_CTX *,const void *, size_t );
int cavium_digest_final(EVP_MD_CTX *, unsigned char *);
int cavium_digest_copy(EVP_MD_CTX *, const EVP_MD_CTX *);
int cavium_digest_cleanup(EVP_MD_CTX *ctx);
#endif

/* Cipher related structures and functions */

#ifdef CAVIUM_CIPHERS

struct cipher_data{
	unsigned char *e_key;
	unsigned char *d_key;
	Uint64  e_ctx;
	Uint64  d_ctx;
};
struct cipher_ctx{
	Uint64 e_ctx;
	Uint64 d_ctx;
};

static struct {
	int 	id;
	int	nid;
	int	ivmax;
	int	keylen;
} ciphers[] = {
	{1,		NID_des_ede3_cbc,	8,	 24, },
	{2,		NID_des_cbc,		8,	  8, },
	{3,		NID_aes_128_cbc,	16,	 16, },
	{4,		NID_aes_256_cbc,	16,	 32, },
#ifdef ENABLE_RC4
	{5,		NID_rc4,		0,	  0,  },
#endif
	{0,		NID_undef,		0,	  0, },
};

int cipher_nid_to_id(int);
int cavium_get_cipher_max_iv(int);
int cavium_is_cipher_key_length_valid(int ,int);
int get_cavium_ciphers(const int **cnids);

int cavium_init_key(EVP_CIPHER_CTX *ctx,const unsigned char *key,const unsigned char *iv,int enc){
	Uint32 req_id;
	int cipher_id;
	int ret;
	struct cipher_ctx *c_ctx=NULL;
	struct cipher_data *c_data=NULL;
	AesType aes_type;
	unsigned char *temp_key=(unsigned char *)OPENSSL_malloc(100);
	unsigned char *e_key, *d_key;
	if(temp_key ==NULL)
		return 0;
	cipher_id = cipher_nid_to_id(ctx->cipher->nid);
	if(cipher_id == 0)
		return 0;
	if(!cavium_is_cipher_key_length_valid(cipher_id,ctx->key_len))
		return 0;
	if(ctx->cipher->block_size > 1){
		if(ctx->cipher->iv_len > cavium_get_cipher_max_iv(cipher_id))
			return 0;
		c_data= (struct cipher_data *)(ctx->cipher_data);
		if(ctx->encrypt){
#ifdef MC2
			e_key=(unsigned char *)OPENSSL_malloc(100);
			if(e_key == NULL)
				return 0;
			memcpy(e_key,key,ctx->key_len);
			c_data->e_key = e_key;
			c_data->e_ctx=(Uint64)0;
#else
			c_data->e_key=NULL;
			memcpy(temp_key,key,ctx->key_len);
			if(Csp1AllocContext(CONTEXT_SSL,&c_data->e_ctx)){
				OPENSSL_free(temp_key);
				return 0;
			}
#endif	
			
		} else {
#ifdef MC2
			d_key=(unsigned char *)OPENSSL_malloc(100);
			if(d_key == NULL )
				return 0;
			c_data->d_key = d_key;
			memcpy(c_data->d_key,key,ctx->key_len);
			c_data->d_ctx=(Uint64)0;
#else
			c_data->d_key=NULL;
			memcpy(temp_key,key,ctx->key_len);
			if(Csp1AllocContext(CONTEXT_SSL,&c_data->d_ctx)){
				OPENSSL_free(temp_key);
				return 0;
			}
#endif	
		}
	}else{
		c_ctx= (struct cipher_ctx *)(ctx->cipher_data);
		if(ctx->encrypt){
			if(Csp1AllocContext(CONTEXT_SSL, &c_ctx->e_ctx))
				return 0;
		} else{
			if(Csp1AllocContext(CONTEXT_SSL, &c_ctx->d_ctx))
				return 0;
		}
	}
	switch(ctx->cipher->nid){

		case NID_des_cbc	:
#ifdef MC2
				if(ctx->encrypt){
					memcpy(&e_key[8],&e_key[0],8);
					memcpy(&e_key[16],&e_key[0],8);
				}else {
					memcpy(&d_key[8],&d_key[0],8);
					memcpy(&d_key[16],&d_key[0],8);
				}
				return 1;
#else
				memcpy(&temp_key[8],&temp_key[0],8);	
				memcpy(&temp_key[16],&temp_key[0],8);	
					
#endif
		case NID_des_ede3_cbc 	:
#ifdef MC2
				OPENSSL_free(temp_key);
				return 1;
#else
				if(ctx->encrypt){
				ret = Csp1Initialize3DES( CAVIUM_BLOCKING,
							  c_data->e_ctx,
							  (unsigned char *)iv,
							  (unsigned char *)temp_key,
							  &req_id );
				}else {
				ret = Csp1Initialize3DES( CAVIUM_BLOCKING,
							  c_data->d_ctx,
							  (unsigned char *)iv,
							  (unsigned char *)temp_key,
							  &req_id );
				}
				OPENSSL_free(temp_key);
				if(ret == 0)
					return 1;
				else	
					return 0;
#endif
				break;
		case NID_aes_128_cbc	:
		case NID_aes_256_cbc	:
#ifdef MC2
				OPENSSL_free(temp_key);
				return 1;
#else
				OPENSSL_free(temp_key);
				if(ctx->cipher->nid == NID_aes_128_cbc )
					aes_type = AES_128;
				else {					
				if(ctx->cipher->nid == NID_aes_256_cbc )
					aes_type = AES_256;
				else
					return 0;
				}
				if(ctx->encrypt){
				ret = Csp1InitializeAES( CAVIUM_BLOCKING,
							  c_data->e_ctx,
							  aes_type,
							  (unsigned char *)iv,
							  (unsigned char *)key,
							  &req_id );
				} else {
				ret = Csp1InitializeAES( CAVIUM_BLOCKING,
							  c_data->d_ctx,
							  aes_type,
							  (unsigned char *)iv,
							  (unsigned char *)key,
							  &req_id );
				}
				if(ret == 0)
					return 1;
				else	
					return 0;
#endif			
				break;
		case NID_rc4	:
				if(ctx->encrypt)
				{		
					ret = Csp1InitializeRc4( CAVIUM_BLOCKING,
								 c_ctx->e_ctx,
								 ctx->key_len,
								 (Uint8 *)key,
								 &req_id );
				} else {
					ret = Csp1InitializeRc4( CAVIUM_BLOCKING,
								 c_ctx->d_ctx,
								 ctx->key_len,
								 (Uint8 *)key,
								 &req_id );
				}
#ifndef MC2
				OPENSSL_free(temp_key);
#endif			
				if(ret == 0)
					return 1;
				else
					return 0;							 
		default 	:
				break;
				
	}
	return 0;	
}

int cavium_do_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out,const unsigned char *in,unsigned int inln){
	Uint32 req_id;
	struct cipher_data *ciph_data=NULL;
	struct cipher_ctx *ciph_ctx=NULL;
	int ret = 0;
	AesType aes_type;
#ifdef MC2
	unsigned char *iiv;
	unsigned char saved_iv[25];
#endif
	if(!inln)
		return 0;
	if(ctx->cipher->block_size >1)
		ciph_data=(struct cipher_data *)ctx->cipher_data;
	else 	
		ciph_ctx=(struct cipher_ctx *)ctx->cipher_data;
	switch(ctx->cipher->nid){
		case NID_des_ede3_cbc	: 
		case NID_des_cbc	: 
				if((inln%ctx->cipher->block_size) != 0)
					return 0;
#ifdef MC2
				if(!ctx->encrypt){
					iiv=(void *)in+inln - ctx->cipher->iv_len;
					memcpy(saved_iv,iiv,ctx->cipher->iv_len);
				}
#endif
				if(ctx->encrypt){
					ret = Csp1Encrypt3Des( CAVIUM_BLOCKING,
								ciph_data->e_ctx,
#ifdef MC2
								CAVIUM_NO_UPDATE,
#else
								CAVIUM_UPDATE,
#endif
								inln,
								(Uint8 *)in,
								(Uint8 *)out,
#ifdef MC2
								(Uint8 *)ctx->iv,
								(Uint8 *)ciph_data->e_key,
#endif
								&req_id );
				} else {
					ret = Csp1Decrypt3Des( 	CAVIUM_BLOCKING,
							      	ciph_data->d_ctx,
#ifdef MC2
								CAVIUM_NO_UPDATE,
#else
								CAVIUM_UPDATE,
#endif
								inln,
								(Uint8 *)in,
								(Uint8 *)out,
#ifdef MC2 
								(Uint8 *)ctx->iv,
								(Uint8 *)ciph_data->d_key,
#endif
								&req_id );
				}
				if(ret)
					return 0;
#ifdef MC2
				if(ctx->encrypt)
					iiv = (void *)out+ inln -ctx->cipher->iv_len;
				else
					iiv = saved_iv;
					memcpy(ctx->iv,iiv,ctx->cipher->iv_len);
#endif
				return 1;
		case NID_aes_128_cbc	: 
		case NID_aes_256_cbc	: 
				if((inln%ctx->cipher->block_size) != 0)
					return 0;
				 if(ctx->cipher->nid == NID_aes_128_cbc)
					aes_type = AES_128;
				else{
				if(ctx->cipher->nid == NID_aes_256_cbc)
					aes_type = AES_256;
				else
					return 0;
				}
#ifdef MC2
				if(!ctx->encrypt){
					iiv=(void *)in+inln - ctx->cipher->iv_len;
					memcpy(saved_iv,iiv,ctx->cipher->iv_len);
				}
#endif
				if(ctx->encrypt){
					ret = Csp1EncryptAes( CAVIUM_BLOCKING,
								ciph_data->e_ctx,
#ifdef MC2
								CAVIUM_NO_UPDATE,
#else
								CAVIUM_UPDATE,
#endif
								aes_type,
								inln,
								(Uint8 *)in,
								(Uint8 *)out,
#ifdef MC2
								(Uint8 *)ctx->iv,
								(Uint8 *)ciph_data->e_key,
#endif
								&req_id );
				} else {
					ret = Csp1DecryptAes( 	CAVIUM_BLOCKING,
							      	ciph_data->d_ctx,
#ifdef MC2
								CAVIUM_NO_UPDATE,
#else
								CAVIUM_UPDATE,
#endif
								aes_type,
								inln,
								(Uint8 *)in,
								(Uint8 *)out,
#ifdef MC2 
								(Uint8 *)ctx->iv,
								(Uint8 *)ciph_data->d_key,
#endif
								&req_id );
				}
				if(ret)
					return 0;
#ifdef MC2
				if(ctx->encrypt)
					iiv = (void *)out+ inln -ctx->cipher->iv_len;
				else
					iiv = saved_iv;
					memcpy(ctx->iv,iiv,ctx->cipher->iv_len);
#endif
				return 1;
		case NID_rc4 :
				if(ctx->encrypt){
					ret = Csp1EncryptRc4(
						CAVIUM_BLOCKING,
						(Uint64)ciph_ctx->e_ctx,
						CAVIUM_UPDATE,
						inln,
						(Uint8 *)in,
						(Uint8 *)out,
						&req_id );
				} else {
					ret = Csp1EncryptRc4(
						CAVIUM_BLOCKING,
						(Uint64)ciph_ctx->d_ctx,
						CAVIUM_UPDATE,
						inln,
						(Uint8 *)in,
						(Uint8 *)out,
						&req_id );
				}
				if(ret)
					return 0;
				else 
					return 1;
				break;
		default		: 
				break;	
	}
	return 0;
						
}
int cavium_cleanup(EVP_CIPHER_CTX *ctx){
	struct cipher_data *ciph_data;
	struct cipher_ctx *ciph_ctx;
	if(ctx->cipher->block_size >1){
		ciph_data =(struct cipher_data *)ctx->cipher_data;
		if(ctx->encrypt){
			if(ciph_data->e_key){
				OPENSSL_free(ciph_data->e_key);		
				ciph_data->e_key=NULL;
			}
			if(ciph_data->e_ctx){
				Csp1FreeContext(CONTEXT_SSL, ciph_data->e_ctx);
				ciph_data->e_ctx=(Uint64)0;
			}
				
		}else{
			if(ciph_data->d_key){
				OPENSSL_free(ciph_data->d_key);	
				ciph_data->d_key = NULL;
			}
			if(ciph_data->d_ctx){
				Csp1FreeContext(CONTEXT_SSL, ciph_data->d_ctx);
				ciph_data->d_ctx=(Uint64)0;
			}
		}	
	}else{
		ciph_ctx =(struct cipher_ctx *)ctx->cipher_data;
		if(ctx->encrypt && ciph_ctx->e_ctx) {
			Csp1FreeContext(CONTEXT_SSL, ciph_ctx->e_ctx);
			ciph_ctx->e_ctx =(Uint64)0;
		}
		if(!ctx->encrypt && ciph_ctx->d_ctx) {
			Csp1FreeContext(CONTEXT_SSL, ciph_ctx->d_ctx);
			ciph_ctx->d_ctx = (Uint64)0;
		}
	}
	return 1;
}
int cipher_nid_to_id(int nid){
	int i;
	for(i=0;ciphers[i].id;i++){
		if(ciphers[i].nid == nid)
			return ciphers[i].id;
	} 
	return 0;
}

int cavium_get_cipher_max_iv(int id){
	int i;
	for(i=0;ciphers[i].id;i++){
		if(ciphers[i].id == id)
			return (ciphers[i].ivmax);
	}
	return 0;
}

int cavium_is_cipher_key_length_valid(int id,int len){
	int i;
	for(i=0;ciphers[i].id;i++){
		if(ciphers[i].id == id)
		{	
			if(ciphers[i].keylen == len || ciphers[i].keylen ==0 )
				return 1;
			else
				return 0;
		}
	}
	return 0;
}
const EVP_CIPHER cavium_3des_cbc = {
	NID_des_ede3_cbc,
	8, 24, 8,
	EVP_CIPH_CBC_MODE,
	cavium_init_key,
	cavium_do_cipher,
	cavium_cleanup,
	sizeof(struct cipher_data),
	EVP_CIPHER_set_asn1_iv,
	EVP_CIPHER_get_asn1_iv,
	NULL,
	NULL
};
const EVP_CIPHER cavium_des_cbc = {
	NID_des_cbc,
	8, 8, 8,
	EVP_CIPH_CBC_MODE,
	cavium_init_key,
	cavium_do_cipher,
	cavium_cleanup,
	sizeof(struct cipher_data),
	EVP_CIPHER_set_asn1_iv,
	EVP_CIPHER_get_asn1_iv,
	NULL,
	NULL
};

const EVP_CIPHER cavium_rc4= {
	NID_rc4,
	1, 16, 0,
	EVP_CIPH_VARIABLE_LENGTH,
	cavium_init_key,
	cavium_do_cipher,
	cavium_cleanup,
	sizeof(struct cipher_ctx),
	EVP_CIPHER_set_asn1_iv,
	EVP_CIPHER_get_asn1_iv,
	NULL,
	NULL
};

const EVP_CIPHER cavium_aes_128 = {
	NID_aes_128_cbc,
	16, 16, 16,
	EVP_CIPH_CBC_MODE,
	cavium_init_key,
	cavium_do_cipher,
	cavium_cleanup,
	sizeof(struct cipher_data),
	EVP_CIPHER_set_asn1_iv,
	EVP_CIPHER_get_asn1_iv,
	NULL,
	NULL
};

const EVP_CIPHER cavium_aes_256 = {
	NID_aes_256_cbc,
	16, 32, 16,
	EVP_CIPH_CBC_MODE,
	cavium_init_key,
	cavium_do_cipher,
	cavium_cleanup,
	sizeof(struct cipher_data),
	EVP_CIPHER_set_asn1_iv,
	EVP_CIPHER_get_asn1_iv,
	NULL,
	NULL
};

static int cavium_engine_ciphers(ENGINE *e, const EVP_CIPHER **cipher, const int **nids, int nid)
{
	if (!cipher)
		return (get_cavium_ciphers(nids));

	switch (nid) {
	case NID_des_ede3_cbc	:
			*cipher = &cavium_3des_cbc;
			break;
	case NID_des_cbc	:
			*cipher = &cavium_des_cbc;
			break;
	case NID_aes_128_cbc	:
			*cipher = &cavium_aes_128;
			break;
	case NID_aes_256_cbc	:
			*cipher = &cavium_aes_256;
			break;
	case NID_rc4		:
			*cipher = &cavium_rc4;
			break;
	default:
			*cipher = NULL;
			break;
	}
	if(*cipher == NULL)
		return 0;
	return 1;
}
		
int get_cavium_ciphers(const int **cnids)
{
	static int nids[MAX_SUPPORTED_CIPHERS];
	int i, count = 0;

	for (i = 0; ciphers[i].id && count < MAX_SUPPORTED_CIPHERS; i++) {
		if (ciphers[i].nid == NID_undef)
			continue;
		nids[count++] = ciphers[i].nid;
	}
	if (count > 0)
		*cnids = nids;
	else
		*cnids = NULL;
	return (count);
}

#endif


#ifdef CAVIUM_DIGEST

static const EVP_MD cavium_sha_md=
	{
	NID_sha1,
	NID_sha1WithRSAEncryption,
	SHA_DIGEST_LENGTH,
	0,
	cavium_digest_init,
	cavium_digest_update,
	cavium_digest_final,
	cavium_digest_copy,
	cavium_digest_cleanup,
	EVP_PKEY_RSA_method,
	SHA_CBLOCK,
	sizeof(EVP_MD)+sizeof(struct digest_st),
	};
static const EVP_MD cavium_md5_md=
	{
	NID_md5,
	NID_md5WithRSAEncryption,
	MD5_DIGEST_LENGTH,
	0,
	cavium_digest_init,
	cavium_digest_update,
	cavium_digest_final,
	cavium_digest_copy,
	cavium_digest_cleanup,
	EVP_PKEY_RSA_method,
	MD5_CBLOCK,
	sizeof(EVP_MD)+sizeof(struct digest_st),
	};

static int
cavium_engine_digests(ENGINE *e, const EVP_MD **digest, const int **nids, int nid)
{
	if (!digest)
		return (get_cavium_digests(nids));
	switch (nid) {
	case NID_sha1 :
		*digest = &cavium_sha_md; 
		break;
	case NID_md5 :
		*digest = &cavium_md5_md; 
		break;
	default:
		*digest = NULL;
		break;
	}
	return (*digest != NULL);
}

int get_cavium_digests(const int **cnids)
{
	static int nids[MAX_SUPPORTED_DIGESTS];
	int i, count = 0;
	for (i = 0; digests[i].id && count < MAX_SUPPORTED_DIGESTS; i++) {
		if (digests[i].nid == NID_undef)
			continue;
		nids[count++] = digests[i].nid;
	}
	if (count > 0)
		*cnids = nids;
	else
		*cnids = NULL;
	return (count);
}


int cavium_digest_init(EVP_MD_CTX *ctx){
	struct digest_st *digest_buf=(struct digest_st *)ctx->md_data;
	digest_buf->data=(unsigned char *)OPENSSL_malloc(4000);
	memset(digest_buf->data,0,4000);
	digest_buf->len = 0;
	digest_buf->size=4000;
	return 1;
}

int cavium_digest_update(EVP_MD_CTX *ctx,const void *data, size_t count){
	struct digest_st *digest_buf=(struct digest_st *)ctx->md_data;
	if(digest_buf->data==NULL)
	{
		printf("\n There is no data buffer \n");
		return 0;
	}
	switch(ctx->digest->type){
		case NID_sha1	:
		case NID_md5	:
				while((digest_buf->len+count) > digest_buf->size){
					digest_buf->data=(unsigned char *)OPENSSL_realloc(digest_buf->data,(digest_buf->size+1000));
					if(digest_buf->data == NULL)
						return 0;
					digest_buf->size+=1000;
				}	
				memcpy(&digest_buf->data[digest_buf->len],data,count);
				digest_buf->len+=count;
				return 1;
		default 	: break;
				
	}	
	return 0;
}

int cavium_digest_final(EVP_MD_CTX *ctx, unsigned char *md){
	int ret=0;
	Uint32 req_id;
#ifndef MC2
	unsigned char md5[100];
	unsigned char sha[100];
	Uint64 temp_ctx;
#endif
	struct digest_st *digest_buf=(struct digest_st *)ctx->md_data;
	switch(ctx->digest->type){
#ifdef MC2
		case NID_sha1	:
				if(digest_buf->len >32768)
				{
					printf("\n Can't Handle this much data ");
					return 0;
				}
				 ret = Csp1Hash( CAVIUM_BLOCKING,
						  SHA1_TYPE,
						  digest_buf->len,
						  digest_buf->data,
						  md,
						  &req_id);
				if(ret)
					return 0;
				else			
					return 1;
		case NID_md5	:
				if(digest_buf->len >32768)
				{
					printf("\n Can't Handle this much data ");
					return 0;
				}
				  ret = Csp1Hash( CAVIUM_BLOCKING,
						  MD5_TYPE,
						  digest_buf->len,
						  digest_buf->data,
						  md,
						  &req_id);
				if(ret)
					return 0;
				else			
					return 1;
	
#else
		case NID_sha1	:
		case NID_md5	:
				if(Csp1AllocContext(CONTEXT_SSL,&temp_ctx))
					return 0;
				ret = Csp1HandshakeStart( CAVIUM_BLOCKING,
						    temp_ctx,
						    0,
						    NULL,
						    &req_id);
				if(ret)
				return 0;
				ret = Csp1HandshakeUpdate( CAVIUM_BLOCKING,
						     temp_ctx,
						    digest_buf->len,
						    digest_buf->data,
						    &req_id);	
				if(ret)
				return 0;
				ret = Csp1HandshakeFinish( CAVIUM_BLOCKING,
						    temp_ctx,
						    0,
						    NULL,
						    md5,
						    sha,
						   &req_id);
						    
				Csp1FreeContext(CONTEXT_SSL,temp_ctx);
				if(!ret){
					if(ctx->digest->type == NID_sha1){
						memcpy(md,sha,20);
					}
					else{
						memcpy(md,md5,16);
					}
					return 1;
				}
				else 	return 0;
#endif
		default :
				return 0;
	}
	return 0;
}
int cavium_digest_cleanup(EVP_MD_CTX *ctx)
{
	struct digest_st *digest_buf=(struct digest_st *)ctx->md_data;
	if(digest_buf->data)
	{
		OPENSSL_free(digest_buf->data);
		digest_buf->size=0;
		digest_buf->len = 0;
	}
	return 1;
}

int cavium_digest_copy(EVP_MD_CTX *out, const EVP_MD_CTX *in)
{
	struct digest_st *in_buf=(struct digest_st *)in->md_data;
	struct digest_st *out_buf=(struct digest_st *)out->md_data;
	if(in_buf->data)
	{
		out_buf->data=(unsigned char *)OPENSSL_malloc(in_buf->size);
		if(out_buf->data == NULL)
			return 0;
		memcpy(out_buf->data,in_buf->data,in_buf->len);
		out_buf->len=in_buf->len;		
		out_buf->size=in_buf->size;		
	}
	return 1;
}
#endif


static int cavium_init(ENGINE *e)
{
#ifdef NPLUS
	if(Csp1Initialize(CAVIUM_DIRECT,SSL_SPM_IDX))
#else
	if(Csp1Initialize(CAVIUM_DIRECT))
#endif
	{
		return 0;	
	}
	default_rsa=(RSA_METHOD *)RSA_PKCS1_SSLeay();
	if(default_rsa == NULL)
		return 0;
	return 1;
}



static int cavium_shutdown(ENGINE *e)
{
	Csp1Shutdown();
	return 1;
}

#ifndef OPENSSL_NO_RSA

int cav_rsa_sign(int type, const unsigned char *m, unsigned int m_len,unsigned char *sigret, unsigned int *siglen, const RSA *rsa)
        {
        X509_SIG sig;
        ASN1_TYPE parameter;
        int i,j,ret=1;
        unsigned char *p, *tmps = NULL;
        const unsigned char *s = NULL;
        X509_ALGOR algor;
        ASN1_OCTET_STRING digest;
	RSA *temp = NULL;

        if((rsa->flags & RSA_FLAG_SIGN_VER) && rsa->meth->rsa_sign)
                {
                return rsa->meth->rsa_sign(type, m, m_len,
                        sigret, siglen, rsa);
                }
        /* Special case: SSL signature, just check the length */
        if(type == NID_md5_sha1) {
                if(m_len != ENGINE_SIG_LENGTH) {
                        RSAerr(RSA_F_RSA_SIGN,RSA_R_INVALID_MESSAGE_LENGTH);
                        return(0);
                }
                i = ENGINE_SIG_LENGTH;
                s = m;
        } else {
                sig.algor= &algor;
                sig.algor->algorithm=OBJ_nid2obj(type);
                if (sig.algor->algorithm == NULL)
                        {
                        RSAerr(RSA_F_RSA_SIGN,RSA_R_UNKNOWN_ALGORITHM_TYPE);
                        return(0);
                        }
                if (sig.algor->algorithm->length == 0)
                     {
                        RSAerr(RSA_F_RSA_SIGN,RSA_R_THE_ASN1_OBJECT_IDENTIFIER_IS_NOT_KNOWN_FOR_THIS_MD);
                        return(0);
                     }
                parameter.type=V_ASN1_NULL;
                parameter.value.ptr=NULL;
                sig.algor->parameter= &parameter;
     
	        sig.digest= &digest;
                sig.digest->data=(unsigned char *)m; /* TMP UGLY CAST */
                sig.digest->length=m_len;
                                                                                                                             
                i=i2d_X509_SIG(&sig,NULL);
        }
        j=RSA_size(rsa);
        if (i > (j-RSA_PKCS1_PADDING_SIZE))
                {
                RSAerr(RSA_F_RSA_SIGN,RSA_R_DIGEST_TOO_BIG_FOR_RSA_KEY);
                return(0);
                }
        if(type != NID_md5_sha1) {
                tmps=(unsigned char *)OPENSSL_malloc((unsigned int)j+1);
                if (tmps == NULL)
                        {
                        RSAerr(RSA_F_RSA_SIGN,ERR_R_MALLOC_FAILURE);
                        return(0);
                        }
                p=tmps;
                i2d_X509_SIG(&sig,&p);
                s=tmps;
        }
	temp = (RSA *)rsa;
        i=cav_rsa_priv_enc(i,s,sigret,temp,RSA_PKCS1_PADDING);
        if (i <= 0)
                ret=0;
        else
              *siglen=i;
                                                                                                                             
        if(type != NID_md5_sha1) {
                OPENSSL_cleanse(tmps,(unsigned int)j+1);
                OPENSSL_free(tmps);
        }
        return(ret);
}


int cav_rsa_verify(int dtype, const unsigned char *m, unsigned int m_len,unsigned char *sigbuf, unsigned int siglen, const RSA *rsa)
        {
        int i,ret=0,sigtype;
        unsigned char *s;
        const unsigned char *p;
        X509_SIG *sig=NULL;
	RSA *temp = NULL;
                                                                                                                             
        if (siglen != (unsigned int)RSA_size(rsa))
                {
                RSAerr(RSA_F_RSA_VERIFY,RSA_R_WRONG_SIGNATURE_LENGTH);
                return(0);
                }
                                                                                                                             
        if((rsa->flags & RSA_FLAG_SIGN_VER) && rsa->meth->rsa_verify)
                {
                return rsa->meth->rsa_verify(dtype, m, m_len,
                        sigbuf, siglen, rsa);
                }
                                                                                                                             
        s=(unsigned char *)OPENSSL_malloc((unsigned int)siglen);
        if (s == NULL)
                {
                RSAerr(RSA_F_RSA_VERIFY,ERR_R_MALLOC_FAILURE);
                goto err;
                }
        if((dtype == NID_md5_sha1) && (m_len != ENGINE_SIG_LENGTH) ) {
                        RSAerr(RSA_F_RSA_VERIFY,RSA_R_INVALID_MESSAGE_LENGTH);
                        return(0);
        }
	temp = (RSA *)rsa;
        i=cav_rsa_pub_dec((int)siglen,sigbuf,s,temp,RSA_PKCS1_PADDING);

        if (i <= 0) goto err;

        /* Special case: SSL signature */
        if(dtype == NID_md5_sha1) {
                if((i != ENGINE_SIG_LENGTH) || memcmp(s, m, ENGINE_SIG_LENGTH))
                                RSAerr(RSA_F_RSA_VERIFY,RSA_R_BAD_SIGNATURE);
                else ret = 1;
        } else {
                p=s;
                sig=d2i_X509_SIG(NULL,&p,(long)i);
                                                                                                                             
                if (sig == NULL) goto err;
                sigtype=OBJ_obj2nid(sig->algor->algorithm);
        
#ifdef RSA_DEBUG
                /* put a backward compatibility flag in EAY */
                fprintf(stderr,"in(%s) expect(%s)\n",OBJ_nid2ln(sigtype),
                        OBJ_nid2ln(dtype));
#endif
                if (sigtype != dtype)
                        {
                        if (((dtype == NID_md5) &&
                                (sigtype == NID_md5WithRSAEncryption)) ||
                                ((dtype == NID_md2) &&
                                (sigtype == NID_md2WithRSAEncryption)))
                                {
                                /* ok, we will let it through */
#if !defined(OPENSSL_NO_STDIO) && !defined(OPENSSL_SYS_WIN16)
                                fprintf(stderr,"signature has problems, re-make with post SSLeay045\n");
#endif
                                }
                        else
                                {
                                RSAerr(RSA_F_RSA_VERIFY,
                                                RSA_R_ALGORITHM_MISMATCH);
                                goto err;
                                }
                        }
                if (    ((unsigned int)sig->digest->length != m_len) ||
                        (memcmp(m,sig->digest->data,m_len) != 0))
                        {
                        RSAerr(RSA_F_RSA_VERIFY,RSA_R_BAD_SIGNATURE);
                        }
                else
                        ret=1;
        }
err:
        if (sig != NULL) X509_SIG_free(sig);
        OPENSSL_cleanse(s,(unsigned int)siglen);
        OPENSSL_free(s);
        return(ret);
        }

static int cav_rsa_pub_enc(int flen,const unsigned char *from, unsigned char *to,RSA *rsa,int padding)
{
	int ret=0;
	#if 0
	if(padding == RSA_PKCS1_PADDING)
	{
		ret=pkp_rsa_public_encrypt(flen,(unsigned char *)from,to,rsa);
		if(!ret)
			ret=default_rsa->rsa_pub_enc(flen,from,to,rsa,padding);
	}
	else
	#endif
	{
		ret=default_rsa->rsa_pub_enc(flen,from,to,rsa,padding);
	}
	return ret;
}
static int cav_rsa_pub_dec(int flen,const unsigned char *from, unsigned char *to,RSA *rsa,int padding)
{
	int ret=0;
	if(padding == RSA_PKCS1_PADDING)
	{
		ret=pkp_rsa_public_decrypt(flen,(unsigned char *)from,to,rsa);
		if(!ret)
		ret=default_rsa->rsa_pub_dec(flen,from,to,rsa,padding);
	}
	else
	{
		ret=default_rsa->rsa_pub_dec(flen,from,to,rsa,padding);
	}
	return ret;
}
static int cav_rsa_priv_enc(int flen,const unsigned char *from, unsigned char *to,RSA *rsa,int padding)
{
	int ret=0;
	if(padding == RSA_PKCS1_PADDING)
	{
		ret=pkp_rsa_private_encrypt(flen,(unsigned char *)from,to,rsa);
		if(!ret)
		ret=default_rsa->rsa_priv_enc(flen,from,to,rsa,padding);
	}
	else
	{
		ret=default_rsa->rsa_priv_enc(flen,from,to,rsa,padding);
	}
	return ret;
}
static int cav_rsa_priv_dec(int flen,const unsigned char *from, unsigned char *to,RSA *rsa,int padding)
{
	int ret=0;
	if(padding == RSA_PKCS1_PADDING)
	{
		ret=pkp_rsa_private_decrypt(flen,(unsigned char *)from,to,rsa);
		if(!ret)
		ret=default_rsa->rsa_priv_dec(flen,from,to,rsa,padding);
	}
	else
	{
		ret=default_rsa->rsa_priv_dec(flen,from,to,rsa,padding);
	}
	return ret;
}

int cav_bn_mod_exp(BIGNUM *r, const BIGNUM *a,const BIGNUM *p,const BIGNUM *m, BN_CTX *ctx,BN_MONT_CTX *m_ctx)
{
	if(cav_mod_exp(r,(BIGNUM *)a, (BIGNUM *)p,(BIGNUM *)m))
		return 1;
	return 0;
	
}
static RSA_METHOD cavium_rsa={
	"Cavium RSA method",
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	0,
	NULL,
	NULL,
	NULL
	};
#endif

#ifndef OPENSSL_NO_DSA
static DSA_METHOD cavium_dsa={
	"Cavium DSA method ",
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	0,
	NULL
};
int cav_dsa_bn_mod_exp(DSA *dsa, BIGNUM *r, BIGNUM *a, const BIGNUM *p,const BIGNUM *m, BN_CTX *ctx,BN_MONT_CTX *m_ctx) 
{
	if(cav_mod_exp(r,(BIGNUM *)a, (BIGNUM *)p,(BIGNUM *)m))
		return 1;
	return 0;
}
#endif
#ifndef OPENSSL_NO_DH
static DH_METHOD cavium_dh={
	"Cavium DH Method",
	NULL,	
	NULL,	
	NULL,	
	NULL,	
	NULL,	
	0,
	NULL
};
int cav_dh_bn_mod_exp(const DH *dh, BIGNUM *r, const BIGNUM *a,const BIGNUM *p, const BIGNUM *m, BN_CTX *ctx,BN_MONT_CTX *m_ctx) 
{
	if(cav_mod_exp(r,(BIGNUM *)a, (BIGNUM *)p,(BIGNUM *)m))
		return 1;
	return 0;
}
#endif

static RAND_METHOD cavium_rand =
	{
	NULL, /* seed */
	NULL, /* get random bytes from the card */
	NULL, /* cleanup */
	NULL, /* add */
	NULL, /* pseudo rand */
	NULL, /* status */
	};

int cavium_rand_bytes(unsigned char *buf, int num){
	Uint32  req_id;
	if(Csp1Random(0, num, buf, &req_id)){
		return 0;
	}
	return 1;
}

int cavium_bind_helper(ENGINE *e)
{
	const RAND_METHOD *meth2;
	const RSA_METHOD *meth1;
	const DSA_METHOD  *meth3;
	const DH_METHOD   *meth4;
	if(!ENGINE_set_id(e,cavium_engine_id) ||
		!ENGINE_set_name(e,cavium_engine_name) ||
#ifndef OPENSSL_NO_RSA
		!ENGINE_set_RSA(e,&cavium_rsa) ||
#endif
#ifndef OPENSSL_NO_DSA
		!ENGINE_set_DSA(e,&cavium_dsa) ||
#endif
#ifndef OPENSSL_NO_DH
		!ENGINE_set_DH(e,&cavium_dh) ||
#endif
		!ENGINE_set_RAND(e,&cavium_rand) ||
		!ENGINE_set_init_function(e,cavium_init) ||
		!ENGINE_set_ctrl_function(e, cavium_ctrl) ||
#ifdef CAVIUM_CIPHERS
		!ENGINE_set_ciphers(e,cavium_engine_ciphers) ||
#endif
#ifdef CAVIUM_DIGEST
 		!ENGINE_set_digests(e, cavium_engine_digests)	||
#endif
		!ENGINE_set_finish_function(e,cavium_shutdown))
	{
		return 0;
	}
#ifndef OPENSSL_NO_RSA
	meth1 = RSA_PKCS1_SSLeay();
	cavium_rsa.bn_mod_exp	= 	cav_bn_mod_exp;
	cavium_rsa.rsa_mod_exp 	=	meth1->rsa_mod_exp;
	cavium_rsa.rsa_pub_enc	=	cav_rsa_pub_enc;
	cavium_rsa.rsa_pub_dec	=	cav_rsa_pub_dec;
	cavium_rsa.rsa_priv_enc	=	cav_rsa_priv_enc;
	cavium_rsa.rsa_priv_dec	=	cav_rsa_priv_dec;
	cavium_rsa.rsa_sign	=	cav_rsa_sign;
	cavium_rsa.rsa_verify	=	cav_rsa_verify;
#endif
#ifndef OPENSSL_NO_DSA
	meth3 = DSA_get_default_method();
	cavium_dsa.dsa_do_sign 		= meth3->dsa_do_sign;
	cavium_dsa.dsa_sign_setup 	= meth3->dsa_sign_setup;
	cavium_dsa.dsa_do_verify 	= meth3->dsa_do_verify;
	cavium_dsa.dsa_mod_exp 		= meth3->dsa_mod_exp;
	cavium_dsa.bn_mod_exp 		= cav_dsa_bn_mod_exp;
	cavium_dsa.init			= meth3->init;
	cavium_dsa.finish		= meth3->finish;
	cavium_dsa.flags		= meth3->flags;
	cavium_dsa.app_data		= meth3->app_data;
	
#endif
#ifndef OPENSSL_NO_DH
	meth4 = DH_get_default_method();
	cavium_dh.generate_key 	= meth4->generate_key;
	cavium_dh.compute_key	= meth4->compute_key;
        cavium_dh.bn_mod_exp   	= cav_dh_bn_mod_exp;	
	cavium_dh.init		= meth4->init;
	cavium_dh.finish	= meth4->finish;
    	cavium_dh.flags		= meth4->flags;
	cavium_dh.app_data	= meth4->app_data;	
#endif
	meth2=RAND_SSLeay();
	cavium_rand.seed	=	meth2->seed;
	//cavium_rand.bytes	=	cavium_rand_bytes;
	cavium_rand.bytes	=	meth2->bytes;
	cavium_rand.cleanup	=	meth2->cleanup;
	cavium_rand.add		=	meth2->add;
	//cavium_rand.pseudorand	=	cavium_rand_bytes;
	cavium_rand.pseudorand	=	meth2->pseudorand;
	cavium_rand.status	=	meth2->status;

	return 1;
}


ENGINE *engine_cavium(void)
{
	ENGINE *ret = ENGINE_new();
	if(!ret)
		return NULL;
	if(!cavium_bind_helper(ret)){
		ENGINE_free(ret);
		return NULL;
	}	
	return ret;
}
void ENGINE_load_cavium()
{
	ENGINE *to_add = engine_cavium();
	if(!to_add)
		return;
	ENGINE_add(to_add);
	ENGINE_free(to_add);
	ERR_clear_error();
}

#ifdef ENGINE_DYNAMIC_SUPPORT
static int bind_fn(ENGINE *e,const char *id)
{
	if(id && strcmp(id,cavium_engine_id)!=0){
		return 0;
	}
	if(!cavium_bind_helper(e)){
		return 0;
	}
	return 1;
}
IMPLEMENT_DYNAMIC_CHECK_FN()
/*IMPLEMENT_DYNAMIC_BIND_FN(bind_fn)*/
int bind_engine(ENGINE *e, const char *id, const dynamic_fns *fns) { 
	if (ERR_get_implementation() != fns->err_fns) 
	{ 
	if(!CRYPTO_set_mem_functions(fns->mem_fns.malloc_cb, 
				fns->mem_fns.realloc_cb, fns->mem_fns.free_cb)) 				return 0; 
	CRYPTO_set_locking_callback(fns->lock_fns.lock_locking_cb); 
	CRYPTO_set_add_lock_callback(fns->lock_fns.lock_add_lock_cb); 
	CRYPTO_set_dynlock_create_callback(fns->lock_fns.dynlock_create_cb); 
	CRYPTO_set_dynlock_lock_callback(fns->lock_fns.dynlock_lock_cb); 
	CRYPTO_set_dynlock_destroy_callback(fns->lock_fns.dynlock_destroy_cb); 
	if(!CRYPTO_set_ex_data_implementation(fns->ex_data_fns)) 
		return 0; 
	} 
	if(!bind_fn(e,id)) return 0; 
	return 1; 
}
#endif

#endif
