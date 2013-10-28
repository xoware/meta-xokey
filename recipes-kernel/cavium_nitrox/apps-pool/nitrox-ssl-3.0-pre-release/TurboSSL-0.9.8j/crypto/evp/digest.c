/* crypto/evp/digest.c */
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
 * Copyright (c) 1998-2001 The OpenSSL Project.  All rights reserved.
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

#include <stdio.h>
#include "cryptlib.h"
#include <openssl/objects.h>
#include <openssl/evp.h>
#ifndef OPENSSL_NO_ENGINE
#include <openssl/engine.h>
#endif
#include "evp_locl.h"
#ifndef CAVIUM_SSL
#include <openssl/md5.h>
#ifndef CAVIUM_FIPS
#include "cavium_common.h"
#include "cavium_ssl.h"
#endif
#endif

void EVP_MD_CTX_init(EVP_MD_CTX *ctx)
	{
	memset(ctx,'\0',sizeof *ctx);
	}

EVP_MD_CTX *EVP_MD_CTX_create(void)
	{
	EVP_MD_CTX *ctx=OPENSSL_malloc(sizeof *ctx);

	EVP_MD_CTX_init(ctx);

	return ctx;
	}

int EVP_DigestInit(EVP_MD_CTX *ctx, const EVP_MD *type)
	{
	EVP_MD_CTX_init(ctx);
	return EVP_DigestInit_ex(ctx, type, NULL);
	}

#ifdef OPENSSL_FIPS

/* The purpose of these is to trap programs that attempt to use non FIPS
 * algorithms in FIPS mode and ignore the errors.
 */

static int bad_init(EVP_MD_CTX *ctx)
	{ FIPS_ERROR_IGNORED("Digest init"); return 0;}

static int bad_update(EVP_MD_CTX *ctx,const void *data,size_t count)
	{ FIPS_ERROR_IGNORED("Digest update"); return 0;}

static int bad_final(EVP_MD_CTX *ctx,unsigned char *md)
	{ FIPS_ERROR_IGNORED("Digest Final"); return 0;}

static const EVP_MD bad_md =
	{
	0,
	0,
	0,
	0,
	bad_init,
	bad_update,
	bad_final,
	NULL,
	NULL,
	NULL,
	0,
	{0,0,0,0},
	};

#endif

#ifndef OPENSSL_NO_ENGINE

#ifdef OPENSSL_FIPS

static int do_engine_null(ENGINE *impl) { return 0;}
static int do_evp_md_engine_null(EVP_MD_CTX *ctx,
				const EVP_MD **ptype, ENGINE *impl)
	{ return 1; }

static int (*do_engine_init)(ENGINE *impl)
		= do_engine_null;

static int (*do_engine_finish)(ENGINE *impl)
		= do_engine_null;

static int (*do_evp_md_engine)
	(EVP_MD_CTX *ctx, const EVP_MD **ptype, ENGINE *impl)
		= do_evp_md_engine_null;

void int_EVP_MD_set_engine_callbacks(
	int (*eng_md_init)(ENGINE *impl),
	int (*eng_md_fin)(ENGINE *impl),
	int (*eng_md_evp)
		(EVP_MD_CTX *ctx, const EVP_MD **ptype, ENGINE *impl))
	{
	do_engine_init = eng_md_init;
	do_engine_finish = eng_md_fin;
	do_evp_md_engine = eng_md_evp;
	}

#else

#define do_engine_init	ENGINE_init
#define do_engine_finish ENGINE_finish

static int do_evp_md_engine(EVP_MD_CTX *ctx, const EVP_MD **ptype, ENGINE *impl)
	{
	if (*ptype)
		{
		/* Ensure an ENGINE left lying around from last time is cleared
		 * (the previous check attempted to avoid this if the same
		 * ENGINE and EVP_MD could be used). */
		if(ctx->engine)
			ENGINE_finish(ctx->engine);
		if(impl)
			{
			if (!ENGINE_init(impl))
				{
				EVPerr(EVP_F_DO_EVP_MD_ENGINE,EVP_R_INITIALIZATION_ERROR);
				return 0;
				}
			}
		else
			/* Ask if an ENGINE is reserved for this job */
			impl = ENGINE_get_digest_engine((*ptype)->type);
		if(impl)
			{
			/* There's an ENGINE for this job ... (apparently) */
			const EVP_MD *d = ENGINE_get_digest(impl, (*ptype)->type);
			if(!d)
				{
				/* Same comment from evp_enc.c */
				EVPerr(EVP_F_DO_EVP_MD_ENGINE,EVP_R_INITIALIZATION_ERROR);
				return 0;
				}
			/* We'll use the ENGINE's private digest definition */
			*ptype = d;
			/* Store the ENGINE functional reference so we know
			 * 'type' came from an ENGINE and we need to release
			 * it when done. */
			ctx->engine = impl;
			}
		else
			ctx->engine = NULL;
		}
	else
	if(!ctx->digest)
		{
		EVPerr(EVP_F_DO_EVP_MD_ENGINE,EVP_R_NO_DIGEST_SET);
		return 0;
		}
	return 1;
	}

#endif

#endif

int EVP_DigestInit_ex(EVP_MD_CTX *ctx, const EVP_MD *type, ENGINE *impl)
	{
	M_EVP_MD_CTX_clear_flags(ctx,EVP_MD_CTX_FLAG_CLEANED);
#ifdef OPENSSL_FIPS
	if(FIPS_selftest_failed())
		{
		FIPSerr(FIPS_F_EVP_DIGESTINIT_EX,FIPS_R_FIPS_SELFTEST_FAILED);
		ctx->digest = &bad_md;
		return 0;
		}
#endif
#ifndef OPENSSL_NO_ENGINE
	/* Whether it's nice or not, "Inits" can be used on "Final"'d contexts
	 * so this context may already have an ENGINE! Try to avoid releasing
	 * the previous handle, re-querying for an ENGINE, and having a
	 * reinitialisation, when it may all be unecessary. */
	if (ctx->engine && ctx->digest && (!type ||
			(type && (type->type == ctx->digest->type))))
		goto skip_to_init;
	if (!do_evp_md_engine(ctx, &type, impl))
		return 0;
#endif
	if (ctx->digest != type)
		{
#ifdef OPENSSL_FIPS
		if (FIPS_mode())
			{
			if (!(type->flags & EVP_MD_FLAG_FIPS) 
			 && !(ctx->flags & EVP_MD_CTX_FLAG_NON_FIPS_ALLOW))
				{
				EVPerr(EVP_F_EVP_DIGESTINIT_EX, EVP_R_DISABLED_FOR_FIPS);
				ctx->digest = &bad_md;
				return 0;
				}
			}
#endif
		if (ctx->digest && ctx->digest->ctx_size)
			OPENSSL_free(ctx->md_data);
		ctx->digest=type;
		if (type->ctx_size)
			ctx->md_data=OPENSSL_malloc(type->ctx_size);
		}
#ifndef OPENSSL_NO_ENGINE
	skip_to_init:
#endif
	return ctx->digest->init(ctx);
	}


#ifndef CAVIUM_SSL
void EVP_Copy_Pad(EVP_MD_CTX *ctx,unsigned char *pad) 
{
    if(EVP_MD_CTX_type(ctx) == NID_sha1) 
    {
        SHA_CTX *c = (SHA_CTX *)ctx->md_data;
        ltoc(&(pad[0]),c->h0,1);
        ltoc(&(pad[4]),c->h1,1);
        ltoc(&(pad[8]),c->h2,1);
        ltoc(&(pad[12]),c->h3,1);
        ltoc(&(pad[16]),c->h4,1);
    }
    else if(EVP_MD_CTX_type(ctx) == NID_md5) 
    {
        MD5_CTX *c = (MD5_CTX *)ctx->md_data;
        ltoc(&(pad[0]),c->A,0);
        ltoc(&(pad[4]),c->B,0);
        ltoc(&(pad[8]),c->C,0);
        ltoc(&(pad[12]),c->D,0);
    }
}


void EVP_Digest_new_init(EVP_MD_CTX *ctx,unsigned char *pad) 
{
    if(EVP_MD_CTX_type(ctx) == NID_sha1) 
	{
        SHA_CTX *c =(SHA_CTX *)ctx->md_data;

        c->h0 = (SHA_LONG) ctol(&(pad[0]),1);
        c->h1 = (SHA_LONG) ctol(&(pad[4]),1);
        c->h2 = (SHA_LONG) ctol(&(pad[8]),1);
        c->h3 = (SHA_LONG) ctol(&(pad[12]),1);
        c->h4 = (SHA_LONG) ctol(&(pad[16]),1);
        c->Nl = (SHA_LONG)512;
        c->Nh = (SHA_LONG) 0;
    }
    else if(EVP_MD_CTX_type(ctx) == NID_md5) 
	{
        MD5_CTX *c =(MD5_CTX *)ctx->md_data;

        c->A = (MD5_LONG) ctol(&(pad[0]),0);
        c->B = (MD5_LONG) ctol(&(pad[4]),0);
        c->C = (MD5_LONG) ctol(&(pad[8]),0);
        c->D = (MD5_LONG) ctol(&(pad[12]),0);
        c->Nl = (MD5_LONG)512;
        c->Nh = (MD5_LONG) 0;
    }
}


unsigned long ctol(unsigned char *c,int is_sha)
{
    unsigned long l;

    if(is_sha)
        l =  ((((unsigned long)(c[0])) << 24) |
              (((unsigned long)(c[1])) << 16) |
              (((unsigned long)(c[2])) <<  8) |
              (((unsigned long)(c[3])) <<  0));
    else
        l = ((((unsigned long)(c[0])) << 0) |
             (((unsigned long)(c[1])) << 8) |
             (((unsigned long)(c[2])) << 16) |
             (((unsigned long)(c[3])) << 24));
    return l;
 }

void ltoc(unsigned char *s,unsigned long l,int is_sha) 
{
    if(is_sha) {
        s[0] = (unsigned char)((l >> 24) & 0xff);
        s[1] = (unsigned char)((l >> 16) & 0xff);
        s[2] = (unsigned char)((l >>  8) & 0xff);
        s[3] = (unsigned char)((l >>  0) & 0xff);
    }
    else {
        s[0] = (unsigned char)((l >> 0) & 0xff);
        s[1] = (unsigned char)((l >> 8 ) & 0xff);
        s[2] = (unsigned char)((l >> 16) & 0xff);
        s[3] = (unsigned char)((l >> 24) & 0xff);
    }
}

#endif

int EVP_DigestUpdate(EVP_MD_CTX *ctx, const void *data,
	     size_t count)
	{
#ifdef OPENSSL_FIPS
	FIPS_selftest_check();
#endif
	return ctx->digest->update(ctx,data,count);
	}

/* The caller can assume that this removes any secret data from the context */
int EVP_DigestFinal(EVP_MD_CTX *ctx, unsigned char *md, unsigned int *size)
	{
	int ret;
	ret = EVP_DigestFinal_ex(ctx, md, size);
	EVP_MD_CTX_cleanup(ctx);
	return ret;
	}

/* The caller can assume that this removes any secret data from the context */
int EVP_DigestFinal_ex(EVP_MD_CTX *ctx, unsigned char *md, unsigned int *size)
	{
	int ret;
#ifdef OPENSSL_FIPS
	FIPS_selftest_check();
#endif

	OPENSSL_assert(ctx->digest->md_size <= EVP_MAX_MD_SIZE);
	ret=ctx->digest->final(ctx,md);
	if (size != NULL)
		*size=ctx->digest->md_size;
	if (ctx->digest->cleanup)
		{
		ctx->digest->cleanup(ctx);
		M_EVP_MD_CTX_set_flags(ctx,EVP_MD_CTX_FLAG_CLEANED);
		}
	memset(ctx->md_data,0,ctx->digest->ctx_size);
	return ret;
	}

int EVP_MD_CTX_copy(EVP_MD_CTX *out, const EVP_MD_CTX *in)
	{
	EVP_MD_CTX_init(out);
	return EVP_MD_CTX_copy_ex(out, in);
	}

int EVP_MD_CTX_copy_ex(EVP_MD_CTX *out, const EVP_MD_CTX *in)
	{
	unsigned char *tmp_buf;
	if ((in == NULL) || (in->digest == NULL))
		{
		EVPerr(EVP_F_EVP_MD_CTX_COPY_EX,EVP_R_INPUT_NOT_INITIALIZED);
		return 0;
		}
#ifndef OPENSSL_NO_ENGINE
	/* Make sure it's safe to copy a digest context using an ENGINE */
	if (in->engine && !do_engine_init(in->engine))
		{
		EVPerr(EVP_F_EVP_MD_CTX_COPY_EX,ERR_R_ENGINE_LIB);
		return 0;
		}
#endif

	if (out->digest == in->digest)
		{
		tmp_buf = out->md_data;
	    	M_EVP_MD_CTX_set_flags(out,EVP_MD_CTX_FLAG_REUSE);
		}
	else tmp_buf = NULL;
	EVP_MD_CTX_cleanup(out);
	memcpy(out,in,sizeof *out);

	if (out->digest->ctx_size)
		{
		if (tmp_buf) out->md_data = tmp_buf;
		else out->md_data=OPENSSL_malloc(out->digest->ctx_size);
		memcpy(out->md_data,in->md_data,out->digest->ctx_size);
		}

	if (out->digest->copy)
		return out->digest->copy(out,in);
	
	return 1;
	}
#if 0 //jjose
#if defined(CAVIUM_SSL) && !defined(CAVIUM_FIPS)
static int evp_pkp_device_state=1;
#endif
#endif //jjose
int EVP_Digest(const void *data, size_t count,
		unsigned char *md, unsigned int *size, const EVP_MD *type, ENGINE *impl)
	{
	EVP_MD_CTX ctx;
	int ret;
#ifndef CAVIUM_SSL
#ifndef CAVIUM_FIPS
        Uint32 req_id;
        int driver_open = 0;
#ifdef CAVIUM_MULTICARD_API
        int driver_ready = Csp1GetDriverState(CAVIUM_DEV_ID);
#else
        int driver_ready = Csp1GetDriverState();
#endif

        if(driver_ready == -1)
        {

#ifdef CAVIUM_MULTICARD_API
                if(Csp1Initialize(CAVIUM_DIRECT,CAVIUM_DEV_ID))
#else
                if(Csp1Initialize(CAVIUM_DIRECT))
#endif

                   evp_pkp_device_state=0;     /*return 0;*/
                else
                   driver_open = 1;
        }
if(evp_pkp_device_state)
{
#ifdef MC2
        switch(type->type)
        {
                case NID_sha1   :
                                ret = Csp1Hash( CAVIUM_BLOCKING,
                                                  SHA1_TYPE,
                                                  (Uint16)count,
                                                  (Uint8 *)data,
                                                  (Uint8 *)md,
#ifdef CAVIUM_MULTICARD_API
                                                  &req_id,CAVIUM_DEV_ID
#else
                                                  &req_id
#endif
                                                );
                                if(ret)
                                        ret = 0;
                                else{
                                        if(size)
                                                *size =20;
                                        ret = 1;
                                }
                                break;
                case NID_md5    :
                                ret = Csp1Hash( CAVIUM_BLOCKING,
                                                  MD5_TYPE,
                                                  (Uint16)count,
                                                  (Uint8 *)data,
                                                  (Uint8 *)md,
#ifdef CAVIUM_MULTICARD_API
                                                  &req_id,CAVIUM_DEV_ID
#else
                                                  &req_id
#endif
                                                );
                                if(ret)
                                        ret =0;
                                else{
                                        if(size)
                                                *size =16;
                                        ret=1;
                                }
                                break;
                default         :
                                EVP_MD_CTX_init(&ctx);
                                EVP_MD_CTX_set_flags(&ctx,EVP_MD_CTX_FLAG_ONESHOT);
                                ret=EVP_DigestInit_ex(&ctx, type, impl)
                                         && EVP_DigestUpdate(&ctx, data, count)
                                         && EVP_DigestFinal_ex(&ctx, md, size);
                                EVP_MD_CTX_cleanup(&ctx);
                                break;
        }

#else
{
        Uint64 temp_ctx;
        unsigned char md5[16],sha[20];
        if(type->type == NID_sha1 || type->type==NID_md5)
        {
#ifdef CAVIUM_MULTICARD_API
                if(Csp1AllocContext(CONTEXT_SSL,&temp_ctx,CAVIUM_DEV_ID))
#else
                if(Csp1AllocContext(CONTEXT_SSL,&temp_ctx))
#endif
                        return 0;
                ret = Csp1HandshakeStart( CAVIUM_BLOCKING,
                                          temp_ctx,
                                          0,
                                          NULL,
#ifdef CAVIUM_MULTICARD_API
                                                  &req_id,CAVIUM_DEV_ID
#else
                                                  &req_id
#endif
                                                );
                if(ret)
                        return 0;
                ret = Csp1HandshakeUpdate(CAVIUM_BLOCKING,
                                          temp_ctx,
                                          (Uint16)count,
                                          (Uint8 *)data,
#ifdef CAVIUM_MULTICARD_API
                                                  &req_id,CAVIUM_DEV_ID
#else
                                                  &req_id
#endif
                                                );
                if(ret)
                        return 0;
                ret = Csp1HandshakeFinish( CAVIUM_BLOCKING,
                                           temp_ctx,
                                           0,
                                           NULL,
                                           md5,
                                           sha,
#ifdef CAVIUM_MULTICARD_API
                                                  &req_id,CAVIUM_DEV_ID
#else
                                                  &req_id
#endif
                                                );
#ifdef CAVIUM_MULTICARD_API
                Csp1FreeContext(CONTEXT_SSL,temp_ctx,CAVIUM_DEV_ID);
#else
                Csp1FreeContext(CONTEXT_SSL,temp_ctx);
#endif
                if(!ret){
                        if(type->type == NID_sha1){
                                memcpy(md,sha,20);
                                if(size)
                                        *size=20;
                        }
                        else{
                                memcpy(md,md5,16);
                                if(size)
                                        *size=16;
                        }
                }
                return ret;
        }else{
                EVP_MD_CTX_init(&ctx);
                EVP_MD_CTX_set_flags(&ctx,EVP_MD_CTX_FLAG_ONESHOT);
                ret=EVP_DigestInit_ex(&ctx, type, impl)
                        && EVP_DigestUpdate(&ctx, data, count)
                        && EVP_DigestFinal_ex(&ctx, md, size);
                EVP_MD_CTX_cleanup(&ctx);
        }
}
#endif
        if(driver_open)
#ifdef CAVIUM_MULTICARD_API
	   Csp1Shutdown(CAVIUM_DEV_ID);
#else
	   Csp1Shutdown();
#endif
	return ret;
}
#else
        EVP_MD_CTX_init(&ctx);
        EVP_MD_CTX_set_flags(&ctx,EVP_MD_CTX_FLAG_ONESHOT);
        ret=EVP_DigestInit_ex(&ctx, type, impl)
          && EVP_DigestUpdate(&ctx, data, count)
          && EVP_DigestFinal_ex(&ctx, md, size);
        EVP_MD_CTX_cleanup(&ctx);
	return ret;
#endif 
#endif

	EVP_MD_CTX_init(&ctx);
	M_EVP_MD_CTX_set_flags(&ctx,EVP_MD_CTX_FLAG_ONESHOT);
	ret=EVP_DigestInit_ex(&ctx, type, impl)
	  && EVP_DigestUpdate(&ctx, data, count)
	  && EVP_DigestFinal_ex(&ctx, md, size);
	EVP_MD_CTX_cleanup(&ctx);

	return ret;
	}

void EVP_MD_CTX_destroy(EVP_MD_CTX *ctx)
	{
	EVP_MD_CTX_cleanup(ctx);
	OPENSSL_free(ctx);
	}

/* This call frees resources associated with the context */
int EVP_MD_CTX_cleanup(EVP_MD_CTX *ctx)
	{
	/* Don't assume ctx->md_data was cleaned in EVP_Digest_Final,
	 * because sometimes only copies of the context are ever finalised.
	 */
	if (ctx->digest && ctx->digest->cleanup
	    && !M_EVP_MD_CTX_test_flags(ctx,EVP_MD_CTX_FLAG_CLEANED))
		ctx->digest->cleanup(ctx);
	if (ctx->digest && ctx->digest->ctx_size && ctx->md_data
	    && !M_EVP_MD_CTX_test_flags(ctx, EVP_MD_CTX_FLAG_REUSE))
		{
		OPENSSL_cleanse(ctx->md_data,ctx->digest->ctx_size);
		OPENSSL_free(ctx->md_data);
		}
#ifndef OPENSSL_NO_ENGINE
	if(ctx->engine)
		/* The EVP_MD we used belongs to an ENGINE, release the
		 * functional reference we held for this reason. */
		do_engine_finish(ctx->engine);
#endif
	memset(ctx,'\0',sizeof *ctx);

	return 1;
	}
