
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


/* ssl_engine.c */
/*
 *  Author  :   Imran Badr
 *              Cavium Networks
 */


#include <openssl/buffer.h>
#include <openssl/rand.h>
#include <openssl/objects.h>
#include <openssl/evp.h>
#include <openssl/x509.h>

#if defined(linux)
#include <endian.h>
#endif

#include <netinet/in.h>

#include "ssl_locl.h"
#include "ssl_engine.h"

#include "openssl/cav_debug.h"

#ifdef CAVIUM_FIPS
#include "luna_common.h"
#include "luna_ssl.h"
#include "luna_api.h"
#include "cav_crypto_engine.h"
#else
#include "cavium_common.h"
#include "cavium_ssl.h"
#endif
Rc4Type get_Rc4_type (unsigned long id);
DesType get_Des_type (unsigned long id);
int generate_pre_master_secret (SSL * s, int modlength, unsigned char *p,
    RSA * rsa);
extern void print_hex (char *label, Uint8 * datap, int len);

int check_vryf_mac_completion (SSL * s);
/*
   int check_dec_peer_completion(
   SSL *s,
   int *ip,
   int *lenp,
   int *md_sizep,
   int *finish_sizep,
   int *is_blockp,
   unsigned short *peer_lenp,
   char *dec_peer_client_finishedp);
 */
int check_handshake_completion (SSL * s,
    int *ip,
    int *lenp,
    int *md_sizep,
    int *finish_sizep,
    int *is_blockp, char *client_finishedp, char *server_finishedp);

#ifdef WIN32
#include <stdlib.h>
#include <string.h>
#endif

//static unsigned int pkp_random_index;


int pkp_device_present = 1;
void
pkp_init (void)
{

#ifdef CAV_DEBUG
    char cav_nb_fname[100];
#endif

#ifdef CAVIUM_MULTICARD_API
    int dev_id = 0;
    Uint32 dev_cnt = 0;
    Uint8 dev_mask = 0;
#endif

    cav_printf ("pkp_init(): entry\n");
#if defined(CAVIUM_SCATTER_GATHER_MODE)
    /* initialize the API layer */
#ifndef CAVIUM_FIPS
#ifdef CAVIUM_MULTICARD_API
    if (Csp1Initialize (CAVIUM_SCATTER_GATHER, CAVIUM_DEV_ID))    /* 500 ms */
#else
    if (Csp1Initialize (CAVIUM_SCATTER_GATHER))    /* 500 ms */
#endif
#else /*FIPS*/
    if (Cfm1Initialize (500, SCATTER_GATHER))
#endif

    {
        /*exit(-1); */
        pkp_device_present = 0;
    }
#elif defined (CAVIUM_DIRECT_MODE)

    /* initialize the API layer */
#ifndef CAVIUM_FIPS
#ifdef CAVIUM_MULTICARD_API
    if (Csp1Initialize (CAVIUM_DIRECT, CAVIUM_DEV_ID))    /* 500 ms */
#else
    if (Csp1Initialize (CAVIUM_DIRECT))    /* 500 ms */
#endif
#else /*FIPS*/
    if (Cfm1Initialize (500, DIRECT))    /* 500 ms */
#endif
    {
        cav_printf ("pkp_init(): Cps1Initialize() failed. exiting\n");
        /*exit(-1); */
        pkp_device_present = 0;
    }
#else

    /* initialize the API layer */
    //if(Csp1Initialize(5000,DIRECT))  /* 5000 ms */
#ifndef CAVIUM_FIPS
#ifdef CAVIUM_MULTICARD_API
    if (Csp1Initialize (CAVIUM_DIRECT, CAVIUM_DEV_ID))
#else
    if (Csp1Initialize (CAVIUM_DIRECT))
#endif
#else
    if (Cfm1Initialize (500, DIRECT))
#endif
    {
        cav_printf ("pkp_init(): Cps1Initialize() failed. exiting\n");
        /*exit(-1); */
        pkp_device_present = 0;
    }
#endif


#ifdef CAVIUM_MULTICARD_API
    Csp1GetDevCnt (&dev_cnt, &dev_mask);
    for (dev_id = 0; dev_id < dev_cnt; dev_id++) {
        if (Csp1Initialize (CAVIUM_DIRECT, dev_id))
        {
            printf ("pkp_init(): Cps1Initialize() failed for dev%d.\n",
                dev_id);
            //cav_printf("pkp_init(): Cps1Initialize() failed for dev%d.\n",dev_id);
            exit (-1);
        }

    }
#endif


#ifdef CAV_DEBUG
    if (cav_nb_fp == NULL) {
        sprintf (cav_nb_fname, "cav_nb.log.%d", getpid ());
        //sprintf(cav_nb_fname, "/tmp/cav_nb.log.%d",1);
        if ((cav_nb_fp = fopen (cav_nb_fname, "w+")) == NULL) {
            cav_fprintf (cav_nb_fp,
                "pkp_init(): fopen(%s) failed %s <%d>\n", cav_nb_fname,
                sys_errlist[errno], errno);
        }
        setbuf (cav_nb_fp, NULL);
    }
#endif

}            /* pkp_init */


int
pkp_get_random (char *out, int len, SSL * s)
{
    cav_fprintf (cav_nb_fp, "pkp_get_random(): entry\n");

    if (!pkp_device_present)
        return 1;

    CRYPTO_r_lock (CRYPTO_LOCK_SSL);

    if ((s->random_index + len) >= PKP_RANDOM_BUFFER_SIZE) {
/* here I could have copied the bytes already in the buffer
 * and after re-filling the buffer, get the remaining bytes.
 * But that process involves two memcpy's which I want to avoid. :-) */

/* refill the buffer */
#ifdef CAVIUM_FIPS
        if (Cfm1Random (OP_BLOCKING, PKP_RANDOM_BUFFER_SIZE,
                s->random_buffer, &s->cav_req_id))
#else
#ifdef CAVIUM_MULTICARD_API
        if (Csp1Random (CAVIUM_BLOCKING, PKP_RANDOM_BUFFER_SIZE,
                s->random_buffer, &s->cav_req_id, s->dev_id))
#else
        if (Csp1Random (CAVIUM_BLOCKING, PKP_RANDOM_BUFFER_SIZE,
                s->random_buffer, &s->cav_req_id))
#endif
#endif
        {
            CRYPTO_r_unlock (CRYPTO_LOCK_SSL);
            cav_fprintf (cav_nb_fp, "pkp_get_random(): return 0\n");
            return 0;
        }

        s->random_index = 0;

    }

    memcpy (out, &s->random_buffer[s->random_index], len);
    s->random_index += len;

    CRYPTO_r_unlock (CRYPTO_LOCK_SSL);
    cav_fprintf (cav_nb_fp, "pkp_get_random(): return 0\n");
    return 1;
}


/* wrec->data is where we should get the encrypted record
   wrec->input is the source
   wrec->length is the length of source
   wrec->type has the content type
 */

void
leftfill (unsigned char input[], int length, unsigned char output[],
    int finallength)
{
    int i, j;
    memset (output, 0, finallength);
    j = finallength - 1;
    for (i = length - 1; i >= 0; i--) {
        output[j] = input[i];
        j = j - 1;
    }
}

void
swap_word_openssl (unsigned char *d, unsigned char *s, int len)
{
    int i, j;
#ifdef WIN32
    unsigned __int64 *ps;
    unsigned __int64 *pd;
#else
    unsigned long long *ps;
    unsigned long long *pd;
#endif

    j = 0;

#ifdef WIN32
    ps = (unsigned __int64 *) s;
    pd = (unsigned __int64 *) d;
#else
    ps = (unsigned long long *) s;
    pd = (unsigned long long *) d;
#endif

    for (i = (len >> 3) - 1; i >= 0; i--) {
        pd[j] = ps[i];
        j++;
    }

}



#ifdef CAVIUM_MULTICARD_API
int
store_pkey (EVP_PKEY * pkey, Uint64 * key_handle, Uint32 dev_id)
#else
int
store_pkey (EVP_PKEY * pkey, Uint64 * key_handle)
#endif
{
#ifndef CAVIUM_FIPS
#ifdef CAVIUM_CRT_MOD_EX
    int size_mod, size_q, size_eq, size_p, size_ep, size_iqmp, size_crt;
    int ret = 1;
    unsigned char *qb, *eqb, *pb, *epb, *iqmpb, *temp, *dummy;
    BIGNUM *mod, *q, *eq, *p, *ep, *iqmp;

    mod = pkey->pkey.rsa->n;

    size_mod = BN_num_bytes (mod);
    if ((size_mod < 8) || (size_mod > 2048))
        return 0;

    size_crt = size_mod / 2;

    temp = alloca (size_crt + (size_mod * 2));
    if (temp == NULL)
        return 0;
    memset (temp, 0, size_crt + (size_mod * 2));


    /* Q */
    q = pkey->pkey.rsa->q;

    qb = alloca (size_crt);
    if (qb == NULL)
        return 0;
    memset (qb, 0, size_crt);
    BN_bn2bin (q, qb);

    size_q = BN_num_bytes (q);
    if (size_q < size_crt) {
        leftfill (qb, size_q, temp, size_crt);
        memcpy (qb, temp, size_crt);
        memset (temp, 0, size_crt);
    }

    /* Eq */
    eq = pkey->pkey.rsa->dmq1;
    if (eq == NULL) {
        cav_fprintf (cav_nb_fp,
            "store_pkey(): eq = pkey->pkey.rsa->dmq1 is NULL\n");
    }

    eqb = alloca (size_crt);
    if (eqb == NULL)
        return 0;
    memset (eqb, 0, size_crt);
    BN_bn2bin (eq, eqb);

    size_eq = BN_num_bytes (eq);
    if (size_eq < size_crt) {
        leftfill (eqb, size_eq, temp, size_crt);
        memcpy (eqb, temp, size_crt);
        memset (temp, 0, size_crt);
    }


    /* P */
    p = pkey->pkey.rsa->p;

    if (p == NULL) {
        cav_fprintf (cav_nb_fp,
            "store_pkey(): p = pkey->pkey.rsa->p is NULL\n");
    }

    pb = alloca (size_crt);
    if (pb == NULL)
        return 0;
    memset (pb, 0, size_crt);
    BN_bn2bin (p, pb);

    size_p = BN_num_bytes (p);
    if (size_p < size_crt) {
        leftfill (pb, size_p, temp, size_crt);
        memcpy (pb, temp, size_crt);
        memset (temp, 0, size_crt);
    }

    /* Ep */
    ep = pkey->pkey.rsa->dmp1;

    epb = alloca (size_crt);
    if (epb == NULL)
        return 0;
    memset (epb, 0, size_crt);
    BN_bn2bin (ep, epb);

    size_ep = BN_num_bytes (ep);
    if (size_ep < size_crt) {
        leftfill (epb, size_ep, temp, size_crt);
        memcpy (epb, temp, size_crt);
        memset (temp, 0, size_crt);
    }


    /* iqmp */
    iqmp = pkey->pkey.rsa->iqmp;

    iqmpb = alloca (size_crt);
    if (iqmpb == NULL)
        return 0;
    memset (iqmpb, 0, size_crt);
    BN_bn2bin (iqmp, iqmpb);

    size_iqmp = BN_num_bytes (iqmp);
    if (size_iqmp < size_crt) {
        leftfill (iqmpb, size_iqmp, temp, size_crt);
        memcpy (iqmpb, temp, size_crt);
        memset (temp, 0, size_crt);
    }

    /* now convert all to Integer format */

    dummy = temp;

#ifdef MC2
    memcpy (dummy, qb, size_crt);
#else
    swap_word_openssl (dummy, qb, size_crt);
#endif

    dummy += size_crt;

#ifdef MC2
    memcpy (dummy, eqb, size_crt);
#else
    swap_word_openssl (dummy, eqb, size_crt);
#endif
    dummy += size_crt;

#ifdef MC2
    memcpy (dummy, pb, size_crt);
#else
    swap_word_openssl (dummy, pb, size_crt);
#endif
    dummy += size_crt;

#ifdef MC2
    memcpy (dummy, epb, size_crt);
#else
    swap_word_openssl (dummy, epb, size_crt);
#endif
    dummy += size_crt;

#ifdef MC2
    memcpy (dummy, iqmpb, size_crt);
#else
    swap_word_openssl (dummy, iqmpb, size_crt);
#endif

#ifdef CAVIUM_MULTICARD_API
    if (Csp1StoreKey (key_handle,
            (unsigned short) (size_crt + (size_mod * 2)), temp, CRT_MOD_EX,
            dev_id))
#else
    if (Csp1StoreKey (key_handle,
            (unsigned short) (size_crt + (size_mod * 2)), temp,
            CRT_MOD_EX))
#endif
    {
        ret = 0;
    }


    memset (temp, 0, size_crt + (size_mod * 2));
    return ret;


#else                            /*presumably CAVIUM_NORMAL_MOD_EX */

    int sizem, sizep, ret = 1;
    unsigned char *mb, *pb, *temp;
    BIGNUM *m, *p;

    m = pkey->pkey.rsa->n;
    p = pkey->pkey.rsa->d;

    sizem = BN_num_bytes (m);
    if ((sizem < 8) || (sizem > 2048))
        return 0;
    sizem = ((sizem + 7) / 8) * 8;
    sizep = BN_num_bytes (p);

    mb = alloca (sizem);
    if (mb == NULL)
        return 0;
    memset (mb, 0, sizem);

    pb = alloca (sizem);
    if (pb == NULL)
        return 0;
    memset (pb, 0, sizem);

    temp = alloca (sizem * 2);
    if (temp == NULL)
        return 0;
    memset (temp, 0, sizem * 2);

    BN_bn2bin (m, mb);

    BN_bn2bin (p, pb);

    if (sizep < sizem) {
        leftfill (pb, sizep, temp, sizem);
        memcpy (pb, temp, sizem);
        memset (temp, 0, sizem);
    }
#ifdef MC2
    memcpy (temp, mb, sizem);
    memcpy (temp + sizem, pb, sizem);
#else
    swap_word_openssl (temp, mb, sizem);
    swap_word_openssl (temp + sizem, pb, sizem);
#endif

#ifdef CAVIUM_MULTICARD_API
    if (Csp1StoreKey (key_handle, (unsigned short) (sizem * 2), temp,
            NORMAL_MOD_EX, dev_id))
#else
    if (Csp1StoreKey (key_handle, (unsigned short) (sizem * 2), temp,
            NORMAL_MOD_EX))
#endif
    {
        ret = 0;
    }

    memset (temp, 0, sizem * 2);
    return (ret);

#endif

#else
    return (0);
#endif
}


int
pkp_encrypt_record (SSL * s)
{

    int cipher_type, digest_type, md_size;
    int err;
    SslVersion version;
    SslPartyType ssl_party;
    AesType aes_type = 0;

    version = s->ssl_version;
    cipher_type = s->cipher_type;
    digest_type = s->digest_type;
    md_size = s->md_size;

    if (cipher_type == NID_aes_256_cbc)
        aes_type = AES_256;
    else if (cipher_type == NID_aes_128_cbc)
        aes_type = AES_128;

    if (s->server)
        ssl_party = SSL_SERVER;
    else
        ssl_party = SSL_CLIENT;

    switch (cipher_type) {
    case NID_rc4:
    case NID_rc4_40:
        switch (digest_type) {
        case NID_md5:

#ifdef CAVIUM_FIPS
            err = Cfm1EncryptRecordRc4 (s->cav_nb_mode,
                s->context_pointer,
                MD5_TYPE,
                version,
                ssl_party,
                s->s3->wrec.type,
                (unsigned short) (s->s3->wrec.length),
                s->s3->wrec.input, s->s3->wrec.data, &s->cav_req_id);
#else
            err = Csp1EncryptRecordRc4 (s->cav_nb_mode,
                s->context_pointer,
                MD5_TYPE,
                version,
                ssl_party,
                s->s3->wrec.type,
                (unsigned short) (s->s3->wrec.length),
                s->s3->wrec.input, s->s3->wrec.data,
#ifdef CAVIUM_MULTICARD_API
                &s->cav_req_id, s->dev_id
#else
                &s->cav_req_id
#endif
                );
#endif

            if (err == 0) {
                s->cav_msg_len = s->s3->wrec.length + md_size;
                break;
            } else if (err == EAGAIN) {
                cav_fprintf (cav_nb_fp, "pkp_encrypt_record(): %s\n",
                    "Csp1EncryptRecordRc4() EAGAIN");
                s->cav_crypto_state = CAV_ST_IN_ENCRYPT;
                s->cav_req_id_check_done = 0;
                s->cav_process_flag = 1;
                s->cav_saved_state = s->state;
                s->rwstate = SSL_NITROX_BUSY;
                return (0);
            } else {
                cav_fprintf (cav_nb_fp,
                    "pkp_encrypt_record(): ERROR return %d %s\n",
                    err, "from Csp1EncryptRecordRc4()");
                // -----
                return (-1);
                // -----
            }

            break;

        case NID_sha1:
#ifdef CAVIUM_FIPS
            err = Cfm1EncryptRecordRc4 (s->cav_nb_mode,
                s->context_pointer,
                SHA1_TYPE,
                version,
                ssl_party,
                s->s3->wrec.type,
                (unsigned short) s->s3->wrec.length,
                s->s3->wrec.input, s->s3->wrec.data, &s->cav_req_id);
#else

            err = Csp1EncryptRecordRc4 (s->cav_nb_mode,
                s->context_pointer,
                SHA1_TYPE,
                version,
                ssl_party,
                s->s3->wrec.type,
                (unsigned short) s->s3->wrec.length,
                s->s3->wrec.input, s->s3->wrec.data,
#ifdef CAVIUM_MULTICARD_API
                &s->cav_req_id, s->dev_id
#else
                &s->cav_req_id
#endif
                );
#endif

            if (err == 0) {
                s->cav_msg_len = s->s3->wrec.length + md_size;
                break;
            } else if (err == EAGAIN) {
                cav_fprintf (cav_nb_fp, "pkp_encrypt_record(): %s\n",
                    "Csp1EncryptRecordRc4() EAGAIN");
                s->cav_crypto_state = CAV_ST_IN_ENCRYPT;
                s->cav_req_id_check_done = 0;
                s->cav_process_flag = 1;
                s->rwstate = SSL_NITROX_BUSY;
                return (0);
            } else {
                cav_fprintf (cav_nb_fp,
                    "pkp_encrypt_record(): ERROR return %d %s\n", err,
                    "from Csp1EncryptRecordRc4()");
                // ------
                return (-1);
                // ------
            }

            break;

        default:
            return -1;
        }
        break;


    case NID_des_ede3_cbc:
    case NID_des_cbc:

        switch (digest_type) {
        case NID_md5:
#ifdef CAVIUM_FIPS
            err = Cfm1EncryptRecord3Des (s->cav_nb_mode, s->context_pointer,
                MD5_TYPE, version, ssl_party,
                s->s3->wrec.type, 0,    /* pad_length, */
                (unsigned short) s->s3->wrec.length,
                s->s3->wrec.input,
                &s->cav_msg_len, s->s3->wrec.data, &s->cav_req_id);
#else
            err = Csp1EncryptRecord3Des (s->cav_nb_mode, s->context_pointer,
                MD5_TYPE, version, ssl_party,
                s->s3->wrec.type, 0,    /* pad_length, */
                (unsigned short) s->s3->wrec.length,
                s->s3->wrec.input, &s->cav_msg_len, s->s3->wrec.data,
#ifdef CAVIUM_MULTICARD_API
                &s->cav_req_id, s->dev_id
#else
                &s->cav_req_id
#endif
                );
#endif
            if (err == 0) {
                break;
            } else if (err == EAGAIN) {
                cav_fprintf (cav_nb_fp, "pkp_encrypt_record(): %s\n",
                    "Csp1EncryptRecord3Des() EAGAIN");
                s->cav_crypto_state = CAV_ST_IN_ENCRYPT;
                s->cav_req_id_check_done = 0;
                s->cav_process_flag = 0;
                s->rwstate = SSL_NITROX_BUSY;
                return (0);
            } else {
                cav_fprintf (cav_nb_fp,
                    "pkp_encrypt_record(): ERROR return %d %s\n", err,
                    "from Csp1EncryptRecord3Des()");
                // -----
                return (-1);
                // ------
            }

            break;

        case NID_sha1:
#ifdef CAVIUM_FIPS
            err = Cfm1EncryptRecord3Des (s->cav_nb_mode, s->context_pointer,
                SHA1_TYPE, version, ssl_party,
                s->s3->wrec.type, 0,    /* pad_length, */
                (unsigned short) s->s3->wrec.length,
                s->s3->wrec.input,
                &s->cav_msg_len, s->s3->wrec.data, &s->cav_req_id);
#else
            err = Csp1EncryptRecord3Des (s->cav_nb_mode, s->context_pointer,
                SHA1_TYPE, version, ssl_party,
                s->s3->wrec.type, 0,    /* pad_length, */
                (unsigned short) s->s3->wrec.length,
                s->s3->wrec.input, &s->cav_msg_len, s->s3->wrec.data,
#ifdef CAVIUM_MULTICARD_API
                &s->cav_req_id, s->dev_id
#else
                &s->cav_req_id
#endif
                );
#endif
            if (err == 0) {
                break;
            } else if (err == EAGAIN) {
                cav_fprintf (cav_nb_fp, "pkp_encrypt_record(): %s\n",
                    "Csp1DecryptRecord3Des() EAGAIN");
                s->cav_crypto_state = CAV_ST_IN_ENCRYPT;
                s->cav_req_id_check_done = 0;
                s->cav_process_flag = 0;
                s->rwstate = SSL_NITROX_BUSY;
                return (0);
            } else {
                cav_fprintf (cav_nb_fp,
                    "pkp_encrypt_record(): ERROR return %d %s\n",
                    err, "from Csp1EncryptRecord3Des()");
                // -----
                return (-1);
                // ------
            }

            break;

        default:
            return -1;
        }
        break;


    case NID_aes_256_cbc:
    case NID_aes_128_cbc:


        if (aes_type == NID_aes_128_cbc)
            cav_fprintf (cav_nb_fp,
                "pkp_encrypt_record(): case NID_aes_128_cbc\n");
        else
            cav_fprintf (cav_nb_fp,
                "pkp_encrypt_record(): case NID_aes_256_cbc\n");


        switch (digest_type) {

        case NID_sha1:
#ifdef CAVIUM_FIPS
            err = Cfm1EncryptRecordAes (s->cav_nb_mode, s->context_pointer,
                SHA1_TYPE, version, ssl_party,
                aes_type, s->s3->wrec.type, 0,    /* pad_length, */
                (unsigned short) s->s3->wrec.length,
                s->s3->wrec.input,
                &s->cav_msg_len, s->s3->wrec.data, &s->cav_req_id);
#else
            err = Csp1EncryptRecordAes (s->cav_nb_mode, s->context_pointer,
                SHA1_TYPE, version, ssl_party,
                aes_type, s->s3->wrec.type, 0,    /* pad_length, */
                (unsigned short) s->s3->wrec.length,
                s->s3->wrec.input, &s->cav_msg_len, s->s3->wrec.data,
#ifdef CAVIUM_MULTICARD_API
                &s->cav_req_id, s->dev_id
#else
                &s->cav_req_id
#endif
                );
#endif
            if (err == 0) {
                break;
            } else if (err == EAGAIN) {
                cav_fprintf (cav_nb_fp, "pkp_encrypt_record(): %s\n",
                    "Csp1DecryptRecordAes() EAGAIN");
                s->cav_crypto_state = CAV_ST_IN_ENCRYPT;
                s->cav_req_id_check_done = 0;
                s->cav_process_flag = 0;
                s->rwstate = SSL_NITROX_BUSY;
                return (0);
            } else {
                cav_fprintf (cav_nb_fp,
                    "pkp_encrypt_record(): ERROR return %d %s\n",
                    err, "from Csp1EncryptRecordAes()");
                // -----
                return (-1);
                // ------
            }

            break;

        default:
            cav_fprintf (cav_nb_fp, "%s %s %d\n",
                "pkp_encrypt_record(): ",
                "ERROR invalid default case for digest_type", digest_type);
            return -1;

        }                        // end aes cipher

        break;


    default:
        /* do the software only encryption */
        // -----
        //return 0;
        return (-1);
        // ------
    }

    cav_fprintf (cav_nb_fp,
        "pkp_encrypt_record(): end: returning s->msg_len = %d\n",
        s->cav_msg_len);

    return (int) s->cav_msg_len;

}                                /* pkp_encrypt_record */


/* rrec->data is where we should get the decrypted record
   rrec->input is the source
   rrec->length is the length of source
   rrec->type has the content type
   Returns:
   - 0 if request has not completed.
   - >0 # of bytes in the decrypted buffer if request has completed.
 */
int
pkp_decrypt_record (SSL * s)
{
    int cipher_type, digest_type, md_size;
    Uint32 err;
    SslVersion version;
    SslPartyType ssl_party;
    AesType aes_type = 0;


    cav_fprintf (cav_nb_fp, "%s %d\n",
        "pkp_decrypt_record(): entry, s->crypto_state = ",
        s->cav_crypto_state);

    version = s->ssl_version;
    md_size = s->md_size;
    cipher_type = s->cipher_type;
    digest_type = s->digest_type;

    if (cipher_type == NID_aes_256_cbc)
        aes_type = AES_256;
    else if (cipher_type == NID_aes_128_cbc)
        aes_type = AES_128;

    if (s->server)
        ssl_party = SSL_SERVER;
    else
        ssl_party = SSL_CLIENT;

    if (s->s3->rrec.type == SSL3_RT_CHANGE_CIPHER_SPEC) {
        cav_fprintf (cav_nb_fp,
            "pkp_decrypt_record(): SSL3_RT_CHANGE_CIPHER_SPEC\n");
        s->cav_renego = 5;
    }

    switch (cipher_type) {
    case NID_rc4:
    case NID_rc4_40:

        switch (digest_type) {
        case NID_md5:

#ifdef CAVIUM_FIPS
            err = Cfm1DecryptRecordRc4 (s->cav_nb_mode,
                s->context_pointer,
                MD5_TYPE,
                version,
                ssl_party,
                s->s3->rrec.type & 0x3,
                (unsigned short) s->s3->rrec.length,
                s->s3->rrec.input, s->s3->rrec.data, &s->cav_req_id);
#else
            err = Csp1DecryptRecordRc4 (s->cav_nb_mode,
                s->context_pointer,
                MD5_TYPE,
                version,
                ssl_party,
                s->s3->rrec.type,
                (unsigned short) s->s3->rrec.length,
                s->s3->rrec.input, s->s3->rrec.data,
#ifdef CAVIUM_MULTICARD_API
                &s->cav_req_id, s->dev_id
#else
                &s->cav_req_id
#endif
                );
#endif
            if (err == 0) {
                s->cav_msg_len = s->s3->rrec.length - md_size;
                break;
            } else if (err == EAGAIN) {
                cav_fprintf (cav_nb_fp, "pkp_decrypt_record(): %s\n",
                    "Csp1DecryptRecordRc4() EAGAIN");
                s->cav_crypto_state = CAV_ST_IN_DECRYPT;
                s->cav_req_id_check_done = 0;
                s->cav_process_flag = 1;
                s->rwstate = SSL_NITROX_BUSY;
                return (0);
            } else {
                cav_fprintf (cav_nb_fp,
                    "pkp_decrypt_record(): ERROR return %ld %s\n", err,
                    "from Csp1DecryptRecordRc4()");
                // -----
                return (-1);
                // -----
            }

        case NID_sha1:

#ifdef CAVIUM_FIPS
            err = Cfm1DecryptRecordRc4 (s->cav_nb_mode,
                s->context_pointer,
                SHA1_TYPE,
                version,
                ssl_party,
                s->s3->rrec.type & 0x3,
                (unsigned short) s->s3->rrec.length,
                s->s3->rrec.input, s->s3->rrec.data, &s->cav_req_id);
#else
            err = Csp1DecryptRecordRc4 (s->cav_nb_mode,
                s->context_pointer,
                SHA1_TYPE,
                version,
                ssl_party,
                s->s3->rrec.type,
                (unsigned short) s->s3->rrec.length,
                s->s3->rrec.input, s->s3->rrec.data,
#ifdef CAVIUM_MULTICARD_API
                &s->cav_req_id, s->dev_id
#else
                &s->cav_req_id
#endif
                );
#endif
            if (err == 0) {
                s->cav_msg_len = s->s3->rrec.length - md_size;
                break;
            } else if (err == EAGAIN) {
                cav_fprintf (cav_nb_fp, "pkp_decrypt_record(): %s\n",
                    "Csp1DecryptRecordRc4() EAGAIN");
                s->cav_crypto_state = CAV_ST_IN_DECRYPT;
                s->cav_req_id_check_done = 0;
                s->cav_process_flag = 1;
                s->rwstate = SSL_NITROX_BUSY;
                return (0);
            } else {
                cav_fprintf (cav_nb_fp,
                    "pkp_decrypt_record(): ERROR return %ld %s\n",
                    err, "from Csp1DecryptRecordRc4()");
                // -----
                return (-1);
                // -----
            }

        default:
            return -1;
        }
        break;

    case NID_des_ede3_cbc:
    case NID_des_cbc:
        switch (digest_type) {
        case NID_md5:

#ifdef CAVIUM_FIPS
            err = Cfm1DecryptRecord3Des (s->cav_nb_mode,
                s->context_pointer,
                MD5_TYPE,
                version,
                ssl_party,
                s->s3->rrec.type & 0x3,
                (unsigned short) s->s3->rrec.length,
                s->s3->rrec.input,
                &s->cav_msg_len, s->s3->rrec.data, &s->cav_req_id);
#else
            err = Csp1DecryptRecord3Des (s->cav_nb_mode,
                s->context_pointer,
                MD5_TYPE,
                version,
                ssl_party,
                s->s3->rrec.type,
                (unsigned short) s->s3->rrec.length,
                s->s3->rrec.input, &s->cav_msg_len, s->s3->rrec.data,
#ifdef CAVIUM_MULTICARD_API
                &s->cav_req_id, s->dev_id
#else
                &s->cav_req_id
#endif
                );
#endif
            if (err == 0) {
                cav_fprintf (cav_nb_fp,
                    "pkp_decrypt_record(): cav_msg_len = %d\n",
                    s->cav_msg_len);
                break;
            } else if (err == EAGAIN) {
                cav_fprintf (cav_nb_fp, "pkp_decrypt_record(): %s\n",
                    "Csp1DecryptRecord3Des() EAGAIN");
                cav_fprintf (cav_nb_fp,
                    "pkp_decrypt_record(): cav_msg_len = %d\n",
                    s->cav_msg_len);
                s->cav_crypto_state = CAV_ST_IN_DECRYPT;
                s->cav_req_id_check_done = 0;
                s->cav_process_flag = 0;
                s->rwstate = SSL_NITROX_BUSY;
                return (0);
            } else {
                cav_fprintf (cav_nb_fp,
                    "pkp_decrypt_record(): ERROR return %ld %s\n",
                    err, "from Csp1DecryptRecord3Des()");
                // -----
                return (-1);
                // -----
            }


        case NID_sha1:

#ifdef CAVIUM_FIPS
            err = Cfm1DecryptRecord3Des (s->cav_nb_mode,
                s->context_pointer,
                SHA1_TYPE,
                version,
                ssl_party,
                s->s3->rrec.type & 0x3,
                (unsigned short) s->s3->rrec.length,
                s->s3->rrec.input,
                &s->cav_msg_len, s->s3->rrec.data, &s->cav_req_id);
#else
            err = Csp1DecryptRecord3Des (s->cav_nb_mode,
                s->context_pointer,
                SHA1_TYPE,
                version,
                ssl_party,
                s->s3->rrec.type,
                (unsigned short) s->s3->rrec.length,
                s->s3->rrec.input, &s->cav_msg_len, s->s3->rrec.data,
#ifdef CAVIUM_MULTICARD_API
                &s->cav_req_id, s->dev_id
#else
                &s->cav_req_id
#endif
                );
#endif
            if (err == 0) {
                cav_fprintf (cav_nb_fp,
                    "pkp_decrypt_record(): cav_msg_len = %d\n",
                    s->cav_msg_len);
                break;
            } else if (err == EAGAIN) {
                cav_fprintf (cav_nb_fp, "pkp_decrypt_record(): %s\n",
                    "Csp1DecryptRecord3Des() EAGAIN");
                cav_fprintf (cav_nb_fp,
                    "pkp_decrypt_record(): cav_msg_len = %d\n",
                    s->cav_msg_len);
                s->cav_crypto_state = CAV_ST_IN_DECRYPT;
                s->cav_req_id_check_done = 0;
                s->cav_process_flag = 0;
                s->rwstate = SSL_NITROX_BUSY;
                return (0);
            } else {
                cav_fprintf (cav_nb_fp,
                    "pkp_decrypt_record(): ERROR return %ld %s\n",
                    err, "from Csp1DecryptRecord3Des()");
                // -----
                return (-1);
                // -----
            }


        default:
            return -1;
        }
        break;


    case NID_aes_256_cbc:
    case NID_aes_128_cbc:


        if (aes_type == NID_aes_128_cbc)
            cav_fprintf (cav_nb_fp,
                "pkp_decrypt_record(): case NID_aes_128_cbc\n");
        else
            cav_fprintf (cav_nb_fp,
                "pkp_decrypt_record(): case NID_aes_256_cbc\n");

        switch (digest_type) {

        case NID_sha1:
#ifdef CAVIUM_FIPS
            err = Cfm1DecryptRecordAes (s->cav_nb_mode,
                s->context_pointer,
                SHA1_TYPE,
                version,
                ssl_party,
                aes_type,
                s->s3->rrec.type & 0x3,
                (unsigned short) s->s3->rrec.length,
                s->s3->rrec.input,
                &s->cav_msg_len, s->s3->rrec.data, &s->cav_req_id);
#else

            err = Csp1DecryptRecordAes (s->cav_nb_mode,
                s->context_pointer,
                SHA1_TYPE,
                version,
                ssl_party,
                aes_type,
                s->s3->rrec.type,
                (unsigned short) s->s3->rrec.length,
                s->s3->rrec.input, &s->cav_msg_len, s->s3->rrec.data,
#ifdef CAVIUM_MULTICARD_API
                &s->cav_req_id, s->dev_id
#else
                &s->cav_req_id
#endif
                );
#endif
            if (err == 0) {
                cav_fprintf (cav_nb_fp,
                    "pkp_decrypt_record(): cav_msg_len = %d\n",
                    s->cav_msg_len);
                break;
            } else if (err == EAGAIN) {
                cav_fprintf (cav_nb_fp, "pkp_decrypt_record(): %s\n",
                    "Csp1DecryptRecordAes() EAGAIN");
                cav_fprintf (cav_nb_fp,
                    "pkp_decrypt_record(): cav_msg_len = %d\n",
                    s->cav_msg_len);
                s->cav_crypto_state = CAV_ST_IN_DECRYPT;
                s->cav_req_id_check_done = 0;
                s->cav_process_flag = 0;
                s->rwstate = SSL_NITROX_BUSY;
                return (0);
            } else {
                cav_fprintf (cav_nb_fp,
                    "pkp_decrypt_record(): ERROR return %ld, 0x%lx, %s\n",
                    err, err, "from Csp1DecryptRecordAes()");
                // -----
                return (-1);
                // -----
            }


        default:
            cav_fprintf (cav_nb_fp, "%s %s %d\n",
                "pkp_decrypt_record(): ",
                "ERROR invalid default case for digest_type", digest_type);
            return (-1);

        }                        // end switch digest_type
        break;


    default:
        /* do the software only decryption */
        // -----
        //return 0;
        cav_fprintf (cav_nb_fp, "%s %s %d\n",
            "pkp_decrypt_record(): ",
            "ERROR invalid default case for cipher_type", cipher_type);
        return (-1);
        // -----
    }

    return (int) s->cav_msg_len;

}                                /* pkp_decrypt_record */


/*
 * We have been storing all handshake messages to s->hs_msgs[] buffer.
 * Offsets of Client finish, Client Key Exchange messages are also stored
 * in the same structure. Now that we have received Client finish message,
 * following operations have to be performed:

   1. do RSA_private_decrypt for CKE msg
   2. generate master secret
   3. generate key material
   4. decrypt client finish message
   5. verify client finish msg
   6. create handshake hash including client finish message
   7. create server finish message
   8. create final handshake hash
 */

int
pkp_handshake (SSL * s)
{
    int i, ret = 0, rc = 0;
    int is_block = 0;
    int cipher_type, digest_type;
    int modlength, handshake_len, md_size, len, finish_size;
    unsigned short peer_len;
    unsigned char *p;
    unsigned char server_finished[80], client_finished[80];
    unsigned char temp[512], dec_peer_client_finished[80];
    const EVP_MD *hash;
    const EVP_CIPHER *c;
    SSL_COMP *comp;
    HashType hash_type;
    SslVersion ssl_version;
    MasterSecretReturn master_secret_return;

    cav_fprintf (cav_nb_fp,
        "pkp_handshake(): entry, s->cav_crypto_state = %d\n",
        s->cav_crypto_state);


    if (s->cav_renego > 0 && s->reneg_flag == 0) {

        cav_fprintf (cav_nb_fp,
            "pkp_handshake(): building old change cipher spec msg\n");

        s->s3->rrec.off = 0;
        s->packet_length = 0;
        p = (unsigned char *) s->init_buf->data;
        *p = SSL3_MT_CCS;
        s->init_num = 1;
        s->init_off = 0;
        s->state = SSL3_ST_SW_CHANGE_B;

        /* SSL3_ST_CW_CHANGE_B */
        i = ssl3_do_write (s, SSL3_RT_CHANGE_CIPHER_SPEC);
        if (i <= 0) {
            s->reneg_flag = 1;
            s->state = SSL3_ST_SR_FINISHED_A;
            ret = 0;
            goto err;
        }
        s->write_cipher_active = 0;
    }

    s->session->cipher = s->s3->tmp.new_cipher;

    if (!ssl_cipher_get_evp (s->session, &c, &hash, &comp)) {
        SSLerr (SSL_F_SSL3_SETUP_KEY_BLOCK,
            SSL_R_CIPHER_OR_HASH_UNAVAILABLE);
        ret = 0;
        goto err;
    }

    digest_type = EVP_MD_type (hash);
    cipher_type = EVP_CIPHER_nid (c);
    md_size = EVP_MD_size (hash);

    if (digest_type == NID_md5)
        hash_type = MD5_TYPE;
    else if (digest_type == NID_sha1)
        hash_type = SHA1_TYPE;
    else {
        ret = 0;
        goto err;
    }

    if (s->version > SSL3_VERSION) {
        finish_size = 16;
        ssl_version = VER_TLS;
    } else {
        finish_size = 40;
        ssl_version = VER3_0;
    }



#ifndef NO_SESSION_CACHE
    if (SSL_CTX_get_session_cache_mode (s->ctx) == SSL_SESS_CACHE_OFF)
        master_secret_return = NOT_RETURNED;
    else
        master_secret_return = RETURN_ENCRYPTED;
#else
    master_secret_return = NOT_RETURNED;
#endif

    /* make p point to the CKE message */
    /* 4-byte handshake header */
    p = (unsigned char *) &(s->hs_msgs[s->client_key_exch_msg_offset + 4]);

    /* n1 has the length of the message */
    /* 4 header bytes */
    modlength =
        s->client_finish_msg_offset - s->client_key_exch_msg_offset - 4;

    if (ssl_version == VER_TLS) {
        n2s (p, i);
        if (modlength != i + 2) {
            if (!(s->options & SSL_OP_TLS_D5_BUG)) {
                SSLerr (SSL_F_SSL3_GET_CLIENT_KEY_EXCHANGE,
                    SSL_R_TLS_RSA_ENCRYPTED_VALUE_LENGTH_IS_WRONG);
                goto err;
            } else
                p -= 2;
        } else
            modlength = i;
    }

    if ((modlength % 8)) {
        ret = 0;
        goto err;
    }
#ifdef MC2
    memcpy (temp, p, modlength);
#else
    swap_word_openssl (temp, p, modlength);
#endif

    handshake_len = s->client_finish_msg_offset;


    /*
     * Check if this is not the 1st call (i.e. that this
     * call is to check for completion of a previously
     * queued cmd).
     */
    if (s->state == CAV_ST_IN_HANDSHAKE) {

        if (s->cav_crypto_state == CAV_ST_IN_HANDSHAKE) {

            rc = check_handshake_completion (s,
                &i,
                &len,
                &md_size,
                &finish_size,
                &is_block,
                (char *) client_finished, (char *) server_finished);
            if (rc == 1) {
                memcpy (s->server_finished, server_finished, 80);
                memcpy (s->client_finished, client_finished, 80);
            }
        } else if (s->cav_crypto_state == CAV_ST_IN_CHK_DEC_PEER) {

            rc = check_dec_peer_completion (s,
                &i,
                &len,
                &md_size,
                &finish_size,
                &is_block, &peer_len, (char *) dec_peer_client_finished);
            if (rc == 1) {
                cav_fprintf (cav_nb_fp, "pkp_handshake(): %s %d\n",
                    "check_handshake_completion() completed, rc = ", rc);
                goto dec_peer;
            }
        }

        if (rc == 0) {
            cav_fprintf (cav_nb_fp, "pkp_handshake(): %s\n",
                "check_handshake_completion() not completed");
            return (0);
        } else if (rc == -1) {
            cav_fprintf (cav_nb_fp, "pkp_handshake(): %s\n",
                "ERROR check_handshake_completion() failed");
            return (-1);
        }

    }                            // end if .. CAV_ST_IN_HANDSHAKE

    else {

        // 1st time call - not in crypto state

        if ((s->session->cipher->id == SSL3_CK_RSA_RC4_128_MD5)
            || (s->session->cipher->id == SSL3_CK_RSA_RC4_128_SHA)
            ||
            (s->session->cipher->id ==
                TLS1_CK_RSA_EXPORT1024_WITH_RC4_56_SHA)
            || (s->session->cipher->id ==
                TLS1_CK_RSA_EXPORT1024_WITH_RC4_56_MD5)
            || (s->session->cipher->id == SSL3_CK_RSA_RC4_40_MD5))
        {
            // RC4
            Rc4Type rc4_type = get_Rc4_type (s->session->cipher->id);

            len = finish_size + md_size;

            cav_fprintf (cav_nb_fp,
                "pkp_handshake():before Csp1RsaServerFullRc4()\n");
            cav_fprintf (cav_nb_fp,
                "pkp_handshake(): finish_size = %d, md_size = %d, len = %d\n",
                finish_size, md_size, len);

            cav_fprintf (cav_nb_fp,
                "pkp_handshake(): modlength = %d, handshake_len = %d\n",
                modlength, handshake_len);

#ifdef CAVIUM_FIPS
            i = Cfm1RsaServerFullRc4 (s->cav_nb_mode,
                s->context_pointer,
                &s->key_handle,
                hash_type,
                ssl_version,
                rc4_type,
                master_secret_return,
                (unsigned short) modlength,
                temp, s->s3->client_random, s->s3->server_random,
                /* length of meg buffer upto finished msg */
                (unsigned short) handshake_len,
                /* pointer to handshake_data */
                s->hs_msgs,
                s->client_finished,
                s->server_finished,
                s->session->master_key, &s->cav_req_id);
#else
            i = Csp1RsaServerFullRc4 (s->cav_nb_mode,
                s->context_pointer,
                &s->key_handle,
                hash_type,
                ssl_version,
                rc4_type,
                master_secret_return,
                (unsigned short) modlength,
                temp, s->s3->client_random, s->s3->server_random,
                /* length of meg buffer upto finished msg */
                (unsigned short) handshake_len,
                /* pointer to handshake_data */
                s->hs_msgs,
                s->client_finished,
                s->server_finished, s->session->master_key,
#ifdef CAVIUM_MULTICARD_API
                &s->cav_req_id, s->dev_id
#else
                &s->cav_req_id
#endif
                );

#endif
            if (i == 0) {
                // completed
                cav_fprintf (cav_nb_fp, "===>pkp_handshake(): %s\n",
                    "Csp1RsaServerFullRc4() done");
            } else if (i == EAGAIN) {

                cav_fprintf (cav_nb_fp, "pkp_handshake(): %s\n",
                    "Csp1RsaServerFullRc4() EAGAIN");

                s->cav_crypto_state = CAV_ST_IN_HANDSHAKE;

                /*
                 * Save the actual state in cav_saved_state.
                 * So we could navigate back to this
                 * function thru openSSL.
                 */
                s->cav_saved_state = s->state;
                s->state = CAV_ST_IN_HANDSHAKE;
                s->cav_req_id_check_done = 0;
                s->rwstate = SSL_NITROX_BUSY;

            }                    // end .. else i == EAGAIN
            else {
                cav_fprintf (cav_nb_fp,
                    "pkp_handshake(): ERROR return %d %s\n", i,
                    "from Csp1RsaServerFullRc4()");
            }


            if (i != 0) {
                ret = 0;
                goto err;
            }

        }                        // end if .. RC4

        else if ((s->session->cipher->id == SSL3_CK_RSA_DES_192_CBC3_SHA)
            ||
            (s->session->cipher->id ==
                TLS1_CK_RSA_EXPORT1024_WITH_DES_CBC_SHA)
            || (s->session->cipher->id == SSL3_CK_RSA_DES_40_CBC_SHA)
            || (s->session->cipher->id == SSL3_CK_RSA_DES_64_CBC_SHA)) {

            // 3DES

            DesType des_type = get_Des_type (s->session->cipher->id);

            is_block = 1;

            len = ((finish_size + md_size + 7) / 8) * 8;

            cav_fprintf (cav_nb_fp,
                "pkp_handshake(): finish_size = %d, md_size = %d, len = %d\n",
                finish_size, md_size, len);

            if (ssl_version == VER_TLS) {

                cav_fprintf (cav_nb_fp, "pkp_handshake(): %s\n",
                    "before Csp1RsaServerFull3Des()");

#ifdef CAVIUM_FIPS
                i = Cfm1RsaServerFull3Des (s->cav_nb_mode, s->context_pointer,
                    &s->key_handle,
                    hash_type, ssl_version, des_type,
                    master_secret_return,
                    RETURN_CFM_ENCRYPTED,
                    RETURN_SFM_ENCRYPTED,
                    0,    /*client_pad_length, */
                    0,    /*server_pad_length, */
                    (unsigned short) modlength,
                    temp,
                    s->s3->client_random,
                    s->s3->server_random,
                    (unsigned short) handshake_len,
                    s->hs_msgs,
                    s->client_finished,
                    s->server_finished,
                    s->session->master_key, &s->cav_req_id);
#else
                i = Csp1RsaServerFull3Des (s->cav_nb_mode, s->context_pointer,
                    &s->key_handle,
                    hash_type, ssl_version, des_type,
                    master_secret_return,
                    RETURN_CFM_ENCRYPTED,
                    RETURN_SFM_ENCRYPTED,
                    0,    /*client_pad_length, */
                    0,    /*server_pad_length, */
                    (unsigned short) modlength,
                    temp,
                    s->s3->client_random,
                    s->s3->server_random,
                    (unsigned short) handshake_len,
                    s->hs_msgs,
                    s->client_finished,
                    s->server_finished, s->session->master_key,
#ifdef CAVIUM_MULTICARD_API
                    &s->cav_req_id, s->dev_id
#else
                    &s->cav_req_id
#endif
                    );
#endif

            }                    // end if TLS
            else {
                // else ssl_version != VER_TLS
                cav_fprintf (cav_nb_fp, "pkp_handshake(): %s\n",
                    "before NOT TLS Csp1RsaServerFull3Des()");

#ifdef CAVIUM_FIPS
                i = Cfm1RsaServerFull3Des (s->cav_nb_mode, s->context_pointer,
                    &s->key_handle,
                    hash_type, ssl_version, des_type,
                    master_secret_return,
                    RETURN_CFM_UNENCRYPTED,
                    RETURN_SFM_ENCRYPTED,
                    0,    /*client_pad_length, */
                    0,    /*server_pad_length, */
                    (unsigned short) modlength,
                    temp,
                    s->s3->client_random,
                    s->s3->server_random,
                    (unsigned short) handshake_len,
                    s->hs_msgs,
                    s->client_finished,
                    s->server_finished,
                    s->session->master_key, &s->cav_req_id);
#else
                i = Csp1RsaServerFull3Des (s->cav_nb_mode, s->context_pointer,
                    &s->key_handle,
                    hash_type, ssl_version, des_type,
                    master_secret_return,
                    RETURN_CFM_UNENCRYPTED,
                    RETURN_SFM_ENCRYPTED,
                    0,    /*client_pad_length, */
                    0,    /*server_pad_length, */
                    (unsigned short) modlength,
                    temp,
                    s->s3->client_random,
                    s->s3->server_random,
                    (unsigned short) handshake_len,
                    s->hs_msgs,
                    s->client_finished,
                    s->server_finished, s->session->master_key,
#ifdef CAVIUM_MULTICARD_API
                    &s->cav_req_id, s->dev_id
#else
                    &s->cav_req_id
#endif
                    );
#endif


            }                    // end else

            if (i == 0) {
                // completed
                cav_fprintf (cav_nb_fp, "===>pkp_handshake(): %s\n",
                    "Csp1RsaServerFull3Des() done");
            } else if (i == EAGAIN) {

                cav_fprintf (cav_nb_fp, "pkp_handshake(): %s\n",
                    "Csp1RsaServerFull3Des() EAGAIN");

                s->cav_crypto_state = CAV_ST_IN_HANDSHAKE;
                s->cav_saved_state = s->state;
                s->state = CAV_ST_IN_HANDSHAKE;
                s->cav_req_id_check_done = 0;
                s->rwstate = SSL_NITROX_BUSY;

            }                    // end .. else i == EAGAIN
            else {
                cav_fprintf (cav_nb_fp,
                    "pkp_handshake(): ERROR return %d %s\n", i,
                    "from Csp1RsaServerFull3Des()");
            }

            if (i != 0) {
                ret = 0;
                goto err;
            }

        }                        // end 3DES
        else if ((s->session->cipher->id == TLS1_CK_RSA_WITH_AES_128_SHA)
            || (s->session->cipher->id == TLS1_CK_RSA_WITH_AES_256_SHA)
            ) {

            AesType aes_type = get_Aes_type (s->session->cipher->id);
            ClientFinishMessageOutput cfmo;

            cav_fprintf (cav_nb_fp, "pkp_handshake(): AES case\n");

            is_block = 1;

            len = ((finish_size + md_size + 15) / 16) * 16;

            if (ssl_version == VER_TLS) {
                cfmo = RETURN_CFM_ENCRYPTED;
            } else {
                // ssl3
                cfmo = RETURN_CFM_UNENCRYPTED;
            }

            cav_fprintf (cav_nb_fp,
                "pkp_handshake(): finish_size = %d, md_size = %d, len = %d\n",
                finish_size, md_size, len);


            if (ssl_version == VER_TLS || ssl_version == VER3_0) {

                cav_fprintf (cav_nb_fp, "pkp_handshake(): %s\n",
                    "before TLS Csp1RsaServerFullAes()");

#ifdef CAVIUM_FIPS
                i = Cfm1RsaServerFullAes (s->cav_nb_mode, s->context_pointer,
                    &s->key_handle,
                    hash_type, ssl_version, aes_type,
                    master_secret_return,
                    cfmo,    //RETURN_CFM_ENCRYPTED,
                    RETURN_SFM_ENCRYPTED,
                    0,    /*client_pad_length, */
                    0,    /*server_pad_length, */
                    (unsigned short) modlength,
                    temp,
                    s->s3->client_random,
                    s->s3->server_random,
                    (unsigned short) handshake_len,
                    s->hs_msgs,
                    s->client_finished,
                    s->server_finished,
                    s->session->master_key, &s->cav_req_id);
#else
                i = Csp1RsaServerFullAes (s->cav_nb_mode, s->context_pointer,
                    &s->key_handle,
                    hash_type, ssl_version, aes_type,
                    master_secret_return,
                    cfmo,    //RETURN_CFM_ENCRYPTED,
                    RETURN_SFM_ENCRYPTED,
                    0,    /*client_pad_length, */
                    0,    /*server_pad_length, */
                    (unsigned short) modlength,
                    temp,
                    s->s3->client_random,
                    s->s3->server_random,
                    (unsigned short) handshake_len,
                    s->hs_msgs,
                    s->client_finished,
                    s->server_finished, s->session->master_key,
#ifdef CAVIUM_MULTICARD_API
                    &s->cav_req_id, s->dev_id
#else
                    &s->cav_req_id
#endif
                    );

#endif
                if (i == 0) {
                    // completed
                    cav_fprintf (cav_nb_fp, "===>pkp_handshake(): %s\n",
                        "Csp1RsaServerFullAes() done");
                } else if (i == EAGAIN) {

                    cav_fprintf (cav_nb_fp, "pkp_handshake(): %s\n",
                        "Csp1RsaServerFullAes() EAGAIN");

                    s->cav_crypto_state = CAV_ST_IN_HANDSHAKE;
                    s->cav_saved_state = s->state;
                    s->state = CAV_ST_IN_HANDSHAKE;
                    s->cav_req_id_check_done = 0;
                    s->rwstate = SSL_NITROX_BUSY;

                }                // end .. else i == EAGAIN
                else {
                    cav_fprintf (cav_nb_fp,
                        "pkp_handshake(): ERROR return %d %s\n", i,
                        "from Csp1RsaServerFullAes()");
                }

                if (i != 0) {
                    ret = 0;
                    goto err;
                }

            }                    // end if TLS
            else {
                cav_fprintf (cav_nb_fp, "pkp_handshake(): %s\n",
                    "ERROR not tls1 or ssl3 and AES\n");
                return (0);
            }

        }                        // end else if AES
        else {
            // not RC4 and not 3DES, so error
            ret = 0;
            goto err;
        }

    }                            // end .. else .. 1st time crypto call


    cav_fprintf (cav_nb_fp, "pkp_handshake(): before memcpy()\n");

    /* now replace first four bytes of client finish message. */
    memcpy (&(s->hs_msgs[s->client_finish_msg_offset]),
        s->peer_finish_first_four, 4);

    /* compare with what we got from CSP */
    if (!is_block || ssl_version == VER_TLS) {
        cav_fprintf (cav_nb_fp, "len = %d\n", len);

        if (memcmp (&s->hs_msgs[s->client_finish_msg_offset],
                s->client_finished, len) != 0) {
            cav_fprintf (cav_nb_fp,
                "pkp_handshake(): within memcmp() ERROR\n");
            ret = 0;
            goto err;
        }
    } else {
        /* decrypt the received client finished */
        if (s->session->cipher->id == TLS1_CK_RSA_WITH_AES_128_SHA
            || s->session->cipher->id == TLS1_CK_RSA_WITH_AES_256_SHA) {
            AesType aes_type = get_Aes_type (s->session->cipher->id);

            cav_fprintf (cav_nb_fp, "pkp_handshake(): %s %s\n",
                "before Csp1DecryptRecordAes() ",
                "for decrypting client finished msg\n");


#ifdef CAVIUM_FIPS
            i = Cfm1DecryptRecordAes (s->cav_nb_mode,
                s->context_pointer,
                hash_type,
                ssl_version,
                SSL_SERVER,
                aes_type,
                HANDSHAKE,
                (unsigned short) (s->hs_msgs_len -
                    s->client_finish_msg_offset),
                &s->hs_msgs[s->client_finish_msg_offset], &peer_len,
                s->dec_peer_client_finished, &s->cav_req_id);
#else
            i = Csp1DecryptRecordAes (s->cav_nb_mode,
                s->context_pointer,
                hash_type,
                ssl_version,
                SSL_SERVER,
                aes_type,
                HANDSHAKE,
                (unsigned short) (s->hs_msgs_len -
                    s->client_finish_msg_offset),
                &s->hs_msgs[s->client_finish_msg_offset], &s->peer_len,
                s->dec_peer_client_finished,
#ifdef CAVIUM_MULTICARD_API
                &s->cav_req_id, s->dev_id
#else
                &s->cav_req_id
#endif
                );
#endif

        } else {
            // DES
            cav_fprintf (cav_nb_fp, "pkp_handshake(): %s %s\n",
                "before Csp1DecryptRecord3Des() ",
                "for decrypting client finished msg\n");

            cav_fprintf (cav_nb_fp, "pkp_handshake() s->hs_msgs: %d\n",
                (s->hs_msgs_len - s->client_finish_msg_offset));

#ifdef CAVIUM_FIPS
            i = Cfm1DecryptRecord3Des (s->cav_nb_mode,
                s->context_pointer,
                hash_type,
                ssl_version,
                SSL_SERVER,
                HANDSHAKE,
                (unsigned short) (s->hs_msgs_len -
                    s->client_finish_msg_offset),
                &s->hs_msgs[s->client_finish_msg_offset], &peer_len,
                s->dec_peer_client_finished, &s->cav_req_id);
#else
            i = Csp1DecryptRecord3Des (s->cav_nb_mode,
                s->context_pointer,
                hash_type,
                ssl_version,
                SSL_SERVER,
                HANDSHAKE,
                (unsigned short) (s->hs_msgs_len -
                    s->client_finish_msg_offset),
                &s->hs_msgs[s->client_finish_msg_offset], &s->peer_len,
                s->dec_peer_client_finished,
#ifdef CAVIUM_MULTICARD_API
                &s->cav_req_id, s->dev_id
#else
                &s->cav_req_id
#endif
                );
#endif

        }
        if (i == 0) {
            memcpy (dec_peer_client_finished, s->dec_peer_client_finished,
                s->peer_len);
            peer_len = s->peer_len;

        }
        if (i == EAGAIN) {

            cav_fprintf (cav_nb_fp, "pkp_handshake(): %s\n",
                "Csp1RsaServerFullAes() EAGAIN");
            s->cav_crypto_state = CAV_ST_IN_CHK_DEC_PEER;
            s->cav_saved_state = s->state;
            s->state = CAV_ST_IN_HANDSHAKE;
            s->cav_req_id_check_done = 0;
            s->rwstate = SSL_NITROX_BUSY;
        }
        if (i != 0) {
            ret = 0;
            goto err;
        }

      dec_peer:

        if (memcmp (dec_peer_client_finished, s->client_finished,
                peer_len) != 0) {
            cav_fprintf (cav_nb_fp,
                "pkp_handshake(): within memcmp-2() ERROR\n");
            ret = 0;
            goto err;
        }

    }                            /*isblock */

    cav_fprintf (cav_nb_fp, "pkp_handshake(): before s->s3->rrec.off=0\n");



    if (s->cav_renego == 0) {
        s->s3->rrec.off = 0;
        s->packet_length = 0;
        p = (unsigned char *) s->init_buf->data;
        *p = SSL3_MT_CCS;
        s->init_num = 1;
        s->init_off = 0;
        s->state = SSL3_ST_SW_CHANGE_B;

        /* SSL3_ST_CW_CHANGE_B */
        i = ssl3_do_write (s, SSL3_RT_CHANGE_CIPHER_SPEC);

        //BIO_flush(s->wbio);

        cav_fprintf (cav_nb_fp,
            "pkp_handshake(): sent NEW change cipher spec msg\n");
    }
    s->init_num = 0;

    /* activate cipher on the input (reading)  side */
    s->read_cipher_active = 1;

    //s->s3->tmp.peer_finish_md_len = len;

    /* SEND SERVER FINISH */
    cav_fprintf (cav_nb_fp, "pkp_handshake(): SEND SERVER FINISH\n");


    memcpy ((unsigned char *) s->init_buf->data, s->server_finished, len);
    s->init_num = len;
    s->init_off = 0;
    s->state = SSL3_ST_SW_FINISHED_B;
    i = ssl3_do_write (s, SSL3_RT_HANDSHAKE);

    /* activate cipher on the output (writing)  side */
    s->write_cipher_active = 1;

    s->state = SSL3_ST_SW_CHANGE_A;

    if ((s->enc_read_ctx == NULL) &&
        ((s->enc_read_ctx =
                (EVP_CIPHER_CTX *)
                OPENSSL_malloc (sizeof (EVP_CIPHER_CTX))) == NULL)) {
        ret = 0;
        goto err;
    }

    EVP_CIPHER_CTX_init (s->enc_read_ctx);
    s->enc_read_ctx->cipher = c;
    s->read_hash = hash;

    if ((s->enc_write_ctx == NULL) &&
        ((s->enc_write_ctx =
                (EVP_CIPHER_CTX *)
                OPENSSL_malloc (sizeof (EVP_CIPHER_CTX))) == NULL)) {
        ret = 0;
        goto err;
    }

    EVP_CIPHER_CTX_init (s->enc_write_ctx);
    s->enc_write_ctx->cipher = c;
    s->write_hash = hash;

    /* Here update some variables for record processing */
    s->ssl_version = ssl_version;

    /* I hope that client and the server are using the same cipher :-)  */
    s->cipher_type = EVP_CIPHER_CTX_nid (s->enc_write_ctx);

    /* and of course the same hash */
    s->digest_type = EVP_MD_type (hash);

    s->md_size = md_size;

    ret = 1;
    s->reneg_flag = 0;
  err:
    if (s->reneg_flag)
        return ret;

    if (s->cav_renego > 0) {
        s->cav_renego = 0;
    }

    return ret;

}                                /*pkp_handshake */


int
pkp_ephemeral_handshake (SSL * s)
{
    int i, ret = 0, rc = 0;
    int is_block = 0;
    int cipher_type, digest_type;
    int modlength, handshake_len, md_size, len, finish_size, pre_master_len = 0;
    unsigned short peer_len;
    unsigned char *p;
    unsigned char server_finished[80], client_finished[80];
    unsigned char dec_peer_client_finished[80];
    const EVP_MD *hash;
    const EVP_CIPHER *c;
    SSL_COMP *comp;
    HashType hash_type;
    SslVersion ssl_version;
    MasterSecretReturn master_secret_return;

    if (s->cav_renego > 0 && s->reneg_flag == 0) {

        cav_fprintf (cav_nb_fp,
            "pkp_ephemeral_handshake(): building old change cipher spec msg\n");

        s->s3->rrec.off = 0;
        s->packet_length = 0;
        p = (unsigned char *) s->init_buf->data;
        *p = SSL3_MT_CCS;
        s->init_num = 1;
        s->init_off = 0;
        s->state = SSL3_ST_SW_CHANGE_B;

        /* SSL3_ST_CW_CHANGE_B */
        i = ssl3_do_write (s, SSL3_RT_CHANGE_CIPHER_SPEC);
        if (i <= 0) {
            s->reneg_flag = 1;
            s->state = SSL3_ST_SR_FINISHED_A;
            ret = 0;
            goto err;
        }

        s->write_cipher_active = 0;

    }

    s->session->cipher = s->s3->tmp.new_cipher;

    if (!ssl_cipher_get_evp (s->session, &c, &hash, &comp)) {
        SSLerr (SSL_F_SSL3_SETUP_KEY_BLOCK,
            SSL_R_CIPHER_OR_HASH_UNAVAILABLE);
        ret = 0;
        goto err;
    }

    digest_type = EVP_MD_type (hash);
    cipher_type = EVP_CIPHER_nid (c);
    md_size = EVP_MD_size (hash);

    if (digest_type == NID_md5)
        hash_type = MD5_TYPE;

    else if (digest_type == NID_sha1)
        hash_type = SHA1_TYPE;

    else {
        ret = 0;
        goto err;
    }

    if (s->version > SSL3_VERSION) {
        finish_size = 16;
        ssl_version = VER_TLS;
    } else {
        finish_size = 40;
        ssl_version = VER3_0;
    }


#ifndef NO_SESSION_CACHE

    if (SSL_CTX_get_session_cache_mode (s->ctx) == SSL_SESS_CACHE_OFF)
        master_secret_return = NOT_RETURNED;
    else
        master_secret_return = RETURN_ENCRYPTED;


#else
    master_secret_return = NOT_RETURNED;
#endif



    /* make p point to the CKE message */
    p = (unsigned char *) &(s->hs_msgs[s->client_key_exch_msg_offset + 4]);    /* 4-byte handshake header */

    /* n1 has the length of the message */
    modlength = s->client_finish_msg_offset - s->client_key_exch_msg_offset - 4;    /* 4 header bytes */

    if (s->version > SSL3_VERSION) {
        n2s (p, i);
        if (modlength != i + 2) {
            if (!(s->options & SSL_OP_TLS_D5_BUG)) {
                SSLerr (SSL_F_SSL3_GET_CLIENT_KEY_EXCHANGE,
                    SSL_R_TLS_RSA_ENCRYPTED_VALUE_LENGTH_IS_WRONG);
                goto err;
            } else
                p -= 2;
        } else
            modlength = i;
    }


    if ((modlength % 8)) {
        ret = 0;
        goto err;
    }

    handshake_len = s->client_finish_msg_offset;

    /*
     * Check if this is not the 1st call (i.e. that this
     * call is to check for completion of a previously
     * queued cmd).
     */

    if (s->cav_crypto_state == CAV_ST_IN_HANDSHAKE) {

        rc = check_handshake_completion (s,
            &i,
            &len,
            &md_size,
            &finish_size,
            &is_block, (char *) client_finished, (char *) server_finished);
        if (rc == 1) {
            memcpy (s->server_finished, server_finished, 80);
            memcpy (s->client_finished, client_finished, 80);
            goto handshake;
        } else if (rc == 0) {
            cav_fprintf (cav_nb_fp, "pkp_ephemeral_handshake(): %s\n",
                "check_handshake_completion() not completed");
            return (0);
        } else if (rc == -1) {
            cav_fprintf (cav_nb_fp, "pkp_ephemeral_handshake(): %s\n",
                "ERROR check_handshake_completion() failed");
            return (-1);
        }
        cav_fprintf (cav_nb_fp, "pkp_ephemeral_handshake(): %s %d\n",
            "check_handshake_completion() completed, rc = ", rc);

    } else if (s->cav_crypto_state == CAV_ST_IN_CHK_DEC_PEER) {

        rc = check_dec_peer_completion (s,
            &i,
            &len,
            &md_size,
            &finish_size,
            &is_block, &peer_len, (char *) dec_peer_client_finished);

        if (rc == 1)
            goto dec_peer;

        else if (rc == 0) {
            cav_fprintf (cav_nb_fp, "pkp_ephemeral_handshake(): %s\n",
                "check_handshake_completion() not completed");
            return (0);
        } else if (rc == -1) {
            cav_fprintf (cav_nb_fp, "pkp_ephemeral_handshake(): %s\n",
                "ERROR check_handshake_completion() failed");
            return (-1);
        }
        cav_fprintf (cav_nb_fp, "pkp_ephemeral_handshake(): %s %d\n",
            "check_handshake_completion() completed, rc = ", rc);
    }



    /* now first decrypt CKE message */
    if (s->cav_renego > 0 && s->alloc_flag == 0) {
#ifdef CAVIUM_FIPS
        Cfm1AllocContext (OP_BLOCKING, &s->s3->tmp.ctx_ptr, &s->cav_req_id);
#else

#ifdef CAVIUM_MULTICARD_API
        Csp1AllocContext (CONTEXT_SSL, &s->s3->tmp.ctx_ptr, s->dev_id);
#else
        Csp1AllocContext (CONTEXT_SSL, &s->s3->tmp.ctx_ptr);
#endif
#endif
        s->alloc_flag = 1;
    }
    pre_master_len =
        generate_pre_master_secret (s, modlength, p, s->cert->rsa_tmp);

    if (pre_master_len != SSL_MAX_MASTER_KEY_LENGTH) {
        ret = 0;
        goto err;
    }

    if ((s->session->cipher->id == SSL3_CK_RSA_RC4_40_MD5)
        ||
        (s->session->cipher->id == TLS1_CK_RSA_EXPORT1024_WITH_RC4_56_MD5)
        ||
        (s->session->cipher->id == TLS1_CK_RSA_EXPORT1024_WITH_RC4_56_SHA))
    {

        Rc4Type rc4_type = get_Rc4_type (s->session->cipher->id);
        len = finish_size + md_size;

        if (s->cav_renego > 0) {
#ifdef CAVIUM_FIPS
            i = Cfm1OtherFullRc4 (OP_BLOCKING,
                s->s3->tmp.ctx_ptr,
                hash_type,
                ssl_version,
                rc4_type,
                master_secret_return,
                (unsigned short) pre_master_len,
                s->s3->client_random,
                s->s3->server_random,
                (unsigned short) handshake_len,
                s->hs_msgs,
                s->client_finished,
                s->server_finished, s->session->master_key, &s->cav_req_id);

#else
            i = Csp1OtherFullRc4 (s->cav_nb_mode,
                s->s3->tmp.ctx_ptr,
                hash_type,
                ssl_version,
                rc4_type,
                master_secret_return,
                (unsigned short) pre_master_len,
                s->s3->client_random,
                s->s3->server_random,
                (unsigned short) handshake_len,
                s->hs_msgs,
                s->client_finished,
                s->server_finished, s->session->master_key,
#ifdef CAVIUM_MULTICARD_API
                &s->cav_req_id, s->dev_id
#else
                &s->cav_req_id
#endif
                );
#endif
        } else {
#ifdef CAVIUM_FIPS
            i = Cfm1OtherFullRc4 (OP_BLOCKING,
                s->context_pointer,
                hash_type,
                ssl_version,
                rc4_type,
                master_secret_return,
                (unsigned short) pre_master_len,
                s->s3->client_random,
                s->s3->server_random,
                (unsigned short) handshake_len,
                s->hs_msgs,
                s->client_finished,
                s->server_finished, s->session->master_key, &s->cav_req_id);
#else
            i = Csp1OtherFullRc4 (s->cav_nb_mode,
                s->context_pointer,
                hash_type,
                ssl_version,
                rc4_type,
                master_secret_return,
                (unsigned short) pre_master_len,
                s->s3->client_random,
                s->s3->server_random,
                (unsigned short) handshake_len,
                s->hs_msgs,
                s->client_finished,
                s->server_finished, s->session->master_key,
#ifdef CAVIUM_MULTICARD_API
                &s->cav_req_id, s->dev_id
#else
                &s->cav_req_id
#endif
                );
#endif
        }
        if (i == 0) {
            // completed/
            cav_fprintf (cav_nb_fp, "===>pkp_ephemeral_handshake(): %s\n",
                "Csp1OtherFullRc4() done");
        }

        else if (i == EAGAIN) {

            cav_fprintf (cav_nb_fp, "pkp_ephemeral_handshake(): %s\n",
                "Csp1OtherFullRc4() EAGAIN");

            s->cav_crypto_state = CAV_ST_IN_HANDSHAKE;
            s->cav_saved_state = s->state;
            s->state = CAV_ST_IN_HANDSHAKE;
            s->cav_req_id_check_done = 0;
            s->rwstate = SSL_NITROX_BUSY;

        }                        //end ... else i == EAGAIN
        else {
            cav_fprintf (cav_nb_fp,
                "pkp_ephemeral_handshake(): ERROR return %d %s\n", i,
                "from Csp1OtherFullRc4()");
        }

        if (i != 0) {
            ret = 0;
            goto err;
        }
    }

    else if ((s->session->cipher->id == SSL3_CK_RSA_DES_192_CBC3_SHA)
        ||
        (s->session->cipher->id == TLS1_CK_RSA_EXPORT1024_WITH_DES_CBC_SHA)
        || (s->session->cipher->id == SSL3_CK_RSA_DES_40_CBC_SHA)
        || (s->session->cipher->id == SSL3_CK_RSA_DES_64_CBC_SHA))



    {
        DesType des_type = get_Des_type (s->session->cipher->id);
        is_block = 1;
        len = ((finish_size + md_size + 7) / 8) * 8;


        if (s->cav_renego > 0) {

            if (ssl_version == VER_TLS) {
#ifdef CAVIUM_FIPS
                i = Cfm1OtherFull3Des (OP_BLOCKING, s->s3->tmp.ctx_ptr,
                    hash_type, ssl_version, des_type,
                    master_secret_return,
                    RETURN_CFM_ENCRYPTED,
                    RETURN_SFM_ENCRYPTED,
                    0,    /*client_pad_length, */
                    0,            /*server_pad_length, */
                    (unsigned short) pre_master_len,
                    s->s3->client_random,
                    s->s3->server_random,
                    (unsigned short) handshake_len,
                    s->hs_msgs,
                    s->client_finished,
                    s->server_finished,
                    s->session->master_key, &s->cav_req_id);
#else
                i = Csp1OtherFull3Des (s->cav_nb_mode, s->s3->tmp.ctx_ptr,
                    hash_type, ssl_version, des_type,
                    master_secret_return,
                    RETURN_CFM_ENCRYPTED,
                    RETURN_SFM_ENCRYPTED,
                    0,    /*client_pad_length, */
                    0,            /*server_pad_length, */
                    (unsigned short) pre_master_len,
                    s->s3->client_random,
                    s->s3->server_random,
                    (unsigned short) handshake_len,
                    s->hs_msgs,
                    s->client_finished,
                    s->server_finished, s->session->master_key,
#ifdef CAVIUM_MULTICARD_API
                    &s->cav_req_id, s->dev_id
#else
                    &s->cav_req_id
#endif
                    );
#endif
            } else {
#ifdef CAVIUM_FIPS
                i = Cfm1OtherFull3Des (OP_BLOCKING, s->s3->tmp.ctx_ptr,
                    hash_type, ssl_version, des_type,
                    master_secret_return,
                    RETURN_CFM_UNENCRYPTED,
                    RETURN_SFM_ENCRYPTED,
                    0,    /*client_pad_length, */
                    0,            /*server_pad_length, */
                    (unsigned short) pre_master_len,
                    s->s3->client_random,
                    s->s3->server_random,
                    (unsigned short) handshake_len,
                    s->hs_msgs,
                    s->client_finished,
                    s->server_finished,
                    s->session->master_key, &s->cav_req_id);
#else
                i = Csp1OtherFull3Des (s->cav_nb_mode, s->s3->tmp.ctx_ptr,
                    hash_type, ssl_version, des_type,
                    master_secret_return,
                    RETURN_CFM_UNENCRYPTED,
                    RETURN_SFM_ENCRYPTED,
                    0,    /*client_pad_length, */
                    0,            /*server_pad_length, */
                    (unsigned short) pre_master_len,
                    s->s3->client_random,
                    s->s3->server_random,
                    (unsigned short) handshake_len,
                    s->hs_msgs,
                    s->client_finished,
                    s->server_finished, s->session->master_key,
#ifdef CAVIUM_MULTICARD_API
                    &s->cav_req_id, s->dev_id
#else
                    &s->cav_req_id
#endif
                    );
#endif
            }
        } else {
            if (ssl_version == VER_TLS) {
#ifdef CAVIUM_FIPS
                i = Cfm1OtherFull3Des (OP_BLOCKING, s->context_pointer,
                    hash_type, ssl_version, des_type,
                    master_secret_return,
                    RETURN_CFM_ENCRYPTED,
                    RETURN_SFM_ENCRYPTED,
                    0,    /*client_pad_length, */
                    0,            /*server_pad_length, */
                    (unsigned short) pre_master_len,
                    s->s3->client_random,
                    s->s3->server_random,
                    (unsigned short) handshake_len,
                    s->hs_msgs,
                    s->client_finished,
                    s->server_finished,
                    s->session->master_key, &s->cav_req_id);
#else
                i = Csp1OtherFull3Des (s->cav_nb_mode, s->context_pointer,
                    hash_type, ssl_version, des_type,
                    master_secret_return,
                    RETURN_CFM_ENCRYPTED,
                    RETURN_SFM_ENCRYPTED,
                    0,    /*client_pad_length, */
                    0,    /*server_pad_length, */
                    (unsigned short) pre_master_len,
                    s->s3->client_random,
                    s->s3->server_random,
                    (unsigned short) handshake_len,
                    s->hs_msgs,
                    s->client_finished,
                    s->server_finished, s->session->master_key,
#ifdef CAVIUM_MULTICARD_API
                    &s->cav_req_id, s->dev_id
#else
                    &s->cav_req_id
#endif
                    );
#endif
            } else {

#ifdef CAVIUM_FIPS
                i = Cfm1OtherFull3Des (OP_BLOCKING, s->context_pointer,
                    hash_type, ssl_version, des_type,
                    master_secret_return,
                    RETURN_CFM_UNENCRYPTED,
                    RETURN_SFM_ENCRYPTED,
                    0,    /*client_pad_length, */
                    0,    /*server_pad_length, */
                    (unsigned short) pre_master_len,
                    s->s3->client_random,
                    s->s3->server_random,
                    (unsigned short) handshake_len,
                    s->hs_msgs,
                    s->client_finished,
                    s->server_finished,
                    s->session->master_key, &s->cav_req_id);
#else
                i = Csp1OtherFull3Des (s->cav_nb_mode, s->context_pointer,
                    hash_type, ssl_version, des_type,
                    master_secret_return,
                    RETURN_CFM_UNENCRYPTED,
                    RETURN_SFM_ENCRYPTED,
                    0,    /*client_pad_length, */
                    0,    /*server_pad_length, */
                    (unsigned short) pre_master_len,
                    s->s3->client_random,
                    s->s3->server_random,
                    (unsigned short) handshake_len,
                    s->hs_msgs,
                    s->client_finished,
                    s->server_finished, s->session->master_key,
#ifdef CAVIUM_MULTICARD_API
                    &s->cav_req_id, s->dev_id
#else
                    &s->cav_req_id
#endif
                    );
#endif
            }
        }

        if (i == 0) {
            // completed/
            cav_fprintf (cav_nb_fp, "===>pkp_ephemeral_handshake(): %s\n",
                "Csp1OtherFullDES() done");
        }

        else if (i == EAGAIN) {

            cav_fprintf (cav_nb_fp, "pkp_ephemeral_handshake(): %s\n",
                "Csp1OtherFull3Des() EAGAIN");

            s->cav_crypto_state = CAV_ST_IN_HANDSHAKE;
            s->cav_saved_state = s->state;
            s->state = CAV_ST_IN_HANDSHAKE;
            s->cav_req_id_check_done = 0;
            s->rwstate = SSL_NITROX_BUSY;

        }                        // end .. else i == EAGAIN
        else {
            cav_fprintf (cav_nb_fp,
                "pkp_ephemeral_handshake(): ERROR return %d %s\n", i,
                "from Csp1OtherFull3Des()");
        }

        if (i != 0) {
            ret = 0;
            goto err;
        }
    }

    else {
        ret = 0;
        goto err;
    }

    /* now replace first four bytes of client finish message. */

  handshake:if (s->cav_renego > 0) {
        if (s->context_pointer) {
#ifdef CAVIUM_FIPS
            Cfm1FreeContext (OP_BLOCKING, s->context_pointer, &s->cav_req_id);
#else
#ifdef CAVIUM_MULTICARD_API
            Csp1FreeContext (CONTEXT_SSL, s->context_pointer, s->dev_id);
#else
            Csp1FreeContext (CONTEXT_SSL, s->context_pointer);
#endif
#endif
        }

        s->context_pointer = s->s3->tmp.ctx_ptr;
        s->alloc_flag = 0;
    }
    memcpy (&(s->hs_msgs[s->client_finish_msg_offset]),
        s->peer_finish_first_four, 4);

    /* compare with what we got from CSP */
    if (!is_block || ssl_version == VER_TLS) {
        if (memcmp (&s->hs_msgs[s->client_finish_msg_offset],
                s->client_finished, len) != 0) {
            cav_fprintf (cav_nb_fp,
                "pkp_ephemeral_handshake(): within memcmp() ERROR\n");
            ret = 0;
            goto err;
        }
    } else {

        /* decrypt the received client finished */
#ifdef CAVIUM_FIPS
        i = Cfm1DecryptRecord3Des (OP_BLOCKING,
            s->context_pointer,
            hash_type,
            ssl_version,
            SSL_SERVER,
            HANDSHAKE,
            (unsigned short) (s->hs_msgs_len -
                s->client_finish_msg_offset),
            &s->hs_msgs[s->client_finish_msg_offset], &peer_len,
            s->dec_peer_client_finished, &s->cav_req_id);
#else

        i = Csp1DecryptRecord3Des (s->cav_nb_mode,
            s->context_pointer,
            hash_type,
            ssl_version,
            SSL_SERVER,
            HANDSHAKE,
            (unsigned short) (s->hs_msgs_len -
                s->client_finish_msg_offset),
            &s->hs_msgs[s->client_finish_msg_offset], &s->peer_len,
            s->dec_peer_client_finished,
#ifdef CAVIUM_MULTICARD_API
            &s->cav_req_id, s->dev_id
#else
            &s->cav_req_id
#endif
            );
#endif
        if (i == 0) {

            memcpy (dec_peer_client_finished, s->dec_peer_client_finished,
                s->peer_len);
            peer_len = s->peer_len;
        }
        if (i == EAGAIN) {

            cav_fprintf (cav_nb_fp, "pkp_handshake(): %s\n",
                "Csp1RsaServerFullAes() EAGAIN");
            s->cav_crypto_state = CAV_ST_IN_CHK_DEC_PEER;

            /*
             * Save the actual state in cav_saved_state.
             * So we could navigate back to this
             * function thru openSSL.
             */
            s->cav_saved_state = s->state;
            s->state = CAV_ST_IN_HANDSHAKE;
            s->cav_req_id_check_done = 0;
            s->rwstate = SSL_NITROX_BUSY;

        }
        if (i != 0) {
            ret = 0;
            goto err;
        }

      dec_peer:if (memcmp (dec_peer_client_finished, s->client_finished,
                peer_len) != 0) {

            ret = 0;
            goto err;
        }

    }                            /*isblock */
    cav_fprintf (cav_nb_fp,
        "pkp_ephemeral_handshake(): before s->s3->rrec.off=0\n");


    if (s->cav_renego == 0) {
        s->s3->rrec.off = 0;
        s->packet_length = 0;
        p = (unsigned char *) s->init_buf->data;
        *p = SSL3_MT_CCS;
        s->init_num = 1;
        s->init_off = 0;
        s->state = SSL3_ST_SW_CHANGE_B;

        /* SSL3_ST_CW_CHANGE_B */
        i = ssl3_do_write (s, SSL3_RT_CHANGE_CIPHER_SPEC);

        //BIO_flush(s->wbio);

        cav_fprintf (cav_nb_fp,
            "pkp_ephemeral_handshake(): sent NEW change cipher spec msg\n");

    }

    s->init_num = 0;

    /* activate cipher on the input (reading)  side */
    s->read_cipher_active = 1;

    s->s3->tmp.peer_finish_md_len = len;

    /* SEND SERVER FINISH */
    cav_fprintf (cav_nb_fp,
        "pkp_ephemeral_handshake(): SEND SERVER FINISH\n");
    memcpy ((unsigned char *) s->init_buf->data, s->server_finished, len);
    s->init_num = len;
    s->init_off = 0;
    s->state = SSL3_ST_SW_FINISHED_B;
    i = ssl3_do_write (s, SSL3_RT_HANDSHAKE);

    /* activate cipher on the output (writing)  side */
    s->write_cipher_active = 1;

    s->state = SSL3_ST_SW_CHANGE_A;

    if ((s->enc_read_ctx == NULL) &&
        ((s->enc_read_ctx =
                (EVP_CIPHER_CTX *)
                OPENSSL_malloc (sizeof (EVP_CIPHER_CTX))) == NULL)) {
        ret = 0;
        goto err;
    }

    EVP_CIPHER_CTX_init (s->enc_read_ctx);
    s->enc_read_ctx->cipher = c;
    s->read_hash = hash;

    if ((s->enc_write_ctx == NULL) &&
        ((s->enc_write_ctx =
                (EVP_CIPHER_CTX *)
                OPENSSL_malloc (sizeof (EVP_CIPHER_CTX))) == NULL)) {
        ret = 0;
        goto err;
    }

    EVP_CIPHER_CTX_init (s->enc_write_ctx);
    s->enc_write_ctx->cipher = c;
    s->write_hash = hash;

    /* Here update some variables for record processing */
    s->ssl_version = ssl_version;

    /* I hope that client and the server are using the same cipher :-)  */
    s->cipher_type = EVP_CIPHER_CTX_nid (s->enc_write_ctx);

    /* abd again the same hash */
    s->digest_type = EVP_MD_type (hash);

    s->md_size = md_size;

    ret = 1;
    s->reneg_flag = 0;
  err:
    if (s->reneg_flag == 1)
        return ret;

    if (s->cav_renego > 0) {
        s->cav_renego = 0;
    }
    return ret;

}                                /* pkp_ephemeral_handshake(s); */



int
pkp_handshake_client_auth (SSL * s)
{
    int i, ret, rc = 0;
    int is_block = 0;
    int cipher_type, digest_type;
    int handshake_len, md_size, len, finish_size;
    unsigned short peer_len;
    unsigned char *p;
    unsigned char server_finished[80], client_finished[80];
    unsigned char dec_peer_client_finished[80];
    const EVP_MD *hash;
    const EVP_CIPHER *c;
    SSL_COMP *comp;
    HashType hash_type;
    SslVersion ssl_version;

    cav_fprintf (cav_nb_fp, "pkp_handshake_client_auth(): entry\n");


    if (s->cav_renego > 0 && s->reneg_flag == 0) {

        cav_fprintf (cav_nb_fp,
            "pkp_handshake(): building old change cipher spec msg\n");

        s->s3->rrec.off = 0;
        s->packet_length = 0;
        p = (unsigned char *) s->init_buf->data;
        *p = SSL3_MT_CCS;
        s->init_num = 1;
        s->init_off = 0;
        s->state = SSL3_ST_SW_CHANGE_B;

        /* SSL3_ST_CW_CHANGE_B */
        i = ssl3_do_write (s, SSL3_RT_CHANGE_CIPHER_SPEC);

        if (i <= 0) {
            s->reneg_flag = 1;
            s->state = SSL3_ST_SR_FINISHED_A;
            ret = 0;
            goto err;
        }
        //BIO_flush(s->wbio);

        cav_fprintf (cav_nb_fp,
            "pkp_handshake(): sent OLD change cipher spec msg\n");

        // so next msg is not encrypted twice
        s->write_cipher_active = 0;

    }

    s->session->cipher = s->s3->tmp.new_cipher;

    if (!ssl_cipher_get_evp (s->session, &c, &hash, &comp)) {
        SSLerr (SSL_F_SSL3_SETUP_KEY_BLOCK,
            SSL_R_CIPHER_OR_HASH_UNAVAILABLE);
        ret = 0;
        goto err;
    }

    digest_type = EVP_MD_type (hash);
    cipher_type = EVP_CIPHER_nid (c);
    md_size = EVP_MD_size (hash);

    if (digest_type == NID_md5)
        hash_type = MD5_TYPE;

    else if (digest_type == NID_sha1)
        hash_type = SHA1_TYPE;

    else {
        ret = 0;
        goto err;
    }

    if (s->version > SSL3_VERSION) {
        finish_size = 16;
        ssl_version = VER_TLS;
    } else {
        finish_size = 40;
        ssl_version = VER3_0;
    }


    /* make p point to the CertVerify msg */
    p = (unsigned char *) &(s->hs_msgs[s->client_cert_verify_msg_offset]);

    handshake_len =
        s->client_finish_msg_offset - s->client_cert_verify_msg_offset;


    /* Renegotiation Fix with client authentication */
    if (s->cav_renego > 0 && s->alloc_flag == 1) {
        cav_fprintf (cav_nb_fp,
            "pkp_handshake_client_auth():freeing the context \n");
        if (s->context_pointer) {
#ifdef CAVIUM_FIPS
            Cfm1FreeContext (OP_BLOCKING, s->context_pointer, &s->cav_req_id);
#else
#ifdef CAVIUM_MULTICARD_API
            Csp1FreeContext (CONTEXT_SSL, s->context_pointer, s->dev_id);
#else
            Csp1FreeContext (CONTEXT_SSL, s->context_pointer);
#endif
#endif
        }

        s->context_pointer = s->s3->tmp.ctx_ptr;
        s->alloc_flag = 0;
    }

    /*
     * Check if this is not the 1st call (i.e. that this
     * call is to check for completion of a previously
     * queued cmd).
     */
    if (s->state == CAV_ST_IN_HANDSHAKE) {

        if (s->cav_crypto_state == CAV_ST_IN_HANDSHAKE) {

            rc = check_handshake_completion (s,
                &i,
                &len,
                &md_size,
                &finish_size,
                &is_block,
                (char *) client_finished, (char *) server_finished);
            if (rc == 1) {
                memcpy (s->server_finished, server_finished, 80);
                memcpy (s->client_finished, client_finished, 80);
            }
        } else if (s->cav_crypto_state == CAV_ST_IN_CHK_DEC_PEER) {

            rc = check_dec_peer_completion (s,
                &i,
                &len,
                &md_size,
                &finish_size,
                &is_block, &peer_len, (char *) dec_peer_client_finished);
            if (rc == 1)
                goto dec_peer;
        }


        if (rc == 0) {
            cav_fprintf (cav_nb_fp, "pkp_handshake_client_auth(): %s\n",
                "check_handshake_completion() not completed");
            return (0);
        } else if (rc == -1) {
            cav_fprintf (cav_nb_fp, "pkp_handshake_client_auth(): %s\n",
                "ERROR check_handshake_completion() failed");
            return (-1);
        }
        cav_fprintf (cav_nb_fp, "pkp_handshake_client_auth(): %s %d\n",
            "check_handshake_completion() completed, rc = ", rc);

    }                            // end if .. CAV_ST_IN_HANDSHAKE

    else {

        if ((s->session->cipher->id == SSL3_CK_RSA_RC4_128_MD5)
            || (s->session->cipher->id == SSL3_CK_RSA_RC4_128_SHA)
            ||
            (s->session->cipher->id ==
                TLS1_CK_RSA_EXPORT1024_WITH_RC4_56_SHA)
            || (s->session->cipher->id ==
                TLS1_CK_RSA_EXPORT1024_WITH_RC4_56_MD5)
            || (s->session->cipher->id == SSL3_CK_RSA_RC4_40_MD5)) {
            len = finish_size + md_size;

#ifdef CAVIUM_FIPS
            i = Cfm1FinishedRc4Finish (OP_BLOCKING,
                s->context_pointer,
                hash_type,
                ssl_version,
                (unsigned short) handshake_len,
                p, s->client_finished, s->server_finished, &s->cav_req_id);
#else

            i = Csp1FinishedRc4Finish (s->cav_nb_mode,
                s->context_pointer,
                hash_type,
                ssl_version,
                (unsigned short) handshake_len,
                p, s->client_finished, s->server_finished,
#ifdef CAVIUM_MULTICARD_API
                &s->cav_req_id, s->dev_id
#else
                &s->cav_req_id
#endif
                );


#endif
            if (i == 0) {
                // completed/
                cav_fprintf (cav_nb_fp,
                    "===>pkp_handshake_client_auth(): %s\n",
                    "Csp1FinishedRc4Finish() done");
            }

            else if (i == EAGAIN) {

                cav_fprintf (cav_nb_fp,
                    "pkp_handshake_client_auth(): %s\n",
                    "Csp1FinishedRc4Finish() EAGAIN");

                s->cav_crypto_state = CAV_ST_IN_HANDSHAKE;
                s->cav_saved_state = s->state;
                s->state = CAV_ST_IN_HANDSHAKE;
                s->cav_req_id_check_done = 0;
                s->rwstate = SSL_NITROX_BUSY;

            }                    // end .. else i == EAGAIN
            else {
                cav_fprintf (cav_nb_fp,
                    "pkp_handshake_client_auth(): ERROR return %d %s\n", i,
                    "from Csp1FinishedRc4Finish()");
            }

            if (i != 0) {
                ret = 0;
                goto err;
            }
        } else if ((s->session->cipher->id == SSL3_CK_RSA_DES_192_CBC3_SHA)
            ||
            (s->session->cipher->id ==
                TLS1_CK_RSA_EXPORT1024_WITH_DES_CBC_SHA)
            || (s->session->cipher->id == SSL3_CK_RSA_DES_40_CBC_SHA)
            || (s->session->cipher->id == SSL3_CK_RSA_DES_64_CBC_SHA))
        {
            is_block = 1;
            len = ((finish_size + md_size + 7) / 8) * 8;

            if (ssl_version == VER_TLS) {
#ifdef CAVIUM_FIPS
                i = Cfm1Finished3DesFinish (OP_BLOCKING, s->context_pointer,
                    hash_type, ssl_version,
                    RETURN_CFM_ENCRYPTED,
                    RETURN_SFM_ENCRYPTED,
                    0,    /*client_pad_length, */
                    0,            /*server_pad_length, */
                    (unsigned short) handshake_len,
                    p,
                    s->client_finished,
                    s->server_finished,
                    &s->cav_req_id);
#else
                i = Csp1Finished3DesFinish (s->cav_nb_mode, s->context_pointer,
                    hash_type, ssl_version,
                    RETURN_CFM_ENCRYPTED,
                    RETURN_SFM_ENCRYPTED,
                    0,    /*client_pad_length, */
                    0,            /*server_pad_length, */
                    (unsigned short) handshake_len,
                    p,
                    s->client_finished,
                    s->server_finished,
#ifdef CAVIUM_MULTICARD_API
                    &s->cav_req_id, s->dev_id
#else
                    &s->cav_req_id
#endif
                    );
#endif
            } else {
#ifdef CAVIUM_FIPS
                i = Cfm1Finished3DesFinish (OP_BLOCKING, s->context_pointer,
                    hash_type, ssl_version,
                    RETURN_CFM_UNENCRYPTED,
                    RETURN_SFM_ENCRYPTED,
                    0,    /*client_pad_length, */
                    0,            /*server_pad_length, */
                    (unsigned short) handshake_len,
                    p,
                    s->client_finished,
                    s->server_finished,
                    &s->cav_req_id);
#else
                i = Csp1Finished3DesFinish (s->cav_nb_mode,
                    s->context_pointer,
                    hash_type,
                    ssl_version,
                    RETURN_CFM_UNENCRYPTED,
                    RETURN_SFM_ENCRYPTED,
                    0,    /*client_pad_length, */
                    0,            /*server_pad_length, */
                    (unsigned short) handshake_len,
                    p,
                    s->client_finished,
                    s->server_finished,
#ifdef CAVIUM_MULTICARD_API
                    &s->cav_req_id, s->dev_id
#else
                    &s->cav_req_id
#endif
                    );
#endif
            }
            if (i == 0) {
                // completed/
                cav_fprintf (cav_nb_fp,
                    "===>pkp_handshake_client_auth(): %s\n",
                    "Csp1Finished3DesFinish() done");
            }
            if (i == EAGAIN) {

                cav_fprintf (cav_nb_fp,
                    "pkp_handshake_client_auth(): %s\n",
                    "Csp1Finished3DesFinish() EAGAIN");

                s->cav_crypto_state = CAV_ST_IN_HANDSHAKE;
                s->cav_saved_state = s->state;
                s->state = CAV_ST_IN_HANDSHAKE;
                s->cav_req_id_check_done = 0;
                s->rwstate = SSL_NITROX_BUSY;

            }                    // end .. else i == EAGAIN
            else {
                cav_fprintf (cav_nb_fp,
                    "pkp_handshake_client_auth ERROR return %d %s\n", i,
                    "from Csp1Finished3DesFinish()");
            }

            if (i != 0) {
                ret = 0;
                goto err;
            }
        } else if ((s->session->cipher->id == TLS1_CK_RSA_WITH_AES_128_SHA)
            || (s->session->cipher->id == TLS1_CK_RSA_WITH_AES_256_SHA)
            ) {

            AesType aes_type = get_Aes_type (s->session->cipher->id);
            ClientFinishMessageOutput cfmo;

            cav_fprintf (cav_nb_fp,
                "pkp_handshake_client_auth(): AES case\n");

            is_block = 1;

            len = ((finish_size + md_size + 15) / 16) * 16;

            // THIS WORKS for AES128-SHA and AES256-SHA with tls
            if (ssl_version == VER_TLS) {
                cfmo = RETURN_CFM_ENCRYPTED;
            } else {
                // ssl3
                cfmo = RETURN_CFM_UNENCRYPTED;
            }

            if (ssl_version == VER_TLS || ssl_version == VER3_0) {

                cav_fprintf (cav_nb_fp,
                    "pkp_handshake_client_auth(): %s\n",
                    "before Csp1FinishedAesFinish()");
#ifdef CAVIUM_FIPS
                i = Cfm1FinishedAesFinish (OP_BLOCKING, s->context_pointer,
                    hash_type, ssl_version, aes_type,
                    cfmo,    //RETURN_CFM_ENCRYPTED,
                    RETURN_SFM_ENCRYPTED,
                    0,    /*client_pad_length, */
                    0,            /*server_pad_length, */
                    (unsigned short) handshake_len,
                    p,
                    s->client_finished,
                    s->server_finished,
                    &s->cav_req_id);

#else

                i = Csp1FinishedAesFinish (s->cav_nb_mode, s->context_pointer,
                    hash_type, ssl_version, aes_type,
                    cfmo,    //RETURN_CFM_ENCRYPTED,
                    RETURN_SFM_ENCRYPTED,
                    0,    /*client_pad_length, */
                    0,            /*server_pad_length, */
                    (unsigned short) handshake_len,
                    p,
                    s->client_finished,
                    s->server_finished,
#ifdef CAVIUM_MULTICARD_API
                    &s->cav_req_id, s->dev_id
#else
                    &s->cav_req_id
#endif
                    );

#endif
                if (i == 0) {
                    // completed/
                    cav_fprintf (cav_nb_fp,
                        "===>pkp_handshakeclient_auth(): %s\n",
                        "Csp1FinishedAesFinish() done");
                }
                if (i == EAGAIN) {

                    cav_fprintf (cav_nb_fp,
                        "pkp_handshake_client_auth(): %s\n",
                        "Csp1FinishedAesFinish() EAGAIN");

                    s->cav_crypto_state = CAV_ST_IN_HANDSHAKE;
                    s->cav_saved_state = s->state;
                    s->state = CAV_ST_IN_HANDSHAKE;
                    s->cav_req_id_check_done = 0;
                    s->rwstate = SSL_NITROX_BUSY;

                }                // end .. else i == EAGAIN
                else {
                    cav_fprintf (cav_nb_fp,
                        "pkp_handshake_client_auth(): ERROR return %d %s\n",
                        i, "from Csp1FinishedAesFinish()");
                }

                if (i != 0) {
                    ret = 0;
                    goto err;
                }
            } else {
                cav_fprintf (cav_nb_fp,
                    "pkp_handshake_client_auth(): %s\n",
                    "ERROR not tls1 or ssl3 and AES\n");
                return (0);
            }

        }                        // end else .. AES
        else {
            ret = 0;
            goto err;
        }

    }                            // end .. else .. 1st time crypto call

    /* now replace first four bytes of client finish message. */
    memcpy (&(s->hs_msgs[s->client_finish_msg_offset]),
        s->peer_finish_first_four, 4);

    /* compare with what we got from CSP */
    if (!is_block || ssl_version == VER_TLS) {
        if (memcmp (&s->hs_msgs[s->client_finish_msg_offset],
                s->client_finished, len) != 0) {
            cav_fprintf (cav_nb_fp,
                "pkp_handshake_client_auth(): memcmp failed\n");
            print_hex ("client_finished", s->client_finished, len);
            print_hex ("client_finished_msg_offset",
                &s->hs_msgs[s->client_finish_msg_offset], len);
            ret = 0;
            goto err;
        }
    } else {

        /* decrypt the received client finished */
        if (s->session->cipher->id == TLS1_CK_RSA_WITH_AES_128_SHA
            || s->session->cipher->id == TLS1_CK_RSA_WITH_AES_256_SHA) {
            // AES
            AesType aes_type = get_Aes_type (s->session->cipher->id);


#ifdef CAVIUM_FIPS
            i = Cfm1DecryptRecordAes (OP_BLOCKING,
                s->context_pointer,
                hash_type,
                ssl_version,
                SSL_SERVER,
                aes_type,
                HANDSHAKE,
                (unsigned short) (s->hs_msgs_len -
                    s->client_finish_msg_offset),
                &s->hs_msgs[s->client_finish_msg_offset], &peer_len,
                s->dec_peer_client_finished, &s->cav_req_id);
#else
            i = Csp1DecryptRecordAes (s->cav_nb_mode,
                s->context_pointer,
                hash_type,
                ssl_version,
                SSL_SERVER,
                aes_type,
                HANDSHAKE,
                (unsigned short) (s->hs_msgs_len -
                    s->client_finish_msg_offset),
                &s->hs_msgs[s->client_finish_msg_offset], &s->peer_len,
                s->dec_peer_client_finished,
#ifdef CAVIUM_MULTICARD_API
                &s->cav_req_id, s->dev_id
#else
                &s->cav_req_id
#endif
                );
#endif
        } else {
            // DES
#ifdef CAVIUM_FIPS
            i = Cfm1DecryptRecord3Des (OP_BLOCKING,
                s->context_pointer,
                hash_type,
                ssl_version,
                SSL_SERVER,
                HANDSHAKE,
                (unsigned short) (s->hs_msgs_len -
                    s->client_finish_msg_offset),
                &s->hs_msgs[s->client_finish_msg_offset], &peer_len,
                s->dec_peer_client_finished, &s->cav_req_id);
#else
            i = Csp1DecryptRecord3Des (s->cav_nb_mode,
                s->context_pointer,
                hash_type,
                ssl_version,
                SSL_SERVER,
                HANDSHAKE,
                (unsigned short) (s->hs_msgs_len -
                    s->client_finish_msg_offset),
                &s->hs_msgs[s->client_finish_msg_offset], &s->peer_len,
                s->dec_peer_client_finished,
#ifdef CAVIUM_MULTICARD_API
                &s->cav_req_id, s->dev_id
#else
                &s->cav_req_id
#endif
                );
#endif
        }                        // end else .. DES

        if (i == 0) {

            memcpy (dec_peer_client_finished, s->dec_peer_client_finished,
                s->peer_len);
            peer_len = s->peer_len;
        } else if (i == EAGAIN) {

            cav_fprintf (cav_nb_fp, "pkp_handshake_client_auth(): %s\n",
                "Csp1RsaServerFullAes() EAGAIN");
            s->cav_crypto_state = CAV_ST_IN_CHK_DEC_PEER;
            s->cav_saved_state = s->state;
            s->state = CAV_ST_IN_HANDSHAKE;
            s->cav_req_id_check_done = 0;
            s->rwstate = SSL_NITROX_BUSY;

        }
        if (i != 0) {
            ret = 0;
            goto err;
        }


      dec_peer:
        if (memcmp (dec_peer_client_finished, s->client_finished,
                peer_len) != 0) {
            cav_fprintf (cav_nb_fp,
                "pkp_handshake_client_auth():memcmp failed \n");
            ret = 0;
            goto err;
        }

    }                            /*isblock */

    /* renegotiation fix for client authentication */

    if (s->cav_renego == 0) {
        s->s3->rrec.off = 0;
        s->packet_length = 0;
        p = (unsigned char *) s->init_buf->data;
        *p = SSL3_MT_CCS;
        s->init_num = 1;
        s->init_off = 0;
        s->state = SSL3_ST_SW_CHANGE_B;

        /* SSL3_ST_CW_CHANGE_B */
        i = ssl3_do_write (s, SSL3_RT_CHANGE_CIPHER_SPEC);

        //BIO_flush(s->wbio);

        cav_fprintf (cav_nb_fp,
            "pkp_handshake(): sent NEW change cipher spec msg\n");

    }

    s->init_num = 0;

    s->s3->tmp.peer_finish_md_len = len;
    /* activate cipher on the input (reading)  side */
    s->read_cipher_active = 1;


    /* SEND SERVER FINISH */
    memcpy ((unsigned char *) s->init_buf->data, s->server_finished, len);
    s->init_num = len;
    s->init_off = 0;
    s->state = SSL3_ST_SW_FINISHED_B;
    i = ssl3_do_write (s, SSL3_RT_HANDSHAKE);

    /* activate cipher on the output (writing)  side */
    s->write_cipher_active = 1;

    s->state = SSL3_ST_SW_CHANGE_A;

    if ((s->enc_read_ctx == NULL) &&
        ((s->enc_read_ctx =
                (EVP_CIPHER_CTX *)
                OPENSSL_malloc (sizeof (EVP_CIPHER_CTX))) == NULL)) {
        ret = 0;
        goto err;
    }

    EVP_CIPHER_CTX_init (s->enc_read_ctx);
    s->enc_read_ctx->cipher = c;
    s->read_hash = hash;

    if ((s->enc_write_ctx == NULL) &&
        ((s->enc_write_ctx =
                (EVP_CIPHER_CTX *)
                OPENSSL_malloc (sizeof (EVP_CIPHER_CTX))) == NULL)) {
        ret = 0;
        goto err;
    }

    EVP_CIPHER_CTX_init (s->enc_write_ctx);
    s->enc_write_ctx->cipher = c;
    s->write_hash = hash;

    /* Here update some variables for record processing */
    s->ssl_version = ssl_version;

    /* I hope that client and the server are using the same cipher :-)  */
    s->cipher_type = EVP_CIPHER_CTX_nid (s->enc_write_ctx);

    /* abd again the same hash */
    s->digest_type = EVP_MD_type (hash);

    s->md_size = md_size;

    ret = 1;
    s->reneg_flag = 0;
  err:
    if (s->reneg_flag)
        return ret;

    if (s->cav_renego > 0) {
        s->cav_renego = 0;
    }
    return ret;

}                                /* pkp_handshake_client_auth(s); */



int
pkp_resume_handshake (SSL * s)
{

    int i, ret, rc = 0;
    int is_block = 0;
    int cipher_type, digest_type;
    int handshake_len, md_size, len, finish_size;
    unsigned char server_finished[80], client_finished[80];
    unsigned char *p;
    const EVP_MD *hash;
    const EVP_CIPHER *c;
    SSL_COMP *comp;
    HashType hash_type;
    SslVersion ssl_version;

    cav_fprintf (cav_nb_fp, "pkp_resume_handshake(): entry\n");

    s->session->cipher = s->s3->tmp.new_cipher;

    if (!ssl_cipher_get_evp (s->session, &c, &hash, &comp)) {
        SSLerr (SSL_F_SSL3_SETUP_KEY_BLOCK,
            SSL_R_CIPHER_OR_HASH_UNAVAILABLE);
        ret = 0;
        goto err;
    }

    digest_type = EVP_MD_type (hash);
    cipher_type = EVP_CIPHER_nid (c);
    md_size = EVP_MD_size (hash);

    if (digest_type == NID_md5)
        hash_type = MD5_TYPE;

    else if (digest_type == NID_sha1)
        hash_type = SHA1_TYPE;

    else {
        ret = 0;
        goto err;
    }

    if (s->version > SSL3_VERSION) {
        finish_size = 16;
        ssl_version = VER_TLS;
    } else {
        finish_size = 40;
        ssl_version = VER3_0;
    }


    /* make p point to handshake msgs */
    p = s->hs_msgs;

    handshake_len = s->hs_msgs_len;
    /*
     * Check if this is not the 1st call (i.e. that this
     * call is to check for completion of a previously
     * queued cmd).
     */
    if (s->cav_crypto_state == CAV_ST_IN_RESUME_HANDSHAKE) {

        rc = check_handshake_completion (s,
            &i,
            &len,
            &md_size,
            &finish_size,
            &is_block, (char *) client_finished, (char *) server_finished);

        if (rc == 0) {
            cav_fprintf (cav_nb_fp, "pkp_resume_handshake(): %s\n",
                "check_handshake_completion() not completed");
            return (0);
        } else if (rc == -1) {
            cav_fprintf (cav_nb_fp, "pkp_resume_handshake(): %s\n",
                "ERROR check_handshake_completion() failed");
            return (-1);
        }
        cav_fprintf (cav_nb_fp, "pkp_resume_handshake(): %s %d\n",
            "check_handshake_completion() completed, rc = ", rc);

    }                            // end if .. CAV_ST_IN_HANDSHAKE

    else {

        if ((s->session->cipher->id == SSL3_CK_RSA_RC4_128_MD5)
            || (s->session->cipher->id == SSL3_CK_RSA_RC4_128_SHA)
            ||
            (s->session->cipher->id ==
                TLS1_CK_RSA_EXPORT1024_WITH_RC4_56_SHA)
            || (s->session->cipher->id ==
                TLS1_CK_RSA_EXPORT1024_WITH_RC4_56_MD5)
            || (s->session->cipher->id == SSL3_CK_RSA_RC4_40_MD5)) {

            Rc4Type rc4_type = get_Rc4_type (s->session->cipher->id);

            len = finish_size + md_size;
#ifdef CAVIUM_FIPS
            i = Cfm1ResumeRc4 (s->cav_nb_mode,
                s->context_pointer,
                hash_type,
                ssl_version,
                rc4_type,
                INPUT_ENCRYPTED,
                s->s3->client_random,
                s->s3->server_random,
                s->session->master_key,
                (unsigned short) handshake_len,
                p, s->client_finished, s->server_finished, &s->cav_req_id);
#else

            i = Csp1ResumeRc4 (s->cav_nb_mode,
                s->context_pointer,
                hash_type,
                ssl_version,
                rc4_type,
                INPUT_ENCRYPTED,
                s->s3->client_random,
                s->s3->server_random,
                s->session->master_key,
                (unsigned short) handshake_len,
                p, s->client_finished, s->server_finished,
#ifdef CAVIUM_MULTICARD_API
                &s->cav_req_id, s->dev_id
#else
                &s->cav_req_id
#endif
                );
#endif
            if (i == 0) {
                // completed
                cav_fprintf (cav_nb_fp, "===>pkp_resume_handshake(): %s\n",
                    "Csp1ResumeRc4() done");
                memcpy (client_finished, s->client_finished, 80);
                memcpy (server_finished, s->server_finished, 80);
            }

            else if (i == EAGAIN) {

                cav_fprintf (cav_nb_fp, "pkp_resume_handshake(): %s\n",
                    "Csp1ResumeRc4() EAGAIN");

                s->cav_crypto_state = CAV_ST_IN_RESUME_HANDSHAKE;
                s->cav_saved_state = s->state;
                s->state = CAV_ST_IN_RESUME_HANDSHAKE;
                s->cav_req_id_check_done = 0;
                s->rwstate = SSL_NITROX_BUSY;

            }                    // end .. else i == EAGAIN


            if (i != 0) {
                ret = 0;
                goto err;
            }

        } else if ((s->session->cipher->id == SSL3_CK_RSA_DES_192_CBC3_SHA)
            ||
            (s->session->cipher->id ==
                TLS1_CK_RSA_EXPORT1024_WITH_DES_CBC_SHA)
            || (s->session->cipher->id == SSL3_CK_RSA_DES_40_CBC_SHA)
            || (s->session->cipher->id == SSL3_CK_RSA_DES_64_CBC_SHA))
        {

            DesType des_type = get_Des_type (s->session->cipher->id);
            is_block = 1;
            len = ((finish_size + md_size + 7) / 8) * 8;

            if (ssl_version == VER_TLS) {
#ifdef CAVIUM_FIPS
                i = Cfm1Resume3Des (s->cav_nb_mode, s->context_pointer,
                    hash_type, ssl_version, des_type,
                    INPUT_ENCRYPTED,
                    RETURN_CFM_ENCRYPTED,
                    RETURN_SFM_ENCRYPTED,
                    0,    /*client_pad_length, */
                    0,            /*server_pad_length, */
                    s->s3->client_random,
                    s->s3->server_random,
                    s->session->master_key,
                    (unsigned short) handshake_len,
                    p,
                    s->client_finished,
                    s->server_finished, &s->cav_req_id);
#else

                i = Csp1Resume3Des (s->cav_nb_mode, s->context_pointer,
                    hash_type, ssl_version, des_type,
                    INPUT_ENCRYPTED,
                    RETURN_CFM_ENCRYPTED,
                    RETURN_SFM_ENCRYPTED,
                    0,    /*client_pad_length, */
                    0,            /*server_pad_length, */
                    s->s3->client_random,
                    s->s3->server_random,
                    s->session->master_key,
                    (unsigned short) handshake_len,
                    p, s->client_finished, s->server_finished,
#ifdef CAVIUM_MULTICARD_API
                    &s->cav_req_id, s->dev_id
#else
                    &s->cav_req_id
#endif
                    );
#endif
            } else {
#ifdef CAVIUM_FIPS
                i = Cfm1Resume3Des (s->cav_nb_mode, s->context_pointer, hash_type, ssl_version, des_type, INPUT_ENCRYPTED, RETURN_CFM_UNENCRYPTED, RETURN_SFM_ENCRYPTED, 0,    /*client_pad_length, */
                    0,            /*server_pad_length, */
                    s->s3->client_random,
                    s->s3->server_random,
                    s->session->master_key,
                    (unsigned short) handshake_len,
                    p,
                    s->client_finished,
                    s->server_finished, &s->cav_req_id);
#else
                i = Csp1Resume3Des (s->cav_nb_mode, s->context_pointer, hash_type, ssl_version, des_type, INPUT_ENCRYPTED, RETURN_CFM_UNENCRYPTED, RETURN_SFM_ENCRYPTED, 0,    /*client_pad_length, */
                    0,            /*server_pad_length, */
                    s->s3->client_random,
                    s->s3->server_random,
                    s->session->master_key,
                    (unsigned short) handshake_len,
                    p, s->client_finished, s->server_finished,
#ifdef CAVIUM_MULTICARD_API
                    &s->cav_req_id, s->dev_id
#else
                    &s->cav_req_id
#endif
                    );
#endif
            }

            if (i == 0) {
                // completed
                cav_fprintf (cav_nb_fp, "===>pkp_resume_handshake(): %s\n",
                    "Csp1Resume3Des() done");
                memcpy (client_finished, s->client_finished, 64);
                memcpy (server_finished, s->server_finished, 64);
            }

            else if (i == EAGAIN) {

                cav_fprintf (cav_nb_fp, "pkp_resume_handshake(): %s\n",
                    "Csp1Resume3Des() EAGAIN");

                s->cav_crypto_state = CAV_ST_IN_RESUME_HANDSHAKE;
                s->cav_saved_state = s->state;
                s->state = CAV_ST_IN_RESUME_HANDSHAKE;
                s->cav_req_id_check_done = 0;
                s->rwstate = SSL_NITROX_BUSY;

            }                    // end .. else i == EAGAIN



            if (i != 0) {
                ret = 0;
                goto err;
            }
        } else if ((s->session->cipher->id == TLS1_CK_RSA_WITH_AES_128_SHA)
            || (s->session->cipher->id == TLS1_CK_RSA_WITH_AES_256_SHA)
            ) {

            AesType aes_type = get_Aes_type (s->session->cipher->id);
            ClientFinishMessageOutput cfmo;

            cav_fprintf (cav_nb_fp, "pkp_resume_handshake(): AES case\n");

            is_block = 1;

            len = ((finish_size + md_size + 15) / 16) * 16;

            if (ssl_version == VER_TLS) {
                cfmo = RETURN_CFM_ENCRYPTED;
            } else {
                // ssl3
                cfmo = RETURN_CFM_UNENCRYPTED;
            }

            if (ssl_version == VER_TLS || ssl_version == VER3_0) {

                cav_fprintf (cav_nb_fp, "pkp__resume_handshake(): %s\n",
                    "before Csp1ResumeAes()");
#ifdef CAVIUM_FIPS
                i = Cfm1ResumeAes (s->cav_nb_mode, s->context_pointer,
                    hash_type, ssl_version, aes_type,
                    INPUT_ENCRYPTED,
                    cfmo,
                    RETURN_SFM_ENCRYPTED,
                    0,    /*client_pad_length, */
                    0,            /*server_pad_length, */
                    s->s3->client_random,
                    s->s3->server_random,
                    s->session->master_key,
                    (unsigned short) handshake_len,
                    p,
                    s->client_finished,
                    s->server_finished, &s->cav_req_id);
#else

                i = Csp1ResumeAes (s->cav_nb_mode, s->context_pointer,
                    hash_type, ssl_version, aes_type,
                    INPUT_ENCRYPTED,
                    cfmo,
                    RETURN_SFM_ENCRYPTED,
                    0,    /*client_pad_length, */
                    0,            /*server_pad_length, */
                    s->s3->client_random,
                    s->s3->server_random,
                    s->session->master_key,
                    (unsigned short) handshake_len,
                    p, s->client_finished, s->server_finished,
#ifdef CAVIUM_MULTICARD_API
                    &s->cav_req_id, s->dev_id
#else
                    &s->cav_req_id
#endif
                    );
#endif
                if (i == 0) {
                    // completed
                    cav_fprintf (cav_nb_fp,
                        "===>pkp_resume_handshake(): %s\n",
                        "Csp1ResumeRc4() done");
                    memcpy (client_finished, s->client_finished, 80);
                    memcpy (server_finished, s->server_finished, 80);
                }

                else if (i == EAGAIN) {

                    cav_fprintf (cav_nb_fp, "pkp_resume_handshake(): %s\n",
                        "Csp1ResumeRc4() EAGAIN");

                    s->cav_crypto_state = CAV_ST_IN_RESUME_HANDSHAKE;
                    s->cav_saved_state = s->state;
                    s->state = CAV_ST_IN_RESUME_HANDSHAKE;
                    s->cav_req_id_check_done = 0;
                    s->rwstate = SSL_NITROX_BUSY;

                }                // end .. else i == EAGAIN

                if (i != 0) {
                    cav_fprintf (cav_nb_fp,
                        "pkp__resume_handshake(): %s %d\n",
                        "ERROR: Csp1ResumeAes() returned i = ", i);
                    ret = 0;
                    goto err;
                }

            } else {
                cav_fprintf (cav_nb_fp, "pkp__resume_handshake(): %s\n",
                    "ERROR not tls1 or ssl3 and AES\n");
                return (0);
            }

        }                        // end else .. AES
        else {
            ret = 0;
            goto err;
        }

    }
    /******
    if(!is_block)
    {
        len = finish_size+md_size;
    }
    else
    {
        len = ((finish_size+md_size+7)/8)*8;
    }
    ***/

    s->s3->tmp.peer_finish_md_len = finish_size;


    /* Send CCP msg */
    s->s3->rrec.off = 0;
    s->packet_length = 0;
    p = (unsigned char *) s->init_buf->data;
    *p = SSL3_MT_CCS;
    s->init_num = 1;
    s->init_off = 0;
    s->state = SSL3_ST_SW_CHANGE_B;

    /* SSL3_ST_CW_CHANGE_B */
    i = ssl3_do_write (s, SSL3_RT_CHANGE_CIPHER_SPEC);

    s->init_num = 0;

    /* SEND SERVER FINISH */
    memcpy ((unsigned char *) s->init_buf->data, server_finished, len);
    s->init_num = len;
    s->init_off = 0;
    s->state = SSL3_ST_SW_FINISHED_B;
    i = ssl3_do_write (s, SSL3_RT_HANDSHAKE);

    /* activate cipher on the output (writing)  side */
    s->write_cipher_active = 1;

    s->state = SSL3_ST_SW_FINISHED_A;

    if ((s->enc_read_ctx == NULL) &&
        ((s->enc_read_ctx =
                (EVP_CIPHER_CTX *)
                OPENSSL_malloc (sizeof (EVP_CIPHER_CTX))) == NULL)) {
        ret = 0;
        goto err;
    }

    EVP_CIPHER_CTX_init (s->enc_read_ctx);
    s->enc_read_ctx->cipher = c;
    s->read_hash = hash;

    if ((s->enc_write_ctx == NULL) &&
        ((s->enc_write_ctx =
                (EVP_CIPHER_CTX *)
                OPENSSL_malloc (sizeof (EVP_CIPHER_CTX))) == NULL)) {
        ret = 0;
        goto err;
    }

    EVP_CIPHER_CTX_init (s->enc_write_ctx);
    s->enc_write_ctx->cipher = c;
    s->write_hash = hash;

    /* Here update some variables for record processing */
    s->ssl_version = ssl_version;

    /* I hope that client and the server are using the same cipher :-)  */
    s->cipher_type = EVP_CIPHER_CTX_nid (s->enc_write_ctx);

    /* abd again the same hash */
    s->digest_type = EVP_MD_type (hash);

    s->md_size = md_size;

    ret = 1;

  err:
    return ret;

    /* Remember that you have already calculated server finish message and have calulated local client finish messages */
}                                /* pkp_resume_handshake */


/* walks down the list of suported ciphers and returns 1 on success and 0 on failure */
int
find_cipher (SSL * s, unsigned long cipher_id)
{
    int i, ret = 0;
    if (!pkp_device_present)
        return ret;

    for (i = 0; i < PKP_SUPPORTED_CIPHER_COUNT; i++) {
        if (s->supported_ciphers[i] == cipher_id) {
            ret = 1;
            break;
        }
    }

    return ret;
}



/* initializes the supported cipher list */
int
init_supported_cipher_list (SSL * s)
{

    /*s->supported_ciphers[0]  = TLS1_CK_RSA_EXPORT1024_WITH_RC4_56_MD5;
       s->supported_ciphers[1]  = TLS1_CK_RSA_EXPORT1024_WITH_DES_CBC_SHA;
       s->supported_ciphers[2]  = TLS1_CK_RSA_EXPORT1024_WITH_RC4_56_SHA;
       s->supported_ciphers[3]  = SSL3_CK_RSA_RC4_40_MD5;
       s->supported_ciphers[4]  = SSL3_CK_RSA_RC4_128_MD5;
       s->supported_ciphers[5]  = SSL3_CK_RSA_RC4_128_SHA;
       s->supported_ciphers[6]  = SSL3_CK_RSA_DES_40_CBC_SHA;
       s->supported_ciphers[7]  = SSL3_CK_RSA_DES_64_CBC_SHA;
       s->supported_ciphers[8]  = SSL3_CK_RSA_DES_192_CBC3_SHA;
       s->supported_ciphers[9]  = SSL3_CK_DH_RSA_DES_40_CBC_SHA;
       s->supported_ciphers[10] = SSL3_CK_DH_RSA_DES_64_CBC_SHA ;
       s->supported_ciphers[11] = SSL3_CK_DH_RSA_DES_192_CBC3_SHA;
       s->supported_ciphers[12] = SSL3_CK_EDH_RSA_DES_40_CBC_SHA;
       s->supported_ciphers[13] = SSL3_CK_EDH_RSA_DES_64_CBC_SHA;
       s->supported_ciphers[14] = SSL3_CK_EDH_RSA_DES_192_CBC3_SHA;
       s->supported_ciphers[15] = SSL3_CK_ADH_RC4_40_MD5;
       s->supported_ciphers[16] = SSL3_CK_ADH_RC4_128_MD5;
       s->supported_ciphers[17] = SSL3_CK_ADH_DES_40_CBC_SHA;
       s->supported_ciphers[18] = SSL3_CK_ADH_DES_64_CBC_SHA;
       s->supported_ciphers[19] = SSL3_CK_ADH_DES_192_CBC_SHA;
     */
    memset (s->supported_ciphers, 0,
        sizeof (unsigned long) * PKP_SUPPORTED_CIPHER_COUNT);

    /*s->supported_ciphers[1]  = TLS1_CK_RSA_EXPORT1024_WITH_DES_CBC_SHA; */
    s->supported_ciphers[0] = TLS1_CK_RSA_EXPORT1024_WITH_RC4_56_MD5;
    s->supported_ciphers[1] = TLS1_CK_RSA_EXPORT1024_WITH_RC4_56_SHA;
    s->supported_ciphers[2] = SSL3_CK_RSA_RC4_40_MD5;
    s->supported_ciphers[3] = SSL3_CK_RSA_RC4_128_MD5;
    s->supported_ciphers[4] = SSL3_CK_RSA_RC4_128_SHA;
    s->supported_ciphers[5] = SSL3_CK_RSA_DES_40_CBC_SHA;
    s->supported_ciphers[6] = SSL3_CK_RSA_DES_64_CBC_SHA;
    s->supported_ciphers[7] = SSL3_CK_RSA_DES_192_CBC3_SHA;
    /* ssl v2 */
    s->supported_ciphers[8] = SSL2_CK_RC4_128_WITH_MD5;
    s->supported_ciphers[9] = SSL2_CK_RC4_128_EXPORT40_WITH_MD5;
    s->supported_ciphers[10] = SSL2_CK_DES_64_CBC_WITH_MD5;
    s->supported_ciphers[11] = SSL2_CK_DES_192_EDE3_CBC_WITH_MD5;

    s->supported_ciphers[12] = TLS1_CK_RSA_WITH_AES_128_SHA;
    s->supported_ciphers[13] = TLS1_CK_RSA_WITH_AES_256_SHA;

    return 1;
}


Rc4Type
get_Rc4_type (unsigned long id)
{
    if ((id == TLS1_CK_RSA_EXPORT1024_WITH_RC4_56_SHA) ||
        (id == TLS1_CK_RSA_EXPORT1024_WITH_RC4_56_MD5)) {
        return RC4_EXPORT_56;
    } else if ((id == SSL3_CK_RSA_RC4_40_MD5) ||
        (id == SSL2_CK_RC4_128_EXPORT40_WITH_MD5)) {
        return RC4_EXPORT_40;
    } else if ((id == SSL3_CK_RSA_RC4_128_MD5) ||
        (id == SSL3_CK_RSA_RC4_128_SHA) ||
        (id == SSL2_CK_RC4_128_WITH_MD5)) {
        return RC4_128;
    }



    return UNSUPPORTED_RC4;
}


DesType
get_Des_type (unsigned long id)
{
    if (id == TLS1_CK_RSA_EXPORT1024_WITH_DES_CBC_SHA) {
        return DES_EXPORT_40;
    } else if (id == SSL3_CK_RSA_DES_40_CBC_SHA) {
        return DES_EXPORT_40;
    } else if ((id == SSL3_CK_RSA_DES_64_CBC_SHA) ||
        (id == SSL2_CK_DES_64_CBC_WITH_MD5)) {
        return DES;
    } else if ((id == SSL3_CK_RSA_DES_192_CBC3_SHA) ||
        (id == SSL2_CK_DES_192_EDE3_CBC_WITH_MD5)) {
        return DES3_192;
    }

    return UNSUPPORTED_DES;

}


AesType
get_Aes_type (unsigned long id)
{
    if (id == TLS1_CK_RSA_WITH_AES_128_SHA)
        return (AES_128);
    else if (id == TLS1_CK_RSA_WITH_AES_256_SHA)
        return (AES_256);
    else
        //return (UNSUPPORTED_AES);
        return (-1);
}


int
pkp_cert_verify_mac (SSL * s)
{
    int i, ret = 0, rc = 0;
    int is_block = 0;
    int cipher_type, digest_type;
    int modlength, handshake_len, md_size, finish_size;
    int pre_master_len;
    unsigned char *p;
    unsigned char server_random[80], client_random[80], temp[512];
    const EVP_MD *hash;
    const EVP_CIPHER *c;
    SSL_COMP *comp;
    HashType hash_type;
    SslVersion ssl_version;
    MasterSecretReturn master_secret_return;

    cav_fprintf (cav_nb_fp, "pkp_cert_verify_mac(): entry\n");

    s->session->cipher = s->s3->tmp.new_cipher;

    if (!ssl_cipher_get_evp (s->session, &c, &hash, &comp)) {
        SSLerr (SSL_F_SSL3_SETUP_KEY_BLOCK,
            SSL_R_CIPHER_OR_HASH_UNAVAILABLE);
        cav_fprintf (cav_nb_fp,
            "pkp_cert_verify_mac(): ssl_cipher_get_evp() failed\n");
        return (0);
    }

    digest_type = EVP_MD_type (hash);
    cipher_type = EVP_CIPHER_nid (c);
    md_size = EVP_MD_size (hash);

    if (digest_type == NID_md5)
        hash_type = MD5_TYPE;

    else if (digest_type == NID_sha1)
        hash_type = SHA1_TYPE;

    else {
        ret = 0;
        cav_fprintf (cav_nb_fp,
            "pkp_cert_verify_mac(): invalid digest type %d\n",
            digest_type);
        goto err;
    }

    if (s->version > SSL3_VERSION) {
        finish_size = 16;
        ssl_version = VER_TLS;
    } else {
        finish_size = 40;
        ssl_version = VER3_0;
    }


#ifndef NO_SESSION_CACHE

    if (SSL_CTX_get_session_cache_mode (s->ctx) == SSL_SESS_CACHE_OFF)
        master_secret_return = NOT_RETURNED;
    else
        master_secret_return = RETURN_ENCRYPTED;

#else
    master_secret_return = NOT_RETURNED;
#endif


    /* make p point to the CKE message */
    p = (unsigned char *) &(s->hs_msgs[s->client_key_exch_msg_offset + 4]);    /* 4-byte handshake header */

    /* n1 has the length of the message */
    modlength = s->hs_msgs_len - s->client_key_exch_msg_offset - 4;    /* 4 header bytes */

    if (s->version > SSL3_VERSION) {
        n2s (p, i);
        if (modlength != i + 2) {
            if (!(s->options & SSL_OP_TLS_D5_BUG)) {
                SSLerr (SSL_F_SSL3_GET_CLIENT_KEY_EXCHANGE,
                    SSL_R_TLS_RSA_ENCRYPTED_VALUE_LENGTH_IS_WRONG);
                cav_fprintf (cav_nb_fp,
                    "pkp_cert_verify_mac(): invalid encrypted len\n");
                goto err;
            } else
                p -= 2;
        } else
            modlength = i;
    }


    if ((modlength % 8)) {
        ret = 0;
        cav_fprintf (cav_nb_fp,
            "pkp_cert_verify_mac(): invalid modlength\n");
        goto err;
    }


    handshake_len = s->hs_msgs_len;

    /*
     * Check if this is not the 1st call (i.e. that this
     * call is to check for completion of a previously
     * queued cmd).
     */
    if (s->cav_crypto_state == CAV_ST_IN_VRFY_CERT) {

        rc = check_handshake_completion (s,
            &i,
            &handshake_len,
            &md_size,
            &finish_size,
            &is_block, (char *) client_random, (char *) server_random);

        if (rc == 0) {
            cav_fprintf (cav_nb_fp, "pkp_cert_verify_mac(): %s\n",
                "check_handshake_completion() not completed");
            return (0);
        } else if (rc == -1) {
            cav_fprintf (cav_nb_fp, "pkp_cert_verify_mac(): %s\n",
                "ERROR check_handshake_completion() failed");
            return (-1);
        } else {
            cav_fprintf (cav_nb_fp, "pkp_cert_verify_mac(): %s %d\n",
                "check_handshake_completion() completed, rc = ", rc);
            return rc;
        }
    }

    /* end if .. CAV_ST_IN_HANDSHAKE */
    if ((s->session->cipher->id == SSL3_CK_RSA_RC4_128_MD5)
        || (s->session->cipher->id == SSL3_CK_RSA_RC4_128_SHA)
        ||
        (s->session->cipher->id == TLS1_CK_RSA_EXPORT1024_WITH_RC4_56_SHA)
        ||
        (s->session->cipher->id == TLS1_CK_RSA_EXPORT1024_WITH_RC4_56_MD5)
        || (s->session->cipher->id == SSL3_CK_RSA_RC4_40_MD5)) {

        Rc4Type rc4_type = get_Rc4_type (s->session->cipher->id);

        /* check for ephemeral handhake */

        if (s->s3->tmp.use_rsa_tmp) {

            if (s->cav_renego > 0 && s->alloc_flag == 0) {
#ifdef CAVIUM_FIPS
                Cfm1AllocContext (OP_BLOCKING, &s->s3->tmp.ctx_ptr,
                    &s->cav_req_id);
#else

#ifdef CAVIUM_MULTICARD_API
                Csp1AllocContext (CONTEXT_SSL, &s->s3->tmp.ctx_ptr,
                    s->dev_id);
#else
                Csp1AllocContext (CONTEXT_SSL, &s->s3->tmp.ctx_ptr);
#endif
#endif
                cav_fprintf (cav_nb_fp,
                    "pkp_cert_verify_mac()alloc context worked\n");
                s->alloc_flag = 1;
            }
            pre_master_len =
                generate_pre_master_secret (s, modlength, p,
                s->cert->rsa_tmp);


            if (pre_master_len != SSL_MAX_MASTER_KEY_LENGTH) {
                ret = 0;
                goto err;
            }

            /* now generate verify message */
            if (s->cav_renego > 0) {
#ifdef CAVIUM_FIPS
                i = Cfm1OtherVerifyRc4 (OP_BLOCKING,
                    s->s3->tmp.ctx_ptr,
                    hash_type,
                    ssl_version,
                    rc4_type,
                    master_secret_return,
                    (unsigned short) pre_master_len,
                    s->s3->client_random,
                    s->s3->server_random,
                    (unsigned short) handshake_len,
                    s->hs_msgs,
                    &(s->s3->tmp.cert_verify_md[0]),
                    s->session->master_key, &s->cav_req_id);
#else

                i = Csp1OtherVerifyRc4 (s->cav_nb_mode,
                    s->s3->tmp.ctx_ptr,
                    hash_type,
                    ssl_version,
                    rc4_type,
                    master_secret_return,
                    (unsigned short) pre_master_len,
                    s->s3->client_random,
                    s->s3->server_random,
                    (unsigned short) handshake_len,
                    s->hs_msgs,
                    &(s->s3->tmp.cert_verify_md[0]),
                    s->session->master_key,
#ifdef CAVIUM_MULTICARD_API
                    &s->cav_req_id, s->dev_id
#else
                    &s->cav_req_id
#endif
                    );
#endif
            } else {
#ifdef CAVIUM_FIPS
                i = Cfm1OtherVerifyRc4 (OP_BLOCKING,
                    s->context_pointer,
                    hash_type,
                    ssl_version,
                    rc4_type,
                    master_secret_return,
                    (unsigned short) pre_master_len,
                    s->s3->client_random,
                    s->s3->server_random,
                    (unsigned short) handshake_len,
                    s->hs_msgs,
                    &(s->s3->tmp.cert_verify_md[0]),
                    s->session->master_key, &s->cav_req_id);
#else
                i = Csp1OtherVerifyRc4 (s->cav_nb_mode,
                    s->context_pointer,
                    hash_type,
                    ssl_version,
                    rc4_type,
                    master_secret_return,
                    (unsigned short) pre_master_len,
                    s->s3->client_random,
                    s->s3->server_random,
                    (unsigned short) handshake_len,
                    s->hs_msgs,
                    &(s->s3->tmp.cert_verify_md[0]),
                    s->session->master_key,
#ifdef CAVIUM_MULTICARD_API
                    &s->cav_req_id, s->dev_id
#else
                    &s->cav_req_id
#endif
                    );
#endif

            }
        } /* if ephemeral */
        else {

#ifdef MC2
            memcpy (temp, p, modlength);
#else
            swap_word_openssl (temp, p, modlength);
#endif


            /* Renegotiation fix for client Authentication */
            if (s->cav_renego > 0 && s->alloc_flag == 0) {
#ifdef CAVIUM_FIPS
                Cfm1AllocContext (OP_BLOCKING, &s->s3->tmp.ctx_ptr,
                    &s->cav_req_id);
#else

#ifdef CAVIUM_MULTICARD_API
                Csp1AllocContext (CONTEXT_SSL, &s->s3->tmp.ctx_ptr,
                    s->dev_id);
#else
                Csp1AllocContext (CONTEXT_SSL, &s->s3->tmp.ctx_ptr);
#endif
#endif
                s->alloc_flag = 1;
            }

            if (s->cav_renego > 0) {
#ifdef CAVIUM_FIPS
                i = Cfm1RsaServerVerifyRc4 (OP_BLOCKING,
                    s->s3->tmp.ctx_ptr,
                    &s->key_handle,
                    hash_type,
                    ssl_version,
                    rc4_type,
                    master_secret_return,
                    (unsigned short) modlength,
                    temp,
                    s->s3->client_random,
                    s->s3->server_random,
                    (unsigned short) handshake_len,
                    s->hs_msgs,
                    &(s->s3->tmp.cert_verify_md[0]),
                    s->session->master_key, &s->cav_req_id);
#else
                i = Csp1RsaServerVerifyRc4 (s->cav_nb_mode,
                    s->s3->tmp.ctx_ptr,
                    &s->key_handle,
                    hash_type,
                    ssl_version,
                    rc4_type,
                    master_secret_return,
                    (unsigned short) modlength,
                    temp,
                    s->s3->client_random,
                    s->s3->server_random,
                    (unsigned short) handshake_len,
                    s->hs_msgs,
                    &(s->s3->tmp.cert_verify_md[0]),
                    s->session->master_key,
#ifdef CAVIUM_MULTICARD_API
                    &s->cav_req_id, s->dev_id
#else
                    &s->cav_req_id
#endif
                    );
#endif
            } else {
#ifdef CAVIUM_FIPS
                i = Cfm1RsaServerVerifyRc4 (OP_BLOCKING,
                    s->context_pointer,
                    &s->key_handle,
                    hash_type,
                    ssl_version,
                    rc4_type,
                    master_secret_return,
                    (unsigned short) modlength,
                    temp,
                    s->s3->client_random,
                    s->s3->server_random,
                    (unsigned short) handshake_len,
                    s->hs_msgs,
                    &(s->s3->tmp.cert_verify_md[0]),
                    s->session->master_key, &s->cav_req_id);
#else
                i = Csp1RsaServerVerifyRc4 (s->cav_nb_mode,
                    s->context_pointer,
                    &s->key_handle,
                    hash_type,
                    ssl_version,
                    rc4_type,
                    master_secret_return,
                    (unsigned short) modlength,
                    temp,
                    s->s3->client_random,
                    s->s3->server_random,
                    (unsigned short) handshake_len,
                    s->hs_msgs,
                    &(s->s3->tmp.cert_verify_md[0]),
                    s->session->master_key,
#ifdef CAVIUM_MULTICARD_API
                    &s->cav_req_id, s->dev_id
#else
                    &s->cav_req_id
#endif
                    );

#endif
            }
        }

        if (i == 0) {

            cav_fprintf (cav_nb_fp,
                "pkp_cert_verify_mac() RSAserververify rc4 returned success  \n");
        }

        else if (i == EAGAIN) {

            cav_fprintf (cav_nb_fp, "pkp_cert_verify_mac(): %s\n",
                "Csp1RsaServerVerifyRc4() EAGAIN");

            s->cav_crypto_state = CAV_ST_IN_VRFY_CERT;
            s->cav_saved_state = s->state;
            s->state = CAV_ST_IN_VRFY_CERT;
            s->cav_req_id_check_done = 0;
            s->rwstate = SSL_NITROX_BUSY;

        }                        // end .. else i == EAGAIN

        if (i != 0) {
            ret = 0;
            goto err;
        }

    } else if ((s->session->cipher->id == SSL3_CK_RSA_DES_192_CBC3_SHA)
        ||
        (s->session->cipher->id == TLS1_CK_RSA_EXPORT1024_WITH_DES_CBC_SHA)
        || (s->session->cipher->id == SSL3_CK_RSA_DES_40_CBC_SHA)
        || (s->session->cipher->id == SSL3_CK_RSA_DES_64_CBC_SHA))
    {

        DesType des_type = get_Des_type (s->session->cipher->id);
        is_block = 1;

        if (s->s3->tmp.use_rsa_tmp) {

            if (s->cav_renego > 0 && s->alloc_flag == 0) {
#ifdef CAVIUM_FIPS
                Cfm1AllocContext (OP_BLOCKING, &s->s3->tmp.ctx_ptr,
                    &s->cav_req_id);
#else

#ifdef CAVIUM_MULTICARD_API
                Csp1AllocContext (CONTEXT_SSL, &s->s3->tmp.ctx_ptr,
                    s->dev_id);
#else
                Csp1AllocContext (CONTEXT_SSL, &s->s3->tmp.ctx_ptr);
#endif

#endif
                s->alloc_flag = 1;
            }
            pre_master_len =
                generate_pre_master_secret (s, modlength, p,
                s->cert->rsa_tmp);
            if (pre_master_len != SSL_MAX_MASTER_KEY_LENGTH) {
                ret = 0;
                goto err;
            }

            if (s->cav_renego > 0) {

#ifdef CAVIUM_FIPS
                i = Cfm1OtherVerify3Des (OP_BLOCKING,
                    s->s3->tmp.ctx_ptr,
                    hash_type,
                    ssl_version,
                    des_type,
                    master_secret_return,
                    (unsigned short) pre_master_len,
                    s->s3->client_random,
                    s->s3->server_random,
                    (unsigned short) handshake_len,
                    s->hs_msgs,
                    &(s->s3->tmp.cert_verify_md[0]),
                    s->session->master_key, &s->cav_req_id);
#else
                i = Csp1OtherVerify3Des (s->cav_nb_mode,
                    s->s3->tmp.ctx_ptr,
                    hash_type,
                    ssl_version,
                    des_type,
                    master_secret_return,
                    (unsigned short) pre_master_len,
                    s->s3->client_random,
                    s->s3->server_random,
                    (unsigned short) handshake_len,
                    s->hs_msgs,
                    &(s->s3->tmp.cert_verify_md[0]),
                    s->session->master_key,
#ifdef CAVIUM_MULTICARD_API
                    &s->cav_req_id, s->dev_id
#else
                    &s->cav_req_id
#endif
                    );
#endif
            } else {
#ifdef CAVIUM_FIPS
                i = Cfm1OtherVerify3Des (OP_BLOCKING,
                    s->context_pointer,
                    hash_type,
                    ssl_version,
                    des_type,
                    master_secret_return,
                    (unsigned short) pre_master_len,
                    s->s3->client_random,
                    s->s3->server_random,
                    (unsigned short) handshake_len,
                    s->hs_msgs,
                    &(s->s3->tmp.cert_verify_md[0]),
                    s->session->master_key, &s->cav_req_id);
#else
                i = Csp1OtherVerify3Des (s->cav_nb_mode,
                    s->context_pointer,
                    hash_type,
                    ssl_version,
                    des_type,
                    master_secret_return,
                    (unsigned short) pre_master_len,
                    s->s3->client_random,
                    s->s3->server_random,
                    (unsigned short) handshake_len,
                    s->hs_msgs,
                    &(s->s3->tmp.cert_verify_md[0]),
                    s->session->master_key,
#ifdef CAVIUM_MULTICARD_API
                    &s->cav_req_id, s->dev_id
#else
                    &s->cav_req_id
#endif
                    );
#endif


            }

        }
        /* ephemeral */
        else {
#ifdef MC2
            memcpy (temp, p, modlength);
#else
            swap_word_openssl (temp, p, modlength);
#endif
            if (s->cav_renego > 0 && s->alloc_flag == 0) {
#ifdef CAVIUM_FIPS
                Cfm1AllocContext (OP_BLOCKING, &s->s3->tmp.ctx_ptr,
                    &s->cav_req_id);
#else

#ifdef CAVIUM_MULTICARD_API
                Csp1AllocContext (CONTEXT_SSL, &s->s3->tmp.ctx_ptr,
                    s->dev_id);
#else
                Csp1AllocContext (CONTEXT_SSL, &s->s3->tmp.ctx_ptr);
#endif
#endif
                s->alloc_flag = 1;
            }

            if (s->cav_renego > 0) {
#ifdef CAVIUM_FIPS
                i = Cfm1RsaServerVerify3Des (OP_BLOCKING,
                    s->s3->tmp.ctx_ptr,
                    &s->key_handle,
                    hash_type,
                    ssl_version,
                    des_type,
                    master_secret_return,
                    (unsigned short) modlength,
                    temp,
                    s->s3->client_random,
                    s->s3->server_random,
                    (unsigned short) handshake_len,
                    s->hs_msgs,
                    &(s->s3->tmp.cert_verify_md[0]),
                    s->session->master_key, &s->cav_req_id);
#else
                i = Csp1RsaServerVerify3Des (s->cav_nb_mode,
                    s->s3->tmp.ctx_ptr,
                    &s->key_handle,
                    hash_type,
                    ssl_version,
                    des_type,
                    master_secret_return,
                    (unsigned short) modlength,
                    temp,
                    s->s3->client_random,
                    s->s3->server_random,
                    (unsigned short) handshake_len,
                    s->hs_msgs,
                    &(s->s3->tmp.cert_verify_md[0]),
                    s->session->master_key,
#ifdef CAVIUM_MULTICARD_API
                    &s->cav_req_id, s->dev_id
#else
                    &s->cav_req_id
#endif
                    );
#endif
            } else {
#ifdef CAVIUM_FIPS
                i = Cfm1RsaServerVerify3Des (OP_BLOCKING,
                    s->context_pointer,
                    &s->key_handle,
                    hash_type,
                    ssl_version,
                    des_type,
                    master_secret_return,
                    (unsigned short) modlength,
                    temp,
                    s->s3->client_random,
                    s->s3->server_random,
                    (unsigned short) handshake_len,
                    s->hs_msgs,
                    &(s->s3->tmp.cert_verify_md[0]),
                    s->session->master_key, &s->cav_req_id);
#else
                i = Csp1RsaServerVerify3Des (s->cav_nb_mode,
                    s->context_pointer,
                    &s->key_handle,
                    hash_type,
                    ssl_version,
                    des_type,
                    master_secret_return,
                    (unsigned short) modlength,
                    temp,
                    s->s3->client_random,
                    s->s3->server_random,
                    (unsigned short) handshake_len,
                    s->hs_msgs,
                    &(s->s3->tmp.cert_verify_md[0]),
                    s->session->master_key,
#ifdef CAVIUM_MULTICARD_API
                    &s->cav_req_id, s->dev_id
#else
                    &s->cav_req_id
#endif
                    );

#endif
            }
        }
        if (i == EAGAIN) {

            cav_fprintf (cav_nb_fp, "pkp_cert_verify_mac(): %s\n",
                "Csp1RsaServerVerify3Des() EAGAIN");

            s->cav_crypto_state = CAV_ST_IN_VRFY_CERT;
            s->cav_saved_state = s->state;
            s->state = CAV_ST_IN_VRFY_CERT;
            s->cav_req_id_check_done = 0;
            s->rwstate = SSL_NITROX_BUSY;

        }                        // end .. else i == EAGAIN

        if (i != 0) {
            ret = 0;
            goto err;
        }

    } else if ((s->session->cipher->id == TLS1_CK_RSA_WITH_AES_128_SHA)
        || (s->session->cipher->id == TLS1_CK_RSA_WITH_AES_256_SHA)
        ) {

        AesType aes_type = get_Aes_type (s->session->cipher->id);
        is_block = 1;

        if (s->s3->tmp.use_rsa_tmp) {

            pre_master_len =
                generate_pre_master_secret (s, modlength, p,
                s->cert->rsa_tmp);
            if (pre_master_len != SSL_MAX_MASTER_KEY_LENGTH) {
                ret = 0;
                cav_fprintf (cav_nb_fp,
                    "pkp_cert_verify_mac(): invalid pre_master_len\n");
                goto err;
            }
#ifdef CAVIUM_FIPS
            i = Cfm1OtherVerifyAes (OP_BLOCKING,
                s->context_pointer,
                hash_type,
                ssl_version,
                aes_type,
                master_secret_return,
                (unsigned short) pre_master_len,
                s->s3->client_random,
                s->s3->server_random,
                (unsigned short) handshake_len,
                s->hs_msgs,
                &(s->s3->tmp.cert_verify_md[0]),
                s->session->master_key, &s->cav_req_id);
#else

            i = Csp1OtherVerifyAes (s->cav_nb_mode,
                s->context_pointer,
                hash_type,
                ssl_version,
                aes_type,
                master_secret_return,
                (unsigned short) pre_master_len,
                s->s3->client_random,
                s->s3->server_random,
                (unsigned short) handshake_len,
                s->hs_msgs,
                &(s->s3->tmp.cert_verify_md[0]), s->session->master_key,
#ifdef CAVIUM_MULTICARD_API
                &s->cav_req_id, s->dev_id
#else
                &s->cav_req_id
#endif
                );
#endif

        }
        /* ephemeral */
        else {
            cav_fprintf (cav_nb_fp,
                "pkp_cert_verify_mac(): AES - regular\n");

#ifdef MC2
            memcpy (temp, p, modlength);
#else
            swap_word_openssl (temp, p, modlength);
#endif
            if (s->cav_renego > 0 && s->alloc_flag == 0) {
#ifdef CAVIUM_FIPS
                Cfm1AllocContext (OP_BLOCKING, &s->s3->tmp.ctx_ptr,
                    &s->cav_req_id);
#else

#ifdef CAVIUM_MULTICARD_API
                Csp1AllocContext (CONTEXT_SSL, &s->s3->tmp.ctx_ptr,
                    s->dev_id);
#else
                Csp1AllocContext (CONTEXT_SSL, &s->s3->tmp.ctx_ptr);
#endif
#endif
                s->alloc_flag = 1;
            }

            if (s->cav_renego > 0) {
#ifdef CAVIUM_FIPS
                i = Cfm1RsaServerVerifyAes (OP_BLOCKING,
                    s->s3->tmp.ctx_ptr,
                    &s->key_handle,
                    hash_type,
                    ssl_version,
                    aes_type,
                    master_secret_return,
                    (unsigned short) modlength,
                    temp,
                    s->s3->client_random,
                    s->s3->server_random,
                    (unsigned short) handshake_len,
                    s->hs_msgs,
                    &(s->s3->tmp.cert_verify_md[0]),
                    s->session->master_key, &s->cav_req_id);
#else
                i = Csp1RsaServerVerifyAes (s->cav_nb_mode,
                    s->s3->tmp.ctx_ptr,
                    &s->key_handle,
                    hash_type,
                    ssl_version,
                    aes_type,
                    master_secret_return,
                    (unsigned short) modlength,
                    temp,
                    s->s3->client_random,
                    s->s3->server_random,
                    (unsigned short) handshake_len,
                    s->hs_msgs,
                    &(s->s3->tmp.cert_verify_md[0]),
                    s->session->master_key,
#ifdef CAVIUM_MULTICARD_API
                    &s->cav_req_id, s->dev_id
#else
                    &s->cav_req_id
#endif
                    );
#endif
            } else {
#ifdef CAVIUM_FIPS
                i = Cfm1RsaServerVerifyAes (OP_BLOCKING,
                    s->context_pointer,
                    &s->key_handle,
                    hash_type,
                    ssl_version,
                    aes_type,
                    master_secret_return,
                    (unsigned short) modlength,
                    temp,
                    s->s3->client_random,
                    s->s3->server_random,
                    (unsigned short) handshake_len,
                    s->hs_msgs,
                    &(s->s3->tmp.cert_verify_md[0]),
                    s->session->master_key, &s->cav_req_id);
#else
                i = Csp1RsaServerVerifyAes (s->cav_nb_mode,
                    s->context_pointer,
                    &s->key_handle,
                    hash_type,
                    ssl_version,
                    aes_type,
                    master_secret_return,
                    (unsigned short) modlength,
                    temp,
                    s->s3->client_random,
                    s->s3->server_random,
                    (unsigned short) handshake_len,
                    s->hs_msgs,
                    &(s->s3->tmp.cert_verify_md[0]),
                    s->session->master_key,
#ifdef CAVIUM_MULTICARD_API
                    &s->cav_req_id, s->dev_id
#else
                    &s->cav_req_id
#endif
                    );
#endif

            }
        }

        if (i == EAGAIN) {

            cav_fprintf (cav_nb_fp, "pkp_cert_verify_mac(): %s\n",
                "Csp1RsaServerVerifyAes() EAGAIN");

            s->cav_crypto_state = CAV_ST_IN_VRFY_CERT;
            s->cav_saved_state = s->state;
            s->state = CAV_ST_IN_VRFY_CERT;
            s->cav_req_id_check_done = 0;
            s->rwstate = SSL_NITROX_BUSY;

        }                        // end .. else i == EAGAIN

        if (i != 0) {
            ret = 0;
            cav_fprintf (cav_nb_fp, "%s %s %d\n",
                "pkp_cert_verify_mac(): AES - ",
                "Csp1OtherVerifyAes()/Csp1RsaServerVerifyAes() failed", i);
            goto err;
        }

    } else {
        ret = 0;
        goto err;
    }

    ret = 1;
  err:
    return ret;
}                                /*pkp_cert_verify_mac */


#ifdef MC2

int
generate_pre_master_secret (SSL * s, int modlength, unsigned char *from,
    RSA * rsa)
{
    int i, rc;
    int modulus_size, exponent_size;
    unsigned char *result;
    unsigned char result1[256];
    unsigned char *modulus_b = NULL, *exponent_b = NULL;
    Uint16 ret;

    result = alloca (modlength);
    if (result == NULL)
        return 0;

    if (s->cav_crypto_state == CAV_ST_IN_WRITE_CONTEXT) {

        s->state = s->cav_saved_state;
        if (s->cav_req_id_check_done) {
            rc = 0;
        } else {
            // should check for cmd completion here
#ifdef CAVIUM_MULTICARD_API
            rc = Csp1CheckForCompletion (s->cav_req_id, s->dev_id);
#else
            rc = Csp1CheckForCompletion (s->cav_req_id);
#endif
        }
        switch (rc) {
        case EAGAIN:
            s->cav_saved_state = s->state;
            if (s->state == SSL3_ST_SR_CERT_VRFY_A) {
                s->state = CAV_ST_IN_VRFY_CERT;
            } else
                s->state = CAV_ST_IN_HANDSHAKE;
            return (0);
        case 0:
            s->cav_crypto_state = 0;
            s->cav_req_id_check_done = 1;
            s->rwstate = SSL_NOTHING;
            break;
        default:
            s->cav_crypto_state = 0;
            s->cav_req_id_check_done = 1;
            s->rwstate = SSL_NOTHING;
            return (-1);
        }                        // end switch
        return s->pre_master_len;
    }

    else if (s->cav_crypto_state == CAV_ST_IN_PRE_MASTER_KEY) {

        rc = check_pre_master_completion (s, &ret, (char *) result1);

        if (rc == 1) {
            s->pre_master_len = ret;
            memcpy (result, result1, s->cryp_flen);
            goto pre_master;
        } else
            return 0;
    }

    modulus_size = BN_num_bytes (rsa->n);
    exponent_size = BN_num_bytes (rsa->d);

    modulus_b = alloca (modulus_size);
    if (modulus_b == NULL)
        return 0;
    memset (modulus_b, 0, modulus_size);


    exponent_b = alloca (exponent_size);
    if (exponent_b == NULL)
        return 0;
    memset (exponent_b, 0, exponent_size);


    BN_bn2bin (rsa->n, modulus_b);
    BN_bn2bin (rsa->d, exponent_b);

    s->cryp_flen = modlength;

    i = Csp1Pkcs1v15Dec (s->cav_nb_mode,
        BT2,
        (Uint16) modulus_size,
        (Uint16) exponent_size,
        modulus_b,
        exponent_b, from, &s->pre_master_len, s->pre_master_result,
#ifdef CAVIUM_MULTICARD_API
        &s->cav_req_id, s->dev_id
#else
        &s->cav_req_id
#endif
        );

    if (i == EAGAIN) {
        cav_fprintf (cav_nb_fp, "generate_pre_master_secret(): %s\n",
            "Csp1Pkcs1v15Des() EAGAIN");

        s->cav_crypto_state = CAV_ST_IN_PRE_MASTER_KEY;
        s->cav_saved_state = s->state;
        if (s->state == SSL3_ST_SR_CERT_VRFY_A) {
            s->state = CAV_ST_IN_VRFY_CERT;
        } else
            s->state = CAV_ST_IN_HANDSHAKE;

        s->cav_req_id_check_done = 0;
        s->rwstate = SSL_NITROX_BUSY;
        return 0;
    }

    else if (i) {
        ret = 0;
        return ret;
    }

    else
        ret = (Uint32) ntohs (s->pre_master_len);
    memcpy (result, s->pre_master_result, s->cryp_flen);

  pre_master:

    if (s->cav_renego > 0)
#ifdef CAVIUM_MULTICARD_API
        rc = Csp1WriteContext (s->cav_nb_mode, s->s3->tmp.ctx_ptr + 128,
            ret, result, &s->cav_req_id, s->dev_id);
#else
        rc = Csp1WriteContext (s->cav_nb_mode, s->s3->tmp.ctx_ptr + 128,
            ret, result, &s->cav_req_id);
#endif

    else {

#ifdef CAVIUM_MULTICARD_API
        rc = Csp1WriteContext (s->cav_nb_mode, s->context_pointer + 128,
            ret, result, &s->cav_req_id, s->dev_id);
#else
        rc = Csp1WriteContext (s->cav_nb_mode, s->context_pointer + 128,
            ret, result, &s->cav_req_id);
#endif
    }

    if (rc == EAGAIN) {
        cav_fprintf (cav_nb_fp, "generate_pre_master_secret(): %s\n",
            "Csp1WriteContext() EAGAIN");

        s->cav_crypto_state = CAV_ST_IN_WRITE_CONTEXT;
        s->cav_saved_state = s->state;
        if (s->state == SSL3_ST_SR_CERT_VRFY_A) {
            s->state = CAV_ST_IN_VRFY_CERT;
        } else
            s->state = CAV_ST_IN_HANDSHAKE;

        s->cav_req_id_check_done = 0;
        s->rwstate = SSL_NITROX_BUSY;
        return 0;
    } else if (rc != 0) {
        return 0;
    }
    return ret;

}                                /*int generate_pre_master_secret(SSL *s, int modlength, unsigned char *p, RSA *rsa); */

#else                            /* if !MC2 */

int
generate_pre_master_secret (SSL * s, int modlength, unsigned char *from,
    RSA * rsa)
{
    int i, rc;
    unsigned char *temp = NULL, *from_b = NULL;
    unsigned char result1[256];
#ifdef MC2
    int ret = 0;
#else
    long long ret = 0;
#endif
#ifdef CAVIUM_FIPS
    Uint64 out_length = 0;
#endif

#ifndef CAVIUM_FIPS
    unsigned char *modulus_b = NULL, *exponent_b = NULL;
    int modulus_size, exponent_size;


    from_b = alloca (modlength);
    if (from_b == NULL)
        return 0;
    memcpy (from_b, from, modlength);
    s->cryp_flen = modlength;

    if (s->cav_crypto_state == CAV_ST_IN_PRE_MASTER_KEY) {

        rc = check_pre_master_completion (s,
#ifdef MC2
            (Uint32 *) & ret,
#else
            (Uint64 *) (unsigned long) &ret,
#endif
            (char *) result1);

        if (rc == 1) {
            return (Uint32) ret;
        } else
            return 0;
    }




    modulus_size = BN_num_bytes (rsa->n);
    exponent_size = BN_num_bytes (rsa->d);

    modulus_b = alloca (modulus_size);
    if (modulus_b == NULL)
        return 0;
    memset (modulus_b, 0, modulus_size);


    temp = alloca (modulus_size);
    if (temp == NULL)
        return 0;
    memset (temp, 0, modulus_size);


    exponent_b = alloca (modulus_size);
    if (exponent_b == NULL)
        return 0;
    memset (exponent_b, 0, modulus_size);


    BN_bn2bin (rsa->n, modulus_b);
    BN_bn2bin (rsa->d, exponent_b);

    if (exponent_size < modulus_size) {
        pkp_leftfill (exponent_b, exponent_size, temp, modulus_size);
        memcpy (exponent_b, temp, modulus_size);
        memset (temp, 0, exponent_size);
    }


    swap_word_openssl (temp, modulus_b, modulus_size);
    memcpy (modulus_b, temp, modulus_size);
    memset (temp, 0, modulus_size);

    swap_word_openssl (temp, exponent_b, modulus_size);
    memcpy (exponent_b, temp, modulus_size);
    memset (temp, 0, modulus_size);

    swap_word_openssl (temp, from_b, modulus_size);
    memcpy (from_b, temp, modulus_size);
    memset (temp, 0, modulus_size);

    if (s->cav_renego > 0) {
        i = Csp1Pkcs1v15Dec (s->cav_nb_mode,
            CONTEXT_PTR,
            s->s3->tmp.ctx_ptr + 128,
            INPUT_DATA,
            s->key_handle,
            BT2,
            (unsigned short) modulus_size,
            modulus_b, exponent_b, from_b, NULL, &s->pre_master_len,
#ifdef CAVIUM_MULTICARD_API
            &s->cav_req_id, s->dev_id
#else
            &s->cav_req_id
#endif
            );
    } else {
        i = Csp1Pkcs1v15Dec (s->cav_nb_mode,
            CONTEXT_PTR,
            s->context_pointer + 128,
            INPUT_DATA,
            s->key_handle,
            BT2,
            (unsigned short) modulus_size,
            modulus_b, exponent_b, from_b, NULL, &s->pre_master_len,
#ifdef CAVIUM_MULTICARD_API
            &s->cav_req_id, s->dev_id
#else
            &s->cav_req_id
#endif
            );


    }
#else
    Uint64 local_key_handle = 0;
    if (s->cav_crypto_state == CAV_ST_IN_PRE_MASTER_KEY) {
        rc = check_pre_master_completion (s,
#ifdef MC2
            (Uint32 *) & ret,
#else
            (Uint64 *) & ret,
#endif
            (char *) result1);

        if (rc == 1) {
            return (Uint32) ret;
        } else
            return 0;
    }



    ret = fips_import_private_key (rsa, &local_key_handle);
    if (ret)
        return (0);

    from_b = alloca (modlength);
    if (from_b == NULL)
        return 0;
    memcpy (from_b, from, modlength);

    temp = alloca (modlength);
    if (temp == NULL)
        return 0;

    memset (temp, 0, modlength);

    swap_word_openssl (temp, from_b, modlength);
    memcpy (from_b, temp, modlength);
    memset (temp, 0, modlength);

    if (s->cav_renego > 0) {
        i = Cfm1Pkcs1v15Dec (OP_BLOCKING,
            CONTEXT_PTR,
            s->s3->tmp.ctx_ptr + 128,
            &local_key_handle,
            BT2,
            (unsigned short) modlength,
            from_b, NULL, &out_length, &s->cav_req_id);
    } else {
        i = Cfm1Pkcs1v15Dec (OP_BLOCKING,
            CONTEXT_PTR,
            s->context_pointer + 128,
            &local_key_handle,
            BT2,
            (unsigned short) modlength,
            from_b, NULL, &out_length, &s->cav_req_id);
    }
    s->pre_master_len = (Uint32) out_length;

    /* now destroy the key */
    Cfm1DeleteKey (local_key_handle);

#endif

    if (i == EAGAIN) {
        cav_fprintf (cav_nb_fp, "generate_pre_master_secret(): %s\n",
            "Csp1Pkcs1v15Des() EAGAIN");

        s->cav_crypto_state = CAV_ST_IN_PRE_MASTER_KEY;
        s->cav_saved_state = s->state;
        if (s->state == SSL3_ST_SR_CERT_VRFY_A) {
            s->state = CAV_ST_IN_VRFY_CERT;
        } else
            s->state = CAV_ST_IN_HANDSHAKE;
        s->cav_req_id_check_done = 0;
        s->rwstate = SSL_NITROX_BUSY;
        return 0;
    }

    else if (i) {

        ret = 0;
        return ret;
    }

    else
        ret = (Uint32) s->pre_master_len;

    return ret;

}                                /*int generate_pre_master_secret(SSL *s, int modlength, unsigned char *p, RSA *rsa); */
#endif




/*
 * SSL 2.0 specific functions
 */

int
pkp_handshake_20 (SSL * s)
{
#ifdef CAVIUM_FIPS
    goto err;
#else
    int ret = 0, finished_size;
    Uint8 *p;
    Uint16 modlength = 0;
    Uint16 master_secret_length = 0;

    modlength =
        BN_num_bytes (s->cert->pkeys[SSL_PKEY_RSA_ENC].privatekey->pkey.
        rsa->n);


    if ((s->session->cipher->id == SSL2_CK_RC4_128_WITH_MD5) ||
        (s->session->cipher->id == SSL2_CK_RC4_128_EXPORT40_WITH_MD5)) {
        Rc4Type rc4_type;

        finished_size = 16 + 1 + 16;    /* mac, mesage type, session_id/conn_id */

        rc4_type = get_Rc4_type (s->session->cipher->id);
        if (rc4_type == UNSUPPORTED_RC4)
            goto err;

        ret = Csp1RsaSsl20ServerFullRc4 (s->cav_nb_mode,
            s->context_pointer,
            &s->key_handle,
            rc4_type,
            s->client_master_secret,
            s->s2->tmp.clear,
            s->s2->tmp.enc,
            modlength,
            s->s2->challenge,
            s->s2->challenge_length,
            s->s2->conn_id,
            s->session->session_id,
            s->client_finished,
            s->server_finished,
            s->server_verify,
            s->session->master_key, &master_secret_length,
#ifdef CAVIUM_MULTICARD_API
            &s->cav_req_id, s->dev_id
#else
            &s->cav_req_id
#endif
            );
        if (ret != 0)
            return 0;

        s->session->master_key_length = master_secret_length;
        /* just to make sure */
        s->s2->tmp.cavium_block_cipher = 0;
        s->s2->tmp.cavium_pad = 0;
    }

    else if ((s->session->cipher->id == SSL2_CK_DES_64_CBC_WITH_MD5) ||
        (s->session->cipher->id == SSL2_CK_DES_192_EDE3_CBC_WITH_MD5)) {
        DesType des_type;
        int pad;

        finished_size = 16 + 1 + 16;    /* mac, mesage type, session_id/conn_id */
        pad = 8 - (finished_size % 8);

        finished_size += pad;

        des_type = get_Des_type (s->session->cipher->id);
        if (des_type == UNSUPPORTED_DES)
            goto err;


        ret = Csp1RsaSsl20ServerFull3Des (s->cav_nb_mode,
            s->context_pointer,
            &s->key_handle,
            des_type,
            s->client_master_secret,
            s->s2->tmp.clear,
            s->s2->tmp.enc,
            modlength,
            s->s2->challenge,
            s->s2->challenge_length,
            s->s2->conn_id,
            s->session->session_id,
            s->session->key_arg,
            s->client_finished,
            s->server_finished,
            s->server_verify,
            s->session->master_key, &master_secret_length,
#ifdef CAVIUM_MULTICARD_API
            &s->cav_req_id, s->dev_id
#else
            &s->cav_req_id
#endif
            );

        s->session->master_key_length = master_secret_length;
        s->s2->tmp.cavium_block_cipher = 1;
        s->s2->tmp.cavium_pad = pad;
    } else
        goto err;

    /* send server verify message */
    p = (unsigned char *) s->init_buf->data;
    memcpy (p, s->server_verify, finished_size);

    s->init_num = finished_size;
    s->init_off = 0;
    ssl2_do_write (s);

    /* send server finish message */
    p = (unsigned char *) s->init_buf->data;
    memcpy (p, s->server_finished, finished_size);
    s->init_num = finished_size;
    s->init_off = 0;

    ssl2_do_write (s);

    /* activate encryption */
    s->s2->clear_text = 0;

    /* reset some values */
    s->s2->ract_data_length = 0;
    s->rstate = SSL_ST_READ_HEADER;

    /* just to make sure */
    s->s2->tmp.cavium_block_cipher = 0;
    s->s2->tmp.cavium_pad = 0;
#endif
    return 1;
  err:
    return 0;

}                                /* pkp_handshake_20 */



int
pkp_resume_handshake_20 (SSL * s)
{
#ifdef CAVIUM_FIPS
    goto err;
#else
    int ret = 0, finished_size;
    Uint8 *p;

    if ((s->session->cipher->id == SSL2_CK_RC4_128_WITH_MD5) ||
        (s->session->cipher->id == SSL2_CK_RC4_128_EXPORT40_WITH_MD5)) {
        Rc4Type rc4_type;

        finished_size = 16 + 1 + 16;    /* mac, mesage type, session_id/conn_id */

        rc4_type = get_Rc4_type (s->session->cipher->id);
        if (rc4_type == UNSUPPORTED_RC4)
            goto err;

        ret = Csp1Ssl20ResumeRc4 (s->cav_nb_mode,
            s->context_pointer,
            &s->key_handle,
            rc4_type,
            s->session->master_key,
            s->session->master_key_length,
            s->s2->challenge,
            s->s2->challenge_length,
            s->s2->conn_id,
            s->session->session_id,
            s->client_finished, s->server_finished, s->server_verify,
#ifdef CAVIUM_MULTICARD_API
            &s->cav_req_id, s->dev_id
#else
            &s->cav_req_id
#endif
            );
        if (ret != 0)
            return 0;

        /* just to make sure */
        s->s2->tmp.cavium_block_cipher = 0;
        s->s2->tmp.cavium_pad = 0;
    }

    else if ((s->session->cipher->id == SSL2_CK_DES_64_CBC_WITH_MD5) ||
        (s->session->cipher->id == SSL2_CK_DES_192_EDE3_CBC_WITH_MD5)) {
        DesType des_type;
        int pad;

        finished_size = 16 + 1 + 16;    /* mac, mesage type, session_id/conn_id */
        pad = 8 - (finished_size % 8);

        finished_size += pad;

        des_type = get_Des_type (s->session->cipher->id);
        if (des_type == UNSUPPORTED_DES)
            goto err;


        ret = Csp1Ssl20Resume3Des (s->cav_nb_mode,
            s->context_pointer,
            &s->key_handle,
            des_type,
            s->session->master_key,
            s->session->master_key_length,
            s->s2->challenge,
            s->s2->challenge_length,
            s->s2->conn_id,
            s->session->session_id,
            s->session->key_arg,
            s->client_finished, s->server_finished, s->server_verify,
#ifdef CAVIUM_MULTICARD_API
            &s->cav_req_id, s->dev_id
#else
            &s->cav_req_id
#endif
            );

        s->s2->tmp.cavium_block_cipher = 1;
        s->s2->tmp.cavium_pad = pad;
    } else
        goto err;

    /* send server verify message */
    p = (unsigned char *) s->init_buf->data;
    memcpy (p, s->server_verify, finished_size);

    s->init_num = finished_size;
    s->init_off = 0;
    ssl2_do_write (s);

    /* send server finish message */
    p = (unsigned char *) s->init_buf->data;
    memcpy (p, s->server_finished, finished_size);
    s->init_num = finished_size;
    s->init_off = 0;

    ssl2_do_write (s);

    /* activate encryption */
    s->s2->clear_text = 0;

    /* reset some values */
    s->s2->ract_data_length = 0;
    s->rstate = SSL_ST_READ_HEADER;

    /* just to make sure */
    s->s2->tmp.cavium_block_cipher = 0;
    s->s2->tmp.cavium_pad = 0;
#endif
    return 1;
  err:
    return 0;

}                                /* pkp_resume_handshake_20 */



int
pkp_handshake_client_auth_20 (SSL * s)
{
#ifdef CAVIUM_FIPS
    goto err;
#else
    int ret = 0, finished_size, cert_req_size;
    int pad1 = 0, pad2 = 0;
    Uint8 *p;
    Uint16 modlength = 0;
    Uint16 master_secret_length = 0;

    cav_fprintf (cav_nb_fp, "pkp_handshake_client_auth_20(): entry\n");

    if (!s->hit)
        modlength =
            BN_num_bytes (s->cert->pkeys[SSL_PKEY_RSA_ENC].privatekey->
            pkey.rsa->n);


    if ((s->session->cipher->id == SSL2_CK_RC4_128_WITH_MD5) ||
        (s->session->cipher->id == SSL2_CK_RC4_128_EXPORT40_WITH_MD5)) {
        Rc4Type rc4_type;

        finished_size = 16 + 1 + 16;    /* mac, mesage type, session_id/conn_id */
        cert_req_size = 16 + 1 + 1 + 16;    /* mac, message type, auth_type, challenge size */

        rc4_type = get_Rc4_type (s->session->cipher->id);
        if (rc4_type == UNSUPPORTED_RC4)
            goto err;

        if (!s->hit) {
            ret = Csp1RsaSsl20ServerClientAuthRc4 (s->cav_nb_mode, s->context_pointer, &s->key_handle, rc4_type, s->client_master_secret, s->s2->tmp.clear, s->s2->tmp.enc, modlength, s->s2->challenge, s->s2->challenge_length, s->s2->conn_id, s->session->session_id, s->client_finished, SSL2_AT_MD5_WITH_RSA_ENCRYPTION, s->s2->tmp.ccl,    /* cert challenge */
                /* output */
                s->server_cert_req,
                s->server_verify,
                s->session->master_key, &master_secret_length,
#ifdef CAVIUM_MULTICARD_API
                &s->cav_req_id, s->dev_id
#else
                &s->cav_req_id
#endif
                );
            if (ret != 0)
                return 0;

            s->session->master_key_length = master_secret_length;
        } else {
            ret = Csp1Ssl20ResumeClientAuthRc4 (s->cav_nb_mode, s->context_pointer, &s->key_handle, rc4_type, s->session->master_key, s->session->master_key_length, s->s2->challenge, s->s2->challenge_length, s->s2->conn_id, s->session->session_id, s->client_finished, SSL2_AT_MD5_WITH_RSA_ENCRYPTION, s->s2->tmp.ccl,    /* cert challenge */
                /* output */
                s->server_cert_req, s->server_verify,
#ifdef CAVIUM_MULTICARD_API
                &s->cav_req_id, s->dev_id
#else
                &s->cav_req_id
#endif
                );
            if (ret != 0)
                return 0;
        }

        /* just to make sure */
        s->s2->tmp.cavium_block_cipher = 0;
    }

    else if ((s->session->cipher->id == SSL2_CK_DES_64_CBC_WITH_MD5) ||
        (s->session->cipher->id == SSL2_CK_DES_192_EDE3_CBC_WITH_MD5)) {
        DesType des_type;

        finished_size = 16 + 1 + 16;    /* mac, mesage type, session_id/conn_id */
        cert_req_size = 16 + 1 + 1 + 16;    /* mac, message type, auth_type, challenge size */

        pad1 = 8 - (finished_size % 8);
        finished_size += pad1;

        pad2 = 8 - (cert_req_size % 8);
        cert_req_size += pad2;

        des_type = get_Des_type (s->session->cipher->id);
        if (des_type == UNSUPPORTED_DES)
            goto err;

        if (!s->hit) {
            ret = Csp1RsaSsl20ServerClientAuth3Des (s->cav_nb_mode, s->context_pointer, &s->key_handle, des_type, s->client_master_secret, s->s2->tmp.clear, s->s2->tmp.enc, modlength, s->s2->challenge, s->s2->challenge_length, s->s2->conn_id, s->session->session_id, s->session->key_arg, s->client_finished, SSL2_AT_MD5_WITH_RSA_ENCRYPTION, s->s2->tmp.ccl,    /* cert challenge */
                /* output */
                s->server_cert_req,
                s->server_verify,
                s->session->master_key, &master_secret_length,
#ifdef CAVIUM_MULTICARD_API
                &s->cav_req_id, s->dev_id
#else
                &s->cav_req_id
#endif
                );
            if (ret != 0)
                return 0;

            s->session->master_key_length = master_secret_length;
        } else {
            ret = Csp1Ssl20ResumeClientAuth3Des (s->cav_nb_mode, s->context_pointer, &s->key_handle, des_type, s->session->master_key, s->session->master_key_length, s->s2->challenge, s->s2->challenge_length, s->s2->conn_id, s->session->session_id, s->session->key_arg, s->client_finished, SSL2_AT_MD5_WITH_RSA_ENCRYPTION, s->s2->tmp.ccl,    /* cert challenge */
                /* output */
                s->server_cert_req, s->server_verify,
#ifdef CAVIUM_MULTICARD_API
                &s->cav_req_id, s->dev_id
#else
                &s->cav_req_id
#endif
                );

            if (ret != 0)
                return 0;
        }
        s->s2->tmp.cavium_block_cipher = 1;
    } else
        goto err;

    /* send server verify message */
    s->s2->tmp.cavium_pad = pad1;
    p = (unsigned char *) s->init_buf->data;
    memcpy (p, s->server_verify, finished_size);

    s->init_num = finished_size;
    s->init_off = 0;
    ssl2_do_write (s);

    /* send server cert request message */
    s->s2->tmp.cavium_pad = pad2;
    p = (unsigned char *) s->init_buf->data;
    memcpy (p, s->server_cert_req, cert_req_size);
    s->init_num = cert_req_size;
    s->init_off = 0;

    ssl2_do_write (s);

    /* activate encryption */
    s->s2->clear_text = 0;

    /* reset some values */
    s->s2->ract_data_length = 0;
    s->rstate = SSL_ST_READ_HEADER;

    /* just to make sure */
    s->s2->tmp.cavium_block_cipher = 0;
    s->s2->tmp.cavium_pad = 0;
#endif
    return 1;
  err:
    return 0;

}                                /*int pkp_handshake_client_auth_20(SSL *s) */



int
pkp_encrypt_record_20 (SSL * s)
{
#ifdef CAVIUM_FIPS
    int ret = -1;
    goto err;
#else
    int ret, mac_size;
    Uint16 record_size;
    DesType des_type;
    unsigned long digest_type, cipher_type;


    digest_type = EVP_MD_type (s->write_hash);
    cipher_type = EVP_CIPHER_CTX_nid (s->enc_write_ctx);

    if (digest_type == NID_md5)
        mac_size = 16;
    else {
        ret = -1;
        goto err;
    }



    switch (cipher_type) {
    case NID_rc4:
    case NID_rc4_40:

        ret = Csp1Ssl20EncryptRecordRc4 (CAVIUM_NON_BLOCKING,
            //s->cav_nb_mode,
            s->context_pointer,
            s->s2->wact_data_length, s->s2->wact_data, s->s2->mac_data,
#ifdef CAVIUM_MULTICARD_API
            &s->cav_req_id, s->dev_id
#else
            &s->cav_req_id
#endif
            );
        if (ret) {
            ret = -1;
            goto err;
        }


        s->s2->wlength = s->s2->wact_data_length + mac_size;
        ret = 1;
        break;

    case NID_des_ede3_cbc:
    case NID_des_cbc:

        record_size = 0;
        des_type = get_Des_type (s->session->cipher->id);
        if (des_type == UNSUPPORTED_DES) {
            ret = -1;
            goto err;
        }

        ret = Csp1Ssl20EncryptRecord3Des (CAVIUM_NON_BLOCKING,
            //s->cav_nb_mode,
            s->context_pointer,
            des_type,
            s->s2->wact_data_length,
            s->s2->wact_data, &record_size, s->s2->mac_data,
#ifdef CAVIUM_MULTICARD_API
            &s->cav_req_id, s->dev_id
#else
            &s->cav_req_id
#endif
            );

        if (ret) {
            ret = -1;
            goto err;
        }


        s->s2->wlength = record_size;
        ret = 1;
        break;

    default:
        ret = -1;
        goto err;

    }                            /* switch cipher type */
#endif
  err:

    return ret;
}


int
pkp_decrypt_record_20 (SSL * s)
{
#ifdef CAVIUM_FIPS
    int ret = -1;
    goto err;
#else
    int ret, mac_size;
    unsigned long digest_type, cipher_type;
    DesType des_type;


    digest_type = EVP_MD_type (s->read_hash);
    cipher_type = EVP_CIPHER_CTX_nid (s->enc_read_ctx);

    if (digest_type == NID_md5)
        mac_size = 16;
    else {
        ret = -1;
        goto err;
    }

    switch (cipher_type) {
    case NID_rc4:
    case NID_rc4_40:

        ret = Csp1Ssl20DecryptRecordRc4 (CAVIUM_NON_BLOCKING,
            //s->cav_nb_mode,
            s->context_pointer,
            s->s2->rlength, s->s2->mac_data, s->s2->mac_data,
#ifdef CAVIUM_MULTICARD_API
            &s->cav_req_id, s->dev_id
#else
            &s->cav_req_id
#endif
            );
        if (ret) {
            ret = -1;
            goto err;
        }

        s->s2->ract_data_length = s->s2->rlength - mac_size;
        ret = 1;
        break;

    case NID_des_ede3_cbc:
    case NID_des_cbc:
        des_type = get_Des_type (s->session->cipher->id);
        if (des_type == UNSUPPORTED_DES) {
            ret = -1;
            goto err;
        }

        ret = Csp1Ssl20DecryptRecord3Des (CAVIUM_NON_BLOCKING,
            //s->cav_nb_mode,
            s->context_pointer,
            des_type, s->s2->rlength, s->s2->mac_data, s->s2->mac_data,
#ifdef CAVIUM_MULTICARD_API
            &s->cav_req_id, s->dev_id
#else
            &s->cav_req_id
#endif
            );
        if (ret) {
            ret = -1;
            goto err;
        }

        s->s2->ract_data_length =
            s->s2->rlength - mac_size - s->s2->padding;

        ret = 1;
        break;

    default:
        ret = -1;
        goto err;
    }
#endif

  err:
    return ret;
}                                /* pkp_decrypt record 20 */





/************************************************************
 * Client side handshake functions
 ************************************************************/

/*generate master secret, key blob and two finished messages.
   s->server_finished, s->client_finished.
   Only write_cipher is activated.
   Read cipher is activated after receiving server finished message. */
int
pkp_client_handshake (SSL * s)
{
    int i, ret = 0, rc = 0;
    int is_block = 0;
    int cipher_type, digest_type;
    int handshake_len, md_size, len, finish_size;
    int pre_master_len = 0;
    unsigned char *p;
    unsigned char client_finished[80], server_finished[80];
    const EVP_MD *hash;
    const EVP_CIPHER *c;
    SSL_COMP *comp;
    HashType hash_type;
    SslVersion ssl_version;
    MasterSecretReturn master_secret_return;

    if (s->cav_renego > 0 && s->reneg_flag == 0) {
        p = (unsigned char *) s->init_buf->data;
        *p = SSL3_MT_CCS;
        s->init_num = 1;
        s->init_off = 0;
        s->state = SSL3_ST_CW_CHANGE_B;

        /* SSL3_ST_CW_CHANGE_B */
        i = ssl3_do_write (s, SSL3_RT_CHANGE_CIPHER_SPEC);

        if (i <= 0) {
            s->reneg_flag = 1;
            s->state = SSL3_ST_CW_FINISHED_A;
            ret = 0;
            goto err;
        }
        s->session->cipher = s->s3->tmp.new_cipher;
        if (s->s3->tmp.new_compression == NULL)
            s->session->compress_meth = 0;
        else
            s->session->compress_meth = s->s3->tmp.new_compression->id;

        //BIO_flush(s->wbio);

        cav_fprintf (cav_nb_fp,
            "pkp_client_handshake(): sent NEW change cipher spec msg\n");
        s->write_cipher_active = 0;
    }

    s->session->cipher = s->s3->tmp.new_cipher;

    if (!ssl_cipher_get_evp (s->session, &c, &hash, &comp)) {
        SSLerr (SSL_F_SSL3_SETUP_KEY_BLOCK,
            SSL_R_CIPHER_OR_HASH_UNAVAILABLE);
        ret = 0;
        goto err;
    }

    digest_type = EVP_MD_type (hash);
    cipher_type = EVP_CIPHER_nid (c);
    md_size = EVP_MD_size (hash);

    if (digest_type == NID_md5)
        hash_type = MD5_TYPE;

    else if (digest_type == NID_sha1)
        hash_type = SHA1_TYPE;

    else {
        ret = 0;
        goto err;
    }

    if (s->version > SSL3_VERSION) {
        finish_size = 16;
        ssl_version = VER_TLS;
    } else {
        finish_size = 40;
        ssl_version = VER3_0;
    }


#ifndef NO_SESSION_CACHE

    if (SSL_CTX_get_session_cache_mode (s->ctx) == SSL_SESS_CACHE_OFF)
        master_secret_return = NOT_RETURNED;
    else
        master_secret_return = RETURN_ENCRYPTED;


#else
    master_secret_return = NOT_RETURNED;
#endif

    pre_master_len = SSL_MAX_MASTER_KEY_LENGTH;
    handshake_len = s->hs_msgs_len;

    if (s->state == CAV_ST_IN_HANDSHAKE) {

        rc = check_handshake_completion (s,
            &i,
            &len,
            &md_size,
            &finish_size,
            &is_block, (char *) client_finished, (char *) server_finished);
        if (rc == 1) {
            memcpy (s->server_finished, server_finished, 80);
            memcpy (s->client_finished, client_finished, 80);
            goto handshake;
        } else
            return 0;

    }

    if ((s->session->cipher->id == SSL3_CK_RSA_RC4_128_MD5)
        || (s->session->cipher->id == SSL3_CK_RSA_RC4_128_SHA)
        ||
        (s->session->cipher->id == TLS1_CK_RSA_EXPORT1024_WITH_RC4_56_SHA)
        ||
        (s->session->cipher->id == TLS1_CK_RSA_EXPORT1024_WITH_RC4_56_MD5)
        || (s->session->cipher->id == SSL3_CK_RSA_RC4_40_MD5))
    {

        Rc4Type rc4_type = get_Rc4_type (s->session->cipher->id);
        len = finish_size + md_size;
#ifdef CAVIUM_FIPS
        i = Cfm1OtherFullRc4 (OP_BLOCKING,
            s->context_pointer,
            hash_type,
            ssl_version,
            rc4_type,
            master_secret_return,
            (unsigned short) pre_master_len,
            s->s3->client_random,
            s->s3->server_random,
            (unsigned short) handshake_len,
            s->hs_msgs,
            s->client_finished,
            s->server_finished, s->session->master_key, &s->cav_req_id);
#else

        i = Csp1OtherFullRc4 (s->cav_nb_mode,
            s->context_pointer,
            hash_type,
            ssl_version,
            rc4_type,
            master_secret_return,
            (unsigned short) pre_master_len,
            s->s3->client_random,
            s->s3->server_random,
            (unsigned short) handshake_len,
            s->hs_msgs,
            s->client_finished, s->server_finished, s->session->master_key,
#ifdef CAVIUM_MULTICARD_API
            &s->cav_req_id, s->dev_id
#else
            &s->cav_req_id
#endif
            );
#endif

        if (i == 0) {
            cav_fprintf (cav_nb_fp, "===>pkp_client_handshake(): %s\n",
                "Csp1OtherFullRc4() done");

        }

        else if (i == EAGAIN) {

            cav_fprintf (cav_nb_fp, "pkp_client_handshake(): %s\n",
                "Csp1OtherFullRc4() EAGAIN");

            s->cav_crypto_state = CAV_ST_IN_HANDSHAKE;
            s->cav_saved_state = s->state;
            s->state = CAV_ST_IN_HANDSHAKE;
            s->cav_req_id_check_done = 0;
            s->rwstate = SSL_NITROX_BUSY;

        }                        //end ... else i == EAGAIN
        else {
            cav_fprintf (cav_nb_fp,
                "pkp_client_handshake(): ERROR return %d %s\n", i,
                "from Csp1OtherFullRc4()");
        }

        if (i != 0) {
            ret = 0;
            goto err;
        }
    } else if ((s->session->cipher->id == SSL3_CK_RSA_DES_192_CBC3_SHA)
        ||
        (s->session->cipher->id == TLS1_CK_RSA_EXPORT1024_WITH_DES_CBC_SHA)
        || (s->session->cipher->id == SSL3_CK_RSA_DES_40_CBC_SHA)
        || (s->session->cipher->id == SSL3_CK_RSA_DES_64_CBC_SHA))



    {
        DesType des_type = get_Des_type (s->session->cipher->id);
        is_block = 1;
        len = ((finish_size + md_size + 7) / 8) * 8;

        if (ssl_version == VER_TLS) {
#ifdef CAVIUM_FIPS
            i = Cfm1OtherFull3Des (OP_BLOCKING, s->context_pointer,
                hash_type, ssl_version, des_type,
                master_secret_return,
                RETURN_CFM_ENCRYPTED,
                RETURN_SFM_ENCRYPTED,
                0,    /*client_pad_length, */
                0,                /*server_pad_length, */
                (unsigned short) pre_master_len,
                s->s3->client_random,
                s->s3->server_random,
                (unsigned short) handshake_len,
                s->hs_msgs,
                s->client_finished,
                s->server_finished,
                s->session->master_key, &s->cav_req_id);
#else
            i = Csp1OtherFull3Des (s->cav_nb_mode, s->context_pointer,
                hash_type, ssl_version, des_type,
                master_secret_return,
                RETURN_CFM_ENCRYPTED,
                RETURN_SFM_ENCRYPTED,
                0,    /*client_pad_length, */
                0,                /*server_pad_length, */
                (unsigned short) pre_master_len,
                s->s3->client_random,
                s->s3->server_random,
                (unsigned short) handshake_len,
                s->hs_msgs,
                s->client_finished,
                s->server_finished, s->session->master_key,
#ifdef CAVIUM_MULTICARD_API
                &s->cav_req_id, s->dev_id
#else
                &s->cav_req_id
#endif
                );
#endif
        } else {

#ifdef CAVIUM_FIPS
            i = Cfm1OtherFull3Des (OP_BLOCKING, s->context_pointer,
                hash_type, ssl_version, des_type,
                master_secret_return,
                RETURN_CFM_ENCRYPTED,
                RETURN_SFM_UNENCRYPTED,
                0,    /*client_pad_length, */
                0,                /*server_pad_length, */
                (unsigned short) pre_master_len,
                s->s3->client_random,
                s->s3->server_random,
                (unsigned short) handshake_len,
                s->hs_msgs,
                s->client_finished,
                s->server_finished,
                s->session->master_key, &s->cav_req_id);
#else
            i = Csp1OtherFull3Des (s->cav_nb_mode, s->context_pointer,
                hash_type, ssl_version, des_type,
                master_secret_return,
                RETURN_CFM_ENCRYPTED,
                RETURN_SFM_UNENCRYPTED,
                0,    /*client_pad_length, */
                0,                /*server_pad_length, */
                (unsigned short) pre_master_len,
                s->s3->client_random,
                s->s3->server_random,
                (unsigned short) handshake_len,
                s->hs_msgs,
                s->client_finished,
                s->server_finished, s->session->master_key,
#ifdef CAVIUM_MULTICARD_API
                &s->cav_req_id, s->dev_id
#else
                &s->cav_req_id
#endif
                );
#endif
        }

        if (i == 0) {
            cav_fprintf (cav_nb_fp, "===>pkp_client_handshake(): %s\n",
                "Csp1OtherFull3Des() done");
        }

        else if (i == EAGAIN) {

            cav_fprintf (cav_nb_fp, "pkp_client_handshake(): %s\n",
                "Csp1OtherFull3Des() EAGAIN");

            s->cav_crypto_state = CAV_ST_IN_HANDSHAKE;
            s->cav_saved_state = s->state;
            s->state = CAV_ST_IN_HANDSHAKE;
            s->cav_req_id_check_done = 0;
            s->rwstate = SSL_NITROX_BUSY;

        }                        //end ... else i == EAGAIN
        else {
            cav_fprintf (cav_nb_fp,
                "pkp_client_handshake(): ERROR return %d %s\n", i,
                "from Csp1OtherFull3Des()");
        }

        if (i != 0) {
            ret = 0;
            goto err;
        }

    }                            // end else DES
    else if ((s->session->cipher->id == TLS1_CK_RSA_WITH_AES_128_SHA)
        || (s->session->cipher->id == TLS1_CK_RSA_WITH_AES_256_SHA)
        ) {

        AesType aes_type = get_Aes_type (s->session->cipher->id);
        ServerFinishMessageOutput sfmo;

        is_block = 1;

        len = ((finish_size + md_size + 15) / 16) * 16;

        if (ssl_version == VER_TLS) {
            sfmo = RETURN_SFM_ENCRYPTED;
        } else {
            // ssl3
            len = ((finish_size + md_size + 15) / 16) * 16;
            sfmo = RETURN_SFM_UNENCRYPTED;
        }


        if (ssl_version == VER_TLS || ssl_version == VER3_0) {

            cav_fprintf (cav_nb_fp, "pkp_client_handshake(): %s\n",
                "before TLS Csp1RsaServerFullAes()");

#ifdef CAVIUM_FIPS
            i = Cfm1OtherFullAes (OP_BLOCKING, s->context_pointer,
                hash_type, ssl_version, aes_type,
                master_secret_return,
                RETURN_CFM_ENCRYPTED,
                sfmo,
                0,    /*client_pad_length, */
                0,                /*server_pad_length, */
                (unsigned short) pre_master_len,
                s->s3->client_random,
                s->s3->server_random,
                (unsigned short) handshake_len,
                s->hs_msgs,
                s->client_finished,
                s->server_finished,
                s->session->master_key, &s->cav_req_id);
#else
            i = Csp1OtherFullAes (s->cav_nb_mode, s->context_pointer,
                hash_type, ssl_version, aes_type,
                master_secret_return,
                RETURN_CFM_ENCRYPTED,
                sfmo,
                0,    /*client_pad_length, */
                0,                /*server_pad_length, */
                (unsigned short) pre_master_len,
                s->s3->client_random,
                s->s3->server_random,
                (unsigned short) handshake_len,
                s->hs_msgs,
                s->client_finished,
                s->server_finished, s->session->master_key,
#ifdef CAVIUM_MULTICARD_API
                &s->cav_req_id, s->dev_id
#else
                &s->cav_req_id
#endif
                );
#endif

            if (i == 0) {
                cav_fprintf (cav_nb_fp, "===>pkp_client_handshake(): %s\n",
                    "Csp1OtherFullAes() done");
            }

            else if (i == EAGAIN) {

                cav_fprintf (cav_nb_fp, "pkp_client_handshake(): %s\n",
                    "Csp1OtherFullAes() EAGAIN");

                s->cav_crypto_state = CAV_ST_IN_HANDSHAKE;
                s->cav_saved_state = s->state;
                s->state = CAV_ST_IN_HANDSHAKE;
                s->cav_req_id_check_done = 0;
                s->rwstate = SSL_NITROX_BUSY;

            }                    //end ... else i == EAGAIN
            else {
                cav_fprintf (cav_nb_fp,
                    "pkp_client_handshake(): ERROR return %d %s\n", i,
                    "from Csp1OtherFullAes()");
            }

            if (i != 0) {
                ret = 0;
                goto err;
            }

        }                        // end if ssl3 or tls
        else {
            cav_fprintf (cav_nb_fp, "pkp_client_handshake(): %s\n",
                "ERROR not tls1 or ssl3 and AES\n");
            return (0);
        }

    }                            // end else AES
    else {
        ret = 0;
        goto err;
    }

  handshake:
    if (s->cav_renego == 0) {
        p = (unsigned char *) s->init_buf->data;
        *p = SSL3_MT_CCS;
        s->init_num = 1;
        s->init_off = 0;
        s->state = SSL3_ST_CW_CHANGE_B;

        /* SSL3_ST_CW_CHANGE_B */
        i = ssl3_do_write (s, SSL3_RT_CHANGE_CIPHER_SPEC);
        s->session->cipher = s->s3->tmp.new_cipher;
        if (s->s3->tmp.new_compression == NULL)
            s->session->compress_meth = 0;
        else
            s->session->compress_meth = s->s3->tmp.new_compression->id;

        //BIO_flush(s->wbio);

        cav_fprintf (cav_nb_fp,
            "pkp_client_handshake(): sent NEW change cipher spec msg\n");
    }

    /* SEND SERVER FINISH */
    memcpy ((unsigned char *) s->init_buf->data, s->client_finished, len);
    s->init_num = len;
    s->init_off = 0;
    s->state = SSL3_ST_CW_FINISHED_B;
    i = ssl3_do_write (s, SSL3_RT_HANDSHAKE);

    /* activate cipher on the output (writing)  side */
    s->write_cipher_active = 1;

    s->state = SSL3_ST_CW_CHANGE_A;

    if ((s->enc_read_ctx == NULL) &&
        ((s->enc_read_ctx =
                (EVP_CIPHER_CTX *)
                OPENSSL_malloc (sizeof (EVP_CIPHER_CTX))) == NULL)) {
        ret = 0;
        goto err;
    }

    EVP_CIPHER_CTX_init (s->enc_read_ctx);
    s->enc_read_ctx->cipher = c;
    s->read_hash = hash;

    if ((s->enc_write_ctx == NULL) &&
        ((s->enc_write_ctx =
                (EVP_CIPHER_CTX *)
                OPENSSL_malloc (sizeof (EVP_CIPHER_CTX))) == NULL)) {
        ret = 0;
        goto err;
    }

    EVP_CIPHER_CTX_init (s->enc_write_ctx);
    s->enc_write_ctx->cipher = c;
    s->write_hash = hash;

    /* Here update some variables for record processing */
    s->ssl_version = ssl_version;

    /* I hope that client and the server are using the same cipher :-)  */
    s->cipher_type = EVP_CIPHER_CTX_nid (s->enc_write_ctx);

    /* abd again the same hash */
    s->digest_type = EVP_MD_type (hash);

    s->md_size = md_size;

    ret = 1;
    s->reneg_flag = 0;
  err:
    if (s->reneg_flag)
        return ret;

    if (s->cav_renego > 0)
        s->cav_renego = 0;

    return ret;

}                                /*pkp_client_handshake */


int
pkp_client_resume_handshake (SSL * s)
{

    int i, ret, rc = 0;
    int is_block = 0;
    int cipher_type, digest_type;
    int handshake_len, md_size, len, finish_size;
    unsigned short peer_len;
    unsigned char server_finished[80], client_finished[80];
    unsigned char dec_peer_client_finished[80];
    unsigned char *p;
    const EVP_MD *hash;
    const EVP_CIPHER *c;
    SSL_COMP *comp;
    HashType hash_type;
    SslVersion ssl_version;

    s->session->cipher = s->s3->tmp.new_cipher;

    if (!ssl_cipher_get_evp (s->session, &c, &hash, &comp)) {
        SSLerr (SSL_F_SSL3_SETUP_KEY_BLOCK,
            SSL_R_CIPHER_OR_HASH_UNAVAILABLE);
        ret = 0;
        goto err;
    }

    digest_type = EVP_MD_type (hash);
    cipher_type = EVP_CIPHER_nid (c);
    md_size = EVP_MD_size (hash);

    if (digest_type == NID_md5)
        hash_type = MD5_TYPE;

    else if (digest_type == NID_sha1)
        hash_type = SHA1_TYPE;

    else {
        ret = 0;
        goto err;
    }

    if (s->version > SSL3_VERSION) {
        finish_size = 16;
        ssl_version = VER_TLS;
    } else {
        finish_size = 40;
        ssl_version = VER3_0;
    }


    /* make p point to handshake msgs */
    p = s->hs_msgs;

    handshake_len = s->server_finish_msg_offset;


    if (s->state == CAV_ST_IN_RESUME_HANDSHAKE) {

        if (s->cav_crypto_state == CAV_ST_IN_RESUME_HANDSHAKE) {

            rc = check_handshake_completion (s,
                &i,
                &len,
                &md_size,
                &finish_size,
                &is_block,
                (char *) client_finished, (char *) server_finished);
            if (rc == 1) {
                memcpy (s->server_finished, server_finished, 80);
                memcpy (s->client_finished, client_finished, 80);
                goto again;
            }

        }                        // end if .. CAV_ST_IN_HANDSHAKE
        else if (s->cav_crypto_state == CAV_ST_IN_CHK_DEC_PEER) {

            rc = check_dec_peer_completion (s,
                &i,
                &len,
                &md_size,
                &finish_size,
                &is_block, &peer_len, (char *) dec_peer_client_finished);
            if (rc == 1) {

                cav_fprintf (cav_nb_fp,
                    "pkp_client_resume_handshake(): %s %d\n",
                    "check_dec_peer_completion() completed, rc = ", rc);
                goto dec_peer_res;
            }
        }

        if (rc == 0) {

            cav_fprintf (cav_nb_fp, "pkp_client_resume_handshake(): %s\n",
                "check_dec_peer_completion() not completed");
            return (0);
        } else if (rc == -1) {
            cav_fprintf (cav_nb_fp, "pkp_client_resume_handshake(): %s\n",
                "ERROR check_dec_peer_completion() failed");
            return (-1);
        }
    }
    if ((s->session->cipher->id == SSL3_CK_RSA_RC4_128_MD5)
        || (s->session->cipher->id == SSL3_CK_RSA_RC4_128_SHA)
        ||
        (s->session->cipher->id == TLS1_CK_RSA_EXPORT1024_WITH_RC4_56_SHA)
        ||
        (s->session->cipher->id == TLS1_CK_RSA_EXPORT1024_WITH_RC4_56_MD5)
        || (s->session->cipher->id == SSL3_CK_RSA_RC4_40_MD5)) {

        Rc4Type rc4_type = get_Rc4_type (s->session->cipher->id);
        len = finish_size + md_size;
#ifdef CAVIUM_FIPS
        i = Cfm1ResumeRc4 (OP_BLOCKING,
            s->context_pointer,
            hash_type,
            ssl_version,
            rc4_type,
            INPUT_ENCRYPTED,
            s->s3->client_random,
            s->s3->server_random,
            s->session->master_key,
            (unsigned short) handshake_len,
            p, s->client_finished, s->server_finished, &s->cav_req_id);
#else
        i = Csp1ResumeRc4 (s->cav_nb_mode,
            s->context_pointer,
            hash_type,
            ssl_version,
            rc4_type,
            INPUT_ENCRYPTED,
            s->s3->client_random,
            s->s3->server_random,
            s->session->master_key,
            (unsigned short) handshake_len,
            p, s->client_finished, s->server_finished,
#ifdef CAVIUM_MULTICARD_API
            &s->cav_req_id, s->dev_id
#else
            &s->cav_req_id
#endif
            );
#endif
        if (i == 0) {
            // completed
            cav_fprintf (cav_nb_fp,
                "===>pkp_client_resume_handshake(): %s\n",
                "Csp1ResumeRc4() done");
        }

        else if (i == EAGAIN) {

            cav_fprintf (cav_nb_fp, "pkp_client_resume_handshake(): %s\n",
                "Csp1ResumeRc4() EAGAIN");

            s->cav_crypto_state = CAV_ST_IN_RESUME_HANDSHAKE;
            s->cav_saved_state = s->state;
            s->state = CAV_ST_IN_RESUME_HANDSHAKE;
            s->cav_req_id_check_done = 0;
            s->rwstate = SSL_NITROX_BUSY;
            s->flag = 1;

        }                        // end .. else i == EAGAIN
        if (i != 0) {
            ret = 0;
            goto err;
        }

    } else if ((s->session->cipher->id == SSL3_CK_RSA_DES_192_CBC3_SHA)
        ||
        (s->session->cipher->id == TLS1_CK_RSA_EXPORT1024_WITH_DES_CBC_SHA)
        || (s->session->cipher->id == SSL3_CK_RSA_DES_40_CBC_SHA)
        || (s->session->cipher->id == SSL3_CK_RSA_DES_64_CBC_SHA))
    {

        DesType des_type = get_Des_type (s->session->cipher->id);

        len = ((finish_size + md_size + 7) / 8) * 8;
        is_block = 1;

        if (ssl_version == VER_TLS) {
#ifdef CAVIUM_FIPS
            i = Cfm1Resume3Des (OP_BLOCKING, s->context_pointer,
                hash_type, ssl_version, des_type,
                INPUT_ENCRYPTED,
                RETURN_CFM_ENCRYPTED,
                RETURN_SFM_ENCRYPTED,
                0,    /*client_pad_length, */
                0,                /*server_pad_length, */
                s->s3->client_random,
                s->s3->server_random,
                s->session->master_key,
                (unsigned short) handshake_len,
                p, s->client_finished, s->server_finished, &s->cav_req_id);
#else
            i = Csp1Resume3Des (s->cav_nb_mode, s->context_pointer,
                hash_type, ssl_version, des_type,
                INPUT_ENCRYPTED,
                RETURN_CFM_ENCRYPTED,
                RETURN_SFM_ENCRYPTED,
                0,    /*client_pad_length, */
                0,                /*server_pad_length, */
                s->s3->client_random,
                s->s3->server_random,
                s->session->master_key,
                (unsigned short) handshake_len,
                p, s->client_finished, s->server_finished,
#ifdef CAVIUM_MULTICARD_API
                &s->cav_req_id, s->dev_id
#else
                &s->cav_req_id
#endif
                );
#endif
        } else {
#ifdef CAVIUM_FIPS
            i = Cfm1Resume3Des (OP_BLOCKING, s->context_pointer,
                hash_type, ssl_version, des_type,
                INPUT_ENCRYPTED,
                RETURN_CFM_ENCRYPTED,
                RETURN_SFM_UNENCRYPTED,
                0,    /*client_pad_length, */
                0,                /*server_pad_length, */
                s->s3->client_random,
                s->s3->server_random,
                s->session->master_key,
                (unsigned short) handshake_len,
                p, s->client_finished, s->server_finished, &s->cav_req_id);
#else
            i = Csp1Resume3Des (s->cav_nb_mode, s->context_pointer,
                hash_type, ssl_version, des_type,
                INPUT_ENCRYPTED,
                RETURN_CFM_ENCRYPTED,
                RETURN_SFM_UNENCRYPTED,
                0,    /*client_pad_length, */
                0,                /*server_pad_length, */
                s->s3->client_random,
                s->s3->server_random,
                s->session->master_key,
                (unsigned short) handshake_len,
                p, s->client_finished, s->server_finished,
#ifdef CAVIUM_MULTICARD_API
                &s->cav_req_id, s->dev_id
#else
                &s->cav_req_id
#endif
                );
#endif
        }

        if (i == 0) {
            // completed
            cav_fprintf (cav_nb_fp,
                "===>pkp_client_resume_handshake(): %s\n",
                "Csp1Resume3Des() done");
        }

        else if (i == EAGAIN) {

            cav_fprintf (cav_nb_fp, "pkp_client_resume_handshake(): %s\n",
                "Csp1Resume3Des() EAGAIN");

            s->cav_crypto_state = CAV_ST_IN_RESUME_HANDSHAKE;
            s->cav_saved_state = s->state;
            s->state = CAV_ST_IN_RESUME_HANDSHAKE;
            s->cav_req_id_check_done = 0;
            s->rwstate = SSL_NITROX_BUSY;
            s->flag = 1;

        }                        // end .. else i == EAGAIN

        if (i != 0) {
            ret = 0;
            goto err;
        }
    }                            // end else ... DES
    else if ((s->session->cipher->id == TLS1_CK_RSA_WITH_AES_128_SHA)
        || (s->session->cipher->id == TLS1_CK_RSA_WITH_AES_256_SHA)
        ) {

        AesType aes_type = get_Aes_type (s->session->cipher->id);
        ServerFinishMessageOutput sfmo;

        cav_fprintf (cav_nb_fp,
            "pkp_client_resume_handshake(): AES case\n");

        is_block = 1;

        len = ((finish_size + md_size + 15) / 16) * 16;

        if (ssl_version == VER_TLS) {
            sfmo = RETURN_CFM_ENCRYPTED;
        } else {
            // ssl3
            sfmo = RETURN_CFM_UNENCRYPTED;
        }

        if (ssl_version == VER_TLS || ssl_version == VER3_0) {
#ifdef CAVIUM_FIPS
            i = Cfm1ResumeAes (OP_BLOCKING, s->context_pointer,
                hash_type, ssl_version, aes_type,
                INPUT_ENCRYPTED,
                RETURN_CFM_ENCRYPTED,
                sfmo,
                0,    /*client_pad_length, */
                0,                /*server_pad_length, */
                s->s3->client_random,
                s->s3->server_random,
                s->session->master_key,
                (unsigned short) handshake_len,
                p, s->client_finished, s->server_finished, &s->cav_req_id);
#else
            i = Csp1ResumeAes (s->cav_nb_mode, s->context_pointer,
                hash_type, ssl_version, aes_type,
                INPUT_ENCRYPTED,
                RETURN_CFM_ENCRYPTED,
                sfmo,
                0,    /*client_pad_length, */
                0,                /*server_pad_length, */
                s->s3->client_random,
                s->s3->server_random,
                s->session->master_key,
                (unsigned short) handshake_len,
                p, s->client_finished, s->server_finished,
#ifdef CAVIUM_MULTICARD_API
                &s->cav_req_id, s->dev_id
#else
                &s->cav_req_id
#endif
                );
#endif
        } else {
            cav_fprintf (cav_nb_fp, "pkp_client_resume_handshake(): %s\n",
                "ERROR not tls1 or ssl3 and AES\n");
            return (0);
        }

        if (i == 0) {
            // completed
            cav_fprintf (cav_nb_fp,
                "===>pkp_client_resume_handshake(): %s\n",
                "Csp1ResumeAes() done");
        }

        else if (i == EAGAIN) {

            cav_fprintf (cav_nb_fp, "pkp_client_resume_handshake(): %s\n",
                "Csp1ResumeAes() EAGAIN");

            s->cav_crypto_state = CAV_ST_IN_RESUME_HANDSHAKE;
            s->cav_saved_state = s->state;
            s->state = CAV_ST_IN_RESUME_HANDSHAKE;
            s->cav_req_id_check_done = 0;
            s->rwstate = SSL_NITROX_BUSY;
            s->flag = 1;

        }                        // end .. else i == EAGAIN
        if (i != 0) {
            ret = 0;
            goto err;
        }
    }                            // end else ... AES
    else {
        ret = 0;
        goto err;
    }



    /* compare the finished message which is received from server */
    /* now replace first four bytes of client finish message. */
  again:memcpy (&(s->hs_msgs[s->server_finish_msg_offset]),
        s->peer_finish_first_four, 4);

    /* compare with what we got from CSP */
    if (!is_block || ssl_version == VER_TLS) {
        if (memcmp (&s->hs_msgs[s->server_finish_msg_offset],
                s->server_finished, len) != 0) {
            cav_fprintf (cav_nb_fp,
                "pkp_resume_handshake(): memcmp failed for rc4 \n");
            ret = 0;
            goto err;
        }
    } else {

        /* decrypt the received client finished */
        if (s->session->cipher->id == TLS1_CK_RSA_WITH_AES_128_SHA
            || s->session->cipher->id == TLS1_CK_RSA_WITH_AES_256_SHA) {
            // AES
            AesType aes_type = get_Aes_type (s->session->cipher->id);
#if defined  (CAVIUM_FIPS) && !defined (MC2)
            i = Cfm1DecryptRecordAesRecover (OP_BLOCKING,
                s->context_pointer,
                hash_type,
                ssl_version,
                SSL_CLIENT,
                aes_type,
                HANDSHAKE,
                (unsigned short) (s->hs_msgs_len -
                    s->server_finish_msg_offset),
                &s->hs_msgs[s->server_finish_msg_offset], &peer_len,
                s->dec_peer_client_finished, &s->cav_req_id);
#else
#ifndef MC2

            i = Csp1DecryptRecordAesRecover
#else
            i = Csp1DecryptRecordAes
#endif
                (s->cav_nb_mode,
                s->context_pointer,
                hash_type,
                ssl_version,
                SSL_CLIENT,
                aes_type,
                HANDSHAKE,
                (unsigned short) (s->hs_msgs_len -
                    s->server_finish_msg_offset),
                &s->hs_msgs[s->server_finish_msg_offset], &s->peer_len,
                s->dec_peer_client_finished,
#ifdef CAVIUM_MULTICARD_API
                &s->cav_req_id, s->dev_id
#else
                &s->cav_req_id
#endif
                );

#endif
        } else {
            // DES
#if defined  (CAVIUM_FIPS) && !defined (MC2)
            i = Cfm1DecryptRecord3DesRecover (OP_BLOCKING,
                s->context_pointer,
                hash_type,
                ssl_version,
                SSL_CLIENT,
                HANDSHAKE,
                (unsigned short) (s->hs_msgs_len -
                    s->server_finish_msg_offset),
                &s->hs_msgs[s->server_finish_msg_offset], &peer_len,
                s->dec_peer_client_finished, &s->cav_req_id);
#else
#ifndef MC2
            i = Csp1DecryptRecord3DesRecover
#else
            i = Csp1DecryptRecord3Des
#endif
                (s->cav_nb_mode,
                s->context_pointer,
                hash_type,
                ssl_version,
                SSL_CLIENT,
                HANDSHAKE,
                (unsigned short) (s->hs_msgs_len -
                    s->server_finish_msg_offset),
                &s->hs_msgs[s->server_finish_msg_offset], &s->peer_len,
                s->dec_peer_client_finished,
#ifdef CAVIUM_MULTICARD_API
                &s->cav_req_id, s->dev_id
#else
                &s->cav_req_id
#endif
                );
#endif

        }

        if (i == 0) {
            memcpy (dec_peer_client_finished, s->dec_peer_client_finished,
                s->peer_len);
            peer_len = s->peer_len;

        }
        if (i == EAGAIN) {
            cav_fprintf (cav_nb_fp, "pkp_resume_handshake(): %s\n",
                "ssl3_get_finished() EAGAIN");
            s->cav_crypto_state = CAV_ST_IN_CHK_DEC_PEER;
            s->cav_saved_state = s->state;
            s->state = CAV_ST_IN_RESUME_HANDSHAKE;
            s->cav_req_id_check_done = 0;
            s->rwstate = SSL_NITROX_BUSY;
            s->flag = 1;
        }
        if (i != 0) {
            ret = 0;
            goto err;
        }

      dec_peer_res:if (memcmp (dec_peer_client_finished, s->server_finished,
                peer_len) != 0) {
            cav_fprintf (cav_nb_fp,
                "pkp_resume_handshake ... memcmp failed \n");
            ret = 0;
            goto err;
        }

    }                            /*isblock */

    s->s3->tmp.peer_finish_md_len = finish_size;

    /* Send CCP msg */
    s->s3->rrec.off = 0;
    s->packet_length = 0;
    p = (unsigned char *) s->init_buf->data;
    *p = SSL3_MT_CCS;
    s->init_num = 1;
    s->init_off = 0;
    s->state = SSL3_ST_CW_CHANGE_B;

    /* SSL3_ST_CW_CHANGE_B */
    i = ssl3_do_write (s, SSL3_RT_CHANGE_CIPHER_SPEC);

    s->init_num = 0;

    /* SEND CLIENT FINISH */
    memcpy ((unsigned char *) s->init_buf->data, s->client_finished, len);
    s->init_num = len;
    s->init_off = 0;
    s->state = SSL3_ST_CW_FINISHED_B;
    i = ssl3_do_write (s, SSL3_RT_HANDSHAKE);

    /* activate cipher on the output (writing)  side */
    s->write_cipher_active = 1;

    s->init_num = 0;

    s->state = SSL3_ST_CW_FINISHED_A;

    if ((s->enc_read_ctx == NULL) &&
        ((s->enc_read_ctx =
                (EVP_CIPHER_CTX *)
                OPENSSL_malloc (sizeof (EVP_CIPHER_CTX))) == NULL)) {
        ret = 0;
        goto err;
    }

    EVP_CIPHER_CTX_init (s->enc_read_ctx);
    s->enc_read_ctx->cipher = c;
    s->read_hash = hash;

    if ((s->enc_write_ctx == NULL) &&
        ((s->enc_write_ctx =
                (EVP_CIPHER_CTX *)
                OPENSSL_malloc (sizeof (EVP_CIPHER_CTX))) == NULL)) {
        ret = 0;
        goto err;
    }

    EVP_CIPHER_CTX_init (s->enc_write_ctx);
    s->enc_write_ctx->cipher = c;
    s->write_hash = hash;

    /* Here update some variables for record processing */
    s->ssl_version = ssl_version;

    /* I hope that client and the server are using the same cipher :-)  */
    s->cipher_type = EVP_CIPHER_CTX_nid (s->enc_write_ctx);

    /* abd again the same hash */
    s->digest_type = EVP_MD_type (hash);

    s->md_size = md_size;

    ret = 1;

  err:
    return ret;

}                                /* pkp_client_resume_handshake */



//int pkp_client_cert_verify_mac(unsigned char *mac, SSL *s)
int
pkp_client_cert_verify_mac (SSL * s)
{
    int i, ret = 0, rc =0;
    int cipher_type, digest_type;
    int handshake_len, md_size, pre_master_len;
    const EVP_MD *hash;
    const EVP_CIPHER *c;
    SSL_COMP *comp;
    HashType hash_type;
    SslVersion ssl_version;
    MasterSecretReturn master_secret_return;

    s->session->cipher = s->s3->tmp.new_cipher;

    if (!ssl_cipher_get_evp (s->session, &c, &hash, &comp)) {
        SSLerr (SSL_F_SSL3_SETUP_KEY_BLOCK,
            SSL_R_CIPHER_OR_HASH_UNAVAILABLE);
        return (0);
    }

    digest_type = EVP_MD_type (hash);
    cipher_type = EVP_CIPHER_nid (c);
    md_size = EVP_MD_size (hash);

    if (digest_type == NID_md5)
        hash_type = MD5_TYPE;

    else if (digest_type == NID_sha1)
        hash_type = SHA1_TYPE;

    else {
        ret = 0;
        goto err;
    }

    if (s->version > SSL3_VERSION)
        ssl_version = VER_TLS;
    else
        ssl_version = VER3_0;



#ifndef NO_SESSION_CACHE

    if (SSL_CTX_get_session_cache_mode (s->ctx) == SSL_SESS_CACHE_OFF)
        master_secret_return = NOT_RETURNED;
    else
        master_secret_return = RETURN_ENCRYPTED;

#else
    master_secret_return = NOT_RETURNED;
#endif

    handshake_len = s->hs_msgs_len;
    pre_master_len = SSL_MAX_MASTER_KEY_LENGTH;

    if (s->cav_crypto_state == CAV_ST_IN_VRFY_CERT) {

        rc = check_vryf_mac_completion (s);

        if (rc == 0) {
            cav_fprintf (cav_nb_fp, "pkp_client_cert_verify_mac(): %s\n",
                "check_vrfy_mac_completion() not completed");
            return (0);
        } else if (rc == -1) {
            cav_fprintf (cav_nb_fp, "pkp_client_cert_verify_mac(): %s\n",
                "ERROR check_vrfy_mac_completion() failed");
            return (-1);
        } else {
            cav_fprintf (cav_nb_fp,
                "pkp_client_cert_verify_mac(): %s %d\n",
                "check_vrfy_mac_completion() completed, rc = ", rc);
            return rc;
        }
    }                            // end if .. CAV_ST_IN_HANDSHAKE

    if ((s->session->cipher->id == SSL3_CK_RSA_RC4_128_MD5)
        || (s->session->cipher->id == SSL3_CK_RSA_RC4_128_SHA)
        ||
        (s->session->cipher->id == TLS1_CK_RSA_EXPORT1024_WITH_RC4_56_SHA)
        ||
        (s->session->cipher->id == TLS1_CK_RSA_EXPORT1024_WITH_RC4_56_MD5)
        || (s->session->cipher->id == SSL3_CK_RSA_RC4_40_MD5)) {

        Rc4Type rc4_type = get_Rc4_type (s->session->cipher->id);

        if (s->cav_renego > 0) {
#ifdef CAVIUM_FIPS
            i = Cfm1OtherVerifyRc4 (OP_BLOCKING,
                s->s3->tmp.ctx_ptr,
                hash_type,
                ssl_version,
                rc4_type,
                master_secret_return,
                (unsigned short) pre_master_len,
                s->s3->client_random,
                s->s3->server_random,
                (unsigned short) handshake_len,
                s->hs_msgs,
                s->data_sign, s->session->master_key, &s->cav_req_id);
#else

            i = Csp1OtherVerifyRc4 (s->cav_nb_mode,
                s->s3->tmp.ctx_ptr,
                hash_type,
                ssl_version,
                rc4_type,
                master_secret_return,
                (unsigned short) pre_master_len,
                s->s3->client_random,
                s->s3->server_random,
                (unsigned short) handshake_len,
                s->hs_msgs, s->data_sign, s->session->master_key,
#ifdef CAVIUM_MULTICARD_API
                &s->cav_req_id, s->dev_id
#else
                &s->cav_req_id
#endif
                );
#endif

            cav_fprintf (cav_nb_fp,
                "pkp_client_cert_verify_mac(): returned from csp1otherverifyrc4 : %d \n",
                i);
        }

        else {
#ifdef CAVIUM_FIPS
            i = Cfm1OtherVerifyRc4 (OP_BLOCKING,
                s->context_pointer,
                hash_type,
                ssl_version,
                rc4_type,
                master_secret_return,
                (unsigned short) pre_master_len,
                s->s3->client_random,
                s->s3->server_random,
                (unsigned short) handshake_len,
                s->hs_msgs,
                s->data_sign, s->session->master_key, &s->cav_req_id);
#else
            i = Csp1OtherVerifyRc4 (s->cav_nb_mode,
                s->context_pointer,
                hash_type,
                ssl_version,
                rc4_type,
                master_secret_return,
                (unsigned short) pre_master_len,
                s->s3->client_random,
                s->s3->server_random,
                (unsigned short) handshake_len,
                s->hs_msgs, s->data_sign, s->session->master_key,
#ifdef CAVIUM_MULTICARD_API
                &s->cav_req_id, s->dev_id
#else
                &s->cav_req_id
#endif
                );
#endif
            cav_fprintf (cav_nb_fp,
                "pkp_client_cert_verify_mac(): returned from csp1otherverifyrc4 : %d \n",
                i);
        }

        if (i == EAGAIN) {

            cav_fprintf (cav_nb_fp, "pkp_client_cert_verify_mac(): %s\n",
                "Csp1OtherVerifyRc4() EAGAIN");

            s->cav_crypto_state = CAV_ST_IN_VRFY_CERT;
            s->cav_saved_state = s->state;
            s->state = CAV_ST_IN_VRFY_CERT;
            s->cav_req_id_check_done = 0;
            s->rwstate = SSL_NITROX_BUSY;

        }                        // end .. else i == EAGAIN

        if (i != 0) {
            ret = 0;
            goto err;
        }
    } else if ((s->session->cipher->id == SSL3_CK_RSA_DES_192_CBC3_SHA)
        ||
        (s->session->cipher->id == TLS1_CK_RSA_EXPORT1024_WITH_DES_CBC_SHA)
        || (s->session->cipher->id == SSL3_CK_RSA_DES_40_CBC_SHA)
        || (s->session->cipher->id == SSL3_CK_RSA_DES_64_CBC_SHA))
    {

        DesType des_type = get_Des_type (s->session->cipher->id);

        if (s->cav_renego > 0) {
#ifdef CAVIUM_FIPS
            i = Cfm1OtherVerify3Des (OP_BLOCKING,
                s->s3->tmp.ctx_ptr,
                hash_type,
                ssl_version,
                des_type,
                master_secret_return,
                (unsigned short) pre_master_len,
                s->s3->client_random,
                s->s3->server_random,
                (unsigned short) handshake_len,
                s->hs_msgs,
                s->data_sign, s->session->master_key, &s->cav_req_id);
#else

            i = Csp1OtherVerify3Des (s->cav_nb_mode,
                s->s3->tmp.ctx_ptr,
                hash_type,
                ssl_version,
                des_type,
                master_secret_return,
                (unsigned short) pre_master_len,
                s->s3->client_random,
                s->s3->server_random,
                (unsigned short) handshake_len,
                s->hs_msgs, s->data_sign, s->session->master_key,
#ifdef CAVIUM_MULTICARD_API
                &s->cav_req_id, s->dev_id
#else
                &s->cav_req_id
#endif
                );
#endif
        } else {
#ifdef CAVIUM_FIPS
            i = Cfm1OtherVerify3Des (OP_BLOCKING,
                s->context_pointer,
                hash_type,
                ssl_version,
                des_type,
                master_secret_return,
                (unsigned short) pre_master_len,
                s->s3->client_random,
                s->s3->server_random,
                (unsigned short) handshake_len,
                s->hs_msgs,
                s->data_sign, s->session->master_key, &s->cav_req_id);
#else

            i = Csp1OtherVerify3Des (s->cav_nb_mode,
                s->context_pointer,
                hash_type,
                ssl_version,
                des_type,
                master_secret_return,
                (unsigned short) pre_master_len,
                s->s3->client_random,
                s->s3->server_random,
                (unsigned short) handshake_len,
                s->hs_msgs, s->data_sign, s->session->master_key,
#ifdef CAVIUM_MULTICARD_API
                &s->cav_req_id, s->dev_id
#else
                &s->cav_req_id
#endif
                );

#endif
        }

        if (i == EAGAIN) {

            cav_fprintf (cav_nb_fp, "pkp_client_cert_verify_mac(): %s\n",
                "Csp1OtherVerify3Des() EAGAIN");

            s->cav_crypto_state = CAV_ST_IN_VRFY_CERT;
            s->cav_saved_state = s->state;
            s->state = CAV_ST_IN_VRFY_CERT;
            s->cav_req_id_check_done = 0;
            s->rwstate = SSL_NITROX_BUSY;

        }                        // end .. else i == EAGAIN

        if (i != 0) {
            ret = 0;
            goto err;
        }

    }

    else if ((s->session->cipher->id == TLS1_CK_RSA_WITH_AES_128_SHA)
        || (s->session->cipher->id == TLS1_CK_RSA_WITH_AES_256_SHA)
        ) {

        AesType aes_type = get_Aes_type (s->session->cipher->id);

        if (s->cav_renego > 0) {
#ifdef CAVIUM_FIPS
            i = Cfm1OtherVerifyAes (OP_BLOCKING,
                s->s3->tmp.ctx_ptr,
                hash_type,
                ssl_version,
                aes_type,
                master_secret_return,
                (unsigned short) pre_master_len,
                s->s3->client_random,
                s->s3->server_random,
                (unsigned short) handshake_len,
                s->hs_msgs,
                s->data_sign, s->session->master_key, &s->cav_req_id);
#else
            i = Csp1OtherVerifyAes (s->cav_nb_mode,
                s->s3->tmp.ctx_ptr,
                hash_type,
                ssl_version,
                aes_type,
                master_secret_return,
                (unsigned short) pre_master_len,
                s->s3->client_random,
                s->s3->server_random,
                (unsigned short) handshake_len,
                s->hs_msgs, s->data_sign, s->session->master_key,
#ifdef CAVIUM_MULTICARD_API
                &s->cav_req_id, s->dev_id
#else
                &s->cav_req_id
#endif
                );
#endif
        } else {
#ifdef CAVIUM_FIPS
            i = Cfm1OtherVerifyAes (OP_BLOCKING,
                s->context_pointer,
                hash_type,
                ssl_version,
                aes_type,
                master_secret_return,
                (unsigned short) pre_master_len,
                s->s3->client_random,
                s->s3->server_random,
                (unsigned short) handshake_len,
                s->hs_msgs,
                s->data_sign, s->session->master_key, &s->cav_req_id);
#else
            i = Csp1OtherVerifyAes (s->cav_nb_mode,
                s->context_pointer,
                hash_type,
                ssl_version,
                aes_type,
                master_secret_return,
                (unsigned short) pre_master_len,
                s->s3->client_random,
                s->s3->server_random,
                (unsigned short) handshake_len,
                s->hs_msgs, s->data_sign, s->session->master_key,
#ifdef CAVIUM_MULTICARD_API
                &s->cav_req_id, s->dev_id
#else
                &s->cav_req_id
#endif
                );
#endif
        }

        if (i == EAGAIN) {

            cav_fprintf (cav_nb_fp, "pkp_client_cert_verify_mac(): %s\n",
                "Csp1OtherVerifyAes() EAGAIN");

            s->cav_crypto_state = CAV_ST_IN_VRFY_CERT;
            s->cav_saved_state = s->state;
            s->state = CAV_ST_IN_VRFY_CERT;
            s->cav_req_id_check_done = 0;
            s->rwstate = SSL_NITROX_BUSY;

        }                        // end .. else i == EAGAIN

        if (i != 0) {
            ret = 0;
            goto err;
        }

    }

    else {
        ret = 0;
        goto err;
    }

    ret = 1;
  err:
    return ret;
}                                /*pkp_client_cert_verify_mac */

int
pkp_client_handshake_client_auth (SSL * s)
{
    int i, ret, rc = 0;
    int is_block = 0;
    int cipher_type, digest_type;
    int handshake_len, md_size, len, finish_size;
    unsigned char server_finished[80], client_finished[80];
    unsigned char *p;
    const EVP_MD *hash;
    const EVP_CIPHER *c;
    SSL_COMP *comp;
    HashType hash_type;
    SslVersion ssl_version;

    if (s->cav_renego > 0 && s->reneg_flag == 0) {
        s->s3->rrec.off = 0;
        s->packet_length = 0;
        p = (unsigned char *) s->init_buf->data;
        *p = SSL3_MT_CCS;
        s->init_num = 1;
        s->init_off = 0;
        s->state = SSL3_ST_CW_CHANGE_B;

        /* SSL3_ST_CW_CHANGE_B */
        i = ssl3_do_write (s, SSL3_RT_CHANGE_CIPHER_SPEC);

        if (i <= 0) {
            s->reneg_flag = 1;
            s->state = SSL3_ST_CW_FINISHED_A;
            ret = 0;
            goto err;
        }

        s->session->cipher = s->s3->tmp.new_cipher;
        if (s->s3->tmp.new_compression == NULL)
            s->session->compress_meth = 0;
        else
            s->session->compress_meth = s->s3->tmp.new_compression->id;

        //BIO_flush(s->wbio);

        cav_fprintf (cav_nb_fp,
            "pkp_client_handshake(): sent NEW change cipher spec msg\n");

        s->write_cipher_active = 0;
    }
    s->session->cipher = s->s3->tmp.new_cipher;

    if (!ssl_cipher_get_evp (s->session, &c, &hash, &comp)) {
        SSLerr (SSL_F_SSL3_SETUP_KEY_BLOCK,
            SSL_R_CIPHER_OR_HASH_UNAVAILABLE);
        ret = 0;
        goto err;
    }

    digest_type = EVP_MD_type (hash);
    cipher_type = EVP_CIPHER_nid (c);
    md_size = EVP_MD_size (hash);

    if (digest_type == NID_md5)
        hash_type = MD5_TYPE;

    else if (digest_type == NID_sha1)
        hash_type = SHA1_TYPE;

    else {
        ret = 0;
        goto err;
    }

    if (s->version > SSL3_VERSION) {
        finish_size = 16;
        ssl_version = VER_TLS;
    } else {
        finish_size = 40;
        ssl_version = VER3_0;
    }


    /* make p point to the CertVerify msg */
    p = (unsigned char *) &(s->hs_msgs[s->client_cert_verify_msg_offset]);

    handshake_len = s->hs_msgs_len - s->client_cert_verify_msg_offset;

    if (s->cav_renego > 0 && s->alloc_flag == 0) {
        cav_fprintf (cav_nb_fp,
            "pkp_client_handshake_client_auth():freeing context \n");
        if (s->context_pointer) {
#ifdef CAVIUM_FIPS
            Cfm1FreeContext (OP_BLOCKING, s->context_pointer,
                &s->cav_req_id);
#else

#ifdef CAVIUM_MULTICARD_API
            Csp1FreeContext (CONTEXT_SSL, s->context_pointer, s->dev_id);
#else
            Csp1FreeContext (CONTEXT_SSL, s->context_pointer);
#endif
#endif
        }

        s->context_pointer = s->s3->tmp.ctx_ptr;
        s->alloc_flag = 1;
    }

    if (s->state == CAV_ST_IN_HANDSHAKE) {

        if (s->cav_crypto_state == CAV_ST_IN_HANDSHAKE) {

            rc = check_handshake_completion (s,
                &i,
                &len,
                &md_size,
                &finish_size,
                &is_block,
                (char *) client_finished, (char *) server_finished);
            if (rc == 1) {
                memcpy (s->server_finished, server_finished, 80);
                memcpy (s->client_finished, client_finished, 80);
            }
        }

        if (rc == 0) {
            cav_fprintf (cav_nb_fp,
                "pkp_client_handshake_client_auth(): %s\n",
                "check_handshake_completion() not completed");
            return (0);
        } else if (rc == -1) {
            cav_fprintf (cav_nb_fp,
                "pkp_client_handshake_client_auth(): %s\n",
                "ERROR check_handshake_completion() failed");
            return (-1);
        }

    }                            // end if .. CAV_ST_IN_HANDSHAKE
    else {
        if ((s->session->cipher->id == SSL3_CK_RSA_RC4_128_MD5)
            || (s->session->cipher->id == SSL3_CK_RSA_RC4_128_SHA)
            ||
            (s->session->cipher->id ==
                TLS1_CK_RSA_EXPORT1024_WITH_RC4_56_SHA)
            || (s->session->cipher->id ==
                TLS1_CK_RSA_EXPORT1024_WITH_RC4_56_MD5)
            || (s->session->cipher->id == SSL3_CK_RSA_RC4_40_MD5)) {
            len = finish_size + md_size;
#ifdef CAVIUM_FIPS
            i = Cfm1FinishedRc4Finish (OP_BLOCKING,
                s->context_pointer,
                hash_type,
                ssl_version,
                (unsigned short) handshake_len,
                p, s->client_finished, s->server_finished, &s->cav_req_id);
#else

            i = Csp1FinishedRc4Finish (s->cav_nb_mode,
                s->context_pointer,
                hash_type,
                ssl_version,
                (unsigned short) handshake_len,
                p, s->client_finished, s->server_finished,
#ifdef CAVIUM_MULTICARD_API
                &s->cav_req_id, s->dev_id
#else
                &s->cav_req_id
#endif
                );

#endif
            if (i == 0) {

                cav_fprintf (cav_nb_fp,
                    "===>pkp_client_handshake_client_auth(): %s\n",
                    "Csp1FinishedRc4Finish() done");
            }

            else if (i == EAGAIN) {

                cav_fprintf (cav_nb_fp,
                    "pkp_client_handshake_client_auth(): %s\n",
                    "Csp1FinishedRc4Finish() EAGAIN");

                s->cav_crypto_state = CAV_ST_IN_HANDSHAKE;
                s->cav_saved_state = s->state;
                s->state = CAV_ST_IN_HANDSHAKE;
                s->cav_req_id_check_done = 0;
                s->rwstate = SSL_NITROX_BUSY;

            }                    // end .. else i == EAGAIN
            else {
                cav_fprintf (cav_nb_fp,
                    "pkp_client_handshake_client_auth(): ERROR return %d %s\n",
                    i, "from Csp1FinishedRc4Finish()");
            }

            if (i != 0) {
                ret = 0;
                return ret;
            }
        } else if ((s->session->cipher->id == SSL3_CK_RSA_DES_192_CBC3_SHA)
            ||
            (s->session->cipher->id ==
                TLS1_CK_RSA_EXPORT1024_WITH_DES_CBC_SHA)
            || (s->session->cipher->id == SSL3_CK_RSA_DES_40_CBC_SHA)
            || (s->session->cipher->id == SSL3_CK_RSA_DES_64_CBC_SHA))
        {
            is_block = 1;
            len = ((finish_size + md_size + 7) / 8) * 8;

            if (ssl_version == VER_TLS) {
#ifdef CAVIUM_FIPS
                i = Cfm1Finished3DesFinish (OP_BLOCKING, s->context_pointer,
                    hash_type,
                    ssl_version,
                    RETURN_CFM_ENCRYPTED,
                    RETURN_SFM_ENCRYPTED,
                    0,    /*client_pad_length, */
                    0,            /*server_pad_length, */
                    (unsigned short) handshake_len,
                    p,
                    s->client_finished,
                    s->server_finished, &s->cav_req_id);
#else
                i = Csp1Finished3DesFinish (s->cav_nb_mode, s->context_pointer,
                    hash_type, ssl_version,
                    RETURN_CFM_ENCRYPTED,
                    RETURN_SFM_ENCRYPTED,
                    0,    /*client_pad_length, */
                    0,            /*server_pad_length, */
                    (unsigned short) handshake_len,
                    p, s->client_finished, s->server_finished,
#ifdef CAVIUM_MULTICARD_API
                    &s->cav_req_id, s->dev_id
#else
                    &s->cav_req_id
#endif
                    );
#endif
            } else {
#ifdef CAVIUM_FIPS
                i = Cfm1Finished3DesFinish (OP_BLOCKING, s->context_pointer,
                    hash_type, ssl_version,
                    RETURN_CFM_ENCRYPTED,
                    RETURN_SFM_UNENCRYPTED,
                    0,    /*client_pad_length, */
                    0,            /*server_pad_length, */
                    (unsigned short) handshake_len,
                    p,
                    s->client_finished,
                    s->server_finished, &s->cav_req_id);
#else
                i = Csp1Finished3DesFinish (s->cav_nb_mode, s->context_pointer,
                    hash_type, ssl_version,
                    RETURN_CFM_ENCRYPTED,
                    RETURN_SFM_UNENCRYPTED,
                    0,    /*client_pad_length, */
                    0,            /*server_pad_length, */
                    (unsigned short) handshake_len,
                    p, s->client_finished, s->server_finished,
#ifdef CAVIUM_MULTICARD_API
                    &s->cav_req_id, s->dev_id
#else
                    &s->cav_req_id
#endif
                    );
#endif
            }

            if (i == 0) {
                cav_fprintf (cav_nb_fp,
                    "===>pkp_client_handshake_client_auth(): %s\n",
                    "Csp1Finished3DesFinish() done");
            }

            else if (i == EAGAIN) {

                cav_fprintf (cav_nb_fp,
                    "pkp_client_handshake_client_auth(): %s\n",
                    "Csp1Finished3DesFinish() EAGAIN");

                s->cav_crypto_state = CAV_ST_IN_HANDSHAKE;
                s->cav_saved_state = s->state;
                s->state = CAV_ST_IN_HANDSHAKE;
                s->cav_req_id_check_done = 0;
                s->rwstate = SSL_NITROX_BUSY;

            }                    // end .. else i == EAGAIN
            else {
                cav_fprintf (cav_nb_fp,
                    "pkp_client_handshake_client_auth(): ERROR return %d %s\n",
                    i, "from Csp1Finished3DesFinish()");
            }
            if (i != 0) {
                ret = 0;
                return ret;
            }
        }

        else if ((s->session->cipher->id == TLS1_CK_RSA_WITH_AES_128_SHA)
            || (s->session->cipher->id == TLS1_CK_RSA_WITH_AES_256_SHA)
            ) {

            AesType aes_type = get_Aes_type (s->session->cipher->id);
            ServerFinishMessageOutput sfmo;

            cav_fprintf (cav_nb_fp,
                "pkp_client_handshake_client_auth(): AES case\n");

            is_block = 1;

            len = ((finish_size + md_size + 15) / 16) * 16;

            if (ssl_version == VER_TLS) {
                sfmo = RETURN_SFM_ENCRYPTED;
            } else {
                // ssl3
                sfmo = RETURN_SFM_UNENCRYPTED;
            }
#ifdef CAVIUM_FIPS
            i = Cfm1FinishedAesFinish (OP_BLOCKING, s->context_pointer,
                hash_type,
                ssl_version, aes_type,
                RETURN_CFM_ENCRYPTED,
                sfmo,
                0,    /*client_pad_length, */
                0,                /*server_pad_length, */
                (unsigned short) handshake_len,
                p, s->client_finished, s->server_finished, &s->cav_req_id);
#else

            i = Csp1FinishedAesFinish (s->cav_nb_mode, s->context_pointer,
                hash_type, ssl_version, aes_type,
                RETURN_CFM_ENCRYPTED,
                sfmo,
                0,    /*client_pad_length, */
                0,                /*server_pad_length, */
                (unsigned short) handshake_len,
                p, s->client_finished, s->server_finished,
#ifdef CAVIUM_MULTICARD_API
                &s->cav_req_id, s->dev_id
#else
                &s->cav_req_id
#endif
                );

#endif
            if (i == 0) {
                cav_fprintf (cav_nb_fp,
                    "===>pkp_client_handshake_client_auth(): %s\n",
                    "Csp1FinishedAesFinish() done");
            }

            else if (i == EAGAIN) {

                cav_fprintf (cav_nb_fp,
                    "pkp_client_handshake_client_auth(): %s\n",
                    "Csp1FinishedAesFinish() EAGAIN");

                s->cav_crypto_state = CAV_ST_IN_HANDSHAKE;
                s->cav_saved_state = s->state;
                s->state = CAV_ST_IN_HANDSHAKE;
                s->cav_req_id_check_done = 0;
                s->rwstate = SSL_NITROX_BUSY;

            }                    // end .. else i == EAGAIN
            else {
                cav_fprintf (cav_nb_fp,
                    "pkp_client_handshake_client_auth(): ERROR return %d %s\n",
                    i, "from Csp1FinishedAesFinish()");
            }
            if (i != 0) {
                ret = 0;
                return ret;
            }
        }

        else {
            ret = 0;
            goto err;
        }

    }

    if (s->cav_renego == 0) {
        s->s3->rrec.off = 0;
        s->packet_length = 0;
        p = (unsigned char *) s->init_buf->data;
        *p = SSL3_MT_CCS;
        s->init_num = 1;
        s->init_off = 0;
        s->state = SSL3_ST_CW_CHANGE_B;

        /* SSL3_ST_CW_CHANGE_B */
        i = ssl3_do_write (s, SSL3_RT_CHANGE_CIPHER_SPEC);
        s->session->cipher = s->s3->tmp.new_cipher;
        if (s->s3->tmp.new_compression == NULL)
            s->session->compress_meth = 0;
        else
            s->session->compress_meth = s->s3->tmp.new_compression->id;

        //BIO_flush(s->wbio);

        cav_fprintf (cav_nb_fp,
            "pkp_client_handshake(): sent NEW change cipher spec msg\n");
    }
    /* SEND CLIENT FINISH */
    s->s3->tmp.peer_finish_md_len = len;
    memcpy ((unsigned char *) s->init_buf->data, s->client_finished, len);
    s->init_num = len;
    s->init_off = 0;
    s->state = SSL3_ST_CW_FINISHED_B;
    i = ssl3_do_write (s, SSL3_RT_HANDSHAKE);

    /* activate cipher on the output (writing)  side */
    s->write_cipher_active = 1;

    s->state = SSL3_ST_CW_CHANGE_A;

    if ((s->enc_read_ctx == NULL) &&
        ((s->enc_read_ctx =
                (EVP_CIPHER_CTX *)
                OPENSSL_malloc (sizeof (EVP_CIPHER_CTX))) == NULL)) {
        ret = 0;
        return ret;
    }

    EVP_CIPHER_CTX_init (s->enc_read_ctx);
    s->enc_read_ctx->cipher = c;
    s->read_hash = hash;

    if ((s->enc_write_ctx == NULL) &&
        ((s->enc_write_ctx =
                (EVP_CIPHER_CTX *)
                OPENSSL_malloc (sizeof (EVP_CIPHER_CTX))) == NULL)) {
        ret = 0;
        return ret;
    }

    EVP_CIPHER_CTX_init (s->enc_write_ctx);
    s->enc_write_ctx->cipher = c;
    s->write_hash = hash;

    /* Here update some variables for record processing */
    s->ssl_version = ssl_version;

    /* I hope that client and the server are using the same cipher :-)  */
    s->cipher_type = EVP_CIPHER_CTX_nid (s->enc_write_ctx);

    /* abd again the same hash */
    s->digest_type = EVP_MD_type (hash);

    s->md_size = md_size;

    ret = 1;
    s->reneg_flag = 0;

  err:
    if (s->reneg_flag) {
        return ret;
    }

    if (s->cav_renego > 0) {
        s->cav_renego = 0;
        s->alloc_flag = 0;
    }

    return ret;

}                                /*int pkp_client_handshake_client_auth(SSL *s) */


/*
 * Checks if a prior request has completed.
 * Returns 0 if the request has not completed.
 * Returns >0 if the request has completed.
 * Returns -1 on error
 */
int
check_decrypt_completion (SSL * s)
{

    int rc;

    cav_fprintf (cav_nb_fp, "check_decrypt_completion(): entry\n");

    /*
     * Check whether the application has already checked
     * for comletion, by directly calling Csp1CheckForCompletion.
     */
    if (s->cav_req_id_check_done) {

        /*
         * already checked, probably directly by app
         */
        cav_fprintf (cav_nb_fp, "check_decrypt_completion(): %s\n",
            "already checked, probably directly by app\n");

    } else {

        /* completion check has not been done yet */
#ifdef CAVIUM_FIPS
        rc = Cfm1CheckForCompletion (s->cav_req_id);
#else

#ifdef CAVIUM_MULTICARD_API
        rc = Csp1CheckForCompletion (s->cav_req_id, s->dev_id);
#else
        rc = Csp1CheckForCompletion (s->cav_req_id);
#endif
#endif
        if (rc == EAGAIN) {
            cav_fprintf (cav_nb_fp, "check_decrypt_completion(): %s\n",
                "Csp1CheckForCompletion() EAGAIN");
            return (0);
        } else if (rc != 0) {
            cav_fprintf (cav_nb_fp,
                "check_decrypt_completion(): %s %d, 0x%0x\n",
                "Csp1CheckForCompletion() got ERROR, rc = ", rc, rc);
            // -----
            s->cav_crypto_state = 0;
            s->cav_req_id_check_done = 1;
            s->rwstate = SSL_NOTHING;
            return (-1);
        }

        /* cmd completed */
        s->cav_req_id_check_done = 1;

    }

    cav_fprintf (cav_nb_fp, "check_decrypt_completion(): %s\n",
        "Csp1CheckForCompletion() done");

    cav_fprintf (cav_nb_fp,
        "check_decrypt_completion(): cav_process_flag = %d, md_size = %d, s->s3->rrec.length = %d, cav_msg_len = %d\n",
        s->cav_process_flag, s->md_size, s->s3->rrec.length,
        s->cav_msg_len);

    cav_fprintf (cav_nb_fp,
        "check_decrypt_completion(): *(Uint8 *)(s->s3->rrec.data + s->s3->rrec.length - 1) = %d\n",
        *(Uint8 *) (s->s3->rrec.data + s->s3->rrec.length - 1));

    if (s->cav_process_flag) {
        s->cav_msg_len = s->s3->rrec.length - s->md_size;
        s->cav_process_flag = 0;
    } else {
        /*
         * 3Des --- we need some special processing
         * to get record size.
         */
        s->cav_msg_len =
            s->s3->rrec.length - s->md_size -
            *(Uint8 *) (s->s3->rrec.data + s->s3->rrec.length - 1) - 1;
    }

    s->cav_crypto_state = 0;
    s->cav_req_id = 0;
    s->cav_req_id_check_done = 0;
    s->rwstate = SSL_NOTHING;

    if (s->cav_msg_len == 0) {
        cav_fprintf (cav_nb_fp,
            "check_decrypt_completion(): got 0 byte record\n");
    }

    return (int) s->cav_msg_len;

}                                // end check_decrypt_completion()


int
check_encrypt_completion (SSL * s)
{

    int rc;

    cav_fprintf (cav_nb_fp, "check_encrypt_completion(): entry\n");

    /*
     * Check whether the application has already checked
     * for comletion, by directly calling Csp1CheckForCompletion.
     */
    if (s->cav_req_id_check_done) {
        // already checked, probably directly by app
        cav_fprintf (cav_nb_fp, "check_encrypt_completion(): %s\n",
            "already checked, probably directly by app\n");
    } else {

        // should check for cmd completion here
#ifdef CAVIUM_FIPS
        rc = Cfm1CheckForCompletion (s->cav_req_id);
#else

#ifdef CAVIUM_MULTICARD_API
        rc = Csp1CheckForCompletion (s->cav_req_id, s->dev_id);
#else
        rc = Csp1CheckForCompletion (s->cav_req_id);
#endif
#endif
        if (rc == EAGAIN) {
            cav_fprintf (cav_nb_fp, "check_encrypt_completion(): %s\n",
                "Csp1CheckForCompletion() EAGAIN");
            return (0);
        } else if (rc != 0) {
            cav_fprintf (cav_nb_fp,
                "check_encrypt_completion(): %s %d, 0x%0x\n",
                "Csp1CheckForCompletion() got ERROR, rc = ", rc, rc);
            // -----
            s->cav_crypto_state = 0;
            s->cav_req_id_check_done = 1;
            s->rwstate = SSL_NOTHING;
            return (-1);
        }
        // cmd completed
        s->cav_req_id_check_done = 1;
    }

    cav_fprintf (cav_nb_fp, "check_encrypt_completion(): %s\n",
        "Csp1CheckForCompletion() done");

    if (s->cav_process_flag) {
        s->cav_process_flag = 0;
        s->cav_msg_len = s->s3->wrec.length + s->md_size;
    }

    s->cav_crypto_state = 0;
    s->cav_req_id = 0;
    s->cav_req_id_check_done = 0;
    s->rwstate = SSL_NOTHING;

    cav_fprintf (cav_nb_fp,
        "check_encrypt_completion(): returning s->cav_msg_len = %d\n",
        s->cav_msg_len);

    return (int) s->cav_msg_len;

}                                // end check_encrypt_completion()


/*
 * check_handshake_completion:
 *
 *  Returns:
 *      0 if cmd has not completed
 *      1 if cmd has completed
 */
int
check_handshake_completion (SSL * s,
    int *ip,
    int *lenp,
    int *md_sizep,
    int *finish_sizep,
    int *is_blockp, char *client_finishedp, char *server_finishedp)
{
    int rc;
    Rc4Type rc4_type;
    DesType des_type;

    /*
     * restore proper state that was saved in cav_saved_state,
     * so we could navigate to this piece of code.
     */
    s->state = s->cav_saved_state;

    if (s->cav_req_id_check_done) {
        cav_fprintf (cav_nb_fp, "check_handshake_completion(): %s\n",
            "already checked, probably directly by app\n");
        rc = 0;
    } else {
#ifdef CAVIUM_FIPS
        rc = Cfm1CheckForCompletion (s->cav_req_id);
#else
#ifdef CAVIUM_MULTICARD_API
        rc = Csp1CheckForCompletion (s->cav_req_id, s->dev_id);
#else
        rc = Csp1CheckForCompletion (s->cav_req_id);
#endif
#endif
    }

    cav_fprintf (cav_nb_fp,
        "check_handshake_completion():Csp1CheckForCompletion() rc=%d\n",
        rc);


    switch (rc) {

    case EAGAIN:
        cav_fprintf (cav_nb_fp, "check_handshake_completion(): %s\n",
            "Csp1CheckForCompletion() EAGAIN");
        s->cav_saved_state = s->state;

        if ((s->state == SSL3_ST_SR_CERT_VRFY_A)) {
            s->state = CAV_ST_IN_VRFY_CERT;
        } else if (((s->cav_renego == 0) &&
                (s->state == SSL3_ST_SW_CHANGE_A)) || (s->flag == 1))
            s->state = CAV_ST_IN_RESUME_HANDSHAKE;
        else
            s->state = CAV_ST_IN_HANDSHAKE;

        return (0);

    case 0:
        // done:
        cav_fprintf (cav_nb_fp, "===>check_handshake_completion(): %s\n",
            "Csp1CheckForCompletion() completed");

        s->flag = 0;
        s->cav_crypto_state = 0;
        s->cav_req_id_check_done = 1;
        s->rwstate = SSL_NOTHING;
        *ip = 0;
        memcpy (client_finishedp, s->client_finished, 80);
        memcpy (server_finishedp, s->server_finished, 80);


        switch (s->session->cipher->id) {
        case SSL3_CK_RSA_RC4_128_MD5:
        case SSL3_CK_RSA_RC4_128_SHA:
        case TLS1_CK_RSA_EXPORT1024_WITH_RC4_56_SHA:
        case TLS1_CK_RSA_EXPORT1024_WITH_RC4_56_MD5:
        case SSL3_CK_RSA_RC4_40_MD5:
            rc4_type = get_Rc4_type (s->session->cipher->id);
            *lenp = *finish_sizep + *md_sizep;
            break;

        case SSL3_CK_RSA_DES_192_CBC3_SHA:
        case TLS1_CK_RSA_EXPORT1024_WITH_DES_CBC_SHA:
        case SSL3_CK_RSA_DES_40_CBC_SHA:
        case SSL3_CK_RSA_DES_64_CBC_SHA:
            des_type = get_Des_type (s->session->cipher->id);
            cav_fprintf (cav_nb_fp,
                "check_handshake_completion(): DES case\n");
            *is_blockp = 1;
            *lenp = ((*finish_sizep + *md_sizep + 7) / 8) * 8;
            break;

        case TLS1_CK_RSA_WITH_AES_128_SHA:
        case TLS1_CK_RSA_WITH_AES_256_SHA:
            cav_fprintf (cav_nb_fp,
                "check_handshake_completion(): AES case\n");
            *is_blockp = 1;
            *lenp = ((*finish_sizep + *md_sizep + 15) / 16) * 16;
            break;

        default:
            cav_fprintf (cav_nb_fp,
                "check_handshake_completion(): ERROR: default case\n");
            return (-1);

        }                        // end switch

        break;


    default:
        cav_fprintf (cav_nb_fp, "check_handshake_completion(): %s\n",
            "Csp1CheckForCompletion() default case");
        /*
         * should we reset the cav_crypto_state to 0 here
         * to prevent an infinite loop
         */
        s->cav_crypto_state = 0;
        s->cav_req_id_check_done = 1;
        s->rwstate = SSL_NOTHING;
        return (-1);

    }

    return (1);


}                                /* end check_handshake_completion() */

int
check_dec_peer_completion (SSL * s,
    int *ip,
    int *lenp,
    int *md_sizep,
    int *finish_sizep,
    int *is_blockp,
    unsigned short *peer_lenp, char *dec_peer_client_finishedp)
{

    int rc;
    DesType des_type;

    s->state = s->cav_saved_state;

    if (s->cav_req_id_check_done) {
        cav_fprintf (cav_nb_fp, "check_dec_peer_completion(): %s\n",
            "already checked, probably directly by app\n");
        rc = 0;
    } else {
#ifdef CAVIUM_FIPS
        rc = Cfm1CheckForCompletion (s->cav_req_id);
#else
#ifdef CAVIUM_MULTICARD_API
        rc = Csp1CheckForCompletion (s->cav_req_id, s->dev_id);
#else
        rc = Csp1CheckForCompletion (s->cav_req_id);
#endif
#endif
    }

    cav_fprintf (cav_nb_fp,
        "check_dec_peer_completion():Csp1CheckForCompletion() rc=%d\n",
        rc);

    switch (rc) {

    case EAGAIN:
        cav_fprintf (cav_nb_fp, "check_dec_peer_completion(): %s\n",
            "Csp1CheckForCompletion() EAGAIN");
        s->cav_saved_state = s->state;

        if (((s->state == SSL3_ST_SR_FINISHED_B) ||
                (s->state == SSL3_ST_CR_FINISHED_B))
            && s->cav_crypto_state == CAV_ST_IN_CHK_DEC_PEER_2) {
            s->state = CAV_ST_IN_RESUME_HANDSHAKE;
        } else if ((s->flag == 1) &&
            (s->cav_crypto_state == CAV_ST_IN_CHK_DEC_PEER))
            s->state = CAV_ST_IN_RESUME_HANDSHAKE;

        else
            s->state = CAV_ST_IN_HANDSHAKE;

        return (0);

    case 0:
        cav_fprintf (cav_nb_fp, "===>check_dec_peer_completion(): %s\n",
            "Csp1CheckForCompletion() completed");

        s->flag = 0;            /* added due to reneg failing with reconnect for des and aes */
        s->cav_crypto_state = 0;
        s->cav_req_id_check_done = 1;
        s->rwstate = SSL_NOTHING;
        *ip = 0;
        *peer_lenp = s->peer_len - 3;

        memcpy (dec_peer_client_finishedp, s->dec_peer_client_finished,
            80);
        switch (s->session->cipher->id) {

        case SSL3_CK_RSA_DES_192_CBC3_SHA:
        case TLS1_CK_RSA_EXPORT1024_WITH_DES_CBC_SHA:
        case SSL3_CK_RSA_DES_40_CBC_SHA:
        case SSL3_CK_RSA_DES_64_CBC_SHA:
            des_type = get_Des_type (s->session->cipher->id);
            cav_fprintf (cav_nb_fp,
                "check_dec_peer_completion(): DES case\n");
            *is_blockp = 1;
            *lenp = ((*finish_sizep + *md_sizep + 7) / 8) * 8;
            break;

        case TLS1_CK_RSA_WITH_AES_128_SHA:
        case TLS1_CK_RSA_WITH_AES_256_SHA:
            cav_fprintf (cav_nb_fp,
                "check_dec_peer_completion(): AES case\n");
            *is_blockp = 1;
            *lenp = ((*finish_sizep + *md_sizep + 15) / 16) * 16;
            break;

        default:
            cav_fprintf (cav_nb_fp,
                "check_dec_peer_completion(): ERROR: default case\n");
            return (-1);
        }
        break;

    default:
        cav_fprintf (cav_nb_fp, "check_dec_peer_completion(): %s\n",
            "Csp1CheckForCompletion() default case");
        /*
         * should we reset the cav_crypto_state to 0 here
         * to prevent an infinite loop
         */
        s->cav_crypto_state = 0;
        s->cav_req_id_check_done = 1;
        s->rwstate = SSL_NOTHING;
        return (-1);

    }                            // end switch

    return (1);
}

int
check_pre_master_completion (SSL * s,
#ifdef MC2
    Uint16 * out_len,
#else
    Uint64 * out_len,
#endif
    char *result)
{
    int rc;

    s->state = s->cav_saved_state;
    if (s->cav_req_id_check_done) {
        cav_fprintf (cav_nb_fp, "check_pre_master_completion(): %s\n",
            "already checked, probably directly by app\n");
        rc = 0;
    } else {
#ifdef CAVIUM_FIPS
        rc = Cfm1CheckForCompletion (s->cav_req_id);
#else
#ifdef CAVIUM_MULTICARD_API
        rc = Csp1CheckForCompletion (s->cav_req_id, s->dev_id);
#else
        rc = Csp1CheckForCompletion (s->cav_req_id);
#endif
#endif
    }
    cav_fprintf (cav_nb_fp,
        "check_pre_master_completion():Csp1CheckForCompletion() rc=%d\n",
        rc);

    switch (rc) {

    case EAGAIN:
        cav_fprintf (cav_nb_fp, "check_pre_master_completion(): %s\n",
            "Csp1CheckForCompletion() EAGAIN");
        s->cav_saved_state = s->state;
        if (s->state == SSL3_ST_SR_CERT_VRFY_A)
            s->state = CAV_ST_IN_VRFY_CERT;
        else
            s->state = CAV_ST_IN_HANDSHAKE;
        return (0);
    case 0:
        cav_fprintf (cav_nb_fp, "===>check_pre_master_completion(): %s\n",
            "Csp1CheckForCompletion() completed");

        s->cav_crypto_state = 0;
        s->cav_req_id_check_done = 1;
        s->rwstate = SSL_NOTHING;
#ifdef MC2
        *out_len = (Uint32) ntohs (s->pre_master_len);
        memcpy (result, s->pre_master_result, s->cryp_flen);
#else
        *out_len = (Uint32) s->pre_master_len;
#endif

        break;
    default:
        cav_fprintf (cav_nb_fp, "check_pre_master_completion(): %s\n",
            "Csp1CheckForCompletion() default case");
        /*
         * should we reset the cav_crypto_state to 0 here
         * to prevent an infinite loop
         */
        s->cav_crypto_state = 0;
        s->cav_req_id_check_done = 1;
        s->rwstate = SSL_NOTHING;
        return (-1);
    }                            // end switch
    return (1);
}

int
check_vryf_mac_completion (SSL * s)
{
    int rc;

    s->state = s->cav_saved_state;
    if (s->cav_req_id_check_done) {
        // already checked, probably directly by app
        cav_fprintf (cav_nb_fp, "check_vrfy_mac_completion(): %s\n",
            "already checked, probably directly by app\n");
        rc = 0;
    } else {
        // should check for cmd completion here
#ifdef CAVIUM_FIPS
        rc = Cfm1CheckForCompletion (s->cav_req_id);
#else
#ifdef CAVIUM_MULTICARD_API
        rc = Csp1CheckForCompletion (s->cav_req_id, s->dev_id);
#else
        rc = Csp1CheckForCompletion (s->cav_req_id);
#endif
#endif
    }
    cav_fprintf (cav_nb_fp,
        "check_vrfy_mac_completion():Csp1CheckForCompletion() rc=%d\n",
        rc);

    switch (rc) {

    case EAGAIN:
        // not done yet
        cav_fprintf (cav_nb_fp, "check_vrfy_mac_completion(): %s\n",
            "Csp1CheckForCompletion() EAGAIN");
        s->cav_saved_state = s->state;
        s->cav_crypto_state = CAV_ST_IN_VRFY_CERT;
        s->state = CAV_ST_IN_VRFY_CERT;
        return (0);
    case 0:
        // done:
        cav_fprintf (cav_nb_fp, "===>check_vrfy_mac_completion(): %s\n",
            "Csp1CheckForCompletion() completed");

        s->cav_crypto_state = 0;
        s->cav_req_id_check_done = 1;
        s->rwstate = SSL_NOTHING;
        break;
    default:
        cav_fprintf (cav_nb_fp, "check_vrfy_mac_completion(): %s\n",
            "Csp1CheckForCompletion() default case");
        /*
         * should we reset the cav_crypto_state to 0 here
         * to prevent an infinite loop
         */
        s->cav_crypto_state = 0;
        s->cav_req_id_check_done = 1;
        s->rwstate = SSL_NOTHING;
        return (-1);
    }                            // end switch
    return (1);
}

/*
 * For Handshake Offloading
 * Reads the shared secret key context from Nitrox and
 * sets software context structures.
 *
 */

int
pkp_read_ssl_session_context (SSL * s)
{

    int i, is_ssl3_sha = 0;
    unsigned char *p1;
    Uint64 context_offset;
#ifndef CAVIUM_FIPS
    int res;
#endif

    if ((p1 =
            (unsigned char *) OPENSSL_malloc (MAX_CRYPTO_CTX_SIZE)) ==
        NULL)
        goto err;

    context_offset = CRYPTO_OFFSET_IN_CTX;
#ifndef CAVIUM_FIPS
    res = Csp1ReadContext (CAVIUM_BLOCKING,
        s->context_pointer + context_offset, MAX_CRYPTO_CTX_SIZE, p1,
#ifdef CAVIUM_MULTICARD_API
        &s->cav_req_id, s->dev_id
#else
        &s->cav_req_id
#endif
        );
    if (res != 0)
        goto err;
#endif

    i = EVP_MD_size (s->write_hash);

    if (s->ssl_version == VER3_0 &&
        EVP_MD_type (s->write_hash) == NID_sha1)
        is_ssl3_sha = 1;

    switch (s->session->cipher->id) {

    case SSL3_CK_RSA_RC4_128_SHA:
    case SSL3_CK_RSA_RC4_128_MD5:
    case TLS1_CK_RSA_EXPORT1024_WITH_RC4_56_SHA:
    case TLS1_CK_RSA_EXPORT1024_WITH_RC4_56_MD5:
    case SSL3_CK_RSA_RC4_40_MD5:
        if (!s->server) {
            if (is_ssl3_sha)
                memcpy (&(s->s3->write_mac_secret[0]), &(p1[24]), i);
            else {
                memcpy (&(s->s3->write_opad_hash[0]), p1, i);
                memcpy (&(s->s3->write_ipad_hash[0]), &(p1[24]), i);
            }
            memcpy (&(s->s3->write_sequence[0]), &(p1[48]), 8);
            rc4_init_cipher_ctx (s->enc_write_ctx,
                s->enc_write_ctx->cipher, &(p1[56]), 1);

            if (is_ssl3_sha)
                memcpy (&(s->s3->read_mac_secret[0]), &(p1[344]), i);
            else {
                memcpy (&(s->s3->read_opad_hash[0]), &(p1[320]), i);
                memcpy (&(s->s3->read_ipad_hash[0]), &(p1[344]), i);
            }
            memcpy (&(s->s3->read_sequence[0]), &(p1[368]), 8);
            rc4_init_cipher_ctx (s->enc_read_ctx, s->enc_read_ctx->cipher,
                &(p1[376]), 0);
        } else {

            if (is_ssl3_sha)
                memcpy (&(s->s3->read_mac_secret[0]), &(p1[24]), i);
            else {
                memcpy (&(s->s3->read_opad_hash[0]), p1, i);
                memcpy (&(s->s3->read_ipad_hash[0]), &(p1[24]), i);
            }
            memcpy (&(s->s3->read_sequence[0]), &(p1[48]), 8);
            rc4_init_cipher_ctx (s->enc_read_ctx, s->enc_read_ctx->cipher,
                &(p1[56]), 0);

            if (is_ssl3_sha)
                memcpy (&(s->s3->write_mac_secret[0]), &(p1[344]), i);
            else {
                memcpy (&(s->s3->write_opad_hash[0]), &(p1[320]), i);
                memcpy (&(s->s3->write_ipad_hash[0]), &(p1[344]), i);
            }
            memcpy (&(s->s3->write_sequence[0]), &(p1[368]), 8);
            rc4_init_cipher_ctx (s->enc_write_ctx,
                s->enc_write_ctx->cipher, &(p1[376]), 1);
        }

        break;

    case SSL3_CK_RSA_DES_192_CBC3_SHA:
    case SSL3_CK_RSA_DES_40_CBC_SHA:
    case SSL3_CK_RSA_DES_64_CBC_SHA:
    case TLS1_CK_RSA_EXPORT1024_WITH_DES_CBC_SHA:

        if (!s->server) {
            if (is_ssl3_sha)
                memcpy (&(s->s3->write_mac_secret[0]), &(p1[24]), i);
            else {
                memcpy (&(s->s3->write_opad_hash[0]), p1, i);
                memcpy (&(s->s3->write_ipad_hash[0]), &(p1[24]), i);
            }
            memcpy (&(s->s3->write_sequence[0]), &(p1[48]), 8);
            EVP_CipherInit_ex (s->enc_write_ctx, s->enc_write_ctx->cipher,
                NULL, &(p1[64]), &(p1[56]), 1);
            if (is_ssl3_sha)
                memcpy (&(s->s3->read_mac_secret[0]), &(p1[120]), i);
            else {
                memcpy (&(s->s3->read_opad_hash[0]), &(p1[96]), i);
                memcpy (&(s->s3->read_ipad_hash[0]), &(p1[120]), i);
            }
            memcpy (&(s->s3->read_sequence[0]), &(p1[144]), 8);
            EVP_CipherInit_ex (s->enc_read_ctx, s->enc_read_ctx->cipher,
                NULL, &(p1[160]), &(p1[152]), 0);
        } else {

            if (is_ssl3_sha)
                memcpy (&(s->s3->read_mac_secret[0]), &(p1[24]), i);
            else {
                memcpy (&(s->s3->read_opad_hash[0]), p1, i);
                memcpy (&(s->s3->read_ipad_hash[0]), &(p1[24]), i);
            }
            memcpy (&(s->s3->read_sequence[0]), &(p1[48]), 8);
            EVP_CipherInit_ex (s->enc_read_ctx, s->enc_read_ctx->cipher,
                NULL, &(p1[64]), &(p1[56]), 0);
            if (is_ssl3_sha)
                memcpy (&(s->s3->write_mac_secret[0]), &(p1[120]), i);
            else {
                memcpy (&(s->s3->write_opad_hash[0]), &(p1[96]), i);
                memcpy (&(s->s3->write_ipad_hash[0]), &(p1[120]), i);
            }
            memcpy (&(s->s3->write_sequence[0]), &(p1[144]), 8);
            EVP_CipherInit_ex (s->enc_write_ctx, s->enc_write_ctx->cipher,
                NULL, &(p1[160]), &(p1[152]), 1);
        }
        break;

    case TLS1_CK_RSA_WITH_AES_128_SHA:
    case TLS1_CK_RSA_WITH_AES_256_SHA:
        if (!s->server) {
            if (is_ssl3_sha)
                memcpy (&(s->s3->write_mac_secret[0]), &(p1[24]), i);
            else {
                memcpy (&(s->s3->write_opad_hash[0]), p1, i);
                memcpy (&(s->s3->write_ipad_hash[0]), &(p1[24]), i);
            }
            memcpy (&(s->s3->write_sequence[0]), &(p1[48]), 8);
            EVP_CipherInit_ex (s->enc_write_ctx, s->enc_write_ctx->cipher,
                NULL, &(p1[72]), &(p1[56]), 1);
            if (is_ssl3_sha)
                memcpy (&(s->s3->read_mac_secret[0]), &(p1[152]), i);
            else {
                memcpy (&(s->s3->read_opad_hash[0]), &(p1[128]), i);
                memcpy (&(s->s3->read_ipad_hash[0]), &(p1[152]), i);
            }
            memcpy (&(s->s3->read_sequence[0]), &(p1[176]), 8);
            EVP_CipherInit_ex (s->enc_read_ctx, s->enc_read_ctx->cipher,
                NULL, &(p1[200]), &(p1[184]), 0);
        } else {
            if (is_ssl3_sha)
                memcpy (&(s->s3->read_mac_secret[0]), &(p1[24]), i);
            else {
                memcpy (&(s->s3->read_opad_hash[0]), p1, i);
                memcpy (&(s->s3->read_ipad_hash[0]), &(p1[24]), i);
            }
            memcpy (&(s->s3->read_sequence[0]), &(p1[48]), 8);
            EVP_CipherInit_ex (s->enc_read_ctx, s->enc_read_ctx->cipher,
                NULL, &(p1[72]), &(p1[56]), 0);
            if (is_ssl3_sha)
                memcpy (&(s->s3->write_mac_secret[0]), &(p1[152]), i);
            else {
                memcpy (&(s->s3->write_opad_hash[0]), &(p1[128]), i);
                memcpy (&(s->s3->write_ipad_hash[0]), &(p1[152]), i);
            }
            memcpy (&(s->s3->write_sequence[0]), &(p1[176]), 8);
            EVP_CipherInit_ex (s->enc_write_ctx, s->enc_write_ctx->cipher,
                NULL, &(p1[200]), &(p1[184]), 1);
        }
        break;
    }

    OPENSSL_free (p1);
    return (1);
  err:

    return (0);

}

/*
 * For Handshake Offloading
 * Updates the secret key context in Nitrox
 * called when Renegotiation requested from either client or server
 *
 */


int
pkp_write_updated_ssl_session_context (SSL * s)
{
    unsigned char *read_state, *write_state;
#ifndef CAVIUM_FIPS
    int res;
#endif
    Uint64 wr_st_off, re_st_off;

    // RC4 state and sequence Number Need to be updated in Nlite
    // 264 + 8

    if ((read_state = (unsigned char *) OPENSSL_malloc (272)) == NULL)
        goto err;

    if ((write_state = (unsigned char *) OPENSSL_malloc (272)) == NULL)
        goto err;

    memset (read_state, 0, 272);
    memset (write_state, 0, 272);

    switch (s->session->cipher->id) {
    case SSL3_CK_RSA_RC4_128_SHA:
    case SSL3_CK_RSA_RC4_128_MD5:
    case TLS1_CK_RSA_EXPORT1024_WITH_RC4_56_SHA:
    case TLS1_CK_RSA_EXPORT1024_WITH_RC4_56_MD5:
    case SSL3_CK_RSA_RC4_40_MD5:
        wr_st_off = 8 * 28;
        re_st_off = 8 * 68;

        if (!s->server) {
            memcpy (write_state, &(s->s3->write_sequence[0]), 8);
            rc4_get_cipher_state (&(write_state[8]), s->enc_write_ctx);

            memcpy (read_state, &(s->s3->read_sequence[0]), 8);
            rc4_get_cipher_state (&(read_state[8]), s->enc_read_ctx);
        } else {
            memcpy (read_state, &(s->s3->write_sequence[0]), 8);
            rc4_get_cipher_state (&(read_state[8]), s->enc_write_ctx);

            memcpy (write_state, &(s->s3->read_sequence[0]), 8);
            rc4_get_cipher_state (&(write_state[8]), s->enc_read_ctx);
        }
#ifndef CAVIUM_FIPS
        res = Csp1WriteContext (CAVIUM_BLOCKING,
            s->context_pointer + wr_st_off, 272,    // RC4 state + seq number
            write_state,
#ifdef CAVIUM_MULTICARD_API
            &s->cav_req_id, s->dev_id
#else
            &s->cav_req_id
#endif
            );

        if (res != 0)
            goto err;

        res = Csp1WriteContext (CAVIUM_BLOCKING,
            s->context_pointer + re_st_off, 272, read_state,
#ifdef CAVIUM_MULTICARD_API
            &s->cav_req_id, s->dev_id
#else
            &s->cav_req_id
#endif
            );

        if (res != 0)
            goto err;
#endif

        break;

    case SSL3_CK_RSA_DES_192_CBC3_SHA:
    case SSL3_CK_RSA_DES_40_CBC_SHA:
    case SSL3_CK_RSA_DES_64_CBC_SHA:
    case TLS1_CK_RSA_EXPORT1024_WITH_DES_CBC_SHA:
        wr_st_off = 8 * 28;
        re_st_off = 8 * 40;
        if (!s->server) {
            memcpy (write_state, &(s->s3->write_sequence[0]), 8);
            memcpy (&(write_state[8]), s->enc_write_ctx->iv,
                EVP_CIPHER_CTX_iv_length (s->enc_write_ctx));

            memcpy (read_state, &(s->s3->read_sequence[0]), 8);
            memcpy (&(read_state[8]), s->enc_read_ctx->iv,
                EVP_CIPHER_CTX_iv_length (s->enc_read_ctx));
        } else {
            memcpy (read_state, &(s->s3->write_sequence[0]), 8);
            memcpy (&(read_state[8]), s->enc_write_ctx->iv,
                EVP_CIPHER_CTX_iv_length (s->enc_write_ctx));

            memcpy (write_state, &(s->s3->read_sequence[0]), 8);
            memcpy (&(write_state[8]), s->enc_read_ctx->iv,
                EVP_CIPHER_CTX_iv_length (s->enc_read_ctx));

        }
#ifndef CAVIUM_FIPS
        res = Csp1WriteContext (CAVIUM_BLOCKING,
            s->context_pointer + wr_st_off, 16,    // seq number + IV
            write_state,
#ifdef CAVIUM_MULTICARD_API
            &s->cav_req_id, s->dev_id
#else
            &s->cav_req_id
#endif
            );

        if (res != 0)
            goto err;

        res = Csp1WriteContext (CAVIUM_BLOCKING,
            s->context_pointer + re_st_off, 16, read_state,
#ifdef CAVIUM_MULTICARD_API
            &s->cav_req_id, s->dev_id
#else
            &s->cav_req_id
#endif
            );
        if (res != 0)
            goto err;
#endif

        break;

    case TLS1_CK_RSA_WITH_AES_128_SHA:
    case TLS1_CK_RSA_WITH_AES_256_SHA:
        wr_st_off = 8 * 28;
        re_st_off = 8 * 44;

        if (!s->server) {
            memcpy (write_state, &(s->s3->write_sequence[0]), 8);
            memcpy (&(write_state[8]), s->enc_write_ctx->iv,
                EVP_CIPHER_CTX_iv_length (s->enc_write_ctx));
            memcpy (read_state, &(s->s3->read_sequence[0]), 8);
            memcpy (&(read_state[8]), s->enc_read_ctx->iv,
                EVP_CIPHER_CTX_iv_length (s->enc_read_ctx));
        } else {
            memcpy (read_state, &(s->s3->write_sequence[0]), 8);
            memcpy (&(read_state[8]), s->enc_write_ctx->iv,
                EVP_CIPHER_CTX_iv_length (s->enc_write_ctx));
            memcpy (write_state, &(s->s3->read_sequence[0]), 8);
            memcpy (&(write_state[8]), s->enc_read_ctx->iv,
                EVP_CIPHER_CTX_iv_length (s->enc_read_ctx));
        }

#ifndef CAVIUM_FIPS
        res = Csp1WriteContext (CAVIUM_BLOCKING,
            s->context_pointer + wr_st_off, 24,    // sequence num +IV
            write_state,
#ifdef CAVIUM_MULTICARD_API
            &s->cav_req_id, s->dev_id
#else
            &s->cav_req_id
#endif
            );

        if (res != 0)
            goto err;
        res = Csp1WriteContext (CAVIUM_BLOCKING,
            s->context_pointer + re_st_off, 24, read_state,
#ifdef CAVIUM_MULTICARD_API
            &s->cav_req_id, s->dev_id
#else
            &s->cav_req_id
#endif
            );

        if (res != 0)
            goto err;
#endif
        break;
    }

    OPENSSL_free (read_state);
    OPENSSL_free (write_state);
    return (1);
  err:
    return (0);

}


/*
 *For Record Process Offloading
 * Writes secret key context to Nitrox
 *
 */

int
pkp_write_ssl_session_context (SSL * s)
{
    unsigned char *p1;
    Uint64 context_offset;
    int i, is_ssl3_sha = 0;;
#ifndef CAVIUM_FIPS
    int res;
#endif

    context_offset = CRYPTO_OFFSET_IN_CTX;
    i = EVP_MD_size (s->write_hash);

    //initialized for record processing in Nitrox

    s->read_cipher_active = 1;
    s->write_cipher_active = 1;
    s->digest_type = EVP_MD_type (s->write_hash);
    s->cipher_type = EVP_CIPHER_CTX_nid (s->enc_write_ctx);
    s->md_size = i;
    if (s->version > SSL3_VERSION)
        s->ssl_version = VER_TLS;
    else
        s->ssl_version = VER3_0;

    if (s->ssl_version == VER3_0 &&
        EVP_MD_type (s->write_hash) == NID_sha1)
        is_ssl3_sha = 1;

    if ((p1 =
            (unsigned char *) OPENSSL_malloc (MAX_CRYPTO_CTX_SIZE)) ==
        NULL)
        goto err;
    memset (p1, 0, 640);
    switch (s->session->cipher->id) {
    case SSL3_CK_RSA_RC4_128_SHA:
    case SSL3_CK_RSA_RC4_128_MD5:
    case TLS1_CK_RSA_EXPORT1024_WITH_RC4_56_SHA:
    case TLS1_CK_RSA_EXPORT1024_WITH_RC4_56_MD5:
    case SSL3_CK_RSA_RC4_40_MD5:

        if (!s->server) {
            if (is_ssl3_sha)
                memcpy (&(p1[24]), &(s->s3->write_mac_secret[0]), i);
            else {
                memcpy (p1, &(s->s3->write_opad_hash[0]), i);
                memcpy (&(p1[24]), &(s->s3->write_ipad_hash[0]), i);
            }
            memcpy (&(p1[48]), &(s->s3->write_sequence[0]), 8);
            rc4_get_cipher_state (&(p1[56]), s->enc_write_ctx);

            if (is_ssl3_sha)
                memcpy (&(p1[344]), &(s->s3->read_mac_secret[0]), i);
            else {
                memcpy (&(p1[320]), &(s->s3->read_opad_hash[0]), i);
                memcpy (&(p1[344]), &(s->s3->read_ipad_hash[0]), i);
            }
            memcpy (&(p1[368]), &(s->s3->read_sequence[0]), 8);
            rc4_get_cipher_state (&(p1[376]), s->enc_read_ctx);

        } else {
            if (is_ssl3_sha)
                memcpy (&(p1[24]), &(s->s3->read_mac_secret[0]), i);
            else {
                memcpy (p1, &(s->s3->read_opad_hash[0]), i);
                memcpy (&(p1[24]), &(s->s3->read_ipad_hash[0]), i);
            }
            memcpy (&(p1[48]), &(s->s3->read_sequence[0]), 8);
            rc4_get_cipher_state (&(p1[56]), s->enc_read_ctx);

            if (is_ssl3_sha)
                memcpy (&(p1[344]), &(s->s3->write_mac_secret[0]), i);
            else {
                memcpy (&(p1[320]), &(s->s3->write_opad_hash[0]), i);
                memcpy (&(p1[344]), &(s->s3->write_ipad_hash[0]), i);
            }
            memcpy (&(p1[368]), &(s->s3->write_sequence[0]), 8);
            rc4_get_cipher_state (&(p1[376]), s->enc_write_ctx);
        }
#ifndef CAVIUM_FIPS
        res = Csp1WriteContext (CAVIUM_BLOCKING,
            s->context_pointer + context_offset, MAX_CRYPTO_CTX_SIZE, p1,
#ifdef CAVIUM_MULTICARD_API
            &s->cav_req_id, s->dev_id
#else
            &s->cav_req_id
#endif
            );

        if (res != 0)
            goto err;
#endif
        break;

    case SSL3_CK_RSA_DES_192_CBC3_SHA:
    case SSL3_CK_RSA_DES_40_CBC_SHA:
    case SSL3_CK_RSA_DES_64_CBC_SHA:
    case TLS1_CK_RSA_EXPORT1024_WITH_DES_CBC_SHA:

        if (!s->server) {
            if (is_ssl3_sha)
                memcpy (&(p1[24]), &(s->s3->write_mac_secret[0]), i);
            else {
                memcpy (p1, &(s->s3->write_opad_hash[0]), i);
                memcpy (&(p1[24]), &(s->s3->write_ipad_hash[0]), i);
            }
            memcpy (&(p1[48]), &(s->s3->write_sequence[0]), 8);
            memcpy (&(p1[56]), s->enc_write_ctx->iv,
                EVP_CIPHER_CTX_iv_length (s->enc_write_ctx));
            if (s->session->cipher->id == SSL3_CK_RSA_DES_192_CBC3_SHA)
                des3_get_key (&(p1[64]), s->enc_write_ctx);
            else
                des_get_key (&(p1[64]), s->enc_write_ctx);

            memcpy (&(p1[88]), s->enc_write_ctx->oiv,
                EVP_CIPHER_CTX_iv_length (s->enc_write_ctx));
            if (is_ssl3_sha)
                memcpy (&(p1[120]), &(s->s3->read_mac_secret[0]), i);
            else {
                memcpy (&(p1[96]), &(s->s3->read_opad_hash[0]), i);
                memcpy (&(p1[120]), &(s->s3->read_ipad_hash[0]), i);
            }
            memcpy (&(p1[144]), &(s->s3->read_sequence[0]), 8);
            memcpy (&(p1[152]), s->enc_read_ctx->iv,
                EVP_CIPHER_CTX_iv_length (s->enc_read_ctx));
            if (s->session->cipher->id == SSL3_CK_RSA_DES_192_CBC3_SHA)
                des3_get_key (&(p1[160]), s->enc_read_ctx);
            else
                des_get_key (&(p1[160]), s->enc_read_ctx);
            memcpy (&(p1[184]), s->enc_read_ctx->oiv,
                EVP_CIPHER_CTX_iv_length (s->enc_read_ctx));
        } else {
            if (is_ssl3_sha)
                memcpy (&(p1[24]), &(s->s3->read_mac_secret[0]), i);
            else {
                memcpy (p1, &(s->s3->read_opad_hash[0]), i);
                memcpy (&(p1[24]), &(s->s3->read_ipad_hash[0]), i);
            }
            memcpy (&(p1[48]), &(s->s3->read_sequence[0]), 8);
            memcpy (&(p1[56]), s->enc_read_ctx->iv,
                EVP_CIPHER_CTX_iv_length (s->enc_read_ctx));
            if (s->session->cipher->id == SSL3_CK_RSA_DES_192_CBC3_SHA)
                des3_get_key (&(p1[64]), s->enc_read_ctx);
            else
                des_get_key (&(p1[64]), s->enc_read_ctx);
            memcpy (&(p1[88]), s->enc_read_ctx->oiv,
                EVP_CIPHER_CTX_iv_length (s->enc_read_ctx));
            if (is_ssl3_sha)
                memcpy (&(p1[120]), &(s->s3->write_mac_secret[0]), i);
            else {
                memcpy (&(p1[96]), &(s->s3->write_opad_hash[0]), i);
                memcpy (&(p1[120]), &(s->s3->write_ipad_hash[0]), i);
            }
            memcpy (&(p1[144]), &(s->s3->write_sequence[0]), 8);
            memcpy (&(p1[152]), s->enc_write_ctx->iv,
                EVP_CIPHER_CTX_iv_length (s->enc_write_ctx));
            if (s->session->cipher->id == SSL3_CK_RSA_DES_192_CBC3_SHA)
                des3_get_key (&(p1[160]), s->enc_write_ctx);
            else
                des_get_key (&(p1[160]), s->enc_write_ctx);
            memcpy (&(p1[184]), s->enc_write_ctx->oiv,
                EVP_CIPHER_CTX_iv_length (s->enc_write_ctx));
        }
#ifndef CAVIUM_FIPS
        res = Csp1WriteContext (CAVIUM_BLOCKING,
            s->context_pointer + context_offset, 192,    // DES
            p1,
#ifdef CAVIUM_MULTICARD_API
            &s->cav_req_id, s->dev_id
#else
            &s->cav_req_id
#endif
            );

        if (res != 0)
            goto err;
#endif

        break;

    case TLS1_CK_RSA_WITH_AES_128_SHA:
    case TLS1_CK_RSA_WITH_AES_256_SHA:

        if (!s->server) {
            if (is_ssl3_sha)
                memcpy (&(p1[24]), &(s->s3->write_mac_secret[0]), i);
            else {
                memcpy (p1, &(s->s3->write_opad_hash[0]), i);
                memcpy (&(p1[24]), &(s->s3->write_ipad_hash[0]), i);
            }
            memcpy (&(p1[48]), &(s->s3->write_sequence[0]), 8);
            memcpy (&(p1[56]), s->enc_write_ctx->iv,
                EVP_CIPHER_CTX_iv_length (s->enc_write_ctx));
            aes_get_key (&(p1[72]), s->enc_write_ctx);
            memcpy (&(p1[104]), s->enc_write_ctx->oiv,
                EVP_CIPHER_CTX_iv_length (s->enc_write_ctx));

            if (is_ssl3_sha)
                memcpy (&(p1[152]), &(s->s3->read_mac_secret[0]), i);
            else {
                memcpy (&(p1[128]), &(s->s3->read_opad_hash[0]), i);
                memcpy (&(p1[152]), &(s->s3->read_ipad_hash[0]), i);
            }
            memcpy (&(p1[176]), &(s->s3->read_sequence[0]), 8);
            memcpy (&(p1[184]), s->enc_read_ctx->iv,
                EVP_CIPHER_CTX_iv_length (s->enc_read_ctx));
            aes_get_key (&(p1[200]), s->enc_read_ctx);
            memcpy (&(p1[232]), s->enc_read_ctx->oiv,
                EVP_CIPHER_CTX_iv_length (s->enc_read_ctx));
        } else {
            if (is_ssl3_sha)
                memcpy (&(p1[24]), &(s->s3->read_mac_secret[0]), i);
            else {
                memcpy (p1, &(s->s3->read_opad_hash[0]), i);
                memcpy (&(p1[24]), &(s->s3->read_ipad_hash[0]), i);
            }
            memcpy (&(p1[48]), &(s->s3->read_sequence[0]), 8);
            memcpy (&(p1[56]), s->enc_read_ctx->iv,
                EVP_CIPHER_CTX_iv_length (s->enc_read_ctx));
            aes_get_key (&(p1[72]), s->enc_read_ctx);
            memcpy (&(p1[104]), s->enc_read_ctx->oiv,
                EVP_CIPHER_CTX_iv_length (s->enc_read_ctx));

            if (is_ssl3_sha)
                memcpy (&(p1[152]), &(s->s3->write_mac_secret[0]), i);
            else {
                memcpy (&(p1[128]), &(s->s3->write_opad_hash[0]), i);
                memcpy (&(p1[152]), &(s->s3->write_ipad_hash[0]), i);
            }
            memcpy (&(p1[176]), &(s->s3->write_sequence[0]), 8);
            memcpy (&(p1[184]), s->enc_write_ctx->iv,
                EVP_CIPHER_CTX_iv_length (s->enc_write_ctx));
            aes_get_key (&(p1[200]), s->enc_write_ctx);
            memcpy (&(p1[232]), s->enc_write_ctx->oiv,
                EVP_CIPHER_CTX_iv_length (s->enc_write_ctx));
        }

#ifndef CAVIUM_FIPS
        res = Csp1WriteContext (CAVIUM_BLOCKING,
            s->context_pointer + context_offset, 256,    // AES
            p1,
#ifdef CAVIUM_MULTICARD_API
            &s->cav_req_id, s->dev_id
#else
            &s->cav_req_id
#endif
            );

        if (res != 0)
            goto err;
#endif

        break;

    }
    OPENSSL_free (p1);
    return (1);
  err:
    return (0);

}

/*
 * For Record Process Offloading
 * Reads context from Nitrox and updates spftware context structures
 * Called when Renegotiation requested from either client or server
 *
 */

int
pkp_read_updated_ssl_session_context (SSL * s)
{

    unsigned char *p1;
#ifndef CAVIUM_FIPS
    int res;
#endif
    Uint64 context_offset;


    if ((p1 =
            (unsigned char *) OPENSSL_malloc (MAX_CRYPTO_CTX_SIZE)) ==
        NULL)
        goto err;

    context_offset = CRYPTO_OFFSET_IN_CTX;
#ifndef CAVIUM_FIPS
    res = Csp1ReadContext (CAVIUM_BLOCKING,
        s->context_pointer + context_offset, MAX_CRYPTO_CTX_SIZE, p1,
#ifdef CAVIUM_MULTICARD_API
        &s->cav_req_id, s->dev_id
#else
        &s->cav_req_id
#endif
        );
    if (res != 0)
        goto err;
#endif

    switch (s->session->cipher->id) {
    case SSL3_CK_RSA_RC4_128_SHA:
    case SSL3_CK_RSA_RC4_128_MD5:
    case TLS1_CK_RSA_EXPORT1024_WITH_RC4_56_SHA:
    case TLS1_CK_RSA_EXPORT1024_WITH_RC4_56_MD5:
    case SSL3_CK_RSA_RC4_40_MD5:
        if (!s->server) {
            memcpy (&(s->s3->write_sequence[0]), &(p1[48]), 8);
            rc4_set_state (s->enc_write_ctx, &(p1[56]));

            memcpy (&(s->s3->read_sequence[0]), &(p1[368]), 8);
            rc4_set_state (s->enc_read_ctx, &(p1[376]));
        } else {
            memcpy (&(s->s3->read_sequence[0]), &(p1[48]), 8);
            rc4_set_state (s->enc_read_ctx, &(p1[56]));

            memcpy (&(s->s3->write_sequence[0]), &(p1[368]), 8);
            rc4_set_state (s->enc_write_ctx, &(p1[376]));
        }
        break;

    case SSL3_CK_RSA_DES_192_CBC3_SHA:
    case SSL3_CK_RSA_DES_40_CBC_SHA:
    case SSL3_CK_RSA_DES_64_CBC_SHA:
    case TLS1_CK_RSA_EXPORT1024_WITH_DES_CBC_SHA:
        if (!s->server) {
            memcpy (&(s->s3->write_sequence[0]), &(p1[48]), 8);
            memcpy (s->enc_write_ctx->iv, &(p1[56]),
                EVP_CIPHER_CTX_iv_length (s->enc_write_ctx));

            memcpy (&(s->s3->read_sequence[0]), &(p1[144]), 8);
            memcpy (s->enc_read_ctx->iv, &(p1[152]),
                EVP_CIPHER_CTX_iv_length (s->enc_read_ctx));
        } else {
            memcpy (&(s->s3->read_sequence[0]), &(p1[48]), 8);
            memcpy (s->enc_read_ctx->iv, &(p1[56]),
                EVP_CIPHER_CTX_iv_length (s->enc_read_ctx));

            memcpy (&(s->s3->write_sequence[0]), &(p1[144]), 8);
            memcpy (s->enc_write_ctx->iv, &(p1[152]),
                EVP_CIPHER_CTX_iv_length (s->enc_write_ctx));
        }
        break;

    case TLS1_CK_RSA_WITH_AES_128_SHA:
    case TLS1_CK_RSA_WITH_AES_256_SHA:

        if (!s->server) {
            memcpy (&(s->s3->write_sequence[0]), &(p1[48]), 8);
            memcpy (s->enc_write_ctx->iv, &(p1[56]),
                EVP_CIPHER_CTX_iv_length (s->enc_write_ctx));

            memcpy (&(s->s3->read_sequence[0]), &(p1[176]), 8);
            memcpy (s->enc_read_ctx->iv, &(p1[184]),
                EVP_CIPHER_CTX_iv_length (s->enc_read_ctx));
        } else {
            memcpy (&(s->s3->read_sequence[0]), &(p1[48]), 8);
            memcpy (s->enc_read_ctx->iv, &(p1[56]),
                EVP_CIPHER_CTX_iv_length (s->enc_read_ctx));

            memcpy (&(s->s3->write_sequence[0]), &(p1[176]), 8);
            memcpy (s->enc_write_ctx->iv, &(p1[184]),
                EVP_CIPHER_CTX_iv_length (s->enc_write_ctx));
        }
        break;

    }

    OPENSSL_free (p1);
    return (1);

err:
    return (0);

}


/*This function assigns SSL session to a device.Application can use this API
 * to override the default round robin mode of assignement.
 */
#ifdef CAVIUM_MULTICARD_API
int
SSL_set_crypto_dev (SSL * ssl, int dev_id)
{
    /*   Csp1FreeContext(CONTEXT_SSL,ssl->context_pointer,ssl->dev_id);

       ssl->dev_id=dev_id;
       ssl->key_handle=gpkpdev_keyhandle[dev_id];

       if(Csp1AllocContext(CONTEXT_SSL, &ssl->context_pointer,ssl->dev_id))
       {
       printf("SSL_set_crypto_dev: failed to allocate context \n");
       return -1;
       } */
    return 0;
}
#endif
