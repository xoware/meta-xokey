/*
 * Copyright (c) 2003-2005, Cavium Networks. All rights reserved.
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
#include "pots.h"

#include "cavium_sysdep.h"
#include "cavium_common.h"

#include "openssl/evp.h"
#include "openssl/hmac.h"
#include "openssl/rc4.h"


int ciphers_loaded = 0;


int pots_openssl_hmac(   
               int calc_method, 
               int atype, 
               char *key, 
               int keylen,
               char *msgptr, 
               int msglen,
               char *digest_ptr, 
               int *digest_lenp)
{

   HMAC_CTX hmac_ctx;
   EVP_MD *evp_mdp = NULL;
   char *mdp;


   if ( atype == SHA1_TYPE )
      evp_mdp = (EVP_MD *)EVP_sha1();
   else // MD5_TYPE
      evp_mdp = (EVP_MD *)EVP_md5();

   if ( evp_mdp == NULL ) {
      pots_log(PT_LOG_ERROR, 
            "pots_openssl_hmac(): EVP_md5() failed\n");
      return(-1);
   }


   if ( calc_method == CM_ONE_CALL ) {

      mdp = (char *)HMAC(evp_mdp, key, keylen, (unsigned char *)msgptr, msglen,
               (unsigned char *)digest_ptr, (unsigned int *)digest_lenp);
      if ( mdp == NULL ) {
         pots_log(PT_LOG_ERROR, 
               "pots_openssl_hmac(): HMAC() failed\n");
         return(-1);
      }

   }
   else if ( calc_method == CM_MULTIPLE_CALLS ) {
      HMAC_Init(&hmac_ctx, key, keylen, evp_mdp);
      HMAC_Update(&hmac_ctx, (unsigned char *)msgptr, msglen);
      HMAC_Final(&hmac_ctx, (unsigned char *)digest_ptr, (unsigned int *)digest_lenp);
      HMAC_cleanup(&hmac_ctx);
   }
   else {
      pots_log(PT_LOG_ERROR, 
            "pots_openssl_hmac(): invalid calc_method %d\n",
            calc_method);
      return(-1);
   }

   return(0);

} // end pots_openssl_hmac()


int pots_openssl_rc4(int keylen, char *key, int msglen, char *msgptr, char *buf)
{

   RC4_KEY rc4_key;

   RC4_set_key(&rc4_key, keylen, (unsigned char *)key);

   RC4(&rc4_key, msglen, (unsigned char *)msgptr, (unsigned char *)buf);
   
   return(0);

} // end pots_openssl_rc4()


/*
 * pots_openssl_3des:
 *      - for symmetric encryption/decryption
 *
 *
 */
int pots_openssl_evp(int encrypt, 
                 char *cipher_name, 
                 int msglen,
                 Uint8 *msgp, 
                 Uint8 *ivp, 
                 Uint8 *keyp,
                 Uint8 *obuf,
                 int *out_lenp)
{
   char *fname = "pots_openssl_evp()";
   int i;
   int rc;


   // load all ciphers/algorithms in openssl lib's memory tables
   if ( ! ciphers_loaded ) {
      ciphers_loaded = 1;
      OpenSSL_add_all_algorithms();
   }

   if (  encrypt == 1 ) {

      // encrypt
      rc = my_evp_cipher_encrypt(   cipher_name, 
                           msglen, 
                           msgp, 
                           ivp, 
                           keyp, 
                           obuf, 
                           out_lenp);
      if (rc == -1 ) {
         pots_log(PT_LOG_ERROR, "%s() failed\n", fname);
         return(-1);
      }

      pots_log(PT_LOG_DEBUG, "%s: ossl encrypted: len = %d\n", 
            fname, *out_lenp);
      for (i = 0; i < *out_lenp; i++) {
         pots_log0(PT_LOG_DEBUG, "0x%0x ", obuf[i]);
      }
      pots_log0(PT_LOG_DEBUG, "\n");

   } // end if encrypt 
   else {

      // decrypt
      rc = my_evp_cipher_decrypt(   cipher_name, 
                           msglen, 
                           msgp, 
                           ivp, 
                           keyp, 
                           obuf, 
                           out_lenp);
      if (rc == -1 ) {
         pots_log(PT_LOG_ERROR, "%s() failed\n", fname);
         return(-1);
      }

      pots_log(PT_LOG_DEBUG, "%s: ossl decrypted: len = %d\n",
            fname, *out_lenp);
      for (i = 0; i < *out_lenp; i++) {
         pots_log0(PT_LOG_DEBUG, "0x%0x ", obuf[i]);
      }
      pots_log0(PT_LOG_DEBUG, "\n");
   
   } // end else 

   return(0);

} // end pots_openssl_evp()


int my_evp_cipher_encrypt(char *cipher_name, 
           int msglen, char *msgp, 
                char *ivp, char *keyp, 
           char *obuf, int *out_lenp)
{
   char *fname = "my_evp_cipher_encrypt()";
   int rc;
   int temp_len;
   EVP_CIPHER_CTX cctx;
   const EVP_CIPHER *cipherp;

   if ((cipherp = EVP_get_cipherbyname(cipher_name)) == NULL ) {
      pots_log(PT_LOG_ERROR, "%s: EVP_get_cipherbyname(%s) failed\n", 
            fname, cipher_name);
      return(-1);
   }

   *out_lenp = 0;

   /* initialize the cipher context */
   EVP_CIPHER_CTX_init(&cctx);
   
   rc = EVP_EncryptInit(&cctx, cipherp, (unsigned char *)keyp, (unsigned char *)ivp);
   if ( rc != 1 ) {
      EVP_CIPHER_CTX_cleanup(&cctx);
      pots_log(PT_LOG_ERROR, 
            "%s: EVP_EncryptInit() failed, rc = %d\n", fname, rc);
      return(-1);
   }

   temp_len = 0;
   EVP_EncryptUpdate(&cctx, (unsigned char *)&obuf[0], &temp_len, (unsigned char *)msgp, msglen);
   if ( rc != 1 ) {
      EVP_CIPHER_CTX_cleanup(&cctx);
      pots_log(PT_LOG_ERROR, 
            "%s: EVP_EncryptUpdate() failed, rc = %d\n", fname, rc);
      return(-1);
   }

   *out_lenp = temp_len;
   temp_len = 0;
   EVP_EncryptFinal(&cctx, (unsigned char *)&obuf[*out_lenp], &temp_len);
   if ( rc != 1 ) {
      EVP_CIPHER_CTX_cleanup(&cctx);
      pots_log(PT_LOG_ERROR, 
            "%s: EVP_EncryptFinal() failed, rc = %d\n", fname, rc);
      return(-1);
   }

   *out_lenp += temp_len;

   EVP_CIPHER_CTX_cleanup(&cctx);

   return(0);

}  // my_evp_cipher_encrypt()

int my_evp_cipher_decrypt(char *cipher_name, 
                    int msglen, char *msgp, 
                        char *ivp, char *keyp, 
                    char *obuf, int *out_lenp)
{
   char *fname = "my_evp_cipher_decrypt()";
   int rc;
   int temp_len;
   EVP_CIPHER_CTX cctx;
   const EVP_CIPHER *cipherp;


   if ((cipherp = EVP_get_cipherbyname(cipher_name)) == NULL ) {
      pots_log(PT_LOG_ERROR, 
            "%s: EVP_get_cipherbyname(%s) failed\n", 
            fname, cipher_name);
      return(-1);
   }

   *out_lenp = 0;

   /* initialize the cipher context */
   EVP_CIPHER_CTX_init(&cctx);
   
   rc = EVP_DecryptInit(&cctx, cipherp, (unsigned char *)keyp, (unsigned char *)ivp);
   if ( rc != 1 ) {
      EVP_CIPHER_CTX_cleanup(&cctx);
      pots_log(PT_LOG_ERROR, 
            "%s: EVP_DecryptInit() failed, rc = %d\n", fname, rc);
      return(-1);
   }

   temp_len = 0;
   EVP_DecryptUpdate(&cctx, (unsigned char *)&obuf[0], &temp_len, (unsigned char *)msgp, msglen);
   if ( rc != 1 ) {
      EVP_CIPHER_CTX_cleanup(&cctx);
      pots_log(PT_LOG_ERROR, 
            "%s: EVP_DecryptUpdate() failed, rc = %d\n", fname, rc);
      return(-1);
   }

   *out_lenp = temp_len;
   temp_len = 0;
   EVP_DecryptFinal(&cctx, (unsigned char *)&obuf[*out_lenp], &temp_len);
   if ( rc != 1 ) {
      EVP_CIPHER_CTX_cleanup(&cctx);
      pots_log(PT_LOG_ERROR, 
            "%s: EVP_DecryptFinal() failed, rc = %d\n", fname, rc);
      return(-1);
   }

   *out_lenp += temp_len;

   EVP_CIPHER_CTX_cleanup(&cctx);

   return(0);

} // end my_evp_cipher_decrypt()


/*
 * $Id: pots_openssl.c,v 1.3 2008/10/24 08:43:51 ysandeep Exp $
 * $Log: pots_openssl.c,v $
 * Revision 1.3  2008/10/24 08:43:51  ysandeep
 * NPLUS support added
 *
 * Revision 1.2  2008/03/10 10:22:58  kkiran
 *  - Cavium Copyright added.
 *
 * Revision 1.1  2007/02/20 23:43:29  panicker
 * * Utilities checked in
 *
 * Revision 1.3  2005/08/31 17:21:40  bimran
 * Fixed a lot of warnings.
 *
 * Revision 1.2  2004/04/16 00:05:41  bimran
 * Fixed compilation issues/warnings.
 *
 * Revision 1.1  2004/04/15 22:40:51  bimran
 * Checkin of the code from India with some cleanups.
 *
 */

