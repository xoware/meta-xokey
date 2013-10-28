/*
 * pots_aes.c:
 */
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



#include <string.h>
#include "cavium_sysdep.h"
#include "cavium_common.h"

#include "pots.h"
#include "pots_proto.h"


int get_aes_intval(Uint8 *str, int *intvalp);
Uint8 *get_aes_input_data(Uint8* str, Uint8 *msgbufp, int *msglenp);
Uint8 *get_aes_key(Uint8 *str, Uint8 *keybufp);
Uint8 *get_aes_iv(Uint8 *str, Uint8 *ivbufp);
Uint8 *get_aes_expected_output(Uint8 *str, Uint8 *exbufp, int *outlenp);

extern Uint8 msgbuf[];
extern Uint8 encbuf[];
extern Uint8 decbuf[];
extern Uint8 osslbuf[];
extern Uint8 keybuf[];

/* #ifdef OPENSSL_VERSION_0.9.7 */
#ifdef AES_OSSL
/*
 * pots_aes:
 *       Note: AES has the following types:
 *          - AES_128 ... for key/block size of 128 bits (16 bytes)
 *          - AES_192 ... for key/block size of 928 bits (24 bytes)
 *          - AES_256 ... for key/block size of 256 bits (32 bytes)
 *          - iv is always 128 bits (16 bytes)
 *
 *
 */
int pots_aes(pots_sts *pots_stp)
{

   int p;
   int rc;
   int done;
   Uint32 rid;
   FILE *aes_fp;
   AesType aes_type;
   Uint64 shim_ctxt;
   Uint8 ivbuf[18];      
   Uint8 keybuf[MAX_CRYPTO_KEYBUF_SZ];

   int test_nr;
   int msglen;
   int keylen;
   int ivlen;
   int outlen;
   char ossl_cipher_name[36];
   int max_msg_sz_to_test;
   FILE *rfp;
   struct pots_crypto_test_cnf *cptr;
   int err =-1;
   // open dd
#ifdef CAVIUM_MULTICARD_API
   rc = Csp1Initialize(CAVIUM_DIRECT,pots_stp->dev_id);
   rc = Csp1AllocContext(CONTEXT_SSL, &shim_ctxt,pots_stp->dev_id);
#else 
   rc = Csp1Initialize(CAVIUM_DIRECT);
   rc = Csp1AllocContext(CONTEXT_SSL, &shim_ctxt);
#endif 
   
   if ( rc ) {
      pots_log(PT_LOG_ERROR, 
            "pots_aes(): Csp1AllocContext() failed\n");
      goto fail; 
   }

   /* 
    * open the aes data file that contains test input data
    * and expected encrypted data (from nist site).
    */
   if ((aes_fp = fopen(PT_AES_DATA_FNAME, "r")) == NULL ) {
      pots_log(PT_LOG_ERROR,
            "pots_open_file(): fopen(%s) failed %s <%d>\n",
            PT_AES_DATA_FNAME, strerror(errno), errno);
#ifdef CAVIUM_MULTICARD_API
      Csp1FreeContext(CONTEXT_SSL, shim_ctxt,pots_stp->dev_id);
#else
      Csp1FreeContext(CONTEXT_SSL, shim_ctxt);
#endif
      goto fail; 
   }

   /* 
    * open the aes test results file 
    */
   if ((rfp = fopen(PT_AES_RESULTS_FNAME, "w+")) == NULL ) {
      pots_log(PT_LOG_ERROR,
            "pots_rc4(): fopen(%s) failed %s <%d>\n",
            PT_AES_RESULTS_FNAME,strerror(errno), errno);
#ifdef CAVIUM_MULTICARD_API
      Csp1FreeContext(CONTEXT_SSL, shim_ctxt,pots_stp->dev_id);
#else
      Csp1FreeContext(CONTEXT_SSL, shim_ctxt);
#endif
      fclose(aes_fp);
      goto fail;
   }
   setbuf(rfp, NULL);

   cptr = &pots_stp->pt_test_cnf[PT_TESTID_AES];

   if ( cptr->cc_end_msg_sz > MAX_CRYPTO_MSG_SZ )
      max_msg_sz_to_test = MAX_CRYPTO_MSG_SZ;
   else
      max_msg_sz_to_test = cptr->cc_end_msg_sz;


   // AES uses 16 bytes iv
   ivlen = 16;
   getrandom(ivbuf, ivlen);

   fprintf(rfp, "starting AES test:\n");

   /* test for diff key sizes */
   for (keylen = 128; keylen <= 256; keylen = keylen + 64) {

      if ( keylen == 128 )
         aes_type = AES_128;
      else if ( keylen == 192 )
         aes_type = AES_192;
      else 
         aes_type = AES_256;

      pots_log(PT_LOG_DEBUG, "pots_aes(): aes_type = %d\n", aes_type);

      getrandom(keybuf, keylen);

      fprintf(rfp, "\nKEYSIZE = %d bits\n", keylen);
      print_hex2(rfp, "KEY = ", keybuf, keylen/8);
      print_hex2(rfp, "IV = ", ivbuf, 16);

      pots_log(PT_LOG_INFO, "pots_aes(): keylen = %d bits\n", keylen);
      print_hex("key = ", keybuf, keylen/8);
      print_hex("iv = ", ivbuf, 16);

      pots_log(PT_LOG_ERROR, "pots_aes: Testing for messages sizes \
            %d to %d\n", cptr->cc_start_msg_sz, max_msg_sz_to_test);
      /* test for diff msg size for this key size */
      for (msglen = cptr->cc_start_msg_sz; 
          msglen <= max_msg_sz_to_test; 
          msglen = msglen + cptr->cc_msg_incr) 
      {

         fprintf(rfp, "\n\tMSGSIZE = %d\n", msglen);
         pots_log(PT_LOG_INFO, "pots_aes(): msglen = %d\n", msglen);
         
         // generate random key and data for the test
         getrandom(msgbuf, msglen);

         print_hex2(rfp, "\tINPUT_MSG = ", msgbuf, msglen);
   
         print_hex("msgbuf", msgbuf, msglen);
#ifndef MC2
#ifdef CAVIUM_MULTICARD_API
         rc = Csp1InitializeAES(CAVIUM_BLOCKING, shim_ctxt, aes_type, ivbuf, keybuf, &rid,pots_stp->dev_id);
#else
         rc = Csp1InitializeAES(CAVIUM_BLOCKING, shim_ctxt, aes_type, ivbuf, keybuf, &rid);
#endif
         if ( rc ) {
#ifdef CAVIUM_MULTICARD_API
            Csp1FreeContext(CONTEXT_SSL, shim_ctxt,pots_stp->dev_id);
#else
            Csp1FreeContext(CONTEXT_SSL, shim_ctxt);
#endif
            fclose(aes_fp);
            fclose(rfp);
            if (rc == ERR_OPERATION_NOT_SUPPORTED) {
               pots_log(PT_LOG_INFO, 
                   "pots_aes(): Csp1InitializeAES() Operation not supported\n");
#ifdef CAVIUM_MULTICARD_API
               Csp1Shutdown(pots_stp->dev_id);
#else
               Csp1Shutdown();
#endif
               return rc;
            }

            pots_log(PT_LOG_ERROR, 
                  "pots_aes(): Csp1InitializeAES() failed\n");
            goto fail; 
         }

         memset(encbuf, '\0', 1024);
      
#ifdef CAVIUM_MULTICARD_API
         rc = Csp1EncryptAes(CAVIUM_BLOCKING, shim_ctxt, CAVIUM_NO_UPDATE, aes_type, msglen, msgbuf, encbuf, &rid,pots_stp->dev_id);
#else
         rc = Csp1EncryptAes(CAVIUM_BLOCKING, shim_ctxt, CAVIUM_NO_UPDATE, aes_type, msglen, msgbuf, encbuf, &rid);
#endif
#else
#ifdef CAVIUM_MULTICARD_API
         rc = Csp1EncryptAes(CAVIUM_BLOCKING, shim_ctxt, CAVIUM_NO_UPDATE, aes_type, msglen, msgbuf, encbuf, ivbuf, keybuf, &rid,pots_stp->dev_id);
#else
         rc = Csp1EncryptAes(CAVIUM_BLOCKING, shim_ctxt, CAVIUM_NO_UPDATE, aes_type, msglen, msgbuf, encbuf, ivbuf, keybuf, &rid);
#endif
#endif
         //rc = Csp1EncryptAES(shim_ctxt, CAVIUM_NO_UPDATE, 
         //                  aes_type, ROUNDUP8(msglen), 
         //                  msgp, encbuf);
         if ( rc ) {
#ifdef CAVIUM_MULTICARD_API
            Csp1FreeContext(CONTEXT_SSL, shim_ctxt,pots_stp->dev_id);
#else
            Csp1FreeContext(CONTEXT_SSL, shim_ctxt);
#endif
            fclose(aes_fp);
            fclose(rfp);
            if (rc == ERR_OPERATION_NOT_SUPPORTED) {
               pots_log(PT_LOG_INFO, 
			       "pots_aes(): Csp1EncryptAES() Operation not supported\n");
#ifdef CAVIUM_MULTICARD_API
               Csp1Shutdown(pots_stp->dev_id);
#else
               Csp1Shutdown();
#endif
               return rc;
            }

            pots_log(PT_LOG_ERROR, "pots_aes(): Csp1EncryptAES() failed\n");
            goto fail;
         }

         pots_log(PT_LOG_DEBUG, 
               "pots_aes(): msglen = %d; pkp encrypted = \n", msglen);
         print_hex("pkp encrypted", encbuf, msglen);
         print_hex2(rfp, "\tOUTPUT = ", encbuf, msglen);

         // Now descrypt */
         memset(decbuf, '\0', 1024);

         // note; msglen -- may be incorrect for the encbuf !!!
#ifdef MC2
#ifdef CAVIUM_MULTICARD_API
         rc = Csp1DecryptAes(CAVIUM_BLOCKING, shim_ctxt, CAVIUM_NO_UPDATE, aes_type, msglen, encbuf, decbuf, ivbuf, keybuf, &rid,pots_stp->dev_id);
#else
         rc = Csp1DecryptAes(CAVIUM_BLOCKING, shim_ctxt, CAVIUM_NO_UPDATE, aes_type, msglen, encbuf, decbuf, ivbuf, keybuf, &rid);
#endif
#else
#ifdef CAVIUM_MULTICARD_API
         rc = Csp1DecryptAes(CAVIUM_BLOCKING, shim_ctxt, CAVIUM_NO_UPDATE, aes_type, msglen, encbuf, decbuf, &rid,pots_stp->dev_id);
#else
         rc = Csp1DecryptAes(CAVIUM_BLOCKING, shim_ctxt, CAVIUM_NO_UPDATE, aes_type, msglen, encbuf, decbuf, &rid);
#endif
#endif
         if ( rc ) {
#ifdef CAVIUM_MULTICARD_API
            Csp1FreeContext(CONTEXT_SSL, shim_ctxt,pots_stp->dev_id);
#else
            Csp1FreeContext(CONTEXT_SSL, shim_ctxt);
#endif
            fclose(aes_fp);
            fclose(rfp);
            pots_log(PT_LOG_ERROR, "pots_aes(): Csp1DecryptAES() failed\n");
            goto fail; 
         }

         print_hex("pkp decrypted", encbuf, msglen);

#if 1
         /* now encrypt using openssl */
         switch (aes_type) {
         case AES_128:
            strcpy(ossl_cipher_name, "aes-128-cbc");   // FOR NOW!!!
            break;
         case AES_192:
            strcpy(ossl_cipher_name, "aes-192-cbc");   // FOR NOW!!!
            break;
         case AES_256:
            strcpy(ossl_cipher_name, "aes-256-cbc");   // FOR NOW!!!
            break;
         default:
            // error 
            pots_log(PT_LOG_ERROR, 
                  "pots_aes(): invalid aes_type %d\n", aes_type);
#ifdef CAVIUM_MULTICARD_API
            Csp1FreeContext(CONTEXT_SSL, shim_ctxt,pots_stp->dev_id);
#else
            Csp1FreeContext(CONTEXT_SSL, shim_ctxt);
#endif
            fclose(aes_fp);
            fclose(rfp);
            goto fail;            
         }


         rc = pots_openssl_evp(   1, 
                           ossl_cipher_name,
                           msglen,
                           msgbuf, 
                           ivbuf, 
                           keybuf, 
                           osslbuf, 
                           &outlen);
         if ( rc == -1 ) {
            printf("pots_aes(): pots_openssl_evp() failed\n");
#ifdef CAVIUM_MULTICARD_API
            Csp1FreeContext(CONTEXT_SSL, shim_ctxt,pots_stp->dev_id);
#else
            Csp1FreeContext(CONTEXT_SSL, shim_ctxt);
#endif
            fclose(aes_fp);
            fclose(rfp);
            goto fail; 
         }
#endif

         print_hex("openssl encrypted", osslbuf, outlen);

         if ( memcmp(encbuf, osslbuf, msglen) != 0 ) {
            pots_log(PT_LOG_ERROR, 
                  "pots_aes(): %s %s\n",
               "aes output from pkp and expected output ",
               "does not match. Test failed");
            print_hex("pkp encrypted data:\n", encbuf, msglen);
            print_hex("openssl encrypted data:\n", osslbuf, msglen);
#ifdef CAVIUM_MULTICARD_API
            Csp1FreeContext(CONTEXT_SSL, shim_ctxt,pots_stp->dev_id);
#else
            Csp1FreeContext(CONTEXT_SSL, shim_ctxt);
#endif
            fclose(aes_fp);
            fclose(rfp);
            goto fail;
         }
         else {
            pots_log(PT_LOG_INFO, 
                  "pots_aes(): passed test %d\n", test_nr);
         }

      } // end for msg size

   } // end for key size

   pots_log(PT_LOG_INFO, "pots_aes(): aes test PASSED\n");
   fclose(rfp);
   fclose(aes_fp);
   err = 0;
#ifdef CAVIUM_MULTICARD_API
   Csp1FreeContext(CONTEXT_SSL, shim_ctxt,pots_stp->dev_id);
#else
   Csp1FreeContext(CONTEXT_SSL, shim_ctxt);
#endif
fail:
#ifdef CAVIUM_MULTICARD_API
   Csp1Shutdown(pots_stp->dev_id);
#else
   Csp1Shutdown();
#endif
   return err;

} // end pots_aes()
#else
int pots_aes(pots_sts *pots_stp)
{
   int p;
   int rc;
   int done;
   FILE *aes_fp;
   AesType aes_type;
   Uint64 shim_ctxt;
   Uint8 ivbuf[18];      

   Uint32 rid;
   int test_nr;
   int msglen;
   int keylen;
   int ivlen;
   int outlen;


   // open dd 
#ifdef CAVIUM_MULTICARD_API
   rc = Csp1Initialize(CAVIUM_DIRECT,pots_stp->dev_id);
   rc = Csp1AllocContext(CONTEXT_SSL, &shim_ctxt,pots_stp->dev_id);
#else 
   rc = Csp1Initialize(CAVIUM_DIRECT);
   rc = Csp1AllocContext(CONTEXT_SSL, &shim_ctxt);
#endif 

   if ( rc ) {
      pots_log(PT_LOG_ERROR, 
            "pots_aes(): Csp1AllocContext() failed\n");
      return(-1);
   }

   /* 
    * open the aes data file that contains test input data
    * and expected encrypted data (from nist site).
    */
   if ((aes_fp = fopen(PT_AES_DATA_FNAME, "r")) == NULL ) {
      pots_log(PT_LOG_ERROR,
            "pots_open_file(): fopen(%s) failed %s <%d>\n",
            PT_AES_DATA_FNAME, strerror(errno), errno);
#ifdef CAVIUM_MULTICARD_API
      Csp1FreeContext(CONTEXT_SSL, shim_ctxt,pots_stp->dev_id);
#else
      Csp1FreeContext(CONTEXT_SSL, shim_ctxt);
#endif
      return(-1);
   }
   
   done = 0;
   test_nr = 0;
   while ( ! done ) {

      rc = get_test_data(   aes_fp, 
                     &aes_type,
                     &keylen, 
                     keybuf, 
                     &msglen, 
                     msgbuf, 
                     ivbuf, 
                     &outlen,
                     osslbuf);
      if ( rc == -1 ) {
         fclose(aes_fp);
#ifdef CAVIUM_MULTICARD_API
         Csp1FreeContext(CONTEXT_SSL, shim_ctxt,pots_stp->dev_id);
#else
         Csp1FreeContext(CONTEXT_SSL, shim_ctxt);
#endif
         pots_log(PT_LOG_ERROR, 
               "pots_aes(): get_test_data() failed\n");
         return(-1);
      }
      else if ( rc == -2 ) {
         // no more data 
         done = 1;
         continue;
      }

      test_nr++;

      print_hex("iv", ivbuf, 16);
      //print_hex("key", keybuf, 16);
      //print_hex("msgbuf", msgbuf, 16);
      print_hex("key", keybuf, keylen);
      print_hex("msgbuf", msgbuf, msglen);
      print_hex("expected encrypted outout", osslbuf, 16);

      //aes_type = AES_128;   // FOR NOW!!!
#ifndef MC2
#ifdef CAVIUM_MULTICARD_API
      rc = Csp1InitializeAES(CAVIUM_BLOCKING, shim_ctxt, aes_type, ivbuf, keybuf, &rid,pots_stp->dev_id);
#else
      rc = Csp1InitializeAES(CAVIUM_BLOCKING, shim_ctxt, aes_type, ivbuf, keybuf, &rid);
#endif
      if ( rc ) {
         fclose(aes_fp);
#ifdef CAVIUM_MULTICARD_API
         Csp1FreeContext(CONTEXT_SSL, shim_ctxt,0);
#else
         Csp1FreeContext(CONTEXT_SSL, shim_ctxt);
#endif
         pots_log(PT_LOG_ERROR, 
               "pots_aes(): Csp1InitializeAES() failed\n");
         return(-1);
      }

      // input msg is
      pots_log(PT_LOG_DEBUG, 
            "pots_aes(): msglen = %d; input msg = ", msglen);

      for (p = 0; p < msglen + 2; p++) {
         pots_log0(PT_LOG_DEBUG, "0x%0x ", msgbuf[p]);
      }
      pots_log0(PT_LOG_DEBUG, "\n");

      memset(encbuf, '\0', 1024);
      
#ifdef CAVIUM_MULTICARD_API
      rc = Csp1EncryptAes(CAVIUM_BLOCKING, shim_ctxt, CAVIUM_NO_UPDATE, aes_type, msglen, msgbuf, encbuf, &rid,pots_stp->dev_id);
#else
      rc = Csp1EncryptAes(CAVIUM_BLOCKING, shim_ctxt, CAVIUM_NO_UPDATE, aes_type, msglen, msgbuf, encbuf, &rid);
#endif
#else 
#ifdef CAVIUM_MULTICARD_API
      rc = Csp1EncryptAes(CAVIUM_BLOCKING,shim_ctxt, CAVIUM_NO_UPDATE, aes_type, msglen, msgbuf, encbuf, ivbuf, keybuf, &rid,pots_stp->dev_id);
#else
      rc = Csp1EncryptAes(CAVIUM_BLOCKING,shim_ctxt, CAVIUM_NO_UPDATE, aes_type, msglen, msgbuf, encbuf, ivbuf, keybuf, &rid);
#endif
#endif
      //rc = Csp1EncryptAES(shim_ctxt, CAVIUM_NO_UPDATE, aes_type, ROUNDUP8(msglen), msgp, encbuf);
      if ( rc ) {
         fclose(aes_fp);
#ifdef CAVIUM_MULTICARD_API
         Csp1FreeContext(CONTEXT_SSL, shim_ctxt,pots_stp->dev_id);
#else
         Csp1FreeContext(CONTEXT_SSL, shim_ctxt);
#endif
         pots_log(PT_LOG_ERROR, "pots_aes(): Csp1EncryptAES() failed\n");
         return(-1);
      }

      pots_log(PT_LOG_DEBUG, 
            "pots_aes(): msglen = %d; pkp encrypted = \n", msglen);

      for (p = 0; p < msglen + 2; p++) {
         pots_log0(PT_LOG_DEBUG, "0x%0x ", encbuf[p]);
      }
      pots_log0(PT_LOG_DEBUG, "\n");


      // Now descrypt */
      memset(decbuf, '\0', 1024);
      // note; msglen -- may be incorrect for the encbuf !!!
#ifndef MC2
#ifdef CAVIUM_MULTICARD_API
      rc = Csp1DecryptAes(CAVIUM_BLOCKING, shim_ctxt, CAVIUM_NO_UPDATE, aes_type, msglen, encbuf, decbuf, &rid,pots_stp->dev_id);
#else
      rc = Csp1DecryptAes(CAVIUM_BLOCKING, shim_ctxt, CAVIUM_NO_UPDATE, aes_type, msglen, encbuf, decbuf, &rid);
#endif
#else
#ifdef CAVIUM_MULTICARD_API
      rc = Csp1DecryptAes (CAVIUM_BLOCKING,shim_ctxt,CAVIUM_NO_UPDATE,aes_type,msglen,encbuf,decbuf,ivbuf, keybuf,&rid,pots_stp->dev_id);
#else
      rc = Csp1DecryptAes (CAVIUM_BLOCKING,shim_ctxt,CAVIUM_NO_UPDATE,aes_type,msglen,encbuf,decbuf,ivbuf, keybuf,&rid);
#endif

#endif      
      if ( rc ) {
         fclose(aes_fp);
#ifdef CAVIUM_MULTICARD_API
         Csp1FreeContext(CONTEXT_SSL, shim_ctxt,pots_stp->dev_id);
#else
         Csp1FreeContext(CONTEXT_SSL, shim_ctxt);
#endif
         pots_log(PT_LOG_ERROR, "pots_aes(): Csp1DecryptAES() failed\n");
         return(-1);
      }

      pots_log(PT_LOG_DEBUG, 
            "pots_aes(): msglen = %d; pkp decrypted = \n", msglen);

      for (p = 0; p < msglen + 2; p++) {
         pots_log0(PT_LOG_DEBUG, "0x%0x ", decbuf[p]);
      }
      pots_log0(PT_LOG_DEBUG, "\n");


#if 0
      /* now encrypt using openssl */
      rc = pots_openssl_evp(   1, 
                        ossl_cipher_name,
                        msglen,
                         msgp, 
                        ivp, 
                        keyp, 
                        osslbuf, 
                        &outlen);
      if ( rc == -1 ) {
         printf("pots_aes(): pots_openssl_evp() failed\n");
         fclose(rfp);
#ifdef CAVIUM_MULTICARD_API
         Csp1FreeContext(CONTEXT_SSL, shim_ctxt,pots_stp->dev_id);
#else
         Csp1FreeContext(CONTEXT_SSL, shim_ctxt);
#endif
         return(-1);
      }
#endif

      pots_log(PT_LOG_DEBUG, 
            "pots_aes(): expected encrypted output:\n");

      for (p = 0; p < msglen; p++) {
         pots_log0(PT_LOG_DEBUG, "0x%0x ", osslbuf[p]);
      }
      pots_log0(PT_LOG_DEBUG, "\n");


      if ( memcmp(encbuf, osslbuf, msglen) != 0 ) {
         pots_log(PT_LOG_ERROR, 
               "pots_aes(): %s %s\n",
               "aes output from pkp and expected output ",
               "does not match. Test failed");
         print_hex("pkp encrypted data:\n", encbuf, msglen);
         print_hex("nist encrypted data:\n", osslbuf, msglen);
         fclose(aes_fp);
#ifdef CAVIUM_MULTICARD_API
         Csp1FreeContext(CONTEXT_SSL, shim_ctxt,pots_stp->dev_id);
#else
         Csp1FreeContext(CONTEXT_SSL, shim_ctxt);
#endif
         return(-1);
      }
      else {
         pots_log(PT_LOG_INFO, 
               "pots_aes(): passed test %d\n", test_nr);
      }

   } // end for 

#ifdef CAVIUM_MULTICARD_API
   Csp1FreeContext(CONTEXT_SSL, shim_ctxt,pots_stp->dev_id);
#else
   Csp1FreeContext(CONTEXT_SSL, shim_ctxt);
#endif

   pots_log(PT_LOG_INFO, "pots_aes(): aes test PASSED\n");

   fclose(aes_fp);

   return(0);

} // end pots_aes()
#endif


int get_test_data(   FILE *aes_fp, 
               AesType *aes_typep,
                 int *keylenp, 
               Uint8 *keybufp,
               int *msglenp,
               Uint8 *msgbufp,
               Uint8 *ivbufp,
               int *outlenp,
               Uint8 *osslbufp)
{

   int i;
   int rc;
   int test_nr;
   char rbuf[1024];
   char *tokenlist[6] = { "KEYSIZE=", "I=", "KEY=", "IV=", "PT=", "CT="};
   int tk_index;
   char *sptr;

   /* 
    * Read lines from aes data file. 
    * Extract the keysize, key, iv, pt (input) and ct (expected output)
    * Returnwhen got al of these.
    */
   tk_index = 0;   // next token id to look for 
   while ( fgets(rbuf, 1024, aes_fp) != NULL ) {

      // remove trainling newline
      sptr = strtok(rbuf, "\r\n");

      tk_index = -1;
      for (i = 0; i < 6; i++) {
         if ( (sptr = strstr(rbuf, tokenlist[i])) != NULL ) {
            tk_index = i;
            break;
         }
      }

      if ( tk_index == -1 ) {
         // go to next line in file 
         continue;   // back to while loop
      }

      pots_log(PT_LOG_DEBUG, 
            "get_test_data(): got token %s, in sptr = %s\n", 
               tokenlist[tk_index], sptr);

      switch (tk_index) {

      case 0:
         // get the size of key to be used
         if ( (rc = get_aes_intval((unsigned char *)sptr, keylenp)) == 0 ) {
            // got keylen
            tk_index++;

            if ( *keylenp == 128 )
               *aes_typep = AES_128;
            else if ( *keylenp == 192 )
               *aes_typep = AES_192;
            else if ( *keylenp == 256 )
               *aes_typep = AES_256;
            else {
               // error in keylen
               pots_log(PT_LOG_ERROR, 
                     "get_test_data(): invalid keylen = %d\n",
                     *keylenp);
               return(-1);
            }

            pots_log(PT_LOG_DEBUG, 
                  "get_test_data(): got keylen = %d\n",
                  *keylenp);

         } // end if

         break;


      case 1:
         // get test # "I=" 
         if ( (rc = get_aes_intval((unsigned char *)sptr, &test_nr)) == 0 ) {
            // got test_nr
            pots_log(PT_LOG_DEBUG, 
                  "get_test_data(): got test_nr = %d\n", test_nr);
            tk_index++;
         }
         break;


      case 2:
         // get "KEY="
         pots_log(PT_LOG_DEBUG, 
               "get_test_data(): strlen(sptr) = %d\n",
               strlen(sptr));
         get_aes_key((unsigned char *)sptr, keybufp);
         pots_log(PT_LOG_DEBUG, 
               "get_test_data(): got key = %s\n", keybufp);
         tk_index++;
         break;


      case 3:
         // get "IV="
         get_aes_iv((unsigned char *)sptr, ivbufp);
         pots_log(PT_LOG_DEBUG, 
               "get_test_data(): got iv = %s\n", ivbufp);
         tk_index++;
         break;


      case 4:
         // get "PT="
         get_aes_input_data((unsigned char *)sptr, msgbufp, msglenp);
         pots_log(PT_LOG_DEBUG, 
               "get_test_data(): got input = %s\n", msgbufp);
         tk_index++;
         break;


      case 5:
         // get expected data, i.e. "CT="
         get_aes_expected_output((unsigned char *)sptr, osslbufp, outlenp);

         pots_log(PT_LOG_DEBUG, 
               "get_test_data(): got expected output = %s\n", 
               osslbufp);
         
         // we got all data for this test case 
         tk_index = 0;

         pots_log(PT_LOG_DEBUG, 
               "get_test_data(): got complete test data\n");
         return(test_nr);


      default:
         pots_log(PT_LOG_ERROR, 
               "get_test_data(): invalid token # %d\n", tk_index);

      } // end switch
   
   } // end while fgets

   return(-2);      // no more data


} // end get_test_data
            

int get_aes_intval(Uint8 *str, int *intvalp)
{
   
   char *ptr;

   if (( ptr = strchr((char *)str, '=')) == NULL )
      return(-1);

   /* KEYSIZE is in decimal str */
   *intvalp = atoi(ptr+1);

   return(0);

}

Uint8 *get_aes_input_data_my(Uint8* str, Uint8 *msgbufp, int *msglenp)
{
   
   Uint8 *str1 = (Uint8 *)"PT=5d61f3c1866bb1cb80965d4e3a091192";

   get_hex_data(str1, '=', msgbufp, msglenp);

   pots_log(PT_LOG_DEBUG, 
         "get_aes_input_data(): got msglenp = %d\n", *msglenp);

   return(msgbufp);
}

Uint8 *get_aes_input_data(Uint8* str, Uint8 *msgbufp, int *msglenp)
{
   
   //Uint8 *str = "PT=66E94BD4EF8A2C3B884CFA59CA342B2E";

   get_hex_data(str, '=', msgbufp, msglenp);

   pots_log(PT_LOG_DEBUG, 
         "get_aes_input_data(): got msglenp = %d\n", *msglenp);

   return(msgbufp);
}


Uint8 *get_aes_key(Uint8 *str, Uint8 *keybufp)
{
   
   //Uint8 *str = "KEY=0B809DA0087E5D49AE46BC65AB4BC8CC";
   int len;

   get_hex_data(str, '=', keybufp, &len);

   pots_log(PT_LOG_DEBUG, 
         "get_aes_key(): got key len = %d\n", len);

   return(keybufp);

}


Uint8 *get_aes_iv(Uint8 *str, Uint8 *ivbufp)
{
   
   //Uint8 *str = "IV=6D69D674E7F47172260A463C617FE3E2";
   int len;

   get_hex_data(str, '=', ivbufp, &len);

   pots_log(PT_LOG_DEBUG, 
         "get_aes_iv(): got iv len = %d\n", len);

   return(ivbufp);
}


Uint8 *get_aes_expected_output(Uint8 *str, Uint8 *exbufp, int *lenp)
{
   //Uint8 *str = "CT=0499E85A60F426E4EB098CCE91A354E8";

   get_hex_data(str, '=', exbufp, lenp);

   return(exbufp);
}


/*
 * $Id: pots_aes.c,v 1.10 2009/09/22 09:57:08 aravikumar Exp $
 * $Log: pots_aes.c,v $
 * Revision 1.10  2009/09/22 09:57:08  aravikumar
 * made list of test options to constant for both plus and non-nplus
 *
 * Revision 1.9  2009/09/09 15:01:46  aravikumar
 * NPLUS macro dependency removed and made it dynamic
 *
 * Revision 1.8  2008/11/26 05:48:47  ysandeep
 * Fixed Bugs
 *
 * Revision 1.7  2008/11/05 06:45:57  ysandeep
 * Added NPLUS support for N1/NLite
 *
 * Revision 1.6  2008/10/31 10:51:29  ysandeep
 * MULTICARD support added for ipsec.
 * nplus_handle removed (NPLUS).
 *
 * Revision 1.5  2008/10/24 08:43:51  ysandeep
 * NPLUS support added
 *
 * Revision 1.4  2008/03/10 10:22:58  kkiran
 *  - Cavium Copyright added.
 *
 * Revision 1.3  2007/09/11 14:09:02  kchunduri
 * --provide option to run POTS on each PX device.
 *
 * Revision 1.2  2007/09/10 10:16:59  kchunduri
 * --Support added to use new multi-card API.
 *
 * Revision 1.1  2007/02/20 23:43:29  panicker
 * * Utilities checked in
 *
 * Revision 1.7  2006/09/12 07:02:37  kchunduri
 * Csp1FreeContext called at wrong place.
 *
 * Revision 1.6  2006/08/22 06:08:30  kchunduri
 * included "string.h" for declaration of "strtok()".
 *
 * Revision 1.5  2005/08/31 17:21:40  bimran
 * Fixed a lot of warnings.
 *
 * Revision 1.4  2005/05/21 05:17:31  rkumar
 * Merge with India CVS Head
 *
 * Revision 1.3  2004/04/23 21:57:25  bimran
 * Modified Csp1Initialize() call to take care NPLUS mode initiliaztion.
 *
 * Revision 1.2  2004/04/17 01:31:26  bimran
 * Things were not coded correctly to work with MC1 and MC2.
 *
 * Revision 1.1  2004/04/15 22:40:51  bimran
 * Checkin of the code from India with some cleanups.
 *
 */

