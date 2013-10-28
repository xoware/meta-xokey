/*
 * pots_hmac.c:
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



#include "cavium_sysdep.h"
#include "cavium_common.h"

#include "pots.h"
#include "pots_proto.h"


Uint8 msgbuf[MAX_CRYPTO_MSGBUF_SZ];
Uint8 encbuf[MAX_CRYPTO_MSGBUF_SZ];
Uint8 decbuf[MAX_CRYPTO_MSGBUF_SZ];
Uint8 osslbuf[MAX_CRYPTO_MSGBUF_SZ];

Uint8 keybuf[MAX_CRYPTO_KEYBUF_SZ];

int pots_hmac(pots_sts *pots_stp)
{

   int i;
   int p;
   int rc;
   Uint64 shim_ctxt;

   unsigned int hashtype;
   Uint8 *msgptr;
   Uint8 *key;
   int msglen;
   int keylen;
   int outlen;
   struct pots_crypto_test_cnf *cptr;
   int max_msg_sz_to_test;
   int max_key_sz_to_test;
   FILE *rfp;
   int err=-1;

#ifdef CAVIUM_MULTICARD_API
   rc = Csp1Initialize(CAVIUM_DIRECT,pots_stp->dev_id);
   rc = Csp1AllocContext(CONTEXT_SSL, &shim_ctxt,pots_stp->dev_id);
#else /*CAVIUM_MULTICARD_API*/
   rc = Csp1Initialize(CAVIUM_DIRECT);
   rc = Csp1AllocContext(CONTEXT_SSL, &shim_ctxt);
#endif  /*CAVIUM_MULTICARD_API*/

   if ( rc ) {
      pots_log(PT_LOG_ERROR, "pots_hmac(): Csp1AllocContext() failed\n");
      goto fail;
   }

   /* 
    * open the hmac test results file 
    */
   if ((rfp = fopen(PT_HMAC_RESULTS_FNAME, "w+")) == NULL ) {
      pots_log(PT_LOG_ERROR,
            "pots_hmac(): fopen(%s) failed %s <%d>\n",
            PT_HMAC_RESULTS_FNAME, strerror(errno), errno);
#ifdef CAVIUM_MULTICARD_API
      Csp1FreeContext(CONTEXT_SSL, shim_ctxt,pots_stp->dev_id);
#else
      Csp1FreeContext(CONTEXT_SSL, shim_ctxt);
#endif
      goto fail;
   }
   setbuf(rfp, NULL);

   cptr = &pots_stp->pt_test_cnf[PT_TESTID_HMAC];


   if ( cptr->cc_end_key_sz > MAX_CRYPTO_KEY_SZ )
      max_key_sz_to_test = MAX_CRYPTO_KEY_SZ;
   else
      max_key_sz_to_test = cptr->cc_end_key_sz;

   if ( cptr->cc_end_msg_sz > MAX_CRYPTO_MSG_SZ )
      max_msg_sz_to_test = MAX_CRYPTO_MSG_SZ;
   else
      max_msg_sz_to_test = cptr->cc_end_msg_sz;

   fprintf(rfp, "starting HMAC test:\n");


#ifndef MC2
   for(hashtype = SHA1_TYPE; hashtype <= MD5_TYPE; hashtype++) {
#else
   for(hashtype = MD5_TYPE; hashtype <= SHA1_TYPE; hashtype++) {
#endif
      if ( hashtype == SHA1_TYPE )
         fprintf(rfp, "\nSHA1 TEST:\n");
      else
         fprintf(rfp, "\nMD5 TEST:\n");

      /*
       * note: if you change the # of tests, make sure the
       * static buffer size if ok.
       */
      /* test for diff key sizes */
      for (keylen = cptr->cc_start_key_sz; 
          keylen <= max_key_sz_to_test; 
          keylen = keylen + cptr->cc_key_incr) 
      {

         fprintf(rfp, "\nKEYSIZE = %d\n", keylen);
         pots_log(PT_LOG_INFO, "pots_hmac(): keylen = %d\n", keylen);

         key = getrandom(keybuf, keylen);

         print_hex2(rfp, "\tKEY = ", key, keylen);

         /* test for diff msg size for this key size */
         for (msglen = cptr->cc_start_msg_sz; 
             msglen <= max_msg_sz_to_test; 
             msglen = msglen + cptr->cc_msg_incr) 
         {

            fprintf(rfp, "\n\tMSGSIZE = %d\n", msglen);

            // generate random key and data for the test
            msgptr = getrandom(msgbuf, msglen);

            print_hex2(rfp, "\tINPUT_MSG = ", msgptr, msglen);

            memset(encbuf, '\0', 1024);
            rc = pots_calculate_hmac(pots_stp,CM_ONE_CALL, shim_ctxt, hashtype, 
                           keylen, key, 
                           msglen, msgptr, 
                           encbuf);
            if (rc == ERR_OPERATION_NOT_SUPPORTED) {
               pots_log(PT_LOG_INFO,"pots_hmac operation not suported  \n");
#ifdef CAVIUM_MULTICARD_API
               Csp1FreeContext(CONTEXT_SSL, shim_ctxt,pots_stp->dev_id);
#else
               Csp1FreeContext(CONTEXT_SSL, shim_ctxt);
#endif
               fclose(rfp);
#ifdef CAVIUM_MULTICARD_API
               Csp1Shutdown(pots_stp->dev_id);
#else
               Csp1Shutdown();
#endif
               return rc;
            }
            pots_log(PT_LOG_DEBUG, 
                  "pots_hmac(): msglen = %d; encrypted:\n", msglen);
            if ( hashtype == MD5_TYPE )
               outlen = 16;
            else
               outlen = 20;   // for md5, 20 for sha1

            for (p = 0; p < outlen; p++) {
               pots_log0(PT_LOG_DEBUG, "0x%0x ", encbuf[p]);
            }
            pots_log0(PT_LOG_DEBUG, "\n");
            memset(osslbuf, '\0', 1024);
            /* now calculate hmac using openssl */
            rc = pots_openssl_hmac(CM_ONE_CALL, hashtype, key, 
                     keylen, msgptr, msglen, osslbuf, &outlen);
         
            pots_log(PT_LOG_DEBUG, 
                  "pots_hmac(): msglen = %d; ossl encrypted\n", msglen);
            for (p = 0; p < outlen; p++) {
               pots_log0(PT_LOG_DEBUG, "0x%0x ", osslbuf[p]);
            }
            pots_log0(PT_LOG_DEBUG, "\n");

            if ( memcmp(encbuf, osslbuf, outlen) != 0 ) {
               pots_log(PT_LOG_ERROR, 
                     "pots_hmac(): hmac output from pkp and openssl does not match. Test failed\n");
               fprintf(rfp, "HMAC test failed: %s\n",
                     "pkp and openssl out does not match");
#ifdef CAVIUM_MULTICARD_API
               Csp1FreeContext(CONTEXT_SSL, shim_ctxt,pots_stp->dev_id);
#else
               Csp1FreeContext(CONTEXT_SSL, shim_ctxt);
#endif
               fclose(rfp);
               goto fail;
            }

            print_hex2(rfp, "\tOUTPUT_MSG = ", encbuf, outlen);
         
         } // end for msglen

      } // end for keylen

   } // end hashtype

   pots_log(PT_LOG_INFO, "pots_hmac(): hmac test PASSED\n");
   fprintf(rfp, "HMAC TEST PASSED\n");
   fclose(rfp);
   err =0;
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
} // end pots_hmac()


int pots_calculate_hmac(
                pots_sts *pots_stp,
      int calc_method,
      Uint64 shim_ctxt,
      unsigned int hashtype, 
      int keylen,
      Uint8 *key,
      int msglen,
      Uint8 *msgptr,
      Uint8 *hmac)
{

   int rc;
   unsigned int dummy=0;

   if ( calc_method == CM_ONE_CALL ) {
/*
Csp1Hmac (n1_request_type request_type,
     HashType hash_type,
     Uint8 *iv,
     Uint16 key_length,
     Uint8 * key,
     Uint16 message_length,
     Uint8 * message, Uint8 * hmac, Uint32 * request_id);
     */

#ifdef CAVIUM_MULTICARD_API
      rc = Csp1Hmac(CAVIUM_BLOCKING,hashtype, NULL, keylen, key, msglen, msgptr, hmac, &dummy,pots_stp->dev_id);
#else
      rc = Csp1Hmac(CAVIUM_BLOCKING,hashtype, NULL, keylen, key, msglen, msgptr, hmac, &dummy);
#endif
      if (rc == ERR_OPERATION_NOT_SUPPORTED) {
         pots_log(PT_LOG_ERROR, "pots_hmac(): Csp1Hmac() failed\n");
         return rc;
      }
 
      if ( rc ) {
         pots_log(PT_LOG_ERROR, "pots_hmac(): Csp1Hmac() failed\n");
         return(-1);
      }

      return(0);
   }

   // multiple call code ...
   // ADD CODE

} // end pots_calculate_hmac()


/*
 * $Id: pots_hmac.c,v 1.16 2009/09/22 09:57:08 aravikumar Exp $
 * $Log: pots_hmac.c,v $
 * Revision 1.16  2009/09/22 09:57:08  aravikumar
 * made list of test options to constant for both plus and non-nplus
 *
 * Revision 1.15  2009/09/09 15:01:46  aravikumar
 * NPLUS macro dependency removed and made it dynamic
 *
 * Revision 1.14  2008/12/16 12:04:42  jsrikanth
 * Added Common driver and Multi-Card Changes for FreeBSD
 *
 * Revision 1.13  2008/11/26 05:48:47  ysandeep
 * Fixed Bugs
 *
 * Revision 1.12  2008/11/05 06:45:57  ysandeep
 * Added NPLUS support for N1/NLite
 *
 * Revision 1.11  2008/11/03 10:11:21  ysandeep
 * printf removed
 *
 * Revision 1.10  2008/10/31 10:51:29  ysandeep
 * MULTICARD support added for ipsec.
 * nplus_handle removed (NPLUS).
 *
 * Revision 1.9  2008/10/24 08:43:51  ysandeep
 * NPLUS support added
 *
 * Revision 1.8  2008/06/03 07:04:09  rsruthi
 * Added extra argument, IV in Csp1Hmac api for SHA2 support.
 * Still need to be supported in pots test.
 *
 * Revision 1.7  2008/03/10 10:22:58  kkiran
 *  - Cavium Copyright added.
 *
 * Revision 1.6  2008/03/04 04:42:25  kkiran
 *  - Fixed compilation issue.
 *
 * Revision 1.5  2008/03/03 11:19:59  kkiran
 *  - HMAC test for MC2 is fixed under "#ifndef MC2" directive.
 *
 * Revision 1.4  2007/09/11 14:09:02  kchunduri
 * --provide option to run POTS on each PX device.
 *
 * Revision 1.3  2007/09/10 10:16:59  kchunduri
 * --Support added to use new multi-card API.
 *
 * Revision 1.1  2007/02/20 23:43:29  panicker
 * * Utilities checked in
 *
 * Revision 1.6  2005/11/17 13:31:09  kanantha
 * Updating with the 64 bit modifications, with proper matching of data types
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

