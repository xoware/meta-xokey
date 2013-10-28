/*
 * pots_3des.c:
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


extern Uint8 msgbuf[];
extern Uint8 encbuf[];
extern Uint8 decbuf[];
extern Uint8 osslbuf[];

extern Uint8 keybuf[];

int pots_3des(pots_sts *pots_stp)
{

   int i;
   int p;
   int rc;
   Uint64 shim_ctxt;
   Uint8 *msgp;
   Uint8 *keyp;
   Uint8 ivbuf[10];
   Uint8 *ivp;
   Uint32 rid;


   int msglen;
   int keylen;
   int ivlen;
   int outlen;
   int max_msg_sz_to_test;
   FILE *rfp;
   struct pots_crypto_test_cnf *cptr;
   int err = -1;
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

            "pots_3des(): Csp1AllocContext() failed\n");
      goto fail;
   }

   /* 
    * open the 3des test results file 
    */
   if ((rfp = fopen(PT_3DES_RESULTS_FNAME, "w+")) == NULL ) {
#ifdef CAVIUM_MULTICARD_API
      Csp1FreeContext(CONTEXT_SSL, shim_ctxt,pots_stp->dev_id);
#else
      Csp1FreeContext(CONTEXT_SSL, shim_ctxt);
#endif
      pots_log(PT_LOG_ERROR,
            "pots_rc4(): fopen(%s) failed %s <%d>\n",
            PT_3DES_RESULTS_FNAME, strerror(errno), errno);
      goto fail;
   }
   setbuf(rfp, NULL);

   cptr = &pots_stp->pt_test_cnf[PT_TESTID_3DES];

   keylen = 24;      // 3DES using 192 bit keys
   keyp = getrandom(keybuf, keylen);

   ivlen = 8;
   ivp = getrandom(ivbuf, ivlen);

   fprintf(rfp, "starting 3DES test:\n");

   fprintf(rfp, "\nKEYSIZE = %d\n", keylen);
   pots_log(PT_LOG_INFO, "pots_3des(): keylen = %d\n", keylen);

   print_hex2(rfp, "\tKEY = ", keyp, keylen);

   print_hex2(rfp, "\tIV = ", ivp, ivlen);


   if ( cptr->cc_end_msg_sz > MAX_CRYPTO_MSG_SZ )
      max_msg_sz_to_test = MAX_CRYPTO_MSG_SZ;
   else
      max_msg_sz_to_test = cptr->cc_end_msg_sz;


   /*
    * note: if you change the # of tests, make sure the
    * static buffer size if ok.
    */
   for (msglen = cptr->cc_start_msg_sz; 
       msglen <= max_msg_sz_to_test; 
       msglen = msglen + cptr->cc_msg_incr) 
   {


      // generate random key and data for the test
      fprintf(rfp, "\n\tMSGSIZE = %d\n", msglen);

      // generate random key and data for the test
      msgp = getrandom(msgbuf, msglen);

      print_hex2(rfp, "\tINPUT_MSG = ", msgp, msglen);

#ifndef MC2
#ifdef CAVIUM_MULTICARD_API
      rc = Csp1Initialize3DES(CAVIUM_BLOCKING, shim_ctxt, ivp, keyp, &rid,pots_stp->dev_id);
#else
      rc = Csp1Initialize3DES(CAVIUM_BLOCKING, shim_ctxt, ivp, keyp, &rid);
#endif
      if ( rc ) {
#ifdef CAVIUM_MULTICARD_API
         Csp1FreeContext(CONTEXT_SSL, shim_ctxt,pots_stp->dev_id);
#else
         Csp1FreeContext(CONTEXT_SSL, shim_ctxt);
#endif
         fclose(rfp);
         if (rc == ERR_OPERATION_NOT_SUPPORTED) {
            pots_log(PT_LOG_INFO, 
                "pots_3des(): Csp1Initialize3DES() Operation not supported\n");
            fprintf(rfp, "3DES test passed: %s\n", 
                  "Csp1Initialize3DES() Operation not supported\n");
#ifdef CAVIUM_MULTICARD_API
            Csp1Shutdown(pots_stp->dev_id);
#else
            Csp1Shutdown();
#endif
            return rc;
         }
         pots_log(PT_LOG_ERROR, 
               "pots_3des(): Csp1Initialize3DES() failed\n");
         fprintf(rfp, "3DES test failed: %s\n", 
               "Csp1Initialize3DES() failed\n");

         goto fail;
      }

      // input msg is
      pots_log(PT_LOG_DEBUG, 
            "pots_3des(): msglen = %d; input msg = ", msglen);

      for (p = 0; p < msglen + 2; p++) {
         pots_log0(PT_LOG_DEBUG, "0x%0x ", msgp[p]);
      }
      pots_log0(PT_LOG_DEBUG, "\n");

      memset(encbuf, '\0', 1024);
      
#ifdef CAVIUM_MULTICARD_API
      rc = Csp1Encrypt3Des(CAVIUM_BLOCKING, shim_ctxt, CAVIUM_NO_UPDATE, msglen, msgp, encbuf, &rid,pots_stp->dev_id);
#else
      rc = Csp1Encrypt3Des(CAVIUM_BLOCKING, shim_ctxt, CAVIUM_NO_UPDATE, msglen, msgp, encbuf, &rid);
#endif
#else
#ifdef CAVIUM_MULTICARD_API
      rc = Csp1Encrypt3Des(CAVIUM_BLOCKING, shim_ctxt, CAVIUM_NO_UPDATE, msglen, msgp, encbuf, ivp, keyp, &rid,pots_stp->dev_id);
#else
      rc = Csp1Encrypt3Des(CAVIUM_BLOCKING, shim_ctxt, CAVIUM_NO_UPDATE, msglen, msgp, encbuf, ivp, keyp, &rid);
#endif
#endif
      //rc = Csp1Encrypt3Des(shim_ctxt, CAVIUM_NO_UPDATE, ROUNDUP8(msglen), msgp, encbuf);
      if ( rc ) {
#ifdef CAVIUM_MULTICARD_API
         Csp1FreeContext(CONTEXT_SSL, shim_ctxt,pots_stp->dev_id);
#else
         Csp1FreeContext(CONTEXT_SSL, shim_ctxt);
#endif
         fclose(rfp);
         if (rc == ERR_OPERATION_NOT_SUPPORTED ) {
            pots_log(PT_LOG_INFO, "pots_3des(): Csp1Encrypt3Des() Operation not supported\n");
            fprintf(rfp, "3DES test passed : %s\n", 
                  " Csp1Encrypt3Des() Operation not supported");
#ifdef CAVIUM_MULTICARD_API
            Csp1Shutdown(pots_stp->dev_id);
#else
            Csp1Shutdown();
#endif
            return rc;
         }
         pots_log(PT_LOG_ERROR, "pots_3des(): Csp1Encrypt3Des() failed\n");
         fprintf(rfp, "3DES test failed: %s\n", 
               " Csp1Encrypt3Des() failed");
         goto fail;
      }

      pots_log(PT_LOG_DEBUG, 
            "pots_3des(): msglen = %d; pkp encrypted = \n", msglen);

      for (p = 0; p < msglen + 2; p++) {
         pots_log0(PT_LOG_DEBUG, "0x%0x ", encbuf[p]);
      }
      pots_log0(PT_LOG_DEBUG, "\n");


      // Now descrypt */
      memset(decbuf, '\0', 1024);
      // note; msglen -- may be incorrect for the encbuf !!!
#ifdef MC2
#ifdef CAVIUM_MULTICARD_API
      rc = Csp1Decrypt3Des(CAVIUM_BLOCKING, shim_ctxt, CAVIUM_NO_UPDATE, msglen, encbuf, decbuf, ivp, keyp, &rid,pots_stp->dev_id);
#else
      rc = Csp1Decrypt3Des(CAVIUM_BLOCKING, shim_ctxt, CAVIUM_NO_UPDATE, msglen, encbuf, decbuf, ivp, keyp, &rid);
#endif
#else
#ifdef CAVIUM_MULTICARD_API
      rc = Csp1Decrypt3Des(CAVIUM_BLOCKING, shim_ctxt, CAVIUM_NO_UPDATE, msglen, encbuf, decbuf, &rid,pots_stp->dev_id);
#else
      rc = Csp1Decrypt3Des(CAVIUM_BLOCKING, shim_ctxt, CAVIUM_NO_UPDATE, msglen, encbuf, decbuf, &rid);
#endif
#endif
      if ( rc ) {
#ifdef CAVIUM_MULTICARD_API
         Csp1FreeContext(CONTEXT_SSL, shim_ctxt,pots_stp->dev_id);
#else
         Csp1FreeContext(CONTEXT_SSL, shim_ctxt);
#endif
         pots_log(PT_LOG_ERROR, "pots_3des(): Csp1Decrypt3Des() failed\n");
         fprintf(rfp, "3DES test failed: %s\n", 
               " Csp1Decrypt3Des() failed");
         fclose(rfp);
         goto fail;
      }

      pots_log(PT_LOG_DEBUG, 
            "pots_3des(): msglen = %d; pkp decrypted = \n", msglen);

      for (p = 0; p < msglen + 2; p++) {
         pots_log0(PT_LOG_DEBUG, "0x%0x ", decbuf[p]);
      }
      pots_log0(PT_LOG_DEBUG, "\n");


      /* now encrypt using openssl */
      rc = pots_openssl_evp(   1, 
                        "des-ede3-cbc", 
                        msglen,
                         msgp, 
                        ivp, 
                        keyp, 
                        osslbuf, 
                        &outlen);
      if ( rc == -1 ) {
#ifdef CAVIUM_MULTICARD_API
         Csp1FreeContext(CONTEXT_SSL, shim_ctxt,pots_stp->dev_id);
#else
         Csp1FreeContext(CONTEXT_SSL, shim_ctxt);
#endif
         printf("pots_3des(): pots_openssl_evp() failed\n");
         fprintf(rfp, "3DES test failed: pots_openssl_evp() failed\n");
         fclose(rfp);
         goto fail;
      }


      pots_log(PT_LOG_DEBUG, 
            "pots_3des(): ossl encrypted, len %d\n", outlen);

      for (p = 0; p < outlen; p++) {
         pots_log0(PT_LOG_DEBUG, "0x%0x ", osslbuf[p]);
      }
      pots_log0(PT_LOG_DEBUG, "\n");

      if ( memcmp(encbuf, osslbuf, msglen) != 0 ) {
         pots_log(PT_LOG_ERROR, 
               "pots_3des(): 3des output from pkp and openssl does not match. Test failed\n");
#ifdef CAVIUM_MULTICARD_API
         Csp1FreeContext(CONTEXT_SSL, shim_ctxt,pots_stp->dev_id);
#else
         Csp1FreeContext(CONTEXT_SSL, shim_ctxt);
#endif
         fprintf(rfp, "3DES test failed: %s %s\n",
               "3des output from pkp and openssl does not match.",
               "Test failed.");
         print_hex("pkp encrypted data:\n", encbuf, msglen);
         print_hex("openssl encrypted data:\n", osslbuf, msglen);
         fclose(rfp);
         goto fail;
      }

      print_hex2(rfp, "\tOUTPUT_MSG = ", encbuf, msglen);

   } // end for 

   pots_log(PT_LOG_INFO, "pots_3des(): 3des test PASSED\n");
   fprintf(rfp, "3DES Test Passed\n");
   fclose(rfp);
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

} // end pots_3des()

/*
 * $Id: pots_3des.c,v 1.11 2009/09/22 09:57:08 aravikumar Exp $
 * $Log: pots_3des.c,v $
 * Revision 1.11  2009/09/22 09:57:08  aravikumar
 * made list of test options to constant for both plus and non-nplus
 *
 * Revision 1.10  2009/09/09 15:01:46  aravikumar
 * NPLUS macro dependency removed and made it dynamic
 *
 * Revision 1.9  2008/12/16 12:04:42  jsrikanth
 * Added Common driver and Multi-Card Changes for FreeBSD
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
 * Revision 1.4  2005/08/31 17:21:40  bimran
 * Fixed a lot of warnings.
 *
 * Revision 1.3  2005/05/21 05:17:31  rkumar
 * Merge with India CVS Head
 *
 * Revision 1.2  2004/04/23 21:57:25  bimran
 * Modified Csp1Initialize() call to take care NPLUS mode initiliaztion.
 *
 * Revision 1.1  2004/04/15 22:40:51  bimran
 * Checkin of the code from India with some cleanups.
 *
 */

