/*
 * pots_mod_ex.c:
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

#include "openssl/bn.h"
#include "openssl/crypto.h"
#include "openssl/rand.h"
int pots_modex_devid = 0;

int pots_mod_ex(pots_sts *pots_stp)
{
   int i;
   int rc;
   BN_CTX *bn_ctxtp = NULL;
   BIGNUM *pp = NULL;
   BIGNUM *xp = NULL;
   BIGNUM *ep = NULL;
   BIGNUM *mp = NULL;
   BIGNUM *tempp = NULL;
   char *pstr;
   char *xstr;
   char *estr;
   char *mstr;
   char *tempstr;
   char tempbuf[100];
   int test_nr;
   Uint16 modlen;
   //Uint64 shim_ctxt = 0;
   Uint8 *pkp_xp;
   Uint8 *pkp_mp;
   Uint8 *pkp_ep;
   Uint8 *pkp_pp;
   int max_msg_sz_to_test;
   FILE *rfp;
   struct pots_crypto_test_cnf *cptr;
   int explen;
   int max_explen_to_test;
   int max_modlen_to_test;
   // initialize shim (i.e open dd)
   //rc = Csp1Initialize(CAVIUM_DIRECT);
   
   // allocate shim context 
/*   rc = Csp1AllocContext(CONTEXT_SSL, &shim_ctxt);
   if ( rc ) {
      pots_log(PT_LOG_ERROR, 
            "pots_mod_ex(): Csp1AllocContext() failed\n");
      return(-1);
   }*/

   /* seed randomness */
   strcpy(tempbuf, "Random number seeder");
   RAND_seed(tempbuf, strlen(tempbuf));
   if ( RAND_status() == 1 ) 
      pots_log(PT_LOG_DEBUG, "have enough randomness\n");
   else
      pots_log(PT_LOG_DEBUG, "do NOT have enough randomness\n");



   // create a BN_CTX 
   bn_ctxtp = BN_CTX_new();
   
   pp = BN_new();   // so we know that it got changed
   tempp = BN_new();
   xp = BN_new();
   ep = BN_new();
   mp = BN_new();
   pots_log(PT_LOG_DEBUG, "create_bignum() done\n");

   cptr = &pots_stp->pt_test_cnf[PT_TESTID_MOD_EX];

   if ( cptr->cc_end_msg_sz > MAX_CRYPTO_MOD_SZ )
      max_modlen_to_test = MAX_CRYPTO_MOD_SZ;
   else
      max_modlen_to_test = cptr->cc_end_msg_sz;

   /* 
    * open the mod_ex test results file 
    */
   if ((rfp = fopen(PT_MODEX_RESULTS_FNAME, "w+")) == NULL ) {
      pots_log(PT_LOG_ERROR,
            "pots_mod_ex(): fopen(%s) failed %s <%d>\n",
            PT_MODEX_RESULTS_FNAME, strerror(errno), errno);
      rc = -1;
      goto err;
   }
   setbuf(rfp, NULL);

   fprintf(rfp, "starting MOD_EX test:\n");

   /* test for diff modulus size for this exp size */

   for (modlen = cptr->cc_start_msg_sz; 
       modlen <= max_modlen_to_test; 
       modlen = modlen + cptr->cc_msg_incr) 
   {

      fprintf(rfp, "\n\tMODLEN = %d\n", modlen);

      pots_log(PT_LOG_DEBUG, "pots_mod_ex(): modlen = %d\n", modlen);

      /* now get a random # */
      BN_rand(ep, modlen*8, 0, 0);
      BN_rand(xp, modlen*8, 0, 0);
      BN_rand(mp, modlen*8, 0, 1);   // to get odd mod val

      // need for space
      //BN_rand(pp, modlen*8, 0, 0);   

      // print this out
      //xstr = BN_bn2dec(xp);
      //estr = BN_bn2dec(ep);
      //mstr = BN_bn2dec(mp);
      xstr = BN_bn2hex(xp);
      estr = BN_bn2hex(ep);
      mstr = BN_bn2hex(mp);
      pots_log(PT_LOG_INFO ,"xp = %s\n", xstr);
      pots_log(PT_LOG_INFO ,"ep = %s\n", estr);
      pots_log(PT_LOG_INFO ,"mp = %s\n", mstr);

      fprintf(rfp ,"\tx = %s (%d bytes)\n", xstr, BN_num_bytes(xp));
      fprintf(rfp ,"\texp = %s (%d bytes)\n", estr, BN_num_bytes(ep));
      fprintf(rfp ,"\tmodulus = %s (%d bytes)\n", mstr, BN_num_bytes(mp));

      OPENSSL_free(xstr);
      OPENSSL_free(estr);
      OPENSSL_free(mstr);

      // run mod ex
      rc = BN_mod_exp(pp, xp, ep, mp, bn_ctxtp);
      pots_log(PT_LOG_INFO ,"BN_mod_exp(): rc = %d\n", rc);

      pstr = BN_bn2dec(pp);
      pots_log(PT_LOG_INFO ,"result of x exp e mod m = %s\n", pstr);
      fprintf(rfp ,"\tresult of x exp e mod m = %s\n", pstr);
      OPENSSL_free(pstr);

#if 0
      // now use the chip to to mod ex
      pkp_xp = my_bn2_Uint8(xp);
      pkp_ep = my_bn2_Uint8(ep);
      pkp_mp = my_bn2_Uint8(mp);
      pkp_pp = my_bn2_Uint8(xp);   // trick to allocate bufffer

      rc = Csp1Me(RESULT_PTR, 0, modlen, pkp_xp, pkp_mp, pkp_ep, pkp_pp);
      if ( rc != 0 ) {
         pots_log(PT_LOG_ERROR, 
               "pots_mod_ex(): Csp1Me() failed\n");
         fprintf(rfp, "MOD_EX Test Failed: Csp1Me() failed\n");
         rc = -1;
         goto err;
      }
      pots_log(PT_LOG_ERROR, "pots_mod_ex(): Csp1Me() worked\n");
      print_hex(pkp_pp, 5);
      free(pkp_xp);
      free(pkp_ep);
      free(pkp_mp);
      free(pkp_pp);

#else

#ifdef CAVIUM_MULTICARD_API
		pots_modex_devid = pots_stp->dev_id; 
#endif
      rc = cav_mod_exp(tempp, xp, ep, mp);
      if ( rc != 1 ) {
         pots_log(PT_LOG_ERROR, 
               "pots_mod_ex(): cav_mod_exp() failed\n");
         fprintf(rfp, "MOD_EX Test Failed: cav_mod_exp() failed\n");
         rc = -1;
         goto err;
      }
      pots_log(PT_LOG_DEBUG, 
            "pots_mod_ex(): cav_mod_exp() WORKED\n");
      tempstr = BN_bn2dec(tempp);
      pots_log(PT_LOG_INFO ,"tempp = %s\n", tempstr);
      OPENSSL_free(tempstr);
      
      if ( BN_cmp(pp, tempp) != 0 ) {
         pots_log(PT_LOG_ERROR, 
               "pots_mod_ex(): %s %s\n",
               "ERROR: mod_ex results from pkp and openssl ",
               "are diff");
         fprintf(rfp, "%s %s %s\n",
               "MOD_EX Test Failed. "
               "ERROR: mod_ex results from pkp and openssl ",
               "are diff");
         rc = -1;
         goto err;
      }
      pots_log(PT_LOG_DEBUG, 
            "pots_mod_ex(): BN_cmp() WORKED\n");

#endif

temp_go:
      BN_clear(tempp);
      BN_clear(pp);
      BN_clear(xp);
      BN_clear(ep);
      BN_clear(mp);

   } // end for modlen

   fprintf(rfp, "MOD EX Test Passed\n");

err:
   if ( tempp != NULL ) 
      BN_free(tempp);
   if ( pp != NULL ) 
      BN_free(pp);
   if ( xp != NULL ) 
      BN_free(xp);
   if ( ep != NULL ) 
      BN_free(ep);
   if ( mp != NULL ) 
      BN_free(mp);
   
   if ( bn_ctxtp != NULL )
      BN_CTX_free(bn_ctxtp);

   /*if ( shim_ctxt != 0 )
      Csp1FreeContext(CONTEXT_SSL, shim_ctxt);*/

   fclose(rfp);
   
   return rc;

} // end pots_mod_ex()


Uint8 *my_bn2_Uint8(BIGNUM *bnp)
{
   int len;
   Uint8 *befp;   // for big-endian formatted bnp
   Uint8 *dp;      // for host-formatted bnp

   // get len of space needed to save bnp in binary format
   len = BN_num_bytes(bnp);
   if ( (befp = malloc(len)) == NULL ) {
      pots_log(PT_LOG_ERROR ,"malloc(%d) failed\n", len);
      return(NULL);
   }

   /* convert bn to binary */
   len = BN_bn2bin(bnp, befp);

   /* 
    * we now have bnp saved in big-endian format in befp,
    * convert this.
    */
   // ADD CODE!!!
   return(befp);

} // end my_bn2_unit8()


/*
 * $Id: pots_mod_ex.c,v 1.6 2008/12/16 12:04:42 jsrikanth Exp $
 * $Log: pots_mod_ex.c,v $
 * Revision 1.6  2008/12/16 12:04:42  jsrikanth
 * Added Common driver and Multi-Card Changes for FreeBSD
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
 * Revision 1.2  2007/07/14 10:53:44  tghoriparti
 * returned rc in pots_mod_exp
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

