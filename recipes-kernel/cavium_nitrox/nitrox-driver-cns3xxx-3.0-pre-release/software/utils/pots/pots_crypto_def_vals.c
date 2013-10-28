/*
 * pots_crypto_def_vals.c:
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

#include <stdio.h>
#include <string.h>
#include "pots.h"


pots_crypto_def_vals(pots_sts *pots_stp)
{
   
   int i ;
   struct pots_crypto_test_cnf *cptr;

   for (i = 0; i < MAX_CRYPTO_TEST_CNF; i++) {

      cptr = &pots_stp->pt_test_cnf[i];

      cptr->cc_test_id = i;

      switch (i) {

      case PT_TESTID_RC4:   // RC4
         strcpy(cptr->cc_test_name, PT_TESTNAME_RC4);
         cptr->cc_start_key_sz = 8;
         cptr->cc_end_key_sz = 48;
         cptr->cc_key_incr = 8;
         cptr->cc_start_msg_sz = 40;
         cptr->cc_end_msg_sz = 200;
         cptr->cc_msg_incr = 40;
         break;

      case PT_TESTID_HMAC:   // HMAC
         strcpy(cptr->cc_test_name, PT_TESTNAME_HMAC);
         cptr->cc_start_key_sz = 8;
         cptr->cc_end_key_sz = 48;
         cptr->cc_key_incr = 8;
         cptr->cc_start_msg_sz = 40;
         cptr->cc_end_msg_sz = 200;
         cptr->cc_msg_incr = 40;
         break;

      case PT_TESTID_3DES:   // 3DES
         strcpy(cptr->cc_test_name, PT_TESTNAME_3DES);
         cptr->cc_start_key_sz = 24;
         cptr->cc_end_key_sz = 24;
         cptr->cc_key_incr = 0;
         cptr->cc_start_msg_sz = 40;
         cptr->cc_end_msg_sz = 200;
         cptr->cc_msg_incr = 40;
         break;

      case PT_TESTID_AES:   // AES
         strcpy(cptr->cc_test_name, PT_TESTNAME_AES);
         cptr->cc_start_key_sz = 8;
         cptr->cc_end_key_sz = 48;
         cptr->cc_key_incr = 8;
         cptr->cc_start_msg_sz = 40;
         cptr->cc_end_msg_sz = 200;
         cptr->cc_msg_incr = 40;
         break;

      case PT_TESTID_MOD_EX:   // MOD_EX
         strcpy(cptr->cc_test_name, PT_TESTNAME_MOD_EX);
         cptr->cc_start_key_sz = 8;
         cptr->cc_end_key_sz = 48;
         cptr->cc_key_incr = 8;
         cptr->cc_start_msg_sz = 40;
         cptr->cc_end_msg_sz = 200;
         cptr->cc_msg_incr = 40;
         break;
      
      default:
         pots_log(PT_LOG_ERROR, 
               "pots_crpto_def_vals(): invalid test_nr %d\n",
               i);
         return(-1);

      } // end switch

   } // end for 

   return(0);

} // end pots_crypto_def_vals() 


/*
 * $Id: pots_crypto_def_vals.c,v 1.3 2008/10/24 08:43:51 ysandeep Exp $
 * $Log: pots_crypto_def_vals.c,v $
 * Revision 1.3  2008/10/24 08:43:51  ysandeep
 * NPLUS support added
 *
 * Revision 1.2  2008/03/10 10:22:58  kkiran
 *  - Cavium Copyright added.
 *
 * Revision 1.1  2007/02/20 23:43:29  panicker
 * * Utilities checked in
 *
 * Revision 1.2  2005/08/31 17:21:40  bimran
 * Fixed a lot of warnings.
 *
 * Revision 1.1  2004/04/15 22:40:51  bimran
 * Checkin of the code from India with some cleanups.
 *
 */

