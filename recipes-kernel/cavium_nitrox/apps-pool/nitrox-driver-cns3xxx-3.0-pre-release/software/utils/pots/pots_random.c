/*
 * pots_random.c:
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

int pots_random_test(pots_sts *pots_stp)
{

   int i;
   int rc;
   int len = PT_RAND_BUF_SZ;
   unsigned char rdata[len];
   //Uint64 shim_ctxt;
   unsigned long saved_cs_val;   // for cmd/status register
   unsigned int dummy=0;
#ifdef CAVIUM_MULTICARD_API
        rc = Csp1Initialize(CAVIUM_DIRECT, pots_stp->dev_id);
#else
        rc = Csp1Initialize(CAVIUM_DIRECT);
#endif
   if ( rc ) {
      pots_log(PT_LOG_ERROR, 
            "pots_random_test(): Csp1Initialize() failed\n");
      return(-1);
   }
   
   /****
   rc = Csp1AllocContext(CONTEXT_SSL, &shim_ctxt,0);
   if ( rc ) {
      pots_log(PT_LOG_ERROR, "pots_random_test(): Csp1AllocContext() failed\n");
      return(-1);
   }
   ***/

   /* read and save the random entropy bit */
   rc = switch_entropy(pots_stp, 0, &saved_cs_val);

   if (rc == -1 ) {
      pots_log(PT_LOG_ERROR, 
            "pots_random_test(): switch_entropy() failed\n");
      return(-1);
   }
   pots_log(PT_LOG_DEBUG, 
         "pots_random_test(): saved_cs_val = 0x%0x\n", saved_cs_val);

   // read first set of random #'s */
#ifdef CAVIUM_MULTICARD_API
   if ( (rc = Csp1Random(CAVIUM_BLOCKING,len, rdata,&dummy,pots_stp->dev_id)) != 0 ) {
#else
   if ( (rc = Csp1Random(CAVIUM_BLOCKING,len, rdata,&dummy)) != 0 ) {
#endif
      pots_log(PT_LOG_ERROR, 
            "pots_random_test(): Csp1Random() failed\n");
      return(-1);
   }

   /* do soft reset */
   rc = soft_reset_test(pots_stp);
   if ( rc == -1 ) {
      pots_log(PT_LOG_ERROR, 
            "pots_random_test(): soft_reset_test() failed\n");
   }
   else {
      pots_log(PT_LOG_INFO, 
            "pots_random_test(): soft_reset_test() worked\n");
   }

   /* read and save the random entropy bit */
   rc = switch_entropy(pots_stp, 0, &saved_cs_val);
   if (rc == -1 ) {
      pots_log(PT_LOG_ERROR, 
            "pots_random_test(): switch_entropy() failed\n");
      return(-1);
   }
   pots_log(PT_LOG_DEBUG, 
         "pots_random_test(): saved_cs_val = 0x%0x\n", saved_cs_val);

   // read second set of random #'s */
#ifdef CAVIUM_MULTICARD_API
   if ( (rc = Csp1Random(CAVIUM_BLOCKING,len, rdata,&dummy,pots_stp->dev_id)) != 0 ) {
#else
   if ( (rc = Csp1Random(CAVIUM_BLOCKING,len, rdata,&dummy)) != 0 ) {
#endif
      pots_log(PT_LOG_ERROR, 
            "pots_random_test(): Csp1Random() failed\n");
      return(-1);
   }
   
   /* 
    * these two sets should be the same:
    *       - there might be some offset b/w the two sets
    *         (i.e. need to find the start of one set within another
    *          set, etc.).
    */
   // ADD CODE
   // now reset the cmd/status to it's original value 
   rc = pots_write_pkp_reg(pots_stp->pt_dd_fd, 
                     pots_stp->pt_bar0, 
                     COMMAND_STATUS, 
                     saved_cs_val);
   if (rc == -1 ) {
      pots_log(PT_LOG_ERROR, 
            "pots_random_test(): pots_write_pkp_reg() failed %s <%d>\n",
            strerror(errno), errno);
      return(-1);
   }
   
   // FOR NOW, read ths again, to see if entropy is turned on */
   rc = pots_get_pkp_reg_val(   pots_stp->pt_dd_fd, 
                        pots_stp->pt_bar0, 
                        COMMAND_STATUS, 
                        &saved_cs_val);
   if (rc == -1 ) {
      pots_log(PT_LOG_ERROR, 
            "pots_random_test(): pots_get_pkp_reg_val() failed\n");
      return(-1);
   }
   pots_log(PT_LOG_DEBUG, 
         "pots_random_test(): saved_cs_val = 0x%0x\n", saved_cs_val);

   // read set of truly random #'s */

#ifdef CAVIUM_MULTICARD_API
   if ( (rc = Csp1Random(CAVIUM_BLOCKING, len, rdata,&dummy,pots_stp->dev_id)) != 0 ) {
#else
   if ( (rc = Csp1Random(CAVIUM_BLOCKING, len, rdata,&dummy)) != 0 ) {
#endif
      pots_log(PT_LOG_ERROR, 
            "pots_random_test(): Csp1Random() failed\n");
      return(-1);
   }

   /* 
    * using openssl's function check that these numbers are truly 
    * random.
    */
   // ADD CODE!

   if ( (rc = check_random(len, rdata)) != 0 ) {
      pots_log(PT_LOG_INFO, 
            "pots_random(): check_random() failed, %d errors\n", rc);
   }
   else {
      pots_log(PT_LOG_INFO, 
            "pots_random(): check_random() WORKED\n");
   }


   return(0);

} // end pots_ddr()


/*
 * switch_entropy:
 *       - Turns entropy on of off.
 */
int switch_entropy(pots_sts *pots_stp, int on, unsigned long *outp)
{
   int rc;
   unsigned long saved2_cs_val;   // for cmd/status register
   unsigned long dwval;

   /* read and save the random entropy bit */
   rc = pots_get_pkp_reg_val(   pots_stp->pt_dd_fd, 
                        pots_stp->pt_bar0, 
                        COMMAND_STATUS, 
                        outp);
   if (rc == -1 ) {
      pots_log(PT_LOG_ERROR, 
            "pots_random_test(): pots_get_pkp_reg_val() failed\n");
      return(-1);
   }
   pots_log(PT_LOG_DEBUG, "pots_random_test(): *outp = 0x%0x\n", *outp);

   /* 
    * turn entropy on or off depending upon the flag passed: i.e. 
    * bit 9, and Disable rnd (bit 24) in cmd/status register 
    */
   if ( on == 0 )
      dwval = *outp & 0xFFFFFDFF;
   else
      // FIX THIS
      dwval = *outp;

   rc = pots_write_pkp_reg(pots_stp->pt_dd_fd, 
                     pots_stp->pt_bar0, 
                     COMMAND_STATUS, 
                     dwval);
   if (rc == -1 ) {
      pots_log(PT_LOG_ERROR, 
            "pots_random_test(): pots_write_pkp_reg() failed %s <%d>\n",
         strerror(errno), errno);
      return(-1);
   }
   
   // FOR NOW, read this again, to see if entropy is turned off */
   rc = pots_get_pkp_reg_val(   pots_stp->pt_dd_fd, 
                        pots_stp->pt_bar0, 
                        COMMAND_STATUS, 
                        &saved2_cs_val);
   if (rc == -1 ) {
      pots_log(PT_LOG_ERROR, 
            "pots_random_test(): pots_get_pkp_reg_val() failed\n");
      return(-1);
   }
   pots_log(PT_LOG_DEBUG, 
         "pots_random_test(): saved2_cs_val = 0x%0x\n", saved2_cs_val);
   
   return(0);

} // end switch_entropy()



/*
 * $Id: pots_random.c,v 1.6 2009/09/09 15:01:46 aravikumar Exp $
 * $Log: pots_random.c,v $
 * Revision 1.6  2009/09/09 15:01:46  aravikumar
 * NPLUS macro dependency removed and made it dynamic
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
 * Revision 1.1  2004/04/15 22:40:52  bimran
 * Checkin of the code from India with some cleanups.
 *
 */

