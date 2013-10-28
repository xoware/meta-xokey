/*
 * pots_read_write_reg:
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
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "cavium_sysdep.h"
#include "cavium_common.h"

#include "pots.h"
#include "pots_dd.h"


extern int px_flag;

/*
 * read_write_reg:
 */
int read_write_reg(pots_sts *pots_stp)
{

   int i;
   int rc;
   unsigned long saved_iqm_val;
   unsigned int wval;



   /* read and save the IQM0 base address high reg */

   if(px_flag==1){
   rc = pots_get_pkp_reg_val(pots_stp->pt_dd_fd,                           pots_stp->pt_bar0,
                              REQ1_BASE_HIGH,&saved_iqm_val);
   }
   else{
   rc = pots_get_pkp_reg_val(pots_stp->pt_dd_fd,
              pots_stp->pt_bar2, 
              REQ1_BASE_HIGH, 
            &saved_iqm_val);
   }

   if (rc == -1 ) {
      pots_log(PT_LOG_ERROR, 
            "read_write_reg(): pots_get_pkp_reg_val() failed\n");
      return(-1);
   }

   pots_log(PT_LOG_INFO, 
         "read_write_reg(): saved_iqm_val = 0x%0x\n", saved_iqm_val);

   /* 
    * Now write walking 1's then read them back.
    */
   for (i = 0; i < 32; i++ ) {

      wval = 0x00000001 << i;

      /***
      pots_log(PT_LOG_DEBUG, 
            "read_write_reg(): i = %d, wval = 0x%0x\n", i, wval);
      **/

   if(px_flag==1){
      rc = write_and_check_val(pots_stp->pt_dd_fd,pots_stp->pt_bar0,
                     REQ1_BASE_HIGH,wval);
   }
   else{
      rc = write_and_check_val(pots_stp->pt_dd_fd,
                pots_stp->pt_bar2, 
                REQ1_BASE_HIGH, 
                wval);
        }

      if (rc == -1 ) {
         pots_log(PT_LOG_ERROR, 
               "read_write_reg(): write_and_check_val() failed\n",
               strerror(errno), errno);
         return(-1);
      }
      
   } // end for
   pots_log(PT_LOG_INFO, "read_write_reg(): walking 1's test passed\n");

   /* 
    * Now write walking 0's then read them back.
    */
   for (i = 0; i < 32; i++ ) {

      wval = 0x00000001 << i;

      pots_log(PT_LOG_ERROR, 
            "read_write_reg(): i = %d, wval: 0x%lx ~wval = 0x%0lx\n", i, wval, ~wval);

   if(px_flag==1){

   rc = write_and_check_val(pots_stp->pt_dd_fd, 
                  pots_stp->pt_bar0, 
                                 REQ1_BASE_HIGH, ~wval);
   }
   else{

   rc = write_and_check_val(pots_stp->pt_dd_fd,                                   pots_stp->pt_bar2, REQ1_BASE_HIGH, ~wval);
   }


      if (rc == -1 ) {
         pots_log(PT_LOG_ERROR, 
               "read_write_reg(): write_and_check_val() failed\n",
               strerror(errno), errno);
         return(-1);
      }
      
   } // end for
   pots_log(PT_LOG_INFO, 
         "read_write_reg(): walking 0's test passed\n");

   /* restore the saved val */
   
   if(px_flag==1){
   rc = write_and_check_val(   pots_stp->pt_dd_fd,       
                    pots_stp->pt_bar0, 
               REQ1_BASE_HIGH, 
               saved_iqm_val);
   }
   else{
   
   rc = write_and_check_val(       pots_stp->pt_dd_fd,
                                        pots_stp->pt_bar2,
                                        REQ1_BASE_HIGH,
                                        saved_iqm_val);
   }



   if (rc == -1 ) {
      pots_log(PT_LOG_ERROR, 
            "read_write_reg(): pots_write_pkp_reg() failed\n",
            strerror(errno), errno);
      return(-1);
   }
   pots_log(PT_LOG_INFO, 
         "read_write_reg(): successfully restored val 0x%0x to iqm reg\n",
         saved_iqm_val);

   
   return(0);
   
} // end read_write_reg()


/*
 * write a value to a register, and then reads it back,
 * then compares the two values, return 0 on success
 * and -1 on error.
 */
int write_and_check_val(
      int dd_fd, 
      unsigned long bar,
      unsigned long addr_offset,
      unsigned long wval)
{
   int rc;
   unsigned long rval;

   rc = pots_write_pkp_reg(dd_fd, bar, addr_offset, wval);
   if (rc == -1 ) {
      pots_log(PT_LOG_ERROR, 
            "write_and_check_val(): pots_write_pkp_reg() failed %s <%d>\n",
            strerror(errno), errno);
      return(-1);
   }
   
   /* now read this same reg. */
   rc = pots_get_pkp_reg_val(dd_fd, bar, addr_offset, &rval);
   if (rc == -1 ) {
      pots_log(PT_LOG_ERROR, 
            "write_and_check_val(): pots_get_pkp_reg_val() failed\n");
      return(-1);
   }
   /* now compare the values */
   if ( rval != wval ) {
         pots_log(PT_LOG_ERROR, 
               "write_and_check_val(): error, rval = 0x%0lx, wval = 0x%0lx\n",
               rval, wval);
         return(-1);
   }

   return(0);

} // end write_and_check_val()

/*
 * $Id: pots_read_write_reg.c,v 1.6 2008/10/24 08:43:51 ysandeep Exp $
 * $Log: pots_read_write_reg.c,v $
 * Revision 1.6  2008/10/24 08:43:51  ysandeep
 * NPLUS support added
 *
 * Revision 1.5  2008/07/03 05:22:58  aramesh
 * deleted NITROX_PX flag.
 *
 * Revision 1.4  2008/03/10 10:22:58  kkiran
 *  - Cavium Copyright added.
 *
 * Revision 1.3  2007/10/04 11:20:26  tghoriparti
 * PX bar2 address is always read as 0, bar0 is to be used always
 *
 * Revision 1.2  2007/07/10 06:50:56  tghoriparti
 * 64bit changes done
 *
 * Revision 1.1  2007/02/20 23:43:29  panicker
 * * Utilities checked in
 *
 * Revision 1.4  2005/11/17 13:31:09  kanantha
 * Updating with the 64 bit modifications, with proper matching of data types
 *
 * Revision 1.3  2005/08/31 17:21:40  bimran
 * Fixed a lot of warnings.
 *
 * Revision 1.2  2005/05/21 05:17:31  rkumar
 * Merge with India CVS Head
 *
 * Revision 1.1  2004/04/15 22:40:52  bimran
 * Checkin of the code from India with some cleanups.
 *
 */

