/*
 * pots_test:
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
#include <errno.h>

#include "pots.h"

#include "cavium_sysdep.h"
#include "cavium_common.h"
#include "cavium_ioctl.h"

#include "pots_dd.h"

/*
 * Soft Reset Test:
 *       - Does a soft reset on the chip.
 */
int soft_reset_test(pots_sts *pots_stp)
{

   int rc;
   unsigned long outval;
   pots_log(PT_LOG_DEBUG, "soft_reset_test(): entry\n");

   /* 
    * call ioctl to do a "pots based" soft reset of NITROX.
    * (note: existing dd does too many things for the
    *  do_soft_reset()
    */
#ifdef CAVIUM_MULTICARD_API
   rc = ioctl(pots_stp->pt_dd_fd, IOCTL_N1_SOFT_RESET_CODE, pots_stp->dev_id);
#else
   rc = ioctl(pots_stp->pt_dd_fd, IOCTL_N1_SOFT_RESET_CODE,0 );
#endif

   if ( rc == -1 ) {
      pots_log(PT_LOG_SEVERE, 
            "soft_reset_test(): ioctl() failed %s <%d>\n",
            strerror(errno), errno);
      return(-1);
   }
   pots_log(PT_LOG_INFO, 
         "soft_reset_test(): ioctl() for soft reset done\n");


   /*
    * now check bist reg, unit enable reg and # of exec units
    * and save these values.
    */
#if 0 /* BIST desabled */
   if ( (rc = check_bist_reg(pots_stp, &outval)) == -1 ) {
      pots_log(PT_LOG_INFO,
         "soft_reset_test(): check_bist_reg() failed\n");
      return(-1);
   }

   /* save the bist reg value */
   if ( outval != pots_stp->pt_bist_regval ) {
      pots_log(PT_LOG_ERROR, 
         "soft_reset_test(): saved bist reg = 0x%0x, after reset = 0x%0x\n",
         pots_stp->pt_bist_regval, outval);
      pots_stp->pt_bist_regval = outval;
   }
#endif


   if ( (rc = check_unit_enable_reg(pots_stp, &outval)) == -1 ) {
      pots_log(PT_LOG_INFO,
         "soft_reset_test(): check_unit_enable_reg() failed\n");
      return(-1);
   }

   /* save the unit enable reg value */
   if ( outval != pots_stp->pt_cores_enabled ) {
      pots_log(PT_LOG_ERROR,
         "soft_reset_test(): saved unit enable reg = 0x%0x, after reset = 0x%0x\n",
      pots_stp->pt_cores_enabled, outval);
      pots_stp->pt_cores_enabled = outval;
   }

   if ( (rc = get_exec_units(pots_stp, &outval)) == -1 ) {
      pots_log(PT_LOG_INFO,
         "soft_reset_test(): get_exec_units() failed\n");
      return(-1);
   }

   /* save the mask for the exec units that exist */
   if ( outval != pots_stp->pt_cores_present ) {
      pots_log(PT_LOG_ERROR,
         "soft_reset_test(): cores present = 0x%0x, after reset = 0x%0x\n",
      pots_stp->pt_cores_present, outval);
      pots_stp->pt_cores_present = outval;
   }

   return(0);
   
}



/*
 * $Id: pots_soft_reset.c,v 1.7 2008/12/22 10:19:31 jrana Exp $
 * $Log: pots_soft_reset.c,v $
 * Revision 1.7  2008/12/22 10:19:31  jrana
 * - BIST disabled
 *
 * Revision 1.6  2008/12/17 07:11:00  ysandeep
 * Fixed bug
 *
 * Revision 1.5  2008/10/24 08:43:51  ysandeep
 * NPLUS support added
 *
 * Revision 1.4  2008/07/29 11:07:39  aramesh
 * Multicard support is added for SET SOFT RESET.
 *
 * Revision 1.3  2008/07/29 11:04:04  aramesh
 * SET_SOFT_RESET argument :dev_id is added.
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
 * Revision 1.1  2004/04/15 22:40:52  bimran
 * Checkin of the code from India with some cleanups.
 *
 */

