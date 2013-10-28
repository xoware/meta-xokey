/*
 * pots_utils.c:
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
#include <errno.h>

#include "pots.h"

#include "cavium_sysdep.h"
#include "cavium_common.h"
#include "cavium_ioctl.h"

#include "pots_dd.h"

/*
 * count_set_bits:
 *       - Returns the number of bits set with val 
 *         (out of check_bits)
 */
int count_bits_set(unsigned long val, int check_bits)
{
   int i;
   int count = 0;

   for (i = 0; i < check_bits; i++) {
      if ( val & (0x00000001 << i) )
         count++;
   }

   return(count);

} // end count_bits_set()



/*
 * check_and_save_ue_cp:
 *       - Checks bit reg, unit enabled reg and core present.
 *         Saves values in: pt_cores_enabled and pt_cores_present.
 */
int check_and_save_ue_cp(pots_sts *pots_stp)
{
   char *fname = "check_and_save_ue_cp()";
   int rc;
   unsigned long outval;


   if ( (rc = check_unit_enable_reg(pots_stp, &outval)) == -1 ) {
      pots_log(PT_LOG_INFO,
         "%s: check_unit_enable_reg() failed\n", fname);
      return(-1);
   }

   /* save the unit enable reg value */
   if ( outval != pots_stp->pt_cores_enabled ) {
      pots_log(PT_LOG_ERROR,
         "%s: saved unit enable reg = 0x%0x, after reset = 0x%0x\n",
         fname, pots_stp->pt_cores_enabled, outval);
      pots_stp->pt_cores_enabled = outval;
   }

   if ( (rc = get_exec_units(pots_stp, &outval)) == -1 ) {
      pots_log(PT_LOG_INFO,
         "%s: get_exec_units() failed\n", fname);
      return(-1);
   }

   /* save the mask for the exec units that exist */
   //if ( outval != pots_stp->pt_cores_present ) {
   if ( pots_stp->pt_cores_present == 0 ) {
      pots_log(PT_LOG_ERROR,
         "%s(): cores present = 0x%0x, after reset = 0x%0x\n",
         fname, pots_stp->pt_cores_present, outval);
      pots_stp->pt_cores_present = outval;
   }

   /*
    * now check bist reg, unit enable reg and # of exec units
    * and save these values.
    */
#if defined(SSL)
   if ( (rc = check_bist_reg(pots_stp, &outval)) == -1 ) {
      pots_log(PT_LOG_INFO,
         "%s(): check_bist_reg() failed\n", fname);
      return(-1);
   }
#endif
   /* save the bist reg value */
   if ( outval != pots_stp->pt_bist_regval ) {
      pots_log(PT_LOG_ERROR, 
         "%s: saved bist reg = 0x%0x, after reset = 0x%0x\n",
         fname, pots_stp->pt_bist_regval, outval);
      pots_stp->pt_bist_regval = outval;
   }

   pots_log(PT_LOG_ERROR,
      "%s(): cores present = 0x%0x, cores enabled = 0x%0x\n",
      fname, pots_stp->pt_cores_present, pots_stp->pt_cores_enabled);

   return(0);

} // end check_and_save_ue_cp()



char *get_hex_data(Uint8 *str, Uint8 sep, Uint8 *data, Uint32 *length)
{

   Uint8 *buf, *buf1;
   Uint32 i;

   if ( (buf = (Uint8 *)strchr((char *)str, sep)) == NULL ) {
      pots_log(PT_LOG_ERROR,
         "get_hex_data(): error, did not find %c in str %s\n", 
         sep, str);
      return(NULL);
   }

   buf++;   // skip past the '='

   i = 0;
   while(*buf) {

      while(*buf == ' ')
         buf++;

      if(*buf == '\0')
         break;

      if(*buf >= '0' && *buf<= '9' )
         data[i] = ((*buf) - '0') << 4;
      else if  (*buf >= 'a' && *buf<= 'f')
         data[i] = ((*buf) - 'a' + 10) << 4;
      else if  (*buf >= 'A' && *buf<= 'F')
         data[i] = ((*buf) - 'A' + 10) << 4;
      buf++;

      if(*buf >= '0' && *buf <= '9' )
         data[i] = data[i] | ((*buf) - '0');
      else if (*buf >= 'a' && *buf<= 'f')
         data[i] = data[i] | ((*buf) - 'a' + 10);
      else if (*buf >= 'A' && *buf<= 'F')
         data[i] = data[i] | ((*buf) - 'A' + 10);
      buf++;
      i++;

   } // end while 

   if ( i == 0 ) {
      pots_log(PT_LOG_ERROR,
         "get_hex_data(): error, did not get any hex data in str %s\n",
         str);
      return(NULL);
   }

   *length = i;

   return (char *)buf1;

}


void print_hex(char *label, Uint8 *datap, int len)
{
   int i;

   if ( label != NULL )
      pots_log(PT_LOG_INFO, "%s\n", label);
   for (i = 0; i < len; i++) {
      pots_log0(PT_LOG_INFO, "0x%0x ", datap[i]);
   }
   pots_log0(PT_LOG_INFO, "\n");

}


void print_hex2(FILE *rfp, char *label, Uint8 *datap, int len)
{
   int i;

   if ( label != NULL )
      fprintf(rfp, label);

   for (i = 0; i < len; i++) {
      fprintf(rfp, "%02x", datap[i]);
   }
   fprintf(rfp, "\n");

}

/*
 * $Id: pots_utils.c,v 1.5 2008/12/17 07:12:43 ysandeep Exp $
 * $Log: pots_utils.c,v $
 * Revision 1.5  2008/12/17 07:12:43  ysandeep
 * fixed bug for IPSEC as MLM
 *
 * Revision 1.4  2008/11/26 05:48:47  ysandeep
 * Fixed Bugs
 *
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
 * Revision 1.2  2005/05/21 05:17:31  rkumar
 * Merge with India CVS Head
 *
 * Revision 1.1  2004/04/15 22:40:52  bimran
 * Checkin of the code from India with some cleanups.
 *
 */

