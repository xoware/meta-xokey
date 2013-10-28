/*
 * pots_reg_utils.c:
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
#include <errno.h>
#ifdef linux
#include "linux/types.h"
#include "linux/pci.h"
#endif

#include "cavium_sysdep.h"
#include "cavium_common.h"
#include "cavium_ioctl.h"

#include "pots.h"
#include "pots_proto.h"

extern int px_flag;

/* For Nitrox-PX, the Nitrox driver ioctl has been modified to return BAR4
 * io-remapped address at offset 0x0 when this routine is called with bar0
 * and to return BAR4 io-remapped at offset 0x100 when called with bar1.
 * This allows the pots utility to work for Nitrox PX without major
 * modifications for the changed BAR's. 
 */ 
int pots_get_bar_value(int dd_fd, char *bar_name, unsigned long *outp)
{

   int rc;
   unsigned long bar;
   DebugRWReg reg_st;


   if ( strcmp(bar_name, "bar0") == 0 )
      reg_st.addr = 0x10;   // for bar 0 
   else if ( strcmp(bar_name, "bar2") == 0 )
      reg_st.addr = 0x18;   // for bar 2 
   else {
      pots_log(PT_LOG_WARNING, 
            "pots_get_bar_value(): invalid bar_name %s passed\n",
            bar_name);
      return(-1);
   }

   if ( (rc = ioctl(dd_fd, IOCTL_PCI_DEBUG_READ_CODE, &reg_st)) == -1 ) {
      pots_log(PT_LOG_ERROR, 
            "pots_get_bar_value(): ioctl() failed %s <%d>\n",
            strerror(errno), errno);
      return(-1);
   }

   bar = reg_st.data;

//#if !defined(NITROX_PX)
if(px_flag!=1){   
   bar = bar - 1 ;

   pots_log(PT_LOG_INFO, 
         "pots_get_bar_value(): bar from ioctl = 0x%0x\n", bar);

   /* now check for i/o or mem mask */
#ifdef LINUX
   if ( bar & PCI_BASE_ADDRESS_SPACE_IO )
      // i/o space
      bar &= PCI_BASE_ADDRESS_IO_MASK;
   else
      bar &= PCI_BASE_ADDRESS_MEM_MASK;
#endif
   
   pots_log(PT_LOG_INFO,
         "pots_get_bar_value(): after applying mask, bar = 0x%0x\n", 
         bar);

}   
//#endif

   *outp = bar;

   return(0);

} // end pots_get_bar_value()




int pots_get_pkp_reg_val( int dd_fd, 
            unsigned long bar_val, 
            unsigned int  addr_offset, 
            unsigned long *outp)
{

   int rc;
   DebugRWReg reg_st;
   unsigned long val;

    if (px_flag != 1) {
      if (reg_r_w_flg)
    reg_st.addr = (bar_val + addr_offset) & (0xffffff00);
    }
    reg_st.addr = bar_val + addr_offset;

   if ( (rc = ioctl(dd_fd, IOCTL_N1_DEBUG_READ_CODE, &reg_st)) == -1 ) {
      pots_log(PT_LOG_ERROR, 
            "pots_get_pkp_rqg_val(): ioctl() failed %s <%d>\n",
            strerror(errno), errno);
      return(-1);
   }

   val = reg_st.data;
   pots_log(PT_LOG_ERROR, 
         "pots_get_pkp_reg_val(): reg at 0x%0lx has val = 0x%0lx\n", 
         addr_offset, val);
   
   *outp = val;

   return(0);

} // end pots_get_pkp_reg_val()


int pots_write_pkp_reg(
         int dd_fd, 
         unsigned long bar_val, 
         unsigned int  addr_offset, 
         unsigned long val)
{

   int rc;
   DebugRWReg reg_st;

   if (px_flag != 1) {
     if (reg_r_w_flg)
    reg_st.addr = (bar_val + addr_offset) & (0xffffff00);
   }
   reg_st.addr = bar_val + addr_offset;

   reg_st.data = val;

   if ( (rc = ioctl(dd_fd, IOCTL_N1_DEBUG_WRITE_CODE, &reg_st)) == -1 ) {
      pots_log(PT_LOG_ERROR, "pots_write_pkp_reg(): ioctl() failed %s <%d>\n",
            strerror(errno), errno);
      return(-1);
   }

   return(0);

} // end pots_write_pkp_reg()


#if 1
/*
 * Generate random data, len bytes long.
 */
Uint8 *getrandom (Uint8 *buf, int len)
{
   Uint16 tmp = 0;
   int i;
   Uint16 a;

   for (i = 0; i < len; i++) {

      if (i % sizeof tmp == 0)
         tmp = rand();

      buf[i] = tmp & 0xff;
      buf[++i] = tmp >> 8;
   }

   return buf;

} // end getrandom()
#endif

#if 0
/*
 * Generate random data, len bytes long.
 */
Uint8 *getrandom (Uint8 *buf, int len)
{
   int rc;

   rc = RAND_bytes(buf, len);
   if ( rc != 1 ) {
      // error
      return(NULL);
   }

   // worked
   return buf;

} // end getrandom()
#endif

/*
 * $Id: pots_reg_utils.c,v 1.9 2009/09/22 09:57:08 aravikumar Exp $
 * $Log: pots_reg_utils.c,v $
 * Revision 1.9  2009/09/22 09:57:08  aravikumar
 * made list of test options to constant for both plus and non-nplus
 *
 * Revision 1.8  2008/12/18 15:16:54  jsrikanth
 * pci BAR addr related changes and device count ioctl changes
 *
 * Revision 1.7  2008/12/16 12:04:42  jsrikanth
 * Added Common driver and Multi-Card Changes for FreeBSD
 *
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
 * Revision 1.2  2007/07/06 13:07:19  tghoriparti
 * PX changes done
 *
 * Revision 1.1  2007/02/20 23:43:29  panicker
 * * Utilities checked in
 *
 * Revision 1.7  2005/11/28 05:46:21  kanantha
 * Modified the getrandom function argument back to int
 *
 * Revision 1.6  2005/11/21 06:03:48  kanantha
 * Modified the getrandom function
 *
 * Revision 1.4  2005/08/31 17:21:40  bimran
 * Fixed a lot of warnings.
 *
 * Revision 1.3  2005/05/21 05:17:31  rkumar
 * Merge with India CVS Head
 *
 * Revision 1.2  2004/06/28 21:27:15  tahuja
 * OSI Makefiles.
 *
 * Revision 1.1  2004/04/15 22:40:52  bimran
 * Checkin of the code from India with some cleanups.
 *
 */
