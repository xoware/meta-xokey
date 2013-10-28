/*
 * pots_bist:
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

extern int px_flag;

/*
 * check_bist_reg:
 */
int check_bist_reg(pots_sts *pots_stp, unsigned long *outp)
{
   
   int rc;
   unsigned long rval;
   rc = pots_get_pkp_reg_val(   pots_stp->pt_dd_fd,
                        pots_stp->pt_bar0, 
                        FAILING_EXEC_REG, 
                        &rval);
   if ( rc == -1 ) {
      pots_log(PT_LOG_ERROR, 
            "pots_get_pkp_reg_val(FAILING_EXEC_REG) failed\n");
      return(-1);
   }

   pots_log(PT_LOG_INFO, 
         "check_bist_reg(): BIST Reg Value = 0x%0x\n", rval);
   if ( rval & pots_stp->pt_cores_present ) {
      // some cores/exec units failed during bist.
      pots_log(PT_LOG_INFO, 
         "check_bist_reg(): some exec units failed during bist (rval=0x%lx,cores_present=0x%lx\n",
            rval, pots_stp->pt_cores_present);
      return(-1);
   }
   else
     rval=0;

   *outp = rval;

   return(0);

} // end check_bist_reg()


/*
 * check_unit_enable_reg:
 */
int check_unit_enable_reg(pots_sts *pots_stp, unsigned long *outp)
{
   
   int rc;
   unsigned long rval;
   int count;

   rc = pots_get_pkp_reg_val(   pots_stp->pt_dd_fd, 
                        pots_stp->pt_bar0, 
                        UNIT_ENABLE, 
                        &rval);
   if ( rc == -1 ) {
      pots_log(PT_LOG_ERROR, 
       "check_unit_enable_reg: pots_get_pkp_reg_val(UNIT_ENABLE) failed\n");
      return(-1);
   }

   pots_log(PT_LOG_INFO, 
         "check_unit_enable_reg(): UNIT_ENABLE Reg Value = 0x%0lx\n", 
         rval);

   /*
    * print out, how many cores/exec units are enabled 
    */
//#if  defined(NITROX_PX)
   if(px_flag==1)
      count = count_bits_set(rval, 8);
   else
//#else
   count = count_bits_set(rval, 28);
//#endif

   pots_log(PT_LOG_INFO, 
      "check_unit_enable_reg(): %d cores/exec units are enabled\n",
         count);
   
   *outp = rval;

   return(0);

} // end check_unit_enable_reg()


/*
 * check_interrupt_status_reg:
 */
int check_interrupt_status_reg(pots_sts *pots_stp, unsigned int *outp)
{
   
   int rc;
   unsigned int rval;
   int count;

   rc = pots_get_pkp_reg_val(   pots_stp->pt_dd_fd, 
                        pots_stp->pt_bar0, 
                        ISR_REG, 
                        &rval);
   if ( rc == -1 ) {
      pots_log(PT_LOG_ERROR, 
       "check_interrupt_status_reg: pots_get_pkp_reg_val(ISR) failed\n");
      return(-1);
   }

   pots_log(PT_LOG_INFO, 
         "check_interrupt_status_reg(): ISR Reg Value = 0x%0x\n", 
         rval);
   
   if ( rval != 0 ) {
      pots_log(PT_LOG_INFO, 
            "check_interrupt_status_reg(): ERROR: interrupt occured\n");
   }

   *outp = rval;

   return(0);

} // end check_interrupt_status_reg()


/*
 * get_exec_units:
 *       - Returns a bitmask of exec units that are available.
 */
int get_exec_units(pots_sts *pots_stp, unsigned long *outp)
{
   int rc;
   unsigned long wval;
   unsigned long rval;
   unsigned long exec_unit_mask;

   
   /* 
    * write 0x7cb to DEBUG_REG, then read it to get the
    * bits 22:12 that will represent cores/exec units 27-17
    */
   //wval = 0x3cb;
   wval = 0x7cb;
   rc = pots_write_pkp_reg(pots_stp->pt_dd_fd, 
                     pots_stp->pt_bar0, 
                     DEBUG_REG, 
                     wval);
   if (rc == -1 ) {
      pots_log(PT_LOG_ERROR, 
            "get_exec_units(): pots_get_pkp_reg_val() failed\n");
      return(-1);
   }
   

   /* read reg */
   rc = pots_get_pkp_reg_val(pots_stp->pt_dd_fd, 
                       pots_stp->pt_bar0, 
                       DEBUG_REG, 
                       &rval);
   if (rc == -1 ) {
      pots_log(PT_LOG_ERROR, 
            "get_exec_units(): pots_get_pkp_reg_val() failed\n");
      return(-1);
   }

   pots_log(PT_LOG_ERROR, 
      "get_exec_units(): rval = 0x%0x check bits 22:12 for cores 27-17\n", 
      rval);
   
   exec_unit_mask = rval >> 12;   
   pots_log(PT_LOG_ERROR, 
         "get_exec_units(): exec_unit_mask = 0x%0x\n", exec_unit_mask);

   /* 
    * write 0x7cc to DEBUG_REG, then read it to get the
    * bits 28:12 that will represent cores/exec units 16-0
    */
   //wval = 0x3cc;
   wval = 0x7cc;
   rc = pots_write_pkp_reg(pots_stp->pt_dd_fd, 
                     pots_stp->pt_bar0, 
                     DEBUG_REG, 
                     wval);
   if (rc == -1 ) {
      pots_log(PT_LOG_ERROR, 
            "get_exec_units(): pots_get_pkp_reg_val() failed\n");
      return(-1);
   }
   
   /* read reg */
   rc = pots_get_pkp_reg_val(pots_stp->pt_dd_fd, 
                       pots_stp->pt_bar0, 
                       DEBUG_REG, 
                       &rval);
   if (rc == -1 ) {
      pots_log(PT_LOG_ERROR, 
            "get_exec_units(): pots_get_pkp_reg_val() failed\n");
      return(-1);
   }

   pots_log(PT_LOG_ERROR, 
         "get_exec_units(): rval = 0x%0x check bits 28:12 for cores 16-0\n",
         rval);
   
   exec_unit_mask = (exec_unit_mask <<17) | (rval >> 12);

   pots_log(PT_LOG_ERROR, 
         "get_exec_units(): exec_unit_mask = 0x%0x\n", exec_unit_mask);
   *outp = exec_unit_mask;

   return(0);

} // end get_exec_unit()


int request_unit_operation(pots_sts *pots_stp, int action, unsigned int mask)
{
   int rc;
   Uint32 rval;

   rc = pots_get_pkp_reg_val(pots_stp->pt_dd_fd,
                       pots_stp->pt_bar0,
                       UNIT_ENABLE,
                       &rval);
   if ( rc == -1 ) {
      pots_log(PT_LOG_ERROR, 
            "request_unit_oper(): pots_get_pkp_reg_val() failed\n");
      return(-1);
   }

   switch (action) {

   case PT_DISABLE_RU:
      rval &= 0x0FFFFFFF;
      break;

   case PT_ENABLE_RU:
      rval |= 0x10000000;
      break;

   case PT_DISABLE_ALL_EU:
      rval &= 0x10000000;
      break;

   case PT_ENABLE_ALL_EU:
      /* this enables all the "present" exec units */
      //rval |= 0x0FFFFFFF;
      rval |= pots_stp->pt_cores_present;
      break;

   case PT_ENABLE_EU_FROM_MASK:
      rval |= mask;
      break;

   case PT_DISABLE_EU_FROM_MASK:
      rval &= ~mask;
      break;

   default:
      pots_log(PT_LOG_ERROR, 
            "request_unit_oper(): invalid action %d\n", action);
      return(-1);

   } // end switch

   rc = pots_write_pkp_reg(   pots_stp->pt_dd_fd,
                         pots_stp->pt_bar0,
                         UNIT_ENABLE,
                          rval);
   if ( rc == -1 ) {
      pots_log(PT_LOG_ERROR, 
            "request_unit_oper(): pots_write_pkp_reg() failed\n");
      return(-1);
   }

   // FOR NOW: check the value again!
   rc = pots_get_pkp_reg_val(pots_stp->pt_dd_fd,
                       pots_stp->pt_bar0,
                       UNIT_ENABLE,
                       &rval);
   if ( rc == -1 ) {
      pots_log(PT_LOG_ERROR, 
            "request_unit_oper(): pots_get_pkp_reg_val() failed\n");
      return(-1);
   }

   pots_log(PT_LOG_ERROR, 
         "request_unit_oper(): after oper; reg val = 0x%0x\n",
         rval);

   return(0);

} // end request_unit_oper()


/*
 * get_chip_csr:
 */
int get_chip_csr(pots_sts *pots_stp, unsigned long *outp)
{
   
   int rc;
   unsigned long rval;

   rc = pots_get_pkp_reg_val(   pots_stp->pt_dd_fd, 
                        pots_stp->pt_bar0, 
                        COMMAND_STATUS, 
                        &rval);
   if ( rc == -1 ) {
      pots_log(PT_LOG_ERROR, 
       "get_chip_csr: pots_get_pkp_reg_val(CSR) failed\n");
      return(-1);
   }

   pots_log(PT_LOG_INFO, 
         "get_chip_csr(): CSR Reg Value = 0x%0x\n", 
         rval);
   
   *outp = rval;

   return(0);

} // end get_chip_csr()


/*
 * get_pci_csr:
 */
int get_pci_csr(pots_sts *pots_stp, unsigned int *outp)
{
   
   int rc;
   unsigned int rval;
   DebugRWReg reg_st;


   reg_st.addr = 0x04;   // for pci cmd/status reg

   if ( (rc = ioctl(pots_stp->pt_dd_fd, IOCTL_PCI_DEBUG_READ_CODE, &reg_st)) == -1 ) {
      pots_log(PT_LOG_ERROR, 
            "get_pci_csr(): ioctl() failed %s <%d>\n",
            strerror(errno), errno);
      return(-1);
   }

   rval = reg_st.data;

   pots_log(PT_LOG_INFO, 
         "get_pci_csr(): pci csr from ioctl = 0x%0x\n", rval);

   *outp = rval;

   return(0);

} // end get_pci_csr()


/*
 * get_pci_config_reg:
 */
int get_pci_config_reg(pots_sts *pots_stp, unsigned int *outp)
{
   
   int rc;
   unsigned int rval;
   DebugRWReg reg_st;


   reg_st.addr = 0x00;   // for pci config reg

   if ( (rc = ioctl(pots_stp->pt_dd_fd, IOCTL_PCI_DEBUG_READ_CODE, &reg_st)) == -1 ) {
      pots_log(PT_LOG_ERROR, 
            "get_pci_config_reg(): ioctl() failed %s <%d>\n",
            strerror(errno), errno);
      return(-1);
   }

   rval = reg_st.data;

   pots_log(PT_LOG_INFO, 
         "get_pci_config_reg(): pci config from ioctl = 0x%0x\n", rval);

   *outp = rval;

   return(0);

} // end get_pci_config_reg()

/*
 * $Id: pots_bist.c,v 1.7 2009/07/24 11:14:22 aravikumar Exp $
 * $Log: pots_bist.c,v $
 * Revision 1.7  2009/07/24 11:14:22  aravikumar
 * removed px_flag check in get_exec_unit to get present running cores for Px also
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
 * Revision 1.2  2007/07/10 06:50:56  tghoriparti
 * 64bit changes done
 *
 * Revision 1.1  2007/02/20 23:43:29  panicker
 * * Utilities checked in
 *
 * Revision 1.4  2006/11/16 02:35:15  bimran
 * bist value should be checked if the failing exec-unit is within the core mask of the current device. I don't care about a failing exec-unit which is not used.
 *
 * Revision 1.3  2005/11/17 13:31:09  kanantha
 * Updating with the 64 bit modifications, with proper matching of data types
 *
 * Revision 1.2  2005/08/31 17:21:40  bimran
 * Fixed a lot of warnings.
 *
 * Revision 1.1  2004/04/15 22:40:51  bimran
 * Checkin of the code from India with some cleanups.
 *
 */

