/*! file  n1test_common.c*/

/* This file holds routines that are common to all the utilities. */
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
 * EITHER EXPRESS,IMPLIED, STATUTORY,OR OTHERWISE, WITH RESPECT TO THE SOFTWARE, * INCLUDING ITS CONDITION,ITS CONFORMITY TO ANY REPRESENTATION OR DESCRIPTION,
 * OR THE EXISTENCE OF ANY LATENT OR PATENT DEFECTS, AND CAVIUM SPECIFICALLY
 * DISCLAIMS ALL IMPLIED (IF ANY) WARRANTIES OF TITLE, MERCHANTABILITY,
 * NONINFRINGEMENT, FITNESS FOR A PARTICULAR PURPOSE,LACK OF VIRUSES,ACCURACY OR * COMPLETENESS, QUIET ENJOYMENT, QUIET POSSESSION OR CORRESPONDENCE TO
 * DESCRIPTION. THE ENTIRE RISK ARISING OUT OF USE OR PERFORMANCE OF THE
 * SOFTWARE LIES WITH YOU.
 *
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "cavium_sysdep.h"
#include "cavium_common.h"
#include "cavium_ioctl.h"

#ifdef CAVIUM_MULTICARD_API
extern int gpkpdev_hdlr[];
#else
extern int CSP1_driver_handle;
#endif

#ifdef CAVIUM_MULTICARD_API 
int OpenNitroxDevice(int dma_mode,int dev_id)
#else
int OpenNitroxDevice(int dma_mode)
#endif
{
   int retval=0;
   Csp1CoreAssignment core_assign;
   int microcode_type=0;
   Uint32 device;
#ifdef CAVIUM_MULTICARD_API
   if(Csp1Initialize(CAVIUM_DIRECT,CAVIUM_DEV_ID))
#else
   if(Csp1Initialize(CAVIUM_DIRECT))
#endif
      return -1;
   if(Csp1GetDevType(&device))
      return -1;
   if(device == NPX_DEVICE)
      microcode_type = UCODE_IDX;
   else
   {
#ifdef CAVIUM_MULTICARD_API
      if(ioctl(gpkpdev_hdlr[CAVIUM_DEV_ID], IOCTL_CSP1_GET_CORE_ASSIGNMENT, (Uint32 *)&core_assign)!= 0)
#else
      if(ioctl(CSP1_driver_handle, IOCTL_CSP1_GET_CORE_ASSIGNMENT, (Uint32 *)&core_assign)!= 0)
#endif
         return -1;
      else
         microcode_type = core_assign.mc_present[UCODE_IDX]; 
   }
#ifdef CAVIUM_MULTICARD_API
   Csp1Shutdown(dev_id);
#else
   Csp1Shutdown();
#endif


#ifdef CAVIUM_MULTICARD_API
        retval = Csp1Initialize(dma_mode, dev_id);
#else /* Assuming SSL_SPM here */
        retval = Csp1Initialize(dma_mode);
#endif

   return retval;
}

