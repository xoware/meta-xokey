/* command_que.c */
/*
 * Copyright (c) 2003-2005 Cavium Networks (support@cavium.com). All rights 
 * reserved.
 * 
 * Redistribution and use in source and binary forms, with or without 
 * modification, are permitted provided that the following conditions are met:
 * 
 * 1. Redistributions of source code must retain the above copyright notice, 
 * this list of conditions and the following disclaimer.
 * 
 * 2. Redistributions in binary form must reproduce the above copyright notice, 
 *    this list of conditions and the following disclaimer in the documentation 
 *    and/or other materials provided with the distribution.
 * 
 * 3. All manuals,brochures,user guides mentioning features or use of this
 *    software must display the following acknowledgement:
 * 
 *   This product includes software developed by Cavium Networks
 * 
 * 4. Cavium Networks' name may not be used to endorse or promote products 
 *    derived from this software without specific prior written permission.
 * 
 * 5. User agrees to enable and utilize only the features and performance 
 *    purchased on the target hardware.
 * 
 * This Software,including technical data,may be subject to U.S. export control 
 * laws, including the U.S. Export Administration Act and its associated 
 * regulations, and may be subject to export or import regulations in other 
 * countries.You warrant that You will comply strictly in all respects with all 
 * such regulations and acknowledge that you have the responsibility to obtain 
 * licenses to export, re-export or import the Software.

 * TO THE MAXIMUM EXTENT PERMITTED BY LAW, THE SOFTWARE IS PROVIDED "AS IS" AND 
 * WITH ALL FAULTS AND CAVIUM MAKES NO PROMISES, REPRESENTATIONS OR WARRANTIES, 
 * EITHER EXPRESS,IMPLIED,STATUTORY, OR OTHERWISE, WITH RESPECT TO THE SOFTWARE,
 * INCLUDING ITS CONDITION,ITS CONFORMITY TO ANY REPRESENTATION OR DESCRIPTION, 
 * OR THE EXISTENCE OF ANY LATENT OR PATENT DEFECTS, AND CAVIUM SPECIFICALLY 
 * DISCLAIMS ALL IMPLIED (IF ANY) WARRANTIES OF TITLE, MERCHANTABILITY, 
 * NONINFRINGEMENT,FITNESS FOR A PARTICULAR PURPOSE,LACK OF VIRUSES, ACCURACY OR
 * COMPLETENESS, QUIET ENJOYMENT, QUIET POSSESSION OR CORRESPONDENCE TO 
 * DESCRIPTION. THE ENTIRE RISK ARISING OUT OF USE OR PERFORMANCE OF THE 
 * SOFTWARE LIES WITH YOU.
 *
 */
#include "cavium_sysdep.h"
#include "cavium_common.h"
#include "cavium_list.h"
#include "cavium.h"
#include "command_que.h"

/*
 * Allocate memory for command queue and check bus address 
 * to be multiple of 32 bytes
 */
int 
init_command_queue(cavium_device *pkp_dev, Uint32 q_no)
{
   Uint32            q_size;
   ptrlong           q_baseaddr;
   cavium_dmaaddr    q_busaddr = 0;

   MPRINTFLOW();

   /* size in bytes */

   q_size = (pkp_dev->command_queue_max + 1) * COMMAND_BLOCK_SIZE;
   pkp_dev->command_queue_size = q_size; 

   q_baseaddr = (ptrlong)cavium_malloc_nc_dma(pkp_dev, q_size, &q_busaddr);

   if(!q_baseaddr) {
      cavium_print("Not enough memory to intialize command que\n");
      return 1;
     }

   /* Store the real addresses here. This will be used to free this space.*/
   pkp_dev->real_command_queue_base[q_no]     = (Uint8 *)q_baseaddr;
   pkp_dev->real_command_queue_bus_addr[q_no] = q_busaddr;


   /* We need a 32-byte aligned address. */
   if(q_baseaddr & 0x1f) {
      q_baseaddr = (q_baseaddr + 32) & ~(0x1fUL);
      q_busaddr  = (q_busaddr + 32) & ~(0x1fUL);
   }

     
   /* Use the adjusted base & bus address for the driver's activities.*/
   pkp_dev->command_queue_front[q_no]    = (Uint8 *)q_baseaddr;
   pkp_dev->command_queue_base[q_no]     = (Uint8 *)q_baseaddr; 
   pkp_dev->command_queue_bus_addr[q_no] = q_busaddr; 

   pkp_dev->command_queue_end[q_no] =
         (Uint8 *)(q_baseaddr + (q_size - COMMAND_BLOCK_SIZE));
   
   /* cavium_spin_lock_init(&(pkp_dev->command_queue_lock[q_no])); */

   pkp_dev->door_bell_count[q_no]     = 0;
   pkp_dev->door_bell_threshold[q_no] = 1;
    
   return 0;
}


/*
 * cleanup command queue. Free memory.
 */
int 
cleanup_command_queue(cavium_device * pkp_dev, int q_no)
{

   if(pkp_dev->real_command_queue_base[q_no] != NULL) {
      cavium_free_nc_dma(pkp_dev,
               pkp_dev->command_queue_size,
               pkp_dev->real_command_queue_base[q_no],
               (cavium_dmaaddr)pkp_dev->real_command_queue_bus_addr[q_no]);
   pkp_dev->real_command_queue_bus_addr[q_no] = 0;
   pkp_dev->command_queue_bus_addr[q_no] = 0;
   pkp_dev->command_queue_base[q_no]=NULL;
   pkp_dev->command_queue_front[q_no]=NULL;
   pkp_dev->command_queue_end[q_no]=NULL;
   pkp_dev->door_bell_count[q_no]=0;
   pkp_dev->door_bell_threshold[q_no]=1;
}
 
   return 0;
}

/*
 * Increment write pointer and handle wrap-around case.
 */
void   
inc_front_command_queue(cavium_device * pkp_dev, int q_no)
{
   
   MPRINTFLOW();
   pkp_dev->command_queue_front[q_no] = 
      (Uint8*)((ptrlong)pkp_dev->command_queue_front[q_no] + 
          COMMAND_BLOCK_SIZE);

   if (pkp_dev->command_queue_front[q_no] == 
         pkp_dev->command_queue_end[q_no]) {
      pkp_dev->command_queue_front[q_no] = 
         pkp_dev->command_queue_base[q_no];
   }
   return;
}


void 
reset_command_queue(cavium_device * pkp_dev, int q_no)
{
   MPRINTFLOW();
   pkp_dev->command_queue_front[q_no] = 
   pkp_dev->command_queue_base[q_no];
   
   pkp_dev->door_bell_count[q_no]=0;
   pkp_dev->door_bell_threshold[q_no]=1;
}


/*
 * $Id: command_que.c,v 1.5 2008/09/30 13:15:17 jsrikanth Exp $
 * $Log: command_que.c,v $
 * Revision 1.5  2008/09/30 13:15:17  jsrikanth
 * PX-4X [Multicard] support for IPsec :
 *      -  Round-robin scheduling for selecting a device
 *         implemented within IPSec APIs.
 *      -  All Lists [Pending/Direct/SG/CompletionDMA]
 *         moved to device structure.
 *      -  A single buffer pool manager for all devices.
 *         Interrupt handler now checks for PCI Error register as well.
 *         Proc Entry bug fixes when dumping more than a single page.
 *         DUMP_FAILING_REQUESTS pre-processor define added to dump
 *         out all failing requests.
 * Minor modifications of removing all tabs to spaces.
 *
 * Revision 1.4  2007/11/19 11:11:55  lpathy
 * ported to 64 bit windows.
 *
 * Revision 1.3  2007/05/01 06:39:57  kchunduri
 * * fix compiler warnings.
 *
 * Revision 1.2  2007/02/02 02:27:25  panicker
 * * init_command_queue() - rewritten for readability.
 *
 * Revision 1.1  2007/01/06 02:47:40  panicker
 * * first cut - NITROX PX driver
 *
 * Revision 1.12  2006/05/16 09:31:54  kchunduri
 * --support for Dynamic DMA mapping instead of virt_to_phys
 *
 * Revision 1.11  2005/09/28 15:50:26  ksadasivuni
 * - Merging FreeBSD 6.0 AMD64 Release with CVS Head
 * - Now context pointer given to user space applications is physical pointer.
 *   So there is no need to do cavium_vtophys() of context pointer.
 *
 * Revision 1.10  2005/09/06 14:38:57  ksadasivuni
 * - Some cleanup error fixing and spin_lock_destroy functionality added to osi.
 *   spin_lock_destroy was necessary because of FreeBSD 6.0.
 *
 * Revision 1.9  2005/09/06 07:08:22  ksadasivuni
 * - Merging FreeBSD 4.11 Release with CVS Head
 *
 * Revision 1.8  2005/06/13 06:35:42  rkumar
 * Changed copyright
 *
 * Revision 1.7  2005/02/01 04:11:07  bimran
 * copyright fix
 *
 * Revision 1.6  2004/06/23 19:48:33  bimran
 * Fixed command queue 32-byte alignment.
 *
 * Revision 1.4  2004/05/02 19:44:29  bimran
 * Added Copyright notice.
 *
 * Revision 1.3  2004/04/30 01:37:13  tsingh
 * chnaged inc_front_* function to inline
 *
 * Revision 1.2  2004/04/16 03:19:49  bimran
 * Added doorbell coalescing support.
 *
 * Revision 1.1  2004/04/15 22:40:48  bimran
 * Checkin of the code from India with some cleanups.
 *
 */

