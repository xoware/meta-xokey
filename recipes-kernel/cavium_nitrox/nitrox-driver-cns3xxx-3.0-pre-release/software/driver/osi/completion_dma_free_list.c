/* completion_dma_free_list.c */
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
 * 3. All manuals,brochures,user guides mentioning features or use of this software 
 *    must display the following acknowledgement:
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
#include "completion_dma_free_list.h"

int 
init_completion_dma_free_list(cavium_device *pkp_dev, Uint32 max)
{
   Uint32 i;
   Uint64 *p;
   cavium_dmaaddr comp_bus_addr = 0;
   cavium_completion_dma_stru *ptr_comp_dma = NULL;

   MPRINTFLOW();
   /*Allocate completion_dma_stru*/
   ptr_comp_dma = (cavium_completion_dma_stru *)cavium_malloc_dma(sizeof(cavium_completion_dma_stru),0);
   if(ptr_comp_dma == NULL)
   {
      cavium_error("init_completion_dma_free_list:failed to allocate elemen\n");
      return 1;
   }
   memset(ptr_comp_dma,0, sizeof(cavium_completion_dma_stru));
      
   /* initialize lock */
   cavium_spin_lock_init(&ptr_comp_dma->completion_dma_free_lock); 
   
   ptr_comp_dma->completion_dma_free_max = max;
   ptr_comp_dma->completion_dma_free_list = (ptrlong *)cavium_malloc_virt(ptr_comp_dma->completion_dma_free_max * sizeof(ptrlong));
   
   if (ptr_comp_dma->completion_dma_free_list == NULL) 
   {
      cavium_print(("Not enough memory in allocating completion_dma_free_list\n"));
      cavium_free_dma(ptr_comp_dma);
      return 1;
   }
   
   /* allocate one contiguous block and divid 'em into pieces ;-)*/
   ptr_comp_dma->completion_dma_buffer_size = ptr_comp_dma->completion_dma_free_max * COMPLETION_CODE_SIZE;
   p = (Uint64 *)cavium_malloc_nc_dma(pkp_dev,
            ptr_comp_dma->completion_dma_buffer_size,
                                &comp_bus_addr);
   ptr_comp_dma->completion_dma_bus_addr = (ptrlong)comp_bus_addr;
   ptr_comp_dma->completion_dma_buffer = (Uint64 *)p;

   if(p == NULL) 
   {
      cavium_print(("Not enough memory in allocating completion_dma\n"));
      cavium_free_virt(ptr_comp_dma->completion_dma_free_list);
      cavium_free_dma(ptr_comp_dma);
      return 1;
   }

   /* build the free list */
   for(i = 0; i < ptr_comp_dma->completion_dma_free_max; i++,p++) 
   {
      ptr_comp_dma->completion_dma_free_list[i] = (ptrlong)(p);
   }
    
   /* initialize lock */
   /* cavium_spin_lock_init(&completion_dma_free_lock); */

   ptr_comp_dma->completion_dma_count = ptr_comp_dma->completion_dma_free_max;

   ptr_comp_dma->completion_dma_free_index=0;

   pkp_dev->ptr_comp_dma = ptr_comp_dma;
   return 0;
}


/*
 * Get next avilable entry
 */

Uint64 *
get_completion_dma(cavium_device *pkp_dev,int *test)
{
   Uint64 *p;
   cavium_completion_dma_stru *ptr_comp_dma = pkp_dev->ptr_comp_dma;

   MPRINTFLOW();
    /* acquire lock */
   cavium_spin_lock_softirqsave(&ptr_comp_dma->completion_dma_free_lock);

   if(ptr_comp_dma->completion_dma_count == 0)
   {
      *test = -1;
      p = NULL;
      goto cleanup;
    }
    else
      *test=0;

   p = (Uint64 *)ptr_comp_dma->completion_dma_free_list[ptr_comp_dma->completion_dma_free_index];
   ptr_comp_dma->completion_dma_free_index++;
   ptr_comp_dma->completion_dma_count--;
 
cleanup:
   /* release lock*/
   cavium_spin_unlock_softirqrestore(&ptr_comp_dma->completion_dma_free_lock);
   return p;
}

/*
 * Returns bus address
 */
ptrlong 
get_completion_dma_bus_addr(cavium_device *pkp_dev,volatile Uint64 *p)
{
   cavium_completion_dma_stru *ptr_comp_dma = pkp_dev->ptr_comp_dma;
   return (ptr_comp_dma->completion_dma_bus_addr +((ptrlong)p - (ptrlong)ptr_comp_dma->completion_dma_buffer));
}/*get_completion_dma_bus_addr*/

/*
 * Put entry back in the free list.
 */
int 
put_completion_dma(cavium_device *pkp_dev,volatile Uint64 *p)
{
   
   int ret=0;
   cavium_completion_dma_stru *ptr_comp_dma = pkp_dev->ptr_comp_dma;
 
   MPRINTFLOW();
   cavium_spin_lock_softirqsave(&ptr_comp_dma->completion_dma_free_lock);

   ptr_comp_dma->completion_dma_free_index--;
   ptr_comp_dma->completion_dma_count++;
   ptr_comp_dma->completion_dma_free_list[ptr_comp_dma->completion_dma_free_index] = (ptrlong)p;
   ret=0;

   /* release lock*/
   cavium_spin_unlock_softirqrestore(&ptr_comp_dma->completion_dma_free_lock);   
   return ret;

}

/*
 * Cleanup things
 */
int 
cleanup_completion_dma_free_list(cavium_device *pkp_dev)
{
   cavium_completion_dma_stru *ptr_comp_dma = pkp_dev->ptr_comp_dma;

   MPRINTFLOW();
   cavium_spin_lock_destroy(&ptr_comp_dma->completion_dma_free_lock);
   if(ptr_comp_dma->completion_dma_free_list) 
   {
      if(ptr_comp_dma->completion_dma_buffer)
      {
         cavium_free_nc_dma(pkp_dev,ptr_comp_dma->completion_dma_buffer_size,
                              (void *)ptr_comp_dma->completion_dma_buffer,
                              (cavium_dmaaddr)ptr_comp_dma->completion_dma_bus_addr);
         ptr_comp_dma->completion_dma_buffer=NULL;
      }

      cavium_free_virt(ptr_comp_dma->completion_dma_free_list);
      ptr_comp_dma->completion_dma_free_list = NULL;
      ptr_comp_dma->completion_dma_free_index=0;
      pkp_dev->ptr_comp_dma = NULL;
   }
   cavium_free_dma(ptr_comp_dma);

   return 0;
}/*cleanup_completion_dma_free_list*/


/*
 * $Id: completion_dma_free_list.c,v 1.8 2008/09/30 13:15:17 jsrikanth Exp $
 * $Log: completion_dma_free_list.c,v $
 * Revision 1.8  2008/09/30 13:15:17  jsrikanth
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
 * Revision 1.7  2008/02/14 06:38:33  rkumar
 * The list management was improper with respect to sizes, it is corrected.
 *
 * Revision 1.6  2007/10/22 08:36:46  aramesh
 * completion dma buffer type is changed from Uint64 to ptrlong to be compatable with 32bit machine. unnecessary increment of pointer is removed.
 *
 * Revision 1.5  2007/10/18 09:35:09  lpathy
 * Added windows support.
 *
 * Revision 1.4  2007/07/31 10:11:08  tghoriparti
 * N1 related changes done
 *
 * Revision 1.3  2007/07/03 11:43:35  kchunduri
 * maintain completion_dma_free_list per device. Done as part of MultiCard support.
 *
 * Revision 1.2  2007/06/18 06:32:30  tghoriparti
 * type casting of static volatile variable avoided
 *
 * Revision 1.1  2007/01/06 02:47:40  panicker
 * * first cut - NITROX PX driver
 *
 * Revision 1.20  2006/08/16 10:37:01  kchunduri
 * --fix compilation warning on Linux
 *
 * Revision 1.19  2006/08/16 04:42:04  kchunduri
 * --fix for compilation warning on FreeBSD-4.11
 *
 * Revision 1.18  2006/05/17 04:23:09  kchunduri
 * --removed debug statements
 *
 * Revision 1.17  2006/05/16 09:34:26  kchunduri
 * --support for Dynamic DMA mapping instead of virt_to_phys
 *
 * Revision 1.16  2006/03/24 09:47:07  pyelgar
 *   - Checkin of Scatter/Gather code changes in driver and IPSec.
 *
 * Revision 1.15  2006/02/14 10:22:38  sgadam
 * - Warning Fixed for RHEL4
 *
 * Revision 1.14  2006/01/31 13:59:50  pyelgar
 *    - Fixed compilation warning.
 *
 * Revision 1.13  2005/12/07 04:50:59  kanantha
 * modified to support both 32 and 64 bit versions
 *
 * Revision 1.12  2005/10/13 09:21:15  ksnaren
 * changed cavium_malloc_dma to cavium_malloc_virt for the control structs
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
 * Revision 1.7  2005/05/20 14:34:05  rkumar
 * Merging CVS head from india
 *
 * Revision 1.6  2005/02/01 04:11:07  bimran
 * copyright fix
 *
 * Revision 1.5  2004/06/23 19:52:23  bimran
 * included header file.
 *
 * Revision 1.4  2004/06/03 21:22:56  bimran
 * included cavium_list.h
 * fixed list* calls to use cavium_list
 *
 * Revision 1.3  2004/05/02 19:44:29  bimran
 * Added Copyright notice.
 *
 * Revision 1.2  2004/04/30 00:00:33  bimran
 * Removed semaphoers from context memory in favour of just counts and a lock.
 *
 * Revision 1.1  2004/04/15 22:40:48  bimran
 * Checkin of the code from India with some cleanups.
 *
 */





