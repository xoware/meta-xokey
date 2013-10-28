/* direct_free_list.c */
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
#include "direct_free_list.h"

Uint32 get_direct_free_index(cavium_device *);

int 
init_direct_free_list(cavium_device *n1_dev, Uint32 max)
{
   Uint32 i;

   MPRINTFLOW();
   cavium_spin_lock_init(&(n1_dev->direct_free_lock)); 
   if(n1_dev->direct_free_list)
   {
      cavium_print(("DIRECT free list already exists\n"));
      return 1;
   }
   n1_dev->direct_free_max = max + CAVIUM_SPECIAL_QUEUE_SIZE;
   n1_dev->direct_free_list = (ptrlong *)cavium_malloc_virt(n1_dev->direct_free_max*sizeof(ptrlong));
  
   if(n1_dev->direct_free_list == NULL)
   {
      cavium_print(("Not enough memory in allocating direct_free_list\n"));
      return 1;
   }

   n1_dev->direct_entry_array = (struct PKP_DIRECT_OPERATION_STRUCT *)
   cavium_malloc_virt(n1_dev->direct_free_max*sizeof(struct PKP_DIRECT_OPERATION_STRUCT));

   if(n1_dev->direct_entry_array == NULL)
   {
      cavium_print(("Not enough memory in allocating direct_entry_array.\n"));
      cavium_free_virt(n1_dev->direct_free_list);
       n1_dev->direct_free_list = NULL;
      return 1;
   }

   for(i=0; i<n1_dev->direct_free_max; i++)
   {
      n1_dev->direct_free_list[i] = (ptrlong)&(n1_dev->direct_entry_array[i]);
    }    
   /* cavium_spin_lock_init(&(n1_dev->direct_free_lock)); */
   n1_dev->direct_free_index=0;
   return 0;
}


struct PKP_DIRECT_OPERATION_STRUCT * 
get_direct_entry(cavium_device *n1_dev)
{
   struct PKP_DIRECT_OPERATION_STRUCT *p = NULL;
   MPRINTFLOW();
   /* acquire lock */
   cavium_spin_lock_softirqsave(&(n1_dev->direct_free_lock));

   if(n1_dev->direct_free_index >= n1_dev->direct_free_max)
   {
      p = NULL;
     goto cleanup;
   }

   p = (struct PKP_DIRECT_OPERATION_STRUCT *)(n1_dev->direct_free_list[n1_dev->direct_free_index]);
   n1_dev->direct_free_index++;

cleanup: 
   /* release lock*/
   cavium_spin_unlock_softirqrestore(&(n1_dev->direct_free_lock));
   return p;
}


extern cavium_device cavium_dev[];
int
put_direct_entry(cavium_device *n1_dev, struct PKP_DIRECT_OPERATION_STRUCT *p)
{
   
   int ret=0;
   MPRINTFLOW();

   cavium_spin_lock_softirqsave(&(n1_dev->direct_free_lock));
   n1_dev->direct_free_index--;
   n1_dev->direct_free_list[n1_dev->direct_free_index] = (ptrlong)p;
   ret=0;
   
   /* release lock*/
   cavium_spin_unlock_softirqrestore(&(n1_dev->direct_free_lock));   
   return ret;

}


int 
cleanup_direct_free_list(cavium_device *n1_dev)
{
   MPRINTFLOW();
   cavium_spin_lock_destroy(&(n1_dev->direct_free_lock));
   if(n1_dev->direct_free_list)
      cavium_free_virt(n1_dev->direct_free_list);

   if(n1_dev->direct_entry_array)
      cavium_free_virt(n1_dev->direct_entry_array);
   return 0;
}

Uint32 get_direct_free_index(cavium_device *n1_dev)
{
   return n1_dev->direct_free_index;
}




/*
 * $Id: direct_free_list.c,v 1.2 2008/09/30 13:15:17 jsrikanth Exp $
 * $Log: direct_free_list.c,v $
 * Revision 1.2  2008/09/30 13:15:17  jsrikanth
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
 * Revision 1.1  2007/01/06 02:47:40  panicker
 * * first cut - NITROX PX driver
 *
 * Revision 1.12  2006/01/31 07:00:55  sgadam
 * - Added pending entries and direct entries to special queue
 *
 * Revision 1.11  2005/10/13 09:22:31  ksnaren
 * changed cavium_malloc_dma to cavium_malloc_virt for the control structs
 *
 * Revision 1.10  2005/09/28 15:50:26  ksadasivuni
 * - Merging FreeBSD 6.0 AMD64 Release with CVS Head
 * - Now context pointer given to user space applications is physical pointer.
 *   So there is no need to do cavium_vtophys() of context pointer.
 *
 * Revision 1.9  2005/09/06 14:38:57  ksadasivuni
 * - Some cleanup error fixing and spin_lock_destroy functionality added to osi.
 *   spin_lock_destroy was necessary because of FreeBSD 6.0.
 *
 * Revision 1.8  2005/09/06 07:11:23  ksadasivuni
 * - Merging FreeBSD 4.11 release with CVS Head
 *
 * Revision 1.7  2005/06/13 06:35:42  rkumar
 * Changed copyright
 *
 * Revision 1.6  2005/02/01 04:11:07  bimran
 * copyright fix
 *
 * Revision 1.5  2004/06/23 19:58:24  bimran
 * compiler warnings on NetBSD.
 *
 * Revision 1.4  2004/06/03 21:22:56  bimran
 * included cavium_list.h
 * fixed list* calls to use cavium_list
 *
 * Revision 1.3  2004/05/02 19:44:29  bimran
 * Added Copyright notice.
 *
 * Revision 1.2  2004/04/30 00:00:34  bimran
 * Removed semaphoers from context memory in favour of just counts and a lock.
 *
 * Revision 1.1  2004/04/15 22:40:49  bimran
 * Checkin of the code from India with some cleanups.
 *
 */

