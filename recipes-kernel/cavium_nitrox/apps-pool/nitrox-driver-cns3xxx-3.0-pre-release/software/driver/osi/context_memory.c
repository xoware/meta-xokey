/* context_memory.c */
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
#include "context_memory.h"


#ifdef CTX_MEM_IS_HOST_MEM
#include "init_cfg.h"
#include "buffer_pool.h"

/* These should be in sync with CtxType enum */
static
Uint32 ctx_mem_sizes[] = 
{
   SSL_CONTEXT_SIZE,
   IPSEC_CONTEXT_SIZE,
   ECC_P256_CONTEXT_SIZE,
   ECC_P384_CONTEXT_SIZE
};
#endif




/* context memory */
extern int dev_count;
volatile Uint32 allocated_context_count = 0;

/*
 * Initialize context buffers
 */
int 
init_context(cavium_device *pkp_dev)
{
#ifndef CTX_MEM_IS_HOST_MEM
   Uint32 i;
   ptrlong  ipsec_context_memory_base, ssl_context_memory_base;
   Uint32 ipsec_context_memory_size=0;
   Uint32 ssl_context_memory_size=0;
   Uint8 *p;

   MPRINTFLOW();
   if(pkp_dev->ctx_free_list) 
   {
      cavium_print(("context memory free list already exists\n"));
      return 1;
   }
   cavium_spin_lock_init(&pkp_dev->ctx_lock); 

   /* calculate the total amount of context memory that IPsec contexts will use*/
   ipsec_context_memory_size = (Uint32) ((pkp_dev->dram_max-pkp_dev->dram_base)/2);

   /* well same goes for SSL */
   ssl_context_memory_size = ipsec_context_memory_size;

   /* calcualte base addresses for IPsec and SSL blcoks */
   ipsec_context_memory_base = pkp_dev->dram_base;
   ssl_context_memory_base = pkp_dev->dram_base + ipsec_context_memory_size;

   /* calculate chunk counts */
   pkp_dev->ipsec_chunk_count = ipsec_context_memory_size/IPSEC_CONTEXT_SIZE;
   pkp_dev->ssl_chunk_count = ssl_context_memory_size/SSL_CONTEXT_SIZE;

   pkp_dev->dram_chunk_count = pkp_dev->ipsec_chunk_count + pkp_dev->ssl_chunk_count;

   cavium_dbgprint("dram_chunk count: %d\n",pkp_dev->dram_chunk_count);
   
   pkp_dev->ctx_free_list = 
      (ptrlong *)cavium_malloc_virt(pkp_dev->dram_chunk_count*sizeof(ptrlong));
   pkp_dev->org_ctx_free_list = 
      (ptrlong *)cavium_malloc_virt(pkp_dev->dram_chunk_count*sizeof(ptrlong));
#ifdef DUMP_FAILING_REQUESTS
   pkp_dev->org_busctx_free_list =
       (ptrlong *)cavium_malloc_virt(pkp_dev->dram_chunk_count*sizeof(ptrlong));   if(pkp_dev->ctx_free_list == NULL || pkp_dev->org_ctx_free_list == NULL ||
      pkp_dev->org_busctx_free_list == NULL)
#else
   if(pkp_dev->ctx_free_list == NULL || pkp_dev->org_ctx_free_list == NULL)
#endif 
   {
      if(pkp_dev->ctx_free_list)
       {
         cavium_free_virt(pkp_dev->ctx_free_list);
         pkp_dev->ctx_free_list = NULL;
      }
      if(pkp_dev->org_ctx_free_list)
      {
         cavium_free_virt(pkp_dev->org_ctx_free_list);
         pkp_dev->org_ctx_free_list = NULL;
      }
#ifdef DUMP_FAILING_REQUESTS
      if (pkp_dev->org_busctx_free_list) {
          cavium_free_virt(pkp_dev->org_busctx_free_list);
          pkp_dev->org_busctx_free_list = NULL;
      }
#endif
     cavium_print("Not enough memory in allocating ctx_free_list\n");
     return 1;
   }
      
   /* Allocate IPSEC */
   for (i=0; i < pkp_dev->ipsec_chunk_count ; i++) 
   {
      /* DRAM present */
      if (pkp_dev->dram_present) 
      {
         pkp_dev->ctx_free_list[i] = (ptrlong)((i*IPSEC_CONTEXT_SIZE)+ipsec_context_memory_base);
      } 
      else 
      {
      /* NO DRAM Using host memory*/
         p = cavium_malloc_dma(IPSEC_CONTEXT_SIZE+ALIGNMENT,NULL);
         if(p)
         {
            pkp_dev->org_ctx_free_list[i] = (ptrlong)p;
            p = (Uint8 *)((ptrlong)((Uint8 *)p+ALIGNMENT) & ALIGNMENT_MASK );
            /*pkp_dev->ctx_free_list[i] = (ptrlong)p;*/
            pkp_dev->ctx_free_list[i] =
                       (ptrlong)cavium_map_kernel_buffer(pkp_dev,
                                    p,
                                    IPSEC_CONTEXT_SIZE,
                                    CAVIUM_PCI_DMA_BIDIRECTIONAL);
 #ifdef DUMP_FAILING_REQUESTS
            pkp_dev->org_busctx_free_list[i] = pkp_dev->ctx_free_list[i];
 #endif

            if(! pkp_dev->ctx_free_list[i])   
            {   
               cavium_free_dma((Uint8 *)pkp_dev->org_ctx_free_list[i]);
            }
         }
         if((!p)||(!pkp_dev->ctx_free_list[i]))   
         {
            Uint32 j;

            for(j=0; j<i; j++) 
            {
               cavium_unmap_kernel_buffer(pkp_dev,
                          pkp_dev->ctx_free_list[j],
                          IPSEC_CONTEXT_SIZE,
                          CAVIUM_PCI_DMA_BIDIRECTIONAL);
               p = (Uint8 *)pkp_dev->org_ctx_free_list[j];
               cavium_free_dma(p);
            }
            cavium_print("Not enough memory in allocating context memory %d\n", j);
            cavium_free_virt(pkp_dev->ctx_free_list);
            cavium_free_virt(pkp_dev->org_ctx_free_list);
#ifdef DUMP_FAILING_REQUESTS
            cavium_free_virt(pkp_dev->org_busctx_free_list);
            pkp_dev->org_busctx_free_list=NULL;
#endif
            pkp_dev->org_ctx_free_list=NULL;
            pkp_dev->ctx_free_list=NULL;
            return 1;
         }
      }
   }
      
   /* Allocate SSL*/
   for (i=pkp_dev->ipsec_chunk_count; i<pkp_dev->dram_chunk_count; i++) 
   {
      /* DRAM present */
      if (pkp_dev->dram_present) 
      {
         pkp_dev->ctx_free_list[i] = (ptrlong)(((i-pkp_dev->ipsec_chunk_count)*SSL_CONTEXT_SIZE)+ssl_context_memory_base);
      } 
      else
      {
         /* NO DRAM Using host memory*/ 
         p = cavium_malloc_dma(SSL_CONTEXT_SIZE+ALIGNMENT,NULL);
         if(p)
         {
            pkp_dev->org_ctx_free_list[i] = (ptrlong)p;
            p = (Uint8 *)((ptrlong)((Uint8 *)p+ALIGNMENT) & ALIGNMENT_MASK );
            /*pkp_dev->ctx_free_list[i] = (ptrlong)p;*/
            pkp_dev->ctx_free_list[i] = 
                                    (ptrlong) cavium_map_kernel_buffer(
                                               pkp_dev,
                                               p,
                                               SSL_CONTEXT_SIZE,
                                               CAVIUM_PCI_DMA_BIDIRECTIONAL);
#ifdef DUMP_FAILING_REQUESTS
            pkp_dev->org_busctx_free_list[i] = pkp_dev->ctx_free_list[i];
#endif
            if(! pkp_dev->ctx_free_list[i])   
            {   
               cavium_free_dma((Uint8 *)pkp_dev->org_ctx_free_list[i]);
            }
         
      }
     /* Failure cases for cavium_malloc_dma and map_kernel */   
     if((!p)||(!pkp_dev->ctx_free_list[i]))   
          {
             Uint32 j;

             for(j=0; j<i; j++) 
             {
               if(j<pkp_dev->ipsec_chunk_count)
               {
                cavium_unmap_kernel_buffer(pkp_dev,
                              pkp_dev->ctx_free_list[j],
                              IPSEC_CONTEXT_SIZE,
                              CAVIUM_PCI_DMA_BIDIRECTIONAL);
               }
               else
               { 
                cavium_unmap_kernel_buffer(pkp_dev,
                              pkp_dev->ctx_free_list[j],
                              SSL_CONTEXT_SIZE,
                              CAVIUM_PCI_DMA_BIDIRECTIONAL);
               }
                p = (Uint8*)pkp_dev->org_ctx_free_list[j];
                cavium_free_dma(p);
             }
             cavium_print("Not enough memory in allocating context memory\n");
             cavium_free_virt(pkp_dev->ctx_free_list);
             cavium_free_virt(pkp_dev->org_ctx_free_list);
#ifdef DUMP_FAILING_REQUESTS
             cavium_free_virt(pkp_dev->org_busctx_free_list);
             pkp_dev->org_busctx_free_list=NULL;
#endif

             pkp_dev->org_ctx_free_list=NULL;
             pkp_dev->ctx_free_list=NULL;
             return 1;
          }
      }
   }
   
 /* initialize lock */
 /* cavium_spin_lock_init(&pkp_dev->ctx_lock); */

 pkp_dev->ctx_ipsec_count =pkp_dev->ipsec_chunk_count;
 pkp_dev->ctx_ssl_count = pkp_dev->ssl_chunk_count;

 pkp_dev->ctx_ipsec_free_index = 0;
 pkp_dev->ctx_ipsec_put_index = -1;
 pkp_dev->ctx_ssl_free_index =pkp_dev->ipsec_chunk_count;
 return 0;
#else
  cavium_dbgprint("ctx init simulated (i.e, using buffer pool)\n");
 return 0;
#endif
}/*init_context*/


/*
 * Get next available context ID
 */
int
alloc_context_id(cavium_device *pkp_dev, ContextType c, ptrlong *cid)
{
   #ifndef CTX_MEM_IS_HOST_MEM
   int ret=0;
   ptrlong   cm=0;

   MPRINTFLOW();
   cavium_spin_lock_softirqsave(&pkp_dev->ctx_lock);
   if ( c ==  CONTEXT_IPSEC) 
   {
      if(pkp_dev->ctx_ipsec_count==0)
      {
         ret = -1;
         goto cleanup;
      }
         
      cm = pkp_dev->ctx_free_list[pkp_dev->ctx_ipsec_free_index];
      pkp_dev->ctx_ipsec_free_index++;
      if(pkp_dev->ctx_ipsec_free_index ==pkp_dev->ipsec_chunk_count)
        pkp_dev->ctx_ipsec_free_index = 0;
      pkp_dev->ctx_ipsec_count--;
   } 
   else 
   {
      if(pkp_dev->ctx_ssl_count == 0)
      {
         ret = -1;
         goto cleanup;
      }
      
      cm = pkp_dev->ctx_free_list[pkp_dev->ctx_ssl_free_index];
      pkp_dev->ctx_ssl_free_index++;
      pkp_dev->ctx_ssl_count--;
   }

   allocated_context_count++;
cleanup:
   cavium_spin_unlock_softirqrestore(&pkp_dev->ctx_lock);
   *cid = cm;
   return ret;
#else
   Uint8 *ptr = NULL;
   ptrlong cm;

   if(c > CONTEXT_ECC_P384)
   {
     cavium_error("request for invalid ctxtype=%d\n",(int)c);
     return -1;
   }

   ptr = get_buffer_from_pool(pkp_dev,ctx_mem_sizes[(int)c]);

   if(!ptr) 
   {
     cavium_dbgprint("ctx type=%d get_buffer_from_pool failed\n",(int)c);
     return -1;
   }

   cm = (ptrlong)cavium_map_kernel_buffer(pkp_dev,ptr,ctx_mem_sizes[(int)c],
                                                 CAVIUM_PCI_DMA_BIDIRECTIONAL);
   *cid = cm;
   return 0;
#endif
} /* alloc_context */



/*
 * Put back
 */
int 
dealloc_context_id(cavium_device * pkp_dev, ContextType c, ptrlong cid)
{
#ifndef CTX_MEM_IS_HOST_MEM
   int ret=0;
   MPRINTFLOW();
    /* acquire lock */   
    cavium_spin_lock_softirqsave(&pkp_dev->ctx_lock);
   
    if (c == CONTEXT_IPSEC)  
    {
      if(pkp_dev->ctx_ipsec_count == pkp_dev->ipsec_chunk_count)
          ret = -1;
         else{
            pkp_dev->ctx_ipsec_put_index++;
            if(pkp_dev->ctx_ipsec_put_index == pkp_dev->ipsec_chunk_count)
                pkp_dev->ctx_ipsec_put_index = 0;
            pkp_dev->ctx_free_list[pkp_dev->ctx_ipsec_put_index] = cid;   
            pkp_dev->ctx_ipsec_count++;
        }
    } 
    else 
    {
      /* SSL */
       pkp_dev->ctx_ssl_free_index--;
       pkp_dev->ctx_ssl_count++;
       pkp_dev->ctx_free_list[pkp_dev->ctx_ssl_free_index] = cid;   
    }
   
    allocated_context_count--;

    /* release lock*/
    cavium_spin_unlock_softirqrestore(&pkp_dev->ctx_lock);

    return ret;
#else
    Uint8 *ptr = cavium_phystov(cid);
    cavium_unmap_kernel_buffer(pkp_dev,cid,ctx_mem_sizes[(int)c],
                          CAVIUM_PCI_DMA_BIDIRECTIONAL);
    put_buffer_in_pool(pkp_dev,ptr);
    return 0;
#endif
}/* dealloc context */

Uint64
alloc_context(cavium_device *pkp_dev, ContextType c)
{
   ptrlong cid;

   MPRINTFLOW();
   if(alloc_context_id(pkp_dev, c, &cid))
   {
      cavium_error("alloc_context: context memory allocation failed\n");
      return 0;
   }
   else
   {
      /* Increment the allocated context counter */
      if (pkp_dev->dram_present)
      {
         return (Uint64)cid | (Uint64)(0x8000000000000000ULL);
      }
      else
         return (Uint64)cid;
   }
}
   
#ifdef CAVIUM_RESOURCE_CHECK
int
insert_ctx_entry(cavium_device *pdev,struct cavium_list_head *ctx_head, ContextType c, Uint64 addr)
{
   struct CTX_ENTRY *entry;
   
   MPRINTFLOW();
   entry = cavium_malloc(sizeof(struct CTX_ENTRY), NULL);
   if (entry == NULL) {
      cavium_error("Insert-ctx-entry: Not enough memory\n");
      return -1;
   }

   entry->ctx = addr;
   entry->ctx_type = c;
   entry->pkp_dev = pdev;

   cavium_list_add_tail(&entry->list, ctx_head);   
   
   return 0;
}
#endif

void 
dealloc_context(cavium_device *pkp_dev, ContextType c, Uint64 addr)
{
   ptrlong cid = 0;

   MPRINTFLOW();
   if(pkp_dev->dram_present)
   {
      cid = (ptrlong)(addr & (Uint64)0x7fffffffffffffffULL);
   }
   else
      cid = (ptrlong)addr;

   dealloc_context_id(pkp_dev, c, cid);
}


/*
 * Free memory 
 */
int 
cleanup_context(cavium_device *pkp_dev)
{
#ifndef CTX_MEM_IS_HOST_MEM
   Uint32 i;
   Uint8 *p;

   MPRINTFLOW();
   cavium_spin_lock_destroy(&pkp_dev->ctx_lock);
   if (pkp_dev->dram_present) 
   {
      if (pkp_dev->ctx_free_list) 
      {
         cavium_free_virt((Uint8 *)pkp_dev->ctx_free_list);
         pkp_dev->ctx_free_list = NULL;
      }
      if(pkp_dev->org_ctx_free_list) 
      {
         cavium_free_virt((Uint8 *)pkp_dev->org_ctx_free_list);
         pkp_dev->org_ctx_free_list=NULL;
      }
      
   }
   else 
   {
      if(pkp_dev->org_ctx_free_list) 
      {
         for(i = 0; i < pkp_dev->dram_chunk_count; i++) 
         {
            if(i<pkp_dev->ipsec_chunk_count)
            {
          cavium_unmap_kernel_buffer(pkp_dev,
                          pkp_dev->ctx_free_list[i],
                          IPSEC_CONTEXT_SIZE,
                          CAVIUM_PCI_DMA_BIDIRECTIONAL);
            }
            else
            { 
          cavium_unmap_kernel_buffer(pkp_dev,
                          pkp_dev->ctx_free_list[i],
                          SSL_CONTEXT_SIZE,
                          CAVIUM_PCI_DMA_BIDIRECTIONAL);
            }
            p = (Uint8 *)pkp_dev->org_ctx_free_list[i];
            if (p)
               cavium_free_dma(p);
         }
      }

      if(pkp_dev->ctx_free_list) 
      {
         cavium_free_virt((Uint8 *)pkp_dev->ctx_free_list);
         pkp_dev->ctx_free_list=NULL;
      }
      if(pkp_dev->org_ctx_free_list) 
      {
         cavium_free_virt((Uint8 *)pkp_dev->org_ctx_free_list);
         pkp_dev->org_ctx_free_list=NULL;
      }
   }

   pkp_dev->ctx_ipsec_free_index=0;
   pkp_dev->ctx_ssl_free_index=0;

   return 0;
#else
   cavium_dbgprint("ctx cleanup simulated (i.e, using buffer pool)\n");
   return 0;
#endif
}/*cleanup_context*/

#ifdef DUMP_FAILING_REQUESTS
Uint8 *
find_host_ctx(cavium_device *pkp_dev, Uint64 ctx_addr)
{
    Uint8 *ret = NULL;

    if (pkp_dev->dram_present || (!ctx_addr))
       return ret;

#ifdef CTX_MEM_IS_HOST_MEM
    ret = cavium_phystov(ctx_addr);
#else
    cavium_spin_lock_softirqsave(&pkp_dev->ctx_lock);
    for (i=pkp_dev->ipsec_chunk_count; i<pkp_dev->dram_chunk_count; i++) {
        if (pkp_dev->org_busctx_free_list[i] == ctx_addr) {
           ret = (Uint8 *)(pkp_dev->org_ctx_free_list[i]);
           break;
        }
    }
    cavium_spin_unlock_softirqrestore(&pkp_dev->ctx_lock);
#endif
    return ret;
}
#endif


/*
 * $Id: context_memory.c,v 1.9 2008/09/30 13:15:17 jsrikanth Exp $
 * $Log: context_memory.c,v $
 * Revision 1.9  2008/09/30 13:15:17  jsrikanth
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
 * Revision 1.8  2008/02/22 10:20:13  aramesh
 * N1_SANITY is set always.
 *
 * Revision 1.7  2007/12/07 05:33:37  ksadasivuni
 * ptr should be freed not ptr-8 to buffer pool
 *
 * Revision 1.6  2007/12/07 05:24:18  ksadasivuni
 * 1.  changed context memory to use buffer pool as px doesn't have DDR
 * 2.  PX_ECC_FreeContext now takes cid argument
 *
 * Revision 1.5  2007/11/19 11:11:55  lpathy
 * ported to 64 bit windows.
 *
 * Revision 1.4  2007/10/18 09:35:09  lpathy
 * Added windows support.
 *
 * Revision 1.3  2007/09/10 10:56:18  kchunduri
 * --Maintain Context and KeyMemory resources per device.
 *
 * Revision 1.2  2007/06/11 13:41:07  tghoriparti
 * cavium_mmap_kernel_buffers return values handled properly when failed.
 *
 * Revision 1.1  2007/01/06 02:47:40  panicker
 * * first cut - NITROX PX driver
 *
 * Revision 1.24  2006/11/13 14:25:45  kchunduri
 * 'allocated_context_count' locked while updating.
 *
 * Revision 1.23  2006/05/16 09:32:28  kchunduri
 * --support for Dynamic DMA mapping instead of virt_to_phys
 *
 * Revision 1.22  2006/01/30 11:08:49  sgadam
 * - check in corrected
 *
 * Revision 1.21  2006/01/30 10:55:57  sgadam
 *  - ipsec and ssl chunk counts moved to device structure
 *
 * Revision 1.20  2006/01/30 07:13:48  sgadam
 * - ipsec context new put index added
 *
 * Revision 1.19  2006/01/24 07:52:31  pyelgar
 *    - For N1 with DDR fixed the context freeing in cleanup_command.
 *      For freebsd changed the interrupt level to splnet.
 *
 * Revision 1.18  2006/01/19 09:48:08  sgadam
 * - IPsec 2.6.11 changes
 *
 * Revision 1.17  2005/11/17 13:31:09  kanantha
 * Updating with the 64 bit modifications, with proper matching of data types
 *
 * Revision 1.16  2005/10/24 06:51:59  kanantha
 * - Fixed RHEL4 warnings
 *
 * Revision 1.15  2005/10/13 09:21:59  ksnaren
 * fixed compile errors for windows xp
 *
 * Revision 1.14  2005/09/28 15:50:26  ksadasivuni
 * - Merging FreeBSD 6.0 AMD64 Release with CVS Head
 * - Now context pointer given to user space applications is physical pointer.
 *   So there is no need to do cavium_vtophys() of context pointer.
 *
 * Revision 1.13  2005/09/06 14:38:57  ksadasivuni
 * - Some cleanup error fixing and spin_lock_destroy functionality added to osi.
 *   spin_lock_destroy was necessary because of FreeBSD 6.0.
 *
 * Revision 1.12  2005/08/31 18:10:30  bimran
 * Fixed several warnings.
 * Fixed the corerct use of ALIGNMENT and related macros.
 *
 * Revision 1.11  2005/07/17 04:35:09  sgadam
 * 8 bytes alignment issue on linux-2.6.2 is fixed. README and Makefile in
 * apps/cavium_engine updated
 *
 * Revision 1.10  2005/06/13 06:35:42  rkumar
 * Changed copyright
 *
 * Revision 1.9  2005/05/20 14:34:05  rkumar
 * Merging CVS head from india
 *
 * Revision 1.8  2005/02/01 04:11:07  bimran
 * copyright fix
 *
 * Revision 1.7  2004/06/03 21:22:56  bimran
 * included cavium_list.h
 * fixed list* calls to use cavium_list
 *
 * Revision 1.6  2004/05/04 20:48:34  bimran
 * Fixed RESOURCE_CHECK.
 *
 * Revision 1.5  2004/05/02 19:44:29  bimran
 * Added Copyright notice.
 *
 * Revision 1.4  2004/04/30 00:00:33  bimran
 * Removed semaphoers from context memory in favour of just counts and a lock.
 *
 * Revision 1.3  2004/04/21 21:21:04  bimran
 * statis and free lists were using DMA memory for no reason. Changed the memory allocation to virtual.
 *
 * Revision 1.2  2004/04/20 02:23:17  bimran
 * Made code more generic. Divided context memory into two portions, one for Ipsec and One for SSL.
 * Fixed  bug where DDR was present and index was not pushed in free list.
 *
 * Revision 1.1  2004/04/15 22:40:48  bimran
 * Checkin of the code from India with some cleanups.
 *
 */

