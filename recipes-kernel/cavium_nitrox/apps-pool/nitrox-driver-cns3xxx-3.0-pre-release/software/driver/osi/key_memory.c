/* key_memory.c */
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
#include "request_manager.h"
#include "key_memory.h"
#include "cavium_endian.h"
#include "init_cfg.h"
#include "buffer_pool.h"
#include "error_handler.h"

/* Key Memory related variables */
extern int dev_count;
extern short nplus, ssl, ipsec;
volatile Uint32 fsk_mem_chunk_count[MAX_DEV];
volatile Uint32 ex_key_mem_chunk_count[MAX_DEV];
volatile Uint32 host_key_mem_chunk_count[MAX_DEV];

/*
 * Key Memory Management Functions
 */
static int
init_fsk_memory(cavium_device *pkp_dev)
{
   Uint32 i;

   MPRINTFLOW();
   if(pkp_dev->fsk_free_list) 
   {
      cavium_error("Key memory free list already exists\n");
      return 1;
   }
   
   pkp_dev->fsk_chunk_count = (Uint32)(FSK_MAX/FSK_CHUNK_SIZE);
   /* Store the fsk chunk count in the global array fsk_mem_chunk_count */
   fsk_mem_chunk_count[dev_count-1] = pkp_dev->fsk_chunk_count;
   
   pkp_dev->fsk_free_list = (Uint16 *)cavium_malloc_virt(pkp_dev->fsk_chunk_count * sizeof(Uint16));

   if(pkp_dev->fsk_free_list == NULL) 
   {
      cavium_error("Not enough memory in allocating fsk free_list\n");
      return 1;
   }
 
   for(i = 0; i < pkp_dev->fsk_chunk_count; i++) 
   {
      pkp_dev->fsk_free_list[i] = (Uint16) (FSK_BASE + (i*FSK_CHUNK_SIZE));
   } 
       
   pkp_dev->fsk_free_index = 0;

   return 0;
}


static int
init_ex_key_memory(cavium_device *pkp_dev)
{
   Uint32 i;

    MPRINTFLOW();
   if(pkp_dev->ex_keymem_free_list) 
   {
      cavium_print("Key memory free list already exists\n");
      return 1;
   }
   
   pkp_dev->ex_keymem_chunk_count = (Uint32)(EX_KEYMEM_MAX/EX_KEYMEM_CHUNK_SIZE);
   
  /* Store the ex key memory count in the global array ex_key_mem_chunk_count */
   ex_key_mem_chunk_count[dev_count -1] = pkp_dev->ex_keymem_chunk_count;
   pkp_dev->ex_keymem_free_list = (Uint32 *)cavium_malloc_virt(pkp_dev->ex_keymem_chunk_count* sizeof(Uint32));
   
   if(pkp_dev->ex_keymem_free_list == NULL) 
   {
        cavium_print("Not enough memory in allocating ex_keymem free_list\n");
        return 1;
   }
 
   for (i = 0; i < pkp_dev->ex_keymem_chunk_count; i++) 
   {
      pkp_dev->ex_keymem_free_list[i] = i*EX_KEYMEM_CHUNK_SIZE;
   }    

   pkp_dev->ex_keymem_free_index = 0;

   return 0;
}


static int
init_key_host_memory(cavium_device *pkp_dev)
{
   Uint32 i;

   cavium_dmaaddr bus_addr = 0;
   MPRINTFLOW();
   if(pkp_dev->host_keymem_free_list) 
   {
      cavium_error( "Key memory free list already exists\n");
      return 1;
   }

   pkp_dev->host_keymem_count = (Uint32)(HOST_KEYMEM_MAX/HOST_KEYMEM_CHUNK_SIZE);

/* Store host key memory chunk count in the global array host_key_mem_chunk_count */
   host_key_mem_chunk_count[dev_count -1] = pkp_dev->host_keymem_count;
   pkp_dev->host_keymem_free_list = (Uint32 *)cavium_malloc_virt(pkp_dev->host_keymem_count * sizeof(Uint32));
   if (pkp_dev->host_keymem_free_list == NULL) 
   {
      cavium_error("Not enough memory in allocating host_key_mem freelist\n");
      return -1;
   }

   pkp_dev->host_keymem_static_list = ((struct PKP_BUFFER_ADDRESS *)
               cavium_malloc_virt(pkp_dev->host_keymem_count * 
                       sizeof(struct PKP_BUFFER_ADDRESS))
                                 );

   if(pkp_dev->host_keymem_static_list == NULL) 
   {
      cavium_error("Not enough memory in allocating ctx_static_list\n");
      goto host_error;
      return 1;
   }

   cavium_memset((Uint8 *)pkp_dev->host_keymem_static_list, 0,
            pkp_dev->host_keymem_count*sizeof(struct PKP_BUFFER_ADDRESS));

   for (i = 0; i < pkp_dev->host_keymem_count; i++) 
   {
      pkp_dev->host_keymem_static_list[i].size = HOST_KEYMEM_CHUNK_SIZE;
      pkp_dev->host_keymem_static_list[i].vaddr =
                              (ptrlong)cavium_malloc_nc_dma(pkp_dev,
                              pkp_dev->host_keymem_static_list[i].size,
                              &bus_addr);
      pkp_dev->host_keymem_static_list[i].baddr = bus_addr;
      if (pkp_dev->host_keymem_static_list[i].vaddr) 
      {
         pkp_dev->host_keymem_free_list[i] = i;
      } 
      else 
      {
         goto host_error;
      }
   }
   return 0;
host_error:
   for (i = 0; i < pkp_dev->host_keymem_count; i++) 
   {
      if (pkp_dev->host_keymem_static_list == NULL) 
      {
         break;
      }
      if (pkp_dev->host_keymem_static_list[i].vaddr) 
      { 
         cavium_free_nc_dma(pkp_dev,
                            pkp_dev->host_keymem_static_list[i].size,
                            (Uint8 *)pkp_dev->host_keymem_static_list[i].vaddr,
                            (cavium_dmaaddr)pkp_dev->host_keymem_static_list[i].baddr);
      } 
      else 
      {
         break;
      }   
   }

   if (pkp_dev->host_keymem_static_list) 
   {
      cavium_free_virt(pkp_dev->host_keymem_static_list);
      pkp_dev->host_keymem_static_list=NULL;
   }
   if (pkp_dev->host_keymem_free_list) 
   {
      cavium_free_virt(pkp_dev->host_keymem_free_list);
      pkp_dev->host_keymem_free_list = NULL;
   }
   return 1;
}

int
init_key_memory(cavium_device * pkp_dev)
{
   int ret=0;

   MPRINTFLOW();
   cavium_spin_lock_init(&pkp_dev->keymem_lock);
   /* Initialize fsk memory ==> On-chip SRAM memory */
   ret = init_fsk_memory(pkp_dev);
   if (ret) 
   {
      return ret;
   }
 
   if(pkp_dev->dram_present) 
   {
      /* Initialize EX key memory on DRAM */
      ret = init_ex_key_memory(pkp_dev);
      if(ret) 
      {
         return ret;
      }
   }

   /* Initialize the host key memory */
   ret = init_key_host_memory(pkp_dev);
   if (ret) 
   {
      return ret;
   }

   /*cavium_spin_lock_init(&pkp_dev->keymem_lock);*/

   CAVIUM_INIT_LIST_HEAD(&pkp_dev->keymem_head);

   return ret;
}


static void
free_host_key_memory(cavium_device *pkp_dev)
{
   Uint32 i;

    MPRINTFLOW();
   for (i = 0; i < pkp_dev->host_keymem_count; i++) 
   {
      if (pkp_dev->host_keymem_static_list == NULL) 
      {
         break;
      }
      if (pkp_dev->host_keymem_static_list[i].vaddr) 
      {
         cavium_free_nc_dma(pkp_dev,
                          pkp_dev->host_keymem_static_list[i].size,
                         (Uint8 *)pkp_dev->host_keymem_static_list[i].vaddr,
                         (cavium_dmaaddr)pkp_dev->host_keymem_static_list[i].baddr);
      } 
      else 
      {
         break;
      }   
   }

   if (pkp_dev->host_keymem_static_list) 
   {
      cavium_free_virt(pkp_dev->host_keymem_static_list);
      pkp_dev->host_keymem_static_list = NULL;
   }
   if (pkp_dev->host_keymem_free_list) 
   {
      cavium_free_virt(pkp_dev->host_keymem_free_list);
      pkp_dev->host_keymem_free_list = NULL;
   }
   return;
}

void
cleanup_key_memory(cavium_device *pkp_dev)
{
   MPRINTFLOW();
   cavium_spin_lock_destroy(&pkp_dev->keymem_lock);
   if(pkp_dev->fsk_free_list) 
   cavium_free_virt(pkp_dev->fsk_free_list);
   pkp_dev->fsk_free_list = NULL;

   if (pkp_dev->dram_present) 
   {
      if (pkp_dev->ex_keymem_free_list)
      cavium_free_virt(pkp_dev->ex_keymem_free_list);
      pkp_dev->ex_keymem_free_list = NULL;
   }

   if(pkp_dev->host_keymem_free_list) 
   free_host_key_memory(pkp_dev);

   return;
}
   
static Uint64
alloc_fsk(cavium_device *pkp_dev)
{
   Uint64 key_handle = (Uint64)0;
   MPRINTFLOW();
#ifdef CAVIUM_PKEY_HOST_MEM
   return key_handle;
#endif
#ifdef CAVIUM_PKEY_LOCAL_DDR
   return key_handle;
#endif
   if (pkp_dev->fsk_free_index >= pkp_dev->fsk_chunk_count) 
   {
      return key_handle;
   }

#ifdef MC2
   key_handle = (Uint64)((pkp_dev->fsk_free_list[pkp_dev->fsk_free_index])
            | ((Uint64)1 << 48));
#else
   key_handle = (Uint64)(pkp_dev->fsk_free_list[pkp_dev->fsk_free_index]);
#endif
   pkp_dev->fsk_free_index++;
   return key_handle;
}

static Uint64
alloc_ex_key_mem(cavium_device *pkp_dev)
{
   Uint64 key_handle = (Uint64)0;
   MPRINTFLOW();

#ifdef CAVIUM_PKEY_HOST_MEM
   return key_handle;
#endif
#ifdef CAVIUM_PKEY_INTERNAL_SRAM
   return key_handle;
#endif
   if (pkp_dev->ex_keymem_free_index >= pkp_dev->ex_keymem_chunk_count) 
   {
      return key_handle;
   }

#ifdef MC2
   key_handle = (((Uint64)(pkp_dev->ex_keymem_free_list[pkp_dev->ex_keymem_free_index])) & ((Uint64)0x00000000FFFFFFFFULL));
#else
   key_handle = ((((Uint64)(pkp_dev->ex_keymem_free_list[pkp_dev->ex_keymem_free_index])) \
                                                                >> 7) | 0x8000);
#endif

   key_handle |= (Uint64)0x8000000000000000ULL;
   pkp_dev->ex_keymem_free_index++;
   return key_handle;
}

static Uint64
alloc_host_key_memory(cavium_device *pkp_dev)
{
   Uint64 key_handle = (Uint64)0;
   Uint32 free_key;

    MPRINTFLOW();
   if (pkp_dev->host_keymem_free_index >= pkp_dev->host_keymem_count) 
   {
      return key_handle;
   }
   free_key = pkp_dev->host_keymem_free_list[pkp_dev->host_keymem_free_index];
   pkp_dev->host_keymem_free_index ++;
#ifdef MC2
   key_handle = (pkp_dev->host_keymem_static_list[free_key].baddr);
#else
   key_handle = (pkp_dev->host_keymem_static_list[free_key].baddr) | ((Uint64)0x20000 << 32);
#endif
   return key_handle;
}

Uint64
alloc_key_memory(cavium_device *pkp_dev)
{
   struct KEYMEM_ALLOC_ENTRY *entry;
   Uint32 loc;
   Uint64 key_handle= 0;

   MPRINTFLOW();
   entry = (struct KEYMEM_ALLOC_ENTRY *)cavium_malloc(sizeof(struct KEYMEM_ALLOC_ENTRY), NULL);
   if(entry == NULL) 
   {
      cavium_error( "keymem alloc: Not enough memory in allocating keymem entry.\n");
      return 0;
   }

   cavium_spin_lock(&pkp_dev->keymem_lock);

   key_handle = alloc_fsk(pkp_dev);
   if (!key_handle) 
   {
      if (pkp_dev->dram_present) 
      {
         key_handle = (Uint64)alloc_ex_key_mem(pkp_dev);
      }

      if (!key_handle) 
      {
         key_handle = (Uint64)alloc_host_key_memory(pkp_dev);
         if (!key_handle) 
         {
            cavium_free(entry);
            cavium_spin_unlock(&pkp_dev->keymem_lock);
            cavium_error("No more key memory available\n");
            return (Uint64)0;
         }
         loc = OP_MEM_FREE_KEY_HOST_MEM;
      } 
      else 
      {
         loc = OP_MEM_FREE_KEY_DDR_MEM;
      }
   } 
   else 
   {
      loc = OP_MEM_FREE_KEY_SRAM_MEM;
   }
   
   /* insert into allocated keymem_alloc list */
   entry->proc_pid = cavium_get_pid();
   entry->loc = (Uint16) loc;
   entry->key_handle = key_handle;
   cavium_list_add_tail(&entry->list, &pkp_dev->keymem_head);

   cavium_spin_unlock(&pkp_dev->keymem_lock);
   cavium_dbgprint("alloc_key: key handle = %16lx, loc = %d, pid = %d\n",
           (unsigned long)key_handle, loc, entry->proc_pid);

   return key_handle;
}


static void
dealloc_fsk(cavium_device *pkp_dev, Uint64 key_handle)
{
   MPRINTFLOW();
   pkp_dev->fsk_free_index --;
   pkp_dev->fsk_free_list[pkp_dev->fsk_free_index] = (Uint16) key_handle;
   return;
}

static void
dealloc_ex_keymem(cavium_device *pkp_dev, Uint64 key_handle)
{
   MPRINTFLOW();
   pkp_dev->ex_keymem_free_index --;
   key_handle &= (Uint64)0x7FFFFFFFFFFFFFFFULL;
   pkp_dev->ex_keymem_free_list[pkp_dev->ex_keymem_free_index] = (Uint32) (key_handle);
   return;
}

static void
dealloc_host_keymem(cavium_device *pkp_dev, Uint64 key_handle)
{
   Uint32 i;

   MPRINTFLOW();
#ifndef MC2
   /* turn off bit 49 */
   key_handle &= (((Uint64)0xfffdffff << 32) | (0xffffffff));
#endif

   for (i = 0; i <pkp_dev->host_keymem_count; i++) 
   {
      if (pkp_dev->host_keymem_static_list[i].baddr == key_handle) 
      {
         pkp_dev->host_keymem_free_index --;
         pkp_dev->host_keymem_free_list[pkp_dev->host_keymem_free_index] = i;
         return;
      }
   }
   cavium_error("CRIT ERROR ... KEY memory not found for deallocation\n");
   return;
}

void
dealloc_key_memory(cavium_device *pkp_dev, Uint64 key_handle)
{
   cavium_pid_t pid;
   struct cavium_list_head *tmp;
   struct KEYMEM_ALLOC_ENTRY *entry;

   MPRINTFLOW();
   pid = cavium_get_pid();
   cavium_spin_lock(&pkp_dev->keymem_lock);

   cavium_list_for_each(tmp, &pkp_dev->keymem_head) 
   {
      entry = cavium_list_entry(tmp, struct KEYMEM_ALLOC_ENTRY,
               list);
      
      if ((key_handle == entry->key_handle)) 
      {
         switch (entry->loc) 
         {
            case OP_MEM_FREE_KEY_SRAM_MEM:
               dealloc_fsk(pkp_dev, key_handle);
               break;
            case OP_MEM_FREE_KEY_DDR_MEM:
               dealloc_ex_keymem(pkp_dev, key_handle);
               break;
            case OP_MEM_FREE_KEY_HOST_MEM:
               dealloc_host_keymem(pkp_dev, key_handle);
               break;
         }
              cavium_list_del(&entry->list);
              cavium_free(entry);
         cavium_spin_unlock(&pkp_dev->keymem_lock);
         return;
      }
   }

   cavium_spin_unlock(&pkp_dev->keymem_lock);
   cavium_error("dealloc_key_memory: NOT FOUND 0x%lx\n", (ptrlong)key_handle);

   return;   
}

void
flush_key_memory(cavium_device *pkp_dev)
{
   cavium_pid_t pid;
   struct cavium_list_head *tmp;
   struct KEYMEM_ALLOC_ENTRY *entry;

    MPRINTFLOW();
   pid = cavium_get_pid();
   cavium_spin_lock(&pkp_dev->keymem_lock);

   cavium_list_for_each(tmp, &pkp_dev->keymem_head) 
   {
      entry = cavium_list_entry(tmp, struct KEYMEM_ALLOC_ENTRY,
                                                 list);
      
      if (pid == entry->proc_pid) 
      {
         switch (entry->loc) 
         {
            case OP_MEM_FREE_KEY_SRAM_MEM:
               dealloc_fsk(pkp_dev, entry->key_handle);
               break;
            case OP_MEM_FREE_KEY_DDR_MEM:
               dealloc_ex_keymem(pkp_dev, entry->key_handle);
               break;
            case OP_MEM_FREE_KEY_HOST_MEM:
               dealloc_host_keymem(pkp_dev, entry->key_handle);
               break;
         }
              cavium_list_del(&entry->list);
              cavium_free(entry);
         cavium_spin_unlock(&pkp_dev->keymem_lock);
         return;
      }
   }

   cavium_spin_unlock(&pkp_dev->keymem_lock);

   return;   
}

static int
store_host_keymem(cavium_device *pkp_dev, n1_write_key_buf key_buf)
{
   Uint64 key_handle,i;

   MPRINTFLOW();
#ifdef MC2
   key_handle = key_buf.key_handle;
#else
   key_handle = (key_buf.key_handle & (Uint64)0xfffdffffffffffffULL);
#endif
   cavium_dbgprint("KEY HANDLE 0x%lx\n",(unsigned long)key_handle);

   for (i = 0; i <pkp_dev->host_keymem_count; i++) 
   {
      if (pkp_dev->host_keymem_static_list[i].baddr == key_handle) 
      {
         cavium_dbgprint("KEY HANDLE copied to 0x%lx \n", pkp_dev->host_keymem_static_list[i].vaddr);
         if (cavium_debug_level >=  2)
            cavium_dump("KEY copied:", (Uint8 *)CAST_FRM_X_PTR(key_buf.key),
                                          (Uint32)key_buf.length);

         cavium_memcpy((void *)(pkp_dev->host_keymem_static_list[i].vaddr),
                                CAST_FRM_X_PTR(key_buf.key), key_buf.length);
         return 0;
      }
   }
   cavium_error("store_host_keymem: key_handle not found\n");
   return -1;
}

static int
store_ex_keymem(cavium_device *pkp_dev, n1_write_key_buf key_buf, int ucode_idx)
{
   Cmd strcmd;
   Request request;
   Uint64 key_handle;
   Uint64 *completion_address;
   Uint8 *dptr = NULL, *rptr = NULL;
   int ret;
   int srq_idx = -1;
   
    MPRINTFLOW();
   cavium_dbgprint("Inside store_ex_key_mem: key_buf.key_length %d\n",key_buf.length);
   key_handle = (Uint64)(key_buf.key_handle);            
   strcmd.opcode = htobe16(((0x2<<8) | MAJOR_OP_RANDOM_WRITE_CONTEXT));
#ifdef MC2
   strcmd.size = htobe16(0);
   strcmd.param = htobe16(0);
   strcmd.dlen = htobe16(key_buf.length);
#else
   strcmd.size = htobe16(((key_buf.length >> 3) - 1));
   strcmd.param = htobe16(0);
   strcmd.dlen = htobe16(((key_buf.length) >> 3));
#endif   
   cavium_memcpy((Uint8 *)&request, (Uint8 *)&strcmd, 8);

   dptr = (Uint8 *)get_buffer_from_pool(pkp_dev, (key_buf.length));
   if (dptr == NULL) 
   {
      cavium_error(" OOM for key buffer\n");
      ret = -1;
      goto store_exkeymem_clean;
   }
   cavium_memcpy(dptr, CAST_FRM_X_PTR(key_buf.key), key_buf.length);
   if (cavium_debug_level > 2)
      cavium_dump("KEY copied:", (Uint8 *)CAST_FRM_X_PTR(key_buf.key), key_buf.length);

   request.dptr = (Uint64)cavium_map_kernel_buffer(pkp_dev,
                                 dptr, (key_buf.length),
                                 CAVIUM_PCI_DMA_BIDIRECTIONAL);
   if(!request.dptr)
   {   
      cavium_error(" map kernel buffer failed for keybuffer\n");
      ret = -1;
      goto store_exkeymem_clean;
   }
   request.dptr = htobe64(request.dptr);

   rptr = (Uint8*)get_buffer_from_pool(pkp_dev,16);
   if (rptr == NULL) 
   {
      cavium_error(" OOM for key buffer\n");
      ret = -1;
      goto store_exkeymem_clean;
   }
   completion_address = (Uint64 *)rptr;
   *completion_address = COMPLETION_CODE_INIT;

   request.rptr = (Uint64)cavium_map_kernel_buffer(pkp_dev,
                                 rptr, 16,
                                 CAVIUM_PCI_DMA_BIDIRECTIONAL);
   if(!request.rptr)
   {   
      cavium_error(" map kernel buffer failed for keybuffer\n");
      ret = -1;
      goto store_exkeymem_clean;
   }
   request.rptr = htobe64(request.rptr);

   request.cptr = htobe64(key_handle);

/* nplus change */
   if((nplus || ssl>0 || ipsec>0) && pkp_dev->device_id != NPX_DEVICE)
      srq_idx = send_command(pkp_dev, &request, 0, ucode_idx, completion_address);
   else
      send_command(pkp_dev, &request, 0, ucode_idx, completion_address);

   ret = check_completion(pkp_dev, completion_address, (nplus||ssl>0||ipsec>0)?500:100, ucode_idx,srq_idx);
/* nplus change end */

   if (ret) 
   {
      cavium_error( "Error: %x in storing FSK memory\n", ret);
      ret = -1;
   }

store_exkeymem_clean:
   if (rptr)
   { 
     cavium_unmap_kernel_buffer(pkp_dev,
                                 betoh64(request.rptr), 16,
                                 CAVIUM_PCI_DMA_BIDIRECTIONAL);

      put_buffer_in_pool(pkp_dev,rptr);
      rptr = NULL;
   }
   if (dptr) 
   {
     cavium_unmap_kernel_buffer(pkp_dev,
                                 betoh64(request.dptr), (key_buf.length),
                                 CAVIUM_PCI_DMA_BIDIRECTIONAL);
      put_buffer_in_pool(pkp_dev, dptr);
   }
   return ret;
}

static int
store_fsk1(cavium_device *pkp_dev, n1_write_key_buf key_buf, int ucode_idx)
{
   Cmd strcmd;
   Request request;
   Uint64 key_handle;
   Uint64 *completion_address, *p;
   Uint8 *dptr = NULL, *rptr = NULL;
   int ret;
   int srq_idx = -1;
   
    MPRINTFLOW();
   cavium_dbgprint("Inside store_fsk: key_buf.key_length %d\n",key_buf.length);
   strcmd.opcode = htobe16(((0x0<<8) | MAJOR_OP_RANDOM_WRITE_CONTEXT));
#ifdef MC2
   strcmd.size = htobe16(0);
   strcmd.param = htobe16(0);
   strcmd.dlen = htobe16(8 + key_buf.length);
#else
   strcmd.size = htobe16((key_buf.length >> 3));
   strcmd.param = htobe16(0x8);
   strcmd.dlen = htobe16(((8 + key_buf.length) >> 3));
#endif
   cavium_memcpy((Uint8 *)&request, (Uint8 *)&strcmd, 8);

   dptr = (Uint8 *)get_buffer_from_pool(pkp_dev, (8 + key_buf.length));
   if (dptr == NULL) 
   {
      cavium_error(" OOM for key buffer\n");
      ret = -1;
      goto store_fsk_clean;
   }
   key_handle = (Uint64)(key_buf.key_handle);
   cavium_memcpy(dptr, &key_handle, 8);
   p = (Uint64 *)dptr;
   *p = htobe64(*p);
   cavium_memcpy(dptr + 8, CAST_FRM_X_PTR(key_buf.key), key_buf.length);
   if (cavium_debug_level > 2)
     cavium_dump("KEY copied:", (Uint8 *)CAST_FRM_X_PTR(key_buf.key), key_buf.length);
   request.dptr =  (Uint64)cavium_map_kernel_buffer(pkp_dev,
                      dptr, (8 + key_buf.length),
                      CAVIUM_PCI_DMA_BIDIRECTIONAL);
   if(!request.dptr)
   {   
      cavium_error(" map kernel buffer failed for keybuffer\n");
      ret = -1;
      goto store_fsk_clean;
   }   

   request.dptr = htobe64(request.dptr);

   /* rptr = cavium_malloc_dma(8, NULL); */
   rptr = (Uint8*)get_buffer_from_pool(pkp_dev,16);
   if (rptr == NULL) 
   {
      cavium_error(" OOM for key buffer\n");
      ret = -1;
      goto store_fsk_clean;
   }
   completion_address = (Uint64 *)rptr;
   *completion_address = COMPLETION_CODE_INIT;
   request.rptr = (Uint64)cavium_map_kernel_buffer(pkp_dev,
                   rptr,16,
                   CAVIUM_PCI_DMA_BIDIRECTIONAL);
   if(!request.rptr)
   {   
      cavium_error(" map kernel buffer failed for keybuffer\n");
      ret = -1;
      goto store_fsk_clean;
   }   

   request.rptr = htobe64(request.rptr);
   request.cptr = htobe64(0);

/*  nplus  change */
   if ((nplus || ssl>0 || ipsec>0) && pkp_dev->device_id != NPX_DEVICE)
      srq_idx = send_command(pkp_dev, &request, 0, ucode_idx, completion_address);
   else
      send_command(pkp_dev, &request, 0, ucode_idx, completion_address);

   ret = check_completion(pkp_dev, completion_address, (nplus||ssl>0||ipsec>0)?500:100, ucode_idx,srq_idx);
/*  nplus change end */

   if (ret) 
   {
      cavium_error( "Error: %x in storing FSK memory\n", ret);
      ret = -1;
   }

store_fsk_clean:
   if (rptr)
   { 
      cavium_unmap_kernel_buffer(pkp_dev,
                   betoh64(request.rptr),16,
                   CAVIUM_PCI_DMA_BIDIRECTIONAL);

      /* cavium_free_dma(rptr); */
      put_buffer_in_pool(pkp_dev,rptr);
      rptr = NULL;
   }
   if (dptr) 
   {
      cavium_unmap_kernel_buffer(pkp_dev,
                      betoh64(request.dptr), (8 + key_buf.length),
                      CAVIUM_PCI_DMA_BIDIRECTIONAL);

      put_buffer_in_pool(pkp_dev, dptr);
   }
   return ret;
}

#define MAX_FSK_WRITE  640

static int
store_fsk(cavium_device *pkp_dev, n1_write_key_buf key_buf, int ucode_idx)
{
   int ret=0;

   if(key_buf.length<=MAX_FSK_WRITE)
   {
      ret =store_fsk1(pkp_dev,key_buf,ucode_idx);
   }
   else
   {
     int length=key_buf.length;
     key_buf.length=MAX_FSK_WRITE;
     ret =store_fsk1(pkp_dev,key_buf,ucode_idx);
     key_buf.key_handle=key_buf.key_handle+MAX_FSK_WRITE;
     key_buf.key=key_buf.key+MAX_FSK_WRITE;
     key_buf.length=length-MAX_FSK_WRITE;
    
     ret =store_fsk1(pkp_dev,key_buf,ucode_idx);
   }
   return ret;
}


int
store_key_mem(cavium_device *pkp_dev, n1_write_key_buf key_buf, int ucode_idx)
{
   struct cavium_list_head *tmp;
   struct KEYMEM_ALLOC_ENTRY *entry;
   Uint32 found = 0 ;
   int ret = -1;

   MPRINTFLOW();
   cavium_spin_lock(&pkp_dev->keymem_lock);

   cavium_list_for_each(tmp, &pkp_dev->keymem_head) 
   {
      entry = cavium_list_entry(tmp, struct KEYMEM_ALLOC_ENTRY,
                                list);

      cavium_dbgprint("entry key 0x%lx\n",(unsigned long)entry->key_handle);
      cavium_dbgprint("entry key 0x%lx\n",(unsigned long)key_buf.key_handle);
      if (entry->key_handle == key_buf.key_handle) 
      {
         found = 1;
         switch (entry->loc) 
         {
            case OP_MEM_FREE_KEY_SRAM_MEM:
               ret = store_fsk(pkp_dev, key_buf, ucode_idx);
               
               break;
            case OP_MEM_FREE_KEY_DDR_MEM:
               ret = store_ex_keymem(pkp_dev, key_buf, ucode_idx);
               break;
            case OP_MEM_FREE_KEY_HOST_MEM:
               ret = store_host_keymem(pkp_dev, key_buf);
               break;
         }
      }
   }
   cavium_spin_unlock(&pkp_dev->keymem_lock);

   if (!found) 
   {
      cavium_error("store_key_mem: key_handle not found\n");
      return -1;
   }
   return ret;
}
#ifdef CAVIUM_RESOURCE_CHECK
int
insert_key_entry(cavium_device *pdev,struct cavium_list_head *key_head, Uint64 key_handle)
{
   struct KEY_ENTRY *entry;
   
    MPRINTFLOW();
   entry = cavium_malloc(sizeof(struct KEY_ENTRY), NULL);
   if (entry == NULL) 
   {
      cavium_error("Insert-key-entry: Not enough memory\n");
      return -1;
   }

   entry->key_handle = key_handle;
   entry->pkp_dev    = pdev;
   cavium_list_add_tail(&entry->list, key_head);   
   
   return 0;
}
#endif

/*
 * $Id: key_memory.c,v 1.13 2009/09/09 11:26:19 aravikumar Exp $
 * $Log: key_memory.c,v $
 * Revision 1.13  2009/09/09 11:26:19  aravikumar
 * NPLUS macro dependency removed and made it dynamic
 *
 * Revision 1.12  2008/12/16 12:04:42  jsrikanth
 * Added Common driver and Multi-Card Changes for FreeBSD
 *
 * Revision 1.11  2008/11/06 09:10:19  ysandeep
 * Removed PX_PLUS
 *
 * Revision 1.10  2008/09/30 13:15:17  jsrikanth
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
 * Revision 1.9  2008/08/04 14:55:57  aramesh
 * for key size >640 two fsk writes done.
 *
 * Revision 1.8  2008/03/06 08:05:13  aramesh
 * enquing store key request to cmd_queue-0.
 *
 * Revision 1.7  2007/09/10 10:56:18  kchunduri
 * --Maintain Context and KeyMemory resources per device.
 *
 * Revision 1.6  2007/06/11 13:41:07  tghoriparti
 * cavium_mmap_kernel_buffers return values handled properly when failed.
 *
 * Revision 1.5  2007/03/08 20:43:33  panicker
 * * NPLUS mode changes. pre-release
 * * NitroxPX now supports N1-style NPLUS operation.
 * * Native PX mode PLUS operations are enabled only if PX_PLUS flag is enabled
 *
 * Revision 1.4  2007/03/06 03:12:19  panicker
 * * PX will use the same core id lookup mechanism as N1.
 * * store_ex_keymem(), store_fsk(), store_key_mem(), send_command() uses same
 *   prototype as N1 for PX.
 * * check_completion() uses N1-nonNPLUS mode for NitroxPX NPLUS mode(PX_PLUS in
 *   the future)
 *
 * Revision 1.3  2007/01/13 03:17:47  panicker
 * * compilation warnings fixed.
 *
 * Revision 1.2  2007/01/11 02:09:40  panicker
 * - store_key_mem(), store_fsk(), store_ex_keymem() use in non-NPLUS mode
 *   for PX.
 *
 * Revision 1.1  2007/01/06 02:47:40  panicker
 * * first cut - NITROX PX driver
 *
 * Revision 1.35  2006/10/11 09:47:49  ksnaren
 * Fixed extended key memory load for MC1
 *
 * Revision 1.34  2006/09/25 10:14:41  ksnaren
 * Made proper Fix to the key_handle in alloc_ex_key_mem
 *
 * Revision 1.33  2006/09/21 07:25:49  rkumar
 * Warning fixed.
 *
 * Revision 1.32  2006/09/21 06:54:58  rkumar
 * Key memory in DDR causes handshake failures. This is fixed (63rd bit is not set properly for DDR access).
 *
 * Revision 1.31  2006/05/16 09:29:31  kchunduri
 * --support for Dynamic DMA mapping instead of virt_to_phys
 *
 * Revision 1.30  2005/12/20 14:48:35  kkiran
 * - 8 byte alignment issue fixed.
 *
 * Revision 1.29  2005/12/20 09:46:11  ksadasivuni
 * - when memory debugging was enabled cavium_malloc_dma was not returning 8 byte
 *   aligned pointers in RH9 SMP .changed it to get_buffer_from_pool() which does it.
 *
 * Revision 1.28  2005/12/07 04:50:59  kanantha
 * modified to support both 32 and 64 bit versions
 *
 * Revision 1.27  2005/11/17 13:31:09  kanantha
 * Updating with the 64 bit modifications, with proper matching of data types
 *
 * Revision 1.26  2005/10/24 06:53:51  kanantha
 * - Fixed RHEL4 warnings
 *
 * Revision 1.25  2005/10/13 09:25:13  ksnaren
 * changed cavium_malloc_dma to cavium_malloc_virt for the control structs
 *
 * Revision 1.24  2005/09/29 03:51:16  ksadasivuni
 * - Fixed some warnings
 *
 * Revision 1.23  2005/09/27 05:23:52  sgadam
 * Warning fixed
 *
 * Revision 1.22  2005/09/21 06:54:49  lpathy
 * Merging windows server 2003 release with CVS head
 *
 * Revision 1.21  2005/09/06 14:38:57  ksadasivuni
 * - Some cleanup error fixing and spin_lock_destroy functionality added to osi.
 *   spin_lock_destroy was necessary because of FreeBSD 6.0.
 *
 * Revision 1.20  2005/09/06 07:08:22  ksadasivuni
 * - Merging FreeBSD 4.11 Release with CVS Head
 *
 * Revision 1.19  2005/08/31 18:10:30  bimran
 * Fixed several warnings.
 * Fixed the corerct use of ALIGNMENT and related macros.
 *
 * Revision 1.18  2005/07/21 09:28:32  sgadam
 * pointer are asigned NULL after freeing them.
 *
 * Revision 1.17  2005/06/13 06:35:42  rkumar
 * Changed copyright
 *
 * Revision 1.16  2005/06/03 08:07:55  rkumar
 * Moved cavium_prints to cavium_dbgprint
 *
 * Revision 1.15  2005/05/20 14:34:05  rkumar
 * Merging CVS head from india
 *
 * Revision 1.14  2005/02/01 04:11:07  bimran
 * copyright fix
 *
 * Revision 1.13  2004/07/29 19:55:26  tsingh
 * Bug fix from India office.
 *
 * Revision 1.1.1.1  2004/07/28 06:43:29  rkumar
 * Initial Checkin
 *
 * Revision 1.12  2004/06/23 20:45:26  bimran
 * compiler warnings on NetBSD.
 *
 * Revision 1.8  2004/05/04 20:48:34  bimran
 * Fixed RESOURCE_CHECK.
 *
 * Revision 1.7  2004/05/02 19:45:31  bimran
 * Added Copyright notice.
 *
 * Revision 1.6  2004/04/27 01:29:28  tsingh
 * Fixed another bug in extended key memory store. The function was doing RSHIFT of 7 bits whereas it had to do LSHIFT :-)
 *
 * Revision 1.5  2004/04/27 00:31:01  tsingh
 * Changed debug print to print
 *
 * Revision 1.4  2004/04/27 00:02:39  tsingh
 * Fixed extended key memory load bug. (bimran).
 *
 * Revision 1.3  2004/04/23 22:40:19  bimran
 * Fixed dealloc_host_key_mem() function. Bit 49 must be cleared for MC1.
 *
 * Revision 1.2  2004/04/21 19:18:58  bimran
 * NPLUS support.
 *
 * Revision 1.1  2004/04/15 22:40:49  bimran
 * Checkin of the code from India with some cleanups.
 *
 */

