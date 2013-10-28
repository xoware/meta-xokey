/* cavium.c */
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
#include "cavium_endian.h"
#include "cavium_list.h"
#include "cavium.h"
#include "command_que.h"
#include "context_memory.h"
#include "hw_lib.h"
#include "error_handler.h"
#include "pending_free_list.h"
#include "pending_list.h"
#include "direct_free_list.h"
#include "sg_free_list.h"
#include "sg_dma_free_list.h"
#include "completion_dma_free_list.h"
#include "soft_req_queue.h"   /* Software queues are not used in PX_PLUS */

enum {
    AVAILABLE = 0,
    USED      = 1
};

static struct {
    int status;
    int core_grp;
} npx_group[NITROX_PX_MAX_GROUPS];

extern short nplus;

static void pkp_convert_sg_to_int_format(struct PKP_SG_OPERATION_STRUCT *);


/*
 */
int
check_completion(cavium_device *n1_dev, volatile Uint64 *p, int max_wait_states, int ucode_idx, int srq_idx)
{
   int i, ret;

   i=ret=0;
   
   MPRINTFLOW();
   cavium_dbgprint("comp-address: %016llx\n", CAST64(*p));
   cavium_invalidate_cache(n1_dev, 8, p, p, 0);
   while (((Uint8)((*p) >> COMPLETION_CODE_SHIFT)) == 0xff) 
   {
      /* If this check is for a SPM code, then we try to move requests
       * from SRQ to the CTP here
       */
      if(nplus && n1_dev->device_id != NPX_DEVICE && n1_dev->microcode[ucode_idx].code_type == CODE_TYPE_SPECIAL)
         move_srq_entries(n1_dev, ucode_idx, 0);
      cavium_mdelay(2);
      i++;
      if(i > max_wait_states)
      {
         ret = ERR_REQ_TIMEOUT;
         break;
      }
      cavium_invalidate_cache(n1_dev, 8, p, p, 0);
   }

   if(nplus && n1_dev->device_id != NPX_DEVICE && n1_dev->microcode[ucode_idx].code_type == CODE_TYPE_SPECIAL)
   {
      if(ret == 0)
      {
         /* We will have to free our entry in the SRQ */
         free_srq_entries(n1_dev, ucode_idx, srq_idx, p);
      }
      else
      {
         /* Our request timed out! :-(. We still need to remove our
          * entry from the SRQ, but make sure that no core is
          * looking at our instruction */
          del_srq_entry(n1_dev, ucode_idx, srq_idx, p);
      }
   }
   if (!ret)
      ret = check_completion_code(p);

   cavium_dbgprint( "Completion code = %016llx\n",CAST64(*p));
   return ret;

}


/* 
 *Direct operation setup 
 */
int pkp_setup_direct_operation(cavium_device *pdev,
      Csp1OperationBuffer *csp1_operation, 
      struct PKP_DIRECT_OPERATION_STRUCT *pkp_direct_operation)
{
   volatile Uint64 *completion_address;
   pkp_direct_operation->ctx = csp1_operation->ctx_ptr;

   MPRINTFLOW();
   pkp_direct_operation->cmd_bytes = ((Uint64)csp1_operation->opcode) << 48
                                   | ((Uint64)csp1_operation->size << 32)
                                     | ((Uint64)csp1_operation->param << 16)
                                     | csp1_operation->dlen;

   pkp_direct_operation->dptr  = CAST_FRM_X_PTR(csp1_operation->inptr[0]);
   pkp_direct_operation->dlen = csp1_operation->dlen;
   if(pkp_direct_operation->dlen)
   {
     pkp_direct_operation->dptr_baddr = (Uint64)cavium_map_kernel_buffer(pdev, pkp_direct_operation->dptr, pkp_direct_operation->dlen, CAVIUM_PCI_DMA_BIDIRECTIONAL);
     if(pkp_direct_operation->dptr_baddr == (Uint64)0)
        return -1;

 
   cavium_flush_cache(pdev, 
         pkp_direct_operation->dlen,
         pkp_direct_operation->dptr,
         pkp_direct_operation->dptr_baddr, 
         CAVIUM_PCI_DMA_BIDIRECTIONAL);
   }
   else
   {
      pkp_direct_operation->dptr = (Uint64)0;
      pkp_direct_operation->dptr_baddr = (Uint64)0;
   }

   pkp_direct_operation->rptr   = CAST_FRM_X_PTR(csp1_operation->outptr[0]);
   pkp_direct_operation->rlen = csp1_operation->rlen;
   pkp_direct_operation->rptr_baddr = (Uint64)cavium_map_kernel_buffer(pdev, pkp_direct_operation->rptr, pkp_direct_operation->rlen + sizeof(Uint64), CAVIUM_PCI_DMA_BIDIRECTIONAL);
   if(pkp_direct_operation->rptr_baddr == (Uint64)0)
      return -1;

   pkp_direct_operation->completion_address = (volatile Uint64 *)
   ((ptrlong)(pkp_direct_operation->rptr) + (pkp_direct_operation->rlen));

   completion_address = pkp_direct_operation->completion_address;
   *completion_address = COMPLETION_CODE_INIT;

   cavium_flush_cache(pdev, 
         COMPLETION_CODE_SIZE,
         (ptrlong)completion_address,
         pkp_direct_operation->rptr_baddr+pkp_direct_operation->rlen, 
         CAVIUM_PCI_DMA_BIDIRECTIONAL);
   return 0;

}/* pkp_setup_direct_operation */

/*
 * Unmap the bus addresses
 */
void pkp_unsetup_direct_operation(cavium_device *pdev,
      struct PKP_DIRECT_OPERATION_STRUCT *pkp_direct_operation)
{
      if(pkp_direct_operation->dptr_baddr)   
            cavium_unmap_kernel_buffer(pdev, 
                   pkp_direct_operation->dptr_baddr,
                   pkp_direct_operation->dlen,
                    CAVIUM_PCI_DMA_BIDIRECTIONAL);

      if(pkp_direct_operation->rptr_baddr)   
            cavium_unmap_kernel_buffer(pdev, 
                pkp_direct_operation->rptr_baddr,
                     pkp_direct_operation->rlen + COMPLETION_CODE_SIZE,
                      CAVIUM_PCI_DMA_BIDIRECTIONAL);
}/* pkp_unsetup_direct_operation */
/*
 * Scatter/Gather functions 
 */
int pkp_setup_sg_operation(cavium_device *pdev, 
            Csp1OperationBuffer * csp1_operation, 
            struct PKP_SG_OPERATION_STRUCT * pkp_sg_operation)
{
   Uint32 in_component, out_component, rem_ptr, comp,j;
   int i,test=0;
   volatile struct PKP_4_SHORTS *p;
   volatile struct CSP1_SG_LIST_COMPONENT *sg_comp;
   volatile Uint64 *completion_address;

   MPRINTFLOW();
   comp=0;
   memset(pkp_sg_operation, 0, sizeof(struct PKP_SG_OPERATION_STRUCT));

   pkp_sg_operation->cmd_bytes = ((Uint64)csp1_operation->opcode) << 48
                                   | ((Uint64)csp1_operation->size << 32)
                                     | ((Uint64)csp1_operation->param << 16)
                                     | csp1_operation->dlen;
        pkp_sg_operation->ctx = csp1_operation->ctx_ptr;
   pkp_sg_operation->incnt = csp1_operation->incnt;
   pkp_sg_operation->outcnt = csp1_operation->outcnt;

   /* map all user input buffers */
   for(j=0;j<pkp_sg_operation->incnt; j++)
   {
      pkp_sg_operation->inbuffer[j].size = csp1_operation->insize[j];
      pkp_sg_operation->inbuffer[j].vaddr = (ptrlong)CAST_FRM_X_PTR(csp1_operation->inptr[j]);
      pkp_sg_operation->inbuffer[j].baddr = 
         cavium_map_kernel_buffer(pdev, CAST_FRM_X_PTR(csp1_operation->inptr[j]), csp1_operation->insize[j], CAVIUM_PCI_DMA_BIDIRECTIONAL);
         if(!pkp_sg_operation->inbuffer[j].baddr)
    {
           Uint32 k;
      for(k=0; k<j; k++)
      {
               cavium_unmap_kernel_buffer(pdev, 
                                  pkp_sg_operation->inbuffer[k].baddr, 
                                  pkp_sg_operation->inbuffer[k].size,
                                  CAVIUM_PCI_DMA_BIDIRECTIONAL);
      }
            cavium_print(" Unable map kernel buffer\n");
      return 1;
   }
      pkp_sg_operation->inunit[j] = csp1_operation->inunit[j];

      cavium_dbgprint("sg:%d:size=%d, ptr=0x%lx\n",j, pkp_sg_operation->inbuffer[j].size, \
                                                    pkp_sg_operation->inbuffer[j].vaddr);
      if(cavium_debug_level > 2)
      {
         cavium_dump("data",(Uint8 *)CAST_FRM_X_PTR(csp1_operation->inptr[j]), csp1_operation->insize[j]);
      }
    }

   /* map all user output buffers */
   for(j=0;j<pkp_sg_operation->outcnt; j++)
   {
      pkp_sg_operation->outbuffer[j].size = csp1_operation->outsize[j];
      pkp_sg_operation->outbuffer[j].vaddr = (ptrlong)CAST_FRM_X_PTR(csp1_operation->outptr[j]);
      pkp_sg_operation->outbuffer[j].baddr =
         cavium_map_kernel_buffer(pdev, CAST_FRM_X_PTR(csp1_operation->outptr[j]), csp1_operation->outsize[j], CAVIUM_PCI_DMA_BIDIRECTIONAL);   
         if(!pkp_sg_operation->outbuffer[j].baddr)
    {
           Uint32 k;
      for(k=0; k<j; k++)
      {
               cavium_unmap_kernel_buffer(pdev, 
                                       pkp_sg_operation->outbuffer[k].baddr, 
                                       pkp_sg_operation->outbuffer[k].size,
                                       CAVIUM_PCI_DMA_BIDIRECTIONAL);
      }

         for(k=0;k<pkp_sg_operation->incnt; k++)
      {
               cavium_unmap_kernel_buffer(pdev, 
                                  pkp_sg_operation->inbuffer[k].baddr, 
                                  pkp_sg_operation->inbuffer[k].size,
                                  CAVIUM_PCI_DMA_BIDIRECTIONAL);
      }
            cavium_print(" Unable map kernel buffer\n");
      return 1;
    }
      pkp_sg_operation->outunit[j] = csp1_operation->outunit[j];
      cavium_dbgprint("%d:size=%d, ptr=0x%lx\n",j, pkp_sg_operation->outbuffer[j].size, \
                                                     pkp_sg_operation->outbuffer[j].vaddr);
    }


   /* first do the input/gather side */
   if(csp1_operation->incnt != 0)
   {
      check_endian_swap(pkp_sg_operation, CAVIUM_SG_READ);
      pkp_sg_operation->gather_list_size = csp1_operation->incnt;
      in_component = (csp1_operation->incnt + 3)/4;
   }
   else
   {
      pkp_sg_operation->gather_list_size=1;
      in_component = 1;
   }
   
   /* now do output/scatter side*/
   if(csp1_operation->outcnt != 0)
   {
      /* No need to do check_endian_swap on output side right now. 
      That would be done after the request is completed*/

      pkp_sg_operation->scatter_list_size = csp1_operation->outcnt;
      out_component = ( csp1_operation->outcnt + 3)/4;
   }
   else
   {
      pkp_sg_operation->scatter_list_size=1;
      out_component = 1;
   }

   /* now allocate memory for DMA'able scatter/gather buffer */
   test=0;
   pkp_sg_operation->sg_dma_size = 8 + ( (in_component + out_component) * 40);
   pkp_sg_operation->sg_dma = (volatile Uint64 *)get_sg_dma(pdev, &test);
   if(test)
   {
      cavium_print("Unable to create pkp_sg_dma\n");
      /* unmap all buffers */
      pkp_unmap_user_buffers(pdev, pkp_sg_operation);
      return 1;
   }

   if(!pkp_sg_operation->sg_dma)
   {
      cavium_print("Unable to get sg_dma_virt address\n");
      /* unmap all buffers */
      pkp_unmap_user_buffers(pdev, pkp_sg_operation);
      return 1;
   }

   /* map sg_dma buffer*/
   pkp_sg_operation->sg_dma_baddr = 
      (ptrlong)cavium_map_kernel_buffer(pdev, (volatile Uint8 *)pkp_sg_operation->sg_dma,
            pkp_sg_operation->sg_dma_size,
            CAVIUM_PCI_DMA_TODEVICE);   
   if(!pkp_sg_operation->sg_dma_baddr)
   {   
      /* unmap all buffers */
      pkp_unmap_user_buffers(pdev, pkp_sg_operation);
      cavium_print(" Unable map kernel buffer\n");
      return 1;
   }
   
   p = (volatile struct PKP_4_SHORTS *)pkp_sg_operation->sg_dma;
   
   p->short_val[0] = 0;
   p->short_val[1] = 0;
   
   p->short_val[2] = pkp_sg_operation->gather_list_size;
   p->short_val[3] = pkp_sg_operation->scatter_list_size;

   sg_comp = (volatile struct CSP1_SG_LIST_COMPONENT *)((volatile Uint8 *)(pkp_sg_operation->sg_dma) + 8);
  
  /* now we have the starting point to all gather and then scatter components */
   if(pkp_sg_operation->incnt)
   {
      rem_ptr = pkp_sg_operation->incnt%4;
      comp = 0;
      
      for(i=0; i<(int)(pkp_sg_operation->incnt/4); i++)
      {
         for(j=0; j<4; j++)
         {
            sg_comp[i].length[j] = (Uint16)pkp_sg_operation->inbuffer[comp].size;
            sg_comp[i].ptr[j] = (Uint64)pkp_sg_operation->inbuffer[comp].baddr;
            comp++;
         }
      }
      
      /* now copy the remaining pointers*/
      for(j=0; j<rem_ptr; j++)
      {
         sg_comp[i].length[j] = (Uint16)pkp_sg_operation->inbuffer[comp].size;
         sg_comp[i].ptr[j] = (Uint64)pkp_sg_operation->inbuffer[comp].baddr;
         comp++;
      }
   }
   else
   {
      /*since there is no incnt so I will set all pointers and all lengths to zero */
      for(j=0; j<4; j++)
      {
         sg_comp[0].length[j] = 0;
         sg_comp[0].ptr[j] = 0;
      }
   }


   /* now make sg_comp point to scatter components*/
   sg_comp = &sg_comp[in_component];

   /* repeat the same steps for scatter compnents */
   if(pkp_sg_operation->outcnt)
   {
      rem_ptr = pkp_sg_operation->outcnt%4;
      comp=0;
      
      for(i=0; i<(int)(pkp_sg_operation->outcnt/4); i++)
      {
         for(j=0; j<4; j++)
         {
            sg_comp[i].length[j] = (Uint16)pkp_sg_operation->outbuffer[comp].size;
            sg_comp[i].ptr[j] = (Uint64)pkp_sg_operation->outbuffer[comp].baddr;
            comp++;
         }
      }
      
      /* now copy the remaining pointers*/
      for(j=0; j<rem_ptr; j++)
      {
         sg_comp[i].length[j] = (Uint16)(Uint16)pkp_sg_operation->outbuffer[comp].size;
         sg_comp[i].ptr[j] = (Uint64)pkp_sg_operation->outbuffer[comp].baddr;
         comp++;
      }
   }
   else
   {
      /*since there is no incnt so I will set all pointers and all lengths to zero */
      for(j=0; j<4; j++)
      {
         sg_comp[0].length[j] = 0;
         sg_comp[0].ptr[j] = 0;
      }
   }

   /* Format scatter/gather list depending upon system endianness. */
   pkp_convert_sg_to_int_format(pkp_sg_operation);

   /* Now setup completion code */
   pkp_sg_operation->completion_dma = (volatile Uint64 *)get_completion_dma(pdev,&test);
   if(test)
   {
      cavium_print("Unable to allocate pkp_completion_dma\n");
      cavium_unmap_kernel_buffer(pdev, 
            pkp_sg_operation->sg_dma_baddr,
            pkp_sg_operation->sg_dma_size,
            CAVIUM_PCI_DMA_TODEVICE);
      put_sg_dma(pdev, (volatile Uint8 *)pkp_sg_operation->sg_dma);
      pkp_sg_operation->sg_dma=NULL;
      /* unmap all buffers */
      pkp_unmap_user_buffers(pdev, pkp_sg_operation);
      return 1;
   }

   /* flush all user buffers. */
   pkp_flush_input_buffers(pdev,pkp_sg_operation);

   /* flush sg */
   cavium_flush_cache(pdev, pkp_sg_operation->sg_dma_size, 
      (Uint8 *)pkp_sg_operation->sg_dma,
      pkp_sg_operation->sg_dma_baddr,
      CAVIUM_PCI_DMA_BIDIRECTIONAL);

   completion_address = (volatile Uint64 *)pkp_sg_operation->completion_dma;
   *completion_address = COMPLETION_CODE_INIT;
   /* no need of flushing completion_dma because it was allocated i
    * from non-cached memory*/

   if(cavium_debug_level > 1)
      cavium_dump("scatter_gather", (volatile Uint8 *)pkp_sg_operation->sg_dma,    \
                                    pkp_sg_operation->sg_dma_size);

   return 0;

}/* pkp_setup_sg_operation */




void check_endian_swap(   struct PKP_SG_OPERATION_STRUCT *pkp_sg_operation, int rw)
{
   int i;
   volatile Uint64 *p;
   Uint8 temp[8];
   MPRINTFLOW();

   if(rw == CAVIUM_SG_READ)
   {
      if(pkp_sg_operation->incnt)
      {
         for(i=0; i<pkp_sg_operation->incnt; i++)
         {
            if((pkp_sg_operation->inbuffer[i].size) && (pkp_sg_operation->inunit[i] == UNIT_64_BIT))
            {
               if(pkp_sg_operation->inbuffer[i].size != 8)
               {
                  cavium_print("pkp_check_endian_swap: got UNIT_64_BIT but more than 8 bytes\n");
                  continue;
               }
               else
               {
                  cavium_memcpy(temp, (Uint8 *)pkp_sg_operation->inbuffer[i].vaddr, 8);
                  p = (volatile Uint64 *)temp;
                  *p = htobe64(*p);
                  cavium_memcpy((Uint8*)pkp_sg_operation->inbuffer[i].vaddr,temp,8);
               }
            } /*if UINIT_64_BIT */
         }/* for incnt*/
      } /* if incnt */  
   } /* READ */
   else
   {
     if(pkp_sg_operation->outcnt)
    {
       for(i=0; i<pkp_sg_operation->outcnt; i++)
       {
          if((pkp_sg_operation->outbuffer[i].size) && (pkp_sg_operation->outunit[i] == UNIT_64_BIT))
          {
             if(pkp_sg_operation->outbuffer[i].size != 8)
             {
                cavium_print("pkp_check_endian_swap: got UNIT_64_BIT but more than 8 bytes\n");
                continue;
             }
             else
             {
                cavium_memcpy(temp, (Uint8 *)pkp_sg_operation->outbuffer[i].vaddr, 8);
                p = (volatile Uint64 *)temp;
                *p = htobe64(*p);
                cavium_memcpy((Uint8 *)pkp_sg_operation->outbuffer[i].vaddr,temp,8);
             }
          } /*if UNIT_64_BIT */
       }/* for outcnt*/
    } /* if outcnt */  
   } /* if WRITE */
}/*check_endian_swap*/


void pkp_convert_sg_to_int_format(struct PKP_SG_OPERATION_STRUCT *pkp_sg_operation)
{
   volatile Uint64 *p;
   Uint16 i, gather_count, scatter_count;
   volatile struct PKP_4_SHORTS *short_list;
   volatile Uint64 *pkp_sg_dma;
   pkp_sg_dma = pkp_sg_operation->sg_dma;
   MPRINTFLOW();
   short_list = (volatile struct PKP_4_SHORTS *)pkp_sg_dma;
   gather_count = short_list->short_val[2];
   scatter_count = short_list->short_val[3];
   p = (volatile Uint64 *)pkp_sg_dma;

   /* first do the header */
#if __CAVIUM_BYTE_ORDER == __CAVIUM_LITTLE_ENDIAN
   *p = SWAP_SHORTS_IN_64(*p);
#endif

   /* now loop through each component and convert to integer format */

   p = (volatile Uint64 *)((pkp_sg_dma + 1));

   for(i=0; i<((gather_count +3)/4+ (scatter_count+3)/4); i++)
   {
#if __CAVIUM_BYTE_ORDER == __CAVIUM_LITTLE_ENDIAN
      *p = SWAP_SHORTS_IN_64(*p);
#endif

      p++;
   
      *p = htobe64(*p);
      p++;

      *p = htobe64(*p);
      p++;

      *p = htobe64(*p);
      p++;
  
      *p = htobe64(*p);
      p++;
   } 

}/* pkp_convert_sg_to_int_format */


/*
 * Unmap all inpout and output buffers provided by the application
 */
void pkp_unmap_user_buffers(cavium_device *pdev,struct PKP_SG_OPERATION_STRUCT *pkp_sg_operation)
{
   int j;

   MPRINTFLOW();
   /* unmap all user input buffers */
   for(j=0;j<pkp_sg_operation->incnt; j++)
   {
      cavium_unmap_kernel_buffer(pdev,pkp_sg_operation->inbuffer[j].baddr, \
                                 pkp_sg_operation->inbuffer[j].size, \
                                 CAVIUM_PCI_DMA_BIDIRECTIONAL);
      pkp_sg_operation->inbuffer[j].baddr = 0;
    }

   /* unmap all user output buffers */
   for(j=0;j<pkp_sg_operation->outcnt; j++)
   {
      cavium_unmap_kernel_buffer(pdev,pkp_sg_operation->outbuffer[j].baddr, pkp_sg_operation->outbuffer[j].size, CAVIUM_PCI_DMA_BIDIRECTIONAL);
      pkp_sg_operation->outbuffer[j].baddr = 0;
    }

}/*pkp_unmap_user_buffers*/


/*
 * Flushed the contents of all user buffers.
 */
void 
pkp_flush_input_buffers(cavium_device *pdev,struct PKP_SG_OPERATION_STRUCT *pkp_sg_operation)
{
   int j;
   Uint32 size;
   ptrlong  vaddr, baddr;

    MPRINTFLOW();
   /* flush all user input buffers */
   for(j=0;j<pkp_sg_operation->incnt; j++)
   {
      size = pkp_sg_operation->inbuffer[j].size;
      vaddr = pkp_sg_operation->inbuffer[j].vaddr;
      baddr = pkp_sg_operation->inbuffer[j].baddr;
      cavium_flush_cache(pdev,size,vaddr,baddr,CAVIUM_PCI_DMA_BIDIRECTIONAL);
    }
} /* pkp_flush_input_buffers */

void 
pkp_invalidate_output_buffers(cavium_device *pdev,struct PKP_SG_OPERATION_STRUCT *pkp_sg_operation)
{
   int j;
   Uint32 size;
   ptrlong vaddr, baddr;

    MPRINTFLOW();
   /* flush all user output buffers */
   for(j=0;j<pkp_sg_operation->outcnt; j++)
   {
      size = pkp_sg_operation->outbuffer[j].size;
      vaddr = pkp_sg_operation->outbuffer[j].vaddr;
      baddr = pkp_sg_operation->outbuffer[j].baddr;
      cavium_invalidate_cache(pdev,size,vaddr,baddr,CAVIUM_PCI_DMA_BIDIRECTIONAL);
    }

}/*pkp_invalidate_output_buffers*/



/* Initialize the group list. Initially all groups are available. */
void
init_npx_group_list(void)
{
    int i;

    for(i = 0; i < NITROX_PX_MAX_GROUPS; i++) {
        npx_group[i].status = AVAILABLE;
        npx_group[i].core_grp = NITROX_PX_MAX_GROUPS;
    }
}

/* Get the next free core group number. There cannot be more than
   4 core groups. If none are available return -1.
*/
Uint8
get_next_npx_group(void)
{
    Uint8 i;

    for(i = 0; i < NITROX_PX_MAX_GROUPS; i++) {
        if(npx_group[i].status == AVAILABLE) {
            npx_group[i].status = USED;
            return i;
        }
    }
    return i;
}


/* Mark a core group as available for reuse */
void
free_npx_group(Uint8  core_grp)
{
    if(core_grp >= NITROX_PX_MAX_GROUPS) {
        cavium_error("free_npx_group: Incorrect core_grp: 0x%x\n", core_grp);
        return;
    }
    if(npx_group[core_grp].status == AVAILABLE) {
        cavium_error("free_npx_group: Core Group 0x%x is already free\n",
                     core_grp);
        return;
    }
    npx_group[core_grp].status = AVAILABLE;
}



/*
 * $Id: cavium.c,v 1.15 2009/09/09 11:26:19 aravikumar Exp $
 * $Log: cavium.c,v $
 * Revision 1.15  2009/09/09 11:26:19  aravikumar
 * NPLUS macro dependency removed and made it dynamic
 *
 * Revision 1.14  2008/12/22 05:42:10  jrana
 *  COUNTERS and INTERRUPT COALEASCING ADDED
 *
 * Revision 1.13  2008/12/16 12:04:42  jsrikanth
 * Added Common driver and Multi-Card Changes for FreeBSD
 *
 * Revision 1.12  2008/11/06 09:07:53  ysandeep
 * Removed PX_PLUS
 *
 * Revision 1.11  2008/09/30 13:15:17  jsrikanth
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
 * Revision 1.10  2007/10/18 09:35:09  lpathy
 * Added windows support.
 *
 * Revision 1.9  2007/07/03 11:46:45  kchunduri
 * --Invoke modified 'completion_dma_free_list' API.
 *
 * Revision 1.8  2007/06/11 13:41:07  tghoriparti
 * cavium_mmap_kernel_buffers return values handled properly when failed.
 *
 * Revision 1.7  2007/06/06 08:49:53  rkumar
 * Cache invalidation in check_for_completion() added
 *
 * Revision 1.6  2007/03/19 23:51:04  panicker
 * * Include rlen + completion code bytes when mapping rptr in direct mode.
 *   (warnings seen in FC5 otherwise for outbufs with space for completion code only, in which case rlen would be 0).
 *
 * Revision 1.5  2007/03/08 20:43:33  panicker
 * * NPLUS mode changes. pre-release
 * * NitroxPX now supports N1-style NPLUS operation.
 * * Native PX mode PLUS operations are enabled only if PX_PLUS flag is enabled
 *
 * Revision 1.4  2007/03/06 03:18:26  panicker
 * * new routines to maintain core groups for NitroxPX in PLUS mode -
 *   init_npx_group_list(), get_next_npx_group(), free_npx_group().
 *
 * Revision 1.3  2007/02/02 02:25:04  panicker
 * * Prints modified
 * * cmd_bytes - a new field in PKP_DIRECT_OPERATION_STRUCT to store the command bytes of a request
 *
 * Revision 1.2  2007/01/11 01:53:46  panicker
 * * - soft_req_queue.h is included only if !(NITROX_PX).
 *   - check_completion() uses non-NPLUS mode for PX.
 *
 * Revision 1.1  2007/01/06 02:47:40  panicker
 * * first cut - NITROX PX driver
 *
 * Revision 1.26  2006/09/28 08:51:37  kchunduri
 * --avoid dmap_map when 'dptr' is NULL
 *
 * Revision 1.25  2006/08/16 04:40:46  kchunduri
 * --fix for compilation warning on FreeBSD-4.11
 *
 * Revision 1.24  2006/08/08 13:29:31  kchunduri
 * fix warning message
 *
 * Revision 1.23  2006/05/16 09:33:48  kchunduri
 * --support for Dynamic DMA mapping instead of virt_to_phys
 *
 * Revision 1.22  2006/03/24 09:47:07  pyelgar
 *   - Checkin of Scatter/Gather code changes in driver and IPSec.
 *
 * Revision 1.21  2005/12/07 04:50:59  kanantha
 * modified to support both 32 and 64 bit versions
 *
 * Revision 1.20  2005/11/17 13:31:09  kanantha
 * Updating with the 64 bit modifications, with proper matching of data types
 *
 * Revision 1.19  2005/10/24 06:51:36  kanantha
 * - Fixed RHEL4 warnings
 *
 * Revision 1.18  2005/10/13 09:19:32  ksnaren
 * fixed compile warnings
 *
 * Revision 1.17  2005/09/28 15:50:26  ksadasivuni
 * - Merging FreeBSD 6.0 AMD64 Release with CVS Head
 * - Now context pointer given to user space applications is physical pointer.
 *   So there is no need to do cavium_vtophys() of context pointer.
 *
 * Revision 1.16  2005/09/06 07:11:23  ksadasivuni
 * - Merging FreeBSD 4.11 release with CVS Head
 *
 * Revision 1.15  2005/06/13 06:35:42  rkumar
 * Changed copyright
 *
 * Revision 1.14  2005/02/01 04:11:07  bimran
 * copyright fix
 *
 * Revision 1.13  2004/07/21 23:24:41  bimran
 * Fixed MC2 completion code issues on big endian systems.
 *
 * Revision 1.12  2004/07/09 01:08:59  bimran
 * fixed scatter gather support
 *
 * Revision 1.11  2004/06/28 20:37:42  tahuja
 * Fixed compiler warnings on NetBSD. changed mdelay in check_completion from 1ms to 2ms.
 *
 * Revision 1.10  2004/06/23 19:39:22  bimran
 * changed check_completion to accept volatile comp_addr
 *
 * Revision 1.9  2004/06/23 19:29:23  bimran
 * Fixed compiler warnings on NetBSD.
 * changed READ to CAVIUM_SG_READ.
 *
 * Revision 1.8  2004/06/03 21:21:58  bimran
 * included cavium_list.h
 * fixed list* calls to use cavium_list
 *
 * Revision 1.7  2004/06/01 17:43:28  bimran
 * changed check_completion to not to sleep.
 *
 * Revision 1.6  2004/05/11 03:10:24  bimran
 * some performance opt.
 *
 * Revision 1.5  2004/05/02 19:44:29  bimran
 * Added Copyright notice.
 *
 * Revision 1.4  2004/04/21 19:18:57  bimran
 * NPLUS support.
 *
 * Revision 1.3  2004/04/17 00:59:32  bimran
 * fixed check completion to sleep instead of busy looping.
 *
 * Revision 1.2  2004/04/16 03:17:50  bimran
 * removed a print.
 *
 * Revision 1.1  2004/04/15 22:40:48  bimran
 * Checkin of the code from India with some cleanups.
 *
 */

