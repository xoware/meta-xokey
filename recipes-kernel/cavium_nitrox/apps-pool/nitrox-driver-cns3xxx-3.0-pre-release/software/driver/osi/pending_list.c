/* pending_list.c */
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
#include "error_handler.h"
#include "pending_free_list.h"
#include "pending_list.h"
#include "direct_free_list.h"
#include "context_memory.h"
#include "sg_free_list.h"
#include "sg_dma_free_list.h"
#include "completion_dma_free_list.h"
#include "pending_list.h"
#include "request_manager.h"
#include "soft_req_queue.h"

extern int MAX_CORES;
extern Uint32 cavium_command_timeout;
extern int dev_count;
extern short nplus, ssl, ipsec;
extern cavium_device cavium_dev[];
#ifdef COUNTER_ENABLE
extern Uint32 enc_pkt_err;
extern Uint32 dec_pkt_err;
extern Uint32 enc_rec_pkt_err;
extern Uint32 dec_rec_pkt_err;
extern Uint32 in_ipsec_pkt_err;
extern Uint32 out_ipsec_pkt_err;
extern Uint32 hmac_pkt_err;
uint16_t opcode16;
uint8_t major_op;
uint8_t minor_op;
#endif


/*
void finalize_request(cavium_device *pdev,
      struct PENDING_ENTRY *entry, 
      Csp1ResponseOrder response_order);
*/

cavium_spinlock_t check_completion_lock = CAVIUM_SPIN_LOCK_UNLOCKED;
#ifdef INTERRUPT_ON_COMP
int pending_count = 0;
#endif

#ifdef DUMP_FAILING_REQUESTS

#define cavium_error_dump(str_,buf_,len_) \
{ \
   Uint32 i_=0; \
   cavium_error("%s\n",str_); \
   cavium_error("0x%04X : ", i_*8); \
   for (i_=0;i_<(Uint32)(len_);i_++){    \
      if(i_ && ((i_%8) == 0)) \
      { \
         cavium_error( "%s", "\n"); \
         cavium_error("0x%04X : ", (i_)); \
      } \
      cavium_error("%02x ",(buf_)[i_]);\
   } \
   cavium_error("\n%s\n",str_); \
}

static void
cavium_request_dump(cavium_device *pdev,
                    n1_request_buffer *req, int status,
                    struct PENDING_ENTRY *entry)
{
   int i;
   Uint8 *ctx = NULL;
#define DUMP_COUNT 0
#if DUMP_COUNT
   static int count = 0;
   if (count > DUMP_COUNT)
      return;
   count++;
#endif
   cavium_error("FAILED REQUEST.. dumping data:\n");
   cavium_error("-------- PKP registers ------------- \n");
   dump_pkp_registers(pdev);
   cavium_error("-------- PCI Config registers ------------- \n");
   dump_config_registers(pdev);
   cavium_error(" -------- Failed Request details ----------- \n");
   cavium_error("Request failed with status 0x%08x \n", status);
   cavium_error("Opcode: 0x%02x Size: 0x%02x Param: 0x%02x dlen: 0x%02x\n",
                  req->opcode, req->size, req->param, req->dlen);
   cavium_error("rlen: 0x%02x \n", req->rlen);

   if (entry->dma_mode == CAVIUM_DIRECT) {
      struct PKP_DIRECT_OPERATION_STRUCT *dir;
      dir = (struct PKP_DIRECT_OPERATION_STRUCT *)entry->pkp_operation;
      cavium_error("Direct Mode Request\n");
      cavium_error("Dptr [Bus Addr: 0x%016llx Virt Addr: 0x%016llx]\n",
                    dir->dptr_baddr, CAST_TO_X_PTR(dir->dptr));
      cavium_error("Rptr [Bus Addr: 0x%016llx Virt Addr: 0x%016llx]\n",
                    dir->rptr_baddr, CAST_TO_X_PTR(dir->rptr));
   } else {
      struct PKP_SG_OPERATION_STRUCT *sg;
      sg = (struct PKP_SG_OPERATION_STRUCT *)entry->pkp_operation;
      cavium_error("SG Mode Request\n");
      cavium_error("Gather list size: %d Scatter list size: %d\n", sg->gather_list_size, sg->scatter_list_size);
      cavium_error("SG DMA buffer size %d\n", sg->sg_dma_size);
      cavium_error("SG DMA buffer address: 0x%016llx \n",
      CAST_TO_X_PTR(sg->sg_dma));
      cavium_error("SG DMA bus address: 0x%016llx \n",CAST_TO_X_PTR(sg->sg_dma_baddr));
      cavium_error_dump("SG buffer", ((Uint8 *)(sg->sg_dma)), sg->sg_dma_size);
    }
    if (req->ctx_ptr) {
       ctx = find_host_ctx(pdev,(Uint64)(req->ctx_ptr - req->reserved));
       if (ctx) {
          cavium_error("Context [Bus Addr %016llx Virt Addr %016llx]\n",
                        req->ctx_ptr, (Uint64)(ptrlong)ctx);
       } else {
          cavium_error("Unable to get the Virt address for ctx %016llx\n",
                         req->ctx_ptr);
          }
    } else {
         cavium_error("Context is NULL\n");
  }

   if (req->callback == CAST_TO_X_PTR(user_scatter)) {
      /* User space request */
      n1_user_info_buffer *ub = (n1_user_info_buffer *)(entry->cb_arg);
      cavium_error_dump("Input", ub->in_buffer, ub->in_size);
      cavium_error_dump("Output", ub->out_buffer, ub->out_size);
   } else {
      cavium_error("Input");
      for (i = 0; i < req->incnt; i++) {
         Uint8 *ptr = (Uint8*)(CAST_FRM_X_PTR(req->inptr[i]));
         cavium_error_dump("", ptr, (req->insize[i]));
      }
      cavium_error("Input END");
      cavium_error("Output");
      for (i = 0; i < req->outcnt; i++) {
         Uint8 *ptr = (Uint8*)(CAST_FRM_X_PTR(req->outptr[i]));
         cavium_error_dump("", ptr, req->outsize[i]);
      }
       cavium_error("Output END");
    }

   if (ctx)
      cavium_error_dump("Context Data", ctx, 1024);
   cavium_error("Opcode: 0x%02x Size: 0x%02x Param: 0x%02x dlen: 0x%02x\n",
                  req->opcode, req->size, req->param, req->dlen);
   cavium_error("rlen: 0x%02x \n", req->rlen);
   cavium_error("Request failed with status 0x%08x \n", status);
   cavium_error("-------- Failed Request details END ----------- \n");

   return;
}

#endif


int
check_srq_state(cavium_device *pdev, int ucode_idx, int srq_idx)
{
   softreq_t *srq;
   int state;

   MPRINTFLOW();
   /* Lock the microcode-cores structure */
   cavium_spin_lock_softirqsave(&(pdev->mc_core_lock));
   srq = &(pdev->microcode[ucode_idx].srq);
   /* Lock the SRQ */
   cavium_spin_lock_softirqsave(&(srq->lock));
   state = srq->state[srq_idx];
   /* Unlock the SRQ */
   cavium_spin_unlock_softirqrestore(&(srq->lock));
   /* Unlock the microcode-cores structure */
   cavium_spin_unlock_softirqrestore(&(pdev->mc_core_lock));
   return state;
}


/*
 * Pending list initialization.
 */
void
init_pending_lists()
{
    int i=0;
    MPRINTFLOW();
    for(i=0; i<dev_count; i++)
    {    
   CAVIUM_INIT_LIST_HEAD(&((&cavium_dev[i])->ordered_list_head));
   CAVIUM_INIT_LIST_HEAD(&((&cavium_dev[i])->unordered_list_head));

   cavium_spin_lock_init(&((&cavium_dev[i])->ordered_list_lock));
   cavium_spin_lock_init(&((&cavium_dev[i])->unordered_list_lock));
     }
   cavium_spin_lock_init(&check_completion_lock);
}/*init_pending_lists*/

void
cleanup_pending_lists(void)
{
   int i=0;
   MPRINTFLOW();
   for(i=0; i<dev_count; i++)
   {
      cavium_spin_lock_destroy(&((&cavium_dev[i])->ordered_list_lock));
      cavium_spin_lock_destroy(&((&cavium_dev[i])->unordered_list_lock));
   }
   cavium_spin_lock_destroy(&check_completion_lock);
}

#define THRESHOLD_PENDING_COUNT 10
#define LOW_THRESHOLD_PENDING_COUNT 5
/*
 * Push to Ordered pending queue.
 */
void push_pending_ordered(cavium_device *n1_dev, struct PENDING_ENTRY *entry)
{
   MPRINTFLOW();
#ifdef INTERRUPT_ON_COMP
   pending_count++;
#endif
   cavium_spin_lock_softirqsave(&(n1_dev->ordered_list_lock));
   cavium_list_add_tail(&entry->list, &(n1_dev->ordered_list_head));
   cavium_spin_unlock_softirqrestore(&(n1_dev->ordered_list_lock));
}/* push_pending_ordered*/


/*
 * Push to Record Processing pending queue.
 */
__inline void push_pending_unordered(cavium_device *n1_dev, struct PENDING_ENTRY *entry)
{
   MPRINTFLOW();
#ifdef INTERRUPT_ON_COMP
   pending_count++;
#endif
   cavium_spin_lock_softirqsave(&(n1_dev->unordered_list_lock));
   cavium_list_add_tail(&entry->list, &(n1_dev->unordered_list_head));
   cavium_spin_unlock_softirqrestore(&(n1_dev->unordered_list_lock));
}/* push_pending_unordered*/



/*
 * Push pending structure to the corresponding queue 
 */
void push_pending(cavium_device *n1_dev, struct PENDING_ENTRY *entry, Csp1ResponseOrder response_order)
{
    MPRINTFLOW();
#ifdef ENABLE_CAVIUM_UNORDERED
   if(response_order == CAVIUM_RESPONSE_ORDERED)
      push_pending_ordered(n1_dev, entry);
   else
      push_pending_unordered(n1_dev, entry);
#else
   push_pending_ordered(n1_dev, entry);
#endif
}/* push_pending*/



void check_for_completion_callback(void *pdev)
{
 cavium_device *dev  = (cavium_device *)pdev;
 /*//unsigned int flags=0;*/

/* //cavium_spin_lock_irqsave(&check_completion_lock, flags);*/
/* cavium_spin_lock_softirqsave(&check_completion_lock); */

 /* clear the interrupt status */
/* write_PKP_register(dev,(dev->bar_0 + ISR_REG), 8);*/

#ifdef ENABLE_CAVIUM_UNORDERED
   /* poll ordered first */
   poll_pending_ordered(dev);

   /* now poll others */
   poll_pending_unordered(dev);

#else
   /* poll ordered only */
   poll_pending_ordered(dev);

#endif /*ENABLE_CAVIUM_UNORDERED*/

 /*//cavium_spin_unlock_irqrestore(&check_completion_lock, flags);*/
/*  cavium_spin_unlock_softirqrestore(&check_completion_lock); */
}/*check_for_completion_callback*/


/*
 * get entry at the head of the ordered queue
 */
__inline struct PENDING_ENTRY *  
get_queue_head_ordered(cavium_device *n1_dev)
{
   struct PENDING_ENTRY *pending_entry;
   struct cavium_list_head *first;

/*//   cavium_spin_lock_softirqsave(&ordered_list_lock);*/

   if(n1_dev->ordered_list_head.next != &(n1_dev->ordered_list_head))
   {
      first = n1_dev->ordered_list_head.next;
      pending_entry = cavium_list_entry(first, struct PENDING_ENTRY, list);
   }
   else
      pending_entry =NULL;

/* //  cavium_spin_unlock_softirqrestore(&ordered_list_lock);*/
   return pending_entry;
}/*get_queue_head_ordered*/


/*
 * get entry at the head of the unordered queue
 */
__inline struct PENDING_ENTRY *  
get_queue_head_unordered(cavium_device *n1_dev)
{
   struct PENDING_ENTRY *pending_entry;
   struct cavium_list_head *first;

   MPRINTFLOW();
/*   //cavium_spin_lock_softirqsave(&unordered_list_lock);*/

   if(n1_dev->unordered_list_head.next != &(n1_dev->unordered_list_head))
   {
      first = n1_dev->unordered_list_head.next;
      pending_entry = cavium_list_entry(first, struct PENDING_ENTRY, list);
   }
   else
      pending_entry =NULL;

/*   //cavium_spin_unlock_softirqrestore(&unordered_list_lock);*/
   return pending_entry;
}/*get_queue_head_unordered*/

/* Ordered list polling function */
void poll_pending_ordered(cavium_device *pdev)
{
   struct PENDING_ENTRY *entry;
   volatile Uint64 *p;
   struct PKP_DIRECT_OPERATION_STRUCT *op;

   cavium_spin_lock_softirqsave(&(pdev->ordered_list_lock));

    while((entry = get_queue_head_ordered(pdev)) != NULL)
   {
      if (entry->status != ERR_REQ_PENDING) {
         /* Lying here for some time */
         break;
      }

      p = (volatile Uint64 *)entry->completion_address;
   
      /* no need of invalidating in case of Scatter/gather
       * because completion_dma was allocated from non-cached memory
       */   
      if(entry->dma_mode == CAVIUM_DIRECT)
      {
         Uint32 size;
         ptrlong vaddr, baddr;
         struct PKP_DIRECT_OPERATION_STRUCT *dir;
         
         dir = (struct PKP_DIRECT_OPERATION_STRUCT *)entry->pkp_operation;

         size = COMPLETION_CODE_SIZE;
         vaddr = (ptrlong)dir->completion_address;
         baddr = (ptrlong) (dir->rptr_baddr + dir->rlen);

         cavium_invalidate_cache(pdev, size, vaddr, baddr,
                     CAVIUM_PCI_DMA_BIDIRECTIONAL);
      }

      if ((Uint8)(*p >> COMPLETION_CODE_SHIFT) == 0xff)
      {
         /* check for timeout */
         if(cavium_check_timeout(entry->tick+cavium_command_timeout, cavium_jiffies))
         {

            if((nplus || ssl>0 || ipsec>0) && pdev->device_id != NPX_DEVICE)
            {
               if(pdev->microcode[entry->ucode_idx].code_type == CODE_TYPE_SPECIAL)   {
                  if(cavium_check_timeout(entry->tick+cavium_command_timeout*(MAX_SRQ_TIMEOUT + 1), cavium_jiffies)) {
                     if (del_srq_entry(pdev, entry->ucode_idx, entry->srq_idx, (Uint64 *)entry->completion_address) < 0) {
                        entry->tick = cavium_jiffies;
                        break;
                     }
                     entry->status = ERR_REQ_TIMEOUT;
                     finalize_request(pdev, entry, CAVIUM_RESPONSE_ORDERED);
                     continue;
                      } else 
                     break;
                  } else {
                     op = (struct PKP_DIRECT_OPERATION_STRUCT *)entry->pkp_operation;
                     cavium_error("\n#--**poll_ordered: Oops! timed out; cmd=0x%016llx\n",
                     CAST64(op->cmd_bytes));
                     entry->status = ERR_REQ_TIMEOUT;
                     finalize_request(pdev, entry, CAVIUM_RESPONSE_ORDERED);
               }
         }
         else 
		 {
            op = (struct PKP_DIRECT_OPERATION_STRUCT *)entry->pkp_operation;
            cavium_error("\n#--**poll_ordered: Oops! timed out; cmd=0x%016llx\n",
                         CAST64(op->cmd_bytes));
            cavium_error("entry->tick: %ld TIMEOUT: %d jiffies: %ld\n", entry->tick, cavium_command_timeout, (ptrlong) cavium_jiffies);
            entry->status = ERR_REQ_TIMEOUT;
            finalize_request(pdev, entry, CAVIUM_RESPONSE_ORDERED);
		 }
        }
        else
           break;
      }
      else
      {
#if !defined(INTERRUPT_ON_COMP)
   /*      Uint8  ccode = (Uint8)(*p >> COMPLETION_CODE_SHIFT); */
                        Uint8 ccode = (Uint8) check_completion_code(p);
         op = (struct PKP_DIRECT_OPERATION_STRUCT *)entry->pkp_operation;
         if(ccode) {
            cavium_error("pkp_drv: (cmd: 0x%016llx) completed with error code: 0x%x\n", CAST64((ptrlong) op), ccode); 
         } else {
            cavium_dbgprint("##-- (cmd: 0x%016llx) completed with code: 0x%x\n", CAST64((ptrlong)op), ccode); 
         }
#endif


         if(nplus && pdev->device_id != NPX_DEVICE && pdev->microcode[entry->ucode_idx].code_type == CODE_TYPE_SPECIAL)
         {
            /* This is an SRQ request */
            free_srq_entries(pdev, entry->ucode_idx, entry->srq_idx, (Uint64 *)entry->completion_address);
         }
         entry->status=0;
         finalize_request(pdev, entry, CAVIUM_RESPONSE_ORDERED);
      }
      cavium_dbgprint("poll_ordered: running\n");
   } /* while */
   cavium_spin_unlock_softirqrestore(&(pdev->ordered_list_lock));

}/* poll_pending_ordered*/


/* Unordered list processing */
void poll_pending_unordered(cavium_device *pdev)
{
   struct PENDING_ENTRY *entry;
   volatile Uint64 *p;
   volatile int loop_count=0;
   struct PKP_DIRECT_OPERATION_STRUCT *op;

   cavium_spin_lock_softirqsave(&(pdev->unordered_list_lock));
   
   while((entry = get_queue_head_unordered(pdev)) != NULL)
   {
      loop_count++;
      if(loop_count > MAX_CORES)
         break;

      if (entry->status != ERR_REQ_PENDING) {
         /* Lying here for some time */
         break;
      }

      p = (volatile Uint64 *)entry->completion_address;
      /* no need of invalidating in case of Scatter/gather
       * because completion_dma was allocated from non-cached memory
       */   
      if(entry->dma_mode == CAVIUM_DIRECT)
      {
         Uint32 size;
         ptrlong vaddr, baddr;
         struct PKP_DIRECT_OPERATION_STRUCT *dir;
         
         dir = (struct PKP_DIRECT_OPERATION_STRUCT *)entry->pkp_operation;

         size = COMPLETION_CODE_SIZE;
         vaddr = (ptrlong)dir->completion_address;
         baddr = (ptrlong)dir->rptr_baddr + dir->rlen;

         cavium_invalidate_cache(pdev, size,vaddr,baddr,CAVIUM_PCI_DMA_BIDIRECTIONAL);
      }
       
      if ((Uint8)(*p >> COMPLETION_CODE_SHIFT) != 0xff)
      {
         if(nplus && pdev->device_id != NPX_DEVICE && pdev->microcode[entry->ucode_idx].code_type == CODE_TYPE_SPECIAL)
         {
         /* This is an SRQ request */
         free_srq_entries(pdev, entry->ucode_idx, entry->srq_idx, (Uint64 *)entry->completion_address);
         }
         entry->status=0;
         finalize_request(pdev,entry, CAVIUM_RESPONSE_UNORDERED);
      }
      else
      {
         /* check for timeout */
#ifdef N1_TIMER_ROLLOVER
         if(cavium_time_before(entry->tick+cavium_command_timeout,cavium_jiffies))
#else
         if((entry->tick + cavium_command_timeout) < cavium_jiffies)
#endif
         {
         if((nplus || ssl>0 || ipsec>0) && pdev->device_id != NPX_DEVICE)
         {
            if(pdev->microcode[entry->ucode_idx].code_type == CODE_TYPE_SPECIAL)
            {
#ifdef N1_TIMER_ROLLOVER
               if(cavium_time_before(entry->tick+cavium_command_timeout*(MAX_SRQ_TIMEOUT+1), cavium_jiffies))
#else
               if((entry->tick + cavium_command_timeout*(MAX_SRQ_TIMEOUT+1)) < cavium_jiffies)
#endif
               {
                  if (del_srq_entry(pdev, entry->ucode_idx, entry->srq_idx, (Uint64 *)entry->completion_address) < 0) {
                     entry->tick = cavium_jiffies;
                     break;
                  }
                  entry->status = ERR_REQ_TIMEOUT;
                  finalize_request(pdev, entry, CAVIUM_RESPONSE_UNORDERED);
                  continue;
               } else 
                            break;
            } else {
               op = (struct PKP_DIRECT_OPERATION_STRUCT *)entry->pkp_operation;
               cavium_error("poll_ordered: Oops! timed out; cmd=0x%016llx.\n",
               CAST64(op->cmd_bytes));
               entry->status = ERR_REQ_TIMEOUT;
               finalize_request(pdev, entry, CAVIUM_RESPONSE_UNORDERED);
            }
         }
          else 
		  {
            op = (struct PKP_DIRECT_OPERATION_STRUCT *)entry->pkp_operation;
            cavium_error("poll_ordered: Oops! timed out; cmd=0x%016llx.\n",
                         CAST64(op->cmd_bytes));
            entry->status = ERR_REQ_TIMEOUT;
            finalize_request(pdev, entry, CAVIUM_RESPONSE_UNORDERED);
		  }
        }
      }
            
   } /* while */
   
   cavium_spin_unlock_softirqrestore(&(pdev->unordered_list_lock));

}/* poll_pending_unordered*/



void finalize_request(cavium_device *pdev,
      struct PENDING_ENTRY *entry, 
      Csp1ResponseOrder response_order)
{
   int cond_code;
   struct PKP_DIRECT_OPERATION_STRUCT *dir;
   struct PKP_SG_OPERATION_STRUCT *sg;
   
    MPRINTFLOW();
   cavium_list_del(&entry->list);
   
   if(response_order == CAVIUM_RESPONSE_ORDERED)
     {
       cavium_spin_unlock_softirqrestore(&(pdev->ordered_list_lock));
     }
   else
     {
       cavium_spin_unlock_softirqrestore(&(pdev->unordered_list_lock));
     }
   
   if(entry->dma_mode == CAVIUM_SCATTER_GATHER)
   {
      sg = (struct PKP_SG_OPERATION_STRUCT *)entry->pkp_operation;

      if(entry->status)
         cond_code = ERR_REQ_TIMEOUT;
      else
         cond_code = check_completion_code((Uint64 *)(entry->completion_address));
#ifdef COUNTER_ENABLE
      if(cond_code)
      { 
   opcode16 = (sg->cmd_bytes >> 48) & 0xffff;
   major_op=(opcode16 & 0xff);
   minor_op=(opcode16 >> 8) & 0xff;
   switch (major_op)
   {
    case MAJOR_OP_ENCRYPT_DECRYPT:
         if(minor_op & 0x01) 
          dec_pkt_err++; 
         else 
         enc_pkt_err++;
         break;
    case MAJOR_OP_ENCRYPT_DECRYPT_RECORD:
         if(minor_op & 0x01) 
          dec_rec_pkt_err++; 
         else 
         enc_rec_pkt_err++;
         break;
    case MAJOR_OP_HMAC:
         hmac_pkt_err++;
         break;  
    case (int) OP_IPSEC_PACKET_INBOUND:
         in_ipsec_pkt_err++; 
         break; 
    case (int) OP_IPSEC_PACKET_OUTBOUND:
         out_ipsec_pkt_err++;
         break;  
default: cavium_dbgprint("No data counter related opcode");
    }
 }
#endif
         
       

      /* flush all user buffers */
      pkp_invalidate_output_buffers(pdev, sg);

      /* unmap sg buffer */
      cavium_unmap_kernel_buffer(pdev, 
            sg->sg_dma_baddr,
            sg->sg_dma_size,
            CAVIUM_PCI_DMA_TODEVICE);

      /* unmap user buffers */
      pkp_unmap_user_buffers(pdev, sg);

      /* check endianness */
      check_endian_swap(sg, CAVIUM_SG_WRITE);
               
      cavium_dbgprint("finalize_request: calling callback function\n");      
      /* make callback function call*/
#ifdef DUMP_FAILING_REQUESTS
      if (cond_code)
         cavium_request_dump(pdev, &entry->n1_buf, cond_code, entry);
#endif
      entry->callback(cond_code,entry->cb_arg);
      
      put_sg_dma(pdev, (volatile Uint8 *)sg->sg_dma);
      put_completion_dma(pdev,(volatile Uint64 *)(sg->completion_dma));
      
      put_sg_entry(pdev, sg);   
   }
   else /* presumably DIRECT ;-) */
   {
      dir = (struct PKP_DIRECT_OPERATION_STRUCT *)entry->pkp_operation;

      /* invalidate output buffer */
      cavium_invalidate_cache(pdev, dir->rlen,
         dir->rptr,
         dir->rptr_baddr, 
         CAVIUM_PCI_DMA_BIDIRECTIONAL);     

      if(entry->status)
         cond_code = ERR_REQ_TIMEOUT;
      else
         cond_code = check_completion_code((Uint64 *)(entry->completion_address));
      
#ifdef COUNTER_ENABLE
      if(cond_code)
     { 
         opcode16 = (dir->cmd_bytes >> 48) & 0xffff;
   major_op=(opcode16 & 0xff);
   minor_op=(opcode16 >> 8) & 0xff;
   switch (major_op)
   {
    case MAJOR_OP_ENCRYPT_DECRYPT:
         if(minor_op & 0x01) {
         dec_pkt_err++; 
         }
         else { 
         enc_pkt_err++;
         }
         break;
    case MAJOR_OP_ENCRYPT_DECRYPT_RECORD:
         if(minor_op & 0x01) { 
          dec_rec_pkt_err++; 
          }
         else { 
         enc_rec_pkt_err++;
        }
         break;
    case MAJOR_OP_HMAC:
         { hmac_pkt_err++;
          }
         break;  
    case (int) OP_IPSEC_PACKET_INBOUND:
         in_ipsec_pkt_err++; 
         break; 
    case (int) OP_IPSEC_PACKET_OUTBOUND:
         out_ipsec_pkt_err++;
         break;  
default: cavium_dbgprint("No data counter related opcode");
    }
}
#endif
      /* make callback function call*/
      cavium_dbgprint("calling callback %p, cond_code=0x%x\n", entry->callback, cond_code);
#ifdef DUMP_FAILING_REQUESTS
      if (cond_code)
         cavium_request_dump(pdev, &entry->n1_buf, cond_code, entry);
#endif
      entry->callback(cond_code,entry->cb_arg);

      /* unmap buffers */
                if(dir->dptr_baddr)
         cavium_unmap_kernel_buffer(pdev,dir->dptr_baddr,
            dir->dlen,CAVIUM_PCI_DMA_BIDIRECTIONAL);

      cavium_unmap_kernel_buffer(pdev,dir->rptr_baddr,
            dir->rlen+COMPLETION_CODE_SIZE,CAVIUM_PCI_DMA_BIDIRECTIONAL);
                //printk("\n in %s put_direct_entry\n",__FUNCTION__);
      put_direct_entry(pdev, dir);
   }

   if(response_order == CAVIUM_RESPONSE_ORDERED)
   {
#ifdef INTERRUPT_ON_COMP
      pending_count --;
#endif
      /*//cavium_spin_lock_softirqsave(&ordered_list_lock);*/
/*       cavium_list_del(&entry->list); */
      /*//cavium_spin_unlock_softirqrestore(&ordered_list_lock);*/
   }
   else
   {
#ifdef INTERRUPT_ON_COMP
      pending_count --;
#endif
      /*//cavium_spin_lock_softirqsave(&unordered_list_lock);*/
/*       cavium_list_del(&entry->list); */
      /*//cavium_spin_unlock_softirqrestore(&unordered_list_lock);*/
   }
       
   put_pending_entry(pdev, entry);

   if(response_order == CAVIUM_RESPONSE_ORDERED)
     {
       cavium_spin_lock_softirqsave(&(pdev->ordered_list_lock));
     }
   else
     {
       cavium_spin_lock_softirqsave(&(pdev->unordered_list_lock));
     }
}/* finalize_request*/



/*
 * $Id: pending_list.c,v 1.18 2009/09/09 11:26:19 aravikumar Exp $
 * $Log: pending_list.c,v $
 * Revision 1.18  2009/09/09 11:26:19  aravikumar
 * NPLUS macro dependency removed and made it dynamic
 *
 * Revision 1.17  2008/12/22 05:42:10  jrana
 *  COUNTERS and INTERRUPT COALEASCING ADDED
 *
 * Revision 1.16  2008/11/06 09:11:11  ysandeep
 * Removed PX_PLUS
 *
 * Revision 1.15  2008/09/30 13:15:17  jsrikanth
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
 * Revision 1.14  2008/07/02 12:35:26  aramesh
 * deleted part number and corresponding flags.
 *
 * Revision 1.13  2007/11/19 11:11:55  lpathy
 * ported to 64 bit windows.
 *
 * Revision 1.12  2007/10/18 09:35:09  lpathy
 * Added windows support.
 *
 * Revision 1.11  2007/07/03 11:46:01  kchunduri
 * --Invoke modified 'completion_dma_free_list' API.
 *
 * Revision 1.10  2007/06/18 13:33:56  tghoriparti
 * error messages disabled when INTERRUPT enabled , To be removed later
 *
 * Revision 1.9  2007/06/11 13:41:07  tghoriparti
 * cavium_mmap_kernel_buffers return values handled properly when failed.
 *
 * Revision 1.8  2007/06/06 08:54:31  rkumar
 * cavium_invalidate_cache takes improper arguments
 *
 * Revision 1.7  2007/05/11 07:59:13  kchunduri
 * -- commenting the error msg when INTERRUPT_ON_COMP is enabled. To be removed later.
 *
 * Revision 1.6  2007/05/01 06:39:57  kchunduri
 * * fix compiler warnings.
 *
 * Revision 1.5  2007/03/08 20:43:33  panicker
 * * NPLUS mode changes. pre-release
 * * NitroxPX now supports N1-style NPLUS operation.
 * * Native PX mode PLUS operations are enabled only if PX_PLUS flag is enabled
 *
 * Revision 1.4  2007/02/20 23:10:56  panicker
 * * prints modified; CAST64() macro used;
 *
 * Revision 1.3  2007/02/02 02:34:15  panicker
 * * cavium_check_timeout() replaces code for timeout check
 * * On time out the command bytes for the request are printed.
 *
 * Revision 1.2  2007/01/11 02:12:09  panicker
 *  - soft_req_queue.h is included only if !(NITROX_PX).
 *  - check_srq_state() should not be included for PX
 *  - poll_pending_ordered(), poll_pending_unordered() - use non-NPLUS mode
 *    for PX
 *
 * Revision 1.1  2007/01/06 02:47:40  panicker
 * * first cut - NITROX PX driver
 *
 * Revision 1.40  2006/09/28 08:50:41  kchunduri
 * --avoid dma_map when 'dptr' is NULL
 *
 * Revision 1.39  2006/06/02 11:12:50  pyelgar
 *    - Fixed a bug in DIRECT dma mode and removed dynamic memory allocation for
 *      n1_buff in api.
 *
 * Revision 1.38  2006/05/16 05:26:28  pyelgar
 *   - Used wrapper calls for OS dependent functions in api and osi files.
 *
 * Revision 1.37  2006/05/05 11:08:55  dgandhewar
 * free n1_buf
 *
 * Revision 1.36  2005/12/07 04:50:59  kanantha
 * modified to support both 32 and 64 bit versions
 *
 * Revision 1.35  2005/11/17 13:31:09  kanantha
 * Updating with the 64 bit modifications, with proper matching of data types
 *
 * Revision 1.34  2005/10/07 07:52:08  lpathy
 * windows server 2003 ipsec changes
 *
 * Revision 1.33  2005/09/29 03:51:16  ksadasivuni
 * - Fixed some warnings
 *
 * Revision 1.32  2005/09/28 15:50:26  ksadasivuni
 * - Merging FreeBSD 6.0 AMD64 Release with CVS Head
 * - Now context pointer given to user space applications is physical pointer.
 *   So there is no need to do cavium_vtophys() of context pointer.
 *
 * Revision 1.31  2005/09/21 06:54:49  lpathy
 * Merging windows server 2003 release with CVS head
 *
 * Revision 1.30  2005/09/06 14:38:57  ksadasivuni
 * - Some cleanup error fixing and spin_lock_destroy functionality added to osi.
 *   spin_lock_destroy was necessary because of FreeBSD 6.0.
 *
 * Revision 1.29  2005/09/06 08:52:10  ksadasivuni
 * Check in error corrected
 *
 * Revision 1.27  2005/08/31 18:10:30  bimran
 * Fixed several warnings.
 * Fixed the corerct use of ALIGNMENT and related macros.
 *
 * Revision 1.26  2005/06/13 06:35:42  rkumar
 * Changed copyright
 *
 * Revision 1.25  2005/06/03 07:20:03  rkumar
 * MAX_SRQ_TIMEOUT used for special microcode (for timing out commands), also
 * the timeout is applied after the command has moved to CTP
 *
 * Revision 1.24  2005/05/20 14:34:05  rkumar
 * Merging CVS head from india
 *
 * Revision 1.23  2005/02/01 04:11:07  bimran
 * copyright fix
 *
 * Revision 1.22  2005/01/06 18:43:32  mvarga
 * Added realtime support
 *
 * Revision 1.21  2004/08/03 20:44:11  tahuja
 * support for Mips Linux & HT.
 *
 * Revision 1.20  2004/07/21 23:24:41  bimran
 * Fixed MC2 completion code issues on big endian systems.
 *
 * Revision 1.19  2004/07/09 01:09:00  bimran
 * fixed scatter gather support
 *
 * Revision 1.18  2004/06/28 21:13:43  tahuja
 * fixed a typo.
 *
 * Revision 1.17  2004/06/28 20:37:42  tahuja
 * Fixed compiler warnings on NetBSD. changed mdelay in check_completion from 1ms to 2ms.
 *
 * Revision 1.16  2004/06/23 20:52:20  bimran
 * compiler warnings on NetBSD.
 *
 * Revision 1.15  2004/06/09 00:23:21  bimran
 * Fixed poll_pending_unordered to break after polling MAX_CORES number of commands.
 *
 * Revision 1.14  2004/06/03 21:22:56  bimran
 * included cavium_list.h
 * fixed list* calls to use cavium_list
 *
 * Revision 1.13  2004/06/01 17:47:53  bimran
 * fixed locks to work on SMP systems.
 *
 * Revision 1.12  2004/05/21 18:22:46  tsingh
 * Fixed unordered functionality
 *
 * Revision 1.11  2004/05/11 03:10:55  bimran
 * some performance opt.
 *
 * Revision 1.10  2004/05/08 03:58:51  bimran
 * Fixed INTERRUPT_ON_COMP
 *
 * Revision 1.9  2004/05/02 19:45:31  bimran
 * Added Copyright notice.
 *
 * Revision 1.8  2004/04/30 01:38:37  tsingh
 * Made some functions inline (bimran)
 *
 * Revision 1.7  2004/04/30 01:13:08  tsingh
 * Enable lock around poll_pending_* functions(bimran)
 *
 * Revision 1.6  2004/04/29 21:59:26  tsingh
 * Changed spinlocks to irqsave locks.(bimran)
 *
 * Revision 1.5  2004/04/21 19:18:58  bimran
 * NPLUS support.
 *
 * Revision 1.4  2004/04/19 17:25:25  bimran
 * Fixed a compiler warning.
 *
 * Revision 1.3  2004/04/17 02:53:22  bimran
 * Fixed check_for_completion_callback to not to write 8 to ISR register everytime it is called.
 *
 * Revision 1.2  2004/04/16 23:59:49  bimran
 * Added more debug prints.
 *
 * Revision 1.1  2004/04/15 22:40:49  bimran
 * Checkin of the code from India with some cleanups.
 *
 */

