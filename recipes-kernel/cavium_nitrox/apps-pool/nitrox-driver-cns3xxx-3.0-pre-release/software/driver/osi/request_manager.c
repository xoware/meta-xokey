/* request_manager.c */
/*
 * Copyright (c) 2003-2006 Cavium Networks (support@cavium.com). All rights 
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
#include "cavium_endian.h"
#include "cavium_list.h"
#include "cavium.h"
#include "request_manager.h"
#include "command_que.h"
#include "pending_free_list.h"
#include "pending_list.h"
#include "direct_free_list.h"
#include "sg_free_list.h"
#include "context_memory.h"
#include "completion_dma_free_list.h"
#include "init_cfg.h"
#include "buffer_pool.h"
#include "bl_nbl_list.h"
#include "hw_lib.h"
#include "error_handler.h"
#include "soft_req_queue.h" /* PX_PLUS does not use software queues. */

extern int dev_count;
extern short nplus, ssl, ipsec;
extern cavium_device cavium_dev[];
int cavium_speed_timeout = 0;

#ifdef INTERRUPT_ON_COMP
extern int pending_count;
#endif

extern int MAX_CORES;

#ifdef COUNTER_ENABLE
 Uint32 hmac_count =0;
 Uint32 encrypt_count=0;
 Uint32 decrypt_count=0;
 Uint32 encrypt_record_count=0;
 Uint32 decrypt_record_count=0;
 Uint32 ipsec_inbound_count=0;
 Uint32 ipsec_outbound_count=0;
 Uint64 bytes_in_enc =0;
 Uint64 bytes_out_enc =0;
 Uint64 bytes_in_dec =0;
 Uint64 bytes_out_dec =0;
 Uint64 bytes_in_rec_enc =0;
 Uint64 bytes_out_rec_enc =0;
 Uint64 bytes_in_rec_dec =0;
 Uint64 bytes_out_rec_dec =0;
 Uint64 bytes_in_hmac =0;
 Uint64 bytes_out_hmac =0;
 Uint64 bytes_in_ipsec_ib =0;
 Uint64 bytes_out_ipsec_ib =0;
 Uint64 bytes_in_ipsec_ob =0;
 Uint64 bytes_out_ipsec_ob =0;
 Uint32 enc_pkt_err =0;
 Uint32 dec_pkt_err =0;
 Uint32 enc_rec_pkt_err =0;
 Uint32 dec_rec_pkt_err =0;
 Uint32 in_ipsec_pkt_err =0;
 Uint32 out_ipsec_pkt_err =0;
 Uint32 hmac_pkt_err =0;
#endif

#ifdef CNS3000
Uint64  test_grp64 = 0;
#endif

void
cavium_dump_op_bytes(n1_operation_buffer *n1_op)
{
   cavium_print("----- do_operation Opcode : (Major: %x Minor: %x) -------\n",
                (n1_op->opcode & 0xff), ((n1_op->opcode & 0xff00) >> 8));
   cavium_print("Size: 0x%x Param: 0x%x dlen: 0x%x, rlen: 0x%x\n",
                n1_op->size, n1_op->param, n1_op->dlen, n1_op->rlen);
   cavium_print("insize[0]: 0x%x inoff[0]: 0x%x\n", n1_op->insize[0],
                n1_op->inoffset[0]);
    cavium_print("outsize[0]: 0x%x outoff[0]: 0x%x\n", n1_op->outsize[0],
               n1_op->outoffset[0]);
   cavium_print("incnt: 0x%x outcnt: 0x%x\n", n1_op->incnt, n1_op->outcnt);
   cavium_print("req_type: 0x%x req_queue: 0x%x resp_ord: 0x%x\n",
                n1_op->req_type, n1_op->req_queue, n1_op->res_order);
   cavium_print("-------------------------------\n\n");
}




static inline void
check_for_pcie_error(cavium_device *pdev)
{
   Uint32  dwval, corr_err, uncorr_err;
   Uint32  corr_mask;
   static Uint32  lnk_ctl_sts, prev_lnk_ctl_sts = 0;
   static Uint32  power_ctl, prev_power_ctl = 0;

   read_PCI_register(pdev, 0x44, &power_ctl);
   read_PCI_register(pdev, 0x80, &lnk_ctl_sts);

   if (power_ctl != prev_power_ctl) {
     cavium_error("Power Control: 0x%08x\n", power_ctl);
   }

   prev_power_ctl = power_ctl;

   if (lnk_ctl_sts != prev_lnk_ctl_sts) {
     cavium_error("Link Control Status: 0x%08x\n", lnk_ctl_sts);
   }

   prev_lnk_ctl_sts = lnk_ctl_sts;

   read_PCI_register(pdev, 0x78, &dwval);
   if(dwval & 0x000f0000) {
      cavium_error("PCI-E error detected: 0x%08x\n", dwval & 0x000f0000);
      if(dwval & 0x00010000) {
         read_PCI_register(pdev, 0x110, &corr_err);
         if(corr_err) {
            cavium_error("Correctable error: 0x%08x\n", corr_err);
            write_PCI_register(pdev, 0x110, corr_err);
         } else {
            read_PCI_register(pdev, 0x114, &corr_mask);
            cavium_error("Config[0x78] is 0x%08x but CEStatus is 0x%08x, CEMask is 0x%08x\n", dwval, corr_err, corr_mask);
         }
      }
      if(dwval & 0x0004000) {
         read_PCI_register(pdev, 0x104, &uncorr_err);
         if(uncorr_err) {
            cavium_error("Uncorrectable error: 0x%08x\n", uncorr_err);
            write_PCI_register(pdev, 0x104, uncorr_err);
         }
      }
      write_PCI_register(pdev, 0x78,(dwval & ~(0x000f0000)));
   }
}


int send_command(cavium_device *n1_dev, Request *request, int queue, int ucode_idx, Uint64 *ccptr)
{
   int ret=0;
   Uint8 * command;
   struct MICROCODE *microcode = NULL;
   short plus_check = (nplus || ssl>0 || ipsec > 0);

    MPRINTFLOW();
   if (plus_check) { 
      microcode = &(n1_dev->microcode[ucode_idx]);   
   if(n1_dev->device_id == NPX_DEVICE)
   {
      Uint64  core_grp64 = (Uint64)microcode->core_grp;

      cavium_dbgprint("send_command: core grp for ucode[%d]: %d\n",
                       ucode_idx, microcode->core_grp);
      /* Set the core group here. The cptr would be in big-endian mode.*/
#if __CAVIUM_BYTE_ORDER == __CAVIUM_BIG_ENDIAN
      /* Bits 62-61 of cptr store the queue index. */
      request->cptr |= (core_grp64 << 61);
#else
      /* Bits 6-5 of the last byte (MSB) of cptr stores the queue index. */
      request->cptr |= (core_grp64 << 5);
#endif
   }
   else if(microcode->code_type == CODE_TYPE_SPECIAL)
   /* For SPM code, we have to queue the req to the CTP */
   {
      cavium_dbgprint("send_cmd: add srq entry(ucode idx=%d)\n",ucode_idx);
      if (cavium_debug_level > 1) 
         cavium_dump("Request:", (Uint8 *)request,32);

      /* Queue the request to the SRQ */
      if (queue == HIGH_PRIO_QUEUE) 
      {
         ret = add_srq_entry(n1_dev, microcode, request, ccptr,1);
      }
      else 
         ret = add_srq_entry(n1_dev, microcode, request, ccptr,0);
	  
      /* Attempt to move entries to the CTP */
      move_srq_entries(n1_dev, ucode_idx, CTP_QUEUE_SIZE);
      if(ret<0)
      {
         cavium_dbgprint("add_srq_entry failed in send_request\n");
         return(-1);
      }

   }
   }
   if (!plus_check || (plus_check && (n1_dev->device_id == NPX_DEVICE || microcode->code_type != CODE_TYPE_SPECIAL)))
   {
#ifdef CNS3000 /* XXX: for FPGA testing */
#if __CAVIUM_BYTE_ORDER == __CAVIUM_BIG_ENDIAN
		/* Bits 62-61 of cptr store the queue index. */
		request->cptr |= (test_grp64 << 61);
#else
		/* Bits 6-5 of the last byte (MSB) of cptr stores the queue index. */
     		request->cptr |= (test_grp64 << 5);
#endif
#endif

     if (cavium_debug_level > 1) 
         cavium_dump("Request:", (Uint8 *)request,32);

   /* Send command to the chip */
      lock_command_queue(n1_dev, queue);
      command = (Uint8 *)(n1_dev->command_queue_front[queue]);
      cavium_memcpy(command, (Uint8 *)request, COMMAND_BLOCK_SIZE);
      inc_front_command_queue(n1_dev, queue);
#ifdef CAVIUM_NO_NC_DMA
      cavium_flush_cache(n1_dev, COMMAND_BLOCK_SIZE, command, NULL, 0);
#endif

      cavium_wmb();

     
   /* doorbell coalescing */
      n1_dev->door_bell_count[queue]++;
      if((n1_dev->door_bell_count[queue] >= n1_dev->door_bell_threshold[queue])
#ifdef INTERRUPT_ON_COMP
            ||(pending_count < 32)
#endif
      )
      {
         cavium_dbgprint("send command: hitting doorbell: %d\n", n1_dev->door_bell_count[queue]);
         ring_door_bell(n1_dev, queue, n1_dev->door_bell_count[queue]);
         n1_dev->door_bell_count[queue]=0;
      }

      unlock_command_queue(n1_dev, queue);
   }
   return ret;
}
   

int
do_request(cavium_device * n1_dev, n1_request_buffer *req, Uint32 *req_id)
{

   int ret = 0;
   struct PENDING_ENTRY *pending_entry = NULL;
   struct PKP_DIRECT_OPERATION_STRUCT *pkp_direct_operation = NULL;
   struct PKP_SG_OPERATION_STRUCT *pkp_sg_operation = NULL;
   volatile Uint64 *completion_address;
   Cmd *strcmd;
   Request request;
   uint8_t major_op=(req->opcode & 0xff);
#ifdef COUNTER_ENABLE
   uint8_t minor_op=(req->opcode >> 8) & 0xff;
     cavium_dbgprint("\n\n\n========================================\n");
   cavium_dbgprint("Current request opcode is = 0x%x\n ",(Uint32)req->opcode);
   switch (major_op)
   {
    case MAJOR_OP_ENCRYPT_DECRYPT:
         if(minor_op & 0x01) {
         decrypt_count++;
         bytes_in_dec = bytes_in_dec + (Uint64) req->dlen;
         bytes_out_dec = bytes_out_dec + (Uint64) req->rlen;
                   }
         else {
         encrypt_count++;
         bytes_in_enc = bytes_in_enc + (Uint64) req->dlen;
         bytes_out_enc = bytes_out_enc + (Uint64) req->rlen;
                   } 
         break;
    case MAJOR_OP_ENCRYPT_DECRYPT_RECORD:
         if(minor_op & 0x40) {
         encrypt_record_count++;
         bytes_in_rec_enc = bytes_in_rec_enc + (Uint64) req->dlen;
         bytes_out_rec_enc = bytes_out_rec_enc + (Uint64) req->rlen;
                   }
         else {
         decrypt_record_count++;
         bytes_in_rec_dec = bytes_in_rec_dec + (Uint64) req->dlen;
         bytes_out_rec_dec = bytes_out_rec_dec + (Uint64) req->rlen;
                   } 
         break;
    case MAJOR_OP_HMAC:
         hmac_count++;
         bytes_in_hmac = bytes_in_hmac + (Uint64) req->dlen;
         bytes_out_hmac = bytes_out_hmac + (Uint64) req->rlen;
         break;  
    case (int) OP_IPSEC_PACKET_INBOUND:
         ipsec_inbound_count++;
         bytes_in_ipsec_ib = bytes_in_ipsec_ib + (Uint64) req->dlen;
         bytes_out_ipsec_ib = bytes_out_ipsec_ib  + (Uint64) req->rlen;
         break; 
    case (int) OP_IPSEC_PACKET_OUTBOUND:
         ipsec_outbound_count++; 
         bytes_in_ipsec_ob = bytes_in_ipsec_ob + (Uint64) req->dlen;
         bytes_out_ipsec_ob = bytes_out_ipsec_ob + (Uint64) req->rlen;
         break;  
default: cavium_dbgprint("No data counter related opcode\n");
    }
#endif
    MPRINTFLOW();
    if( (n1_dev->device_id == N1_DEVICE) && (major_op == MAJOR_OP_ME_PKCS) && req->group == CAVIUM_IPSEC_GRP)
    {
        cavium_dbgprint("This operation not supported in N1 device...!\n");
        ret = ERR_OPERATION_NOT_SUPPORTED;
        return ret;
     }

/*#define SSH_REALTIME*/
#ifdef SSH_REALTIME
   if (req->res_order == CAVIUM_RESPONSE_REALTIME)
   {
#define MAX_REALTIME_WAIT 100000
      Uint64 *comp_addr;
      Uint8* cmp;
      int i;
      int dlen = 0;

      strcmd= (Cmd*)&request;
      strcmd->opcode = htobe16(req->opcode);
      strcmd->size = htobe16(req->size);
      strcmd->param = htobe16(req->param);
      strcmd->dlen = htobe16(req->dlen);

      /* Setup dptr */
      if (req->inptr[0])
         request.dptr = htobe64((Uint64)cavium_vtophys(req->inptr[0]));
      else
         request.dptr = 0;

      /* Setup rptr */
      request.rptr = htobe64((Uint64)cavium_vtophys(req->outptr[0]));
      comp_addr = (Uint64 *)((ptrlong)(req->outptr[0]) + (req->rlen));
      *comp_addr = COMPLETION_CODE_INIT;

      /* Setup cptr */
      if (req->ctx_ptr)
         request.cptr = htobe64((ptrlong)req->ctx_ptr);
      else
         request.cptr = 0;

      cavium_dbgprint("request.cptr=%p\n",request.cptr);
      lock_command_queue(n1_dev, req->req_queue);

      cavium_memcpy(
         (Uint8 *)(n1_dev->command_queue_front[req->req_queue]), 
         (Uint8 *)&request, 
         COMMAND_BLOCK_SIZE);
      inc_front_command_queue(n1_dev, req->req_queue);

      cavium_dbgprint("send command: hitting doorbell: %d\n", \
                                 n1_dev->door_bell_count[req->req_queue]+1);
      ring_door_bell(n1_dev, req->req_queue, \
                     n1_dev->door_bell_count[req->req_queue]+1);
      n1_dev->door_bell_count[req->req_queue]=0;

      unlock_command_queue(n1_dev, req->req_queue);
      
      cmp = (Uint8*)comp_addr;
      i = 0;

      while((*cmp == 0xff)&&(i++ < MAX_REALTIME_WAIT))
         cavium_udelay(100);

      return (Uint32)((*cmp) & 0x1f);
}
#endif /* SSH_REALTIME */

   pkp_direct_operation = NULL;
   pkp_sg_operation = NULL;

   pending_entry = get_pending_entry(n1_dev, req_id,req->req_queue);
   if (pending_entry == NULL) 
   {
         cavium_dbgprint("do_request: pending entry list full\n");
         check_for_completion_callback(n1_dev);
         ret = ERR_MEMORY_ALLOC_FAILURE;
         return ret;
   }

   req->time_in = cavium_jiffies;
   strcmd = (Cmd *)&request.cmd;

   switch(req->dma_mode) 
   {
      case CAVIUM_DIRECT:
      {
         cavium_dbgprint("CAVIUM_DIRECT\n");
         /* Get a direct operation struct from free pool */
         pkp_direct_operation = get_direct_entry(n1_dev);
         if (pkp_direct_operation == NULL) 
         {
            cavium_dbgprint("do_request: direct entry entry list full\n");
            ret = ERR_MEMORY_ALLOC_FAILURE;
            goto cleanup_direct;
         }

         /* Setup direct operation -- fill in {d,r,c}ptr */
         if(pkp_setup_direct_operation(n1_dev,req, pkp_direct_operation))
         {
            cavium_dbgprint("do_request: map kernel buffer failed\n");
            ret = ERR_DMA_MAP_FAILURE;
            goto cleanup_direct;
         }
      

         /* write completion address of all 1's */
         completion_address = pkp_direct_operation->completion_address;

         /* 
          * Build the 8 byte command(opcode,size,param,dlen) 
          * and put it in the request structure
          */
#ifdef CNS3000
         if(((pending_count < 32)||(!(pending_count %10)))) 
#else
         if((n1_dev->device_id !=NPX_DEVICE) && ((pending_count < 32)||(!(pending_count %10)))) 
#endif		 
            strcmd->opcode = htobe16((req->opcode | (0x1 << 15)));
         else
            strcmd->opcode = htobe16(req->opcode);
         strcmd->size = htobe16(req->size);
         strcmd->param = htobe16(req->param);
         strcmd->dlen = htobe16(pkp_direct_operation->dlen);

       cavium_dbgprint("Sending request with Opcode: 0x%x\n",
                   (Uint32)strcmd->opcode);
         /* Setup dptr */   
         if (pkp_direct_operation->dptr) 
         {
            request.dptr = htobe64(pkp_direct_operation->dptr_baddr);
         } 
         else
         {
            request.dptr = 0;
         }
         
         /* Setup rptr */
         request.rptr = htobe64(pkp_direct_operation->rptr_baddr);

         /* Setup cptr */ 
         if (pkp_direct_operation->ctx) 
         {
            if (!n1_dev->dram_present) 
            {
               /*   request.cptr = htobe64((Uint64)(cavium_vtophys((Uint32 *)(ptrlong)(pkp_direct_operation->ctx))));*/
               /* No longer necessary as the pkp_dev->ctx_free_list already has physical addresses in init_context */
               request.cptr = htobe64((ptrlong)(pkp_direct_operation->ctx));
            } 
            else 
            {
               request.cptr = htobe64(pkp_direct_operation->ctx);
            }
         } 
         else 
         {
            request.cptr = 0;
         }
         
         pending_entry->pkp_operation = (void *)pkp_direct_operation;


         if(cavium_debug_level > 2)
#ifdef MC2
            cavium_dump("dptr", pkp_direct_operation->dptr, pkp_direct_operation->dlen);
#else
            cavium_dump("DPTR", pkp_direct_operation->dptr, pkp_direct_operation->dlen*8);
#endif
         break;
      }
      case CAVIUM_SCATTER_GATHER:
      {
         /* 
          * Get a scatter/gather operation struct from free pool 
          */
         /* 
          * to scatter/gather module 
          */
         pkp_sg_operation = get_sg_entry(n1_dev);
         if (pkp_sg_operation == NULL) 
         {
            ret = ERR_MEMORY_ALLOC_FAILURE;
            cavium_dbgprint("do_request: sg_entry list full\n");
            goto cleanup_sg;
         }

         /* Setup scatter/gather list */
         if (pkp_setup_sg_operation(n1_dev, req,
                     pkp_sg_operation)) 
         {
            ret = ERR_SCATTER_GATHER_SETUP_FAILURE;
            goto cleanup_sg;
         }

         cavium_dbgprint("do_req: completion address = %p\n", pkp_sg_operation->completion_dma);

         /* write completion address of all 1's  */
         completion_address = (volatile Uint64 *)(pkp_sg_operation->completion_dma);


         /* 
          * Build the 8 byte command(opcode,size,param,dlen) 
          * and put it in the request structure
          */
         cavium_dbgprint("do_req: building command\n");
#if defined(INTERRUPT_ON_COMP) && defined(MC2)
         strcmd->opcode = htobe16((req->opcode | (0x1 << 7) | (0x1 << 15)));
#else
         strcmd->opcode = htobe16((req->opcode|(0x1 << 7)));
#endif
         strcmd->size = htobe16(req->size);
         strcmd->param = htobe16(req->param);
         strcmd->dlen = 
            htobe16((8 +
           (((pkp_sg_operation->gather_list_size + 3)/4
           +(pkp_sg_operation->scatter_list_size + 3)/4) * 40)));
#ifndef MC2
         strcmd->dlen = strcmd->dlen>>3;
#endif

         /* Setup dptr */
         cavium_dbgprint("do_req: setting up dptr\n");
         request.dptr = pkp_sg_operation->sg_dma_baddr;
         request.dptr = htobe64(request.dptr);

         /* Setup rptr */ /*Uncommenting. This should be the case -kchunduri*/
         cavium_dbgprint("do_req: setting up rptr\n");
         request.rptr 
         = htobe64((Uint64)get_completion_dma_bus_addr(n1_dev,
            (volatile Uint64 *)(pkp_sg_operation->completion_dma)));
   
      
#if 0
         request.rptr = (Uint64)cavium_vtophys((volatile void*) (pkp_sg_operation->completion_dma));
         request.rptr = htobe64(request.rptr);
#endif

   cavium_dbgprint ( "rptr = %llx \n",(long long) request.rptr  ) ;
         
         /* Setup cptr */
         cavium_dbgprint("do_req: setting up cptr\n");
         if (pkp_sg_operation->ctx) 
         {
            if (!n1_dev->dram_present) 
            {
            /*      
               request.cptr 
               = htobe64((Uint64)(cavium_vtophys((Uint32 *)(ptrlong)(pkp_sg_operation->ctx))));
            
            */   
               request.cptr = htobe64((ptrlong)pkp_sg_operation->ctx);
            } 
            else 
            {
               request.cptr = htobe64(pkp_sg_operation->ctx);
            }
                   
         } 
         else 
         {
            request.cptr = 0;
         }

         pending_entry->pkp_operation = (void *)pkp_sg_operation;

         break;
      }
      default:
         cavium_error("Unknown dma mode\n");
         ret = ERR_INVALID_COMMAND;
         return ret;
   }

   /* Send the command to the chip */

   
   pending_entry->dma_mode = req->dma_mode;
   pending_entry->completion_address = (ptrlong)completion_address;
   cavium_dbgprint ( "do_request pending entry completion addr %p \n", completion_address ) ;
   pending_entry->tick = cavium_jiffies;
   pending_entry->status = ERR_REQ_PENDING;
   /*pending_entry->callback = (void (*)(int, void *))(ptrlong)req->callback;*/
   pending_entry->callback = CAST_FRM_X_PTR(req->callback);
   pending_entry->cb_arg = CAST_FRM_X_PTR(req->cb_arg);
#ifdef DUMP_FAILING_REQUESTS
   cavium_memcpy(&pending_entry->n1_buf, req, sizeof(n1_request_buffer));
#else
   pending_entry->n1_buf = req;
#endif
   cavium_dbgprint ("do_request: calling send_command()\n");
   cavium_dbgprint ( "pending_entry->n1_buf %p \n", req ) ;
   if ((nplus || ssl>0 || ipsec>0) && n1_dev->device_id != NPX_DEVICE)
   {
      cavium_dbgprint("do_request: ucode_idx = %d\n", req->ucode_idx);
      pending_entry->ucode_idx = req->ucode_idx;
      pending_entry->srq_idx = 
      send_command(n1_dev, &request, req->req_queue, req->ucode_idx, (Uint64 *)completion_address);
      if (pending_entry->srq_idx < 0) 
      {
         ret = pending_entry->srq_idx;
         goto cleanup_direct;
      }
   }
   else 
      send_command(n1_dev, &request, req->req_queue, req->ucode_idx, (Uint64 *)completion_address);

   push_pending(n1_dev, pending_entry, req->res_order);

   ret = 0;

//#if defined(NITROX_PX) && !defined(CN1500) && defined(ENABLE_PCIE_ERROR_REPORTING)

#ifdef ENABLE_PCIE_ERROR_REPORTING
   if(n_dev->device_id ==NPX_DEVICE && n_dev->px_flag!=CN15XX)
      check_for_pcie_error(n1_dev);
#endif


   return ret;

cleanup_direct:
   check_for_completion_callback(n1_dev);
   if (pkp_direct_operation)
   {
      put_direct_entry(n1_dev, pkp_direct_operation);
      pkp_unsetup_direct_operation(n1_dev, pkp_direct_operation);
   }
   if (pending_entry)
      put_pending_entry(n1_dev, pending_entry);

   return ret;

cleanup_sg:
   check_for_completion_callback(n1_dev);
   if (pkp_sg_operation) 
   {
      if (pkp_sg_operation->completion_dma)
         put_completion_dma(n1_dev,(volatile Uint64 *)(pkp_sg_operation->completion_dma));
      put_sg_entry(n1_dev, pkp_sg_operation);
   }
   if (pending_entry)
      put_pending_entry(n1_dev, pending_entry);

   return ret;
}

/*
 * n1_operation_buffer = n1_request_buffer + blocking/non-blocking 
 *                   operation. 
 * 
 * 
 * Fill in callback fn and its args. 
 * 
 * Call do_request()
 * 
 * If it is a blocking operation (n1_op->response_type),
 *    wait till the result appears or timeout
 * else
 *    return
 *
 * Questions::
 *    Why no scatter-gather?
 */

int
do_operation(cavium_device * n1_dev, n1_operation_buffer *n1_op)
{
   
   n1_user_info_buffer *user_info = NULL;
   n1_request_buffer *req = NULL;
   Uint32 dlen, rlen, req_id;
   Uint8 *in_buffer = NULL, *out_buffer = NULL;
   Uint64 *p;
   int total_size, mapped = 0;
   Uint32 i;
   int ret=0;
   int entry_pushed=0;
   struct MICROCODE *microcode = NULL;


   MPRINTFLOW();
   
   user_info = (n1_user_info_buffer *)get_buffer_from_pool(n1_dev,
                  sizeof(n1_user_info_buffer));

   if (user_info == NULL) 
   {
      cavium_error(" OOM for user_info buffer\n");
      ret = 1;
      goto do_op_clean;
   }

   req = (n1_request_buffer *)get_buffer_from_pool(n1_dev,
                  sizeof(n1_request_buffer));

   if (req == NULL) 
   {
      cavium_error(" OOM for n1_request_buffer buffer\n");
      ret = 1;
      goto do_op_clean;
   }

   /* check for the modexp capability */
   /*** Paired cores are not supported on NitroxPX ***/
//#if defined(NPLUS) && !defined(NITROX_PX) 
   if((nplus || ssl>0 || ipsec>0) && n1_dev->device_id!=NPX_DEVICE){ 
   /* check for the number of cores assigned to this microcode index.
    * If not enough cores are present, then return error.
    */
      if((n1_op->opcode & 0x00ff) == MAJOR_OP_ME_PKCS_LARGE || 
                    (n1_op->opcode & 0x00ff) == MAJOR_OP_RSASERVER_LARGE)
      {
         /* It is a large operation. check core mask */ 
         unsigned long core_mask;
   
         core_mask = get_core_mask(n1_dev,n1_op->ucode_idx);
         if(get_core_pair(n1_dev, core_mask))
         {
            ret = ERR_OPERATION_NOT_SUPPORTED;
            goto do_op_clean;
         }
      } 
   }    
   

   /* Check for the Part number.
    * If part has less cores than needed, then return error.
    * Allow this opcode for NITROX PX parts.
    */
//#if defined(CN501) || defined(CN1001)
   if(!nplus && n1_dev->device_id==N1_LITE_DEVICE&&MAX_CORES==1)
   {
      if((n1_op->opcode & 0x00ff) == MAJOR_OP_ME_PKCS_LARGE || 
       (n1_op->opcode & 0x00ff) == MAJOR_OP_RSASERVER_LARGE)
      {
         ret = ERR_OPERATION_NOT_SUPPORTED;
         goto do_op_clean;
      }
   }
//#endif /* part number */
   


#ifndef CAVIUM_NO_MMAP
   if (n1_op->dma_mode == CAVIUM_DIRECT) 
   {
      if((n1_op->opcode & 0x00ff) == 
            MAJOR_OP_ENCRYPT_DECRYPT_RECORD) 
      {
           if(((ptrlong)n1_op->inptr[0] & 0x7) ||
                  ((ptrlong)n1_op->outptr[0] & 0x7) ||
                  (n1_op->incnt > 1) || 
                  (n1_op->outcnt > 1)) 
           {
              mapped = 0;
           } 
           else 
           {
              mapped = 1;
           }
      }
   } 
   else 
   {
      mapped = 0;
   }
#else
   mapped = 0;
#endif


#ifndef MC2
   dlen = n1_op->dlen * 8;
   rlen = n1_op->rlen * 8;
#else
   dlen = n1_op->dlen;
   rlen = ROUNDUP8(n1_op->rlen + 8);
#endif

   if (mapped) 
   {
      if(dlen)
      {
         in_buffer=cavium_get_kernel_address(CAST_FRM_X_PTR(n1_op->inptr[0]));
         if (in_buffer == NULL) 
         {
            ret = 1;
            goto do_op_clean;
         }
      }
      else
         in_buffer = NULL;
      
     out_buffer = cavium_get_kernel_address(CAST_FRM_X_PTR(n1_op->outptr[0]));
      if (out_buffer == NULL) 
      {
         ret = 1;
         goto do_op_clean;
      }

      goto build_user_info;
   }

   /* Not mapped */

   if (dlen) 
   {
      in_buffer = get_buffer_from_pool(n1_dev, dlen);
      if (in_buffer == NULL) 
      {
         cavium_error(" In buffer allocation failure\n");
         ret = 1;
         goto do_op_clean;
      }
         
      total_size = 0;
      for (i = 0; i < n1_op->incnt; i++) 
      {
        if(cavium_copy_in(&in_buffer[total_size],
                              CAST_FRM_X_PTR(n1_op->inptr[i]),
                               n1_op->insize[i]))
         {
            cavium_error("Failed to copy in user buffer=%d, size=%d\n",
                          i,n1_op->insize[i]);
            ret = 1;
            goto do_op_clean;
         }
         if (n1_op->inunit[i] == UNIT_64_BIT) 
         {
            p = (Uint64 *)&in_buffer[total_size];
            *p = htobe64(*p);
         }
         total_size += n1_op->inoffset[i];
      }
   }

   if (rlen) 
   {
      out_buffer = get_buffer_from_pool(n1_dev, rlen);
      if (out_buffer == NULL) 
      {
         cavium_print(" Out buffer allocation failure\n");
         ret = 1;
         goto do_op_clean;
      }
#ifdef DUMP_FAILING_REQUESTS
      memset(out_buffer, 0xa5, rlen);
#endif
   }
   
build_user_info:
   /* Build user info buffer */
   user_info->n1_dev = n1_dev;
   user_info->req_type = n1_op->req_type;
   user_info->in_buffer = in_buffer;
   user_info->out_buffer = out_buffer;
   user_info->in_size = dlen;
   user_info->out_size = rlen;
   user_info->pid = cavium_get_pid();
   user_info->signo = CAVIUM_SIGNAL_NUM;
   user_info->mmaped = mapped;

   /* user mode pointers and request buffer*/
   user_info->outcnt = n1_op->outcnt;
   for (i = 0; i < user_info->outcnt; i++) 
   {
      user_info->outptr[i] = CAST_FRM_X_PTR(n1_op->outptr[i]);
      user_info->outsize[i] = n1_op->outsize[i];
      user_info->outoffset[i] = n1_op->outoffset[i];
      user_info->outunit[i] = n1_op->outunit[i];
   }

   if (n1_op->req_type == CAVIUM_BLOCKING) 
   {
      cavium_get_channel(&user_info->channel);
   } 

   user_info->req = req;
   user_info->status = 0xff;
   push_user_info(user_info);
   entry_pushed = 1;
   /* Build request buffer */
   req->opcode = n1_op->opcode;
   req->size = n1_op->size;
   req->param = n1_op->param;
#ifdef MC2
   req->dlen = (Uint16) dlen;
   req->rlen = n1_op->rlen;
#else
   req->dlen = (Uint16) (dlen >> 3);
   req->rlen = (Uint16) (rlen - 8);
#endif
   req->reserved = 0;
   req->ctx_ptr = n1_op->ctx_ptr;
   req->incnt = n1_op->incnt;
   req->outcnt = n1_op->outcnt;
   req->inptr[0] = CAST_TO_X_PTR(in_buffer);
   req->outptr[0] = CAST_TO_X_PTR(out_buffer);
   req->dma_mode = n1_op->dma_mode;
   req->dma_mode = CAVIUM_DIRECT;
   req->res_order = CAVIUM_RESPONSE_UNORDERED;
   req->timeout = n1_op->timeout;
   req->req_queue = n1_op->req_queue;
   req->callback = CAST_TO_X_PTR(user_scatter);
   req->cb_arg = CAST_TO_X_PTR(user_info);
   req->ucode_idx = n1_op->ucode_idx;

   cavium_dbgprint("do_operation req: timeout = %x \n", req->timeout); 
   ret = do_request(n1_dev, req, &req_id);

   if(ret) 
   {
      cavium_error(" do_request() failed 0x%x\n", ret);
      goto do_op_clean;
   }

   /* Request id is sent to the application */
   n1_op->request_id = req_id; 
   req->request_id = req_id;

   if (n1_op->req_type == CAVIUM_BLOCKING) 
   {
      volatile Uint64* req_compl_addr;
      req_compl_addr = (volatile Uint64 *)((ptrlong)out_buffer + req->rlen);

      cavium_dbgprint("do_operation: blocking call: rptr=0x%p\n", user_info->out_buffer);
      if((nplus || ssl>0 || ipsec>0) && n1_dev->device_id != NPX_DEVICE)
      { 
         microcode = &(n1_dev[0].microcode[n1_op->ucode_idx]);
           /* Attempt to move entries to the CTP, once */
         if(microcode->code_type == CODE_TYPE_SPECIAL)
         {
            move_srq_entries(n1_dev, n1_op->ucode_idx, 0);
         }
      }
      /* Blocking -- sleep peacefully:) -- when it is time, 
       * poll_thread() (user_scatter to be specific) will wake me 
       * up */
      /* Before sleeping, check for any requests that have been
       * completed, wake them up */
      check_for_completion_callback(n1_dev);
      
      /* Our work might have finished.. then a wake up would already 
       * 've been sent on the channel.. */
      while (user_info->status == 0xff) 
      {
#ifdef SLOW_CPU
         cavium_yield(&(user_info->channel),(10*CAVIUM_HZ)/1000);
#else
         cavium_wait_interruptible_timeout(user_info->channel,
         ((Uint8)(*req_compl_addr >> COMPLETION_CODE_SHIFT)!=0xFF),10);
#endif
         check_for_completion_callback(n1_dev);
            /* Wake up every 10ms seconds and check the result */
            /* This is necessary in cases of missed wakeups */
            /* Attempt to move entries to the CTP, once */
         if(nplus && n1_dev->device_id != NPX_DEVICE && microcode->code_type == CODE_TYPE_SPECIAL)
         {
            move_srq_entries(n1_dev, n1_op->ucode_idx, 0);
         }
      }

      ret = user_info->status;

      cavium_dbgprint("status = 0x%x\n", ret);

      del_user_info_from_list(user_info);
      entry_pushed=0;
      if (mapped) 
      {
          if (req)
             put_buffer_in_pool(n1_dev, (Uint8 *)req);
         if (user_info) 
            put_buffer_in_pool(user_info->n1_dev, (Uint8 *)user_info);
         return ret;
      }

      if (user_info->out_size) 
      {
         int total_offset;
         if (cavium_debug_level > 2)
            cavium_dump("Response Pkt:", (Uint8 *)user_info->out_buffer, user_info->out_size);
         total_offset = 0;
         for (i = 0; i < user_info->outcnt; i++) 
         {
            if (user_info->outunit[i] == UNIT_64_BIT) 
            {
               p = (Uint64 *)&user_info->out_buffer[total_offset];
               *p = htobe64(*p);
            }
            if(cavium_copy_out(user_info->outptr[i], 
                  &user_info->out_buffer[total_offset], 
                  user_info->outsize[i]))
            {
               cavium_error("Failed to copy out %d bytes to user buffer 0x%lx\n",
                     user_info->outsize[i], (ptrlong)user_info->outptr[i]);
            }
            total_offset += user_info->outoffset[i];
         }
      }

do_op_clean:
   if (entry_pushed)
      del_user_info_from_list(user_info);      
   if (in_buffer && !mapped)
      put_buffer_in_pool(n1_dev, (Uint8 *)in_buffer);
   if (out_buffer && !mapped)
       put_buffer_in_pool(n1_dev, (Uint8 *)out_buffer);
   if (req)
       put_buffer_in_pool(n1_dev, (Uint8 *)req);
   if (user_info) 
       put_buffer_in_pool(n1_dev, (Uint8 *)user_info);
   } 
   else 
   {
      /* Non-blocking -- nothing else to do, just return */
      ret = ERR_REQ_PENDING;
   }

   return ret;
}

/*
 * do_speed() function to test the performance of device
 *
 * Fill maximum no. of requests in command queue then call ring_door_bell(),
 * then calculate the result for (no. of devices *command_queue_max) requests 
 *
 * or according to time given in cavium_speed_timeout (default 0 seconds).
 *
 * If time is 0 seconds then 
 * calculate the result for (no. of devices * command_queue_max) requests.
 *
 */


int
do_speed(cavium_device *n1_dev, n1_request_buffer *n1_req)
{
   Uint32 speed_dev_count = 0;
   Uint32 dlen, rlen;
   Uint8 *in_buffer[MAX_DEV] , **out_buffer[MAX_DEV] ;
   Uint64 *p;
   int total_size, ret = 0; 
   Request *request[MAX_DEV] ;
   Cmd *strcmd = NULL;
   Uint64 **comp_addr[MAX_DEV] ;
   volatile Uint8* cmp;
   Uint64 start_time = 0, end_time = 0, total_time = 0;
   Uint32 i = 0, j = 0, k = 0, count[] = {0,0,0,0}, l[] = {0,0,0,0};
   Uint32 no_req = 0;
   Uint64 dataptr = 0, recvptr = 0;
   Speed_Test_Info *info = NULL;
   Uint8 *user_info;
   Uint32 CHUNK_SIZE = 0;
   struct MICROCODE *microcode = NULL;
   unsigned long core_mask;
#if 1 /* jijo */
#define CAVIUM_COMMAND_QUEUE_SIZE    cavium_dev[0].command_queue_max
#endif
//#define CAVIUM_COMMAND_QUEUE_SIZE    15

   cavium_dbgprint ("do_speed called\n");

   speed_dev_count = dev_count;

   if((cavium_dev[0].device_id == N1_LITE_DEVICE) 
                || (cavium_dev[0].device_id == N1_DEVICE))

      CHUNK_SIZE = 127;

   else if(cavium_dev[0].device_id == NPX_DEVICE)

      CHUNK_SIZE = CAVIUM_COMMAND_QUEUE_SIZE;

   /* check for the modexp capability */
   /*** Paired cores are not supported on NitroxPX ***/
   if (nplus || ssl > 0 || ipsec > 0)
   {
      core_mask = get_core_mask(&cavium_dev[0],n1_req->ucode_idx);

    // printk(" ucode: %d, 1core_mask %0lx\n",n1_req->ucode_idx, core_mask);
      if(cavium_dev[0].device_id!=NPX_DEVICE) {
      /* check for the number of cores assigned to this microcode index.
       * If not enough cores are present, then return error.
       */
         if((n1_req->opcode & 0x00ff) == MAJOR_OP_ME_PKCS_LARGE ||
                       (n1_req->opcode & 0x00ff) == MAJOR_OP_RSASERVER_LARGE)
         {
         /* It is a large operation. check core mask */

            if(get_core_pair(&cavium_dev[0], core_mask))
            {
               return ERR_OPERATION_NOT_SUPPORTED;
            }
         }
      }
      microcode = &(cavium_dev[0].microcode[n1_req->ucode_idx]);
	  if (microcode->code_type == CODE_TYPE_SPECIAL) 
	  {
	     cavium_dbgprint ("do_speed: operation not supported for CODE_TYPE_SPECIAL micrcode\n");
		 return ERR_OPERATION_NOT_SUPPORTED;
      }
   }
   else {

/* Check for the Part number.
    * If part has less cores than needed, then return error.
    * Allow this opcode for NITROX PX parts.
    */
      if(cavium_dev[0].device_id==N1_LITE_DEVICE&&MAX_CORES==1)
      {
         if((n1_req->opcode & 0x00ff) == MAJOR_OP_ME_PKCS_LARGE ||
             (n1_req->opcode & 0x00ff) == MAJOR_OP_RSASERVER_LARGE)
         {
            return ERR_OPERATION_NOT_SUPPORTED;
         }
      }
   }

 
#ifndef MC2
   dlen = n1_req->dlen * 8;
   rlen = n1_req->rlen * 8;
#else
   dlen = n1_req->dlen;
   rlen = ROUNDUP8(n1_req->rlen + 8);
#endif

   user_info = CAST_FRM_X_PTR(n1_req->outptr[0]);

   for(k = 0; k < speed_dev_count; k++) 
   {
      if (dlen) 
      {
         in_buffer[k] = get_buffer_from_pool(&cavium_dev[k], dlen);
         if (in_buffer[k] == NULL) 
         { 
            cavium_error(" In buffer allocation failure\n");
            ret = 1;
            goto do_speed_clean;
         }
         total_size = 0;
         for (i = 0; i < n1_req->incnt; i++) 
         {
            if(cavium_copy_in(&in_buffer[k][total_size],                                                 CAST_FRM_X_PTR(n1_req->inptr[i]), n1_req->insize[i]))
            {
               cavium_error("Failed to copy in user buffer=%d, size=%d\n",
                         i,n1_req->insize[i]);
               ret = 1;
               goto do_speed_clean;
            }
            if (n1_req->inunit[i] == UNIT_64_BIT) 
            {
               p = (Uint64 *)&in_buffer[k][total_size];
               *p = htobe64(*p);
            }
            total_size += n1_req->inoffset[i];
         }
      }
   } 

#ifdef MC2
   n1_req->dlen = (Uint16) dlen;
   n1_req->rlen = n1_req->rlen;
#else
   n1_req->dlen = (Uint16) (dlen >> 3);
   n1_req->rlen = (Uint16) (rlen - 8);
#endif

   for(k = 0; k < speed_dev_count; k++) 
   {
      n1_req->inptr[0] = CAST_TO_X_PTR(in_buffer[k]);
      request[k] = (Request *) get_buffer_from_pool(&cavium_dev[k],                                                                         sizeof(Request));
      if (request[k] == NULL)
      {
         cavium_error("OOM for request allocation \n");
         ret = 1;
         goto do_speed_clean;
      }

      comp_addr[k] = (Uint64 **) get_buffer_from_pool(&cavium_dev[k],                                                 CAVIUM_COMMAND_QUEUE_SIZE * sizeof(Uint64 *));
      if(comp_addr[k] == NULL)
      {
         cavium_error("OOM for comp_addr allocation \n");
         ret =1;        
         goto do_speed_clean;
      }

      strcmd = (Cmd *)(request[k]); 
      strcmd->opcode = htobe16(n1_req->opcode);
      strcmd->size = htobe16(n1_req->size);
      strcmd->param = htobe16(n1_req->param);
      strcmd->dlen = htobe16(n1_req->dlen);

      /* Setup dptr */
      if (n1_req->dlen)
         dataptr = (Uint64) cavium_map_kernel_buffer(&cavium_dev[k],
                                              in_buffer[k] ,n1_req->dlen,
                                              CAVIUM_PCI_DMA_BIDIRECTIONAL);
      else
         dataptr = 0;
        
      (request[k])->dptr = htobe64(dataptr);

      out_buffer[k] = (Uint8 **) get_buffer_from_pool(&cavium_dev[k],
                                 CAVIUM_COMMAND_QUEUE_SIZE * sizeof(Uint8 *));
      if(out_buffer[k] == NULL) 
      {
         cavium_print(" OOM for out_buffer\n");
         ret =1;
         goto do_speed_clean;
      }

      lock_command_queue(&cavium_dev[k], n1_req->req_queue);
     for(i=0; i< CAVIUM_COMMAND_QUEUE_SIZE; i++)  
      {
         if (rlen) 
         {
            out_buffer[k][i] = get_buffer_from_pool(&cavium_dev[k], rlen);
            if (out_buffer[k][i] == NULL) 
            {
               cavium_print(" Out buffer allocation failure\n");
               ret = 1;
               goto do_speed_clean;
            }
            memset(out_buffer[k][i], 0, rlen);
            n1_req->outptr[0] = CAST_TO_X_PTR(out_buffer[k][i]);

            /* Setup rptr */
            recvptr = (Uint64) cavium_map_kernel_buffer(&cavium_dev[k],                                         out_buffer[k][i] ,n1_req->rlen + sizeof(Uint64),                                CAVIUM_PCI_DMA_BIDIRECTIONAL);

            (request[k])->rptr = htobe64(recvptr);
         } 

         comp_addr[k][i] = (Uint64 *)((ptrlong)(out_buffer[k][i])                                                                 + (n1_req->rlen));

         *comp_addr[k][i] = COMPLETION_CODE_INIT;
      cavium_flush_cache(NULL, COMMAND_BLOCK_SIZE, comp_addr[k][i], NULL, 0);
         /* Setup cptr */
         if (n1_req->ctx_ptr)
            (request[k])->cptr = htobe64((ptrlong)n1_req->ctx_ptr);
         else
            (request[k])->cptr = 0;

         if (nplus || ssl > 0 || ipsec > 0) {
            if( cavium_dev[k].device_id == NPX_DEVICE && 
                microcode->code_type != CODE_TYPE_SPECIAL )
            {
#if __CAVIUM_BYTE_ORDER == __CAVIUM_BIG_ENDIAN
         /* Bits 62-61 of cptr store the queue index. */
               request[k]->cptr |= (((Uint64)(microcode->core_grp)) << 61);
#else
         /* Bits 6-5 of the last byte (MSB) of cptr stores the queue index. */
               request[k]->cptr |= (((Uint64)microcode->core_grp) << 5);
#endif
            }
            else if(microcode->code_type == CODE_TYPE_SPECIAL)
            {
               cavium_print("Microcode not supported for speedtest \n");
               ret = 1;
               goto do_speed_clean;
            }
         }
         if(!nplus || (nplus && (cavium_dev[k].device_id==NPX_DEVICE || 
                       microcode->code_type != CODE_TYPE_SPECIAL)))
         {
            cavium_memcpy((Uint8 *)
                    (cavium_dev[k].command_queue_front[n1_req->req_queue]),
                    (Uint8 *)(request[k]),COMMAND_BLOCK_SIZE);
            inc_front_command_queue(&cavium_dev[k], n1_req->req_queue);
         }
      }
   }
   
   start_time = cavium_rdtsc();
   while(1) 
   {
      for(k = 0; k < speed_dev_count; k++) 
      {
         if(cavium_dev[k].device_id == NPX_DEVICE)
            count[k] = CHUNK_SIZE;        
         else 
         {
            if((l[k]+CHUNK_SIZE)>=CAVIUM_COMMAND_QUEUE_SIZE)
               count[k] = CAVIUM_COMMAND_QUEUE_SIZE - l[k];
            else 
               count[k] = CHUNK_SIZE;        
         }
         if(!nplus || (nplus && (cavium_dev[k].device_id==NPX_DEVICE || 
                       microcode->code_type != CODE_TYPE_SPECIAL)))
         ring_door_bell(&cavium_dev[k], n1_req->req_queue, count[k]);
      }
      for(k = 0; k < speed_dev_count; k++) 
      {
         for(j = 0; j < count[k]; j++, l[k]++) 
         {
            cmp = (volatile Uint8 *)(comp_addr[k][l[k]]);
         
               while(*cmp == 0xff) {

         		cavium_invalidate_cache(NULL, COMPLETION_CODE_SIZE, 
										(ptrlong)cmp, 
										NULL,
                 						CAVIUM_PCI_DMA_BIDIRECTIONAL);
               cavium_udelay(100);
			   }
             *comp_addr[k][l[k]] = COMPLETION_CODE_INIT;
         }
         no_req += count[k];
         if( l[k] == CAVIUM_COMMAND_QUEUE_SIZE) 
         {
            l[k] = 0;
            if(no_req >= (speed_dev_count * CAVIUM_COMMAND_QUEUE_SIZE))
            {
                 end_time =  cavium_rdtsc();
//				 printk (KERN_CRIT "start_time is %llu\n", start_time);
//				 printk (KERN_CRIT "end_time is %llu\n", end_time);
               total_time += (((Uint32)(end_time - start_time)) /(cavium_speed_unit()/1000));
//				 printk (KERN_CRIT "total_time is %llu\n", total_time);
                   start_time = end_time;
              
               if((total_time)>=(((Uint64)(cavium_speed_timeout)*1000000)))
                  goto timeout;        
            }
         }
      }
   }

timeout:
   for(k = 0;k < speed_dev_count; k++) 
   {
      cavium_dev[k].door_bell_count[n1_req->req_queue] = 0;
      unlock_command_queue(&cavium_dev[k], n1_req->req_queue);
   }
        
   info = (Speed_Test_Info *) get_buffer_from_pool(&cavium_dev[0],                                                                sizeof(Speed_Test_Info));
   if (info == NULL)
   {
      cavium_error(" OOM for info buffer allocation \n");
      ret = 1;
      goto do_speed_clean;
   }
   info->time_taken = total_time;    /* microseconds */
   info->req_completed = no_req;
   info->dlen = dlen;
   info->rlen = rlen;

   if(cavium_copy_out(user_info, (info), sizeof(Speed_Test_Info)))
   {
      cavium_error("Failed to copy out to user \n"); 
      ret = 1;
      goto do_speed_clean;                
   }


do_speed_clean:

   if(info)
      put_buffer_in_pool(&cavium_dev[0], (Uint8 *)info);
   for(k = 0; k < speed_dev_count; k++) 
   {
      if(comp_addr[k])        
         put_buffer_in_pool(&cavium_dev[k], (Uint8 *)comp_addr[k]);
      if(request[k])
         put_buffer_in_pool(&cavium_dev[k], (Uint8 *)request[k]);
      if (in_buffer[k]) 
      {
         cavium_unmap_kernel_buffer(&cavium_dev[k],dataptr,n1_req->dlen,
                                    CAVIUM_PCI_DMA_BIDIRECTIONAL);
         put_buffer_in_pool(&cavium_dev[k], (Uint8 *)in_buffer[k]);
      }
   
      cavium_unmap_kernel_buffer(&cavium_dev[k],recvptr,n1_req->rlen,
                                 CAVIUM_PCI_DMA_BIDIRECTIONAL);
   
      for(i = 0; i < CAVIUM_COMMAND_QUEUE_SIZE; i++)
         put_buffer_in_pool(&cavium_dev[k], (Uint8 *) out_buffer[k][i]);
      if(out_buffer[k])
         put_buffer_in_pool(&cavium_dev[k], (Uint8 *) out_buffer[k]);
   }
   cavium_dbgprint ("do_speed return\n");
   return ret;
}


/*
 * Callback function to scatter result to user space pointers.
 */
void 
user_scatter(int status, void *arg)
{
   n1_user_info_buffer *user_info;

   MPRINTFLOW();
   user_info = (n1_user_info_buffer *)arg;

   if (user_info->req_type == CAVIUM_NON_BLOCKING) 
   {
       /* The user thread will do a poll()/ioctl() to 
       * find out the status */
   } else if (user_info->req_type == CAVIUM_SIGNAL) 
   {
      /* The user thread asked for a signal to be sent */
      cavium_send_signal((ptrlong)user_info->pid, user_info->signo);
   } 
   else 
   {
      /* Blocking call -- the caller is sleeping .. wake him up */
      cavium_dbgprint("user_scatter: waking up: rptr=0x%p\n", user_info->out_buffer);
      cavium_wakeup(&user_info->channel);
   }
   user_info->status = status;

   return;
}

void flush_queue(cavium_device *n1_dev, int queue)
{
    MPRINTFLOW();
       lock_command_queue(n1_dev, queue);
         ring_door_bell(n1_dev, queue, n1_dev->door_bell_count[queue]);
         n1_dev->door_bell_count[queue]=0;
       unlock_command_queue(n1_dev, queue);
}

/*
 * $Id: request_manager.c,v 1.38 2009/09/29 10:50:40 aravikumar Exp $
 * $Log: request_manager.c,v $
 * Revision 1.38  2009/09/29 10:50:40  aravikumar
 * Added plus_check varible in send_command and add group ipsec condition for N1 card in do_request
 *
 * Revision 1.37  2009/09/16 12:06:36  aravikumar
 * nplus support added in do_speed
 *
 * Revision 1.36  2009/09/09 11:26:19  aravikumar
 * NPLUS macro dependency removed and made it dynamic
 *
 * Revision 1.35  2009/08/19 06:11:10  jrana
 * Removed compilation error with major_op.Changer printk to cavium_dbgprint to reatin portability.
 *
 * Revision 1.34  2009/07/22 10:17:24  pnalla
 * In case of N1 device ModExp operation not supported.
 *
 * Revision 1.33  2009/07/15 11:04:01  aravikumar
 * changed minor_op mask to identify both encryption and decryption
 *
 * Revision 1.32  2009/06/23 08:39:37  kmonendra
 * Modify do_speed() for time based calculation.
 *
 * Revision 1.31  2009/06/02 14:43:55  kmonendra
 * Changes in do_speed, for multicard support.
 *
 * Revision 1.30  2009/05/15 10:34:51  kmonendra
 * Changes in do_speed, for time based calculation.
 *
 * Revision 1.29  2009/05/11 09:30:42  jrana
 * Done type casting on some variables to remove compilation error for windows.
 *
 * Revision 1.28  2009/05/06 09:36:59  kmonendra
 * Changes in do_speed for support of NLITE/N1 Family
 *
 * Revision 1.27  2009/04/07 05:27:38  kmonendra
 * Added do_speed for speedtest(PX only)
 *
 * Revision 1.26  2009/02/25 09:58:16  sgadam
 * - check_for_completion_callback removed in do_request
 *
 * Revision 1.25  2008/12/22 05:42:10  jrana
 *  COUNTERS and INTERRUPT COALEASCING ADDED
 *
 * Revision 1.24  2008/11/06 09:11:36  ysandeep
 * Removed PX_PLUS
 *
 * Revision 1.23  2008/09/30 13:15:17  jsrikanth
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
 * Revision 1.22  2008/07/30 13:01:08  aramesh
 * removed CN501 and CN1001.
 *
 * Revision 1.21  2008/07/02 12:35:26  aramesh
 * deleted part number and corresponding flags.
 *
 * Revision 1.20  2008/02/22 09:30:53  aramesh
 * driver cleanup done.
 *
 * Revision 1.19  2008/02/14 05:37:35  kchunduri
 * --remove CN1600 dependency.
 *
 * Revision 1.18  2008/01/08 12:35:34  rkumar
 * rlen in do_operation changed for MC2 -- improper calculation
 *
 * Revision 1.17  2008/01/02 09:13:22  rkumar
 * In Scatter gather mode, Interrupt bit is not set in the opcode
 * even when INTERRUPT_ON_COMP is set.
 *
 * Revision 1.16  2007/12/05 14:34:08  lpathy
 * introduced load balancing between interrupt and polling modes
 *
 * Revision 1.15  2007/11/19 11:11:55  lpathy
 * ported to 64 bit windows.
 *
 * Revision 1.14  2007/10/18 09:19:18  lpathy
 * moved cavium_pcie_print to sysdep files
 *
 * Revision 1.13  2007/07/03 11:48:34  kchunduri
 * --Invoked modified 'completion_dma_free_list' API.
 *
 * Revision 1.12  2007/06/18 13:50:18  tghoriparti
 * user_info status is updated after sending wake up signal
 *
 * Revision 1.11  2007/06/11 13:41:07  tghoriparti
 * cavium_mmap_kernel_buffers return values handled properly when failed.
 *
 * Revision 1.10  2007/06/06 08:59:22  rkumar
 * CAVIUM_NO_NC_DMA flag introduced
 *       in platforms which do not have non-cacheable memory allocation routines.
 *
 * Revision 1.9  2007/05/01 05:22:58  kchunduri
 * * --replaced pci_write_config_dword/pci_read_config_dword calls with write_PCI_register/read_PCI_register OSI calls.
 * * --replaced wmb() with cavium_wmb().
 *
 * Revision 1.8  2007/04/05 02:39:04  panicker
 * * PCI Error report prints are enabled only if ENABLE_PCIE_ERROR_REPORTING is
 *   enabled.
 *
 * Revision 1.7  2007/04/04 21:52:59  panicker
 * * Added support for CN1600
 * * check_for_pcie_error() pokes the device status and error registers for the
 *   CN1600 device. It is called after every request.
 *
 * Revision 1.6  2007/03/08 20:43:33  panicker
 * * NPLUS mode changes. pre-release
 * * NitroxPX now supports N1-style NPLUS operation.
 * * Native PX mode PLUS operations are enabled only if PX_PLUS flag is enabled
 *
 * Revision 1.5  2007/03/06 03:14:21  panicker
 * * send_command() uses same  prototype as N1 for PX. Adds the core group to
 *   cptr for NPLUS mode on PX (PX-PLUS in the future)
 *
 * Revision 1.4  2007/02/02 02:35:41  panicker
 * * cavium_dump_op_bytes() to print request parameters
 * * RSASERVER_LARGE & ME_PKCS_LARGE operations are allowed for PX.
 *
 * Revision 1.3  2007/01/13 03:18:04  panicker
 * * compilation warnings fixed.
 *
 * Revision 1.2  2007/01/11 02:13:57  panicker
 *  - soft_req_queue.h is included only if !(NITROX_PX).
 *  - send_command() uses non-NPLUS mode for PX.
 *  - do_request() uses non-NPLUS mode send_command().
 *  - do_operation()
 *    * use non-NPLUS behavior for OP_*_LARGE, same as for CN501, CN1001.
 *    * use req->ucode_idx for PX; srq operations mode in NPLUS only if
 *      !(NITROX_PX)
 *
 * Revision 1.1  2007/01/06 02:47:40  panicker
 * * first cut - NITROX PX driver
 *
 * Revision 1.54  2006/08/18 09:35:14  kchunduri
 * --Excess 'htobe64' in rptr setup.
 *
 * Revision 1.53  2006/08/16 04:33:29  kchunduri
 * --For MC1 you need not configure for Interrupt for every request. By default all requests upon completion generates interrupts
 *
 * Revision 1.52  2006/08/08 13:30:22  kchunduri
 * remove c++ style of comments
 *
 * Revision 1.51  2006/08/01 07:58:13  kchunduri
 * remove deprecated interruptible_sleep_on_timeout
 *
 * Revision 1.50  2006/05/16 15:35:47  kchunduri
 * --fix compilation warnings on PPC64
 *
 * Revision 1.49  2006/05/16 09:35:35  kchunduri
 * --support for Dynamic DMA mapping instead of virt_to_phys
 *
 * Revision 1.48  2006/05/05 11:10:06  dgandhewar
 * rptr changes for Scatter/Gather
 *
 * Revision 1.47  2006/03/24 07:11:16  kanantha
 * Removed C++ style comment
 *
 * Revision 1.46  2006/02/13 11:58:52  kanantha
 * Adding #ifdef SLOW_CPU to use cavium_yield(), to improve performance on slow cpuboxes where number of driver instances are very less
 *
 * Revision 1.45  2006/01/30 06:56:32  sgadam
 * - Disabled check for completion callback for control path
 *
 * Revision 1.44  2006/01/22 06:58:22  sgadam
 * - Added lock for flush_queue function
 *
 * Revision 1.43  2006/01/19 09:48:08  sgadam
 * - IPsec 2.6.11 changes
 *
 * Revision 1.42  2006/01/12 13:12:14  ksadasivuni
 * - changed copyright notice.
 *
 * Revision 1.41  2006/01/06 10:15:26  ksadasivuni
 * - Avoided double free in do_operation
 *
 * Revision 1.40  2006/01/06 09:20:11  ksadasivuni
 * - do_request failure case was not handled properly in one scenario.
 *   Fixed.
 *
 * Revision 1.39  2005/11/17 13:31:09  kanantha
 * Updating with the 64 bit modifications, with proper matching of data types
 *
 * Revision 1.38  2005/10/13 09:26:12  ksnaren
 * fixed compile warnings
 *
 * Revision 1.37  2005/09/29 03:51:16  ksadasivuni
 * - Fixed some warnings
 *
 * Revision 1.36  2005/09/28 15:50:26  ksadasivuni
 * - Merging FreeBSD 6.0 AMD64 Release with CVS Head
 * - Now context pointer given to user space applications is physical pointer.
 *   So there is no need to do cavium_vtophys() of context pointer.
 *
 * Revision 1.35  2005/09/28 12:40:01  pyelgar
 *    - Fixed the delay in driver polling mode for RHEL3.
 *
 * Revision 1.34  2005/09/21 06:54:49  lpathy
 * Merging windows server 2003 release with CVS head
 *
 * Revision 1.33  2005/09/06 07:08:22  ksadasivuni
 * - Merging FreeBSD 4.11 Release with CVS Head
 *
 * Revision 1.32  2005/08/31 18:10:30  bimran
 * Fixed several warnings.
 * Fixed the corerct use of ALIGNMENT and related macros.
 *
 * Revision 1.31  2005/08/31 02:34:44  bimran
 * Fixed code to check for copy_in/out return values.
 *
 * Revision 1.30  2005/06/13 06:35:42  rkumar
 * Changed copyright
 *
 * Revision 1.29  2005/06/03 07:18:00  rkumar
 * Priority now associated with requests (WriteIPSecSA) -- and a reserved area is
 * earmarked for them in the SRQ list
 *
 * Revision 1.28  2005/05/24 09:14:50  rkumar
 * add_srq_entry: failed moved from cavium_print cavium_dbgprint
 *
 * Revision 1.27  2005/05/20 14:34:05  rkumar
 * Merging CVS head from india
 *
 * Revision 1.26  2005/02/01 04:11:07  bimran
 * copyright fix
 *
 * Revision 1.25  2005/01/26 20:35:45  bimran
 * Added support to check for available core pairs for Modexp operation.
 *
 * Revision 1.24  2005/01/19 23:31:44  tsingh
 * *** empty log message ***
 *
 * Revision 1.23  2005/01/18 19:06:24  tsingh
 * Added check to look for microcode type before calling move_srq_entries()
 * (bimran)
 *
 * Revision 1.22  2005/01/14 23:48:43  tsingh
 * Fix for NPLUS in single core mode. (bimran)
 *
 * Revision 1.21  2005/01/06 18:43:32  mvarga
 * Added realtime support
 *
 * Revision 1.20  2004/07/30 18:02:42  tsingh
 * fix for interrupt mode from India office (Ram)
 *
 * Revision 1.1.1.1  2004/07/28 06:43:29  rkumar
 * Initial Checkin
 *
 * Revision 1.19  2004/07/09 01:09:00  bimran
 * fixed scatter gather support
 *
 * Revision 1.18  2004/06/03 21:22:56  bimran
 * included cavium_list.h
 * fixed list* calls to use cavium_list
 *
 * Revision 1.17  2004/05/28 17:58:57  bimran
 * fixed a bug in mmap where in_buffer calcaluation was done even when not needed.
 *
 * Revision 1.16  2004/05/21 18:22:46  tsingh
 * Fixed unordered functionality
 *
 * Revision 1.15  2004/05/19 19:13:00  bimran
 * added CAVIUM_NO_MMAP to make it consistent with our older releases of SSL SDK.
 *
 * Revision 1.14  2004/05/11 20:50:32  tsingh
 * Changed some arguments passed through a function
 *
 * Revision 1.13  2004/05/11 03:10:55  bimran
 * some performance opt.
 *
 * Revision 1.12  2004/05/10 22:24:23  tsingh
 * Fix to decrease Latency on low loads
 *
 * Revision 1.11  2004/05/08 03:58:51  bimran
 * Fixed INTERRUPT_ON_COMP
 *
 * Revision 1.10  2004/05/05 06:48:10  bimran
 * Request ID is now copied to req buffer too.
 *
 * Revision 1.9  2004/05/02 19:45:31  bimran
 * Added Copyright notice.
 *
 * Revision 1.8  2004/05/01 07:14:37  bimran
 * Fixed non-blocking operation from user mode.
 *
 * Revision 1.7  2004/04/26 20:38:36  tsingh
 * moved debug print to avoid compile error
 *
 * Revision 1.6  2004/04/24 04:02:43  bimran
 * Fixed NPLUS related bugs.
 * Added some more debug prints.
 *
 * Revision 1.5  2004/04/21 21:33:58  bimran
 * added some more debug dumps.
 *
 * Revision 1.4  2004/04/21 19:18:58  bimran
 * NPLUS support.
 *
 * Revision 1.3  2004/04/17 00:00:40  bimran
 * Added more debug prints.
 * Fixed command dump.
 *
 * Revision 1.2  2004/04/16 03:21:14  bimran
 * Added doorbell coalescing support.
 *
 * Revision 1.1  2004/04/15 22:40:49  bimran
 * Checkin of the code from India with some cleanups.
 *
 */

