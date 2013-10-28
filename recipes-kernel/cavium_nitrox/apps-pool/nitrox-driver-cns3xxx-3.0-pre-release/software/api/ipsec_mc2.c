/* ipsec_mc2.c */
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
#include <cavium_sysdep.h>
#include <cavium_common.h>
#include <cavium_endian.h>
#include "cavium_list.h"
#include "cavium.h"
#include "context_memory.h"
#include "request_manager.h"
/*
 * opcodes
 */

#define OP_IPSEC_PACKET_INBOUND                 0x10
#define OP_IPSEC_PACKET_OUTBOUND                0x11
#define OP_WRITE_INBOUND_IPSEC_SA              0x2014
#define OP_WRITE_OUTBOUND_IPSEC_SA              0x4014
#define OP_ERASE_CONTEXT                        0x114

#define IPv4    0

#define MICRO_CODE2 2

extern int dev_count;
extern short nplus;
extern cavium_device cavium_dev[];
extern struct N1_Dev *device_list;
#ifdef CAVIUM_MULTICARD_API
struct N1_Dev *m_device = NULL;
void check_list(void);
void delete_list(void *);
#endif


Uint32
n1_invalidate_ipsec_sa(void *device, Uint64 ctx, Uint32 *in_buffer, Uint32 *out_buffer, CallBackFn cb, void *cb_data, int res_order,int req_queue) ;

void 
n1_flush_packet_queue(void *device);


#ifdef CAVIUM_NEW_API
Uint32
n1_process_inbound_packet(void *device, Uint16 size, Uint16 param,Uint16 dlen,
                              n1_scatter_buffer * in_buff,
                              n1_scatter_buffer * out_buff,
                              int rlen,Uint64 ctx, CallBackFn cb, void *cb_data,
                              int response_order, int req_queue);


Uint32
n1_process_outbound_packet(void *device, Uint16 size, Uint16 param, Uint16 dlen,
                              n1_scatter_buffer * in_buff,
                              n1_scatter_buffer *out_buff,
                              int rlen,Uint64 ctx, CallBackFn cb, void *cb_data,
                              int response_order, int req_queue);
#else

Uint32
n1_process_inbound_packet(void *device, Uint16 size, Uint16 param, Uint16 dlen,
                         Uint32 * inbuffer, Uint32 *outbuffer, int rlen,
                         Uint64 ctx, CallBackFn cb, void *cb_data,
                         int response_order, int req_queue);

Uint32
n1_process_outbound_packet(void *device, Uint16 size, Uint16 param, Uint16 dlen,
                         Uint32 * inbuffer, Uint32 *outbuffer, int rlen,
                         Uint64 ctx, CallBackFn cb, void *cb_data,
                         int response_order, int req_queue);
#endif


/******************************************************************************/
/*! \ingroup IPSEC_OPS
* n1_unconfig_device
*
* Uncofigures the usage of the device.
*
*/
/******************************************************************************/
void
n1_unconfig_device(void)
{
   CAVIUM_MOD_DEC_USE_COUNT;
   return;
}

/*****************************************************************************/
/*! \ingroup IPSEC_OPS
* n1_alloc_context
*
* Allocates context and returns context handle.
*
* \param device   Pointer to the device to be used (returned in n1_config_device)
*
*
* \retval SUCCESS context handle.
* \retval FAILURE 0
*/
/****************************************************************************/
Uint64
n1_alloc_context(void *device)
{
   Uint64 ctx;

   ctx = alloc_context((cavium_device *)device, CONTEXT_IPSEC);
   if (ctx == (Uint64)0) {
      cavium_error("n1_alloc_context: Alloc Context failed\n");
      return ((Uint64)0);
   }

   return ctx;
}

/*****************************************************************************/
/*! \ingroup IPSEC_OPS
* n1_free_context
*
*   Frees the context handle.
*
* \param device   Pointer to the device to be used (returned in n1_config_device)
* \param ctx   context handle.
*
*/
/****************************************************************************/
void
n1_free_context(void *device, Uint64 ctx)
{
   dealloc_context((cavium_device *)device, CONTEXT_IPSEC, ctx); 

   return;
}


static int 
n1_get_ipsec_ucode_idx(cavium_device *n1_device)
{
   if(n1_device->microcode[UCODE_IDX + nplus].core_id != (Uint8)-1) {
        return (UCODE_IDX+nplus);
   }
   return -1;   
}



#ifdef CAVIUM_NEW_API
/*****************************************************************************/
/*! \ingroup IPSEC_OPS
* n1_config_device
*
*   Configures  the device and returns list of Cavium devices found
*   in an abstract pointer
*
* \param mc   Microcode version (MC2 or MC1)
*
* \retval NULL Failure 
*/
/****************************************************************************/
void *
n1_config_device(Uint32 mc)
{
   if (mc != MICRO_CODE2) {
       cavium_error("The driver is compiled for MC2.. IPSec isn't compiled for the same \n");
       return NULL;
   }

   if (device_list) {
       CAVIUM_MOD_INC_USE_COUNT;
#ifdef CAVIUM_MULTICARD_API
            check_list();
            m_device = device_list;
#endif
       return device_list;
   } else {
       return NULL;
   }
}
#ifdef CAVIUM_MULTICARD_API

void check_list(void)
{
        int i=0;
        for(i=0;i<dev_count;i++)
           if(!(cavium_dev[i].enable))
                   delete_list((void *)(&cavium_dev[i]));
}

void delete_list(void *delete)
{
        struct N1_Dev *curr=NULL;
        struct N1_Dev *del=NULL;
        if( device_list->data == delete)
        {
                del = device_list;
                device_list = del->next;
        }
        else
        {
                for(curr=device_list;curr;curr=curr->next)
                {
                        if(curr->next && curr->next==delete)
                        {
                           del = curr->next;
                           curr->next = del->next;
                                break;
                        }
                }
        }
        if(del) kfree(del);
}

#endif
/*****************************************************************************/
/*! \ingroup IPSEC_OPS
* n1_process_inbound_packet
*
*       Processes Inbound IPSec packet -- decrypts the packet with
*       ciphers in the ctx in kernel space. 
*
*
* \param device  Pointer to the device to be used (returned in n1_config_device)
* \param size    Param1 field as defined in the Microcode Spec.
* \param param   Param2 field as defined in the Microcode Spec.
* \param dlen   length of input (packet)
* \param inv   pointer to input data (packet to be processed) in iovec format
* \param outv   pointer to output buffer in iovec format
* \param rlen   Expected length of output. 
* \param ctx    context handle.
* \param cb   callback function
* \param cb_data callback function argument
* \param response_order  Response order (CAVIUM_RESPONSE_ORDERED or CAVIUM_RESPONSE_UNORDERED).
* \param req_queue Queue on which this request has to be sent.
*
*
* \retval SUCCESS 0
* \retval FAILURE -1
*/
/****************************************************************************/
Uint32
n1_process_inbound_packet(void *device, Uint16 size, Uint16 param, Uint16 dlen,
                         n1_scatter_buffer *inv,n1_scatter_buffer *outv, int rlen,
                         Uint64 ctx, CallBackFn cb, void *cb_data,
                         int response_order, int req_queue)
{
   n1_request_buffer n1_buf;
   Uint32 req_id;
   int i;
   cavium_memset(&n1_buf, 0, sizeof(n1_buf));

   n1_buf.opcode = OP_IPSEC_PACKET_INBOUND; 
   n1_buf.size = size;
   n1_buf.param = param;
   n1_buf.dlen = dlen;
   n1_buf.rlen = rlen ;
   n1_buf.reserved = 0;
   n1_buf.ctx_ptr = ctx;
   
   n1_buf.incnt = inv->bufcnt;
   n1_buf.outcnt = outv->bufcnt;
   
   for (i = 0; i < inv->bufcnt; i++) {
      n1_buf.inptr[i] = CAST_TO_X_PTR((Uint8 *)inv->bufptr[i]);
      n1_buf.insize[i] = inv->bufsize[i];
      n1_buf.inoffset[i] = n1_buf.insize[i];
      n1_buf.inunit[i] = UNIT_8_BIT;
   }

   for (i = 0; i < outv->bufcnt; i++) {
      n1_buf.outptr[i] = CAST_TO_X_PTR((Uint8 *)outv->bufptr[i]);
      n1_buf.outsize[i] = outv->bufsize[i];
      n1_buf.outoffset[i] = n1_buf.outsize[i];
      n1_buf.outunit[i] = UNIT_8_BIT;
   }

#ifdef IPSEC_SCATTER_GATHER
   n1_buf.dma_mode = CAVIUM_SCATTER_GATHER;
#else
   n1_buf.dma_mode = CAVIUM_DIRECT;
#endif
   
   n1_buf.res_order = response_order;
   /*n1_buf.req_queue = req_queue;*/
   n1_buf.req_queue = 1;
   n1_buf.callback = CAST_TO_X_PTR(cb);
   n1_buf.cb_arg = CAST_TO_X_PTR(cb_data);
#ifdef CAVIUM_MULTICARD_API
    device = (cavium_device *)(m_device->data);
    m_device = (m_device->next)? m_device->next : device_list;    
#endif
   n1_buf.group = CAVIUM_IPSEC_GRP;
   n1_buf.ucode_idx = n1_get_ipsec_ucode_idx((cavium_device *)device);

   if(n1_buf.ucode_idx < 0)
   {
      cavium_error("n1_process_inbound_pkt: No Ipsec microcode found!\n");
      req_id = 0;
      goto cleanup;
   }
   if (do_request((cavium_device *)device, &n1_buf, &req_id)) {
      cavium_dbgprint("n1_process_inbound_packet: do_request failed");
       return -1;
   }
cleanup:
   return 0;
}

/*****************************************************************************/
/*! \ingroup IPSEC_OPS
* n1_process_outbound_packet
*
*   Processes Outbound IPSec packet -- encrypts the packet with
*       ciphers in the ctx in kernel space.
*
*
* \param device   Pointer to the device to be used (returned in n1_config_device).
* \param size   Param1 field as defined in the Microcode Spec.
* \param param   Param2 field as defined in the Microcode Spec.
* \param dlen   length of input (packet)
* \param inv   pointer to input data (packet to be processed) in iovec format
* \param outv   pointer to output buffer in iovec format 
* \param rlen   Expected length of output.  
* \param ctx   context handle.
* \param cb   callback function.
* \param cb_data   callback function argument
* \param response_order   Response Order (CAVIUM_RESPONSE_ORDERED or CAVIUM_RESPONSE_UNORDERED).
* \param req_queue   Queue on which this request has to be sent.
*
*
* \retval SUCCESS 0
* \retval FAILURE -1
*/
/****************************************************************************/
Uint32
n1_process_outbound_packet(void *device, Uint16 size, Uint16 param, Uint16 dlen,
                         n1_scatter_buffer * inv,n1_scatter_buffer *outv, int rlen,
                         Uint64 ctx, CallBackFn cb, void *cb_data,
                         int response_order, int req_queue)
{
   n1_request_buffer n1_buf; 
   Uint32 req_id;
   int i;
   cavium_dbgprint("n1_process_outbound_packet called\n");
   cavium_memset(&n1_buf, 0, sizeof(n1_buf));

   n1_buf.opcode = OP_IPSEC_PACKET_OUTBOUND; 
   n1_buf.size = size;
   n1_buf.param = param;
   n1_buf.dlen = dlen;
   n1_buf.rlen = rlen;
   n1_buf.reserved = 0;
   n1_buf.ctx_ptr = ctx;
   
   n1_buf.incnt = inv->bufcnt;
   n1_buf.outcnt = outv->bufcnt;
   
   for ( i = 0; i < inv->bufcnt; i++) {
      n1_buf.inptr[i] = CAST_TO_X_PTR((Uint8 *)inv->bufptr[i]);
      n1_buf.insize[i] = inv->bufsize[i];
      n1_buf.inoffset[i] = n1_buf.insize[i];
      n1_buf.inunit[i] = UNIT_8_BIT;
   }

   for ( i = 0; i < outv->bufcnt; i++) {
      n1_buf.outptr[i] = CAST_TO_X_PTR((Uint8 *)outv->bufptr[i]);
      n1_buf.outsize[i] = outv->bufsize[i];
      n1_buf.outoffset[i] = n1_buf.outsize[i];
      n1_buf.outunit[i] = UNIT_8_BIT;
   }

#ifdef IPSEC_SCATTER_GATHER
   n1_buf.dma_mode = CAVIUM_SCATTER_GATHER;
#else
   n1_buf.dma_mode = CAVIUM_DIRECT;
#endif
   n1_buf.res_order = response_order;
   /*n1_buf.req_queue = req_queue;*/
   n1_buf.req_queue = 1;
   n1_buf.callback = CAST_TO_X_PTR(cb);
   n1_buf.cb_arg = CAST_TO_X_PTR(cb_data);
   cavium_dbgprint("n1_process_outbound_packet: calling do_request\n");
#ifdef CAVIUM_MULTICARD_API
   device = (cavium_device *)(m_device->data);
   m_device = (m_device->next)? m_device->next : device_list; 
#endif
   n1_buf.group = CAVIUM_IPSEC_GRP;
   n1_buf.ucode_idx = n1_get_ipsec_ucode_idx((cavium_device *)device);

   if(n1_buf.ucode_idx < 0)
   {
      cavium_error("n1_process_outbound_pkt: No Ipsec microcode found!\n");
      req_id = 0;
      goto cleanup;
   }

   if (do_request((cavium_device *)device, &n1_buf, &req_id)) {
      cavium_dbgprint("n1_process_outbound_packet: do_request failed");
       return -1;
   }
cleanup:
   return 0;
}

#else /* !CAVIUM_NEW_API */

/*****************************************************************************/
/*! \ingroup IPSEC_OPS
* n1_config_device
*
* Configures  the device and returns list of Cavium devices found
*   in an abstract pointer.
*
* \retval NULL Failure
*/
/****************************************************************************/
void *
n1_config_device(void)
{
   if (device_list) {
       CAVIUM_MOD_INC_USE_COUNT;
       return device_list;
   } else {
       return NULL;
   }
}

/*****************************************************************************/
/*! \ingroup IPSEC_OPS
* n1_process_inbound_packet
*
*   Processes Inbound IPSec packet -- decrypts the packet with
*       ciphers in the ctx in kernel space.
*
*
* \param device   Pointer to the device to be used (returned in n1_config_device)
* \param size   Param1 field as defined in the Microcode Spec.
* \param param   Param2 field as defined in the Microcode Spec.
* \param dlen   length of input (packet)
* \param inbuffer   pointer to the input data.
* \param outbuffer   pointer to the output data.
* \param rlen   Expected length of output. 
* \param ctx   context handle.
* \param cb   callback function.
* \param cb_data   callback function argument
* \param response_order   Response Order (CAVIUM_RESPONSE_ORDERED or CAVIUM_RESPONSE_UNORDERED).
* \param req_queue   Queue on which this request has to be sent.
*
*
* \retval SUCCESS 0
* \retval FAILURE -1
*/
/****************************************************************************/
Uint32
n1_process_inbound_packet(void *device, Uint16 size, Uint16 param, Uint16 dlen,
                         Uint32 * inbuffer, Uint32 *outbuffer, int rlen,
                         Uint64 ctx, CallBackFn cb, void *cb_data,
                         int response_order, int req_queue)
{
   n1_request_buffer n1_buf;
   Uint32 req_id;
   int ucode_idx;
   cavium_device *n1_device;

   n1_device = (cavium_device *)device;
   n1_buf.group = CAVIUM_IPSEC_GRP;
   ucode_idx = n1_get_ipsec_ucode_idx(n1_device);
   if(ucode_idx < 0)
   {
      cavium_error("n1_process_inbound_pkt: No Ipsec microcode found!\n");
      req_id = 0;
      goto cleanup;
   }

   cavium_dbgprint("n1_process_inbound_packet  called\n");
   cavium_memset(&n1_buf, 0, sizeof(n1_buf));

   n1_buf.opcode = OP_IPSEC_PACKET_INBOUND; 
   n1_buf.size = size;
   n1_buf.param = param;
   n1_buf.dlen = dlen;
   n1_buf.rlen = rlen;
   n1_buf.reserved = 0;
   n1_buf.ctx_ptr = ctx;
   
   n1_buf.incnt = 1;
   n1_buf.outcnt = 1;
   
   n1_buf.inptr[0] = CAST_TO_X_PTR((Uint8 *)inbuffer);
   n1_buf.insize[0] = dlen;
   n1_buf.inoffset[0] = n1_buf.insize[0];
   n1_buf.inunit[0] = UNIT_8_BIT;

   n1_buf.outptr[0] = CAST_TO_X_PTR((Uint8 *)outbuffer);
   n1_buf.outsize[0] = rlen;
   n1_buf.outoffset[0] = n1_buf.outsize[0];
   n1_buf.outunit[0] = UNIT_8_BIT;

#ifdef IPSEC_SCATTER_GATHER
   n1_buf.dma_mode = CAVIUM_SCATTER_GATHER;
#else
   n1_buf.dma_mode = CAVIUM_DIRECT;
#endif
   
   n1_buf.res_order = response_order;
   /*n1_buf.req_queue = req_queue;*/
   n1_buf.req_queue = 1;
   n1_buf.callback = CAST_TO_X_PTR(cb);
   n1_buf.cb_arg = CAST_TO_X_PTR(cb_data);
   n1_buf.ucode_idx = ucode_idx;

   if (do_request((cavium_device *)device, &n1_buf, &req_id)) {
      cavium_dbgprint("n1_process_inbound_packet: do_request failed");
       return -1;
   }

cleanup:
   return 0;
}

/*****************************************************************************/
/*! \ingroup IPSEC_OPS
* n1_process_outbound_packet
*
*   Processes Outbound IPSec packet -- encrypts the packet with
*       ciphers in the ctx in kernel space.
*
*
* \param device   Pointer to the device to be used (returned in n1_config_device)
* \param size   Param1 field as defined in the Microcode Spec.
* \param param   Param2 field as defined in the Microcode Spec.
* \param dlen   length of input (packet)
* \param inbuffer   pointer to the input data.
* \param outbuffer   pointer to the output data.
* \param rlen   Expected length of output. 
* \param ctx   context handle.
* \param cb   callback function.
* \param cb_data   callback function argument
* \param response_order   Response order (CAVIUM_RESPONSE_ORDERED or CAVIUM_RESPONSE_UNORDERED).
* \param req_queue   Queue on which this request has to be sent.
*
*
* \retval SUCCESS 0
* \retval FAILURE -1
*/
/****************************************************************************/
Uint32
n1_process_outbound_packet(void *device, Uint16 size, Uint16 param, Uint16 dlen,
                         Uint32 * inbuffer, Uint32 *outbuffer, int rlen,
                         Uint64 ctx, CallBackFn cb, void *cb_data,
                         int response_order, int req_queue)
{
   n1_request_buffer n1_buf;
   Uint32 req_id;
   int ucode_idx;
   cavium_device *n1_device;

   n1_device = (cavium_device *)device;
   n1_buf.group = CAVIUM_IPSEC_GRP;
   ucode_idx = n1_get_ipsec_ucode_idx(n1_device);
   if(ucode_idx < 0)
   {
      cavium_error("n1_process_outbound_pkt: No Ipsec microcode found!\n");
      req_id = 0;
      goto cleanup;
   }

   cavium_dbgprint("n1_process_outbound_packet called\n");
   cavium_memset(&n1_buf, 0, sizeof(n1_buf));

   n1_buf.opcode = OP_IPSEC_PACKET_OUTBOUND; 
   n1_buf.size = size;
   n1_buf.param = param;
   n1_buf.dlen = dlen;
   n1_buf.rlen = rlen;
   n1_buf.reserved = 0;
   n1_buf.ctx_ptr = ctx;
   
   n1_buf.incnt = 1;
   n1_buf.outcnt = 1;

   n1_buf.inptr[0] = CAST_TO_X_PTR((Uint8 *)inbuffer);
   n1_buf.insize[0] = dlen;
   n1_buf.inoffset[0] = n1_buf.insize[0];
   n1_buf.inunit[0] = UNIT_8_BIT;

   n1_buf.outptr[0] = CAST_TO_X_PTR((Uint8 *)outbuffer);
   n1_buf.outsize[0] = rlen;
   n1_buf.outoffset[0] = n1_buf.outsize[0];
   n1_buf.outunit[0] = UNIT_8_BIT;

#ifdef IPSEC_SCATTER_GATHER
   n1_buf.dma_mode = CAVIUM_SCATTER_GATHER;
#else
   n1_buf.dma_mode = CAVIUM_DIRECT;
#endif
   n1_buf.res_order = response_order;
   /*n1_buf.req_queue = req_queue;*/
   n1_buf.req_queue = 1;
   n1_buf.callback = CAST_TO_X_PTR(cb);
   n1_buf.cb_arg = CAST_TO_X_PTR(cb_data);
   n1_buf.ucode_idx = ucode_idx;

   cavium_dbgprint("n1_process_outbound_packet: calling do_request\n");

   if (do_request((cavium_device *)device, &n1_buf, &req_id)) {
      cavium_dbgprint("n1_process_outbound_packet: do_request failed");
       return -1;
   }

cleanup:
   return 0;
}
#endif /* CAVIUM_NEW_API */


/*****************************************************************************/
/*! \ingroup IPSEC_OPS
* n1_write_ipsec_sa
*
*   Writes the IPSec SA into the context in kernel space.
*
*
* \param device   Pointer to the device to be used (returned in n1_config_device)
* \param proto   ESP or AH
* \param inner_version   Protocol version of inner IP header.
* \param outer_version   Protocol version of outer IP header.
* \param mode   SA mode (TUNNEL or TRANSPORT)
* \param dir   Direction (INBOUND or OUTBOUND)
* \param cypher   Encryption algorithm
*              (DESCBC, DES3CBC, AES128CBC, AES192CBC, AES256CBC)
* \param e_key   Encryption key
* \param auth   Authentication algorithm
*              (MD5HMAC96 or SHA1HMAC96)
* \param a_key   Authentication key
* \param template   Template for Outer IP header
* \param spi   32 bit SPI value
* \param copy_df   0 (copy the df bit for packet fragments) or 1 (do not copy)
* \param udp_encap   0 (no UDP encapsulation) or 1 (UDP encapsulation)
* \param ctx   context handle.
* \param next_ctx   Next context (In case of bundles) Non-bundles it is NULL  
* \param in_buffer   Pointer to input buffer (used for SA filling)
* \param out_buffer  Pointer to output buffer
* \param cb   callback function.
* \param cb_data   callback function argument
* \param res_order   Response order (CAVIUM_RESPONSE_ORDERED or CAVIUM_RESPONSE_UNORDERED).
* \param req_queue   Queue on which this request has to be sent.
*
*
* \retval SUCCESS 0
* \retval FAILURE -1
*/
/****************************************************************************/
Uint32
n1_write_ipsec_sa(void *device, IpsecProto proto, Version inner_version, 
      Version outer_version, IpsecMode mode,
          Direction dir, EncType cypher, Uint8 *e_key, AuthType auth,
          Uint8 *a_key, Uint8 template[40], Uint32 spi, Uint8 copy_df,
          Uint8 udp_encap, Uint64 ctx, Uint64 next_ctx, Uint32 *in_buffer, 
          Uint32 *out_buffer, CallBackFn cb, void *cb_data, int res_order,
          int req_queue)          
{
   Uint8 *p;
   Uint16 *control;
   n1_request_buffer n1_buf;
   Uint32 req_id;
   Uint32 len;
   int queue = 0;
   int s=0;
   int ucode_idx;
   cavium_device *n1_device;
#ifdef CNS3000
   Uint8 iv[] = {0x79, 0x75, 0x78, 0xf2, 0xcb, 0x45, 0x22, 0x22, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8};
	Uint32 ivsize;
#endif

   n1_device = (cavium_device *)device;
   n1_buf.group = CAVIUM_IPSEC_GRP;
   ucode_idx = n1_get_ipsec_ucode_idx(n1_device);
   if(ucode_idx < 0)
   {
      cavium_error("n1_write_ipsec_sa: No Ipsec microcode found!\n");
      req_id = 0;
      goto cleanup;
   }
/*   if (n1_device->device_id != NPX_DEVICE)
      queue = (ucode_idx == UCODE_IDX+1)? 0 : HIGH_PRIO_QUEUE;
*/
   p = (Uint8*)in_buffer;

   control = (Uint16*)p;
   *control = 0;

    /* Populate the control structure as the MC2 microcode requires */

   *control = (((dir& 0x1) << IPSEC_DIRECTION_SHIFT) |
      ((VALID_SA & 0x1) << IPSEC_VALID_SHIFT) | 
      ((outer_version & 0x1) << IPSEC_VERSION_SHIFT) |
      ((inner_version & 0x1) << (IPSEC_VERSION_SHIFT+1)) |
      ((mode & 0x1) << IPSEC_MODE_SHIFT) |
      ((proto & 0x1) << IPSEC_PROT_SHIFT) |
            ((udp_encap & 0x3) << IPSEC_ENCAP_SHIFT) |  
      ((cypher & 0x7) << IPSEC_CIPHER_SHIFT) |
      ((auth & 0x3) << IPSEC_AUTH_SHIFT) |
        ((dir==INBOUND) ? (0x0 << IPSEC_SELECTOR_SHIFT) : ((copy_df & 0x1) << IPSEC_DF_SHIFT)) |
       ((0x0) << IPSEC_FT_SHIFT) |                         
       ((next_ctx ? 1 : 0) << IPSEC_NEXT_SA_SHIFT));

   *control = htobe16(*control);
   cavium_dbgprint("write_ipsec_sa : control 0x%x\n", *control);

   p += 2; 

/* XXX: Use proper macro like USE_IV_FROM_SA */
#ifdef CNS3000
        if (dir == OUTBOUND) 
		*(Uint16*)p = (1 << 14);
        else
		*(Uint16*)p = 0;
	*(Uint16*)p = htobe16(*(Uint16*)p);
#else
   	*(Uint16*)p = 0;
#endif
   p += 2; 

   cavium_dbgprint("write_ipsec_sa: spi 0x%x\n", spi);

   memcpy(p,&spi,4);
   p += 4;

   if(cypher != NO_CYPHER)
      memcpy(p, e_key, 32);
   else
      memset(p, 0, 32);

   p += 32;

   switch (auth) {
      case SHA1HMAC96:
         memcpy(p,a_key,20);
      break;

      case MD5HMAC96:
         memcpy(p,a_key,16);
      break;

      default:
      case NO_AUTH:
         memset(p,0,24);
      break;
   }
   p += 24;

    len = (Uint8*)p - (Uint8*)in_buffer;

   /* Next SA */
   /* We are now passing the physical addr directly as context */
   /* so no need for cavium_vtophys */
   *(Uint64*)p = htobe64(next_ctx);

   p += 8;
   len+=8;

   if (dir == OUTBOUND) {
        if (mode==TUNNEL) {
      if (outer_version == IPv4) {
                    if (!udp_encap) {
                         /* Normal IPSec processing */
                          memcpy(p,template,20);
                          p+=20;
                          len+=20;
                    } else {
                           /* UDP Encapsulation */
                        memcpy(p,template,28);
              p+=28;
         len+=28;
                    }
      } else {
         /* IPv6 */
             memcpy(p, template, 40);
             p+=40;
               len+=40;
      }
         }
    }

   cavium_memset(p, 0, IPSEC_CONTEXT_SIZE-len);

#ifdef CNS3000
        ivsize = (cypher > 2) ? 16 : 8;
        if (dir == OUTBOUND) {
      //  	getrandom(iv, ivsize);
        	/* 15, 16 has IV */
                p = (Uint8*)in_buffer + 120;  
                memcpy (p, iv, ivsize);
                len = (Uint8*)p - (Uint8*)in_buffer + ivsize;
	}
#endif
   cavium_memset(&n1_buf, 0, sizeof(n1_buf));

   n1_buf.opcode = ((dir == INBOUND) ? OP_WRITE_INBOUND_IPSEC_SA : OP_WRITE_OUTBOUND_IPSEC_SA); 
   n1_buf.size = 0;
   n1_buf.param = 0;
   n1_buf.dlen = len;
   n1_buf.rlen = 0;
   n1_buf.reserved = 0;
   n1_buf.ctx_ptr = ctx;

#ifdef IPSEC_SCATTER_GATHER
   n1_buf.dma_mode = CAVIUM_SCATTER_GATHER;
#else
   n1_buf.dma_mode = CAVIUM_DIRECT;
#endif

   n1_buf.incnt = 1;
   /* For DIRECT mode, we need out_buffer for completion code.
    * For SCATTER_GATHER, we do not need this, because completion
    * code goes to rptr of command
    */
   if(n1_buf.dma_mode == CAVIUM_DIRECT)
      n1_buf.outcnt=1;
   else
      n1_buf.outcnt=0; 

   n1_buf.inptr[0] = CAST_TO_X_PTR((Uint8 *)in_buffer);
   n1_buf.insize[0] = len;
   n1_buf.inoffset[0] = n1_buf.insize[0];
   n1_buf.inunit[0] = UNIT_8_BIT;

   if(n1_buf.outcnt)
   {
      n1_buf.outptr[0] = CAST_TO_X_PTR((Uint8 *)out_buffer);
      n1_buf.outsize[0] = 0; 
      n1_buf.outoffset[0] = n1_buf.outsize[0];
      n1_buf.outunit[0] = UNIT_8_BIT;
   }

   n1_buf.res_order = res_order;
   n1_buf.req_queue = queue;
   n1_buf.callback = CAST_TO_X_PTR(cb);
   n1_buf.cb_arg = CAST_TO_X_PTR(cb_data);
   n1_buf.ucode_idx = ucode_idx;

   if(cavium_debug_level >= 3)
      cavium_dump("IpsecSA", (Uint8 *)in_buffer, len);

   /* Disabling SoftIRQ's to maximize WriteSA success*/
   cavium_softirq_disable(s);
   if (do_request((cavium_device *)device, &n1_buf, &req_id)) {
      cavium_softirq_enable(s);
      cavium_error("n1_write_ipsec_sa: do_request failed");
       return -1;
   }
   cavium_softirq_enable(s);

cleanup:
   return 0;
}


/*****************************************************************************/
/*! \ingroup IPSEC_OPS
* n1_invalidate_ipsec_sa
*
*       Invalidate IPSec SA
*
*
* \param device   Pointer to the device to be used (returned in n1_config_device)
* \param ctx   context handle.
* \param in_buffer   Pointer to input buffer (used for SA filling)
* \param out_buffer   Pointer to output buffer
* \param cb   callback function.
* \param cb_data   callback function argument
* \param res_order   Response order (CAVIUM_RESPONSE_ORDERED or CAVIUM_RESPONSE_UNORDERED).
* \param req_queue   Queue on which this request has to be sent.
*
*
* \retval SUCCESS 0
* \retval FAILURE -1
*/
/****************************************************************************/
Uint32
n1_invalidate_ipsec_sa(void *device, Uint64 ctx, Uint32 *in_buffer, Uint32 *out_buffer, CallBackFn cb, void *cb_data, int res_order,int req_queue)          
{
   Uint8 *p;
   Uint16 *control;
   n1_request_buffer n1_buf;
   Uint32 req_id;
   Uint32 len=16;
   /*int queue = req_queue;*/
   int s=0;
   int ucode_idx;
   cavium_device *n1_device;
   n1_device = (cavium_device *)device;
   n1_buf.group = CAVIUM_IPSEC_GRP;
    ucode_idx = n1_get_ipsec_ucode_idx(n1_device);
    if(ucode_idx < 0)
   {
      cavium_error("n1_invalidate_ipsec_sa: No Ipsec microcode found!\n");
      req_id = 0;
      goto cleanup;
   }

   p = (Uint8*)in_buffer;

   control = (Uint16*)p;
   *control = 0x0;

    /* Populate the control structure as the MC2 microcode requires */

   cavium_dbgprint("invalidate_ipsec_sa : control 0x%x\n", *control);

   
   cavium_memset(&n1_buf, 0, sizeof(n1_buf));

   n1_buf.opcode = OP_WRITE_INBOUND_IPSEC_SA; 
   n1_buf.size = 0;
   n1_buf.param = 0;
   n1_buf.dlen =16;
   n1_buf.rlen = 0;
   n1_buf.reserved = 0;
   n1_buf.ctx_ptr = ctx;

#ifdef IPSEC_SCATTER_GATHER
   n1_buf.dma_mode = CAVIUM_SCATTER_GATHER;
#else
   n1_buf.dma_mode = CAVIUM_DIRECT;
#endif

   n1_buf.incnt = 1;
   /* For DIRECT mode, we need out_buffer for completion code.
    * For SCATTER_GATHER, we do not need this, because completion
    * code goes to rptr of command
    */
   if(n1_buf.dma_mode == CAVIUM_DIRECT)
      n1_buf.outcnt=1;
   else
      n1_buf.outcnt=0;

   n1_buf.inptr[0] = CAST_TO_X_PTR((Uint8 *)in_buffer);
   n1_buf.insize[0] = 16;
   n1_buf.inoffset[0] = n1_buf.insize[0];
   n1_buf.inunit[0] = UNIT_8_BIT;

   if(n1_buf.outcnt)
   {
      n1_buf.outptr[0] = CAST_TO_X_PTR((Uint8 *)out_buffer);
      n1_buf.outsize[0] = 0; 
      n1_buf.outoffset[0] = n1_buf.outsize[0];
      n1_buf.outunit[0] = UNIT_8_BIT;
   }

   n1_buf.res_order = res_order;
   /*n1_buf.req_queue = queue;*/
   n1_buf.req_queue = 0;
   n1_buf.callback = CAST_TO_X_PTR(cb);
   n1_buf.cb_arg = CAST_TO_X_PTR(cb_data);
   n1_buf.ucode_idx = ucode_idx;

   if(cavium_debug_level >= 3)
      cavium_dump("IpsecSA", (Uint8 *)in_buffer, len);

   /* Disabling SoftIRQ's to maximize WriteSA success*/
   cavium_softirq_disable(s);
   if (do_request((cavium_device *)device, &n1_buf, &req_id)) {
      cavium_softirq_enable(s);
      cavium_error("n1_write_ipsec_sa: do_request failed");
       return -1;
   }
   cavium_softirq_enable(s);

cleanup:
   return 0;
}

void n1_flush_packet_queue(void *device)
{
   flush_queue((cavium_device *)device,1);
   return;
}
/*
 *
 * Revision 1.10  2004/07/09 01:08:21  bimran
 * Added scatter gather support
 *
 * Revision 1.9  2004/07/06 21:31:24  tsingh
 * moved CallBackFn definition from linux_main.h to linux_sysdep.h
 *
 * Revision 1.8  2004/06/28 21:15:51  tahuja
 * commented out #include "linux_main.h".
 *
 * Revision 1.7  2004/06/26 01:15:58  bimran
 * defined linux specific mod counts.
 *
 * Revision 1.6  2004/06/10 18:17:39  tsingh
 * Fixed corener case where return value might be tretraed incorrectly because of sugned and unsiged differences.(bimran)
 *
 * Revision 1.5  2004/06/04 18:21:50  tsingh
 * fixed dealloc_context()
 *
 * Revision 1.4  2004/05/02 19:35:13  bimran
 * Added Copyright notice.
 *
 * Revision 1.3  2004/05/01 00:48:45  tsingh
 * Fixed typo.
 *
 * Revision 1.2  2004/04/30 02:57:56  bimran
 * Added NPLUS support.
 *
 * Revision 1.1  2004/04/15 22:38:38  bimran
 * Checkin of the code from India with some cleanups.
 *
 */

