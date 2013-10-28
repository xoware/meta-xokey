
/* cavium_crypto.c */
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
#include "cavium_common.h"
#include <cavium_ssl.h>
#include <cavium_endian.h>
#include "cavium_list.h"
#include "cavium.h"
#include "context_memory.h"
#include "request_manager.h"

#define SHA256_HASH_LEN 32
#define SHA384_HASH_LEN 48
#define SHA512_HASH_LEN 64
#define SHA2_HASH_IV_LEN 64
#ifndef UINT64_C
#define UINT64_C(x)   ((unsigned long long) (x ## ull))
#endif

struct api_arg
{ 
   Uint16 alg_type;
   Uint16 rlen;
   Uint16 dlen;
   n1_scatter_buffer inv;
   n1_scatter_buffer outv;
};
 
Csp1DmaMode global_dma_mode=CAVIUM_DIRECT;
extern int dev_count;
extern cavium_device cavium_dev[];
extern struct N1_Dev *device_list;
void *
n1_kern_config_device(void)
{
   if (device_list) {
      CAVIUM_MOD_INC_USE_COUNT;

      return device_list;
   }
   else {
      return NULL;
   }
}

void
n1_kern_unconfig_device(void)
{
   CAVIUM_MOD_DEC_USE_COUNT;
   return;
}

Uint32
kernHash(void* device,int size, int param, Uint16 dlen, Uint16 rlen, n1_scatter_buffer *inv, n1_scatter_buffer *outv, CallBackFn cb, void *cb_data)
{
   n1_request_buffer buffer;
   Uint32 req_id =0;
   int i =0;
   memset(&buffer,0,sizeof(n1_request_buffer));
   buffer.opcode = (0x3<<9) | (global_dma_mode<<7) | MAJOR_OP_HASH;
   buffer.size = size;
   buffer.param = param; 
   buffer.reserved = 0;
   buffer.ctx_ptr = 0;
   buffer.dlen = dlen;
   buffer.rlen = rlen;

   buffer.incnt = inv->bufcnt;
   buffer.outcnt = outv->bufcnt;

   buffer.inptr[i] = (unsigned long) inv->bufptr[i];
   buffer.insize[i] = inv->bufsize[0];;
   buffer.inoffset[i] = ROUNDUP8(buffer.insize[i]);
   buffer.inunit[i] = UNIT_8_BIT;

   buffer.outptr[i] = (unsigned long) (outv->bufptr[i]);
   buffer.outsize[i] = outv->bufsize[0];
   buffer.outoffset[i] = 24;
   buffer.outunit[i] = UNIT_8_BIT;

   buffer.dma_mode = CAVIUM_DIRECT;
   buffer.res_order = CAVIUM_RESPONSE_ORDERED; 
   buffer.req_queue = 0;
   buffer.status = 0;
   buffer.callback = CAST_TO_X_PTR(cb);
   buffer.cb_arg = CAST_TO_X_PTR(cb_data);
   if ((do_request((cavium_device *)device, &buffer, &req_id))) {
      cavium_dbgprint("kernhash: do_request failed");
      return -1;
   }
  return 0;
}


Uint32
kernHmac(void* device,int size, int param, Uint16 dlen, Uint16 rlen, n1_scatter_buffer *inv, n1_scatter_buffer *outv, CallBackFn cb, void *cb_data)
{
   n1_request_buffer buffer;
   Uint32 req_id =0;
   int i=0;
   memset(&buffer,0,sizeof(n1_request_buffer));

   buffer.opcode = (0x3<<9) | (global_dma_mode<<7) | MAJOR_OP_HMAC;
   buffer.size = size;
   buffer.param = param;
   buffer.dlen = dlen;
   buffer.rlen = rlen;

   buffer.incnt = inv->bufcnt;
   buffer.outcnt = outv->bufcnt;

   buffer.inptr[i] = (unsigned long) inv->bufptr[i];
   buffer.insize[i] = inv->bufsize[0];
   buffer.inoffset[i] = ROUNDUP8(buffer.insize[i]);
   buffer.inunit[i] = UNIT_8_BIT;

   buffer.outptr[i] = (unsigned long) outv->bufptr[i];
   buffer.outsize[i] = outv->bufsize[0];
   buffer.outoffset[i] = 24;
   buffer.outunit[i] = UNIT_8_BIT;

   buffer.dma_mode = CAVIUM_DIRECT;
   buffer.res_order = CAVIUM_RESPONSE_ORDERED;
   buffer.req_queue = 0;
   buffer.status = 0;
   buffer.callback = CAST_TO_X_PTR(cb);
   buffer.cb_arg = CAST_TO_X_PTR(cb_data);
   if ((do_request((cavium_device *)device, &buffer, &req_id))) {
      cavium_dbgprint("kernhmac: do_request failed");
      return -1;
   }
  return 0;
}

int
kernAes(void *device,int enc, Uint16 size,
         Uint16 param, Uint16 dlen, Uint16 rlen,
         n1_scatter_buffer *inv,
         n1_scatter_buffer *outv,
         CallBackFn cb,void *cb_data)
{
   n1_request_buffer n1_buf;
   Uint32 req_id;
   int i;

   cavium_memset(&n1_buf,0,sizeof(n1_buf));
   n1_buf.opcode = ((enc ? 0x6:0x7)<<8) | MAJOR_OP_ENCRYPT_DECRYPT;
   n1_buf.size = size;
   n1_buf.param = param;
   n1_buf.dlen = dlen;
   n1_buf.rlen = rlen;
   n1_buf.reserved = 0;
   n1_buf.ctx_ptr = 0;

   n1_buf.incnt = inv->bufcnt;
   n1_buf.outcnt = outv->bufcnt;
   for( i = 0; i < inv->bufcnt; i++ )
   {
      n1_buf.inptr[i] = (unsigned long) inv->bufptr[i];
      n1_buf.insize[i] = inv->bufsize[i];
      n1_buf.inoffset[i] = n1_buf.insize[i];
      n1_buf.inunit[i] = UNIT_8_BIT;
   }
   for ( i = 0; i < outv->bufcnt; i++)
   {
      n1_buf.outptr[i] = (unsigned long) outv->bufptr[i];
      n1_buf.outsize[i] = outv->bufsize[i];
      n1_buf.outoffset[i] = n1_buf.outsize[i];
      n1_buf.outunit[i] = UNIT_8_BIT;
   }
   n1_buf.dma_mode = CAVIUM_DIRECT;
   n1_buf.res_order = CAVIUM_RESPONSE_ORDERED;
   n1_buf.req_queue = 0;
   n1_buf.callback = CAST_TO_X_PTR(cb);
   n1_buf.cb_arg = CAST_TO_X_PTR(cb_data);
   if (do_request((cavium_device *)device, &n1_buf, &req_id))
   {
      cavium_dbgprint("n1_process_outbound_packet: do_request failed");
      return -1;
   }
   return 0;
}


int
kern3Des(void *device,int enc, Uint16 size,
         Uint16 param, Uint16 dlen, Uint16 rlen,
         n1_scatter_buffer *inv,
         n1_scatter_buffer *outv,
         CallBackFn cb,void *cb_data)
{
   n1_request_buffer n1_buf;
   Uint32 req_id;
   int i;

   cavium_memset(&n1_buf,0,sizeof(n1_buf));
   n1_buf.opcode = ((enc ? 0x4:0x5)<<8) | MAJOR_OP_ENCRYPT_DECRYPT;
   n1_buf.size = size;
   n1_buf.param = param;
   n1_buf.dlen = dlen;
   n1_buf.rlen = rlen;
   n1_buf.reserved = 0;
   n1_buf.ctx_ptr = 0;

   n1_buf.incnt = inv->bufcnt;
   n1_buf.outcnt = outv->bufcnt;
   for( i = 0; i < inv->bufcnt; i++ )
   {
      n1_buf.inptr[i] = (unsigned long) inv->bufptr[i];
      n1_buf.insize[i] = inv->bufsize[i];
      n1_buf.inoffset[i] = n1_buf.insize[i];
      n1_buf.inunit[i] = UNIT_8_BIT;
   }
   for ( i = 0; i < outv->bufcnt; i++)
   {
      n1_buf.outptr[i] = (unsigned long) outv->bufptr[i];
      n1_buf.outsize[i] = outv->bufsize[i];
      n1_buf.outoffset[i] = n1_buf.outsize[i];
      n1_buf.outunit[i] = UNIT_8_BIT;
   }
   n1_buf.dma_mode = CAVIUM_DIRECT;
   n1_buf.res_order = CAVIUM_RESPONSE_ORDERED;
   n1_buf.req_queue = 0;
   n1_buf.callback = CAST_TO_X_PTR(cb);
   n1_buf.cb_arg = CAST_TO_X_PTR(cb_data);
   if (do_request((cavium_device *)device, &n1_buf, &req_id))
   {
      cavium_dbgprint("n1_process_outbound_packet: do_request failed");
      return -1;
   }
   return 0;
}

int
kern_ModExp (void *device, Uint16 size,
      Uint16 param, Uint16 dlen,
      n1_scatter_buffer *inv,
      n1_scatter_buffer *outv,
      int rlen, CallBackFn cb,
      void *cb_data, int response_order)
{
   n1_request_buffer n1_buf;
   Uint32 req_id;
   int i;

   cavium_memset(&n1_buf,0,sizeof(n1_buf));
   if( size >=17 && size <=128 )
      n1_buf.opcode = 4;
   else if ( size > 128 && size <= 512 )
      n1_buf.opcode = 2;
   n1_buf.size = size;
   n1_buf.param = param;
   n1_buf.dlen = dlen;
   n1_buf.rlen = rlen;
   n1_buf.reserved = 0;
   n1_buf.ctx_ptr = 0;
   n1_buf.incnt = inv->bufcnt;
   n1_buf.outcnt = outv->bufcnt;

   for( i = 0; i < inv->bufcnt; i++ )
   {
      n1_buf.inptr[i] = (unsigned long) inv->bufptr[i];
      n1_buf.insize[i] = inv->bufsize[i];
      n1_buf.inoffset[i] = n1_buf.insize[i];
      n1_buf.inunit[i] = UNIT_8_BIT;
   }
   for ( i = 0; i < outv->bufcnt; i++)
   {
      n1_buf.outptr[i] = (unsigned long) outv->bufptr[i];
      n1_buf.outsize[i] = outv->bufsize[i];
      n1_buf.outoffset[i] = n1_buf.outsize[i];
      n1_buf.outunit[i] = UNIT_8_BIT;
   }
   n1_buf.dma_mode = CAVIUM_DIRECT;
   n1_buf.res_order = response_order;
   n1_buf.req_queue = 0;
   n1_buf.callback = CAST_TO_X_PTR(cb);
   n1_buf.cb_arg = CAST_TO_X_PTR(cb_data);

   n1_buf.group = CAVIUM_SSL_GRP;
   n1_buf.ucode_idx = UCODE_IDX;
   if (do_request((cavium_device *)device, &n1_buf, &req_id))
   {
      cavium_dbgprint("n1_process_outbound_packet: do_request failed");
      return -1;
   }
   return 0;
}




EXPORT_SYMBOL(n1_kern_config_device);
EXPORT_SYMBOL(n1_kern_unconfig_device);
EXPORT_SYMBOL(kernHash);
EXPORT_SYMBOL(kernHmac);
EXPORT_SYMBOL(kernAes);
EXPORT_SYMBOL(kern3Des);
EXPORT_SYMBOL(kern_ModExp);
