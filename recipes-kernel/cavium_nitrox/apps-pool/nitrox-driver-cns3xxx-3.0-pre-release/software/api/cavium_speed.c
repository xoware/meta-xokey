/* cavium_speed.c */
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
#include <cavium_ssl.h>
#include <cavium_endian.h>
#include "cavium_list.h"
#include "cavium.h"
#include "context_memory.h"
#include "request_manager.h"

#define APP_DATA 3

extern int dev_count;
extern cavium_device cavium_dev[];
extern struct N1_Dev *device_list;
#ifdef CAVIUM_MULTICARD_API
struct N1_Dev *ssl_m_device = NULL;
void ssl_check_list(void);
void ssl_delete_list(void *);
#endif

void *
n1_ssl_config_device(void)
{
   if (device_list) {
      CAVIUM_MOD_INC_USE_COUNT;
#ifdef CAVIUM_MULTICARD_API
      ssl_check_list();
      ssl_m_device = device_list;
#endif
      return device_list;
   } 
   else {
      return NULL;
   }
}

#ifdef CAVIUM_MULTICARD_API
void ssl_check_list(void)
{
   int i=0;
   for(i=0;i<dev_count;i++)
   if(!(cavium_dev[i].enable))
      ssl_delete_list((void *)(&cavium_dev[i]));
}

void ssl_delete_list(void *delete)
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


void 
n1_ssl_unconfig_device(void) 
{
   CAVIUM_MOD_DEC_USE_COUNT;
   return;
}

int 
n1_RsaGen (void *device, Uint16 size, 
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
   if(size <= 128)
      n1_buf.opcode = 0x404; 
   else if (size <= 256)
      n1_buf.opcode = 0x402; 
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
      n1_buf.inptr[i] = (unsigned long)inv->bufptr[i];
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

   if (do_request((cavium_device *)device, &n1_buf, &req_id)) { 
      cavium_dbgprint("n1_process_outbound_packet: do_request failed");
      return -1;
   }
   return 0;
}

int 
n1_ModExp (void *device, Uint16 size,
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
   if( size == 64 || size == 96 || size == 128 )
      n1_buf.opcode = 4;
   else if ( size == 192 || size == 256 ) 
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

int 
n1_RsaNoCrt (void *device, Uint16 size, 
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
   if( size <= 128 )
      n1_buf.opcode = 0x304;  
   else if (size <= 256 )
      n1_buf.opcode = 0x302; 
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

int 
n1_encrypt_record(void *device, Uint16 size,
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
   n1_buf.opcode = (0x6<<8) | MAJOR_OP_ENCRYPT_DECRYPT;
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
int 
n1_rc4_initialize(void *device, Uint64 context_handle,
         Uint16 dlen, 
         n1_scatter_buffer *inv, 
         n1_scatter_buffer *outv,
         int rlen, CallBackFn cb, 
         void *cb_data, int response_order) 
{
   n1_request_buffer n1_buf;
   Uint32 req_id;

   cavium_memset(&n1_buf,0,sizeof(n1_buf));
   n1_buf.opcode = (0x9<<8) |  MAJOR_OP_RANDOM_WRITE_CONTEXT;
   n1_buf.size = 0;
   n1_buf.param = 0;
   n1_buf.dlen = dlen;
   n1_buf.rlen = 0;
   n1_buf.ctx_ptr = context_handle;

   n1_buf.incnt = inv->bufcnt;
   n1_buf.outcnt = 0;

   n1_buf.inptr[0] = (unsigned long) inv->bufptr[0];
   n1_buf.insize[0] = inv->bufsize[0];
   n1_buf.inoffset[0] = ROUNDUP8(n1_buf.insize[0]);
   n1_buf.inunit[0] = UNIT_8_BIT;

   n1_buf.outptr[0] = (unsigned long) outv->bufptr[0];
   n1_buf.outsize[0] = outv->bufsize[0];
   n1_buf.outoffset[0] = ROUNDUP8(n1_buf.outsize[0]);
   n1_buf.outunit[0] = UNIT_8_BIT;

   n1_buf.dma_mode = CAVIUM_DIRECT;
   n1_buf.res_order = response_order;
   n1_buf.req_queue = 0;
   n1_buf.callback = CAST_TO_X_PTR(cb);
   n1_buf.cb_arg = CAST_TO_X_PTR(cb_data);
   n1_buf.group = CAVIUM_SSL_GRP;
   n1_buf.ucode_idx = UCODE_IDX;

   if (do_request((cavium_device *)device, &n1_buf, &req_id)) 
   {
      cavium_dbgprint("n1_rc4_initialize: do_request failed");
      return -1;
   }
   return 0;
}

int 
n1_rc4_encrypt_record(void *device, Uint64 context_handle, 
         Uint16 dlen, 
         n1_scatter_buffer *inv,
         n1_scatter_buffer *outv,
         int rlen, CallBackFn cb, 
         void *cb_data, int response_order) 
{
   n1_request_buffer n1_buf;
   Uint32 req_id;

   cavium_memset(&n1_buf,0,sizeof(n1_buf));
   n1_buf.opcode = (CAVIUM_NO_UPDATE<<13) |  MAJOR_OP_ENCRYPT_DECRYPT;
   n1_buf.size = 0;
   n1_buf.param = 0;
   n1_buf.dlen = dlen;
   n1_buf.rlen = rlen;
   n1_buf.ctx_ptr = context_handle;

   n1_buf.incnt = inv->bufcnt;
   n1_buf.outcnt = outv->bufcnt;

   n1_buf.inptr[0] = CAST_TO_X_PTR(inv->bufptr[0]);
   n1_buf.insize[0] = inv->bufsize[0];
   n1_buf.inoffset[0] = ROUNDUP8(n1_buf.insize[0]);
   n1_buf.inunit[0] = UNIT_8_BIT;

   n1_buf.outptr[0] = CAST_TO_X_PTR(outv->bufptr[0]);
   n1_buf.outsize[0] = outv->bufsize[0];
   n1_buf.outoffset[0] = ROUNDUP8(n1_buf.outsize[0]);
   n1_buf.outunit[0] = UNIT_8_BIT;

   n1_buf.dma_mode = CAVIUM_DIRECT;
   n1_buf.res_order = response_order;
   n1_buf.req_queue = 0;
   n1_buf.callback = CAST_TO_X_PTR(cb);
   n1_buf.cb_arg = CAST_TO_X_PTR(cb_data);
   n1_buf.group = CAVIUM_SSL_GRP;
   n1_buf.ucode_idx = UCODE_IDX;

   if (do_request((cavium_device *)device, &n1_buf, &req_id)) 
   {
      cavium_dbgprint("n1_rc4_encrypt: do_request failed");
      return -1;
   }
   return 0;
}

Uint32 
n1_EncryptRecord3Des (void *device, Uint16 size, 
         Uint16 param, Uint16 dlen, 
         Uint64 context_handle, HashType hash_type,
         n1_scatter_buffer *inv, 
         n1_scatter_buffer *outv,
         int rlen, CallBackFn cb, 
         void *cb_data, int response_order) 
{
   n1_request_buffer n1_buf;
   Uint32 req_id;
   int i;

   cavium_memset(&n1_buf,0,sizeof(n1_buf));
   n1_buf.opcode = (APP_DATA << 12) | MAJOR_OP_ENCRYPT_DECRYPT_RECORD;
   n1_buf.size = size;
   n1_buf.param = param;
   n1_buf.dlen = dlen;
   n1_buf.rlen = rlen;
   n1_buf.reserved = 0;
   n1_buf.ctx_ptr = context_handle;

   n1_buf.incnt = inv->bufcnt;
   n1_buf.outcnt = outv->bufcnt;
   for( i = 0; i < inv->bufcnt; i++ )
   {
      n1_buf.inptr[i] = (unsigned long) inv->bufptr[i];
      n1_buf.insize[i] = inv->bufsize[i];
      n1_buf.inoffset[i] = n1_buf.insize[i];
      n1_buf.inunit[i] = UNIT_8_BIT;
   }
   for ( i = 0; i < outv->bufcnt; i++) {
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

Uint32 
n1_EncryptRecordAes (void *device, Uint16 size, 
         Uint16 param, Uint16 dlen, 
         Uint64 context_handle, HashType hash_type, 
         AesType aes_type, 
         n1_scatter_buffer *inv,
         n1_scatter_buffer *outv,
         int rlen, CallBackFn cb,
         void *cb_data, int response_order)
{
   n1_request_buffer n1_buf;
   Uint32 req_id;
   int i;

   cavium_memset(&n1_buf,0,sizeof(n1_buf));
   n1_buf.opcode = (APP_DATA << 12) | MAJOR_OP_ENCRYPT_DECRYPT_RECORD;
   n1_buf.size = size;
   n1_buf.param = param;
   n1_buf.dlen = dlen;
   n1_buf.rlen = rlen;
   n1_buf.reserved = 0;
   n1_buf.ctx_ptr = context_handle;

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

Uint32 
n1_EncryptRecordRc4 (void *device, Uint16 size, 
         Uint16 param, Uint16 dlen,
         Uint64 context_handle, HashType hash_type, 
         n1_scatter_buffer *inv,
         n1_scatter_buffer *outv, 
         int rlen, CallBackFn cb, 
         void *cb_data, int response_order) 
{
   n1_request_buffer n1_buf;
   Uint32 req_id;
   int i;

   cavium_memset(&n1_buf,0,sizeof(n1_buf));
   n1_buf.opcode = (APP_DATA << 12) | MAJOR_OP_ENCRYPT_DECRYPT_RECORD;
   n1_buf.size = size; 
   n1_buf.param = param; 
   n1_buf.dlen = dlen; 
   n1_buf.rlen = rlen; 
   n1_buf.reserved = 0; 
   n1_buf.ctx_ptr = context_handle;
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
   n1_buf.req_queue = 1;
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

Uint64 
n1_ssl_alloc_context(void *device)
{
   return alloc_context((cavium_device *)device,CONTEXT_SSL);
}

void 
n1_ssl_dealloc_context(void *device,Uint64 ctx) 
{
   dealloc_context((cavium_device *)device,CONTEXT_SSL,ctx);
}

EXPORT_SYMBOL (n1_ssl_dealloc_context);
EXPORT_SYMBOL (n1_ssl_alloc_context);
EXPORT_SYMBOL(n1_encrypt_record); 
EXPORT_SYMBOL(n1_ModExp); 
EXPORT_SYMBOL(n1_RsaGen); 
EXPORT_SYMBOL(n1_RsaNoCrt); 
EXPORT_SYMBOL(n1_rc4_initialize); 
EXPORT_SYMBOL(n1_rc4_encrypt_record); 
EXPORT_SYMBOL(n1_EncryptRecordAes); 
EXPORT_SYMBOL(n1_EncryptRecord3Des); 
EXPORT_SYMBOL(n1_EncryptRecordRc4); 
EXPORT_SYMBOL(n1_ssl_config_device);
EXPORT_SYMBOL(n1_ssl_unconfig_device);
