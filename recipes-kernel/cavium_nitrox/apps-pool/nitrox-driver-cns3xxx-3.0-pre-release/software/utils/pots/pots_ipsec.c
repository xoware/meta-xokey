/*
 * pots_ipsec.c:
 */
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



#include <string.h>
#include "cavium_common.h"
#include "cavium_endian.h"
#include <cavium_sysdep.h>
#include "cavium_ioctl.h"

#include "pots.h"
#include "pots_proto.h"

#ifdef CAVIUM_MULTICARD_API
extern int gpkpdev_hdlr[];
#endif

Uint32
n1_process_inbound_packet(Uint16 size, Uint16 param, Uint16 dlen,
                         n1_scatter_buffer *inv,n1_scatter_buffer *outv,
                int rlen,Uint64 ctx, 
#ifdef CAVIUM_MULTICARD_API
                int response_order, int req_queue, Uint32 dev_id
#else
                int response_order, int req_queue
#endif
   )
{
   n1_request_buffer n1_buf;
   Uint32 req_id;
   Uint32 cond_code;
   int i;
   memset(&n1_buf, 0, sizeof(n1_buf));

   n1_buf.opcode = OP_IPSEC_PACKET_INBOUND; 
   n1_buf.size = size;
   n1_buf.param = param;
   n1_buf.dlen = dlen;
   n1_buf.rlen = rlen;
   n1_buf.reserved = 0;
   n1_buf.ctx_ptr = ctx;
   
   n1_buf.incnt = inv->bufcnt;
   n1_buf.outcnt = outv->bufcnt;
   n1_buf.group = CAVIUM_IPSEC_GRP;
   
   for (i = 0; i < inv->bufcnt; i++) {
      n1_buf.inptr[i] = CAST_TO_X_PTR((Uint8 *)(inv->bufptr[i]));
      n1_buf.insize[i] = inv->bufsize[i];
      n1_buf.inoffset[i] = n1_buf.insize[i];
      n1_buf.inunit[i] = UNIT_8_BIT;
   }

   for (i = 0; i < outv->bufcnt; i++) {
      n1_buf.outptr[i] =CAST_TO_X_PTR((Uint8 *)(outv->bufptr[i]));
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
   n1_buf.req_queue = req_queue;

   cond_code = 
#ifdef CAVIUM_MULTICARD_API
      ioctl(gpkpdev_hdlr[dev_id], IOCTL_N1_OPERATION_CODE, &n1_buf, &req_id);
#else
      ioctl(CSP1_driver_handle, IOCTL_N1_OPERATION_CODE, &n1_buf, &req_id);
#endif
   return cond_code;
   if ( cond_code == 0)
      return cond_code ;
   else
      return -1 ;
}

Uint32
n1_process_outbound_packet(Uint16 size, Uint16 param, Uint16 dlen,
                         n1_scatter_buffer * inv,n1_scatter_buffer *outv, int rlen,Uint64 ctx,
#ifdef CAVIUM_MULTICARD_API
                         int response_order, int req_queue, Uint32 dev_id
#else
                         int response_order, int req_queue
#endif
   )

{
   n1_request_buffer n1_buf;
   Uint32 req_id;
   Uint32 cond_code;
   int i;

   memset(&n1_buf, 0, sizeof(n1_buf));

   n1_buf.opcode = OP_IPSEC_PACKET_OUTBOUND; 
   n1_buf.size = size;
   n1_buf.param = param;
   n1_buf.dlen = dlen;
   n1_buf.rlen = rlen;
   n1_buf.reserved = 0;
   n1_buf.ctx_ptr = ctx;
   
   n1_buf.incnt = inv->bufcnt;
   n1_buf.outcnt = outv->bufcnt;
   n1_buf.group = CAVIUM_IPSEC_GRP;
   
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
   n1_buf.req_queue = req_queue;

   cond_code =
#ifdef CAVIUM_MULTICARD_API
      ioctl(gpkpdev_hdlr[dev_id], IOCTL_N1_OPERATION_CODE, &n1_buf, &req_id);
#else
      ioctl(CSP1_driver_handle, IOCTL_N1_OPERATION_CODE, &n1_buf, &req_id);
#endif

   return cond_code;
   if ( cond_code == 0)
      return cond_code ;
   else
      return -1 ;

}
#if 0
void print_hex(char *label, Uint8 *datap, int len)
{
int i;

   if ( label != NULL )
      fprintf(stdout, "%s\n", label);
      for (i = 0; i < len; i++) {
         fprintf(stdout, "0x%0x ", datap[i]);
      }
      fprintf(stdout, "\n");
}
#endif

#ifndef MC2
Uint32
n1_write_ipsec_sa(IpsecProto proto, Version version, IpsecMode mode,Direction dir, EncType cypher, Uint8 *e_key, AuthType auth,
          Uint8 *a_key, Uint8 template[40], Uint32 spi, Uint8 copy_df,
          Uint8 udp_encap, Uint64 ctx, Uint32 *in_buffer, 
          Uint32 *out_buffer,
#ifdef CAVIUM_MULTICARD_API
                         int res_order, int req_queue, Uint32 dev_id
#else
                         int res_order, int req_queue
#endif
   )
          
#else
Uint32
n1_write_ipsec_sa(IpsecProto proto, Version version, IpsecMode mode,Direction dir, EncType cypher, Uint8 *e_key, AuthType auth,
          Uint8 *a_key, Uint8 template[40], Uint32 spi, Uint8 copy_df,
          Uint8 udp_encap, Uint64 ctx, Uint64 next_ctx, Uint32 *in_buffer, 
          Uint32 *out_buffer,
#ifdef CAVIUM_MULTICARD_API
          int res_order, int req_queue, Uint32 dev_id
#else
          int res_order, int req_queue
#endif
   )
          
#endif
{
   Uint8 *p;
   Uint16 *control;
   n1_request_buffer n1_buf;
   Uint32 req_id;
   Uint32 cond_code;
   Uint32 len;
#ifdef CNS3000
   Uint8 iv[] = {0x79, 0x75, 0x78, 0xf2, 0xcb, 0x45, 0x22, 0x22, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8};
	Uint32 ivsize;
#endif
   memset(in_buffer, 0, 512);

   p = (Uint8*)in_buffer;

   control = (Uint16*)p;
   *control = 0;
#ifndef MC2 
   *control = (((dir&0x1) << IPSEC_DIRECTION_SHIFT) | 
      ((version & 0x1) << IPSEC_VERSION_SHIFT) |
      ((mode & 0x1) << IPSEC_MODE_SHIFT) |
      ((proto & 0x1) << IPSEC_PROT_SHIFT) |
      ((auth & 0x0f) << IPSEC_AUTH_SHIFT) |
      ((cypher & 0x0f) << IPSEC_CIPHER_SHIFT) |
      ((copy_df & 0x01) << IPSEC_DF_SHIFT) |
      ((udp_encap & 0x01) << IPSEC_UDP_SHIFT)); 
#else
   *control = (((dir& 0x1) << IPSEC_DIRECTION_SHIFT) |
      ((VALID_SA & 0x1) << IPSEC_VALID_SHIFT) | 
      ((version & 0x1) << IPSEC_VERSION_SHIFT) |
      ((version & 0x1) << (IPSEC_VERSION_SHIFT+1)) |
      ((mode & 0x1) << IPSEC_MODE_SHIFT) |
      ((proto & 0x1) << IPSEC_PROT_SHIFT) |
             ((0x0) << IPSEC_ENCAP_SHIFT) |  
      ((cypher & 0x7) << IPSEC_CIPHER_SHIFT) |
      ((auth & 0x3) << IPSEC_AUTH_SHIFT) |
            ((dir==INBOUND) ? (0x0 << IPSEC_SELECTOR_SHIFT) : ((copy_df & 0x1) << IPSEC_DF_SHIFT)) |
           ((0x0) << IPSEC_FT_SHIFT) |                         
           ((next_ctx ? 1 : 0) << IPSEC_NEXT_SA_SHIFT));
#endif
   *control = htobe16(*control);

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

#ifndef MC2
   if (mode == 1 )
      memcpy(p,template,40);

   memset(&n1_buf, 0, sizeof(n1_buf));

   n1_buf.opcode = OP_WRITE_IPSEC_SA; 
   n1_buf.size = 0;
   n1_buf.param = 0;
   n1_buf.dlen = 13;
   n1_buf.rlen = 1;
   //n1_buf.rlen = 0;
   n1_buf.reserved = 0;
   n1_buf.ctx_ptr = ctx;
#else
        len = (Uint8*)p - (Uint8*)in_buffer;

   p += 8;
   len+=8;

   if (dir == OUTBOUND) {
        if (mode==TUNNEL) {
               if (!version) {
               memcpy(p, template, 20);
              p+=20;
               len+=20;
               }
               else {
                  /* IPv6 */
               memcpy(p, template, 40);
              p+=40;
               len+=40;
               }
         }
    }
   memset(p, 0, 256-len);

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
   memset(&n1_buf, 0, sizeof(n1_buf));

   n1_buf.opcode = ((dir == INBOUND) ? OP_WRITE_INBOUND_IPSEC_SA : OP_WRITE_OUTBOUND_IPSEC_SA); 
   n1_buf.size = 0;
   n1_buf.param = 0;
   n1_buf.dlen = len;
   n1_buf.rlen = 0;
   n1_buf.reserved = 0;
   n1_buf.ctx_ptr = ctx;
#endif

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
#ifndef MC2
   n1_buf.insize[0] = n1_buf.dlen*8;
#else
   n1_buf.insize[0] = len;
#endif
   n1_buf.inoffset[0] = n1_buf.insize[0];
   n1_buf.inunit[0] = UNIT_8_BIT;
   n1_buf.group = CAVIUM_IPSEC_GRP;

   if(n1_buf.outcnt)
   {
      n1_buf.outptr[0] = CAST_TO_X_PTR((Uint8 *)out_buffer);
      n1_buf.outsize[0] = 0; 
      n1_buf.outoffset[0] = n1_buf.outsize[0];
      n1_buf.outunit[0] = UNIT_8_BIT;
   }

   n1_buf.res_order = res_order;
   n1_buf.req_queue = req_queue;

   cond_code = 
#ifdef CAVIUM_MULTICARD_API
      ioctl(gpkpdev_hdlr[dev_id], IOCTL_N1_OPERATION_CODE, &n1_buf, &req_id);
#else
      ioctl(CSP1_driver_handle, IOCTL_N1_OPERATION_CODE, &n1_buf, &req_id);
#endif
   return cond_code;
   if (cond_code == 0 )
      return cond_code ;
   else
      return -1 ;
}
