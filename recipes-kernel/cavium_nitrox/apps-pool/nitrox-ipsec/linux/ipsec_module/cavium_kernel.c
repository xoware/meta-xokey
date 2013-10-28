/*
Copyright (c) 2003-2005, Cavium Networks. All rights reserved.

This Software is the property of Cavium Networks. The Software and all 
accompanying documentation are copyrighted. The Software made available here 
constitutes the proprietary information of Cavium Networks. You agree to 
take reasonable steps to prevent the disclosure, unauthorized use or 
unauthorized distribution of the Software. You shall use this Software
solely with Cavium hardware.

Except as expressly permitted in a separate Software License Agreement
between You and Cavium Networks, you shall not modify, decompile,
disassemble, extract, or otherwise reverse engineer this Software. You shall
not make any copy of the Software or its accompanying documentation, except
for copying incident to the ordinary and intended use of the Software and
the Underlying Program and except for the making of a single archival copy.

This Software, including technical data, may be subject to U.S. export
control laws, including the U.S. Export Administration Act and its
associated regulations, and may be subject to export or import regulations
in other countries. You warrant that You will comply strictly in all
respects with all such regulations and acknowledge that you have the
responsibility to obtain licenses to export, re-export or import the
Software.

TO THE MAXIMUM EXTENT PERMITTED BY LAW, THE SOFTWARE IS PROVIDED "AS IS" AND
WITH ALL FAULTS AND CAVIUM MAKES NO PROMISES, REPRESENTATIONS OR WARRANTIES,
EITHER EXPRESS, IMPLIED, STATUTORY, OR OTHERWISE, WITH RESPECT TO THE
SOFTWARE, INCLUDING ITS CONDITION, ITS CONFORMITY TO ANY REPRESENTATION OR
DESCRIPTION, OR THE EXISTENCE OF ANY LATENT OR PATENT DEFECTS, AND CAVIUM
SPECIFICALLY DISCLAIMS ALL IMPLIED (IF ANY) WARRANTIES OF TITLE,
MERCHANTABILITY, NONINFRINGEMENT, FITNESS FOR A PARTICULAR PURPOSE, LACK OF
VIRUSES, ACCURACY OR COMPLETENESS, QUIET ENJOYMENT, QUIET POSSESSION OR
CORRESPONDENCE TO DESCRIPTION. THE ENTIRE RISK ARISING OUT OF USE OR
PERFORMANCE OF THE SOFTWARE LIES WITH YOU.
*/
#include <linux/module.h>
#include <linux/kernel.h> 
#include <linux/slab.h>
#include <linux/skbuff.h>
#include <asm/io.h>
#include <net/xfrm.h>

#include "cavium_common.h"
#include "cavium_kernel.h"


typedef struct N1_Dev {
    struct N1_dev *next;
    int id;
    int bus;
    int dev;
    int func;
    void *data;
}n1_dev;

#define Csp1ConfigDeviceName "N1ConfigDevice"
#define Csp1UnconfigDeviceName "N1UnconfigDevice"
#define Csp1AllocContextName "N1AllocContext"
#define Csp1FreeContextName "N1FreeContext"
#define Csp1ProcessOutboundPacketName "N1ProcessOutboundPacket"
#define Csp1ProcessInboundPacketName "N1ProcessInboundPacket"
#define Csp1WriteIpSecSaName "N1WriteIpSecSa"

static n1_dev *n1_list = NULL;
static int module_count = 0;
Uint64 n1_alloc_context(void *);
void n1_free_context(void *, Uint64 context);
int n1_process_inbound_packet(void *, Uint16 size, Uint16 param, Uint16 dlen,
			        n1_scatter_buffer* inv,
			    n1_scatter_buffer* outv, int rlen, Uint64 ctx, Request_cb cb, void *cb_arg, Uint32 res_order, Uint32 req_id);
int n1_process_outbound_packet(void *, Uint16 size, Uint16 param, Uint16 dlen,
	       		 	 n1_scatter_buffer * inv, n1_scatter_buffer* outv, int rlen,
				 Uint64 ctx, Request_cb cb, void *cb_arg, 
				 Uint32 res_order, Uint32 req_id);

static Uint64 (*p_Csp1AllocContext)(void *) = NULL;
static void (*p_Csp1FreeContext)(void *, Uint64 context) = NULL;
static int (*p_process_inbound)(void *, Uint16 size, Uint16 param, Uint16 dlen,
			        n1_scatter_buffer* inv,
			    n1_scatter_buffer* outv, int rlen, Uint64 ctx, Request_cb cb, void *cb_arg, Uint32 res_order, Uint32 req_id) = NULL;
static int (*p_process_outbound)(void *, Uint16 size, Uint16 param, Uint16 dlen,
	       		 	 n1_scatter_buffer * inv, n1_scatter_buffer* outv, int rlen,
				 Uint64 ctx, Request_cb cb, void *cb_arg, 
				 Uint32 res_order, Uint32 req_id) = NULL;
#ifdef MC2
int n1_write_ipsec_sa(void *, IpsecProto , Version, Version, IpsecMode,
	       		       Direction, EncType, Uint8*, AuthType , 
			       Uint8* a_key, Uint8 template[40], Uint32 spi, 
			       Uint8 copy_df, Uint8 udp_encap, Uint64 ctx, 
						 Uint64 next_ctx, Uint32* in_buffer,
						 Uint32* out_buffer,Request_cb cb,
						 void *cb_data, Uint32, Uint32);
static int (*p_Write_Ipsec_Sa)(void *, IpsecProto , Version, Version, IpsecMode,
	       		       Direction, EncType, Uint8*, AuthType , 
			       Uint8* a_key, Uint8 template[40], Uint32 spi, 
			       Uint8 copy_df, Uint8 udp_encap, Uint64 ctx, 
						 Uint64 next_ctx, Uint32* in_buffer,
						 Uint32* out_buffer,Request_cb cb,
						 void *cb_data, Uint32, Uint32) = NULL;
void n1_flush_packet_queue(void *);
static void (*n1_Flush_Packet_Queue)(void *)=NULL;
#else
int n1_write_ipsec_sa(void *, IpsecProto , Version, IpsecMode,
	       		       Direction, EncType, Uint8*, AuthType , 
			       Uint8* a_key, Uint8 template[40], Uint32 spi, 
			       Uint8 copy_df, Uint8 udp_encap, Uint64 ctx, 
			       Uint32* in_buffer, Uint32* out_buffer, 
			       Request_cb cb, void *cb_data, Uint32, Uint32);
static int (*p_Write_Ipsec_Sa)(void *, IpsecProto , Version, IpsecMode,
	       		       Direction, EncType, Uint8*, AuthType , 
			       Uint8* a_key, Uint8 template[40], Uint32 spi, 
			       Uint8 copy_df, Uint8 udp_encap, Uint64 ctx, 
			       Uint32* in_buffer, Uint32* out_buffer, 
			       Request_cb cb, void *cb_data, Uint32, Uint32) = NULL;
#endif
int 
n1_invalidate_ipsec_sa(void *device, Uint64 ctx, Uint32 *in_buffer, Uint32 *out_buffer, Request_cb cb, void *cb_data, int res_order,int req_queue);	       
static int 
(*p_Invalidate_Ipsec_Sa)(void *device, Uint64 ctx, Uint32 *in_buffer, Uint32 *out_buffer, Request_cb cb, void *cb_data, int res_order,int req_queue);	       

int cavium_print_buf(Uint8 *header, Uint8 *buffer, uint len);

int 
Csp1ConfigDevice(void *device)
{
    void * n1_config_device(Uint32);
    void * (*func)(Uint32);
    func = symbol_get(n1_config_device);
    if (!func) {
        printk(KERN_CRIT "Csp1ConfigDevice: symbol_get failed\n");
        return -1;
    }
	
#ifdef MC2
    n1_list = (n1_dev *)(*func)((Uint32)2);
#else
    n1_list = (n1_dev *)(*func)((Uint32)1);
#endif
//printk(KERN_CRIT "\n n1_list ptr %p\n",n1_list);
    if (n1_list == NULL) {
        printk(KERN_CRIT "No Cavium devices detected in the system\n");
   	symbol_put(n1_config_device);
        return -1;
    }
    module_count++;
    if (module_count == 1) {
	if (p_Csp1AllocContext == NULL) {
		p_Csp1AllocContext = symbol_get(n1_alloc_context);
	}
	if (p_Csp1FreeContext == NULL) {
		p_Csp1FreeContext = symbol_get(n1_free_context);
	}
	if (p_process_outbound == NULL) {
		p_process_outbound = symbol_get(n1_process_outbound_packet);
	}
	if (p_process_inbound == NULL) {
		p_process_inbound = symbol_get(n1_process_inbound_packet);
	}
	if (p_Write_Ipsec_Sa == NULL) {
		p_Write_Ipsec_Sa = symbol_get(n1_write_ipsec_sa);
	}
	if (p_Invalidate_Ipsec_Sa == NULL) {
		p_Invalidate_Ipsec_Sa = symbol_get(n1_invalidate_ipsec_sa);
	}
#ifdef MC2
	if(n1_Flush_Packet_Queue == NULL){
		n1_Flush_Packet_Queue = symbol_get(n1_flush_packet_queue);
	}
#endif
   }
   symbol_put(n1_config_device);

    return 0;
}
#ifdef MC2
void n1_flush_queue(void)
{
	if(n1_list == NULL)
		return;
	(*n1_Flush_Packet_Queue)(n1_list->data);
}
#endif

void
Csp1UnconfigDevice(void)
{
    void n1_unconfig_device(void);
    void (*func)(void);
#ifdef PKP_DEBUG
    printk(KERN_CRIT "Csp1UnConfigDevice Called\n");
#endif

	func = symbol_get(n1_unconfig_device);
    if (!func) {
        printk(KERN_CRIT "Csp1UnConfigDevice: symbol_get failed\n");
				return;
    }
   
    (*func)();

    symbol_put(n1_unconfig_device);

    module_count--;

    if (module_count == 0) {
    	n1_list = NULL;
	if (p_Csp1AllocContext) {
		symbol_put(n1_alloc_context);
		p_Csp1AllocContext = NULL;
	}
	if (p_Csp1FreeContext) {
		symbol_put(n1_free_context);
		p_Csp1FreeContext = NULL;
	}
	if (p_process_outbound) {
		symbol_put(n1_process_outbound_packet);
		p_process_outbound = NULL;
	}
	if (p_process_inbound) {
		symbol_put(n1_process_inbound_packet);
		p_process_inbound = NULL;
	}
	if (p_Write_Ipsec_Sa) {
		symbol_put(n1_write_ipsec_sa);
		p_Write_Ipsec_Sa = NULL;
	}
	if (p_Invalidate_Ipsec_Sa) {
		symbol_put(n1_invalidate_ipsec_sa);
		p_Invalidate_Ipsec_Sa = NULL;
	}
#ifdef MC2
	if(n1_Flush_Packet_Queue){
		symbol_put(n1_flush_packet_queue);
		n1_Flush_Packet_Queue = NULL;
	}
#endif
   }
    return;
}


Uint64 
Csp1AllocContext()
{
//printk(KERN_CRIT "n1_list ptr %p \n",n1_list);
#ifdef PKP_DEBUG
        printk(KERN_CRIT "kernel_shim: Csp1AllocContext: called \n");
#endif /* PKP_DEBUG */
	if (!p_Csp1AllocContext)
	{
    		if (n1_list == NULL)
		 {
       	 		printk(KERN_CRIT " Cavium device is not initialized1\n");
			return (Uint64)0;
		}
		p_Csp1AllocContext = symbol_get(n1_alloc_context);
		if (!p_Csp1AllocContext) {
        		printk(KERN_CRIT "kernel_shim: Csp1AllocContext: symbol_get(Csp1AllocContext) failed\n");
			return (Uint64)0;	
		}
	}

	return (*p_Csp1AllocContext)(n1_list->data);

}

void 
Csp1FreeContext(Uint64 ctx)
{
#ifdef PKP_DEBUG
        printk(KERN_CRIT "kernel_shim: Csp1FreeContext: called \n");
#endif /* PKP_DEBUG */
	if (!p_Csp1FreeContext)
	{
    		if (n1_list == NULL)
		 {
       	 		printk(KERN_CRIT " Cavium device is not initialized2\n");
			return;
		}
		p_Csp1FreeContext = symbol_get(n1_free_context);
		if (!p_Csp1FreeContext) {
        		printk(KERN_CRIT "kernel_shim: Csp1FreeContext: symbol_get(Csp1FreeContext) failed\n");
			return;	
		}
	}

	(*p_Csp1FreeContext)(n1_list->data, ctx);
	return;
}
//EXPORT_SYMBOL(Csp1FreeContext);

Uint32 
Csp1ProcessInboundPacket(
	void* pkt_before,
	void* pkt_after,
	Uint64 ctx,
	int rlen,
	Request_cb cb,
	void *data)
{
    int req_id;
    unsigned long offset;
    n1_scatter_buffer inv, outv;
    	if (n1_list == NULL)
     	{
    		printk(KERN_CRIT " Cavium device is not initialized3\n");
		return -1;
	}

	offset=(unsigned long)(((struct sk_buff*)pkt_before)->data ) & 0x7L;

    if (!p_process_inbound) {
        p_process_inbound = symbol_get(n1_process_inbound_packet);
        if (!p_process_inbound) {
            printk(KERN_CRIT "Csp1ProcessInboundPacket: symbol_get failed\n");
	    return -1;
        }
    }

    	inv.bufcnt = 1; 
	outv.bufcnt = 1;
#ifdef MC2
	inv.bufsize[0] = ((struct sk_buff *)pkt_before)->len;
	inv.bufptr[0] = (Uint32 *)(((struct sk_buff*)pkt_before)->data); 
	outv.bufsize[0] = rlen;
	outv.bufptr[0] = (Uint32 *)(((struct sk_buff*)pkt_after)->data); 
req_id = (*p_process_inbound)(n1_list->data, 0, 0,
                   ((struct sk_buff*)pkt_before)->len,
		   &inv, &outv,
            rlen, /* comp offset */
            ctx, /* Context handle */
            (void *)cb,  /* Callback */    
            data,    /* Callback arg */
            0,      /* Ordered Response */
            0       /* Request Queue */);
#else
	inv.bufsize[0] = (ROUNDUP8(((struct sk_buff*)pkt_before)->len + offset)>>3) << 3;
	inv.bufptr[0] = (Uint32 *)((unsigned long)(((struct sk_buff*)pkt_before)->data) & ~(0x7)); 
	outv.bufsize[0] = rlen;
	outv.bufptr[0] = (Uint32 *)(((struct sk_buff*)pkt_after)->data); 
    req_id = (*p_process_inbound)(n1_list->data, ((struct sk_buff*)pkt_before)->len, /* size*/
            (unsigned long)(((struct sk_buff*)pkt_before)->data ) & 0x7L, /* param */
            ROUNDUP8(((struct sk_buff*)pkt_before)->len + offset)>>3, /* dlen */
	    &inv, &outv,
            rlen, /* comp offset */
            ctx, /* Context handle */
            (void *)cb,  /* Callback */    
            data,    /* Callback arg */
            0,      /* Ordered Response */
            0       /* Request Queue */);
#endif

#ifdef PKP_DEBUG
    printk(KERN_CRIT "ProcessInbound packet returning\n");
#endif

    if (req_id < 0) {
#ifdef PKP_DEBUG
        printk(KERN_CRIT "ProcessInbound packet failed\n");
#endif
        return -1;
    }

    return 0;
}


#define SKB_PUSHER(pkt_,len_,data_)		\
       if((pkt_->data-len_) < pkt_->head)	\
                return -1; 			\
        pkt_->data-=len_; 			\
        pkt_->len+=len_; 			\
        memcpy(pkt_->data,data_,len_);

Uint32 Csp1ProcessOutboundPacket(
	void* pkt_before,
	void* pkt_after,
	Uint64 ctx,
	int rlen,
	Uint32 seq,
	Request_cb cb,
	void *data)
{
    unsigned long offset;	
    int req_id;
    n1_scatter_buffer inv, outv;
    	if (n1_list == NULL)
     	{
    		printk(KERN_CRIT " Cavium device is not initialized4\n");
		return -1;
	}

#ifdef PKP_DEBUG
    printk (KERN_CRIT "Csp1ProcessOutboundPacket: len = %d rlen=%d\n", ((struct sk_buff *)pkt_before)->len, rlen);
#endif

    if (!p_process_outbound) {
        p_process_outbound = symbol_get(n1_process_outbound_packet);
        if (!p_process_outbound) {
            printk(KERN_CRIT "Csp1ProcessOutboundPacket: symbol_get failed\n");
	    return -1;
        }
    }
	seq = htonl(seq);

	SKB_PUSHER(((struct sk_buff*)pkt_before),4,&seq);
	SKB_PUSHER(((struct sk_buff*)pkt_before),4,&seq);

	offset=(unsigned long)(((struct sk_buff*)pkt_before)->data) & 0x7UL;
#if 0
	{
	cavium_print_buf("IN BUFFER COPY DUMP", ((struct sk_buff *)pkt_before)->data, ((struct sk_buff *)pkt_before)->len);
	}
#endif
    	inv.bufcnt = 1; 
	outv.bufcnt = 1;
#ifdef MC2
	inv.bufsize[0] = ((struct sk_buff *)pkt_before)->len;
	inv.bufptr[0] = (Uint32 *)(((struct sk_buff*)pkt_before)->data); 
	outv.bufsize[0] = rlen;
	outv.bufptr[0] = (Uint32 *)(((struct sk_buff*)pkt_after)->data); 
    req_id = (*p_process_outbound)(n1_list->data, 0, /* size */
                    0, /*param */
                    ((struct sk_buff*)pkt_before)->len, /* dlen */
		    &inv, &outv,
                    rlen, /*comp offset*/
                    ctx, /* Context */
                    (void *)cb,  /* Callback */    
                    data,    /* Callback arg */
                    0,      /* Ordered Response */
                    0       /* Request Queue */);
#else
	inv.bufsize[0] =(1+(ROUNDUP8(((struct sk_buff*)pkt_before)->len -8 + offset)>>3)) << 3;
	inv.bufptr[0] = (Uint32 *)((unsigned long)(((struct sk_buff*)pkt_before)->data) & ~(0x7)); 
	outv.bufsize[0] = rlen;
	outv.bufptr[0] = (Uint32 *)(((struct sk_buff*)pkt_after)->data); 
    req_id = (*p_process_outbound)(n1_list->data, 0, /* size */
                    offset, /*param */
                    1+(ROUNDUP8(((struct sk_buff*)pkt_before)->len - 8 + offset)>>3), /* dlen */
		    &inv, &outv,
                    rlen, /*comp offset*/
                    ctx, /* Context */
                    (void *)cb,  /* Callback */    
                    data,    /* Callback arg */
                    0,      /* Ordered Response */
                    0       /* Request Queue */);
#endif

    if (req_id < 0) {
#ifdef PKP_DEBUG
        printk(KERN_CRIT "ProcessOutbound packet failed\n");
#endif
        return -1;
    }

    return 0;
}

#ifdef MC2
Uint32 
Csp1WriteIpsecSa( IpsecProto proto,
	Version version,
	IpsecMode mode,
	Direction dir,
	EncType cypher,
	Uint8* e_key,
	AuthType auth,
	Uint8* a_key,
	Uint8 template[40],
	Uint32 spi,
	Uint8 copy_df,
	Uint8 udp_encap,
	Uint64 ctx,
	Uint64 next_ctx,
	Uint32* in_buffer,
	Uint32* out_buffer,
	Request_cb cb,
	void *cb_data)
#else
Uint32 
Csp1WriteIpsecSa( IpsecProto proto,
	Version version,
	IpsecMode mode,
	Direction dir,
	EncType cypher,
	Uint8* e_key,
	AuthType auth,
	Uint8* a_key,
	Uint8 template[40],
	Uint32 spi,
	Uint8 copy_df,
	Uint8 udp_encap,
	Uint64 ctx,
	Uint32* in_buffer,
	Uint32* out_buffer,
	Request_cb cb,
	void *cb_data)
#endif
{
	int req_id;
        if (!p_Write_Ipsec_Sa) {
    		if (n1_list == NULL)
     		{
    			printk(KERN_CRIT " Cavium device is not initialized5\n");
			return -1;
		}
            p_Write_Ipsec_Sa = symbol_get(n1_write_ipsec_sa);
            if (!p_Write_Ipsec_Sa) {
                printk(KERN_CRIT "Csp1WriteIpSecSa: symbol_get failed\n");
                return -1;
            }
       }
#ifdef MC2 
      req_id = (*p_Write_Ipsec_Sa)(n1_list->data, proto, version, version, mode, dir, cypher, e_key, auth, a_key, template, spi, copy_df, udp_encap, ctx, next_ctx,in_buffer, out_buffer, cb, cb_data, 0, 0);
#else
        req_id = (*p_Write_Ipsec_Sa)(n1_list->data, proto, version, mode, dir, cypher, e_key, auth, a_key, template, spi, copy_df, udp_encap, ctx, in_buffer, out_buffer, cb, cb_data, 0, 0);
#endif
	if (req_id < 0)
	       return -1;	
        return 0;
}

Uint32 Csp1InvalidateIpsecSa(
				Uint64 ctx, 
				Uint32 *in_buffer, 
				Uint32 *out_buffer, 
				Request_cb cb,
				void *cb_data)
{
	int req_id;
        if (!p_Invalidate_Ipsec_Sa) {
    		if (n1_list == NULL)
     		{
    			printk(KERN_CRIT " Cavium device is not initialized6\n");
			return -1;
		}
            p_Invalidate_Ipsec_Sa = symbol_get(n1_invalidate_ipsec_sa);
            if (!p_Invalidate_Ipsec_Sa) {
                printk(KERN_CRIT "Csp1nvalidateIpSecSa: symbol_get failed\n");
                return -1;
            }
       }
      req_id = (*p_Invalidate_Ipsec_Sa)(n1_list->data, ctx, in_buffer,out_buffer, cb, cb_data, 0, 0);
	if (req_id < 0)
	       return -1;	
        return 0;
}	       

#define			MAXPRINT			2048
#define			MAXBUF				8192

int cavium_print_buf(Uint8 *header, Uint8 *buffer, uint len)
{
	int offset = 0, i, j = 0;
	Uint8 *DebugBuf = NULL;
	uint maxlen;

	DebugBuf = (Uint8 *)kmalloc(MAXBUF, GFP_ATOMIC);
	if(!DebugBuf)
	{
		printk("Not  Enough memory to allocate DebugBuf\n");
		return -1;
	}

	j = sprintf(DebugBuf + offset, "%s\n", header);
	offset += j;

	maxlen = min(len, (uint)MAXPRINT);
	for(i = 0; i < maxlen; i++)
	{
		j = sprintf(DebugBuf+offset, "%02x ", buffer[i]);
		offset += j;
		if(i && ((i%8) == 7))
		{
			j = sprintf(DebugBuf + offset, "\n");
			printk(KERN_CRIT "%s", DebugBuf);
			offset = 0;
		}
	}
		printk(KERN_CRIT "\n");
		kfree(DebugBuf);
		return 0;
}
