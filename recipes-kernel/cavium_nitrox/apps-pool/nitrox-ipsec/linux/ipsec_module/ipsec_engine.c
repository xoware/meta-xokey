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
//#include <linux/config.h>
#include <linux/version.h>
#include <linux/module.h>
#include <linux/kernel.h> /* printk() */
#include <linux/slab.h>
#include <linux/skbuff.h>
#include <net/sock.h>
#include <net/ip.h>
#include <net/protocol.h>
#include <linux/ip.h>
#include <net/raw.h>
#include <net/icmp.h>
#include <net/xfrm.h>
#include <asm/system.h>
#include <asm/checksum.h>
#include <net/checksum.h>
#include <linux/ipv6.h>
#include <net/ipv6.h>
#include <net/addrconf.h>


#include <net/ah.h>
#include "cavium_common.h"
#include "cavium_kernel.h"
#include "cavium_ipsec.h"
#include "ipsec_engine.h"


/*typedef void (*Request_cb)(int status, int type, void* data);*/

extern int cavium_print_buf(Uint8 *, Uint8 *, Uint32);	
extern struct xfrm_state * cavium_find_bundle (u8 mode,/*u8 proto*/
		xfrm_address_t *daddr, xfrm_address_t *saddr,Uint8 dir,
		struct xfrm_state *x1);
static void cavium_update_seq(struct sk_buff *, struct xfrm_state *);
static int check_cavium_support (struct xfrm_state *x);

static struct xfrm_state *global_xfrm;
int cav_x_ok(struct xfrm_state *entry, int count, void *data)
{
	struct cavium_xfrm *cav_x = data;
	struct xfrm_state *x;

	if (!cav_x)
		return 0;
	x = cav_x->xfrm;
	if (entry == x) {
		global_xfrm = entry;
		return 1;
	}
	return 0;
}

int check_valid_x(struct cavium_xfrm *cav_x) 
{
	struct xfrm_state_walk walk;
	int ret;
	
#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,6,31))
	walk.state = NULL;
	walk.count = 0;
	walk.proto = cav_x->xfrm->id.proto;
#else
	xfrm_state_walk_init(&walk, cav_x->xfrm->id.proto);
#endif
	global_xfrm = NULL;
#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,6,31))
	ret = xfrm_state_walk(&walk, &cav_x_ok, cav_x);
	if (walk.state)
		__xfrm_state_put(walk.state);
#else
	ret = xfrm_state_walk(&init_net, &walk, &cav_x_ok, cav_x);
	xfrm_state_walk_done(&walk);
#endif
	if(global_xfrm)
		return 0;
	else
		return 1;
}

void cavium_cb(int status, void *data)
{
	Csp1EngineRequest *csp1_request;
	struct iphdr *ipp;
	struct sk_buff *skb_to;
	Csp1InboundPostData *inbound_post_data;
	struct xfrm_state *x;
	Csp1OutboundPostData *outbound_post_data;
 	int skb_from_len=0, ipp_tot_len=0;
	struct cavium_xfrm *cav_x = NULL;
#ifdef MC2
	struct ipv6hdr *ip6hdr;
#endif

	csp1_request = (Csp1EngineRequest *)data;
	
	if(!csp1_request)
	{
		printk( KERN_CRIT "cavium_cb : Callbck data is NULL. returing\n");
		return;
	}

#ifdef PKP_DEBUG
	printk(KERN_CRIT "CAVIUM: cavium_cb: status = %d, type %d, data 0x%x\n", status, csp1_request->req_type, (uint)data);
#endif /* PKP_DEBUG */
	switch(csp1_request->req_type)
	{
		case DELETE_SA:
			if (status)
				printk("\n Delete SA failed"); 
			if(csp1_request->in_buffer)
				kfree(csp1_request->in_buffer);
			if(csp1_request->out_buffer)
			{
				Uint64 ctx=*((Uint64 *)(&(csp1_request->out_buffer[16])));
				if(ctx)
					Csp1FreeContext(ctx);
				kfree(csp1_request->out_buffer);
			}
			kfree(csp1_request);
			break;
				
		case WRITE_SA:
			if(csp1_request->in_buffer)
				kfree(csp1_request->in_buffer);

			if(csp1_request->out_buffer)
				kfree(csp1_request->out_buffer);
			if (status == 0) {
				if (csp1_request->data) {
#if 1
					cav_x = (struct cavium_xfrm *)csp1_request->data;
					if (!check_valid_x(cav_x)) {
						x = cav_x->xfrm;
						spin_lock_bh(&x->lock);
						x->km.state = XFRM_STATE_VALID;
						spin_unlock_bh(&x->lock);
					} else
						printk(KERN_CRIT "cavium_cb: valid x not found \n");
#else
					(struct xfrm_state *)(csp1_request->data)->km.state = XFRM_STATE_VALID;	
#endif
				}
			} else {
				if (csp1_request->data) {
#if 1
					cav_x = (struct cavium_xfrm *)csp1_request->data;
					if (!check_valid_x(cav_x)) {
						xfrm_state_delete(cav_x->xfrm);
					} else {
						printk(KERN_CRIT "cavium_cb: valid x not found \n");
					}
#else
					xfrm_state_delete((struct xfrm_state *)csp1_request->data);
#endif
				}
			}
				
			kfree(cav_x);
			kfree(csp1_request);
			csp1_request = 0;
			break;

		case INBOUND_PROCESSING:
		{
			void (*post_rcv_cb)(int, void *, void *);
			inbound_post_data = (Csp1InboundPostData *)csp1_request->data;
			skb_to = (struct sk_buff *)inbound_post_data->skb_to;

			skb_from_len = ((struct sk_buff*)inbound_post_data->skb_from)->len;
			post_rcv_cb = inbound_post_data->post_rcv_cb;
			x = inbound_post_data->x;
			if (!status)
				cavium_update_seq(inbound_post_data->skb_from, x);
			dev_kfree_skb_irq((struct sk_buff*)inbound_post_data->skb_from);
			kfree(inbound_post_data);
			kfree(csp1_request);
			if (status) {
				goto rcv_error;
			}
#ifdef MC2
			ipp = (struct iphdr *)(skb_to->data + 8);
			if (ipp->version == 4)
				ipp_tot_len = ntohs(ipp->tot_len);
			else if (ipp->version == 6) {
				ip6hdr = (struct ipv6hdr*)(skb_to->data + 8);
				ipp_tot_len = ntohs(ip6hdr->payload_len) + 40;
			}
			else 
				goto rcv_error;

			if (ipp_tot_len > skb_from_len) 
				goto rcv_error;

			memmove(skb_to->data, skb_to->data + 8, ipp_tot_len);
			skb_to->tail -= 8;
#else
			ipp = (struct iphdr *)skb_to->data;
			ipp_tot_len = ntohs(ipp->tot_len);
			if (ipp->version != 4)
				goto rcv_error;
			if (ipp_tot_len > skb_from_len) 
				goto rcv_error;
#endif
         
#ifdef PKP_DEBUG	
			cavium_print_buf("Inbound RESULT PACKET cavium_cb", skb_to->data, 128);	
#endif
			post_rcv_cb(status, (void *)skb_to, x); 	
			break;
rcv_error:
#ifdef PKP_DEBUG	
			cavium_print_buf("Inbound RESULT PACKET err", skb_to->data, skb_from_len);
#endif
			dev_kfree_skb_irq(skb_to);
		}
		break;
			
		case OUTBOUND_PROCESSING:
		{
			void (*post_xmit_cb)(int, void * /*, void * */);
			outbound_post_data = (Csp1OutboundPostData *)csp1_request->data;
			skb_to = (struct sk_buff *)outbound_post_data->skb_to;
			post_xmit_cb = outbound_post_data->post_xmit_cb;
			dev_kfree_skb_irq((struct sk_buff*)outbound_post_data->skb_from);
			kfree(outbound_post_data);
			kfree(csp1_request);
#ifdef PKP_DEBUG
#ifdef MC2
			ipp = (struct iphdr *)skb_to->data;
			ipp_tot_len = ntohs(ipp->tot_len);
#else
			ipp = (struct iphdr *)skb_to->data;
#endif
			cavium_print_buf("Outbound RESULT PACKET", skb_to->data, ntohs(ipp->tot_len)+24);	
#endif
			post_xmit_cb(status, (void *)skb_to); 
		}
		break;

		default:
			printk(KERN_CRIT "CAVIUM: cavium_cb: unrecognized request type: status = %d.\n",status);
			break;
	}
}/* cavium_cb */

/* pass just the xfrm_state and other info can be fetched from there */

/* 
 *  Changed the function to accept a pointer to the structure 
 *  xfrm_decap_state as the  parameter 
 */

int cavium_process_inbound_packet(struct sk_buff *skb_from,
void *x, struct  xfrm_encap_tmpl * encap,IpsecMode mode,
              EncType enc, /* Added parameter for AES handling *NG*/
							/*AuthType auth,*/ 
						  Uint64 ctx, /* Changed *NG*/
						  void(*post_rcv_cb)(int ,void *, void *))
{
	int rlen=0,rcalc=1;
	struct sk_buff *skb_to=NULL;
	struct iphdr *ipp;
	int iphlen = 0, aes=0,auth1=0;
	struct xfrm_state *xp;
	int xfrm_nr = 0;
	struct sec_path *sp;
        struct cavm_private_info *info;

	Csp1InboundPostData *inbound_post_data;
	Csp1EngineRequest *csp1_request;
	struct xfrm_state  *xfrm_vec[XFRM_MAX_DEPTH];
	xp  = (struct xfrm_state *)x;
        info = xp->data;
	if (!(info->supported) && !(check_cavium_support (xp)) ) 
		return -1;
	inbound_post_data = (Csp1InboundPostData *)kmalloc(sizeof(Csp1InboundPostData), GFP_ATOMIC);
	if(inbound_post_data == NULL)
	{
		printk(KERN_CRIT "CAVIUM: cavium_process_inbound_packet: Unable to allocate Csp1InboundPostData\n");
		return -1;
	}

	csp1_request = (Csp1EngineRequest *)kmalloc(sizeof(Csp1EngineRequest), GFP_ATOMIC);
	if(csp1_request == NULL)
	{
		printk(KERN_CRIT "CAVIUM: cavium_process_inbound_packet: Unable to allocate Csp1EngineRequest\n");
		if(inbound_post_data)
			kfree(inbound_post_data);
		return -1;
	}
	memset(csp1_request, 0, sizeof(Csp1EngineRequest));

	ipp = (struct iphdr *)skb_from->data;
	if(mode) {
		if(xp->props.family == AF_INET6)
			iphlen = 40;
		else 
			iphlen = ipp->ihl << 2;
	}
	switch(enc)
	{
		case AES128CBC:
		case AES192CBC:
		case AES256CBC:
			aes = 1;
			break;
		case DES3CBC:
		case DESCBC:
		case NO_CYPHER:
			break;
	}
	if (skb_is_nonlinear(skb_from) && (skb_linearize(skb_from) != 0)) 
	{
		printk (KERN_CRIT "CAVIUM: cavium_process_inbound_packet: Unable to linearize skb\n");
		if(csp1_request)
			kfree(csp1_request);
		if(inbound_post_data)
			kfree(inbound_post_data);
		return -1;
	}
	if(xp->props.ealgo != SADB_EALG_NONE) 
	{
		auth1  = xp->props.aalgo ? 1:0;
		rlen = RLEN_INBOUND_ESP_PACKET(skb_from->len,iphlen,aes,auth1);
	}
	else if(xp->props.aalgo != SADB_AALG_NONE ) {
	if(rcalc) {
		rlen = RLEN_INBOUND_AH_PACKET(skb_from->len,iphlen,0);
		/* BUNDLING ... Jul 24 */
		#ifdef MC2
			if (info->next_context) {
				if (info->bundle && info->bundle_state) {
					if (info->bundle_state->props.mode) {
						if(xp->props.family == AF_INET6)
							iphlen = 40;
						else
							iphlen = 20;
					}
					auth1 = info->bundle_state->props.aalgo ? 1:0;
				}
				rlen = RLEN_INBOUND_ESP_PACKET(rlen-16,iphlen,aes,auth1);
			}
		#endif
		} /* if(rcalc)*/
	}	
     /* Adjust the rlen in case of UDP encapsulation  */

	if (xp->encap && (xp->encap->encap_type == 2))
		rlen -= 8;

#ifdef PKP_DEBUG 
	printk(KERN_CRIT "CAVIUM: cavium_process_inbound_packet: packet_len = %d\n", skb_from->len);
	printk(KERN_CRIT "CAVIUM: cavium_process_inbound_packet: iphlen = %d\n", iphlen);
	printk(KERN_CRIT "CAVIUM: cavium_process_inbound_packet: iph_tot_len = %d\n", ntohs(ipp->tot_len));
	printk(KERN_CRIT "CAVIUM: cavium_process_inbound_packet: rlen = %d\n", rlen);
	cavium_print_buf("INPUT PACKET cavium_process_inbound_packet", skb_from->data, ntohs(ipp->tot_len));	
#endif /* PKP_DEBUG */
	/* allocate final skb */
	/* allocated skb would be rlen+16 size and will adnave data and tail pointers 16 bytes */

	skb_to = (struct sk_buff*) dev_alloc_skb(rlen+iphlen);
	if(skb_to == NULL)
	{
		printk(KERN_CRIT "CAVIUM: cavium_process_inbound_packet: Unable to allocate skb_to\n");
		if(inbound_post_data)
			kfree(inbound_post_data);
		if(csp1_request)
			kfree(csp1_request);
		return -1;
	}

	/* set skb len */
	/*skb_put(skb_to, rlen-8);*/

	/* now copy L2 header */

	memcpy(skb_to->head, skb_from->head, 16);
	skb_to->priority = skb_from->priority;
	skb_to->protocol = skb_from->protocol;
	skb_to->dev = skb_from->dev;
	skb_to->pkt_type = skb_from->pkt_type;
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,27))
	skb_set_mac_header(skb_to, -14);
	skb_to->local_df = skb_from->local_df;
#else
	skb_to->mac.raw = skb_to->data - 14;
#endif

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,31))
    skb_dst_set(skb_to, dst_clone(skb_dst(skb_from)));
#else
	skb_to->dst = dst_clone(skb_from->dst);
#endif

	/* spin_lock_bh(&xp->lock); */
	xfrm_vec[0] = x;

	/* Copy the decapulation structure to the transfor vector 
	 * if UDP encapsulation is set 
	 */

	if (xp->encap && (xp->encap->encap_type == 2))
		memcpy(xfrm_vec[0]->encap,xp->encap,sizeof(struct xfrm_encap_tmpl)); 
	xfrm_state_hold(x);
	xfrm_nr++;

	/* spin_unlock_bh(&xp->lock); */
#ifdef MC2
	if (info->bundle && info->bundle_state) {
		xfrm_vec[1] = info->bundle_state;
		xfrm_state_hold(info->bundle_state);
		xfrm_nr++;
	}
#endif
	if (!skb_to->sp || atomic_read(&skb_to->sp->refcnt) != 1) {
		sp = secpath_dup(skb_to->sp);
		if (!sp)
			goto drop;
		if (skb_to->sp)
			secpath_put(skb_to->sp);
		skb_to->sp = sp;
	}

	memcpy(skb_to->sp->xvec + skb_to->sp->len, xfrm_vec,
        	xfrm_nr * sizeof(xfrm_vec[0]));
	skb_to->sp->len += xfrm_nr;

	inbound_post_data->skb_to = (void *)skb_to;
	inbound_post_data->skb_from = (void *)skb_from;
	inbound_post_data->x = x;
	inbound_post_data->post_rcv_cb =post_rcv_cb;
	
	csp1_request->data = (void *)inbound_post_data;
	csp1_request->req_type = INBOUND_PROCESSING;
#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,6,27))
	skb_get(skb_from);
#endif
	spin_unlock_bh(&xp->lock);

	if(Csp1ProcessInboundPacket((void *)skb_from,
					(void *)skb_to,
					ctx,
					rlen - 8,
					cavium_cb,
					(void *)csp1_request))
	{ 
		dev_kfree_skb_any(skb_from);
		spin_lock_bh(&xp->lock);
		goto drop;
#ifdef PKP_DEBUG
		printk(KERN_CRIT "CAVIUM: cavium_process_inbound_packet: error calling Csp1ProcessInboundPacket\n");
#endif
	}
	spin_lock_bh(&xp->lock);
	return 0;	
drop:
	if(inbound_post_data)
		kfree(inbound_post_data);
	if(csp1_request)
		kfree(csp1_request);
	if(skb_to)
		dev_kfree_skb_any(skb_to);
	return -1;
}/*cavium_process_inbound_packet*/

int cavium_process_outbound_packet(struct sk_buff *skb_from,
						void *x,
						unsigned long seq, 
						IpsecMode mode,
						EncType enc, 
						AuthType auth,
						Uint64 ctx,
						void(*post_xmit_cb)(int ,void *))
{
	struct sk_buff *skb_to;
	struct iphdr *ipp;
	unsigned int rlen=0, iphlen=0, template_len, aes=0, auth1=0;
	Csp1OutboundPostData *outbound_post_data;
	Csp1EngineRequest *csp1_request;
	struct xfrm_state *xp;
	struct cavm_private_info *info;

	xp  = (struct xfrm_state *)x;
	info = xp->data;

	if (!(info->supported) && !(check_cavium_support (xp)) ){
		spin_unlock_bh(&xp->lock);
		return -1;
	}

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,27))
	ipp = (struct iphdr *)skb_network_header(skb_from);
	if(!mode) {
		if(ipp->version == 4) {
        		struct iphdr *iph = ipp;
        		int ihl;
        		ihl = iph->ihl * 4;
        		skb_push(skb_from, ihl);
        		memmove(skb_from->data, iph, ihl);
		}
		else { //IPV6
			struct ipv6hdr *iph = (struct ipv6hdr *)ipp;
			int hdr_len;	
			hdr_len = ((u8 *)skb_from->data - (u8 *)ipp) - xp->props.header_len;			
			skb_push(skb_from, hdr_len);
			memmove(skb_from->data, iph, hdr_len);
		}
        }
#else
	skb_pull(skb_from, xp->props.header_len); //to undo the effect mode->output
	if (!mode) {
		struct iphdr *iph;
		int ihl;
		iph = skb_from->nh.iph;
		ihl = iph->ihl * 4;
		memmove(skb_from->data, iph, ihl);
	}
#endif
	outbound_post_data = (Csp1OutboundPostData *)kmalloc(sizeof(Csp1OutboundPostData), GFP_ATOMIC);
	if(outbound_post_data == NULL)
	{
		printk(KERN_CRIT "CAVIUM: cavium_process_outbound_packet: Unable to allocate Csp1OutboundPostData\n");
		spin_unlock_bh(&xp->lock);
		return -1;
	}

	csp1_request = (Csp1EngineRequest *)kmalloc(sizeof(Csp1EngineRequest), GFP_ATOMIC);
	if(csp1_request == NULL)
	{
		printk(KERN_CRIT "CAVIUM: cavium_process_outbound_packet: Unable to allocate Csp1EngineRequest\n");
		if(outbound_post_data)
			kfree(outbound_post_data);
		spin_unlock_bh(&xp->lock);
		return -1;
	}
	memset(csp1_request, 0, sizeof(Csp1EngineRequest));

	if (skb_is_nonlinear(skb_from) && (skb_linearize(skb_from) != 0)) 
	{
		printk (KERN_CRIT "CAVIUM: cavium_process_inbound_packet: Unable to linearize skb\n");
		if(csp1_request)
			kfree(csp1_request);
		if(outbound_post_data)
			kfree(outbound_post_data);
		spin_unlock_bh(&xp->lock);
		return -1;
	}

	ipp = (struct iphdr *)skb_from->data;
	if(ipp->version == 4)
		iphlen = ipp->ihl << 2;
	else if (ipp->version == 6)
		iphlen = 40;
	template_len = 0;
	if(mode)
	{
		iphlen = 0;
		if(xp->props.family == AF_INET6)
			template_len = 40;
		else
			template_len = 20;
	}
	switch(enc)
	{
		case AES128CBC:
		case AES192CBC:
		case AES256CBC:
			aes = 1;
		case DES3CBC:
		case DESCBC:
		case NO_CYPHER:
			break;
	}
	if(enc) {
		auth1 = auth ? 1:0;
		rlen = RLEN_OUTBOUND_ESP_PACKET(skb_from->len,iphlen,template_len,aes,auth1);
		/* BUNDLING .... Jul 24*/
		#ifdef MC2
			if(info->next_context) {
				rlen = RLEN_OUTBOUND_AH_PACKET(rlen-8,0,0);
			}
		#endif 
	}
	else if(auth)
	{
		rlen = RLEN_OUTBOUND_AH_PACKET(skb_from->len,template_len,0);
	}	
  
	/* Adjust the rlen in case of udp encapsulation */
 
	if(xp->encap && (xp->encap->encap_type == 2)) 
		rlen +=8;

#ifdef PKP_DEBUG 
	printk(KERN_CRIT "CAVIUM: cavium_process_outbound_packet: packet_len = %d\n", skb_from->len);
	printk(KERN_CRIT "CAVIUM: cavium_process_outbound_packet: iphlen = %d\n", iphlen);
	printk(KERN_CRIT "CAVIUM: cavium_process_outbound_packet: iph_tot_len = %d\n", ntohs(ipp->tot_len));
	printk(KERN_CRIT "CAVIUM: cavium_process_outbound_packet: ipp = 0x%x\n", (uint)ipp);
	printk(KERN_CRIT "CAVIUM: cavium_process_outbound_packet: rlen = %d\n", rlen);
#endif
	/*
	 * if the skb_headroom is less than the size of the 
	 * sequence number, reallocate just the skb->data.
	 * This code is replicated from ip_queue_xmit2
	 */
	if(skb_headroom(skb_from) < 8)
	{
		struct sk_buff *skb2;
		struct sock *sk;
		sk = skb_from->sk;
		skb2 = skb_realloc_headroom(skb_from, 8);
		dev_kfree_skb_any(skb_from);
		if(skb2 == NULL)
		{
			spin_unlock_bh(&xp->lock);
			return -ENOMEM;
		}
		if(sk)
			skb_set_owner_w(skb2, sk);
		skb_from = skb2;
	}

#ifdef PKP_DEBUG
	printk(KERN_CRIT "CAVIUM: cavium_process_outbound_packet: after adding sequence number\n");
	printk(KERN_CRIT "CAVIUM: cavium_process_outbound_packet: skb->data 0x%x\n", (uint)skb_from->data);
	printk(KERN_CRIT "CAVIUM: cavium_process_outbound_packet: packet_len = %d\n", skb_from->len);
// 	cavium_print_buf("INPUT PACKET", skb_from->data, ntohs(ipp->tot_len));	

#endif /* PKP_DEBUG */

	/* allocate final skb */

	/* allocated skb would be rlen+16 size and will adnave data and tail pointers 16 bytes */

	skb_to = dev_alloc_skb(rlen+8+iphlen);
	if(skb_to == NULL)
	{
		if(outbound_post_data)
			kfree(outbound_post_data);
		if(csp1_request)
			kfree(csp1_request);
		spin_unlock_bh(&xp->lock);
		return -1;
	}
	{
		int i=((unsigned long)skb_to->data)&(0x7L);
		skb_pull(skb_to,i);
	}
	/* set skb len */
	/*skb_put(skb_to, rlen-8);*/

	/* now copy L2 header */
	skb_to->priority = skb_from->priority;
	skb_to->protocol = skb_from->protocol;
	skb_to->dev = skb_from->dev;
	skb_to->pkt_type = skb_from->pkt_type;
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,27))
	skb_set_mac_header(skb_to, -14);
	skb_to->local_df = skb_from->local_df;
#else
	skb_to->mac.raw = skb_to->data - 14;
#endif
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,31))
    skb_dst_set(skb_to, dst_clone(skb_dst(skb_from)));
#else
	skb_to->dst = dst_clone(skb_from->dst) ;
#endif

	outbound_post_data->skb_to = (void *)skb_to;
	outbound_post_data->skb_from = (void *)skb_from;
	outbound_post_data->post_xmit_cb = post_xmit_cb;

	csp1_request->data = (void *)outbound_post_data;
	csp1_request->req_type = OUTBOUND_PROCESSING;
#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,6,27))
	skb_get(skb_from);
#endif
	spin_unlock_bh(&xp->lock);
	if(Csp1ProcessOutboundPacket((void *)skb_from,
					(void *)skb_to,
					ctx, /* Changed *NG*/
					rlen - 8,
					seq,
					cavium_cb,
					(void *)csp1_request))
	{
#ifdef PKP_DEBUG
		printk(KERN_CRIT "CAVIUM: cavium_process_outbound_packet: error calling Csp1ProcessOutboundPacket\n");
#endif
		if(outbound_post_data)
			kfree(outbound_post_data);
		if(csp1_request)
			kfree(csp1_request);
		if(skb_to)
			dev_kfree_skb_any(skb_to);
		return -1;
	}
	spin_lock_bh(&xp->lock);
	return 0;	
}/*cavium_process_outbound_packet*/

/*
 *	0 - deliver
 *	1 - block
 */
static __inline__ int cav_icmp_filter(struct sock *sk, struct sk_buff *skb)
{
	int type;

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,27))
	type = (icmp_hdr(skb))->type;
#else
	type = skb->h.icmph->type;
#endif
	if (type < 32) {
		__u32 data = raw_sk(sk)->filter.data;

		return ((1 << type) & data) != 0;
	}

	/* Do not block unknown ICMP types */
	return 0;
}

void cavium_post_rcv_processing(int status, void *p_skb, void *p_x)
{
	int len;
	unsigned char *dat;
	struct iphdr *ipp;
	int iphlen;
	struct sk_buff *skb;
	struct xfrm_state *x;
	struct ipv6hdr *ip6hdr;
#ifdef MC2
	int addr_type=0;	
	struct in6_addr daddr;
#endif
	struct cavm_private_info *info;

	skb = (struct sk_buff *)p_skb;
	x = (struct xfrm_state *)p_x;
        info = x->data;
	if(status)
	{	
		#if 0
		if(skb)	
			dev_kfree_skb_any(skb);
		#endif
		return;
	}
	
	if(x==NULL)
	{
		printk(KERN_CRIT "cavium: cavium_post_rcv_processing: Unable to get SA.\n");
		if(skb)	
			dev_kfree_skb_any(skb);
		return;
	}
	
	dat = skb->data;
	if (x->props.family == AF_INET) {	
		ipp = (struct iphdr *)dat;
		skb->len += htons(ipp->tot_len);
		skb->tail+= (htons(ipp->tot_len) + 8); 
		iphlen = ipp->ihl << 2;
		len = skb->len;
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,27))
		skb_reset_network_header(skb);
#else
		skb->nh.raw = skb->data;
#endif
		memset(&(IPCB(skb)->opt), 0, sizeof(struct ip_options));
		#ifdef NET_21
		skb->nh.raw = skb->data;
		skb->h.raw = skb->nh.raw + (skb->nh.iph->ihl << 2);
		memset(&(IPCB(skb)->opt), 0, sizeof(struct ip_options));
		#else /* NET_21 */
		/* 
		skb->h.iph=(struct iphdr *)skb->data;
		skb->ip_hdr=(struct iphdr *)skb->data;
		memset(skb->proto_priv, 0, sizeof(struct options));
		*/
		#endif /* NET_21 */
		iphlen = ipp->ihl << 2;
		ipp->check = 0;
		ipp->check = ip_fast_csum((unsigned char *)dat, iphlen >> 2);
		skb->protocol = htons(ETH_P_IP);
		{
			struct ethhdr *eth;
			eth = (struct ethhdr *)(skb->data- ETH_HLEN);
			memcpy(eth->h_dest,skb->dev->dev_addr,ETH_HLEN);
		}
		skb->ip_summed = 0;
	} /* end of if (family == AF_INET) */
	else if (x->props.family == AF_INET6) {
		ip6hdr = (struct ipv6hdr*)dat;
		skb->len += (ntohs(ip6hdr->payload_len) + sizeof (struct ipv6hdr) );
		skb->tail +=  (skb->len + 8);
		skb->protocol = htons(ETH_P_IPV6);
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,27))
		skb_reset_network_header(skb);
		skb->transport_header = skb->network_header + sizeof(struct ipv6hdr);
		skb->ip_summed = 0;
		skb->csum = csum_add(skb->csum, csum_partial(skb_network_header(skb),skb->transport_header-skb->network_header,0));
#else
		skb->nh.raw = skb->data;
		skb->h.raw = skb->nh.raw + sizeof(struct ipv6hdr);
		skb->ip_summed = 0;
		skb->csum = csum_add(skb->csum, csum_partial(skb->nh.raw,skb->h.raw-skb->nh.raw,0));
#endif
	} /* end of else if(family == AF_INET6) */

#ifdef PKP_DEBUG 
	printk(KERN_CRIT "CAVIUM: cavium_post_rcv: calling netif_rx skb %p\n",skb);
	printk(KERN_CRIT "CAVIUM: cavium_post_rcv: len = %d\n", len);
	printk(KERN_CRIT "CAVIUM: cavium_post_rcv: iphlen = %d\n", iphlen);
	printk(KERN_CRIT "CAVIUM: cavium_post_rcv: iph_total_payload = %d\n", ntohs(ipp->tot_len));
#endif /*PKP_DEBUG */

	if (x->props.mode) {
		if (x->props.family == AF_INET) {
			if( inet_addr_type(&init_net, x->id.daddr.a4) != RTN_LOCAL ) {
				secpath_reset(skb);
			}
		}
#ifdef MC2
		#if defined(CONFIG_IPV6) || defined(CONFIG_IPV6_MODULE)
		else if (x->props.family == AF_INET6) {
		#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,27))
			daddr = ipv6_hdr(skb)->daddr;
		#else
			daddr = skb->nh.ipv6h->daddr;
		#endif
			addr_type = ipv6_addr_type (&daddr);
		/*change this to ipv6_chk_addr*/
			if((addr_type & IPV6_ADDR_LINKLOCAL) != 0 ) {
				secpath_reset(skb);
			}
		}	
	#endif
#endif
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,31))
		dst_release(skb_dst(skb));
		skb_dst_set(skb, NULL);
#else
		dst_release(skb->dst);
		skb->dst = NULL;
#endif
	}
#ifdef MC2
	else if (info->bundle_state) 
	{
		if(info->bundle_state->props.mode) {
			/* Tunnel mode*/
                	if((x->props.family == AF_INET))
			{
				if(inet_addr_type(&init_net, x->id.daddr.a4) != RTN_LOCAL ) 
				secpath_reset(skb);
			}
			else if((x->props.family == AF_INET6))
			{
				#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,27))
				daddr = ipv6_hdr(skb)->daddr;
				#else
				daddr = skb->nh.ipv6h->daddr;
				#endif
				addr_type = ipv6_addr_type (&daddr);
                		/*change this to ipv6_chk_addr*/
				if((addr_type & IPV6_ADDR_LINKLOCAL) != 0) 
					secpath_reset(skb);
			}
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,31))
			dst_release(skb_dst(skb));
			skb_dst_set(skb, NULL);
#else
			dst_release(skb->dst);
			skb->dst = NULL;
#endif
		}
	}
#endif
	netif_rx(skb);
	return ;
}

void cavium_post_xmit_processing(int status, void *p_skb/*, void *p_rt*/)
{
	struct sk_buff *skb;
	struct iphdr *ipp;
	struct ipv6hdr *ip6hdr;
	struct cavm_private_info *info;
	struct dst_entry *dst;

	if(status)
	{
		if(p_skb) 
			dev_kfree_skb_irq((struct sk_buff *)p_skb);
			return;
		}
		skb = (struct sk_buff *)p_skb;

	/*
	 *	Return if there is nothing to do.  (Does this ever happen?) XXX
	 */

	if (skb == NULL) {
		goto cleanup;
	}
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,31))
	dst  = skb_dst(skb);
	info = dst->xfrm->data;
	#ifdef MC2
	if(info->bundle && info->bundle_state ) {
  		skb_dst_set(skb, dst_pop(dst));
  		if((dst = skb_dst(skb)) == NULL ) {
			goto cleanup ;
		}
		if(dst->xfrm->props.mode)
			secpath_reset(skb);
  		/*if(	(skb->dst = dst_pop(skb->dst)) == NULL ) {
				goto cleanup ;
			}
			*/
	}
  	skb_dst_set(skb, dst_pop(dst));
  	if(skb_dst(skb) == NULL ) {
		goto cleanup ;
	}
	#else
  	skb_dst_set(skb, dst_pop(dst));
  	if(skb_dst(skb) == NULL ) {
		goto cleanup ;
	}
	#endif
#else
	dst = skb->dst;
	info = dst->xfrm->data;
	#ifdef MC2
	if(info->bundle && info->bundle_state ) {
  		if((skb->dst = dst_pop(dst)) == NULL ) {
			goto cleanup;
		}
		dst = skb->dst;
		if(dst->xfrm->props.mode)
			secpath_reset(skb);
  		/*if(	(skb->dst = dst_pop(skb->dst)) == NULL ) {
				goto cleanup ;
			}
			*/
	}
 	if(	(skb->dst = dst_pop(dst)) == NULL ) {
		goto cleanup ;
	}
	#else
  	if((skb->dst = dst_pop(dst)) == NULL ) {
		goto cleanup ;
	}
	#endif
#endif
	ipp = (struct iphdr *)skb->data;

	if (ipp->version == 4) {
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,27))
		skb_reset_network_header(skb);
#else
		skb->nh.iph = (struct iphdr *)skb->data;
		skb->nh.raw = skb->data;
#endif
		ipp = (struct iphdr *)skb->data;
		skb->len += htons(ipp->tot_len);
	}
	else if (ipp->version == 6) {
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,27))
		skb_reset_network_header(skb);
		ip6hdr = ipv6_hdr(skb);
#else
		skb->nh.raw = skb->data;
		ip6hdr = (struct ipv6hdr *)skb->data ;
#endif
		skb->len += htons(ip6hdr->payload_len) + sizeof(struct ipv6hdr);
		skb->tail += htons(ip6hdr->payload_len) + sizeof(struct ipv6hdr);
	}

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,27))
	if(skb->len < skb_network_header(skb) - skb->data) {
		goto cleanup;
	}
#else
	if(skb->len < skb->nh.raw - skb->data) {
		goto cleanup;
	}
#endif
	dst_output(skb);
	skb = NULL;
cleanup:
	if(skb)
		dev_kfree_skb_irq(skb);
	return;
}

void cavium_xfrm_replay_notify(struct xfrm_state *x, int event)
{
	struct km_event c;
	/* we send notify messages in case
	 *  1. we updated on of the sequence numbers, and the seqno difference
	 *     is at least x->replay_maxdiff, in this case we also update the
	 *     timeout of our timer function
	 *  2. if x->replay_maxage has elapsed since last update,
	 *     and there were changes
	 *
	 *  The state structure must be locked!
	 */

	switch (event) {
	case XFRM_REPLAY_UPDATE:
		if (x->replay_maxdiff &&
		    (x->replay.seq - x->preplay.seq < x->replay_maxdiff) &&
		    (x->replay.oseq - x->preplay.oseq < x->replay_maxdiff)) {
			if (x->xflags & XFRM_TIME_DEFER)
				event = XFRM_REPLAY_TIMEOUT;
			else
				return;
		}

		break;

	case XFRM_REPLAY_TIMEOUT:
		if ((x->replay.seq == x->preplay.seq) &&
		    (x->replay.bitmap == x->preplay.bitmap) &&
		    (x->replay.oseq == x->preplay.oseq)) {
			x->xflags |= XFRM_TIME_DEFER;
			return;
		}

		break;
	}

	memcpy(&x->preplay, &x->replay, sizeof(struct xfrm_replay_state));
	c.event = XFRM_MSG_NEWAE;
	c.data.aevent = event;
	km_state_notify(x, &c);

	if (x->replay_maxage &&
	    !mod_timer(&x->rtimer, jiffies + x->replay_maxage))
		x->xflags &= ~XFRM_TIME_DEFER;
}

void cavium_xfrm_replay_advance(struct xfrm_state *x, __be32 net_seq)
{
	u32 diff;
	u32 seq = ntohl(net_seq);

	if (seq > x->replay.seq) {
		diff = seq - x->replay.seq;
		if (diff < x->props.replay_window)
			x->replay.bitmap = ((x->replay.bitmap) << diff) | 1;
		else
			x->replay.bitmap = 1;
		x->replay.seq = seq;
	} else {
		diff = x->replay.seq - seq;
		x->replay.bitmap |= (1U << diff);
	}

#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,6,31))
	if (xfrm_aevent_is_on())
#else
	if (xfrm_aevent_is_on(xs_net(x)))
#endif
		cavium_xfrm_replay_notify(x, XFRM_REPLAY_UPDATE);
}

static void
cavium_update_seq(struct sk_buff *skb, struct xfrm_state *x)
{
	int offset = 0;
	u32 seq;
	Uint8 *data = NULL;
	Uint8 nexthdr;
        struct cavm_private_info *info;

        info = x->data;
	data = skb->data;
	if (((struct iphdr *)data)->version == 4) {
		nexthdr = ((struct iphdr *)data)->protocol;
		offset = 20;
	} else if (((struct iphdr *)data)->version == 6) {
		nexthdr = ((struct ipv6hdr *)data)->nexthdr;
		offset = 40;
	} else
		return;
	switch (nexthdr) {
	case IPPROTO_AH:
		offset += offsetof(struct ip_auth_hdr, seq_no);
		break;
	case IPPROTO_ESP:
		offset += offsetof(struct ip_esp_hdr, seq_no);
		break;
	/* if (x->udp_encap is set )*/
	case IPPROTO_UDP:
		/* AH will not work with udp encap
		 * so taking esp as the next header
		 * offset = iphdr(20)----udphdr(8)----ESP hdr */
		offset +=8;
		offset += offsetof(struct ip_esp_hdr, seq_no);
		break;
	default:
		printk(KERN_CRIT "cavium_update_seq: Invalid protocol %d \n", ((struct iphdr*)data)->protocol);
		return;
	}

	if (!pskb_may_pull(skb, 16)) {
		return;
	}

	seq = *(u32*)(skb->data + offset);
	
	spin_lock_bh(&x->lock);
	if ( x->props.replay_window 
#ifdef MC2
|| (info->bundle_state && info->bundle_state->props.replay_window)
#endif
 ) 	{
		cavium_xfrm_replay_advance(x, seq);	
	}
	spin_unlock_bh(&x->lock);
	return;
}

static int check_cavium_support (struct xfrm_state *x)
{
	#ifndef MC2
		struct xfrm_state *x1;
		Uint8 dir;
	#endif
                struct cavm_private_info *info;
                info = x->data;

	#ifdef MC2
		if (info->bundle_state) {
				if(x->id.proto == info->bundle_state->id.proto) {
  				printk (KERN_CRIT "CAVIUM: This Policy is not supported, Dropping packet\n" );
					return 0;
				}
		}
	#else
		/* MC1 not supported features */
		if (x->props.family == AF_INET6){
			printk(KERN_CRIT "\n MC1  Doesn't support IPv6\n");
			return 0;
		}
		if (x->props.ealgo != SADB_EALG_DESCBC && x->props.ealgo != SADB_EALG_3DESCBC) {	
			printk(KERN_CRIT "\n MC1 Supports only DES 3DES \n");
			return 0;
		}
		if(inet_addr_type(x->id.daddr.a4) == RTN_LOCAL )	
			dir = 0 ; /* INBOUND */
		else 
			dir = 1 ; /* OUTBOUND */
		x1 = cavium_find_bundle (x->props.mode,&x->id.daddr,&x->props.saddr,dir,x);
		if(x1) {
			printk(KERN_CRIT "\n MC1 Doesn't support bundles\n");
			return 0;
		}
	#endif
		info->supported = 1;
		return 1;

}

