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

#include <linux/err.h>
#include <linux/module.h>
#include <net/ip.h>
#include <net/xfrm.h>
#include <net/esp.h>
#include <asm/scatterlist.h>
#include <linux/crypto.h>
#include <linux/kernel.h>
#include <linux/pfkeyv2.h>
#include <linux/random.h>
#include <linux/version.h>
#include <net/icmp.h>
#include <net/protocol.h>
#include <net/udp.h>

#include "ipsec_engine.h"
#include "cavium_ipsec.h"
#include "cavium_kernel.h"
#include "cavium_common.h"


static int cav_esp_output(struct xfrm_state *x, struct sk_buff *skb)
{
	EncType ealgo;
	int ret;
	struct cavm_private_info *info;
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,27))
	spin_lock_bh(&x->lock);
#endif
	info = x->data;
	switch(x->props.ealgo){
		case SADB_EALG_DESCBC:
			ealgo = DESCBC;
			break;
		case SADB_EALG_3DESCBC:
			ealgo = DES3CBC;
			break;
		case SADB_X_EALG_AESCBC:
			if(x->ealg->alg_key_len == 128)
				ealgo = AES128CBC;
			else if(x->ealg->alg_key_len == 192)
				ealgo = AES192CBC;
			else if(x->ealg->alg_key_len == 256)
				ealgo = AES256CBC;
			else
				ealgo = NO_CYPHER;
			break;
		default:
			ealgo = NO_CYPHER;
			break;
	}
	ret = cavium_process_outbound_packet(   skb,
						x,
						++x->replay.oseq,
						x->props.mode,
						ealgo,
						x->props.aalgo,
						info->context,
						cavium_post_xmit_processing);
	if(ret < 0)
	{
		dev_kfree_skb_any(skb);
	}
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,27))
	else {
		spin_unlock_bh(&x->lock);
	}
#endif
	return -EINPROGRESS;
}

/*
 * Note: detecting truncated vs. non-truncated authentication data is very
 * expensive, so we only support truncated data, which is the recommended
 * and common case.
 */
static int cav_esp_input(struct xfrm_state *x, struct sk_buff *skb)
{
	int totallen;
	unsigned char *dat;
	struct xfrm_encap_tmpl *tempDecap = NULL;
	struct cavm_private_info *info;
	EncType ealgo = 0;
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,27))
	spin_lock_bh(&x->lock);
#endif
	info = x->data;
	if(x->encap && (x->encap->encap_type == UDP_ENCAP_ESPINUDP))
        {
		skb_push(skb, sizeof(struct iphdr) + sizeof(struct udphdr));
		((struct iphdr *)(skb->data))->check = 0;

		dat = skb->data;

		totallen = ((struct iphdr *)(skb->data))->ihl;

		/* Set the protocol field in the IP header to 11 */
		((struct iphdr *)(skb->data))->protocol = 0x11;

		/* Increment the length field of the IP Header */

		((struct iphdr *)(skb->data))->tot_len  = htons(ntohs(((struct iphdr *)(skb->data))->tot_len) + sizeof(struct udphdr)) ;

		/* Recalculate the IP checksum of the packet */
		((struct iphdr *)(skb->data))->check = ip_fast_csum((unsigned char *)dat,totallen);
	} else {
		skb_push(skb,sizeof(struct iphdr));
		((struct iphdr *)(skb->data))->check =0;
	}
	switch(x->props.ealgo)
	{
		case SADB_EALG_DESCBC:
			ealgo = DESCBC;
			break;
		case SADB_EALG_3DESCBC:
			ealgo = DES3CBC;
			break;
		case SADB_X_EALG_AESCBC:
			if(x->ealg->alg_key_len == 128)
				ealgo = AES128CBC;
			else if(x->ealg->alg_key_len == 192)
				ealgo = AES192CBC;
			else if(x->ealg->alg_key_len == 256)
				ealgo = AES256CBC;
			else
				ealgo = NO_CYPHER;
			break;
		default:
			ealgo = NO_CYPHER;
	}
	if(x->encap && (x->encap->encap_type == UDP_ENCAP_ESPINUDP))
		tempDecap = x->encap;
	cavium_process_inbound_packet(  skb,
					x,
					tempDecap,
					x->props.mode,
					ealgo,
					info->context,
					cavium_post_rcv_processing);
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,27))
	spin_unlock_bh(&x->lock);
#endif
	return -EINPROGRESS;
}

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,27))
static u32 cav_esp4_get_mtu(struct xfrm_state *x, int mtu)
{
	u32 blksize;
	u32 align;
	u32 rem;
	u32 authsize=0;

	switch(x->props.ealgo)
	{
		case SADB_EALG_DESCBC:
		case SADB_EALG_3DESCBC:
			blksize = 8;
			break;
		case SADB_X_EALG_AESCBC:
			blksize = 16;
			break;
		default:
			blksize = 1;
	}
	blksize = ALIGN(blksize, 4);
	align = max_t(u32, blksize, 0);

	if (x->aalg) {
		struct xfrm_algo_desc *aalg_desc;
		aalg_desc = xfrm_aalg_get_byname(x->aalg->alg_name, 0);
		authsize = aalg_desc->uinfo.auth.icv_truncbits/8;
	}
	mtu -= x->props.header_len + authsize;

	rem = mtu & (align - 1);
	mtu &= ~(align - 1);

	switch (x->props.mode) {
	case XFRM_MODE_TUNNEL:
		break;
	default:
	case XFRM_MODE_TRANSPORT:
		/* The worst case */
		mtu -= blksize - 4;
		mtu += min_t(u32, blksize - 4, rem);
		break;
	case XFRM_MODE_BEET:
		/* The worst case. */
		mtu += min_t(u32, IPV4_BEET_PHMAXLEN, rem);
		break;
	}

	return mtu - 2;
}
#else
static u32 cav_esp4_get_max_size(struct xfrm_state *x, int mtu)
{
	u32 blksize;
	int enclen = 0;
	switch(x->props.ealgo)
	{
		case SADB_EALG_DESCBC:
		case SADB_EALG_3DESCBC:
			blksize = 8;
			break;
		case SADB_X_EALG_AESCBC:
			blksize = 16;
			break;
		default:
			blksize = 1;
	}
	blksize = ALIGN(blksize, 4);

	switch (x->props.mode) {
	case XFRM_MODE_TUNNEL:
		mtu = ALIGN(mtu +2, blksize);
		break;
	default:
	case XFRM_MODE_TRANSPORT:
		/* The worst case */
		mtu = ALIGN(mtu + 2, 4) + blksize - 4;
		break;
	case XFRM_MODE_BEET:
		/* The worst case. */
		enclen = IPV4_BEET_PHMAXLEN;
		mtu = ALIGN(mtu + enclen + 2, blksize);
		break;
	}

	if (x->aalg) {
		struct xfrm_algo_desc *aalg_desc;
		aalg_desc = xfrm_aalg_get_byname(x->aalg->alg_name, 0);
		mtu += aalg_desc->uinfo.auth.icv_truncbits/8;
	}

	return mtu + x->props.header_len - enclen;
}
#endif

#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,6,27))
static void cav_esp4_err(struct sk_buff *skb, u32 info)
{
	struct iphdr *iph = (struct iphdr*)skb->data;
	struct ip_esp_hdr *esph = (struct ip_esp_hdr*)(skb->data+(iph->ihl<<2));
	struct xfrm_state *x;

	if (skb->h.icmph->type != ICMP_DEST_UNREACH ||
	    skb->h.icmph->code != ICMP_FRAG_NEEDED)
		return;

	x = xfrm_state_lookup((xfrm_address_t *)&iph->daddr, esph->spi, IPPROTO_ESP, AF_INET);
	if (!x)
		return;
	NETDEBUG(KERN_DEBUG "pmtu discovery on SA ESP/%08x/%08x\n",
		 ntohl(esph->spi), ntohl(iph->daddr));
	xfrm_state_put(x);
}
#else
static void cav_esp4_err(struct sk_buff *skb, u32 info)
{
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,31))
	struct net *net = dev_net(skb->dev);
#endif
	struct iphdr *iph = (struct iphdr*)skb->data;
	struct ip_esp_hdr *esph = (struct ip_esp_hdr*)(skb->data+(iph->ihl<<2));
	struct xfrm_state *x;

	if (icmp_hdr(skb)->type != ICMP_DEST_UNREACH ||
	    icmp_hdr(skb)->code != ICMP_FRAG_NEEDED)
		return;

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,31))
	x = xfrm_state_lookup(net, (xfrm_address_t *)&iph->daddr, esph->spi, IPPROTO_ESP, AF_INET);
#else
	x = xfrm_state_lookup((xfrm_address_t *)&iph->daddr, esph->spi, IPPROTO_ESP, AF_INET);
#endif
	if (!x)
		return;
	NETDEBUG(KERN_DEBUG "pmtu discovery on SA ESP/%08x/%08x\n",
		 ntohl(esph->spi), ntohl(iph->daddr));
	xfrm_state_put(x);
}
#endif

static void cav_esp_destroy(struct xfrm_state *x)
{
	struct cavm_private_info *info = x->data;
	if (!info)
		return;
	kfree(info);
}

static int cav_esp_init_state(struct xfrm_state *x)
{
	struct cavm_private_info *info = NULL;
	int ivlen;

	/* null auth and encryption can have zero length keys */
	if (x->aalg) {
		if (x->aalg->alg_key_len > 512)
			goto error;
	}
	if (x->ealg == NULL)
		goto error;

	switch(x->props.ealgo)
	{
		case SADB_EALG_DESCBC:
		case SADB_EALG_3DESCBC:
			ivlen = 8;
			break;
		case SADB_X_EALG_AESCBC:
			ivlen = 16;
			break;
		default:
			ivlen = 1;
	}
	x->props.header_len = sizeof(struct ip_esp_hdr) + ivlen;

	if (x->props.mode == XFRM_MODE_TUNNEL)
		x->props.header_len += sizeof(struct iphdr);
	if (x->encap) {
		struct xfrm_encap_tmpl *encap = x->encap;

		switch (encap->encap_type) {
		default:
			goto error;
		case UDP_ENCAP_ESPINUDP:
			x->props.header_len += sizeof(struct udphdr);
			break;
		case UDP_ENCAP_ESPINUDP_NON_IKE:
			x->props.header_len += sizeof(struct udphdr) + 2 * sizeof(u32);
			break;
		}
	}

	info = kzalloc(sizeof(*info), GFP_KERNEL);
	if (info == NULL)
		return -ENOMEM;
	x->data = info;
	return 0;
error:
	return -EINVAL;
}

static struct xfrm_type cav_esp_type =
{
	.description	= "ESP4",
	.owner		= THIS_MODULE,
	.proto	     	= IPPROTO_ESP,
	.init_state	= cav_esp_init_state,
	.destructor	= cav_esp_destroy,
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,27))
	.get_mtu	= cav_esp4_get_mtu,
#else
	.get_max_size	= cav_esp4_get_max_size,
#endif
	.input		= cav_esp_input,
	.output		= cav_esp_output
};

static struct net_protocol cav_esp4_protocol = {
	.handler	=	xfrm4_rcv,
	.err_handler	=	cav_esp4_err,
	.no_policy	=	1,
};

int cavium_register_esp4(void)
{

	if (xfrm_register_type(&cav_esp_type, AF_INET) < 0) {
		printk(KERN_INFO "ip esp init: can't add xfrm type\n");
		return -EAGAIN;
	}
	if (inet_add_protocol(&cav_esp4_protocol, IPPROTO_ESP) < 0) {
		printk(KERN_INFO "ip esp init: can't add protocol\n");
		xfrm_unregister_type(&cav_esp_type, AF_INET);
		return -EAGAIN;
	}
	return 0;
}

void cavium_unregister_esp4(void)
{
	if (inet_del_protocol(&cav_esp4_protocol, IPPROTO_ESP) < 0)
		printk(KERN_INFO "ip esp close: can't remove protocol\n");
	if (xfrm_unregister_type(&cav_esp_type, AF_INET) < 0)
		printk(KERN_INFO "ip esp close: can't remove xfrm type\n");
}
