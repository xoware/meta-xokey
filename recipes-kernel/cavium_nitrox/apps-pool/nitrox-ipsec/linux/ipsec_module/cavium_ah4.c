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
#include <net/ah.h>
#include <linux/crypto.h>
#include <linux/pfkeyv2.h>
#include <linux/version.h>
#include <net/icmp.h>
#include <net/protocol.h>
#include <asm/scatterlist.h>

#include "cavium_common.h"
#include "cavium_ipsec.h"
#include "ipsec_engine.h"
#include "cavium_kernel.h"


static int cav_ah_output(struct xfrm_state *x, struct sk_buff *skb)
{
	struct cavm_private_info *info;
	int err=0;
#ifdef MC2
	AuthType aalgo=0;
	int ret;
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,27))
	spin_lock_bh(&x->lock);
#endif       
	if((skb->ip_summed == CHECKSUM_PARTIAL) && (skb_checksum_help(skb)))
	{
		err = -EINVAL;
		dev_kfree_skb_any(skb);
		goto error;
	}
	switch(x->props.aalgo)
	{
		case SADB_AALG_MD5HMAC:
			aalgo = MD5HMAC96;
			break;
		case SADB_AALG_SHA1HMAC:
			aalgo = SHA1HMAC96;
			break;
		default:
			aalgo = NO_AUTH;
			break;
	}
	info = x->data;
	ret = cavium_process_outbound_packet(skb, x, ++x->replay.oseq, x->props.mode, 0, aalgo, info->context, cavium_post_xmit_processing);
	if(ret < 0) {
		dev_kfree_skb_any(skb);
	}
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,27))
	else {
		spin_unlock_bh(&x->lock);
	}
#endif
	err = -EINPROGRESS;
#else
	printk(KERN_CRIT "\n MC1 doesn't support AH");
	err = -ENOSYS; /* Function not implemented */
#endif
error:
	return err;
}

static int cav_ah_input(struct xfrm_state *x, struct sk_buff *skb)
{
	EncType ealgo=0;
	int err=-EINPROGRESS;
	struct cavm_private_info *info;

	skb_push(skb, sizeof(struct iphdr));
	((struct iphdr *)(skb->data))->check = 0;
#ifdef MC2
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,27))
	spin_lock_bh(&x->lock);
#endif
	info = x->data;
	if(info->bundle_state)
	switch(info->bundle_state->props.ealgo)
	{
		case SADB_EALG_DESCBC:
			ealgo = DESCBC;
			break;
		case SADB_EALG_3DESCBC:
			ealgo = DES3CBC;
			break;
		case SADB_X_EALG_AESCBC:
			if(info->bundle_state->ealg->alg_key_len == 128)
				ealgo = AES128CBC;
			else if(info->bundle_state->ealg->alg_key_len == 192)
				ealgo = AES192CBC;
			else if(info->bundle_state->ealg->alg_key_len == 256)
				ealgo = AES256CBC;
			else
				ealgo = NO_CYPHER;
			break;
		default:
			ealgo = NO_CYPHER;
			break;
	}
	cavium_process_inbound_packet(  skb, 
					x, 
					NULL, 
					x->props.mode, ealgo,
					info->context,
					cavium_post_rcv_processing);
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,27))
	spin_unlock_bh(&x->lock);
#endif
#else
	printk(KERN_CRIT "\n MC1 Doesn't support AH");
#endif
	return err;
}

#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,6,27))
static void cav_ah4_err(struct sk_buff *skb, u32 info)
{
	struct iphdr *iph = (struct iphdr*)skb->data;
	struct ip_auth_hdr *ah = (struct ip_auth_hdr*)(skb->data+(iph->ihl<<2));
	struct xfrm_state *x;

	if (skb->h.icmph->type != ICMP_DEST_UNREACH ||
	    skb->h.icmph->code != ICMP_FRAG_NEEDED)
		return;

	x = xfrm_state_lookup((xfrm_address_t *)&iph->daddr, ah->spi, IPPROTO_AH, AF_INET);
	if (!x)
		return;
	printk(KERN_DEBUG "pmtu discovery on SA AH/%08x/%08x\n",
	       ntohl(ah->spi), ntohl(iph->daddr));
	xfrm_state_put(x);
}
#else
static void cav_ah4_err(struct sk_buff *skb, u32 info)
{
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,31))
	struct net *net = dev_net(skb->dev);
#endif
	struct iphdr *iph = (struct iphdr*)skb->data;
	struct ip_auth_hdr *ah = (struct ip_auth_hdr*)(skb->data+(iph->ihl<<2));
	struct xfrm_state *x;

	if (icmp_hdr(skb)->type != ICMP_DEST_UNREACH ||
	    icmp_hdr(skb)->code != ICMP_FRAG_NEEDED)
		return;

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,31))
	x = xfrm_state_lookup(net, (xfrm_address_t *)&iph->daddr, ah->spi, IPPROTO_AH, AF_INET);
#else
	x = xfrm_state_lookup((xfrm_address_t *)&iph->daddr, ah->spi, IPPROTO_AH, AF_INET);
#endif
	if (!x)
		return;
	printk(KERN_DEBUG "pmtu discovery on SA AH/%08x/%08x\n",
	       ntohl(ah->spi), ntohl(iph->daddr));
	xfrm_state_put(x);
}
#endif

static int cav_ah_init_state(struct xfrm_state *x)
{
	struct cavm_private_info *info = NULL;

	if (!x->aalg)
		goto error;

	/* null auth can use a zero length key */
	if (x->aalg->alg_key_len > 512)
		goto error;

	if (x->encap)
		goto error;

	info = kzalloc(sizeof(*info), GFP_KERNEL);
	if (info == NULL)
		return -ENOMEM;
	x->props.header_len = XFRM_ALIGN8(sizeof(struct ip_auth_hdr) + MAX_AH_AUTH_LEN);
	if (x->props.mode == XFRM_MODE_TUNNEL)
		x->props.header_len += sizeof(struct iphdr);
	x->data = info;

	return 0;
error:
	return -EINVAL;
}

static void cav_ah_destroy(struct xfrm_state *x)
{
	struct cavm_private_info *info = x->data;
	if (!info)
		return;
	kfree(info);
}

static struct xfrm_type cav_ah_type =
{
	.description	= "AH4",
	.owner		= THIS_MODULE,
	.proto	     	= IPPROTO_AH,
	.init_state	= cav_ah_init_state,
	.destructor	= cav_ah_destroy,
	.input		= cav_ah_input,
	.output		= cav_ah_output
};

static struct net_protocol cav_ah4_protocol = {
	.handler	=	xfrm4_rcv,
	.err_handler	=	cav_ah4_err,
	.no_policy	=	1,
};

int cavium_register_ah4(void)
{
	if (xfrm_register_type(&cav_ah_type, AF_INET) < 0) {
		printk(KERN_INFO "ip ah init: can't add xfrm type\n");
		return -EAGAIN;
	}
	if (inet_add_protocol(&cav_ah4_protocol, IPPROTO_AH) < 0) {
		printk(KERN_INFO "ip ah init: can't add protocol\n");
		xfrm_unregister_type(&cav_ah_type, AF_INET);
		return -EAGAIN;
	}
	return 0;
}

void cavium_unregister_ah4(void)
{
	if (inet_del_protocol(&cav_ah4_protocol, IPPROTO_AH) < 0)
		printk(KERN_INFO "ip ah close: can't remove protocol\n");
	if (xfrm_unregister_type(&cav_ah_type, AF_INET) < 0)
		printk(KERN_INFO "ip ah close: can't remove xfrm type\n");
}
