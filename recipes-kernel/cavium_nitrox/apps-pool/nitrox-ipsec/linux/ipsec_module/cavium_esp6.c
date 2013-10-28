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
#include <linux/scatterlist.h>
#include <linux/crypto.h>
#include <linux/kernel.h>
#include <linux/pfkeyv2.h>
#include <linux/random.h>
#include <linux/version.h>
#include <net/icmp.h>
#include <net/ipv6.h>
#include <net/protocol.h>
#include <linux/icmpv6.h>

#include "cavium_common.h"
#include "ipsec_engine.h"
#include "cavium_ipsec.h"
#include "cavium_kernel.h"

static int cav_esp6_output(struct xfrm_state *x, struct sk_buff *skb)
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
        }
        ret = cavium_process_outbound_packet(   skb,
                                                x,
                                                ++x->replay.oseq,
                                                x->props.mode,
                                                ealgo,
                                                x->props.aalgo,
                                                info->context,
                                                cavium_post_xmit_processing );
        if(ret < 0)
                kfree_skb(skb);
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,27))
        else {
		spin_unlock_bh(&x->lock);
        }
#endif
	return -EINPROGRESS;
}

static int cav_esp6_input(struct xfrm_state *x, struct sk_buff *skb)
{
        EncType ealgo;
        struct cavm_private_info *info;
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,27))
	spin_lock_bh(&x->lock);
#endif
        info = x->data;
        skb_push(skb,sizeof(struct ipv6hdr));
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
        }
        cavium_process_inbound_packet(  skb,
                                        x,
                                        NULL,
                                        x->props.mode,
                                        ealgo,
                                        info->context,
                                        cavium_post_rcv_processing );
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,27))
	spin_unlock_bh(&x->lock);
#endif
        return -EINPROGRESS;
}

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,27))
static u32 cav_esp6_get_mtu(struct xfrm_state *x, int mtu)
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

        if (x->props.mode != XFRM_MODE_TUNNEL) {
                u32 padsize = ((blksize - 1) & 7) + 1;
                mtu -= blksize - padsize;
                mtu += min_t(u32, blksize - padsize, rem);
        }

        return mtu - 2;
}
#else
static u32 cav_esp6_get_max_size(struct xfrm_state *x, int mtu)
{
	u32 blksize;

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

	if (x->props.mode == XFRM_MODE_TUNNEL) {
		mtu = ALIGN(mtu + 2, blksize);
	} else {
		/* The worst case. */
		u32 padsize = ((blksize - 1) & 7) + 1;
		mtu = ALIGN(mtu + 2, padsize) + blksize - padsize;
	}
	if (x->aalg) {
		struct xfrm_algo_desc *aalg_desc;
		aalg_desc = xfrm_aalg_get_byname(x->aalg->alg_name, 0);
		mtu += aalg_desc->uinfo.auth.icv_truncbits/8;
        }

	return mtu + x->props.header_len;
}
#endif

static void cav_esp6_err(struct sk_buff *skb, struct inet6_skb_parm *opt,
		     u8 type, u8 code, int offset, __be32 info)
{
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,31))
	struct net *net = dev_net(skb->dev);
#endif
	struct ipv6hdr *iph = (struct ipv6hdr*)skb->data;
	struct ip_esp_hdr *esph = (struct ip_esp_hdr *)(skb->data + offset);
	struct xfrm_state *x;

	if (type != ICMPV6_DEST_UNREACH &&
	    type != ICMPV6_PKT_TOOBIG)
		return;

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,31))
	x = xfrm_state_lookup(net, (xfrm_address_t *)&iph->daddr, esph->spi, IPPROTO_ESP, AF_INET6);
#else
	x = xfrm_state_lookup((xfrm_address_t *)&iph->daddr, esph->spi, IPPROTO_ESP, AF_INET6);
#endif
	if (!x)
		return;
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,31))
	printk(KERN_DEBUG "pmtu discovery on SA ESP/%08x/%pI6\n",
			ntohl(esph->spi), &iph->daddr);
#else
	printk(KERN_DEBUG "pmtu discovery on SA ESP/%08x/" NIP6_FMT "\n",
			ntohl(esph->spi), NIP6(iph->daddr));
#endif
	xfrm_state_put(x);
}

static void cav_esp6_destroy(struct xfrm_state *x)
{
	struct cavm_private_info *info = x->data;
	if (!info)
		return;
	kfree(info);
}

static int cav_esp6_init_state(struct xfrm_state *x)
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

	if (x->encap)
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
		x->props.header_len += sizeof(struct ipv6hdr);

        info = kzalloc(sizeof(*info), GFP_KERNEL);
	if (info == NULL)
		return -ENOMEM;
	x->data = info;
	return 0;

error:
	return -EINVAL;
}

static struct xfrm_type cav_esp6_type =
{
	.description	= "ESP6",
	.owner	     	= THIS_MODULE,
	.proto	     	= IPPROTO_ESP,
	.init_state	= cav_esp6_init_state,
	.destructor	= cav_esp6_destroy,
	.get_mtu	= cav_esp6_get_mtu,
	.input		= cav_esp6_input,
	.output		= cav_esp6_output,
	.hdr_offset	= xfrm6_find_1stfragopt,
};

static struct inet6_protocol cav_esp6_protocol = {
	.handler 	=	xfrm6_rcv,
	.err_handler	=	cav_esp6_err,
	.flags		=	INET6_PROTO_NOPOLICY,
};

int cavium_register_esp6(void)
{
	if (xfrm_register_type(&cav_esp6_type, AF_INET6) < 0) {
		printk(KERN_INFO "ipv6 esp init: can't add xfrm type\n");
		return -EAGAIN;
	}
	if (inet6_add_protocol(&cav_esp6_protocol, IPPROTO_ESP) < 0) {
		printk(KERN_INFO "ipv6 esp init: can't add protocol\n");
		xfrm_unregister_type(&cav_esp6_type, AF_INET6);
		return -EAGAIN;
	}
	return 0;
}
void cavium_unregister_esp6(void)
{
	if (inet6_del_protocol(&cav_esp6_protocol, IPPROTO_ESP) < 0)
		printk(KERN_INFO "ipv6 esp close: can't remove protocol\n");
	if (xfrm_unregister_type(&cav_esp6_type, AF_INET6) < 0)
		printk(KERN_INFO "ipv6 esp close: can't remove xfrm type\n");
}
