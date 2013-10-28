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
#include <net/ip.h>
#include <net/ah.h>
#include <linux/crypto.h>
#include <linux/pfkeyv2.h>
#include <linux/string.h>
#include <linux/version.h>
#include <net/icmp.h>
#include <net/ipv6.h>
#include <net/protocol.h>
#include <net/xfrm.h>
#include <asm/scatterlist.h>

#include "cavium_common.h"
#include "cavium_kernel.h"
#include "cavium_ipsec.h"
#include "ipsec_engine.h"


static int cav_ah6_output(struct xfrm_state *x, struct sk_buff *skb)
{
        struct cavm_private_info *info;
        AuthType aalgo;
        int ret;
        if(x == NULL)
                return -1;
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,27))
	spin_lock_bh(&x->lock);
#endif       
        switch(x->props.aalgo)
        {
                case SADB_AALG_MD5HMAC:
                        aalgo = MD5HMAC96;
                        break;
                case SADB_AALG_SHA1HMAC:
                        aalgo = SHA1HMAC96;
                        break;
                default :
                        aalgo = NO_AUTH;
                        break;
        }
        info = x->data;
        ret = cavium_process_outbound_packet(   skb,
                                                x,
                                                ++x->replay.oseq,
                                                x->props.mode,
                                                0, aalgo,
                                                info->context,
                                                cavium_post_xmit_processing);
        if(ret < 0)
                kfree_skb(skb);
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,27))
        else {
		spin_unlock_bh(&x->lock);
	}
#endif
	return -EINPROGRESS;
}

static int cav_ah6_input(struct xfrm_state *x, struct sk_buff *skb)
{
	/*
	 * Before process AH
	 * [IPv6][Ext1][Ext2][AH][Dest][Payload]
	 * |<-------------->| hdr_len
	 *
	 * To erase AH:
	 * Keeping copy of cleared headers. After AH processing,
	 * Moving the pointer of skb->nh.raw by using skb_pull as long as AH
	 * header length. Then copy back the copy as long as hdr_len
	 * If destination header following AH exists, copy it into after [Ext2].
	 *
	 * |<>|[IPv6][Ext1][Ext2][Dest][Payload]
	 * There is offset of AH before IPv6 header after the process.
	 */

	int err=-EINPROGRESS;
        EncType ealgo=0;
        struct cavm_private_info *info;
        skb_push(skb, sizeof(struct ipv6hdr));
        info = x->data;
#ifdef MC2
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,27))
	spin_lock_bh(&x->lock);
#endif
        if(info->bundle_state)
                switch(info->bundle_state->props.ealgo){
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
                        default :
                                ealgo = NO_CYPHER;
                }
#endif
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
	return err;
}

static void cav_ah6_err(struct sk_buff *skb, struct inet6_skb_parm *opt,
		    u8 type, u8 code, int offset, __be32 info)
{
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,31))
	struct net *net = dev_net(skb->dev);
#endif
	struct ipv6hdr *iph = (struct ipv6hdr*)skb->data;
	struct ip_auth_hdr *ah = (struct ip_auth_hdr*)(skb->data+offset);
	struct xfrm_state *x;

	if (type != ICMPV6_DEST_UNREACH &&
	    type != ICMPV6_PKT_TOOBIG)
		return;

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,31))
	x = xfrm_state_lookup(net, (xfrm_address_t *)&iph->daddr, ah->spi, IPPROTO_AH, AF_INET6);
#else
	x = xfrm_state_lookup((xfrm_address_t *)&iph->daddr, ah->spi, IPPROTO_AH, AF_INET6);
#endif
	if (!x)
		return;

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,31))
	NETDEBUG(KERN_DEBUG "pmtu discovery on SA AH/%08x/%pI6\n",
		 ntohl(ah->spi), &iph->daddr);
#else
	NETDEBUG(KERN_DEBUG "pmtu discovery on SA AH/%08x/%pI6\n",
		 ntohl(ah->spi), NIP6(iph->daddr));
#endif

	xfrm_state_put(x);
}

static int cav_ah6_init_state(struct xfrm_state *x)
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

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,27))
	x->props.header_len = XFRM_ALIGN8(sizeof(struct ip_auth_hdr) + MAX_AH_AUTH_LEN);
#else
	x->props.header_len = XFRM_ALIGN8(sizeof(struct ipv6_auth_hdr) + MAX_AH_AUTH_LEN);
#endif
	if (x->props.mode == XFRM_MODE_TUNNEL)
		x->props.header_len += sizeof(struct ipv6hdr);
	x->data = info;

	return 0;

error:
	return -EINVAL;
}

static void cav_ah6_destroy(struct xfrm_state *x)
{
        struct cavm_private_info *info = x->data;

	if (!info)
		return;

	kfree(info);
}

static struct xfrm_type cav_ah6_type =
{
	.description	= "AH6",
	.owner		= THIS_MODULE,
	.proto	     	= IPPROTO_AH,
	.init_state	= cav_ah6_init_state,
	.destructor	= cav_ah6_destroy,
	.input		= cav_ah6_input,
	.output		= cav_ah6_output,
	.hdr_offset	= xfrm6_find_1stfragopt,
};

static struct inet6_protocol cav_ah6_protocol = {
	.handler	=	xfrm6_rcv,
	.err_handler	=	cav_ah6_err,
	.flags		=	INET6_PROTO_NOPOLICY,
};
int cavium_register_ah6(void) 
{
	if (xfrm_register_type(&cav_ah6_type, AF_INET6) < 0) {
		printk(KERN_INFO "ipv6 ah init: can't add xfrm type\n");
		return -EAGAIN;
	}

	if (inet6_add_protocol(&cav_ah6_protocol, IPPROTO_AH) < 0) {
		printk(KERN_INFO "ipv6 ah init: can't add protocol\n");
		xfrm_unregister_type(&cav_ah6_type, AF_INET6);
		return -EAGAIN;
	}
	return 0;
}
void cavium_unregister_ah6(void)
{
	if (inet6_del_protocol(&cav_ah6_protocol, IPPROTO_AH) < 0)
		printk(KERN_INFO "ipv6 ah close: can't remove protocol\n");

	if (xfrm_unregister_type(&cav_ah6_type, AF_INET6) < 0)
		printk(KERN_INFO "ipv6 ah close: can't remove xfrm type\n");
}
