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

#include <linux/list.h>
#include <linux/workqueue.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/fs.h>
#include <net/xfrm.h>


#include <linux/udp.h>
#include "cavium_common.h"
#include "cavium_ipsec.h"
#include "ipsec_engine.h"
#include "cavium_kernel.h"
#include <linux/ipv6.h>
#include <net/ipv6.h>
#include <net/addrconf.h>
#include <linux/version.h>

extern int cavium_register_ah4(void);
extern int cavium_register_esp4(void);
extern int cavium_register_ah6(void);
extern int cavium_register_esp6(void);
extern void cavium_unregister_ah4(void);
extern void cavium_unregister_esp4(void);
extern void cavium_unregister_ah6(void);
extern void cavium_unregister_esp6(void);
#ifdef MC2
extern Uint32 Csp1WriteIpsecSa(
	IpsecProto proto,
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
	void *cb_data);
#else
extern Uint32 Csp1WriteIpsecSa(
	IpsecProto proto,
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
	void *cb_data);
#endif
extern int check_valid_x(struct cavium_xfrm *cav_x);

static struct xfrm_state *global_xfrm;
static int bundle_ok(struct xfrm_state *entry, int count, void* data)
{
	struct xfrm_state *x = data;
	struct cavm_private_info *info = entry->data;
	struct in6_addr inet6;
	int dir, dir1, temp=1;

printk(KERN_CRIT "***************############Inside bundle_ok\n");//Pradeep
	if(x->props.family == AF_INET)
	{
		if(inet_addr_type(&init_net, x->id.daddr.a4) == RTN_LOCAL )
			dir = 0;
		else
			dir = 1;
		if(inet_addr_type(&init_net, entry->id.daddr.a4) == RTN_LOCAL )
			dir1 = 0;
		else
			dir1 = 1;
		if (entry->props.family == AF_INET &&
			x->id.daddr.a4 == entry->id.daddr.a4 &&
			x->props.saddr.a4 == entry->props.saddr.a4 &&
			(!(x->props.mode && entry->props.mode)) && dir == dir1)
		{
			if((entry == x) || (entry->km.state != XFRM_STATE_VALID) || (entry->km.dying))
				return 0;
#ifdef MC2
			if(info->bundle)
				return 0;
#endif
			global_xfrm = entry;
			return 1;
		}
	}
	else if(x->props.family == AF_INET6)
	{
		ipv6_addr_copy((struct in6_addr *)&inet6,(struct in6_addr *)x->id.daddr.a6);
		if(ipv6_chk_addr(&init_net, &inet6, NULL ,0)) 
			dir = 0;
		else
			dir = 1;
		ipv6_addr_copy((struct in6_addr *)&inet6,(struct in6_addr *)entry->id.daddr.a6);
		if(ipv6_chk_addr(&init_net, &inet6, NULL ,0)) 
			dir1 = 0;
		else
			dir1 = 1;

		if(memcmp(x->id.daddr.a6,entry->id.daddr.a6,16) !=0 || 
			memcmp(x->props.saddr.a6,entry->props.saddr.a6,16) !=0)
			temp=0;

		if (entry->props.family == AF_INET6 && temp &&
			(!(x->props.mode && entry->props.mode)) && dir == dir1)
		{
			if((entry == x) || (entry->km.state != XFRM_STATE_VALID) || (entry->km.dying))
				return 0;
#ifdef MC2
			if(info->bundle)
				return 0;
#endif
			global_xfrm = entry;
			return 1;
		}
	}
	return 0;
}

struct xfrm_state * cavium_find_bundle(struct xfrm_state *x1, Uint8 dir)
{
        /* check daddr, saddr, mode, direction  */
	int ret;
	u8 bundle_proto;
	struct xfrm_state_walk walk;
	
	bundle_proto = (x1->id.proto == IPPROTO_AH)? IPPROTO_ESP:IPPROTO_AH;
#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,6,31))
	walk.state = NULL;
	walk.count = 0;
	walk.proto = bundle_proto;
#else
	xfrm_state_walk_init(&walk, bundle_proto);	
#endif
	global_xfrm = NULL; 
#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,6,31))
	ret = xfrm_state_walk(&walk, &bundle_ok, x1);
	if (walk.state)
		__xfrm_state_put(walk.state);
#else
	ret = xfrm_state_walk(&init_net, &walk, &bundle_ok, x1);
	xfrm_state_walk_done(&walk);
#endif
	return global_xfrm;
}


int cavium_sa_put(struct xfrm_state *x, Uint8 alloc_context)
{
	int error = 0,dir,proto = 1;
	Uint8 *in_buffer=NULL, *out_buffer=NULL, ekey[32], *template;
	struct iphdr *ipv4_hdr = NULL;
	struct udphdr *udp_hdr = NULL;
	Csp1EngineRequest *csp1_request = NULL;
	struct cavium_xfrm *cav_x = NULL;
	struct cavm_private_info *info;
	
	/* Set the udp_encap variable to 1 in this function */
	Uint8 copy_df = 1, udp_encap = 0;
	
	/* Set the data pointer to point to xfrm_state structure */
	AuthType aalgo;
	EncType ealgo;
	int try_count = 1;
	Version version = 0;
#if defined (CONFIG_IPV6) || defined (CONFIG_IPV6_MODULE)
	struct ipv6hdr *ip6hdr;
	struct in6_addr ip6_addr;
	int addr_type, iface;
#endif

	info = x->data;
	if(!x) {
		printk( KERN_ERR "cavium_sa_put: null pointer passed in \n ");
		return -ENODATA;
	}

        /* check for UDP encapsulation and set udp_encap flag accordingly */
	if(x->encap && (x->encap->encap_type == 2))
		udp_encap = 1;
#if defined(CONFIG_IPV6) || defined (CONFIG_IPV6_MODULE)
	if(x->props.family == AF_INET6){
		version = 1;
		ipv6_addr_copy((struct in6_addr *)&ip6_addr,(struct in6_addr *)x->id.daddr.a6);
	}
#endif
        /* Set the direction in the variable dir */
	if(!version){
		if(inet_addr_type(&init_net, x->id.daddr.a4) == RTN_LOCAL )
			dir = 0; /* INBOUND */
		else
			dir = 1;
	}
#if defined(CONFIG_IPV6) || defined (CONFIG_IPV6_MODULE)
	else {
		addr_type = ipv6_addr_type(&ip6_addr);
		iface = ipv6_chk_addr(&init_net, &ip6_addr, NULL ,0);
		if(iface)
			dir = 0;
		else
			dir = 1;
	}
#endif

        /* Set the protocol field */
	if(x->id.proto == 50)
		proto = 1 ; /* ESP */
	else if(x->id.proto == 51)
		proto = 0 ; /* AH */

	/* Allocate Context */
	
	if(alloc_context)
		info->context = Csp1AllocContext();
	if(!info->context)
	{
		printk(KERN_CRIT " cavium_sa_put: got NULL context \n");
		error = -1;
		goto donotwritesa;
	}
	
	/* Allocate memory of 256 bytes to the in_buffer */
	
	in_buffer = (Uint8 *)kmalloc(IPSEC_CONTEXT_SIZE, GFP_ATOMIC);
	if(in_buffer == NULL)
	{
		printk(KERN_CRIT "cavium_sa_put: Not enough memory in allocating in_buffer \n");
		error = -1 ;
		goto donotwritesa;
	}
	memset(in_buffer, 0, IPSEC_CONTEXT_SIZE);
	
	/* Allocate memory of 8 bytes to the out_buffer */
	
	out_buffer = (Uint8 *)kmalloc(8+8, GFP_ATOMIC);
	if(out_buffer == NULL)
	{
		printk( KERN_CRIT "cavium_sa_put: Not enough memory in allocating out_buffer \n");
		error = -1;
		goto donotwritesa;
	}
	
	/* Allocate memory to the Csp1_request variable */
	csp1_request = (Csp1EngineRequest *)kmalloc(sizeof(Csp1EngineRequest),GFP_ATOMIC);
	if(csp1_request == NULL)
	{
		printk(KERN_CRIT "cavium_sa_put: Not enough memory in allocating csp1_request \n");
		error = -1;
		goto donotwritesa;
	}
	
	cav_x = (struct cavium_xfrm *)kmalloc(sizeof(struct cavium_xfrm), GFP_ATOMIC);
	if(cav_x == NULL)
	{
		printk(KERN_CRIT "cavium_sa_put: Not enough memory in allocating cavium xfrm \n");
		error = -1;
		goto donotwritesa;
	}
	if(!version){
#ifdef MC2
		ipv4_hdr = (struct iphdr *)&in_buffer[88];
		if(x->encap && (x->encap->encap_type == 2))
		{
			udp_hdr = (struct udphdr *)&in_buffer[108];
			udp_hdr->source = x->encap->encap_sport;
			udp_hdr->dest = x->encap->encap_dport;
		}
#else
		ipv4_hdr = (struct iphdr *)&in_buffer[64];
#endif
		/* Now fill the template */
		ipv4_hdr->version = 4;
		ipv4_hdr->ihl = 5;
		ipv4_hdr->ttl = 64;
		
		if(x->encap && (x->encap->encap_type == 2))
			ipv4_hdr->protocol = 0x11;
		else
			ipv4_hdr->protocol = x->id.proto;
		ipv4_hdr->saddr = x->props.saddr.a4;
		ipv4_hdr->daddr = x->id.daddr.a4;
		template = (Uint8 *)ipv4_hdr;
	}
#if defined(CONFIG_IPV6) || defined (CONFIG_IPV6_MODULE)
	else{
		ip6hdr = (struct ipv6hdr *)&in_buffer[128];
		ip6hdr->version = 6;
		ip6hdr->hop_limit = 64;
		if(proto)
			ip6hdr->nexthdr = IPPROTO_ESP;
		else
			ip6hdr->nexthdr = IPPROTO_AH;
		memcpy(ip6hdr->saddr.s6_addr32,x->props.saddr.a6,16);
		memcpy(ip6hdr->daddr.s6_addr32,x->id.daddr.a6,16);
		template = (Uint8 *)ip6hdr;
	}
#endif

	/* Populate csp1_request structure */
	csp1_request->req_type = WRITE_SA;
	csp1_request->in_buffer = in_buffer;
	csp1_request->in_buffer_len = 256;
	csp1_request->out_buffer = out_buffer;
	csp1_request->out_buffer_len = 256;
	cav_x->version = version;
	memcpy(&(cav_x->dstaddr), &(x->id.daddr),sizeof(xfrm_address_t));
	switch(x->props.ealgo)
	{
		case SADB_EALG_DESCBC:
			ealgo = DESCBC;
			break;
		case SADB_EALG_3DESCBC:
			ealgo = DES3CBC;
			break;
#ifdef MC2
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
#else
		case SADB_X_EALG_AESCBC:
#endif
		default:
			ealgo = NO_CYPHER;
			break;
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
	if(!sizeof(x->ealg->alg_key))
		memset(ekey,0,32);
	else
		memcpy(ekey,x->ealg->alg_key,sizeof(x->ealg->alg_key));
	cav_x->xfrm = x;
	csp1_request->data = (void *)cav_x;
try_again:
#ifdef MC2
	error = Csp1WriteIpsecSa(
			proto,
			version,
			x->props.mode,
			dir,
			ealgo,
			x->ealg->alg_key,
			aalgo,
			x->aalg->alg_key,
			template,
			x->id.spi,
			copy_df,
			udp_encap,
			info->context,
			info->next_context,
			(Uint32 *)in_buffer,
			(Uint32 *)(((unsigned long)out_buffer &~0x7)+8),
			cavium_cb,
			(void *)csp1_request
			);
#else
	error = Csp1WriteIpsecSa(
	                proto,
	                0,/* IPV4 */
	                x->props.mode,
	                dir,
	                ealgo,
	                x->ealg->alg_key,
	                aalgo,
	                x->aalg->alg_key,
	                (Uint8 *)ipv4_hdr,
	                x->id.spi,
	                copy_df,
	                udp_encap,
	                info->context,
	                (Uint32 *)in_buffer,
	                (Uint32 *)(((unsigned long)out_buffer & ~0x7) + 8),
	                cavium_cb,
	                (void *)csp1_request
	                );
#endif
	if(error > 0)
		error = 0;
	if(error < 0 )
	{
		if(try_count++ < 5)
			goto try_again;
		else
		{
			printk(KERN_CRIT "Csp1WriteIpsecSa failed \n");
			if (!check_valid_x(cav_x)) {
				info = cav_x->xfrm->data;
#ifdef MC2
				if(info->bundle_state)
					xfrm_state_delete(info->bundle_state);
#endif
				xfrm_state_delete(cav_x->xfrm);
			}
			return error;
		}
	}
	if(x->km.state == XFRM_STATE_ACQ){
		x->km.state = XFRM_STATE_VALID;
	}
	return  error;

donotwritesa:
	if(csp1_request)
		kfree(csp1_request);
	if(cav_x)
		kfree(cav_x);
	if(in_buffer)
		kfree(in_buffer);
	if(out_buffer)
		kfree(out_buffer);
	return error;
}

void cavium_xfrm_state_insert(struct xfrm_state *x)
{
	struct cavm_private_info *info, *bundle_info;
#ifdef MC2
	Uint8  dir;
	Uint8  version=0;
	struct xfrm_state *x1=NULL;
	int defered_write = 0;
#endif
	int  alloc_context = 1;
#if defined(CONFIG_IPV6) || defined(CONFIG_IPV6_MODULE)
#ifdef MC2
	struct in6_addr ip6_addr;
#endif
#endif
	x->km.state = XFRM_STATE_ACQ;
#ifdef MC2
#if defined (CONFIG_IPV6) || defined(CONFIG_IPV6_MODULE)
	if(x->props.family == AF_INET6){
		ipv6_addr_copy((struct in6_addr *)&ip6_addr,(struct in6_addr *)x->id.daddr.a6);
		version = 1;
	}
#endif
	if(!version){
		if(inet_addr_type(&init_net, x->id.daddr.a4) == RTN_LOCAL )
			dir = 0 ; /* INBOUND */
		else
			dir = 1 ; /* OUTBOUND */
	}
#if defined (CONFIG_IPV6) || defined(CONFIG_IPV6_MODULE)
	else {
		if(ipv6_chk_addr(&init_net, &ip6_addr, NULL ,0))
			dir = 0 ; /* INBOUND */
		else
			dir = 1 ; /* OUTBOUND */
	}
#endif
	info = x->data;
	x1 = cavium_find_bundle(x, dir);
	info->next_context = 0ll;
	info->bundle_state= NULL;
	info->bundle = 0;
	if(x1) {
		/* We got bundle. we need to check whether it is inbound/ outbound esp/ah and update the context accordingly */
		/*
		 * check protocol field to find out ESP/AH for ESP = 50 , AH =51
		 * In case of Inbound AH->next_context = ESP->context
		 * In case of OutBound ESP->next_context = AH->context
		 */
		bundle_info = x1->data;
		if(dir) /* OUTBOUND */
		{
			if(x->id.proto == 51) /* AH */
			{
				if(!info->context)
				{
					info->context = Csp1AllocContext();
					if(!info->context)
						return;
					alloc_context= 0;
				}
				bundle_info->next_context = info->context ;
				bundle_info->bundle_state = x;
				bundle_info->bundle = 1;
				defered_write = 1;
				/*cavium_sa_put( x1, 0);*/
				info->bundle = 1;
			}
			else{   /* ESP */
				info->next_context = bundle_info->context;
				info->bundle_state = x1;
				info->bundle = 1;
				bundle_info->bundle = 1;
			}
		}
		else{  /* INBOUND  */
			if(x->id.proto == 50) { /* ESP */
				if(!info->context){
					info->context = Csp1AllocContext();
					if(!info->context)
						return;
					alloc_context = 0;
				}
				bundle_info->next_context = info->context;
				bundle_info->bundle_state = x;
				bundle_info->bundle = 1;
				defered_write = 1;
				/*cavium_sa_put(x1,0);*/
				info->bundle = 1;
			}
			else{
				info->next_context = bundle_info->context;
				info->bundle_state = x1;
				bundle_info->bundle = 1;
				info->bundle = 1;
			}
		}
	}
	if(x1){
		spin_lock_bh(&x1->lock);
		n1_flush_queue();
	}
#endif  /* MC2 */
	cavium_sa_put(x,alloc_context);
#ifdef MC2
	if(x1){
		if(defered_write)
			cavium_sa_put(x1,0);
		spin_unlock_bh(&x1->lock);
	}
#endif
}

void cavium_xfrm_state_delete(struct xfrm_state *x) 
{
#ifdef MC2
	Uint8 *out_buffer;
	Uint8 *in_buffer;
	Csp1EngineRequest *csp1_request;
	struct xfrm_state *x1=NULL;
	int version=0;
	int dir=0;
#endif
	struct cavm_private_info *info, *bundle_info=NULL;
	info = x->data;
	if(info) {
#ifdef MC2
		if(info->bundle && info->bundle_state==NULL)
		{
#if defined (CONFIG_IPV6) || defined(CONFIG_IPV6_MODULE)
			if(x->props.family == AF_INET6){
				version = 1;
			}
#endif
			if(!version) {
				if(inet_addr_type(&init_net, x->id.daddr.a4) == RTN_LOCAL )
					dir = 0 ; /* INBOUND */
				else
					dir = 1 ; /* OUTBOUND */
				x1 = cavium_find_bundle(x, dir);
				if(x1 != NULL)
					bundle_info = x1->data;
				if(x1 && bundle_info->bundle_state == x) {
					spin_lock_bh(&x1->lock);
					bundle_info->bundle_state= NULL;
					spin_unlock_bh(&x1->lock);
					n1_flush_queue();
					if(info->context) {
						csp1_request=(Csp1EngineRequest *)kmalloc(sizeof(Csp1EngineRequest),GFP_ATOMIC);
						in_buffer=(Uint8 *)kmalloc(256,GFP_ATOMIC);
						out_buffer=(Uint8 *)kmalloc(24,GFP_ATOMIC);
						if(csp1_request == NULL || in_buffer == NULL || out_buffer == NULL){
							Csp1FreeContext(info->context);
							return;
						}
						*((Uint64 *)(&(out_buffer[16]))) = info->context;
						memset(in_buffer,0x0,256);
						csp1_request->req_type = DELETE_SA;
						csp1_request->in_buffer = in_buffer;
						csp1_request->in_buffer_len = 256;
						csp1_request->out_buffer = out_buffer;
						csp1_request->out_buffer_len = 8;
						Csp1InvalidateIpsecSa(
							info->context,
							(Uint32 *)in_buffer,
							(Uint32 *)out_buffer,
							cavium_cb,
							(void *)csp1_request);
					}
				}else{
					if(info->context){
						Csp1FreeContext(info->context);
						info->context = 0x0;
					}
				}
			}else{
				if(info->context){
					Csp1FreeContext(info->context);
					info->context= 0x0;
				}
			}
		}else{
			if(info->context){
				Csp1FreeContext(info->context);
				info->context= 0x0;
			}
		}
#else
		if(info->context)
			Csp1FreeContext(info->context);
#endif
	}
}

int cavium_xfrm_state_notify(struct xfrm_state *x, struct km_event *c)
{
	switch (c->event) {
		case XFRM_MSG_EXPIRE:
			break;
		case XFRM_MSG_DELSA:
			cavium_xfrm_state_delete(x);
			break;
		case XFRM_MSG_NEWSA:
		case XFRM_MSG_UPDSA:
			cavium_xfrm_state_insert(x); 
			break;
		case XFRM_MSG_FLUSHSA:
		case XFRM_MSG_NEWAE: /* not yet supported */
			break;
		default:
			printk("pfkey: Unknown SA event %d\n", c->event);
			break;
	}
	return 0;
}
static int cavium_xfrm_state_acquire(struct xfrm_state *x, struct xfrm_tmpl *t, struct xfrm_policy *xp, int dir) 
{
	return 0;
}
static struct xfrm_policy *cavium_compile_policy(struct sock *sk, int opt,
						u8 *data, int len, int *dir) 
{
	return NULL;
}
static int cavium_send_new_mapping(struct xfrm_state *x, xfrm_address_t *ipaddr, __be16 sport)
{
	return 0;
}
static int cavium_send_policy_notify(struct xfrm_policy *xp, int dir, struct km_event *c)
{
	return 0;
}
static int cavium_send_migrate(struct xfrm_selector *sel, u8 dir, u8 type,
			      struct xfrm_migrate *m, int num_bundles
				  #if (LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,31))
				  , struct xfrm_kmaddress *k
				  #endif
				  )
{
	return 0;
}
static struct  xfrm_mgr cavium_km= {
	.id		= "cavium_km",
	.notify		= cavium_xfrm_state_notify,
	.acquire	= cavium_xfrm_state_acquire,
	.compile_policy	= cavium_compile_policy,
	.new_mapping	= cavium_send_new_mapping,
	.notify_policy	= cavium_send_policy_notify,
	.migrate	= cavium_send_migrate,
};

int cavium_ipsec_init(void)
{
	int err;
	err = Csp1ConfigDevice(NULL);
	if(err) {
		printk(KERN_CRIT "Csp1ConfigDevice returned error %d\n",err);
		goto error;
	}
	err = xfrm_register_km(&cavium_km);
	if (err) {
		printk(KERN_CRIT "Unsuccessful km registration\n");
		goto error_config;
	}
	if (cavium_register_ah4() < 0)
		goto error_km;
	if (cavium_register_esp4() < 0)
		goto error_ah4;
	if (cavium_register_ah6() < 0)
		goto error_esp4;		
	if (cavium_register_esp6() < 0)
		goto error_ah6;
	return 0;
error_ah6:
	cavium_unregister_ah6();
error_esp4:
	cavium_unregister_esp4();
error_ah4:
	cavium_unregister_ah4();
error_km:
	xfrm_unregister_km(&cavium_km); 
error_config:
	Csp1UnconfigDevice();
error:
	return -EAGAIN;
}

void cavium_ipsec_exit(void)
{
	cavium_unregister_ah4();
	cavium_unregister_esp4();
	cavium_unregister_ah6();
	cavium_unregister_esp6();

	xfrm_unregister_km(&cavium_km); 
	Csp1UnconfigDevice();
}

module_init(cavium_ipsec_init);
module_exit(cavium_ipsec_exit);
MODULE_LICENSE("GPL");

