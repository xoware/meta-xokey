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
#ifndef _IPSEC_ENGINE_H
#define _IPSEC_ENGINE_H

#include "cavium_common.h"
#include "cavium_ipsec.h"
/*
extern int cavium_process_outbound_packet(struct sk_buff *skb_from,
                  unsigned long seq,
              IpsecMode mode,
                         EncType enc,
              Uint64 ctx, 
              void(*post_xmit_cb)(int ,void *, void *));
*/
extern int cavium_process_outbound_packet(struct sk_buff *skb_from,
			void *x,
                  unsigned long seq,
              IpsecMode mode,
                         EncType enc,
							AuthType auth,	
              Uint64 ctx, 
              void(*post_xmit_cb)(int ,void *));

extern int cavium_process_inbound_packet(struct sk_buff *skb_from,
void *x, struct xfrm_encap_tmpl *decap,IpsecMode mode,
              EncType enc, /* Added parameter for AES handling *NG*/
              Uint64 ctx, /* Changed *NG*/
              void(*post_rcv_cb)(int ,void *, void *));
extern void cavium_post_rcv_processing(int status, void *p_skb, void *p_x);
extern void cavium_post_xmit_processing(int status, void *p_skb);

typedef enum { WRITE_SA=0, INBOUND_PROCESSING=1, OUTBOUND_PROCESSING=2,DELETE_SA=3} EngineRequestType;

typedef struct 
{
	EngineRequestType req_type;
	Uint8 *in_buffer;
	Uint32 in_buffer_len;
	Uint8 *out_buffer;
	Uint32 out_buffer_len;
	void *data;
    n1_request_buffer *n1_buf;
}Csp1EngineRequest; 

struct cavium_xfrm {
	int version;
	xfrm_address_t dstaddr;
	struct xfrm_state *xfrm;
}; 

typedef struct
{
	void *skb_to;
	void *skb_from;
	void *x;
	void (*post_rcv_cb)(int ,void *, void *);
}Csp1InboundPostData;

typedef struct
{
	void *skb_to;
	void *skb_from;
	void (*post_xmit_cb)(int, void * /*, void * */);
}Csp1OutboundPostData;


/* Cavium common callback function */
extern void cavium_cb(int status, void *data);


#endif /*IPSEC_ENGINE_H*/


