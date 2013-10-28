/*
 * copyright (c) 2003-2005 cavium networks (support@cavium.com). all rights 
 * reserved.
 * 
 * redistribution and use in source and binary forms, with or without 
 * modification, are permitted provided that the following conditions are met:
 * 
 * 1. redistributions of source code must retain the above copyright notice, 
 * this list of conditions and the following disclaimer.
 * 
 * 2. redistributions in binary form must reproduce the above copyright notice, 
 *    this list of conditions and the following disclaimer in the documentation 
 *    and/or other materials provided with the distribution.
 * 
 * 3. all advertising materials mentioning features or use of this software 
 *    must display the following acknowledgement:
 * 
 *   this product includes software developed by cavium networks
 * 
 * 4. cavium networks' name may not be used to endorse or promote products 
 *    derived from this software without specific prior written permission.
 * 
 * 5. user agrees to enable and utilize only the features and performance 
 *    purchased on the target hardware.
 * 
 * this software,including technical data,may be subject to u.s. export control 
 * laws, including the u.s. export administration act and its associated 
 * regulations, and may be subject to export or import regulations in other 
 * countries.you warrant that you will comply strictly in all respects with all 
 * such regulations and acknowledge that you have the responsibility to obtain 
 * licenses to export, re-export or import the software.

 * to the maximum extent permitted by law, the software is provided "as is" and 
 * with all faults and cavium makes no promises, representations or warranties, 
 * either express,implied,statutory, or otherwise, with respect to the software,
 * including its condition,its conformity to any representation or description, 
 * or the existence of any latent or patent defects, and cavium specifically 
 * disclaims all implied (if any) warranties of title, merchantability, 
 * noninfringement,fitness for a particular purpose,lack of viruses, accuracy or
 * completeness, quiet enjoyment, quiet possession or correspondence to 
 * description. the entire risk arising out of use or performance of the 
 * software lies with you.
 *
 */

#ifndef __SPEED_IPSEC_H__


#define ESP_HEADER_LEN      8
#define AH_HEADER_LEN       12
#define AES_IV_LEN          16
#define DES_IV_LEN          8
#define AUTH_DATA_LEN       12 
#define CONDITION_CODE_LEN  8

#define	err(_x, ...)		fprintf (stderr, _x, ## __VA_ARGS__)

#define CALC_LEN(len,hlen,aes,auth) \
           (len+hlen+8+(aes?16:8)+(auth?12:0)+8)

#define REV_ROUND16(val) ((val|0x00000000F)-15)

#define REV_ROUND8(val) ((val|0x000000007)-7)

#define RLEN_OUTBOUND_ESP_PACKET(buflen, iphdr_len, template_len, aes, auth) \
        (template_len +\
        (iphdr_len)+ \
        ESP_HEADER_LEN+ \
        ((aes) ? AES_IV_LEN : DES_IV_LEN)+ \
       ((aes) ? ROUNDUP16((buflen) - iphdr_len + 2) : ROUNDUP8((buflen) - iphdr_len + 2))+ \
        ((auth) ? AUTH_DATA_LEN : 0))

#define RLEN_OUTBOUND_AH_PACKET(pkt_len, template_len, iphdr_len) \
        ((pkt_len)+ \
		template_len + \
        (iphdr_len)+ \
        AH_HEADER_LEN+ \
        AUTH_DATA_LEN)

#define OP_WRITE_OUTBOUND_IPSEC_SA		0x4014
#define OP_WRITE_INBOUND_IPSEC_SA		0x2014

#define MAX_DATA_SIZE 5000

#define MAX_PENDING 10 
#define MAX_TO_POLL 5 

/* Structure to hold the request staus */
typedef struct {
    Uint32 reqId;
    Uint32 status;
    Uint64 outlen;
    Uint8 output[MAX_DATA_SIZE];
} PendingBuffer;


int SpeedProcessOutbound (
		Uint16 size, 
		Uint16 param, 
		Uint16 dlen,
		n1_scatter_buffer *inv,
		n1_scatter_buffer *outv, 
		int rlen,
		Uint64 ctx,
		int response_order, 
		int req_queue,
		int dir,
		Uint32 *req_id
#ifdef CAVIUM_MULTICARD_API
		,Uint32 device_id
#endif
		);

Uint32
SpeedWriteIpsecSa(
	IpsecProto proto, 
	Version inner_version, 
	Version outer_version, 
	IpsecMode mode,
	Direction dir, 
	EncType cypher, 
	Uint8 *e_key, 
	AuthType auth,
	Uint8 *a_key, 
	Uint8 template[40], 
	Uint32 spi, 
	Uint8 copy_df,
	Uint8 udp_encap, 
	Uint64 ctx, 
	Uint64 next_ctx, 
	Uint32 *in_buffer, 
	Uint32 *out_buffer, 
	int res_order,
	int req_queue
#ifdef CAVIUM_MULTICARD_API
	,Uint32 device_id
#endif
	);

int SpeedDoOutbound (
		int8_t proto, 
		Uint32 datalen, 
		int8_t mode, 
		int8_t enc, 
		int8_t auth,
		int dir,
		int time);
#endif
