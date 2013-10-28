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
/* 
 * cavium_ipsec.h
 */


#ifndef _CAVIUM_IPSEC_H_
#define _CAVIUM_IPSEC_H_


/*
 * IPSEC and IKE enumerated constants 
 */
#if 0
typedef enum {TRANSPORT=0, TUNNEL=1} IpsecMode;
typedef enum {AH=0, ESP=1} IpsecProto;
typedef enum {IPV4=0, IPV6=1} Version;
#ifdef MC2
typedef enum {NO_CYPHER=0,DES3CBC=2,AES128CBC=3,AES192CBC=4,AES256CBC=5,DESCBC=1} EncType;
#else
typedef enum {NO_CYPHER=0,DES3CBC=1,AES128CBC=2,AES192CBC=3,AES256CBC=4,DESCBC=9} EncType;
#endif
typedef enum {NO_AUTH=0, MD5HMAC96=1, SHA1HMAC96=2} AuthType;
typedef enum {NO_ERROR=0, LENGTH_INCORRECT=1, MODE_INCORRECT=2, PROTOCOL_INCORRECT=3,
        AUTH_INCORRECT=4, PADDING_INCORRECT=5} IpsecError;
typedef enum {INBOUND = 0, OUTBOUND = 1} Direction;
#endif

enum {
ERR_BAD_PACKET_LENGTH=128,
ERR_BAD_IPSEC_MODE,
ERR_BAD_IPSEC_PROTOCOL,
ERR_BAD_IPSEC_AUTHENTICATION,
ERR_BAD_IPSEC_PADDING,
ERR_BAD_IP_VERSION,
ERR_BAD_IPSEC_AUTH_TYPE,
ERR_BAD_IPSEC_ENCRYPT_TYPE,
ERR_BAD_IKE_DH_GROUP,
ERR_BAD_MODLENGTH,
};


#define IPV4_HEADER_LEN			20
#define IPV6_HEADER_LEN			40
#define ESP_HEADER_LEN			8
#define AH_HEADER_LEN			12
#define DES_IV_LEN				8
#define AUTH_DATA_LEN			12
#define CONDITION_CODE_LEN		8
#define AES_IV_LEN				16
#define PACKET_LEN_LEN			8

#if 0
#define IPSEC_DIRECTION_SHIFT 1
#define IPSEC_VERSION_SHIFT 2
#define IPSEC_MODE_SHIFT 3
#define IPSEC_PROT_SHIFT 4
#define IPSEC_AUTH_SHIFT 5
#define IPSEC_CIPHER_SHIFT 8
#define IPSEC_DF_SHIFT 12
#define IPSEC_UDP_SHIFT 13
#endif


/*
 * opcodes
 */
#define OP_IPSEC_PACKET_INBOUND                 0x10
#define OP_IPSEC_PACKET_OUTBOUND                0x11
#define OP_WRITE_IPSEC_SA                         0x14
#define OP_ERASE_CONTEXT                          0x114


/* 
 * IPSEC sa or context 
 *
 * Expected response length
 */
#define RLEN_NEW_SA			8
#define DLEN_NEW_MANUAL_SA		sizeof(struct _IpsecSa)
#define DLEN_NEW_MANUAL_CTX		128

typedef struct _IpsecSa
{
        Uint16 control;
	Uint16 reserved; 
	Uint32 spi; 
        Uint8 eKey[32];
	Uint8 aKey[48];
	Uint8 template[40];
}IpsecSa;

#ifndef CSP1_KERNEL
extern Uint32 Csp1IpsecAlloc(Uint64 *context_handle);
extern Uint32 Csp1IpsecFree(Uint64 context_handle);
#if 0
extern Uint32 Csp1WriteIpsecSa(
        IpsecProto proto,
        Version version,
        IpsecMode mode,
        EncType enc,
        Uint8* e_key,
        AuthType auth,
        Uint8* a_key ,
        Uint8* template,
        Uint32 spi,
        Uint64 handle);
#endif 
#endif /* CSP1_KERNEL */
/*
 * In bound ipNip RLEN
 */
#ifdef MC2
#define RLEN_INBOUND_ESP_IPNIP(pkt_len,aes,auth) \
        ((pkt_len)- \
        ESP_HEADER_LEN- \
        ((aes)?AES_IV_LEN:DES_IV_LEN)- \
        2- \
        ((auth)?AUTH_DATA_LEN:0)) + 8 + \
        CONDITION_CODE_LEN
#else
#define RLEN_INBOUND_ESP_IPNIP(pkt_len,aes,auth) \
        ROUNDUP8((pkt_len)- \
        ESP_HEADER_LEN- \
        ((aes)?AES_IV_LEN:DES_IV_LEN)- \
        2- \
        ((auth)?AUTH_DATA_LEN:0)) + \
        CONDITION_CODE_LEN
 #endif
#ifdef MC2
#define RLEN_INBOUND_AH_IPNIP(pkt_len) \
        ((pkt_len)- \
        AH_HEADER_LEN- \
        AUTH_DATA_LEN) + 8 + \
        CONDITION_CODE_LEN
#else
#define RLEN_INBOUND_AH_IPNIP(pkt_len) \
        ROUNDUP8((pkt_len)- \
        AH_HEADER_LEN- \
        AUTH_DATA_LEN) + \
        CONDITION_CODE_LEN
#endif
 
/*
 * Out bound ipNip RLEN
 */
#ifdef MC2
#define RLEN_OUTBOUND_ESP_IPNIP(pkt_len,pad_len,aes,auth) \
        ((pkt_len)+2+ \
        ESP_HEADER_LEN+ \
        ((aes) ? 16 : 8)+ \
        ((aes) ? AES_IV_LEN : DES_IV_LEN)+ \
        ((aes) ? 16*(pad_len) : 8*(pad_len))+ \
        ((auth) ? AUTH_DATA_LEN : 0)) + 8 +\
        CONDITION_CODE_LEN
#else
#define RLEN_OUTBOUND_ESP_IPNIP(pkt_len,pad_len,aes,auth) \
        ROUNDUP8((pkt_len)+2+ \
        ESP_HEADER_LEN+ \
        ((aes) ? 16 : 8)+ \
        ((aes) ? AES_IV_LEN : DES_IV_LEN)+ \
        ((aes) ? 16*(pad_len) : 8*(pad_len))+ \
        ((auth) ? AUTH_DATA_LEN : 0)) + \
        CONDITION_CODE_LEN
#endif
#ifdef MC2 
#define RLEN_OUTBOUND_AH_IPNIP(pkt_len) \
        ((pkt_len)+ \
        AH_HEADER_LEN+ \
        AUTH_DATA_LEN) + 8 + \
        CONDITION_CODE_LEN
#else
#define RLEN_OUTBOUND_AH_IPNIP(pkt_len) \
        ROUNDUP8((pkt_len)+ \
        AH_HEADER_LEN+ \
        AUTH_DATA_LEN) + \
        CONDITION_CODE_LEN
#endif

/*
 * In bound IpPacket RLEN
 */

#ifdef MC2
#define RLEN_INBOUND_ESP_PACKET(pkt_len,iphdr_len,aes,auth) \
        ((pkt_len)- \
        ESP_HEADER_LEN- \
        (iphdr_len)- \
        ((aes)?AES_IV_LEN:DES_IV_LEN)- \
        ((auth)?AUTH_DATA_LEN:0)) + 8 + \
        CONDITION_CODE_LEN
#else 
#define RLEN_INBOUND_ESP_PACKET(pkt_len,iphdr_len,aes,auth) \
        ROUNDUP8((pkt_len)- \
        ESP_HEADER_LEN- \
        (iphdr_len)- \
        ((aes)?AES_IV_LEN:DES_IV_LEN)- \
        ((auth)?AUTH_DATA_LEN:0)) + \
        CONDITION_CODE_LEN
#endif 
 
#ifdef MC2
#define RLEN_INBOUND_AH_PACKET(pkt_len,iphdr_len,exthdr_len) \
        ((pkt_len)- \
        (iphdr_len)- \
        (exthdr_len)- \
        AH_HEADER_LEN- \
        AUTH_DATA_LEN) + 8 +\
        CONDITION_CODE_LEN
#else
#define RLEN_INBOUND_AH_PACKET(pkt_len,iphdr_len,exthdr_len) \
        ROUNDUP8((pkt_len)- \
        (iphdr_len)- \
        (exthdr_len)- \
        AH_HEADER_LEN- \
        AUTH_DATA_LEN) + \
        CONDITION_CODE_LEN
#endif

/*
 * Out bound IpPacket RLEN
 */
#ifdef MC2
#define RLEN_OUTBOUND_ESP_PACKET(pkt_len,iphdr_len,template_len,aes,auth) \
        (template_len +\
        (iphdr_len)+ \
        ESP_HEADER_LEN+ \
        ((aes) ? AES_IV_LEN : DES_IV_LEN)+ \
	    ((aes) ? ROUNDUP16((pkt_len) - iphdr_len + 2) : ROUNDUP8((pkt_len) - iphdr_len + 2))+ \
        ((auth) ? AUTH_DATA_LEN : 0))+ \
        CONDITION_CODE_LEN
#else
#define RLEN_OUTBOUND_ESP_PACKET(pkt_len,iphdr_len,template_len,aes,auth) \
        ROUNDUP8(template_len +\
        (iphdr_len)+ \
        ESP_HEADER_LEN+ \
        ((aes) ? AES_IV_LEN : DES_IV_LEN)+ \
	    ((aes) ? ROUNDUP16((pkt_len) - iphdr_len + 2) : ROUNDUP8((pkt_len) - iphdr_len + 2))+ \
        ((auth) ? AUTH_DATA_LEN : 0))+ \
        CONDITION_CODE_LEN
#endif

#ifdef MC2
#define RLEN_OUTBOUND_AH_PACKET(pkt_len,iphdr_len,exthdr_len) \
        ((pkt_len)+ \
        (iphdr_len)+ \
        (exthdr_len)+ \
        AH_HEADER_LEN+ \
        AUTH_DATA_LEN) + \
        CONDITION_CODE_LEN
#else
#define RLEN_OUTBOUND_AH_PACKET(pkt_len,iphdr_len,exthdr_len) \
        ROUNDUP8((pkt_len)+ \
        (iphdr_len)+ \
        (exthdr_len)+ \
        AH_HEADER_LEN+ \
        AUTH_DATA_LEN) + \
        CONDITION_CODE_LEN
#endif

//used in xfrm private data
struct cavm_private_info {
        long long context;
#ifdef MC2
        long long next_context;
        struct xfrm_state *bundle_state;
        int bundle;
#endif
        char xfrm_used;
        char supported;
};

#endif /* _CAVIUM_IPSEC_H_ */



