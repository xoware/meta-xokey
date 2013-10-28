/*! \file cavium_common.h */
/*!\page page2 API Copyright
 * \section Copyright_Api  API copyright
 * \verbatim
 * Copyright (c) 2003-2005 Cavium Networks (support@cavium.com). All rights 
 * reserved.
 * 
 * Redistribution and use in source and binary forms, with or without 
 * modification, are permitted provided that the following conditions are met:
 * 
 * 1. Redistributions of source code must retain the above copyright notice, 
 * this list of conditions and the following disclaimer.
 * 
 * 2. Redistributions in binary form must reproduce the above copyright notice, 
 *    this list of conditions and the following disclaimer in the documentation 
 *    and/or other materials provided with the distribution.
 * 
 * 3. All advertising materials mentioning features or use of this software 
 *    must display the following acknowledgement:
 * 
 *   This product includes software developed by Cavium Networks
 * 
 * 4. Cavium Networks' name may not be used to endorse or promote products 
 *    derived from this software without specific prior written permission.
 * 
 * 5. User agrees to enable and utilize only the features and performance 
 *    purchased on the target hardware.
 * 
 * This Software,including technical data,may be subject to U.S. export control 
 * laws, including the U.S. Export Administration Act and its associated 
 * regulations, and may be subject to export or import regulations in other 
 * countries.You warrant that You will comply strictly in all respects with all 
 * such regulations and acknowledge that you have the responsibility to obtain 
 * licenses to export, re-export or import the Software.

 * TO THE MAXIMUM EXTENT PERMITTED BY LAW, THE SOFTWARE IS PROVIDED "AS IS" AND 
 * WITH ALL FAULTS AND CAVIUM MAKES NO PROMISES, REPRESENTATIONS OR WARRANTIES, 
 * EITHER EXPRESS,IMPLIED,STATUTORY, OR OTHERWISE, WITH RESPECT TO THE SOFTWARE,
 * INCLUDING ITS CONDITION,ITS CONFORMITY TO ANY REPRESENTATION OR DESCRIPTION, 
 * OR THE EXISTENCE OF ANY LATENT OR PATENT DEFECTS, AND CAVIUM SPECIFICALLY 
 * DISCLAIMS ALL IMPLIED (IF ANY) WARRANTIES OF TITLE, MERCHANTABILITY, 
 * NONINFRINGEMENT,FITNESS FOR A PARTICULAR PURPOSE,LACK OF VIRUSES, ACCURACY OR
 * COMPLETENESS, QUIET ENJOYMENT, QUIET POSSESSION OR CORRESPONDENCE TO 
 * DESCRIPTION. THE ENTIRE RISK ARISING OUT OF USE OR PERFORMANCE OF THE 
 * SOFTWARE LIES WITH YOU.
 *
 * \endverbatim
 */

/*! \defgroup GP_OPS    General Purpose APIs */
/*! \defgroup SSL_OPS   SSL APIs */
/*! \defgroup IPSEC_OPS   IPSEC APIs */
/*! \defgroup MISC      Misc APIs */
#ifndef _CAVIUM_COMMON_H_
#define _CAVIUM_COMMON_H_

#ifndef CAVIUM_NO_MMAP
#define CAVIUM_NO_MMAP
#endif

#ifndef INTERRUPT_ON_COMP
#define INTERRUPT_ON_COMP
#endif

#ifndef CAVIUM_HUGE_MEMORY
#define CAVIUM_HUGE_MEMORY
#endif

#include "app_defines.h"
//#define IPSEC_SCATTER_GATHER
#define OP_IPSEC_PACKET_INBOUND                 0x10
#define OP_IPSEC_PACKET_OUTBOUND                0x11

#define N1_OPERATION_CODE   1
#define N1_ALLOC_CONTEXT   2
#define N1_FREE_CONTEXT      3
#define N1_REQUEST_STATUS   4
#define N1_ALLOC_KEYMEM         5
#define N1_FREE_KEYMEM          6
#define N1_WRITE_KEYMEM         7
#define N1_FLUSH_ALL_CODE       8
#define N1_FLUSH_CODE           9
#define N1_DEBUG_WRITE_CODE   10
#define N1_DEBUG_READ_CODE   11
#define PCI_DEBUG_WRITE_CODE   12
#define PCI_DEBUG_READ_CODE   13
#define N1_INIT_CODE      14
#define N1_SOFT_RESET_CODE   15
#define N1_API_TEST_CODE   16
#define N1_SG_OPERATION_CODE   17
#define N1_GET_RANDOM_CODE   20   
#define N1_GET_DEV_CNT       22
#define N1_GET_ALL_REQUEST_STATUS  23
#define N1_GET_DEVICE_TYPE   25  
#define N1_GET_STATUS_DDR   26  
#define N1_CORE_ASSIGNMENT   24
#define N1_GET_DRIVER_STATE 27

#define MAJOR_OP_INIT 0
#define MAJOR_OP_RANDOM_WRITE_CONTEXT 1
#define MAJOR_OP_ME_PKCS_LARGE 2
#define MAJOR_OP_RSASERVER_LARGE 3
#define MAJOR_OP_ME_PKCS 4
#define MAJOR_OP_RSASERVER 5
#define MAJOR_OP_HASH 6
#define MAJOR_OP_HMAC 7
#define MAJOR_OP_HANDSHAKE 8
#define MAJOR_OP_OTHER 10
#define MAJOR_OP_FINISHED 11
#define MAJOR_OP_RESUME 12
#define MAJOR_OP_ENCRYPT_DECRYPT_RECORD 13
#define MAJOR_OP_ENCRYPT_DECRYPT 14
#define MAJOR_OP_ACQUIRE_CORE 4

/* boot and admin codes */
#define OP_BOOT_INIT            0x0000
#define OP_BOOT_SETUP_UCODE         0x0016
#define OP_BOOT_LOAD_UCODE         0x0015
#if 0
#define OP_BOOT_IMPORT_PKCS_KEY      0x0115
#define OP_ADMIN_SETUP_UCODE      0x0016   /* ??? */
#define OP_ADMIN_GEN_RSA_KEY_PAIR   0x0016   /* ??? */
#define OP_ADMIN_SIGN            0x0017   /* ??? */
#define OP_ADMIN_LOAD_UCODE         0x0015
#define OP_ADMIN_LOGIN            0x0215
#define OP_ADMIN_LOGOUT            0x0415
#define OP_ADMIN_EXPORT_KEY_PKCS8   0x0815
#define OP_ADMIN_IMPORT_KEY_PKCS8   0x1015
#define OP_ADMIN_DELETE_KEY         0x0215
#endif /* if 0 */

/*microcode types*/
#define CODE_TYPE_MAINLINE   1
#define CODE_TYPE_BOOT      2
#define CODE_TYPE_SPECIAL   3

#define CODE_TYPE_ADMIN   CODE_TYPE_SPECIAL

#define NPX_DEVICE      0x0010
#define N1_LITE_DEVICE  0x0003
#define N1_DEVICE       0x0001

/* Driver state */
#define DRV_ST_SSL_DFL     0  /* ssl running with default cores */
#define DRV_ST_SSL_CORES   1  /* ssl running with specified number of cores */
#define DRV_ST_IPSEC_DFL   2  /* ipsec running with default cores */ 
#define DRV_ST_IPSEC_CORES 3  /* ipsec running with specified number of cores */
#define DRV_ST_SSL_IPSEC   4  /* driver running with both ssl and ipsec */
#define DRV_ST_UNKNOWN     5  

#ifndef MC2
/*! \enum HashType Sha-1 or MD-5 */
typedef enum
{ SHA1_TYPE = 0, MD5_TYPE = 1 }
HashType;
/*! \enum AesType AES128CBC AES192CBC AES256CBC*/
typedef enum
{ AES_128 = 0, AES_192 = 1, AES_256 = 2 }
AesType;
#else
/*! \enum HashType Sha-256 or Sha-1 or MD-5 */
typedef enum
{ SHA512_TYPE = 5, SHA384_TYPE = 4, SHA256_TYPE = 3, SHA1_TYPE = 2, MD5_TYPE = 1 }
HashType;
/*! \enum AesType AES128CBC AES192CBC AES256CBC*/
typedef enum
{ AES_128 = 5, AES_192 = 6, AES_256 = 7}
AesType;
#endif
/*! \enum RsaBlockType Public BT1 Private BT2*/
typedef enum
{ BT1 = 0, BT2 = 1 }
RsaBlockType;
/*! \enum ContextUpdate YES/NO*/
typedef enum
{ CAVIUM_NO_UPDATE = 0, CAVIUM_UPDATE = 1 }
ContextUpdate;

/*! \enum ContextType Context Type to allocate or deallocate */
typedef enum
{ CONTEXT_SSL = 0, CONTEXT_IPSEC = 1 , CONTEXT_ECC_P256 = 2, CONTEXT_ECC_P384 = 3}
ContextType;
/*! \enum RsaModExType Normal or Chinese Remainder Theorem */
typedef enum
{ NORMAL_MOD_EX = 0, CRT_MOD_EX = 1 }
RsaModExType;

/*! \enum KeyMaterialInput How Key Material is stored */
typedef enum
{ READ_INTERNAL_SRAM = 0, KEY_HANDLE = 0, INPUT_DATA = 1, READ_LOCAL_DDR =
    2, READ_LOCAL_HOST = 3 }
KeyMaterialInput;

/*! \enum KeyMaterialLocation Where Key Material is stored */
typedef enum {INTERNAL_SRAM = 0, HOST_MEM = 1, LOCAL_DDR = 2} KeyMaterialLocation;

/* \enum  EncryptionAlgorithmIndentifier */
typedef enum
{ PBE_MD2_DES_CBC = 0x51, PBE_MD5_DES_CBC = 0x53 }
EncryptionAlgorithmIdentifier;

/*! \enum Csp1ResponseOrder */
typedef enum
{ CAVIUM_RESPONSE_ORDERED = 0, CAVIUM_RESPONSE_UNORDERED = 1, CAVIUM_RESPONSE_REALTIME=2 }
Csp1ResponseOrder, n1_response_order;


/* Csp1RequestType Blocking or NonBlocking */
/*! \enum n1_request_type Blocking, Non-Blocking, Signal*/
typedef enum
{ CAVIUM_BLOCKING = 0, CAVIUM_NON_BLOCKING = 1, CAVIUM_SIGNAL = 2, CAVIUM_SPEED = 3 }
n1_request_type, Csp1RequestType;

/*! \enum n1_request_type Blocking or NonBlocking #Csp1RequestType */

/*! \enum Csp1DmaMode Direct or Scatter Gather*/
typedef enum
{ CAVIUM_DIRECT = 0, CAVIUM_SCATTER_GATHER = 1 }
Csp1DmaMode, n1_dma_mode, DmaMode;

/*! \enum Csp1MicrocodeType Ipsec or SSL/GP Ops*/
typedef enum
{ CAVIUM_IPSEC_MICROCODE = 0, CAVIUM_SSL_MICROCODE = 1, CAVIUM_GP_GRP = 0, CAVIUM_SSL_GRP = 1, CAVIUM_IPSEC_GRP = 2 }
Csp1MicrocodeType, Csp1Group;

/*! \enum ResultLocation Cptr or Rptr */
typedef enum
{ CONTEXT_PTR = 0, RESULT_PTR = 1 }
ResultLocation;

/*! \enum Csp1InterruptMode */
typedef enum
{ CAVIUM_NO_INTERRUPT = 0, CAVIUM_GEN_INTERRUPT = 1 }
Csp1InterruptMode;

/*! \enum Csp1SgMode */
typedef enum
{ CAVIUM_SG_READ = 0, CAVIUM_SG_WRITE = 1 }
Csp1SgMode;

/*
 * IPSEC and IKE enumerated constants 
 */
typedef enum
{ TRANSPORT = 0, TUNNEL = 1 }
IpsecMode;
typedef enum
{ AH = 0, ESP = 1 }
IpsecProto;
typedef enum
{ IPV4 = 0, IPV6 = 1 }
Version;
#ifndef MC2
typedef enum
{ NO_CYPHER = 0, DES3CBC = 1, AES128CBC = 2, AES192CBC = 3, AES256CBC =
    4, DESCBC = 9 }
EncType;
#else
typedef enum
{ NO_CYPHER = 0, DESCBC = 1, DES3CBC = 2, AES128CBC = 3, AES192CBC =
    4, AES256CBC = 5 }
EncType;
typedef enum
{ INVALID_SA = 0, VALID_SA = 1 }
ValidSa;
#endif
typedef enum
{ NO_AUTH = 0, MD5HMAC96 = 1, SHA1HMAC96 = 2 }
AuthType;
typedef enum
{ IPSEC_NO_ERROR = 0, LENGTH_INCORRECT = 1, MODE_INCORRECT = 2, PROTOCOL_INCORRECT =
    3,
  AUTH_INCORRECT = 4, PADDING_INCORRECT = 5
}
IpsecError;
typedef enum
{ INBOUND = 0, OUTBOUND = 1 } 
Direction;
typedef enum {POST_FRAG=0, PRE_FRAG=1} FragType;

#include "cavium_sysdep.h"

#ifndef ROUNDUP4
#define ROUNDUP4(val) (((val) + 3)&0xfffffffc)
#endif

#ifndef ROUNDUP8
#define ROUNDUP8(val) (((val) + 7)&0xfffffff8)
#endif

#ifndef ROUNDUP16
#define ROUNDUP16(val) (((val) + 15)&0xfffffff0)
#endif

#ifdef PORT_TO_64BIT
typedef Uint64 VOIDPTR;
typedef Uint64 UINT8PTR;
typedef Uint64 UINT16PTR;
typedef Uint64 UINT32PTR;
typedef Uint64 UINT64PTR;
typedef Uint64 CBFUNCPTR;

#define CAST_TO_X_PTR (Uint64)(ptrlong)
#define CAST_FRM_X_PTR (void *)(ptrlong)

#else
typedef void *  VOIDPTR;
typedef Uint8 * UINT8PTR;
typedef Uint16 * UINT16PTR;
typedef Uint32 * UINT32PTR;
typedef Uint64 * UINT64PTR;
typedef void (*CBFUNCPTR) (int, void *);
#define CAST_TO_X_PTR
#define CAST_FRM_X_PTR
#endif

#ifdef CSP1_KERNEL


typedef struct _cmd
{
  Uint16 opcode;
  Uint16 size;
  Uint16 param;
  Uint16 dlen;
}
Cmd;

typedef struct _Request
{
  Uint64 cmd;         /* command portion of request */
  Uint64 dptr;         /* pointer to data buffer */
  Uint64 rptr;         /* pointer to result buffer */
  Uint64 cptr;         /* pointer to context */
}
Request;

#define INVALID_CORE 255

/* Core tracking data */
typedef struct core {
   Uint8   next_id;
   Uint8   ucode_idx;
   Uint8   ready;
   Uint8   pend2048;
   int     lrsrq_idx; /* Index of last SRQ request */
   Uint32  doorbell;
   volatile Uint64  *lrcc_ptr;
   Uint8   *ctp_ptr;
   int     ctp_idx;
   int     ctp_srq_idx;
}core_t;


/* Max entries in SRQ */
#define MAX_SRQ_SIZE 1000
#define MAX_SRQ_NORMAL 900 /* 100 entries for Priority commands */
#define HIGH_PRIO_QUEUE 2

/* States of entries in SRQ */
#define SR_FREE      0
#define SR_IN_USE    1
#define SR_IN_CTP    2

/* Soft Request Queue */
typedef struct {
   cavium_spinlock_t lock;
   Uint32   head;
   Uint32   tail;
   Uint32   qsize;
   volatile Uint64   *ccptr[MAX_SRQ_SIZE];
   Uint8    state[MAX_SRQ_SIZE];
   Uint8    core_id[MAX_SRQ_SIZE];
   Request  queue[MAX_SRQ_SIZE];
} softreq_t;

#define SRAM_ADDRESS_LEN 8

struct MICROCODE
{
   Uint8 core_grp; /* core groups are used only for PX_PLUS mode. */
   Uint8 code_type;
   Uint8 *code;
   Uint32 code_size; /* in bytes*/
   Uint8 *data;     /* constants */
   Uint32 data_size; /* in bytes*/
   Uint8 sram_address[SRAM_ADDRESS_LEN];
   cavium_dmaaddr  data_dma_addr;
   Uint8 core_id;
                      /* Paired cores and software queues */
   Uint8 paired_cores;                  /* are not supported in PX_PLUS mode */
   /* Software Request Queue */
   softreq_t srq;
   /* Use count */
   int use_count;
};

#endif /* CSP1_KERNEL */

#define OP_DECRYPT         1
#ifndef MC2
#define IPSEC_DIRECTION_SHIFT 1
#define IPSEC_VERSION_SHIFT 2
#define IPSEC_MODE_SHIFT 3
#define IPSEC_PROT_SHIFT 4
#define IPSEC_AUTH_SHIFT 5
#define IPSEC_CIPHER_SHIFT 8
#define IPSEC_DF_SHIFT 12
#define IPSEC_UDP_SHIFT 13
#define IPSEC_COMPARE_SHIFT      14
#define IPSEC_INTERRUPT_SHIFT      15
#else
#define IPSEC_VALID_SHIFT 0
#define IPSEC_DIRECTION_SHIFT 1
#define IPSEC_VERSION_SHIFT 2
#define IPSEC_MODE_SHIFT 4
#define IPSEC_PROT_SHIFT 5
#define IPSEC_ENCAP_SHIFT 6
#define IPSEC_CIPHER_SHIFT 8
#define IPSEC_AUTH_SHIFT 11
#define IPSEC_DF_SHIFT 13
#define IPSEC_SELECTOR_SHIFT 13
#define IPSEC_FT_SHIFT 14
#define IPSEC_SELECTOR_TYPE_SHIFT 14
#define IPSEC_NEXT_SA_SHIFT 15
#endif

#define CIPHER_KEY_OFFSET   0
#define ESP_OFFSET      32
#define IV_OFFSET      40
#define HMAC_OFFSET      56

typedef struct
{
  Csp1RequestType request_type;
  Csp1ResponseOrder response_order;
  Csp1DmaMode dma_mode;
  Csp1InterruptMode interrupt_mode;
  Csp1MicrocodeType microcode_type;
}
Csp1RequestInfo;


#define MAX_INCNT    32
#define MAX_OUTCNT   32
#define MAX_BUFCNT   MAX_INCNT

typedef struct
{
  Uint16 opcode;
  Uint16 size;
  Uint16 param;
  Uint16 dlen;         /* length in bytes of the input data */
  Uint16 rlen;         /* length in bytes of the output data */
  Uint16 incnt;         /* for getting a pointer to the data */
  Uint16 outcnt;      /* for getting a pointer to the data */
  Uint16 reserved;      /* for future use */

  Uint32 insize[MAX_INCNT];
  Uint32 inoffset[MAX_INCNT];
  Uint32 inunit[MAX_INCNT];
  Uint32 outsize[MAX_OUTCNT];
  Uint32 outoffset[MAX_OUTCNT];
  Uint32 outunit[MAX_OUTCNT];
  Uint32 request_id;
  Uint32 time_in;
  Uint32 timeout;
  Uint32 req_queue;

  n1_dma_mode dma_mode;
  n1_request_type req_type;   /* Only for op buf */
  n1_response_order res_order;
  Uint32  status; /*To store the status of Operation i.e. EAGAIN/SUCCESS('0')*/

  Uint64 ctx_ptr ;
  UINT8PTR inptr[MAX_INCNT];
  UINT8PTR outptr[MAX_OUTCNT];
  CBFUNCPTR callback; /* void (*callback) (int, void *);*/
  VOIDPTR cb_arg;
  UINT64PTR completion_address;
  Csp1Group group;
  int  ucode_idx;
  Uint8  resvd2[4]; //reserved field to ensure 64-bit alignement of structure.
  Uint8 resvd3[OP_BUF_ALIGN];
}
Csp1OperationBuffer, n1_request_buffer, n1_operation_buffer;


typedef struct
{
  Uint16 bufcnt;
  Uint32 *bufptr[MAX_BUFCNT];
  Uint32 bufsize[MAX_BUFCNT];
}
Csp1ScatterBuffer, n1_scatter_buffer;


typedef struct
{
  Uint32 condition_code;
  Uint64 ctx_ptr;
}
Csp1ResponseBuffer;

typedef struct {
    Uint32 request_id;
    Uint32 status;
} Csp1RequestStatusBuffer;

typedef struct {
    /*input */
    Uint32 cnt; /* length of req_stat_buf in size multiple of Csp1RequestStatusBuffer size */
    /*output */
    Uint32 res_count;           /* number of elements update by driver */
   
   Uint64 req_stat_buf;/* pointer to "Csp1RequestStatusBuffer" */
} Csp1StatusOperationBuffer;

#define BOOT_IDX 0
#define MICROCODE_MAX   3

#define UCODE_IDX 1

#define FREE_IDX BOOT_IDX
#define MAX_INIT MICROCODE_MAX

typedef struct 
{
   Uint8  mc_present[MICROCODE_MAX];
   Uint32 core_mask[MICROCODE_MAX]; 
} Csp1CoreAssignment;

typedef struct
{
  Uint32 dev_cnt;
  Uint8  dev_mask;
}Csp1DevMask,n1_dev_mask;

typedef struct
{
   Uint8 size;         /* number of init buffers */
   Uint8 resvd1[7];   /*reserved field for Alignment.*/
   Uint8 version_info[MAX_INIT][32];
   Uint8 sram_address[MAX_INIT][8];
   Uint8 signature[MAX_INIT][256];

   Uint32 code_length[MAX_INIT];
   Uint32 data_length[MAX_INIT];

   UINT8PTR code[MAX_INIT];
   UINT8PTR data[MAX_INIT];

   Uint8 ucode_idx[MAX_INIT];
   Uint8 resvd2[8-MAX_INIT];
} Csp1InitBuffer;


typedef struct _Selector
{
        Uint8 protocol;

        Uint16 src_port_upper;

#define SELECTOR(ps) ((void*)&(ps)->src_port_upper)
#define SELECTOR_SIZE(v) (((v) == IPV4) ? 24 : 72)

}__attribute__((__packed__)) Selector;

typedef struct _Ipv4Selector
{
        Uint8 protocol;

        Uint16 src_port_upper;
        Uint16 src_port_lower;
        Uint16 dst_port_upper;
        Uint16 dst_port_lower;

        Uint32 src_addr_upper;
        Uint32 src_addr_lower;
        Uint32 dst_addr_upper;
        Uint32 dst_addr_lower;
} __attribute__((__packed__))Ipv4Selector;

typedef struct _Ipv6Selector
{
        Uint8 protocol;

        Uint16 src_port_upper;
        Uint16 src_port_lower;
        Uint16 dst_port_upper;
        Uint16 dst_port_lower;

        Uint32 src_addr_upper[4];
        Uint32 src_addr_lower[4];
        Uint32 dst_addr_upper[4];
        Uint32 dst_addr_lower[4];
} __attribute__((__packed__))Ipv6Selector;

/*! \enum Csp1ErrorCodes FAILURE/PENDING codes*/
typedef enum
{
  /* Driver */
  ERR_DRIVER_NOT_READY = (0x40000000 | 256),   /* 0x40000100 */
  ERR_MEMORY_ALLOC_FAILURE,          /* 0x40000101 */
  ERR_DOOR_BEL_TIMEOUT,            /* 0x40000102 */
  ERR_REQ_TIMEOUT,            /* 0x40000103 */
  ERR_CONTEXT_ALLOC_FAILURE,         /* 0x40000104 */
  ERR_CONTEXT_DEALLOC_FAILURE,         /* 0x40000105 */
  ERR_KEY_MEM_ALLOC_FAILURE,         /* 0x40000106 */
  ERR_KEY_MEM_DEALLOC_FAILURE,         /* 0x40000107 */
  ERR_UCODE_LOAD_FAILURE,         /* 0x40000108 */
  ERR_INIT_FAILURE,            /* 0x40000109 */
  ERR_EXEC_WAIT_TIMEOUT,         /* 0x4000010a */
  ERR_OUTBOUND_FIFO_WAIT_TIMEOUT,      /* 0x4000010b */
  ERR_INVALID_COMMAND,            /* 0x4000010c */
  ERR_SCATTER_GATHER_SETUP_FAILURE,      /* 0x4000010d */
  ERR_OPERATION_NOT_SUPPORTED,         /* 0x4000010e */
  ERR_NO_MORE_DEVICE,            /* 0x4000010f */
  ERR_REQ_PENDING,            /* 0x40000110 */
  ERR_DIRECT_SETUP_FAILURE,         /* 0x40000111 */
  ERR_INVALID_REQ_ID,            /* 0x40000112 */
  ERR_ILLEGAL_ASSIGNMENT,         /* 0x40000113 */
  ERR_DMA_MAP_FAILURE,            /* 0x40000114 */
  ERR_UNKNOWN_ERROR,            /* 0x40000115 */

  /* API Layer */
  ERR_ILLEGAL_INPUT_LENGTH = (0x40000000 | 384),/* 0x40000180 */
  ERR_ILLEGAL_OUTPUT_LENGTH,         /* 0x40000181 */
  ERR_ILLEGAL_KEY_LENGTH,         /* 0x40000182 */
  ERR_ILLEGAL_KEY_HANDLE,         /* 0x40000183 */
  ERR_ILLEGAL_CONTEXT_HANDLE,         /* 0x40000184 */
  ERR_ILLEGAL_BLOCK_TYPE,         /* 0x40000185 */
  ERR_ILLEGAL_KEY_MATERIAL_INPUT,      /* 0x40000186 */
  ERR_BAD_PKCS_PAD_OR_LENGTH,         /* 0x40000187 */
  ERR_BAD_CIPHER_OR_MAC,         /* 0x40000188 */
  ERR_ILLEGAL_MOD_EX_TYPE,         /* 0x40000189 */

  ERR_ECC_ILLEGAL_ARGUMENT     = (0x40000000 | 512)+0,
  ERR_ECC_UNSUPPORTED_ARGUMENT,
  ERR_ECC_OUT_OF_MEMORY,
  ERR_ECC_MAX_ECRNG_RANDOM_INT_TRIALS_EXCEED,
  ERR_ECC_INTERNAL_FAILURE
}Csp1ErrorCodes;

/* Microcode generated error codes */
/*!\page page1 General Info
 * \section errorCodes  Error Codes Info
 * \verbatim
 * SSL1.x error codes 
 * ------------------
 *
 *  ERR_BAD_RECORD               0x40000002 
 *  There was a MAC miscompare or otherwise a record was found bad on a 
 *  decrypt.
 *  
 *  ERR_BAD_SIZE_OR_DLEN_VAL            0x4000000b
 *  Either the size of the request was bad or the read stream input length
 *  (indicated either by the Dlen value or the scatter/gather list) did not
 *  match the length expected by the request.
 *  
 *  ERR_BAD_PKCS_PAD_OR_LENGTH            0x4000000c
 *  A PKCS#1v15 decrypt found a bad pad value or length
 *
 *  ERR_BAD_PKCS_TYPE               0x4000000e
 *  A PKCS#1v15 decrypt found a bad type.
 *  
 *  ERR_BAD_SCATTER_GATHER_WRITE_LENGTH         0x4000000d
 *  The write stream length indicated by the scatter list did not match the
 *  write stream length of the request.
 *
 *
 * IPsec 1.x error codes
 * ---------------------
 * 
 *  BAD_PACKET_LENGTH               0x40000080
 *  BAD_IPSEC_MODE               0x40000081
 *  BAD_IPSEC_PROTOCOL               0x40000082
 *  BAD_IPSEC_AUTHENTICATION            0x40000083
 *  BAD_IPSEC_PADDING               0x40000084
 *  BAD_IP_VERSION               0x40000085
 *  BAD_IPSEC_AUTH_TYPE               0x40000086
 *  BAD_IPSEC_ENCRYPT_TYPE            0x40000087
 *  BAD_IKE_DH_GROUP               0x40000088
 *  BAD_MODLENGTH               0x40000089
 *  BAD_PKCS_PAD_OR_LENGTH            0x4000008a
 *  BAD_PKCS_TYPE               0x4000008b
 *  BAD_IPSEC_SPI               0x4000008c
 *  BAD_CHECKSUM               0x4000008d
 *  BAD_IPSEC_CONTEXT               0x4000008e
 *
 *
 * MC2 (Microcode 2.x) SSL and IPsec combined error codes
 * ------------------------------------------------------
 *
 * BAD_OPCODE                  0x40000001
 * BAD_RECORD                  0x40000002
 * BAD_SCATTER_GATHER_LIST            0x40000003
 * BAD_ICV_AESGCM              0x4000000c
 * BAD_KEY_LENGTH_AESGCM       0x40000010
 * BAD_SCATTER_GATHER_WRITE_LENGTH         0x4000000d
 * BAD_LENGTH                  0x4000000f 
 * BAD_BOOT_COMPLETION               0x40000011
 * BAD_PACKET_LENGTH               0x40000012
 * BAD_IPSEC_MODE               0x40000013
 * BAD_IPSEC_PROTOCOL               0x40000014
 * BAD_IPSEC_AUTHENTICATION            0x40000015
 * BAD_IPSEC_PADDING               0x40000016
 * BAD_IP_VERSION               0x40000017
 * BAD_AUTH_TYPE               0x40000018
 * BAD_PKCS_DATA               0x4000001b
 * BAD_IPSEC_SPI               0x4000001c
 * BAD_CHECKSUM                  0x4000001d
 * BAD_IPSEC_CONTEXT               0x4000001e
 * BAD_IPSEC_CONTEXT_DIRECTION            0x4000001f
 * BAD_IPSEC_CONTEXT_FLAG_MISMATCH         0x40000020
 * IPCOMP_PAYLOAD               0x40000021
 * BAD_FRAG_OFFSET               0x40000022
 * BAD_SELECTOR_MATCH               0x40000023
 * BAD_AES_TYPE                  0x40000024
 * BAD_FRAGMENT_SIZE               0x40000026
 * BAD_DSA_VERIFY               0x40000027
 * BAD_PUBLIC_KEY               0x40000028
 * BAD_IKE_DH_GROUP               0x4000002b
 *
 * \endverbatim
 */


enum
{
  UNIT_8_BIT,
  UNIT_16_BIT,
  UNIT_32_BIT,
  UNIT_64_BIT
};


typedef struct
{
  Uint16 opcode;
  Uint8 *inptr0;
  Uint32 insize0;
  Uint8 *inptr1;
  Uint32 insize1;
  Uint8 *inptr2;
  Uint32 insize2;
}
DownloadBuffer;


typedef struct
{
  unsigned long  addr;
  unsigned long  data;
}
DebugRWReg;


typedef struct
{
  unsigned long timeout_max;
}
Csp1Config;

typedef struct
{
  Uint64 ctx_ptr;
  ContextType type;
  Uint8   resvd[8-sizeof(ContextType)];  /*reserved field for Alignment*/
}
n1_context_buf;


/* Store Key Buffer */
typedef struct
{
  Uint64 key_handle;
  /*Uint8 *key;*/
  UINT8PTR key;
  Uint16 length;
  Uint8  resvd[KEY_BUF_ALIGN]; /*reserved field for Alignment*/
}
n1_write_key_buf;

/* Store Speed_Test_Info buffer  */
typedef struct
{
  Uint64 time_taken;   /* microseconds */
  Uint64 req_completed;
  Uint64 dlen;
  Uint64 rlen;
}
Speed_Test_Info;


/*+***************************************************************************/
/*!\ingroup GP_MISC
 *
 * SpeedTestResult
 *
 * Calculate the result of speedtest
 *       
 * Input  
 *  info = information of speedtest.
 *      
 * Output
 *           
 * Return Value
 *      ret = speed values in Mbps 
              0 (if time_taken = 0 microsecond )
 */  
/*-****************************************************************************/
Uint64 SpeedTestResult(Speed_Test_Info *info);


/*+***************************************************************************/
/*!\ingroup GP_MISC
 *
 * Csp1GetAllResults
 *
 * Returns the status of all requests sent by the current process
 *
 * Input
 * \param req_stat_buf  array of Csp1RequestStatusBuffer structures
 * \param buf_size  size of req_stat_buf in multiple of Csp1RequestStatusBuffer size.
 *                           (buf_size % sizeof(Csp1RequestStatusBuffer) = 0)
 * \if CAVIUM_MULTICARD_API
 * \param device_id	Device ID
 * \endif
 *
 * Output
 * \param res_count  number of elements returned in req_stat_buf.
 *
 * Return Value
 * \result completion code  0 (for success), ERR_BAD_IOCTL
 */
/*-****************************************************************************/
Uint32 Csp1GetAllResults(Csp1RequestStatusBuffer *req_stat_buf,
                                  Uint32 buf_size,
                                  Uint32 *res_count
#ifdef CAVIUM_MULTICARD_API
                                  ,Uint32 device_id
#endif
                                  );



#define cavium_dump(str_,buf_,len_) \
{ \
   Uint32 i=0; \
   cavium_print("%s\n",str_); \
        cavium_print("0x%04X : ", i*8); \
   for (i=0;i<(Uint32)(len_);i++){    \
      if(i && ((i%8) == 0)) \
                        { \
         cavium_print( "%s", "\n"); \
                        cavium_print("0x%04X : ", (i)); \
                        } \
      cavium_print("%02x ",(buf_)[i]);\
                     } \
   cavium_print("\n%s\n",str_); \
}

#define OP_MEM_ALLOC_KEY_SRAM_MEM       0
#define OP_MEM_ALLOC_KEY_HOST_MEM       1
#define OP_MEM_ALLOC_KEY_DDR_MEM        2
#define OP_MEM_FREE_KEY_HOST_MEM        3
#define OP_MEM_FREE_KEY_DDR_MEM         4
#define OP_MEM_FREE_KEY_SRAM_MEM        5
#define OP_MEM_STORE_KEY_HOST_MEM       6

#ifndef CSP1_KERNEL

extern int CSP1_driver_handle;



/*+****************************************************************************/
/*!\page page1 General Info
 * \section keyMaterial  Key memory and format
 * \verbatim 
 *
 *  Key memory and format
 *
 * Asymmetric keys can come from three sources:
 *   - the input stream (i.e. the dptr)
 *   - the on-chip (FSK) key memory
 *    - the extended key memory in local DRAM
 *
 * The FSK memory is 8KB and is addressed, read, and
 * written in multiples of 64-bit words
 *
 * The extended key memory in local DRAM can be up to
 * 4MB.
 *
 * The chinese remainder theorem (CRT) is a theorem that
 * allows for faster private key modular exponentiations.
 * This can (conditionally) be used to improve performance.
 *
 * Without CRT, full modular exponentions are performed
 * (up to 2048-bit). The format of the key material is:
 *      modulus   (modlength 64-bit words)
 *       exponent  (modlength 64-bit words)
 *
 * (The operation is result = (input ^ exponent) mod modulus.)
 *
 * With CRT (on private keys), the format of the key material is:
 *      Q        (modlength/2 64-bit words)
 *      Eq       (modlength/2 64-bit words)
 *      P        (modlength/2 64-bit words)
 *      Ep       (modlength/2 64-bit words)
 *      iqmp     (modlength/2 64-bit words)
 *
 * The following are requirements of this key material with CRT:
 *   modulus = Q * P (Q, P are prime factors of modulus, P > Q)
 *   Q, P are 1/2 the length (in bits or words) of the modulus
 *   Eq = exponent mod (Q - 1)
 *   Ep = exponent mod (P - 1)
 *   iqmp = (q ^ -1) mod p = (q ^ (p-2)) mod p
 * Eq and Ep are the precomputed exponents. iqmp is also precomputed.
 *
 * With CRT, the calculation to  get result = (input ^ exponent) mod modulus
 * is:
 *   inputq = input mod Q
 *   inputp = input mod P
 *   Mq = (inputq ^ Eq) mod Q
 *   Mp = (inputp ^ Ep) mod P
 *      temp = Mp - Mq
 *   if(temp < 0)
 *      temp += p
 *   temp = (temp * iqmp) mod p
 *   result = temp * q + Mq  // modular multiplication not necessary since the result is < modulus
 *   
 *
 * #ifndef MC2
 *      The key material should be in integer format. That means that the least-significant 64-bit
 *      word should be the first word and the most-significant word is the last word. 
 *      (Within a word the bytes are still big-endian - the most-significant byte contains the 
 *      most-significant bits, as you might expect.)
 * #endif
 * \endverbatim
 */
/*-***************************************************************************/


/*+****************************************************************************/
/*!\ingroup GP_OPS
 * Csp1Initialize
 *
 * Prepares the aplication.
 *
 * \param dma_mode  CAVIUM_DIRECT or CAVIUM_SCATTER_GATHER
 * 
 * \if CAVIUM_MULTICARD_API
 * \param dev_id	Device ID
 * \endif
 *
 * \retval SUCCESS 0 
 * \retval FAILURE #Csp1ErrorCodes
 */
/*-***************************************************************************/
#ifdef CAVIUM_MULTICARD_API
Uint32
Csp1Initialize(Csp1DmaMode dma_mode, Uint32 dev_id);
#else
Uint32
Csp1Initialize(Csp1DmaMode dma_mode);
#endif


/*+****************************************************************************/
/*!\ingroup MISC
 * Csp1Shutdown
 *
 * Cleanup the driver.
 *
 * \if CAVIUM_MULTICARD_API
 * \param dev_id	Device ID
 * \endif
 *
 * \retval SUCESS 0           
 * \retval FAILURE/PENDING #Csp1ErrorCodes
 *
 */
/*-***************************************************************************/
#ifdef CAVIUM_MULTICARD_API
Uint32 Csp1Shutdown (Uint32 dev_id);
#else
Uint32 Csp1Shutdown (void);
#endif


/*+****************************************************************************/
/*! \ingroup MISC 
 * Csp1CheckForCompletion
 *
 * Checks the status of the request.
 *
 * \param request_id	Unique ID for this request.
 * \if CAVIUM_MULTICARD_API
 * \param dev_id	Device ID
 * \endif
 *
 * \retval SUCCESS 0
 * \retval FAILURE/PENDING #Csp1ErrorCodes

 *
 */
/*-***************************************************************************/
#ifdef CAVIUM_MULTICARD_API
Uint32 Csp1CheckForCompletion (Uint32 request_id,Uint32 dev_id);
#else
Uint32 Csp1CheckForCompletion (Uint32 request_id);
#endif



/*+****************************************************************************/
/*! \ingroup MISC
 * Csp1FlushAllRequests
 *
 * Removes all pending requests for the calling process. This call can make the 
 * current process go to sleep. The driver will wait for all pending requests 
 * to complete or timeout.
 *
 * \if CAVIUM_MULTICARD_API
 * \param dev_id	Device ID
 * \endif
 *
 * \retval  SUCCESS 0
 * \retval  FAILURE/PENDING #Csp1ErrorCodes

 */
/*-***************************************************************************/
#ifdef CAVIUM_MULTICARD_API
Uint32 Csp1FlushAllRequests (Uint32 dev_id);
#else
Uint32 Csp1FlushAllRequests (void);
#endif


/*+****************************************************************************/
/*! \ingroup MISC 
 * Csp1FlushRequest
 *
 * Removes the request for the calling process. This call can make the 
 * current process go to sleep. The driver will wait for the request 
 * to complete or timeout.
 *
 * \param request_id	Unique ID for this request.
 *
 * \if CAVIUM_MULTICARD_API
 * \param dev_id	Device ID
 * \endif
 *
 * \retval SUCCESS 0
 * \retval FAILURE/PENDING #Csp1ErrorCodes
 *
 */
/*-***************************************************************************/
#ifdef CAVIUM_MULTICARD_API
Uint32 Csp1FlushRequest (Uint32 request_id,Uint32 dev_id);
#else
Uint32 Csp1FlushRequest (Uint32 request_id);
#endif



/*+****************************************************************************/
/*! \ingroup GP_OPS
 * Csp1AllocContext
 *
 * Allocates a context segment (in the local DDR DRAM or the host memory 
 * depending on the system) and returns its handle that will be passed to the 
 * processor in the final 8 bytes of the request as Cptr.
 *
 * \param  cntx_type     CONTEXT_SSL or CONTEXT_IPSEC
 * \param  context_handle pointer to 8-byte address of the context for use by 
 *	   the Cavium processor
 *
 * \if CAVIUM_MULTICARD_API
 * \param dev_id	Device ID
 * \endif
 *
 * \retval SUCCESS 0 
 * \retval FAILURE/PENDING #Csp1ErrorCodes
 *
 */
/*-***************************************************************************/
#ifdef CAVIUM_MULTICARD_API
Uint32 Csp1AllocContext (ContextType cntx_type, Uint64 * context_handle,Uint32 dev_id);
#else
Uint32 Csp1AllocContext (ContextType cntx_type, Uint64 * context_handle);
#endif



/*+****************************************************************************/
/*! \ingroup GP_OPS
 * Csp1FreeContext
 *
 * Free a context segment for use by another SSL connection.
 *
 * \param cntx_type       CONTEXT_SSL or CONTEXT_IPSEC
 * \param context_handle    8-byte address of the context for use by 
 *             the Cavium processor
 * \if CAVIUM_MULTICARD_API
 * \param dev_id	Device ID
 * \endif
 *
 * \retval SUCCESS 0 
 * \retval FAILURE/PENDING #Csp1ErrorCodes
 *
 */
/*-***************************************************************************/
#ifdef CAVIUM_MULTICARD_API
Uint32 Csp1FreeContext (ContextType cntx_type, Uint64 context_handle,Uint32 dev_id);
#else
Uint32 Csp1FreeContext (ContextType cntx_type, Uint64 context_handle);
#endif




/*+****************************************************************************/
/*! \ingroup GP_OPS
 * Csp1AllocKeyMem
 *
 * Acquires the handle to a key memory segment and returns a handle.
 *
 * \param key_material_loc   INTERNAL_SRAM, HOST_MEM, or LOCAL_DDR
 *
 * \param key_handle      pointer to 8-byte handle to key memory segment
 *
 * \if CAVIUM_MULTICARD_API
 * \param dev_id	Device ID
 * \endif
 *
 * \retval SUCCESS 0 
 * \retval COMPLETION_CODE #Csp1ErrorCodes
 *
 */
/*-***************************************************************************/

#ifdef CAVIUM_MULTICARD_API
Uint32
Csp1AllocKeyMem (KeyMaterialLocation key_material_loc, Uint64 * key_handle,Uint32 dev_id);
#else
Uint32
Csp1AllocKeyMem (KeyMaterialLocation key_material_loc, Uint64 * key_handle);
#endif


/*+****************************************************************************/
/*! \ingroup GP_OPS
 * Csp1FreeKeyMem
 *
 * Free a key memory segment.
 *
 * \param key_handle   8-byte handle to key memory segment
 *
 * \if CAVIUM_MULTICARD_API
 * \param dev_id	Device ID
 * \endif
 *
 * \retval SUCCESS 0
 * \retval FAILURE/PENDING #Csp1ErrorCodes
 *
 */
/*-***************************************************************************/

#ifdef CAVIUM_MULTICARD_API
Uint32 Csp1FreeKeyMem (Uint64 key_handle,Uint32 dev_id);
#else
Uint32 Csp1FreeKeyMem (Uint64 key_handle);
#endif


       
/*+****************************************************************************/
/*! \ingroup MISC
 * Csp1StoreKey
 *
 * Store a key to memory segment indicated by key handle.
 *
 * \param key_handle     8-byte handle to key memory segment
 * \param length    size of key in bytes
 * \param key       pointer to key
 * \param mod_ex_type    NORMAL_MOD_EX or CRT_MOD_EX
 *
 * \if CAVIUM_MULTICARD_API
 * \param dev_id	Device ID
 * \endif
 *
 * \retval SUCCESS 0
 * \retval FAILURE/PENDING #Csp1ErrorCodes
 *
 */
/*-***************************************************************************/

#ifdef CAVIUM_MULTICARD_API
Uint32
Csp1StoreKey (Uint64 * key_handle,
         Uint16 length, Uint8 * key, RsaModExType mod_ex_type,Uint32 dev_id);
#else
Uint32
Csp1StoreKey (Uint64 * key_handle,
         Uint16 length, Uint8 * key, RsaModExType mod_ex_type);
#endif



/*****************************************************************************/
/*! \ingroup GP_OPS
 * Csp1ReadEpci
 *
 * Routine to read the onchip SRAM memory
 *
 * \param request_type   CAVIUM_BLOCKING or CAVIUM_NON_BLOCKING
 * \param key_handle     64-bit key handle pointer.
 * \param length    size of data to read in bytes (8<=length<=880, length\%8=0).
 * \param  data    Result data (size variable based on size)
 * \param request_id    Unique ID for this request.
 *
 * \if CAVIUM_MULTICARD_API
 * \param dev_id	Device ID
 * \endif
 *
 * \retval SUCCESS 0
 * \retval FAILURE/PENDING #Csp1ErrorCodes
 *
 */
/****************************************************************************/
#ifdef CAVIUM_MULTICARD_API
Uint32
Csp1ReadEpci (n1_request_type request_type,
         Uint64 * key_handle,
         Uint16 length, Uint8 * data, Uint32 * request_id,Uint32 dev_id);
#else
Uint32
Csp1ReadEpci (n1_request_type request_type,
         Uint64 * key_handle,
         Uint16 length, Uint8 * data, Uint32 * request_id);
#endif



/*****************************************************************************/
/*! \ingroup GP_OPS
 * Csp1WriteEpci
 *
 * write data to onchip SRAM.
 *
 * \param request_type   CAVIUM_BLOCKING or CAVIUM_NON_BLOCKING
 * \param key_handle     64-bit key handle pointer.
 * \param length    size of data to write in bytes (8<=length<=880, length\%8=0).
 * \param data       input data 
 * \param request_id    Unique ID for this request.
 *
 * \if CAVIUM_MULTICARD_API
 * \param dev_id	Device ID
 * \endif
 *
 * \retval SUCCESS 0
 * \retval FAILURE/PENDING #Csp1ErrorCodes
 *
 */
/****************************************************************************/
#ifdef CAVIUM_MULTICARD_API
Uint32
Csp1WriteEpci (n1_request_type request_type,
          Uint64 * key_handle,
          Uint16 length, Uint8 * data, Uint32 * request_id,Uint32 dev_id);
#else
Uint32
Csp1WriteEpci (n1_request_type request_type,
          Uint64 * key_handle,
          Uint16 length, Uint8 * data, Uint32 * request_id);
#endif



/*****************************************************************************/
/*! \ingroup GP_OPS
 * Csp1ReadContext
 *
 * Routine to read data from context.
 *
 * \param request_type    CAVIUM_BLOCKING or CAVIUM_NON_BLOCKING
 * \param context_handle  64-bit context handle pointer.
 * \param length     size of data to read in bytes (8<=length<=1024, length\%8=0).
 * \param data        Result data (size variable based on size)
 * \param request_id     Unique ID for this request.
 *
 * \if CAVIUM_MULTICARD_API
 * \param dev_id	Device ID
 * \endif
 *
 * \retval SUCCESS 0
 * \retval FAILURE/PENDING #Csp1ErrorCodes
 *
 */
/****************************************************************************/
#ifdef CAVIUM_MULTICARD_API
Uint32
Csp1ReadContext (n1_request_type request_type,
       Uint64 context_handle,
       Uint16 length, Uint8 * data, Uint32 * request_id,Uint32 dev_id);
#else
Uint32
Csp1ReadContext (n1_request_type request_type,
       Uint64 context_handle,
       Uint16 length, Uint8 * data, Uint32 * request_id);
#endif


/*+****************************************************************************/
/*! \ingroup GP_OPS
 * Csp1WriteContext
 *
 * Write data to context memory.
 *
 * \param request_type     CAVIUM_BLOCKING or CAVIUM_NON_BLOCKING
 * \param context_handle  64-bit context handle pointer (context_handle\%8=0)
 * \param length     size of the data in bytes (8<=length<=1024,length\%8=0)
 * \param data        pointer to length bytes of data to be stored
 * \param request_id     Unique ID for this request.
 *
 * \if CAVIUM_MULTICARD_API
 * \param dev_id	Device ID
 * \endif
 *
 * \retval SUCCESS 0
 * \retval FAILURE/PENDING #Csp1ErrorCodes
 *
 */
/*-***************************************************************************/
#ifdef CAVIUM_MULTICARD_API
Uint32
Csp1WriteContext (n1_request_type request_type,
        Uint64 context_handle,
        Uint16 length, Uint8 * data, Uint32 * request_id,Uint32 dev_id);
#else
Uint32
Csp1WriteContext (n1_request_type request_type,
        Uint64 context_handle,
        Uint16 length, Uint8 * data, Uint32 * request_id);
#endif


/*+****************************************************************************/
/*! \ingroup IPSEC_OPS
 *
 * Csp1WriteIpsecSa
 *
 * Write Ipsec SA data to context memory.
 *
 * \param request_type	CAVIUM_BLOCKING or CAVIUM_NON_BLOCKING
 * \param proto	ESP or AH
 * \param inner_version	Protocol version of inner IP header.
 * \param outer_version	Protocol version of outer IP header.
 * \param mode	SA mode (TUNNEL or TRANSPORT)
 * \param dir	Direction (INBOUND or OUTBOUND)
 * \param cypher	Encryption algorithm 
 *             	(DESCBC, DES3CBC, AES128CBC, AES192CBC, AES256CBC)
 * \param auth	Authentication algorithm
 *           	(MD5HMAC96 or SHA1HMAC96)
 * \param template   Template for Outer IP header
 * \param spi	32 bit SPI value
 * \param copy_df   0 (copy the df bit for packet fragments) or 1 (do not copy)
 * \param ft is fragment type (0 for POST_FRAG and 1 for PRE_FRAG)
 * \param inter_frag_padding is the padding size between fragments
 * \param udp_encap  0 (no UDP encapsulation) or 1 (UDP encapsulation)
 * \param context_handle  64-bit context handle pointer (context_handle\%8=0)
 * \param next_context_handle	context handle pointer for next SA.
 * \param selectors for selector checking
 * \param e_key	Encryption key
 * \param a_key	Authentication key
 * \param res_order	Response order (CAVIUM_RESPONSE_ORDERED or CAVIUM_RESPONSE_UNORDERED).
 * \param req_queue	Queue on which this request has to be sent.
 * \param request_id	Unique ID for this request.
 *
 * \retval SUCCESS 0
 * \retval FAILURE/PENDING #Csp1ErrorCodes
 */
 /*-***************************************************************************/
#ifndef SSL
#ifndef MC2
Uint32
Csp1WriteIpsecSa(IpsecProto proto,
                Version version,
                IpsecMode mode,
                Direction dir,
                EncType cypher,
                Uint8 *e_key,
                AuthType auth,
                Uint8 *a_key,
#ifndef IPV6_EXT_HEADER_SUPPORT
                Uint8 template[40],
#else
                Uint8 template[384],
#endif
                Uint32 spi,
                Uint8 copy_df,
                FragType ft,
                Uint16 inter_frag_padding,
                Uint8 udp_encap,
                Uint64 context_handle,
                Uint64 next_context_handle,
                int res_order,
                int req_queue,
                Uint32 *request_id);

#else
Uint32
Csp1WriteIpsecSa(n1_request_type request_type,
                IpsecProto proto,
                Version inner_version,
                Version outer_version,
                IpsecMode mode,
                Direction dir,
                EncType cypher,
                Uint8 *e_key,
                AuthType auth,
                Uint8 *a_key,
#ifndef IPV6_EXT_HEADER_SUPPORT
                Uint8 template[40],
#else
                Uint8 template[384],
#endif
                Uint32 spi,
                Uint8 copy_df,
                FragType ft,
                Uint16 inter_frag_padding,
                Uint8 udp_encap,
                Uint64 context_handle,
                Uint64 next_context_handle,
                Selector* selectors,  /* selectors, must match in_ver */
                int res_order,
                int req_queue,
                Uint32 *request_id);

#endif
#endif
/*+****************************************************************************/
/*! \ingroup IPSEC_OPS
 * Csp1ProcessPacket
 *
 * Process inbound and outbound packets in userspace.
 *
 * \param size	Param1 field as defined in the Microcode Spec. 
 * \param param	Param2 field as defined in the Microcode Spec. 
 * \param dir	Direction (INBOUND or OUTBOUND)
 *\param dlen	length of input (packet)
 *\param inv	pointer to input data (packet to be processed)
 *\param outv	pointer to output buffer
 *\param rlen	length of output buffer (processed packet)
 *\param context_handle	64-bit context handle pointer (context_handle\%8=0)
 *\param response_order	Response order (CAVIUM_RESPONSE_ORDERED or CAVIUM_RESPONSE_UNORDERED).
 *\param req_queue	Queue on which this request has to be sent. 
 *\param request_id  Unique ID for this request.   
 *
 * \retval SUCCESS 0
 * \retval FAILURE/PENDING #Csp1ErrorCodes
 */
 /*-***************************************************************************/
#ifndef SSL
Uint32
Csp1ProcessPacket(Uint16 size, 
			Uint16 param,
                        Direction dir,
			Uint16 dlen,
	                n1_scatter_buffer *inv,
			n1_scatter_buffer *outv, 
			int rlen,
	                Uint64 context_handle, 
	                int response_order, 
			int req_queue,
			Uint32 *request_id);
#endif
/*+****************************************************************************/
/*! \ingroup GP_OPS
 * Csp1Random
 *
 * Get random data from random pool maintained by the driver.
 *
 * \param request_type CAVIUM_BLOCKING or CAVIUM_NON_BLOCKING \n
 *          This api will only block if driver will have to refill
 *          its random number pool. THis argument is ignored by the 
 *          driver.
 * \param length       size of random data in bytes 
 * \param random      pointer to length bytes of random data
<<<<<<< cavium_common.h
 * \param request_id  Unique ID for this request. This argument is ignored by 
 *                     the driver.
 * \if CAVIUM_MULTICARD_API
 * \param dev_id	Device ID
 * \endif
=======
 * \param request_id  Unique ID for this request. This argument is ignored 
 *                     the driver.
 * \if CAVIUM_MULTICARD_API
 * \param dev_id	Device ID
 * \endif
>>>>>>> 1.44
 *
 * \retval SUCCESS 0
 * \retval FAILURE/PENDING #Csp1ErrorCodes
 *
 */
/*-***************************************************************************/
#ifdef CAVIUM_MULTICARD_API
Uint32
Csp1Random (n1_request_type request_type,
       Uint16 length, Uint8 * random, Uint32 * request_id,Uint32 dev_id);
#else
Uint32
Csp1Random (n1_request_type request_type,
       Uint16 length, Uint8 * random, Uint32 * request_id);
#endif


/*+***************************************************************************/
/*! \ingroup GP_OPS
 * Csp1Hash
 *
 * Compute the HASH of a complete message. Does not use context.
 *
 * \param request_type	CAVIUM_BLOCKING or CAVIUM_NON_BLOCKING
 * \param hash_type	MD5_TYPE or SHA1_TYPE or SHA256_TYPE 
 * \param message_length	size of input in bytes (0<=message_length<=2^16-1)
 * \param message	pointer to length bytes of input to be HMACed
 * \param hash		pointer to the hash_size HASH result 
 * \param request_id	Unique ID for this request.
 *
 * \if CAVIUM_MULTICARD_API
 * \param dev_id	Device ID
 * \endif
 *
 * \retval SUCCESS 0
 * \retval FAILURE/PENDING #Csp1ErrorCodes
 */
/*-***************************************************************************/
#define SHA256_HASH_LEN 32
#define SHA384_HASH_LEN 48
#define SHA512_HASH_LEN 64
#define SHA2_HASH_IV_LEN 64
#ifdef MC2
Uint32 
Csp1Hash(n1_request_type request_type,
	 HashType hash_type, 
	 Uint16 message_length, 
	 Uint8 *message, 
	 Uint8 *hash,
#ifdef CAVIUM_MULTICARD_API
	 Uint32 *request_id,Uint32 dev_id);
#else
	 Uint32 *request_id);
#endif

#endif
/*+****************************************************************************/
/*! \ingroup GP_OPS
 * Csp1Hmac
 *
 * Compute the HMAC of a complete message. Does not use context.
 *
 * \param request_type    CAVIUM_BLOCKING or CAVIUM_NON_BLOCKING
 * \param hash_type     MD5_TYPE or SHA1_TYPE or SHA256_TYPE or SHA384_TYPE or SHA512_TYPE 
 * \param iv            iv for SHA384 and SHA512 
 * \param key_length     size of the key in bytes (key_length\%8=0, 8<=key_length<=64)
 * \param key        pointer to key_length-byte key
 * \param message_length  size of input in bytes (0<=message_length<=2^16-1)
 * \param message     pointer to length bytes of input to be HMACed
 * \param hmac        pointer to the hash_size HMAC result 
 * \param request_id     Unique ID for this request.
 *
 * \if CAVIUM_MULTICARD_API
 * \param dev_id	Device ID
 * \endif
 *
 * \retval SUCCESS 0
 * \retval FAILURE/PENDING #Csp1ErrorCodes
 *
 */
/*-***************************************************************************/
Uint32
Csp1Hmac (n1_request_type request_type,
     HashType hash_type,
     Uint8 * iv, 
     Uint16 key_length,
     Uint8 * key,
     Uint16 message_length,
#ifdef CAVIUM_MULTICARD_API
     Uint8 * message, Uint8 * hmac, Uint32 * request_id,Uint32 dev_id);
#else
     Uint8 * message, Uint8 * hmac, Uint32 * request_id);
#endif



/*+****************************************************************************/
/*! \ingroup GP_OPS
 * Csp1HmacStart
 *
 *   Compute the first stage in a multi-step HMAC.
 *   
 * \param request_type    CAVIUM_BLOCKING or CAVIUM_NON_BLOCKING
 * \param context_handle  64-bit pointer to context (context_handle\%8=0)
 * \param hash_type     MD5_TYPE or SHA1_TYPE  or SHA256_TYPE
 * \param key_length     size of the key in bytes (key_length\%8=0, 8<=key_length<=64)
 * \param key        pointer to key_length-byte key
 * \param message_length  size of input in bytes (0<=message_length<=2^16-1)
 * \param message     pointer to length bytes of input to be HMACed
 * \param request_id     Unique ID for this request.
 *
 * \if CAVIUM_MULTICARD_API
 * \param dev_id	Device ID
 * \endif
 *
 * \retval SUCCESS 0
 * \retval FAILURE/PENDING #Csp1ErrorCodes
 *
 */
/*-***************************************************************************/
Uint32
Csp1HmacStart (n1_request_type request_type,
          Uint64 context_handle,
          HashType hash_type,
          Uint16 key_length,
          Uint8 * key,
#ifdef CAVIUM_MULTICARD_API
          Uint16 message_length, Uint8 * message, Uint32 * request_id,Uint32 dev_id);
#else
          Uint16 message_length, Uint8 * message, Uint32 * request_id);
#endif


/*+****************************************************************************/
/*! \ingroup GP_OPS
 * Csp1HmacUpdate
 *
 *   Compute an intermediate step in a multi-step HMAC.
 *
 * \param request_type    CAVIUM_BLOCKING or CAVIUM_NON_BLOCKING
 * \param context_handle  64-bit pointer to context (context_handle\%8=0)
 * \param hash_type     MD5_TYPE or SHA1_TYPE  or SHA256_TYPE
 * \param message_length  size of input in bytes (0<=message_length<=2^16-1)
 * \param message     pointer to length bytes of input to be HMACed
 * \param request_id     Unique ID for this request.
 *
 * \if CAVIUM_MULTICARD_API
 * \param dev_id	Device ID
 * \endif
 *
 * \retval SUCCESS 0
 * \retval FAILURE/PENDING #Csp1ErrorCodes
 *
 */
/*-***************************************************************************/
Uint32
Csp1HmacUpdate (n1_request_type request_type,
      Uint64 context_handle,
      HashType hash_type,
#ifdef CAVIUM_MULTICARD_API
      Uint16 message_length, Uint8 * message, Uint32 * request_id,Uint32 dev_id);
#else
      Uint16 message_length, Uint8 * message, Uint32 * request_id);
#endif


/*+****************************************************************************/
/*! \ingroup GP_OPS
 * Csp1HmacFinish
 *
 *   Compute the final step in a multi-step HMAC.
 *
 * \param request_type CAVIUM_BLOCKING or CAVIUM_NON_BLOCKING
 * \param context_handle 64-bit pointer to context (context_handle\%8=0)
 * \param hash_type MD5_TYPE or SHA1_TYPE or SHA256_TYPE
 * \param message_length size of input in bytes (0<=message_length<=2^16-1)
 * \param message pointer to length bytes of input to be HMACed
 * \param final_hmac pointer to the hash_size-word HMAC result 
 * \param request_id Unique ID for this request.
 *
 * \if CAVIUM_MULTICARD_API
 * \param dev_id	Device ID
 * \endif
 *
 * \retval SUCCESS 0
 * \retval FAILURE/PENDING #Csp1ErrorCodes
 *
 */
/*-***************************************************************************/
Uint32
Csp1HmacFinish (n1_request_type request_type,
      Uint64 context_handle,
      HashType hash_type,
      Uint16 message_length,
#ifdef CAVIUM_MULTICARD_API
      Uint8 * message, Uint8 * final_hmac, Uint32 * request_id,Uint32 dev_id);
#else
      Uint8 * message, Uint8 * final_hmac, Uint32 * request_id);
#endif


/*+****************************************************************************/
/*! \ingroup GP_OPS 
 * Csp1Me
 *
 * Modular exponentiation.
 *
 * p = x^e mod m
 *
 * \param request_type   CAVIUM_BLOCKING or CAVIUM_NON_BLOCKING
 * \if MC2
 * \param modlength   size of modulus in bytes (17<=modlength<=256)
 * \param explength   size of exponent in bytes 
 * \param datalength   size of data in bytes
 * \param modulus   pointer to modlength-byte modulus
 * \param exponent   pointer to explength-byte exponent
 * \param data      pointer to datalength-byte data
 *   
 * \else
 * \param result_location  CONTEXT_PTR or RESULT_PTR 
 * \param context_handle   64-bit pointer to context (context_handle\%8=0)
 * \param modlength      size of modulus in bytes (modlength\%8=0, 24<modlength<=256)
 * \param data pointer      to modlength-byte value to be exponentiated
 * \param modulus      pointer to modlength-byte modulus
 * \param exponent      pointer to modlength-byte exponent
 * \endif 
 *
 * \if MC2
 * \param result pointer to modlength-byte output
 * \else
 * \param result if (result_location == RESULT_PTR) pointer to modlength-byte 
 * \endif          output in byte format
 * \param  request_id Unique ID for this request.
 *
 * \if CAVIUM_MULTICARD_API
 * \param dev_id	Device ID
 * \endif
 *
 *
 * \retval SUCCESS 0
 * \retval FAILURE/PENDING #Csp1ErrorCodes
 *
 * \note exp_length <= mod_length \n
 *    data_length <= mod_length
 *
 *
 */
/*-***************************************************************************/
#ifdef MC2
Uint32
Csp1Me (n1_request_type request_type,
   Uint16 modlength,
   Uint16 explength,
   Uint16 datalength,
   Uint8 * modulus,
#ifdef CAVIUM_MULTICARD_API
   Uint8 * exponent, Uint8 * data, Uint8 * result, Uint32 * request_id,Uint32 dev_id);
#else
   Uint8 * exponent, Uint8 * data, Uint8 * result, Uint32 * request_id);
#endif

#else
Uint32
Csp1Me (n1_request_type request_type,
   ResultLocation result_location,
   Uint64 context_handle,
   Uint16 modlength,
   Uint8 * data,
   Uint8 * modulus,
#ifdef CAVIUM_MULTICARD_API
   Uint8 * exponent, Uint8 * result, Uint32 * request_id,Uint32 dev_id);
#else
   Uint8 * exponent, Uint8 * result, Uint32 * request_id);
#endif

#endif


/*+****************************************************************************/
/*! \ingroup GP_OPS 
 * Csp1Pkcs1v15Enc
 *
 * Creates PKCS#1v1.5 container.
 *
 * \param request_type   CAVIUM_BLOCKING or CAVIUM_NON_BLOCKING
 * \if MC2
 * \param block_type   type of PKCS#1v1.5 padding (BT1 or BT2)
 * \param modlength   size of modulus in bytes (17 <= modlength <= 256)
 * \param explength   size of exponent in bytes (explength <= modlength -11)
 * \param datalength   size of data in bytes (datalength <= modlength -11)
 * \param modulus   pointer to modlength-byte modulus
 * \param exponent   pointer to explength-byte exponent
 * \param data      pointer to datalength-byte data
 * \else
 * \param result_location    CONTEXT_PTR or RESULT_PTR 
 * \param context_handle     64-bit pointer to context (context_handle\%8=0)
 * \param key_material_input KEY_HANDLE or INPUT_DATA
 * \param key_handle        64-bit handle for key memory 
 * \param block_type        type of PKCS#1v1.5 padding (BT1 or BT2)
 * \param modlength        size of modulus in bytes (modlength\%8=0, 24<=modlength<=256)
 * \param modulus        (key_material_input == INPUT_DATA) ? pointer to RSA modulus : don't care
 * \param exponent        (key_material_input == INPUT_DATA) ? pointer to RSA exponent : don't care
 * \param length        size of the input value 
 * \param data           pointer to length-byte value to be exponentiated
 * \endif
 *
 * 
 * \if MC2
 * \param result   pointer to modlength bytes of output
 * \else
 * \param result   (result_location == RESULT_PTR) ? (pointer to modlength bytes of output: don't care)
 * \endif 
 * \param request_id   Unique ID for this request.
 *
 * \if CAVIUM_MULTICARD_API
 * \param dev_id	Device ID
 * \endif
 *
 * \retval SUCCESS 0
 * \retval FAILURE/PENDING #Csp1ErrorCodes
 *
 */
/*-***************************************************************************/
#ifdef MC2
Uint32
Csp1Pkcs1v15Enc (n1_request_type request_type,
       RsaBlockType block_type,
       Uint16 modlength,
       Uint16 explength,
       Uint16 datalength,
       Uint8 * modulus,
       Uint8 * exponent,
#ifdef CAVIUM_MULTICARD_API
       Uint8 * data, Uint8 * result, Uint32 * request_id,Uint32 dev_id);
#else
       Uint8 * data, Uint8 * result, Uint32 * request_id);
#endif

#else
Uint32
Csp1Pkcs1v15Enc (n1_request_type request_type,
       ResultLocation result_location,
       Uint64 context_handle,
       KeyMaterialInput key_material_input,
       Uint64 key_handle,
       RsaBlockType block_type,
       Uint16 modlength,
       Uint8 * modulus,
       Uint8 * exponent,
       Uint16 length,
#ifdef CAVIUM_MULTICARD_API
       Uint8 * data, Uint8 * result, Uint32 * request_id,Uint32 dev_id);
#else
       Uint8 * data, Uint8 * result, Uint32 * request_id);
#endif

#endif


/*+****************************************************************************/
/*! \ingroup GP_OPS
 * Csp1Pkcs1v15CrtEnc
 *
 * Creates PKCS#1v1.5 container using the Chinese Remainder Theorem.
 * The combination of block type BT2 and CRT may produce unpredictable results.
 *
 * \param request_type   CAVIUM_BLOCKING or CAVIUM_NON_BLOCKING
 * \if MC2
 * \param block_type   type of PKCS#1v1.5 padding (BT1 only)
 * \param modlength   size of modulus in bytes (34 <= modlength <=256, modlength\%2 !=0)
 * \param datalength   size of input data in bytes (datalength <= modlength -11).
 * \param Q      prime factor of RSA modulus
 * \param Eq      exponent mod(Q-1)
 * \param P      prime factor of RSA modulus
 * \param Ep      exponent mod(P-1)
 * \param iqmp      (Q^-1) mod P
 * \else
 * \param result_location     CONTEXT_PTR or RESULT_PTR 
 * \param context_handle      64-bit pointer to context (context_handle\%8=0)
 * \param key_material_input  KEY_HANDLE or INPUT_DATA
 * \param key_handle         64-bit handle for key memory 
 * \param block_type         type of PKCS#1v1.5 padding (BT1 only)
 * \param modlength         size of modulus in bytes (modlength\%8=0, 48<=modlength<=256)
 * \param Q            (key_material_input == INPUT_DATA) ? prime factor of RSA modulus : don't care
 * \param Eq            (key_material_input == INPUT_DATA) ? exponent mod(Q-1) : don't care
 * \param P            (key_material_input == INPUT_DATA) ? prime factor of RSA modulus : don't care
 * \param Ep            (key_material_input == INPUT_DATA) ? exponent mod(P-1) : don't care
 * \param iqmp            (key_material_input == INPUT_DATA) ? (Q^-1) mod P : don't care
 * \param length         size of the input value 
 * \endif
 * \param data pointer to length-byte value to be exponentiated
 *
 * \if MC2
 * \param result     pointer to modlength bytes of output
 * \else
 * \param result   (result_location == RESULT_PTR) ? (pointer to modlength bytes of output : don't care
 * \endif
 * \param request_id   Unique ID for this request.
 * 
 * \if CAVIUM_MULTICARD_API
 * \param dev_id	Device ID
 * \endif
 *
 *
 * \retval SUCCESS 0
 * \retval FAILURE/PENDING #Csp1ErrorCodes
 *
 * \note modlength must be even
 */
/*-***************************************************************************/
#ifdef MC2
Uint32
Csp1Pkcs1v15CrtEnc (n1_request_type request_type,
          RsaBlockType block_type,
          Uint16 modlength,
          Uint16 datalength,
          Uint8 * Q,
          Uint8 * Eq,
          Uint8 * P,
          Uint8 * Ep,
          Uint8 * iqmp,
#ifdef CAVIUM_MULTICARD_API
          Uint8 * data, Uint8 * result, Uint32 * request_id,Uint32 dev_id);
#else
          Uint8 * data, Uint8 * result, Uint32 * request_id);
#endif

#else
Uint32
Csp1Pkcs1v15CrtEnc (n1_request_type request_type,
          ResultLocation result_location,
          Uint64 context_handle,
          KeyMaterialInput key_material_input,
          Uint64 key_handle,
          RsaBlockType block_type,
          Uint16 modlength,
          Uint8 * Q,
          Uint8 * Eq,
          Uint8 * P,
          Uint8 * Ep,
          Uint8 * iqmp,
          Uint16 length,
#ifdef CAVIUM_MULTICARD_API
          Uint8 * data, Uint8 * result, Uint32 * request_id,Uint32 dev_id);
#else
          Uint8 * data, Uint8 * result, Uint32 * request_id);
#endif

#endif


/*+****************************************************************************/
/*! \ingroup GP_OPS
 * Csp1Pkcs1v15Dec
 *
 * Decrypts PKCS#1v1.5 container.
 *
 *
 * \param request_type   CAVIUM_BLOCKING or CAVIUM_NON_BLOCKING
 * \if MC2
 * \param block_type   type of PKCS#1v1.5 padding (BT1 only)
 * \param modlength   size of modulus in bytes (17 <= modlength <=256)
 * \param explength   size of exponent in bytes (explength <= modlength - 11)
 * \param modulus   pointer to modlength-byte modulus
 * \param exponent   pointer to explength-byte exponent
 * \param data      pointer to modlength-11 bytes input
 * \else
 * \param result_location      CONTEXT_PTR or RESULT_PTR 
 * \param context_handle      64-bit pointer to context (context_handle\%8=0)
 * \param key_material_input      KEY_HANDLE or INPUT_DATA
 * \param key_handle         64-bit handle for key memory 
 * \param block_type         type of PKCS#1v1.5 padding (BT1 or BT2)
 * \param modlength         size of modulus in bytes (modlength\%8=0, 24<=modlength<=256)
 * \param modulus         (key_material_input == INPUT_DATA) ? pointer to RSA modulus : don't care
 * \param exponent         (key_material_input == INPUT_DATA) ? pointer to RSA exponent : don't care
 * \param data            pointer to modlength-byte value to be exponentiated
 * \endif
 *
 * \if MC2
 * \param out_length   size of decrypted data in Network Byte order.
 * \param result   out_length byte size result
 * \else
 * \param result   (result_location == RESULT_PTR) ? (pointer to modlength bytes of output, 
 *             *out_length bytes used) : don't care
 * \param out_length   pointer to output length in bytes
 * \endif
 * \param request_id   Unique ID for this request.
 *
 * \if CAVIUM_MULTICARD_API
 * \param dev_id	Device ID
 * \endif
 *
 * \retval SUCCESS 0
 * \retval FAILURE/PENDING #Csp1ErrorCodes
 */
/*-***************************************************************************/
#ifdef MC2
Uint32
Csp1Pkcs1v15Dec (n1_request_type request_type,
       RsaBlockType block_type,
       Uint16 modlength,
       Uint16 explength,
       Uint8 * modulus,
       Uint8 * exponent,
       Uint8 * data,
#ifdef CAVIUM_MULTICARD_API
       Uint16 * out_length, Uint8 * result, Uint32 * request_id,Uint32 dev_id);
#else
       Uint16 * out_length, Uint8 * result, Uint32 * request_id);
#endif

#else
Uint32
Csp1Pkcs1v15Dec (n1_request_type request_type,
       ResultLocation result_location,
       Uint64 context_handle,
       KeyMaterialInput key_material_input,
       Uint64 key_handle,
       RsaBlockType block_type,
       Uint16 modlength,
       Uint8 * modulus,
       Uint8 * exponent,
       Uint8 * data,
#ifdef CAVIUM_MULTICARD_API
       Uint8 * result, Uint64 * out_length, Uint32 * request_id,Uint32 dev_id);
#else
       Uint8 * result, Uint64 * out_length, Uint32 * request_id);
#endif

#endif

/*+****************************************************************************/
/*! \ingroup GP_OPS
 * Csp1Pkcs1v15CrtDec
 *
 * Decrypts PKCS#1v1.5 container using the Chinese Remainder Theorem.
 * The combination of block type 01 and CRT may produce unpredictable results.
 *
 * \param request_type    CAVIUM_BLOCKING or CAVIUM_NON_BLOCKING
 * \if MC2
 * \param block_type   type of PKCS#1v1.5 padding (BT2 only)
 * \param modlength   size of modulus in bytes (34 <= modlength <= 256)
 * \param Q      prime factor of RSA modulus
 * \param Eq      exponent mod(Q-1)
 * \param P      prime factor of RSA modulus
 * \param Ep      exponent mod(P-1)
 * \param iqmp      (Q^-1) mod P
 * \param data      pointer to modlength-byte value to be exponentiated
 * \else
 * \param result_location     CONTEXT_PTR or RESULT_PTR 
 * \param context_handle      64-bit pointer to context (context_handle\%8=0)
 * \param key_material_input  KEY_HANDLE or INPUT_DATA
 * \param key_handle         64-bit handle for key memory 
 * \param block_type         type of PKCS#1v1.5 padding (BT2 only)
 * \param modlength         size of modulus in bytes (modlength\%8=0, 48<=modlength<=256)
 * \param Q            (key_material_input == INPUT_DATA) ? prime factor of RSA modulus : don't care
 * \param Eq            (key_material_input == INPUT_DATA) ? exponent mod(Q-1) : don't care
 * \param P            (key_material_input == INPUT_DATA) ? prime factor of RSA modulus : don't care
 * \param Ep            (key_material_input == INPUT_DATA) ? exponent mod(P-1) : don't care
 * \param iqmp            (key_material_input == INPUT_DATA) ? (Q^-1) mod P : don't care
 * \param data            pointer to modlength-byte value to be exponentiated
 * \endif
 *
 * \if MC2
 * \param out_length   pointer to output length in bytes (Network Byte order)
 * \param result   (pointer to modlength bytes of output,   *out_length bytes used)
 * \else
 * \param result   (result_location == RESULT_PTR) ? (pointer to modlength bytes of output, 
 *                     *out_length bytes used) : don't care
 * \param out_length   pointer to output length in bytes
 * \endif
 * \param request_id   Unique ID for this request.
 *
 * \if CAVIUM_MULTICARD_API
 * \param dev_id	Device ID
 * \endif
 *
 * \retval SUCCESS 0
 * \retval FAILURE/PENDING #Csp1ErrorCodes
 *
 * \note modlength must be even
 *
 */
/*-***************************************************************************/
#ifdef MC2
Uint32
Csp1Pkcs1v15CrtDec (n1_request_type request_type,
          RsaBlockType block_type,
          Uint16 modlength,
          Uint8 * Q,
          Uint8 * Eq,
          Uint8 * P,
          Uint8 * Ep,
          Uint8 * iqmp,
          Uint8 * data,
#ifdef CAVIUM_MULTICARD_API
          Uint16 * out_length, Uint8 * result, Uint32 * request_id,Uint32 dev_id);
#else
          Uint16 * out_length, Uint8 * result, Uint32 * request_id);
#endif

#else
Uint32
Csp1Pkcs1v15CrtDec (n1_request_type request_type,
          ResultLocation result_location,
          Uint64 context_handle,
          KeyMaterialInput key_material_input,
          Uint64 key_handle,
          RsaBlockType block_type,
          Uint16 modlength,
          Uint8 * Q,
          Uint8 * Eq,
          Uint8 * P,
          Uint8 * Ep,
          Uint8 * iqmp,
          Uint8 * data,
#ifdef CAVIUM_MULTICARD_API
          Uint8 * result, Uint64 * out_length, Uint32 * request_id,Uint32 dev_id);
#else
          Uint8 * result, Uint64 * out_length, Uint32 * request_id);
#endif

#endif


/*+****************************************************************************/
/*! \ingroup GP_OPS
 * Csp1InitializeRc4
 *
 *    Initializes  RC4 state in the context and stores the key in context.
 *
 * \param request_type     CAVIUM_BLOCKING or CAVIUM_NON_BLOCKING
 * \param context_handle  64-bit pointer to context (context_handle\%8=0)
 * \param key_length     size of key in bytes (1<=length<=256)
 * \param key        pointer to length-byte key 
 *
 * \param request_id   Unique ID for this request.
 *
 * \if CAVIUM_MULTICARD_API
 * \param dev_id	Device ID
 * \endif
 *
 * \retval SUCCESS 0
 * \retval FAILURE/PENDING #Csp1ErrorCodes
 *
 */
/*-***************************************************************************/
Uint32
Csp1InitializeRc4 (n1_request_type request_type,
         Uint64 context_handle,
#ifdef CAVIUM_MULTICARD_API
         Uint16 key_length, Uint8 * key, Uint32 * request_id,Uint32 dev_id);
#else
         Uint16 key_length, Uint8 * key, Uint32 * request_id);
#endif


/*+****************************************************************************/
/*! \ingroup GP_OPS
 * Csp1EncryptRc4
 *
 *  Encrypts the data provided at input with the key initialized in
 *  the context.
 *
 * \param request_type    CAVIUM_BLOCKING or CAVIUM_NON_BLOCKING
 * \param context_handle  64-bit pointer to context (context_handle\%8=0)
 * \param context_update  UPDATE or NO_UPDATE
 * \param length     size of input in bytes (0<=length<=2^16-1)
 * \param input        pointer to length-byte input
 *
 * \param output     pointer to length-byte output 
 * \param request_id     Unique ID for this request.
 *
 * \if CAVIUM_MULTICARD_API
 * \param dev_id	Device ID
 * \endif
 *
 * \retval SUCCESS 0
 * \retval FAILURE/PENDING #Csp1ErrorCodes
 *
 */
/*-***************************************************************************/
Uint32
Csp1EncryptRc4 (n1_request_type request_type,
      Uint64 context_handle,
      ContextUpdate context_update,
      Uint16 length,
#ifdef CAVIUM_MULTICARD_API
      Uint8 * input, Uint8 * output, Uint32 * request_id,Uint32 dev_id);
#else
      Uint8 * input, Uint8 * output, Uint32 * request_id);
#endif


/*+****************************************************************************/
/*! \ingroup GP_OPS
 * Csp1Initialize3DES
 *
 *    Initializes  3DES state in the context and stores the key in context.
 *
 * \param request_type      CAVIUM_BLOCKING
 * \param context_handle   64-bit pointer to context (context_handle\%8=0)
 * \param iv         pointer to 8-byte initialization vector
 * \param key         pointer to 24-byte key 
 * \param request_id           Unique ID for this request.
 *
 * \if CAVIUM_MULTICARD_API
 * \param dev_id	Device ID
 * \endif
 *
 * \retval SUCCESS 0
 * \retval FAILURE/PENDING #Csp1ErrorCodes
 *
 */
/*-***************************************************************************/
Uint32
Csp1Initialize3DES (n1_request_type request_type,
          Uint64 context_handle,
#ifdef CAVIUM_MULTICARD_API
          Uint8 * iv, Uint8 * key, Uint32 * request_id,Uint32 dev_id);
#else
          Uint8 * iv, Uint8 * key, Uint32 * request_id);
#endif


/*+****************************************************************************/
/*! \ingroup GP_OPS
 * Csp1Encrypt3Des
 *
 *  Encrypts the data provided at input with the key initialized in
 *  the context.
 *
 * \param request_type     CAVIUM_BLOCKING or CAVIUM_NON_BLOCKING
 * \param context_handle  64-bit pointer to context (context_handle\%8=0)
 * \param context_update  UPDATE or NO_UPDATE
 * \param input        pointer to length-byte input
 *\if MC2
 * \param length     size of input in bytes (0<=length<=2^16-32, length\%8=0)
 *\else
 * \param length     size of input in bytes (0<=length<=2^16-8, length\%8=0)
 *\endif 
 * \if MC2
 * \param iv   pointer to 8-byte IV
 * \param key   pointer to 24-byte key
 * \endif
 *
 * \param output   pointer to ROUNDUP8(length)-byte output, 
 * \param request_id   Unique ID for this request.
 *      
 * \if CAVIUM_MULTICARD_API
 * \param dev_id	Device ID
 * \endif
 *
 * \retval SUCCESS 0
 * \retval FAILURE/PENDING #Csp1ErrorCodes
 *
 */
/*-***************************************************************************/
#ifdef MC2
Uint32
Csp1Encrypt3Des (n1_request_type request_type,
       Uint64 context_handle,
       ContextUpdate context_update,
       Uint16 length,
       Uint8 * input,
       Uint8 * output,
#ifdef CAVIUM_MULTICARD_API
       Uint8 * iv, Uint8 * key, Uint32 * request_id,Uint32 dev_id);
#else
       Uint8 * iv, Uint8 * key, Uint32 * request_id);
#endif

#else
Uint32
Csp1Encrypt3Des (n1_request_type request_type,
       Uint64 context_handle,
       ContextUpdate context_update,
       Uint16 length,
#ifdef CAVIUM_MULTICARD_API
       Uint8 * input, Uint8 * output, Uint32 * request_id,Uint32 dev_id);
#else
       Uint8 * input, Uint8 * output, Uint32 * request_id);
#endif

#endif


/*+****************************************************************************/
/*! \ingroup GP_OPS
 * Csp1Decrypt3Des
 *
 *  Decrypts the data provided at input with the key initialized in
 *  the context.
 *
 * \param request_type    CAVIUM_BLOCKING or CAVIUM_NON_BLOCKING
 * \param context_handle  64-bit pointer to context (context_handle\%8=0)
 * \param context_update  UPDATE or NO_UPDATE
 * \param length     size of input in bytes (length\%8=0, 0<=length<=2^16-1)
 * \param input        pointer to length-byte input
 * \if MC2
 * \param iv        pointer to 8-byte IV
 * \param key        pointer to 24-byte key
 * \endif
 *
 * \param output   pointer to length-byte output, 
 * \param request_id   Unique ID for this request.
 *
 * \if CAVIUM_MULTICARD_API
 * \param dev_id	Device ID
 * \endif
 *
 * \retval SUCCESS 0
 * \retval FAILURE/PENDING #Csp1ErrorCodes
 *
 */
/*-***************************************************************************/
#ifdef MC2
Uint32
Csp1Decrypt3Des (n1_request_type request_type,
       Uint64 context_handle,
       ContextUpdate context_update,
       Uint16 length,
       Uint8 * input,
       Uint8 * output,
#ifdef CAVIUM_MULTICARD_API
       Uint8 * iv, Uint8 * key, Uint32 * request_id,Uint32 dev_id);
#else
       Uint8 * iv, Uint8 * key, Uint32 * request_id);
#endif

#else
Uint32
Csp1Decrypt3Des (n1_request_type request_type,
       Uint64 context_handle,
       ContextUpdate context_update,
       Uint16 length,
#ifdef CAVIUM_MULTICARD_API
       Uint8 * input, Uint8 * output, Uint32 * request_id,Uint32 dev_id);
#else
       Uint8 * input, Uint8 * output, Uint32 * request_id);
#endif

#endif


/*+****************************************************************************/
/*! \ingroup GP_OPS
 * Csp1InitializeAES
 *
 *    Initializes  AES state in the context and stores the key in context.
 *
 * \param request_type     CAVIUM_BLOCKING
 * \param context_handle  64-bit pointer to context (context_handle\%8=0)
 * \param aes_type     AES_128, AES_192, or AES_256
 * \param iv        pointer to 16-byte initialization vector
 * \param key        pointer to key, whose length depends on aes_type 
 * \param request_id   Unique ID for this request. (ignored)
 *
 * \if CAVIUM_MULTICARD_API
 * \param dev_id	Device ID
 * \endif
 *
 * \retval SUCCESS 0
 * \retval FAILURE/PENDING #Csp1ErrorCodes
 *
 */
/*-***************************************************************************/
Uint32
Csp1InitializeAES (n1_request_type request_type,
         Uint64 context_handle,
         AesType aes_type,
#ifdef CAVIUM_MULTICARD_API
         Uint8 * iv, Uint8 * key, Uint32 * request_id,Uint32 dev_id);
#else
         Uint8 * iv, Uint8 * key, Uint32 * request_id);
#endif

/*+****************************************************************************/
/*! \ingroup GP_OPS

 * Csp1SrtpAesCtr
 *
 * Performs SRTP (Secure Real Time Protocol) AES-CTR (Counter mode) Encrypt/Decrypt.
 *
 * \param request_type      CAVIUM_BLOCKING or CAVIUM_NON_BLOCKING
 * \param context_handle   64-bit pointer to context (context_handle\%8=0)
 * \param context_update   UPDATE or NO_UPDATE
 * \param aes_type      AES_128 
 * \param length      size of input in bytes (0<=length<=2^16-1)
 * \param input         pointer to length-byte input
 * \if MC2
 * \param iv      pointer to 16- byte IV
 * \param key      pointer to 16- byte key 
 * \endif
 *
 * \param output   pointer to ROUNDUP16(length)-byte output
 * \param request_id   Unique ID for this request.
 *
 * \if CAVIUM_MULTICARD_API
 * \param dev_id	Device ID
 * \endif
 *
 * \retval SUCCESS 0
 * \retval FAILURE/PENDING #Csp1ErrorCodes
 *
 */
/*-***************************************************************************/
#ifdef MC2
Uint32 
Csp1SrtpAesCtr(n1_request_type request_type,
            Uint64 context_handle, 
            ContextUpdate context_update, 
            AesType aes_type, 
            Uint16 length, 
            Uint8 *input, 
            Uint8 *output,
            Uint8 *iv,
            Uint8 *key,
#ifdef CAVIUM_MULTICARD_API
            Uint32 *request_id,Uint32 dev_id
#else
            Uint32 *request_id
#endif
           );

#else
Uint32 
Csp1SrtpAesCtr(n1_request_type request_type,
            Uint64 context_handle, 
            ContextUpdate context_update, 
            AesType aes_type, 
            Uint16 length, 
            Uint8 *input, 
            Uint8 *output,
#ifdef CAVIUM_MULTICARD_API
            Uint32 *request_id,Uint32 dev_id
#else
            Uint32 *request_id
#endif
          );

#endif

/*+****************************************************************************/
/*! \ingroup GP_OPS
 * Csp1ProcessSrtp
 * Performs SRTP (Secure Real Time Protocol) AES-CTR (Counter mode) Encrypt/Decrypt
 *           and Authentication in Single Pass.
 * \param request_type      CAVIUM_BLOCKING or CAVIUM_NON_BLOCKING
 * \param encrypt           0 - encrypt, 1 -decrypt
 * \param keytype           AES_128, AES_192, or AES_256
 * \param authtype          NULL or SHA1 
<<<<<<< cavium_common.h
 * \param in_len            size of input in bytes (0<=length<=2^16-1)
=======
 * \param proto             0 - SRTP, 1 - SRTCP
 * \param in_len            size of input in bytes (0<=length<=2^16-1)
>>>>>>> 1.44
 * \param hdr_ln            size of the hdr in bytes (0 <= hdr_ln <= 72)
 * \param index_ln          size of the Tag len [7:4] and Index len[3:0] in bytes (0 <= index_ln <= 4)
 * \param iv                pointer to 16- byte IV
 * \param key               pointer to key depending upon aes type
 * \param auth_key          pointer to auth_key depending upon auth type
 * \param index             pointer to index depending upon index_ln
 * \param auth_tag          pointer to auth_tag depending upon auth type & encrypt
 * \param input             pointer to ROUNDUP8(length) + ROUNDUP8(hdr_ln) bytes input
 *
 * \param output            pointer to length + ( proto ? Index_ln : 0) + auth_tag[(auth_type&!encrypt)? Tag len : 0] output
 * \param request_id        Unique ID for this request.
 *
 * \if CAVIUM_MULTICARD_API
 * \param dev_id	Device ID
 * \endif
 *
 * \retval SUCCESS 0
 * \retval FAILURE/PENDING #Csp1ErrorCodes
 *
 */
/*-***************************************************************************/

#ifdef MC2
Uint32
Csp1ProcessSrtp(n1_request_type request_type,
                Uint8 encrypt,
                Uint8 keytype,
                Uint8 authtype,
                Uint8 proto,
                Uint16 in_len,
                Uint8 hdr_ln,
                Uint8 index_ln,
                Uint8 *iv,
                Uint8 *key,
                Uint8 *auth_key,
                Uint8 *index,
                Uint8 *auth_tag,
                Uint8 *input,
                Uint8 *output,
#ifdef CAVIUM_MULTICARD_API
                Uint32 *request_id,Uint32 dev_id
#else
                Uint32 *request_id
#endif
                );
#endif

/*+****************************************************************************/
/*! \ingroup MISC
 *
 * Csp1AesXcbcPrf128 
 *
 * Input
 *      request_type = CAVIUM_BLOCKING or CAVIUM_NON_BLOCKING
 *	key = pointer to key
 * 	key_length = size of the key ( 1 <= key_length <= 912)
 *	data = pointer to input data
 * 	data_length = size of input data
 *
 * Output
 *      output = pointer to (AESXCBC_BLOCK_SIZE)-byte output
 *      request_id = Unique ID for this request.
 *
 * \if CAVIUM_MULTICARD_API
 * 		dev_id = Device ID
 * \endif
 *
 * Return Value
 *      0  = success 
 *      >0 = failure or pending
 *      see error_codes.txt
 *
 *-***************************************************************************/
#ifdef MC2
Uint32 
Csp1AesXcbcPrf128(n1_request_type request_type,
	Uint8 *key,
	Uint16 key_length, 
	Uint8 *data, 
	Uint16 data_length,
	Uint8 *output,
#ifdef CAVIUM_MULTICARD_API
	Uint32 *request_id,Uint32 dev_id
#else
	Uint32 *request_id
#endif
	);

#else
Uint32 
Csp1AesXcbcPrf128(n1_request_type request_type,
	Uint8 *key,
	Uint16 key_length, 
	Uint8 *data, 
	Uint16 data_length,
	Uint8 *output,
#ifdef CAVIUM_MULTICARD_API
	Uint32 *request_id,Uint32 dev_id
#else
	Uint32 *request_id
#endif
	);

#endif

/*+****************************************************************************/
/*! \ingroup MISC
 *
 * Csp1AesCfbRfc3826
 *
 * Input
 * \param request_type is either CAVIUM_BLOCKING or CAVIUM_NON_BLOCKING
 * \param key is pointer to key
 * \param aes_type is AES_128=5, AES_192=6, AES_256=7
 * \param iv is Initial Vector 
 * \param data is pointer to input data
 * \param data_length is size of input data
 * \param encrypt  0 for decrypt, 1 for encrypt
 *
 * Output
 * \param output is pointer to (AESXCBC_BLOCK_SIZE)-byte output
 * \param request_id is Unique ID for this request.
 *
 * \if CAVIUM_MULTICARD_API
 * 		dev_id = Device ID
 * \param dev_id	Device ID
 * \endif
 *
 * \if CAVIUM_MULTICARD_API
 * 		dev_id = Device ID
 * \endif
 *
 * Return Value
 *      0  = success 
 *      >0 = failure or pending
 *      see error_codes.txt
 *
 *-***************************************************************************/
#ifdef MC2
Uint32 
Csp1AesCfbRfc3826(n1_request_type request_type,
	Uint8 *key,
	AesType aes_type,
	Uint8 *iv,
	Uint8 *data, 
	Uint16 data_length,
	Uint8 *output,
	Uint8 encrypt, /* 0:1 (decrypt:encrypt) */
#ifdef CAVIUM_MULTICARD_API
	Uint32 *request_id,Uint32 dev_id
#else
	Uint32 *request_id
#endif
	);
#endif
/*+****************************************************************************/
/*! \ingroup GP_OPS
 * Csp1EncryptAes
 *
 *  Encrypts the data provided at input with the key initialized in
 *  the context.
 *
 * \param request_type      CAVIUM_BLOCKING or CAVIUM_NON_BLOCKING
 * \param context_handle   64-bit pointer to context (context_handle\%8=0)
 * \param context_update   UPDATE or NO_UPDATE
 * \param aes_type      AES_128, AES_192, or AES_256
 * \param length      size of input in bytes (0<=length<=2^16-1)
 * \param input         pointer to length-byte input
 * \if MC2
 * \param iv      pointer to 16- byte IV
 * \param key      pointer to key depending upon aes type
 * \endif
 *
 * \param output   pointer to ROUNDUP16(length)-byte output
 * \param request_id   Unique ID for this request.
 *
 * \if CAVIUM_MULTICARD_API
 * \param dev_id	Device ID
 * \endif
 *
 * \retval SUCCESS 0
 * \retval FAILURE/PENDING #Csp1ErrorCodes
 *
 */
/*-***************************************************************************/
#ifdef MC2
Uint32
Csp1EncryptAes (n1_request_type request_type,
      Uint64 context_handle,
      ContextUpdate context_update,
      AesType aes_type,
      Uint16 length,
      Uint8 * input,
#ifdef CAVIUM_MULTICARD_API
      Uint8 * output, Uint8 * iv, Uint8 * key, Uint32 * request_id,Uint32 dev_id);
#else
      Uint8 * output, Uint8 * iv, Uint8 * key, Uint32 * request_id);
#endif

#else
Uint32
Csp1EncryptAes (n1_request_type request_type,
      Uint64 context_handle,
      ContextUpdate context_update,
      AesType aes_type,
      Uint16 length,
#ifdef CAVIUM_MULTICARD_API
      Uint8 * input, Uint8 * output, Uint32 * request_id,Uint32 dev_id);
#else
      Uint8 * input, Uint8 * output, Uint32 * request_id);
#endif

#endif


/*+****************************************************************************/
/*! \ingroup GP_OPS
 * Csp1DecryptAes
 *
 *  Decrypts the data provided at input with the key initialized in
 *  the context.
 *
 * \param request_type     CAVIUM_BLOCKING or CAVIUM_NON_BLOCKING
 * \param context_handle  64-bit pointer to context (context_handle\%8=0)
 * \param context_update  UPDATE or NO_UPDATE
 * \param aes_type     AES_128, AES_192, or AES_256
 * \param length     size of input in bytes (length\%16=0, 0<=length<=2^16-1)
 * \param input        pointer to length-byte input
 * \if MC2
 * \param iv        pointer to 16- byte IV
 * \param key        pointer to key depending upon aes type
 * \endif
 *
 * \param output    pointer to length-byte output
 * \param request_id    Unique ID for this request.
 *
 * \if CAVIUM_MULTICARD_API
 * \param dev_id	Device ID
 * \endif
 *
 * \retval SUCCESS 0
 * \retval FAILURE/PENDING #Csp1ErrorCodes
 *
 */
/*-***************************************************************************/
#ifdef MC2
Uint32
Csp1DecryptAes (n1_request_type request_type,
      Uint64 context_handle,
      ContextUpdate context_update,
      AesType aes_type,
      Uint16 length,
      Uint8 * input,
#ifdef CAVIUM_MULTICARD_API
      Uint8 * output, Uint8 * iv, Uint8 * key, Uint32 * request_id,Uint32 dev_id);
#else
      Uint8 * output, Uint8 * iv, Uint8 * key, Uint32 * request_id);
#endif

#else
Uint32
Csp1DecryptAes (n1_request_type request_type,
      Uint64 context_handle,
      ContextUpdate context_update,
      AesType aes_type,
      Uint16 length,
#ifdef CAVIUM_MULTICARD_API
      Uint8 * input, Uint8 * output, Uint32 * request_id,Uint32 dev_id);
#else
      Uint8 * input, Uint8 * output, Uint32 * request_id);
#endif

#endif

#ifdef MC2
/*+****************************************************************************/
/*! \ingroup GP_OPS
 * Csp1EncryptAesGcmGmac
 *
 *  Encrypts+Authenticates/authenticates the data provided at input 
 *  with the key initialized in the context.
 *
 * \param request_type      CAVIUM_BLOCKING or CAVIUM_NON_BLOCKING
 * \param context_handle   64-bit pointer to context (context_handle\%8=0)
 * \param context_update   UPDATE or NO_UPDATE
 * \param aes_type      AES_128, AES_192, or AES_256
 * \param length      size of input in bytes (0<=length<=2^16-1)
 * \param input         pointer to length-byte input
 * \param aad         pointer to aditional authentication data
 *                    (aad length includes SPI and sequence number (8Bytes).
 *                    and + 4 bytes if esequence number is implemented) in case
 *                    of GCM. In GMAC, input length is 0, the payload data is 
 *                    included in the AAD data.
 * \param eseqnumber   when = 1, extended sequence number is included in AAD.
 * \param gcm_gmac_bit  when set, gmac is done
 * \if MC2
 * \param iv      pointer to 16- byte IV
 * \param key      pointer to key depending upon aes type
 * \endif
 *
 * \param output   pointer to ROUNDUP16(length)-byte output
 * \param request_id   Unique ID for this request.
 *
 * \if CAVIUM_MULTICARD_API
 * \param dev_id	Device ID
 * \endif
 *
 * \retval SUCCESS 0
 * \retval FAILURE/PENDING #Csp1ErrorCodes
 *
 */
/*-***************************************************************************/
Uint32
Csp1EncryptAesGcmGmac (n1_request_type request_type,
      Uint64 context_handle,
      ContextUpdate context_update,
      AesType aes_type,
      Uint16 length,
      Uint8 *input,
      Uint8 *aad,
      Uint8 eseqnumber,
      Uint8 *output, Uint8 gcm_gmac_bit, Uint8 *iv, Uint8 *key, 
#ifdef CAVIUM_MULTICARD_API
      Uint32 *request_id,Uint32 dev_id
#else
      Uint32 *request_id
#endif
      );

/*+****************************************************************************
 *
 * Csp1DecryptAesGcm
 *
 * Input
 *      request_type = CAVIUM_BLOCKING or CAVIUM_NON_BLOCKING
 *      context_handle = 64-bit pointer to context (context_handle%8=0)
 *      context_update = UPDATE or NO_UPDATE
 *      aes_type     = AES_128, AES_192, or AES_256
 *      length       = size of input in bytes (length%16=0, 0<=length<=2^16-1)
 *      input        = pointer to length-byte input in case of GCM
 *      eseqnum      = extented sequence number bit
 *      tag_length   = can be 4, 8. 12 and 16B
 *      aad          = pointer to AAD data incase of GCM, 
 *                     pointer to length-byte AAD in GMAC
 *      output       = pointer to length-byte output in GCM, 
 *                     pointer to 0B output in case of GMAC. 
 *      gcm_gmac_bit = set if GMAC, otherwise GCM
 *      iv = pointer to 16- byte IV
 *      key = pointer to key depending upon aes type
 *
 * Output
 *      output = pointer to length-byte output
 *      request_id = Unique ID for this request.
 *
<<<<<<< cavium_common.h
 * \if CAVIUM_MULTICARD_API
 * 		dev_id	= Device ID
 * \endif
 *
=======
 * \if CAVIUM_MULTICARD_API
 * 		dev_id = Device ID
 * \endif
 *
>>>>>>> 1.44
 * Return Value
 *   0  = success 
 * >0 = failure or pending
 * see error_codes.txt
 *
 *-***************************************************************************/

Uint32 
Csp1DecryptAesGcm(n1_request_type request_type,
            Uint64 context_handle, 
            ContextUpdate context_update, 
            AesType aes_type, 
            Uint16 length, 
            Uint8 *input, 
            Uint8 eseqnumber,           
            Uint16 tag_length,
            Uint8 *aad,
            Uint8 *output,
            Uint8 gcm_gmac_bit,
            Uint8 *iv,
            Uint8 *key,
                 
#ifdef CAVIUM_MULTICARD_API
            Uint32 *request_id,Uint32 dev_id
#else
            Uint32 *request_id
#endif
           );
#endif

#ifdef MC2
/*+****************************************************************************
 *
 * Csp1Hash
 *
 * Compute the HASH of a complete message. Does not use context.
 *
 * \param request_type	CAVIUM_BLOCKING or CAVIUM_NON_BLOCKING
 * \param hash_type	MD5_TYPE or SHA1_TYPE or SHA256_TYPE
 * \param message_length	size of input in bytes (0<=message_length<=2^16-1)
 * \param message	pointer to length bytes of input to be HMACed
 * \param hash	pointer to the hash_size HASH result 
 * \param request_id	Unique ID for this request.
 *
 * \if CAVIUM_MULTICARD_API
 * \param dev_id	Device ID
 * \endif
 *
 * \retval SUCCESS 0
 * \retval FAILURE/PENDING #Csp1ErrorCodes
 */
 /*-***************************************************************************/
Uint32 
Csp1Hash(n1_request_type request_type,
    HashType hash_type, 
    Uint16 message_length, 
    Uint8 *message, 
    Uint8 *hash,
#ifdef CAVIUM_MULTICARD_API
    Uint32 *request_id,Uint32 dev_id);
#else
    Uint32 *request_id);
#endif

#endif
#define INC32(a)        {\
            Uint32 __tmp__    = (Uint32)a;\
            __tmp__    = (__tmp__ + 1)&0xffffffffL;\
            a       = __tmp__;\
         }

#endif /*CSP1_KERNEL */

#ifdef MC2
#define IPSEC_CONTEXT_SIZE 512
#else
#define IPSEC_CONTEXT_SIZE 128
#endif

Uint32 Csp1GetDevCnt(Uint32 *pdev_count,Uint8 *dev_mask);
Uint32 Csp1GetDevType(Uint32 *device);

#ifdef CAVIUM_MULTICARD_API
extern int default_device;
#define CAVIUM_DEV_ID  default_device
#define MAX_DEV_CNT 4
extern int gpkpdev_hdlr[];
#endif


#endif /* _CAVIUM_COMMON_H_ */

/*
 * $Id: cavium_common.h,v 1.45 2009/09/09 14:13:36 aravikumar Exp $
 * $Log: cavium_common.h,v $
 * Revision 1.45  2009/09/09 14:13:36  aravikumar
 * NPLUS macro dependency removed and made it dynamic
 *
 * Revision 1.44  2009/08/07 07:10:59  rdhana
 * Removed returning of SRTP header at output.
 *
 * Revision 1.43  2009/07/27 14:00:37  kkiran
 *  - Edited documentation for Csp1GetAllResults
 *
 * Revision 1.42  2009/07/27 13:55:04  kkiran
 * - Edited documentation.
 *
 * Revision 1.41  2009/07/27 12:14:28  kkiran
 *  - Documentation for Csp1GetAllResults and SpeedTestInfoResult added.
 *
 * Revision 1.40  2009/07/24 12:26:14  pnalla
 * - Added function prototype for Csp1GetAllResults.
 *
 * Revision 1.39  2009/07/22 10:44:03  pnalla
 * Context memory is increased from 256 bytes to 512 as microcode expects.
 *
 * Revision 1.38  2009/07/17 12:45:27  aravikumar
 * Added dev_id info
 *
 * Revision 1.37  2009/07/03 07:09:53  rdhana
 * Updated SRTP_AES_CTR to support variable Tag len and non-returning of ROC incase of SRTP.
 * API changes:
 * minor OPcode[6] = 0 - SRTP and 1 - SRTCP
 * Param2[15:12] =  Tag length in bytes.
 * Param2[11:8]  =  Index length in bytes
 *
 * Revision 1.36  2009/06/23 08:34:03  kmonendra
 * Updating member of Speed_Test_Info.
 *
 * Revision 1.35  2009/06/22 06:55:01  rsruthi
 * -- Added AES_CFB Support.
 *
 * Revision 1.34  2009/06/18 09:54:27  rdhana
 * Added IPv6 Extension header and Selector Check support.
 *
 * Revision 1.33  2009/04/07 05:48:47  kmonendra
 * Added request type CAVIUM_SPEED for speedtest.
 *
 * Revision 1.32  2009/04/07 05:33:06  kmonendra
 e Added Speed_Test_Info structure and SpeedTestResult() for speedtest.
 *
 * Revision 1.31  2009/03/14 10:16:36  jsrikanth
 * Operation and keybuf alignment for 32bit app on 64bit driver
 *
 * Revision 1.30  2009/03/10 11:49:32  rdhana
 * Added Single PASS [AES_xxx + SHA1] SRTP support in SSL and IPSEC.
 *
 * Revision 1.29  2009/01/09 05:54:39  kmaheshwar
 * Added AesXcbcPrf128 (RFC 3566,3664, and 4434) support and it is disabled in Makefile
 *
 * Revision 1.28  2008/12/22 05:43:42  jrana
 * - OPCODES added
 *
 * Revision 1.27  2008/11/06 09:13:21  ysandeep
 * Removed PX_PLUS
 *
 * Revision 1.26  2008/10/16 09:26:47  aramesh
 * default_device varibale added.
 *
 * Revision 1.25  2008/10/15 08:03:39  ysandeep
 * Multicard support for NPLUS added.
 *
 * Revision 1.24  2008/08/12 10:47:53  aramesh
 * deleted gpkpdev_keyhandle.
 *
 * Revision 1.23  2008/08/11 10:21:31  aramesh
 * CAVIUM_DEV_ID is changed to 0.
 *
 * Revision 1.22  2008/07/29 14:51:51  aramesh
 * N1_GET_STATUS_DDR is added.
 *
 * Revision 1.21  2008/07/07 12:33:13  aramesh
 * Csp1GetDevCnt api parameters are chnaged.
 *
 * Revision 1.20  2008/07/03 09:55:44  aramesh
 * added Csp1GetDevType API definition.
 *
 * Revision 1.18  2008/06/03 07:16:29  rsruthi
 * - Added AesGCM/GMAC Encrypt/Decrypt APIs, added additional parameter, IV in Csp1Hmac for SHA2 SUPPORT.
 *
 * Revision 1.17  2008/04/25 05:53:32  rdhana
 * Added the FRAG_SUPPORT code in normal flow and removed FRAG_SUPPORT define.
 *
 * Revision 1.16  2008/03/06 11:41:34  jsrikanth
 * Doxygen format changes
 *
 * Revision 1.15  2008/02/22 09:37:33  aramesh
 * defined CAVIUM_NO_MMAP and  INTERRUPT_ON_COMP.
 *
 * Revision 1.14  2008/02/04 07:45:02  kmaheshwar
 * Added Csp1SrtpAesCtr
 *
 * Revision 1.13  2007/12/07 05:24:18  ksadasivuni
 * 1.  changed context memory to use buffer pool as px doesn't have DDR
 * 2.  PX_ECC_FreeContext now takes cid argument
 *
 * Revision 1.12  2007/12/03 06:19:24  ksadasivuni
 * - ecrng random int inital checkin
 *
 * Revision 1.11  2007/11/30 07:05:30  ksadasivuni
 * ECRNG generate random string done.
 *
 * Revision 1.10  2007/11/21 07:07:33  ksadasivuni
 * all driver load messages now will be printed at CAVIUM_DEBUG_LEVEL>0
 *
 * Revision 1.9  2007/11/19 11:11:55  lpathy
 * ported to 64 bit windows.
 *
 * Revision 1.8  2007/09/10 10:13:17  kchunduri
 * --Define new API to accept "dev_id" as input parameter.
 *
 * Revision 1.7  2007/07/04 04:49:58  kchunduri
 * --IOCTL for returning nitrox devices detected.
 *
 * Revision 1.6  2007/06/11 13:38:07  tghoriparti
 * DMA_MAP error code added
 *
 * Revision 1.5  2007/03/08 20:44:58  panicker
 * * NPLUS mode changes. pre-release
 * * NitroxPX now supports N1-style NPLUS operation.
 * * Native PX mode PLUS operations are enabled only if PX_PLUS flag is enabled
 *
 * Revision 1.4  2007/03/06 02:16:59  panicker
 * * PX will use the same core id lookup mechanism as N1. So core_t is now
 *   defined for PX (minus the ctp & srq fields).
 * * From MICROCODE structure removed core_mask for PX; included core_id.
 *   get_core_mask() will work the same way for N1 and PX.
 *
 * Revision 1.3  2007/02/02 02:39:06  panicker
 * * DebugRWReg uses unsigned long - since they may send/receive addresses.
 *
 * Revision 1.2  2007/01/13 01:18:19  panicker
 * -  core_t, softreq_t structure defs not required in PX for NPLUS mode.
 * -  core_id, paired_cores etc in MICROCODE not required in PX for NPLUS mode.
 * -  core_mask is added to MICROCODE for PX mode.
 *
 * Revision 1.1  2007/01/06 02:47:40  panicker
 * * first cut - NITROX PX driver
 *
 * Revision 1.39  2006/08/23 05:46:58  pnalla
 * Added Fragmentation and UDP Encapsulation support
 *
 * Revision 1.38  2006/08/21 11:05:38  ksnaren
 * Fixed compilation errors for FreeBSD6.1
 *
 * Revision 1.37  2006/08/16 14:14:50  kchunduri
 * --defined new field to store 'status' of OPERATION.
 *
 * Revision 1.36  2006/08/08 13:14:40  kchunduri
 * removed C++ style comments and moved MACROS related to 64-bit port from cavium_sysdep.h to enable freebsd compilation
 *
 * Revision 1.35  2006/08/01 08:02:05  kchunduri
 * Modified DebugRWReg to fix POTS RANDOM TEST failure on PPC-64Bit
 *
 * Revision 1.34  2006/05/16 09:38:14  kchunduri
 * --fields in API structures aligned so that structure size is same on both 32bit and 64 bit platforms.
 *
 * Revision 1.33  2006/04/17 04:08:09  kchunduri
 * --defined new type Csp1StatusOperationBuffer for Csp1GetAllResults --kiran
 *
 * Revision 1.32  2006/03/27 04:58:30  kchunduri
 * --kchunduri new type Csp1RequestStatusBuffer to support api Csp1GetAllResults
 *
 * Revision 1.31  2006/03/24 09:47:07  pyelgar
 *   - Checkin of Scatter/Gather code changes in driver and IPSec.
 *
 * Revision 1.30  2005/12/22 10:17:35  ksadasivuni
 * - NPLUS Release. Freeswan klips code is assuming ipsec context size of 128, driver is assuming 256 for MC2.
 *   Moved IPSEC_CONTEXT_SIZE #define to cavium_common.h
 *
 * Revision 1.29  2005/11/17 13:31:09  kanantha
 * Updating with the 64 bit modifications, with proper matching of data types
 *
 * Revision 1.28  2005/10/20 10:03:11  phegde
 * - Added 2 new function prototypes called Csp1WriteIpsecSa() and Csp1ProcessPacket() to support for IPSec functionality
 *
 * Revision 1.27  2005/10/13 08:56:40  ksnaren
 * removed compile warning
 *
 * Revision 1.26  2005/09/28 15:53:37  ksadasivuni
 * - Merging FreeBSD 6.0 AMD64 release with CVS Head
 *
 * Revision 1.25  2005/09/27 05:29:50  sgadam
 * Compilation error in FC4 fixed
 *
 * Revision 1.24  2005/09/21 06:37:44  lpathy
 * Merging windows server 2003 release with CVS head
 *
 * Revision 1.23  2005/09/08 12:56:26  sgadam
 * - Csp1Hash prototype Added
 *
 * Revision 1.22  2005/06/03 07:29:46  rkumar
 * Priority associated commands in SRQ
 *
 * Revision 1.21  2005/02/01 04:12:05  bimran
 * copyright fix
 *
 * Revision 1.20  2005/01/06 18:43:32  mvarga
 * Added realtime support
 *
 * Revision 1.19  2004/06/23 19:06:20  bimran
 * NetBSD port.
 * Fixed cavium_dump to become OSI
 *
 * Revision 1.18  2004/05/04 00:27:02  danny
 * 2.00b documentation ver 0.01, doxygen ccmment corrections
 *
 * Revision 1.17  2004/05/03 23:30:08  danny
 * Added Doxygen formating to header files
 *
 * Revision 1.16  2004/05/03 22:33:21  danny
 * Added Doxygen formating to header files
 *
 * Revision 1.15  2004/05/03 20:33:13  bimran
 * Removed all references to CAVIUM_IKE context_type.
 *
 * Revision 1.14  2004/05/03 19:53:57  bimran
 * Added all error codes.
 *
 * Revision 1.13  2004/05/02 19:45:59  bimran
 * Added Copyright notice.
 *
 * Revision 1.12  2004/05/01 07:15:35  bimran
 * Added non-blocking error codes.
 *
 * Revision 1.11  2004/05/01 05:58:06  bimran
 * Fixed a function descriptions on each function to match with the latest microcode and driver.
 *
 * Revision 1.10  2004/04/28 03:14:59  bimran
 * Fixed comments.
 *
 * Revision 1.9  2004/04/26 23:29:23  bimran
 * Removed unused data types.
 *
 * Revision 1.8  2004/04/26 22:32:52  tsingh
 * Fixed some typedefs for MC2 (bimran).
 *
 * Revision 1.7  2004/04/23 21:49:34  bimran
 * Csp1Initialze now accepts microcode type to support Plus mode.
 *
 * Revision 1.6  2004/04/22 02:49:34  bimran
 * Removed enumerated error codes from microcode.
 *
 * Revision 1.5  2004/04/22 01:12:11  bimran
 * Moved NPLUS related structures around to avoid compilation problems with user mode programs like nplus_init.
 *
 * Revision 1.4  2004/04/21 20:00:29  bimran
 * NPLUS support.
 *
 * Revision 1.3  2004/04/20 17:45:11  bimran
 * Defined microcode structure.
 * Some early NPLUS related changes.
 *
 * Revision 1.2  2004/04/17 01:37:49  bimran
 * Fixed includes.
 * Added function protos.
 *
 * Revision 1.1  2004/04/15 22:40:50  bimran
 * Checkin of the code from India with some cleanups.
 *
 */
