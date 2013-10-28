/* cavium.h  */ 
/*
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
 * 3. All manuals,brochures,user guides mentioning features or use of this software 
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
 */

#ifndef _CAVIUM_H_
#define _CAVIUM_H_

#include "cavium_sysdep.h"
#include "cavium_endian.h"
#include "cavium_list.h"

#define INTERRUPT_ON_COMP
#define INTERRUPT_COALESCING



/****************************************************************************/
/* PKP Register Offsets                                                     */
/****************************************************************************/
/* define register offsets here */


#define BAR_0            0x10
#define BAR_1            0x18
#define BAR_2            0x20
#define BAR_3            0x28

#define PCI_CONFIG_04         0x4
#define PCI_CONFIG_58         0X58
#define PCI_CONFIG_4C         0x4C
#define PCI_CACHE_LINE         0x0C
#define PCIX_SPLIT_TRANSACTION      0xE0
#ifndef PCI_INTERRUPT_LINE
#define PCI_INTERRUPT_LINE      0x3C
#endif

#define N1_DEVICE           0x0001
#define N1_LITE_DEVICE      0x0003
#define NPX_DEVICE          0x0010
#define CN15XX              15
#define CN16XX              16

extern Uint32  csrbase_a_offset;
extern Uint32  csrbase_b_offset;


#define NITROX_PX_MAX_GROUPS        4

#define CSRBASE_A                   csrbase_a 
#define CSRBASE_B                   csrbase_b
#define BASE_A_OFFSET               csrbase_a_offset
#define BASE_B_OFFSET               csrbase_b_offset




/*BAR 0*/
#define COMMAND_STATUS               (BASE_A_OFFSET + 0x00)
#define UNIT_ENABLE                  (BASE_A_OFFSET + 0x10)
#define IMR_REG                      (BASE_A_OFFSET + 0x20)
#define ISR_REG                      (BASE_A_OFFSET + 0x28)
#define FAILING_SEQ_REG              (BASE_A_OFFSET + 0x30)
#define FAILING_EXEC_REG             (BASE_A_OFFSET + 0x38)
#define ECH_STAT_COUNTER_HIGH_REG    (BASE_A_OFFSET + 0x88)
#define ECH_STAT_COUNTER_LOW_REG     (BASE_A_OFFSET + 0x90)
#define EPC_STAT_COUNTER_HIGH_REG    (BASE_A_OFFSET + 0x98)
#define EPC_STAT_COUNTER_LOW_REG     (BASE_A_OFFSET + 0xA0)
#define PMLT_STAT_COUNTER_LOW_REG    (BASE_A_OFFSET + 0xA8)
#define PMLT_STAT_COUNTER_HIGH_REG   (BASE_A_OFFSET + 0xB0)
#define CLK_STAT_COUNTER_HIGH_REG    (BASE_A_OFFSET + 0xB8)
#define CLK_STAT_COUNTER_LOW_REG     (BASE_A_OFFSET + 0xC0)
#define PCI_ERR_REG                  (BASE_A_OFFSET + 0xD0)
#define DEBUG_REG                    (BASE_A_OFFSET + 0x68)
#define CMC_CTL_REG                  (BASE_A_OFFSET + 0xD8)
#define UCODE_LOAD                   (BASE_A_OFFSET + 0x18)
#define PSE_TO_HOST_DATA             (BASE_A_OFFSET + 0x58)
#define HOST_TO_PSE_DATA             (BASE_A_OFFSET + 0x60)

#ifdef INTERRUPT_COALESCING
#define GENINT_COUNT_THOLD_REG       (BASE_A_OFFSET + 0x280)
#define GENINT_COUNT_INT_TIME_REG    (BASE_A_OFFSET + 0x288)
#define GENINT_COUNT_REG             (BASE_A_OFFSET + 0x290)
#define GENINT_COUNT_TIME_REG        (BASE_A_OFFSET + 0x298)
#define GENINT_COUNT_SUB_REG         (BASE_A_OFFSET + 0x2A0)
#endif
/*BAR 1*/
#define  REQ0_BASE_HIGH              (BASE_B_OFFSET + 0x00)
#define  REQ0_BASE_LOW               (BASE_B_OFFSET + 0x08)
#define  REQ0_SIZE                   (BASE_B_OFFSET + 0x10)

#define  REQ1_BASE_HIGH              (BASE_B_OFFSET + 0x20)
#define  REQ1_BASE_LOW               (BASE_B_OFFSET + 0x28)
#define  REQ1_SIZE                   (BASE_B_OFFSET + 0x30)

#define  REQ2_BASE_HIGH              (BASE_B_OFFSET + 0x40)
#define  REQ2_BASE_LOW               (BASE_B_OFFSET + 0x48)
#define  REQ2_SIZE                   (BASE_B_OFFSET + 0x50)

#define  REQ3_BASE_HIGH              (BASE_B_OFFSET + 0x60)
#define  REQ3_BASE_LOW               (BASE_B_OFFSET + 0x68)
#define  REQ3_SIZE                   (BASE_B_OFFSET + 0x70)

#define REQ0_DOOR_BELL               (BASE_B_OFFSET + 0x18)
#define REQ1_DOOR_BELL               (BASE_B_OFFSET + 0x38)
#define REQ2_DOOR_BELL               (BASE_B_OFFSET + 0x58)
#define REQ3_DOOR_BELL               (BASE_B_OFFSET + 0x78)


#define REG_EXEC_GROUP               (BASE_A_OFFSET + 0x2A8)


/*LDT specific registers */
#define LMT_CONTROL_REG               0xC0
#define LMT_INTERRUPT_CONTROL_REG      0xC8
#define LMT_INTERRUPT_DESTINATION_REG   0xD0
#define LMT_ERROR_REG               0xD8
#define LMT_EXPECTED_CRC_REG         0xE0
#define LMT_RCVD_CRC_REG            0xE8


/****************************************************************************/
/* Software specific macros                                       */
/****************************************************************************/


//#ifdef NITROX_PX
//#define MAX_CORES_NITROX   8 
//#else
#define MAX_CORES_NITROX   24
//#endif   

   
//#if defined(CN1010)||defined(CN1005)||defined(CN1001)||defined(CN501)
//#define MAX_N1_QUEUES         2
//#else
#define MAX_N1_QUEUES         4
//#endif

#define COMMAND_BLOCK_SIZE      32
#define COMPLETION_CODE_INIT      (Uint64)0xFFFFFFFFFFFFFFFFULL
#define COMPLETION_CODE_SIZE      8

#ifdef MC2

#if CAVIUM_ENDIAN == __CAVIUM_LITTLE_ENDIAN
#define COMPLETION_CODE_SHIFT      0
#else
#define COMPLETION_CODE_SHIFT      56
#endif

#define CTP_COMMAND_BLOCK_SIZE      32
#define CTP_QUEUE_SIZE         64   
#define SCRATCHPAD_SIZE         4096

#else /* MC1 */
#if CAVIUM_ENDIAN == __CAVIUM_LITTLE_ENDIAN
#define COMPLETION_CODE_SHIFT      56
#else
#define COMPLETION_CODE_SHIFT      0
#endif

#endif

#define DRAM_BASE         (Uint32)0

#define CONTEXT_OFFSET         4194304

#define DRAM_CAS_LATENCY_INCR      1

#define CAVIUM_DEFAULT_TIMEOUT		(15*CAVIUM_HZ) /* 4 seconds*/
	/* This should be greater than the Microcode's timeout */
/* SRQ Timeout is (MAX_SRQ_TIMEOUT + 1)*CAVIUM_DEFAULT_TIMEOUT*/
#define MAX_SRQ_TIMEOUT         1

#define DOOR_BELL_THRESHOLD      1


/* FSK memory */
#define FSK_BASE         48   
#define FSK_MAX            (8192 - FSK_BASE)
//#define FSK_CHUNK_SIZE      2*640      
#define FSK_CHUNK_SIZE      (2*640)      

/* Extended Key memory stuff */
#define EX_KEYMEM_BASE   DRAM_BASE
#define EX_KEYMEM_MAX   CONTEXT_OFFSET
#define EX_KEYMEM_CHUNK_SIZE   1024   

/* Host Key memory */
#define HOST_KEYMEM_MAX     (512*1024)
#define HOST_KEYMEM_CHUNK_SIZE (2*640)



#define SWAP_SHORTS_IN_64(val)               \
   ((val & (Uint64)0xff00000000000000ULL) >> 8)      \
         |                     \
   ((val & (Uint64)0x00ff000000000000ULL) << 8)      \
         |                     \
   ((val & (Uint64)0x0000ff0000000000ULL) >> 8)      \
         |                     \
   ((val & (Uint64)0x000000ff00000000ULL) << 8)      \
         |                     \
   ((val & (Uint64)0x00000000ff000000ULL) >> 8)      \
         |                     \
   ((val & (Uint64)0x0000000000ff0000ULL) << 8)      \
         |                     \
   ((val & (Uint64)0x000000000000ff00ULL) >> 8)      \
         |                     \
   ((val & (Uint64)0x00000000000000ffULL) << 8)      \

#define SPLIT_TRANSACTION_MASK            0x00700000
/* cavium_special_queue_size */
#define CAVIUM_SPECIAL_QUEUE_SIZE	1000
/* 
 * error codes used in handling error interrupts
 */
typedef enum
{
 /* hard reset group ( the tough guys )*/
 ERR_PCI_MASTER_ABORT_WRITE=2,
 ERR_PCI_TARGET_ABORT_WRITE,
 ERR_PCI_MASTER_RETRY_TIMEOUT_WRITE,
 ERR_OUTBOUND_FIFO_CMD,
 ERR_KEY_MEMORY_PARITY,

 /*soft reset group */
 ERR_PCI_MASTER_ABORT_REQ_READ,
 ERR_PCI_TARGET_ABORT_REQ_READ,
 ERR_PCI_MASTER_RETRY_TIMEOUT_REQ_READ,
 ERR_PCI_MASTER_DATA_PARITY_REQ_READ,
 ERR_REQ_COUNTER_OVERFLOW,

 /*EXEC reset group */
 ERR_EXEC_REG_FILE_PARITY,
 ERR_EXEC_UCODE_PARITY,

 /*seq number based errors */
 ERR_PCI_MASTER_ABORT_EXEC_READ,
 ERR_PCI_TARGET_ABORT_EXEC_READ,
 ERR_PCI_MASTER_RETRY_TIMOUT_EXEC_READ,
 ERR_PCI_MASTER_DATA_PARITY_EXEC_READ,
 ERR_EXEC_GENERAL,
 ERR_CMC_DOUBLE_BIT,
 ERR_CMC_SINGLE_BIT   
}PKP_ERROR;


/*
 * Error codes in DDR discovery
 */
typedef enum
{
   ERR_INIT_TWSI_FAILURE =100,
   ERR_DDR_NO_EEPROM_PRESENT,
   ERR_DDR_MEMORY_NOT_SRAM_DDR,
   ERR_DDR_UNSUPPORTED_NUM_COL_ADDR,
   ERR_DDR_UNSUPPORTED_NUM_ROW_ADDR,
   ERR_DDR_MORE_THAN_1_PHYS_BANK,
   ERR_DDR_UNSUPPORTED_MODULE_DATA_WIDTH,
   ERR_DDR_UNSUPPORTED_VOLT_INTERFACE_LEVEL,
   ERR_DDR_SDRAM_CYCLE_TIME_TOO_SHORT,
   ERR_DDR_UNSUPPORTED_MODULE_CONFIG,
   ERR_DDR_UNSUPPORTED_REFRESH_CLOCK,
   ERR_DDR_UNSUPPORTED_PRIMARY_SDRAM_WIDTH,
   ERR_DDR_REQUIRE_BURST_LENGTH_2,
   ERR_DDR_REQUIRE_4_DEV_BANKS,
   ERR_DDR_UNSUPPORTED_CAS_LATENCY,
   ERR_DDR_UNSUPPORTED_MODULE_BANK_DENSITY,
}DDR_ERROR;

typedef enum {huge_pool = 0, large, medium, small, tiny, ex_tiny, os} pool;

#define BUF_POOLS    6

#define ALIGNMENT   8
#define ALIGNMENT_MASK   (~(0x7L))


#define MAX_FRAGMENTS 32
typedef struct 
{
   struct cavium_list_head list;
   struct cavium_list_head alloc_list;
   Uint8 *big_buf;
   int frags_count;
   int index;
   pool p;
   Uint16 free_list[MAX_FRAGMENTS];
   Uint8 *address[MAX_FRAGMENTS];
   int free_list_index;
   int not_allocated;
} cavium_frag_buf_t;

typedef struct 
{
   cavium_spinlock_t buffer_lock;

   int chunks;
   int chunk_size;
   int real_size;  /* chunk size + tag size*/

#define MAX_BUFFER_CHUNKS      1500
   Uint8 *base;
   Uint8 *address[MAX_BUFFER_CHUNKS];
   Uint8 *address_trans[MAX_BUFFER_CHUNKS];
   Uint16 free_list[MAX_BUFFER_CHUNKS];
   int free_list_index;
   struct cavium_list_head frags_list;
} cavium_buffer_t;


#define MAX_DEV   4
typedef struct _pkp_device
{
Uint32 device_id;
Uint32 px_flag;
Uint8 *csrbase_a;
Uint8 *csrbase_b;

void *dev; /* Platform specific device. For OSI it is opaque */
int       dram_present;/* flag. 1 = dram is local.0 = dram is implemented at host*/
Uint32    dram_max; /* total dram size.*/
ptrlong   dram_base; /* dram base address */
Uint32    dram_chunk_count;
Uint32    cmc_ctl_val; /* Context memory control register value*/

Uint32 bus_number;
Uint32 dev_number;
Uint32 func_number;
//#if defined(NITROX_PX)
ptrlong bar_px_hw;
Uint8  *bar_px;
//#else
ptrlong bar_0;
ptrlong bar_1;
//#endif
unsigned int interrupt_pin;
Uint32 uen;
Uint32 exec_units;
Uint32 boot_core_mask;
int   enable;
Uint32 imr;
cavium_wait_channel cav_poll;

/* command queue */
Uint32 command_queue_max;
Uint8 *command_queue_front[MAX_N1_QUEUES];
Uint8 *command_queue_end[MAX_N1_QUEUES];
Uint8 *command_queue_base[MAX_N1_QUEUES];
cavium_dmaaddr command_queue_bus_addr[MAX_N1_QUEUES];
Uint8 *real_command_queue_base[MAX_N1_QUEUES];
cavium_dmaaddr real_command_queue_bus_addr[MAX_N1_QUEUES];
Uint32 command_queue_size;
cavium_spinlock_t command_queue_lock[MAX_N1_QUEUES];
ptrlong door_addr[MAX_N1_QUEUES];
Uint32 door_bell_count[MAX_N1_QUEUES];
Uint32 door_bell_threshold[MAX_N1_QUEUES];

#ifdef MC2
Uint8 *ctp_base;
/*the following elements hold the bus addresses*/
cavium_dmaaddr ctp_base_busaddr;
Uint8 *scratchpad_base;
cavium_dmaaddr scratchpad_base_busaddr;
Uint64 *error_val;
cavium_dmaaddr error_val_busaddr;
#endif

/* Context memory pool */
volatile Uint32 ipsec_chunk_count;
volatile Uint32 ssl_chunk_count;
volatile Uint32 ctx_ipsec_free_index;
volatile Uint32 ctx_ipsec_put_index;
volatile Uint32 ctx_ssl_free_index;
ptrlong *ctx_free_list;
ptrlong *org_ctx_free_list;
#ifdef DUMP_FAILING_REQUESTS
ptrlong *org_busctx_free_list;
#endif
cavium_spinlock_t ctx_lock;
int ctx_ipsec_count;
int ctx_ssl_count;

/* Key Memory */
cavium_spinlock_t keymem_lock;
struct cavium_list_head keymem_head;

Uint32 fsk_chunk_count;
Uint16 *fsk_free_list;
volatile Uint32 fsk_free_index;

Uint32 ex_keymem_chunk_count;
Uint32 *ex_keymem_free_list;
volatile Uint32 ex_keymem_free_index;

Uint32 host_keymem_count;
Uint32 *host_keymem_free_list;
struct PKP_BUFFER_ADDRESS *host_keymem_static_list;
volatile Uint32 host_keymem_free_index;

/* pending free list */
Uint32 pending_free_max;
Uint32 pending_special_max;
Uint32   pending_free_index;
Uint32  special_free_index;
ptrlong   *pending_free_list;
struct PENDING_ENTRY *pending_entry_array;
cavium_spinlock_t   pending_free_lock;

/* direct free list */
volatile Uint32 direct_free_max;
volatile Uint32 direct_free_index;
ptrlong *direct_free_list;
struct PKP_DIRECT_OPERATION_STRUCT  *direct_entry_array;
cavium_spinlock_t   direct_free_lock;

/* sg free list */
volatile Uint32 sg_free_max;
volatile Uint32 sg_free_index;
ptrlong *sg_free_list;
struct PKP_SG_OPERATION_STRUCT  *sg_entry_array;
cavium_spinlock_t sg_free_lock;

/* sg dma free list */
volatile Uint32 sg_dma_free_max;
volatile Uint32 sg_dma_free_index;
ptrlong *sg_dma_real_free_list;
ptrlong *sg_dma_free_list;
cavium_spinlock_t sg_dma_free_lock;

/* Ordered processing pending list*/
cavium_spinlock_t ordered_list_lock;
struct cavium_list_head ordered_list_head;

/* Unordered processing pending list */
cavium_spinlock_t unordered_list_lock; 
struct cavium_list_head unordered_list_head;

/* random number pool */
Uint8 *rnd_buffer;
Uint32 rnd_index;
cavium_spinlock_t rnd_lock;
cavium_spinlock_t id_lock;
/*ptr to completion_dma_free_list*/
void * ptr_comp_dma;

/* poll thread wait channel */
cavium_wait_channel cav_poll_wait;

#if defined(INTERRUPT_ON_COMP) || defined(INTERRUPT_COALESCING)
cavium_tasklet_t        interrupt_task;
#endif

struct MICROCODE microcode[MICROCODE_MAX];


/* Cores list */
core_t cores[MAX_CORES_NITROX];
/*Lock for microcode & cores data structures */
cavium_spinlock_t mc_core_lock;
cavium_spinlock_t uenreg_lock;
int initialized;

}cavium_device, *cavium_device_ptr;

struct N1_Dev {
        struct N1_Dev *next;
        int id;
        int bus;
        int dev;
        int func;
        void *data;
};

#ifdef CAVIUM_RESOURCE_CHECK
struct CAV_RESOURCES 
{
   cavium_spinlock_t resource_check_lock;
   struct cavium_list_head ctx_head;
   struct cavium_list_head key_head;
};
#endif

/*
 * User Info Buffer
 */
typedef struct 
{
   cavium_device *n1_dev;
   struct cavium_list_head list;
   n1_request_buffer *req;
   n1_request_type req_type;
   int mmaped;
   Uint8 *in_buffer;
   Uint8 *out_buffer;
   Uint32 in_size;
   Uint32 out_size;
   cavium_pid_t pid;
   Uint32 signo;
   Uint32 outcnt;
   Uint8   *outptr[MAX_OUTCNT];
   Uint32  outsize[MAX_OUTCNT];
   Uint32  outoffset[MAX_OUTCNT];
   Uint32  outunit[MAX_OUTCNT];
   cavium_wait_channel channel;
   Uint32 status;
} n1_user_info_buffer;
/*
 * Buffer Address structure
 */
struct PKP_BUFFER_ADDRESS
{
   ptrlong vaddr; /* virtual address */
   ptrlong baddr; /* bus address */
   Uint32 size;
};


/*
 * Direct Operation structs
 */
struct PKP_DIRECT_OPERATION_STRUCT
{
 Uint64 cmd_bytes; /*Newly added - Manoj */
 Uint64 ctx;

 Uint8 *dptr;
 Uint16 dlen;
 Uint64 dptr_baddr;

 Uint8 *rptr;
 Uint16 rlen;
 Uint64 rptr_baddr;

 volatile Uint64 *completion_address;

};


/*
 * Scatter/gather structs
 */

struct PKP_4_SHORTS
{
 Uint16 short_val[4];
};


struct CSP1_SG_LIST_COMPONENT
{
Uint16 length[4];
Uint64 ptr[4];
};


struct CSP1_SG_STRUCT
{
Uint16 unused[2];               /* unused locations */
Uint16 gather_list_size;
Uint16 scatter_list_size;                  
struct CSP1_SG_LIST_COMPONENT   *gather_component;
struct CSP1_SG_LIST_COMPONENT   *scatter_component;
};


struct CSP1_PATCH_WRITE
{
Uint8 prebytes[8];
Uint8 postbytes[8];
};


struct PKP_SG_OPERATION_STRUCT
{
 Uint64 ctx;
 Uint64 cmd_bytes; /*Newly added - */

 Uint16 incnt;
 Uint16 outcnt;

 struct PKP_BUFFER_ADDRESS inbuffer[MAX_INCNT];
 Uint32   inunit[MAX_INCNT];

 struct PKP_BUFFER_ADDRESS outbuffer[MAX_OUTCNT];
 Uint32   outunit[MAX_OUTCNT];

 Uint16 gather_list_size;
 Uint16 scatter_list_size;
 ptrlong sg_dma_baddr;   
 volatile Uint64 *sg_dma;
 Uint32 sg_dma_size;
 volatile Uint64 *completion_dma; 
};


/*
 * Pending queues comprise of this struct.
 */

struct PENDING_ENTRY
{
 struct cavium_list_head list;
 Csp1DmaMode dma_mode;
 ptrlong completion_address;
 void *pkp_operation; 
 unsigned long tick;
 Uint32 status;
 void (*callback)(int,void *);   
 void *cb_arg;
#ifdef DUMP_FAILING_REQUESTS
 n1_request_buffer n1_buf;
#else
 n1_request_buffer *n1_buf;
#endif
 int special;
 int ucode_idx;
 int srq_idx; /* Not required in PX PLUS mode. */
};


/*
 * General software functions
 */

/* Some useful macros */
//#if defined(NITROX_PX)

#define ring_door_bell(pdev,q,cnt)   write_PKP_register(pdev,(unsigned long *)((pdev)->door_addr[(q)]),(cnt))

//#else
//#define ring_door_bell(pdev,q,cnt) write_PKP_register(pdev,((pdev)->door_addr[(q)]),(cnt));
//#endif



/*
 * Direct
 */
int pkp_setup_direct_operation(cavium_device *pdev,
      Csp1OperationBuffer *csp1_operation, 
      struct PKP_DIRECT_OPERATION_STRUCT *pkp_direct_operation);
/*
 * Unmap the bus addresses
 */
void pkp_unsetup_direct_operation(cavium_device *pdev,
      struct PKP_DIRECT_OPERATION_STRUCT *pkp_direct_operation);

/*
 * Scatter/Gather
 */
int pkp_setup_sg_operation(cavium_device *pdev,
      Csp1OperationBuffer *csp1_operation, 
      struct PKP_SG_OPERATION_STRUCT *pkp_sg_operation );

void check_endian_swap( struct PKP_SG_OPERATION_STRUCT *pkp_sg_operation, int rw);

/*
 * Unmap all inpout and output buffers provided by the application
 */
void pkp_unmap_user_buffers(cavium_device *pdev,struct PKP_SG_OPERATION_STRUCT *pkp_sg_operation);


/*
 * Flushed the contents of all user buffers.
 */
void 
pkp_flush_input_buffers(cavium_device *pdev,struct PKP_SG_OPERATION_STRUCT *pkp_sg_operation);

void 
pkp_invalidate_output_buffers(cavium_device *pdev,struct PKP_SG_OPERATION_STRUCT *pkp_sg_operation);

int
check_completion(cavium_device *n1_dev, volatile Uint64 *p, int max_wait_states, int ucode_idx, int srq_idx);

void  init_npx_group_list(void);
Uint8 get_next_npx_group(void);
void  free_npx_group(Uint8  core_grp);

#endif


/*
 * $Id: cavium.h,v 1.32 2009/09/09 11:26:19 aravikumar Exp $
 * $Log: cavium.h,v $
 * Revision 1.32  2009/09/09 11:26:19  aravikumar
 * NPLUS macro dependency removed and made it dynamic
 *
 * Revision 1.31  2009/02/25 09:58:58  sgadam
 * - INTERRUPT_COALEASCING flag defined
 *
 * Revision 1.30  2008/12/22 05:42:10  jrana
 *  COUNTERS and INTERRUPT COALEASCING ADDED
 *
 * Revision 1.29  2008/11/06 09:08:23  ysandeep
 * Removed PX_PLUS
 *
 * Revision 1.28  2008/10/30 10:52:48  aramesh
 * FSK and HOST_KEY_MEM chunk size set to 640*2 for 3k/4k support.
 *
 * Revision 1.27  2008/09/30 13:15:17  jsrikanth
 * PX-4X [Multicard] support for IPsec :
 *      -  Round-robin scheduling for selecting a device
 *         implemented within IPSec APIs.
 *      -  All Lists [Pending/Direct/SG/CompletionDMA]
 *         moved to device structure.
 *      -  A single buffer pool manager for all devices.
 *         Interrupt handler now checks for PCI Error register as well.
 *         Proc Entry bug fixes when dumping more than a single page.
 *         DUMP_FAILING_REQUESTS pre-processor define added to dump
 *         out all failing requests.
 * Minor modifications of removing all tabs to spaces.
 *
 * Revision 1.26  2008/08/14 07:08:38  aramesh
 * fsk chunk size is reset to 640.
 *
 * Revision 1.25  2008/08/05 09:13:14  aramesh
 * FSK_CHUNK_SIZE is chnaged to 640*2
 *
 * Revision 1.24  2008/07/08 04:43:10  aramesh
 * bar_0 and bar_2 are changed to ptrlong type.
 *
 * Revision 1.23  2008/07/02 12:35:26  aramesh
 * deleted part number and corresponding flags.
 *
 * Revision 1.22  2008/03/11 08:54:47  kchunduri
 * --Use exact part number for CN15XX family.
 *
 * Revision 1.21  2008/03/10 07:13:12  kkiran
 * --ECC Unknown Point Multiply Operations require longer time to complete.
 *
 * Revision 1.20  2008/02/22 09:50:22  aramesh
 * driver cleanup is done.
 *
 * Revision 1.19  2008/02/14 05:37:35  kchunduri
 * --remove CN1600 dependency.
 *
 * Revision 1.18  2008/02/12 13:04:39  kchunduri
 * -- Disable core mask check for CN16XX family.
 *
 * Revision 1.17  2007/12/05 14:31:50  lpathy
 * increased the request timeout value
 *
 * Revision 1.16  2007/11/19 11:11:55  lpathy
 * ported to 64 bit windows.
 *
 * Revision 1.15  2007/09/10 10:56:18  kchunduri
 * --Maintain Context and KeyMemory resources per device.
 *
 * Revision 1.14  2007/07/25 08:41:15  kchunduri
 * --define new field in resource structure. Required for Multicard support.
 *
 * Revision 1.13  2007/07/03 11:47:47  kchunduri
 * --'completion_dma_free_list' maintained per device.
 *
 * Revision 1.12  2007/06/11 13:41:07  tghoriparti
 * cavium_mmap_kernel_buffers return values handled properly when failed.
 *
 * Revision 1.11  2007/06/06 08:51:14  rkumar
 * Changed C++ style comments to C comments
 *
 * Revision 1.10  2007/04/04 21:49:52  panicker
 * * Added support for CN1600
 * * Masks renamed as CNPX_* since both parts use the same mask
 *
 * Revision 1.9  2007/03/08 20:43:33  panicker
 * * NPLUS mode changes. pre-release
 * * NitroxPX now supports N1-style NPLUS operation.
 * * Native PX mode PLUS operations are enabled only if PX_PLUS flag is enabled
 *
 * Revision 1.8  2007/03/06 03:19:35  panicker
 * * new routines to maintain core groups for NitroxPX in PLUS mode -
 *   init_npx_group_list(), get_next_npx_group(), free_npx_group().
 * * MAX_CORES_NITROX for PX is set to 8.
 * * cores[] is now included for PX. PX will use the same core id lookup mechanism as N1
 *
 * Revision 1.7  2007/02/20 22:52:34  panicker
 * * command queue bus address fields are now of type cavium_dmaaddr
 *
 * Revision 1.6  2007/02/02 02:26:36  panicker
 * * cmd_bytes - a new field in PKP_DIRECT_OPERATION_STRUCT to store the command bytes of a request
 * * ring_doorbell() has different definitions for PX and N1.
 * * door_addr is unsigned long
 * * _ENDIAN flag name change
 *
 * Revision 1.5  2007/01/16 02:15:45  panicker
 * * compile time check for NITROX_PX flag
 * * scratchpad is required for MC2 (even in PX)
 *
 * Revision 1.4  2007/01/13 03:13:06  panicker
 * * compilation warnings fixed.
 * * check_compilation() use non-NPLUS mode call for PX.
 *
 * Revision 1.3  2007/01/11 01:57:00  panicker
 * * cavium_device structure
 *   - ctp and scratchpad allocation under MC2 only for !NITROX_PX
 *   - cores[MAX_CORES] is not included in PX; the locks are.
 * * PENDING_ENTRY
 *   - ucode_idx and srq_idx in NPLUS mode for !(NITROX_PX).
 *
 * Revision 1.2  2007/01/09 22:27:30  panicker
 * * REG_EXEC_GROUP register added
 *
 * Revision 1.1  2007/01/06 02:47:40  panicker
 * * first cut - NITROX PX driver
 *
 * Revision 1.49  2006/05/16 09:30:54  kchunduri
 * --support for Dynamic DMA mapping instead of virt_to_phys
 *
 * Revision 1.48  2006/02/27 22:45:28  dpatel
 * got rid of "L" long specifier in core mask defines. Helps RHEL4 builds.
 *
 * Revision 1.47  2006/02/03 05:11:22  sgadam
 * - Timeout updated
 *
 * Revision 1.46  2006/01/31 07:00:55  sgadam
 * - Added pending entries and direct entries to special queue
 *
 * Revision 1.45  2006/01/30 10:55:57  sgadam
 *  - ipsec and ssl chunk counts moved to device structure
 *
 * Revision 1.44  2006/01/30 09:01:32  pyelgar
 *    - Moved ipsec api from freebsd_main.h to freebsd_sysdep.h.
 *      Increased the driver timeout to 2 seconds.
 *
 * Revision 1.43  2006/01/30 07:13:48  sgadam
 * - ipsec context new put index added
 *
 * Revision 1.42  2006/01/19 09:48:08  sgadam
 * - IPsec 2.6.11 changes
 *
 * Revision 1.41  2005/12/07 04:50:59  kanantha
 * modified to support both 32 and 64 bit versions
 *
 * Revision 1.40  2005/11/28 05:41:55  kanantha
 * Update by removing 64 bit compilation warnings for 1010
 *
 * Revision 1.39  2005/11/17 13:31:09  kanantha
 * Updating with the 64 bit modifications, with proper matching of data types
 *
 * Revision 1.38  2005/10/24 06:44:44  kanantha
 * - Fixed RHEL4 Warnings
 *
 * Revision 1.37  2005/10/13 09:19:58  ksnaren
 * fixed compile errors for windows xp
 *
 * Revision 1.36  2005/09/28 15:50:26  ksadasivuni
 * - Merging FreeBSD 6.0 AMD64 Release with CVS Head
 * - Now context pointer given to user space applications is physical pointer.
 *   So there is no need to do cavium_vtophys() of context pointer.
 *
 * Revision 1.35  2005/09/06 14:38:57  ksadasivuni
 * - Some cleanup error fixing and spin_lock_destroy functionality added to osi.
 *   spin_lock_destroy was necessary because of FreeBSD 6.0.
 *
 * Revision 1.34  2005/09/06 07:08:22  ksadasivuni
 * - Merging FreeBSD 4.11 Release with CVS Head
 *
 * Revision 1.33  2005/08/31 18:10:30  bimran
 * Fixed several warnings.
 * Fixed the corerct use of ALIGNMENT and related macros.
 *
 * Revision 1.32  2005/07/17 04:35:09  sgadam
 * 8 bytes alignment issue on linux-2.6.2 is fixed. README and Makefile in
 * apps/cavium_engine updated
 *
 * Revision 1.31  2005/06/29 19:41:26  rkumar
 * 8-byte alignment problem fixed with N1_SANITY define.
 *
 * Revision 1.30  2005/06/13 06:35:42  rkumar
 * Changed copyright
 *
 * Revision 1.29  2005/06/03 07:10:19  rkumar
 * Timeout for SRQ_IN_USE entries increased by a factor MAX_SRQ_TIMEOUT(default 1)
 *
 * Revision 1.28  2005/05/20 14:34:05  rkumar
 * Merging CVS head from india
 *
 * Revision 1.27  2005/02/01 04:11:07  bimran
 * copyright fix
 *
 * Revision 1.26  2005/01/28 22:18:06  tsingh
 * Added support for HT part numbers.
 *
 * Revision 1.25  2005/01/19 23:16:21  tsingh
 * increased CTP_QUEUE_SIZE to 64
 *
 * Revision 1.24  2004/08/03 20:44:11  tahuja
 * support for Mips Linux & HT.
 *
 * Revision 1.23  2004/07/21 23:24:41  bimran
 * Fixed MC2 completion code issues on big endian systems.
 *
 * Revision 1.22  2004/07/09 01:09:00  bimran
 * fixed scatter gather support
 *
 * Revision 1.21  2004/06/23 19:40:11  bimran
 * changed check_completion to accept volatile comp_addr;
 * changed spinlock_t to OSI
 * added real addresses for command queues.
 *
 * Revision 1.20  2004/06/03 21:21:59  bimran
 * included cavium_list.h
 * fixed list* calls to use cavium_list
 *
 * Revision 1.19  2004/05/28 17:56:45  bimran
 * added id lock.
 *
 * Revision 1.18  2004/05/17 20:53:15  bimran
 * Fixed completion code shifts becuase now we will be also be supporting MC2 microcode on N1 parts.
 *
 * Revision 1.17  2004/05/11 03:10:24  bimran
 * some performance opt.
 *
 * Revision 1.16  2004/05/08 03:58:51  bimran
 * Fixed INTERRUPT_ON_COMP
 *
 * Revision 1.15  2004/05/04 20:48:34  bimran
 * Fixed RESOURCE_CHECK.
 *
 * Revision 1.14  2004/05/02 19:44:29  bimran
 * Added Copyright notice.
 *
 * Revision 1.13  2004/05/01 07:14:37  bimran
 * Fixed non-blocking operation from user mode.
 *
 * Revision 1.12  2004/04/30 21:22:11  bimran
 * Doorbell threshold is only 1 for SSL.
 *
 * Revision 1.11  2004/04/30 01:36:40  tsingh
 * Changed doorbell threshold to 25.(bimran)
 *
 * Revision 1.10  2004/04/30 00:00:09  bimran
 * Removed semaphoers from context memory in favour of just counts and a lock.
 *
 * Revision 1.9  2004/04/29 21:58:41  tsingh
 * Fixed doorbell threshold, completion code shofts values.(bimran)
 *
 * Revision 1.8  2004/04/26 23:26:25  bimran
 * Changed CTP queue size to 32.
 *
 * Revision 1.7  2004/04/26 19:04:30  bimran
 * Added 505 support.
 *
 * Revision 1.6  2004/04/21 19:18:58  bimran
 * NPLUS support.
 *
 * Revision 1.5  2004/04/20 17:41:30  bimran
 * Added microcode structure to  cavium_device structure instead of global mirocode structure.
 * Some early NPLUS related changes.
 *
 * Revision 1.4  2004/04/20 02:27:57  bimran
 * Removed DRAM_MAX macro.
 *
 * Revision 1.3  2004/04/19 18:37:54  bimran
 * Removed admin microcode support.
 *
 * Revision 1.2  2004/04/16 03:19:18  bimran
 * Added doorbell coalescing support.
 * Fixed MAX_N1_QUEUES so that it is dependent upon part number instead of Microcode type.
 * Fixed COMPLETION_CODE_INIT to be dependent upon Microcode type.
 *
 * Revision 1.1  2004/04/15 22:40:48  bimran
 * Checkin of the code from India with some cleanups.
 *
 */

