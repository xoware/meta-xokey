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
 * cavium_kernel.h 
 */

#ifndef _CAVIUM_KERNEL_H_
#define _CAVIUM_KERNEL_H_

#include "cavium_common.h"
#include "cavium_ipsec.h"
#include "cavium_queue.h"


typedef void (*Request_cb)(int status, void* data);

typedef struct _Context
{
        void* hook;

        Uint64 ddr_ptr;
        Uint8 in_use; /* set to 0 or 1 */
        Uint32 pid;

	 SLIST_ENTRY(_Context) link;
} Context;

typedef enum {COMM_QUEUE_0=0, COMM_QUEUE_1=1, COMM_QUEUE_2=2, COMM_QUEUE_3=3} CommQueueId;
typedef enum {GOOD_STATUS=0, BAD_STATUS=1} PollStatus;

typedef struct _PollItem
{
        Uint64* comp_addr;
        int tick;
        Request_cb cb;
        void *data;
	int len;

	/* dont touch */
        CommQueueId c_q_id;

        SLIST_ENTRY(_PollItem) link;
} PollItem;

typedef struct _PollQueue
{
	SLIST_HEAD(PollList, _PollItem) list;
        PollItem* tail;
        spinlock_t lock;
} PollQueue;


#if defined(LINUX) || defined(linux)
#define Csp1ConfigDeviceName "N1ConfigDevice"
#define Csp1UnconfigDeviceName "N1UnconfigDevice"
#define Csp1AllocContextName "N1AllocContext"
#define Csp1FreeContextName "N1FreeContext"
#define Csp1DoRequestName "N1DoRequest"
#define Csp1PollName "Csp1Poll"
#endif /* LINUX */


extern int Csp1CaviumInit(void);
extern int Csp1ConfigDevice(
	void *device);
extern void Csp1UnconfigDevice(void);
extern Uint64 Csp1AllocContext(void);
extern void Csp1FreeContext(
	Uint64 ctx);
extern Uint32 Csp1DoRequest(
    n1_request_buffer* req,
	int* type);
extern Uint32 Csp1ProcessInboundPacket(
	void* in,
	void* out,
	Uint64 ctx,
	int rlen,
	Request_cb cb,
	void *data);
extern Uint32 Csp1ProcessOutboundPacket(
	void* in,
	void* out,
	Uint64 ctx,
	int rlen,
	Uint32 seq,
	Request_cb cb,
	void *data);
#if 1
#ifdef MC2
Uint32 Csp1WriteIpsecSa(
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
Uint32 Csp1WriteIpsecSa(
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
#endif
Uint32 Csp1InvalidateIpsecSa(
				Uint64 ctx, 
				Uint32 *in_buffer, 
				Uint32 *out_buffer, 
        			Request_cb cb,
				void *cb_data);

#ifdef OVERRIDE_DEFAULT_POLL
extern void Csp1Poll(PollQueue*, PollQueue*);
#endif /* OVERRIDE_DEFAULT_POLL */

#ifdef MC2
void n1_flush_queue(void);
#endif
#endif /* _CAVIUM_KERNEL_H_ */
