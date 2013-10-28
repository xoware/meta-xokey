/* linux_main.h */
/*
 * Copyright (c) 2003-2004 Cavium Networks (support@cavium.com). All rights 
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

#ifndef _LINUX_MAIN_H_
#define _LINUX_MAIN_H_

#define VENDOR_ID			0x177d
#define N1_DEVICE			0x0001
#define N1_LITE_DEVICE			0x0003
#define NPX_DEVICE			0x0010

#define DEVICE_NAME           "pkp_dev"
#define DEVICE_MAJOR			125	/* Major device number requested */
//#endif

/* number of 32 byte structures */
#define CAVIUM_COMMAND_QUEUE_SIZE	2000



/* number of pending response structures to be pre-allocated. */
#define CAVIUM_PENDING_MAX CAVIUM_COMMAND_QUEUE_SIZE

/* number of DIRECT operation structures to be pre-allocated. */
#define CAVIUM_DIRECT_MAX  CAVIUM_COMMAND_QUEUE_SIZE 

/* number of SG operation structures to be pre-allocated. */
#define CAVIUM_SG_MAX CAVIUM_COMMAND_QUEUE_SIZE

/* number of scatter/gather lists to be pre-allocated. */
#define CAVIUM_SG_DMA_MAX CAVIUM_COMMAND_QUEUE_SIZE

/*context memory to be pre-allocated,
 * if DDR memory is not found.
 * Otherwise actual size is used. */ 
#define CAVIUM_CONTEXT_MAX  (2*1024*1024) 

/* 32k buffers */
//#ifdef SSL
#define HUGE_BUFFER_CHUNKS               100
/*#else
#define HUGE_BUFFER_CHUNKS              1
#endif*/

/* 16k buffers */
//#ifdef SSL
#define LARGE_BUFFER_CHUNKS              100
/*#else
#define LARGE_BUFFER_CHUNKS		1
#endif*/

/* 8k buffers */
//#ifdef SSL
#define MEDIUM_BUFFER_CHUNKS            100
/*#else
#define MEDIUM_BUFFER_CHUNKS		1
#endif*/

/* 4k buffers */
//#ifdef SSL
#define SMALL_BUFFER_CHUNKS             100
/*#else
#define SMALL_BUFFER_CHUNKS		1
#endif*/

/* 2k buffers */
//#ifdef SSL
#define TINY_BUFFER_CHUNKS              100
/*#else
#define TINY_BUFFER_CHUNKS		1
#endif*/

/* 1k buffers */
#define EX_TINY_BUFFER_CHUNKS           1000

#define N1ConfigDeviceName "N1ConfigDevice"
#define N1UnconfigDeviceName "N1UnconfigDevice"
#define N1AllocContextName "N1AllocContext"
#define N1FreeContextName "N1FreeContext"
#define N1ProcessInboundPacketName "N1ProcessInboundPacket"
#define N1ProcessOutboundPacketName "N1ProcessOutboundPacket"
#define N1WriteIpSecSaName "N1WriteIpSecSa"

#ifdef CAVIUM_NEW_API
void * n1_config_device(Uint32);
#else
void * n1_config_device();
#endif
void n1_unconfig_device(void);
Uint64 n1_alloc_context(void *);
void n1_free_context(void *device, Uint64 ctx);
Uint32 n1_process_outbound_packet(void *device, Uint16 size, Uint16 param, 
		Uint16 dlen, Uint32 * inbuffer, Uint32 *outbuffer, int rlen,
		Uint64 ctx, CallBackFn cb, void *cb_data, int response_order, int req_queue);

Uint32 n1_process_inbound_packet(void *device, Uint16 size, Uint16 param, 
		Uint16 dlen, Uint32 * inbuffer, Uint32 *outbuffer, int rlen,
		Uint64 ctx, CallBackFn cb, void *cb_data, int response_order, 
		int req_queue);
#ifdef MC2
Uint32 n1_write_ipsec_sa(void *device, IpsecProto proto, Version iver, Version over, 
			 IpsecMode mode, Direction dir, EncType cypher, 
			 Uint8 *e_key, AuthType auth, Uint8 *a_key, 
			 Uint8 template[40], Uint32 spi, Uint8 copy_df,
	  	         Uint8 udp_encap, Uint64 ctx, Uint64 next_ctx, 
			 Uint32 *in_buffer, Uint32 *out_buffer, 
			 CallBackFn cb, void *cb_data, int resp_order, 
			 int req_queue);
void n1_flush_packet_queue(void *device);
Uint32
n1_invalidate_ipsec_sa(void *device, Uint64 ctx, Uint32 *in_buffer, Uint32 *out_buffer, CallBackFn cb, void *cb_data, int res_order,int req_queue); 
#else
Uint32 n1_write_ipsec_sa(void *device, IpsecProto proto, Version version, 
			 IpsecMode mode, Direction dir, EncType cypher, 
			 Uint8 *e_key, AuthType auth, Uint8 *a_key, 
			 Uint8 template[40], Uint32 spi, Uint8 copy_df,
	  	         Uint8 udp_encap, Uint64 ctx, Uint32 *in_buffer, 
			 Uint32 *out_buffer, CallBackFn cb, void *cb_data, 
			 int resp_order, int req_queue);
#endif

int init_kernel_mode (void);
int free_kernel_mode (void);

#endif

/*
 * $Id: linux_main.h,v 1.6 2009/09/09 11:19:04 aravikumar Exp $
 * $Log: linux_main.h,v $
 * Revision 1.6  2009/09/09 11:19:04  aravikumar
 * NPLUS macro dependency removed and made it dynamic
 *
 * Revision 1.5  2008/09/30 13:18:18  jsrikanth
 *         PX-4X [Multicard] support for IPsec :
 *                 -    Round-robin scheduling for selecting a device
 *                      implemented within IPSec APIs.
 *                 -    All Lists [Pending/Direct/SG/CompletionDMA]
 *                      moved to device structure.
 *                 -    A single buffer pool manager for all devices.
 *         Interrupt handler now checks for PCI Error register as well.
 *         Proc Entry bug fixes when dumping more than a single page.
 *         DUMP_FAILING_REQUESTS pre-processor define added to dump
 *         out all failing requests.
 *         Minor modification of changing all tabs to spaces.
 *
 * Revision 1.4  2008/07/02 12:27:41  aramesh
 * deleted config part and corresponding flags.
 *
 * Revision 1.3  2007/10/16 06:27:57  aramesh
 * --Changes for support of NLite/N1 family.
 *
 * Revision 1.2  2007/02/01 23:26:38  panicker
 * * Temporary changes during bringup. Device Id 0x0. Driver names unique for PX and N1.
 *
 * Revision 1.1  2007/01/06 02:47:40  panicker
 * * first cut - NITROX PX driver
 *
 * Revision 1.19  2006/02/10 05:19:12  sgadam
 * - Ipsec MC1 invalidate_ipsec_sa removed
 *
 * Revision 1.18  2006/02/06 05:23:43  sgadam
 *  - invalidate_ipsec_sa api added
 *
 * Revision 1.17  2006/01/31 07:05:18  sgadam
 * - direct entries fix
 *
 * Revision 1.16  2006/01/19 09:44:49  sgadam
 * -Ipsec 2.6.11 changes
 *
 * Revision 1.15  2005/12/21 07:42:55  kanantha
 * Reduced the buffers count, as the driver is taking huge memory(70K),
 * 1K pool is kept as it is as number of 1K pools needed is very high
 *
 * Revision 1.14  2005/06/13 06:35:42  rkumar
 * Changed copyright
 *
 * Revision 1.13  2005/05/21 04:50:54  rkumar
 * NPLUS related parameter changes
 *
 * Revision 1.12  2005/05/20 14:34:05  rkumar
 * Merging CVS head from india
 *
 * Revision 1.11  2005/05/17 22:03:00  bimran
 * changed context size to 2m
 *
 * Revision 1.10  2005/01/19 22:54:52  tsingh
 * parameter changes for quicksec on CN1005
 *
 * Revision 1.9  2005/01/06 18:43:32  mvarga
 * Added realtime support
 *
 * Revision 1.8  2004/08/03 20:44:10  tahuja
 * support for Mips Linux & HT.
 *
 * Revision 1.7  2004/07/13 02:29:21  tsingh
 * increased buffers
 *
 * Revision 1.6  2004/07/06 21:31:24  tsingh
 * moved CallBackFn definition from linux_main.h to linux_sysdep.h
 *
 * Revision 1.5  2004/05/02 19:43:58  bimran
 * Added Copyright notice.
 *
 * Revision 1.4  2004/05/01 00:48:10  tsingh
 * Fixed for NPLus (bimran).
 *
 * Revision 1.3  2004/04/29 21:57:09  tsingh
 * Change command queue size and other related sizes.
 *
 * Revision 1.2  2004/04/20 02:17:21  bimran
 * Modified CAVIUM_CONTEXT_MAX to be 1MB in case if DDR memory is not present.
 *
 * Revision 1.1  2004/04/15 22:40:48  bimran
 * Checkin of the code from India with some cleanups.
 *
 */

