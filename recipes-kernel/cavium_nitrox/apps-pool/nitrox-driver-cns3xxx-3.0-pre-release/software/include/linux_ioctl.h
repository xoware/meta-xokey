/* linux_ioctl.h */
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
 */
#ifndef _LINUX_IOCTL_H_
#define _LINUX_IOCTL_H_

#include <linux/ioctl.h>

#define N1_MAGIC	0xC0
#define IOCTL_N1_OPERATION_CODE		_IOWR(N1_MAGIC, N1_OPERATION_CODE, \
						n1_operation_buffer)
#define IOCTL_N1_DO_OPERATION		_IOWR(N1_MAGIC, N1_OPERATION_CODE, \
						n1_operation_buffer)
#define IOCTL_N1_DO_SG_OPERATION	_IOWR(N1_MAGIC, N1_SG_OPERATION_CODE, \
						n1_operation_buffer)
#define IOCTL_N1_POLL_CODE		_IOWR(N1_MAGIC, N1_REQUEST_STATUS, \
						Csp1RequestStatusBuffer) 
#define IOCTL_N1_GET_REQUEST_STATUS	_IOWR(N1_MAGIC, N1_REQUEST_STATUS, \
						Csp1RequestStatusBuffer) 
#define IOCTL_N1_ALLOC_CONTEXT		_IOWR(N1_MAGIC, N1_ALLOC_CONTEXT, \
						n1_operation_buffer)
#define IOCTL_N1_FREE_CONTEXT		_IOWR(N1_MAGIC, N1_FREE_CONTEXT, \
						n1_operation_buffer)
#define IOCTL_N1_ALLOC_KEYMEM		_IOWR(N1_MAGIC, N1_ALLOC_KEYMEM, \
						Uint64)
#define IOCTL_N1_FREE_KEYMEM		_IOWR(N1_MAGIC, N1_FREE_KEYMEM, \
						n1_write_key_buf)
#define IOCTL_N1_WRITE_KEYMEM		_IOWR(N1_MAGIC, N1_WRITE_KEYMEM, \
						n1_write_key_buf)
#define IOCTL_N1_FLUSH_ALL_CODE		_IO(N1_MAGIC, N1_FLUSH_ALL_CODE)
#define IOCTL_N1_FLUSH_CODE		_IOWR(N1_MAGIC, N1_FLUSH_CODE, Uint32)
#define IOCTL_N1_DEBUG_WRITE_CODE	_IOWR(N1_MAGIC, N1_DEBUG_WRITE_CODE, DebugRWReg)
#define IOCTL_N1_DEBUG_READ_CODE	_IOWR(N1_MAGIC, N1_DEBUG_READ_CODE, DebugRWReg)
#define IOCTL_PCI_DEBUG_WRITE_CODE	_IOWR(N1_MAGIC, PCI_DEBUG_WRITE_CODE, DebugRWReg)
#define IOCTL_PCI_DEBUG_READ_CODE	_IOWR(N1_MAGIC, PCI_DEBUG_READ_CODE, DebugRWReg)
#define IOCTL_N1_INIT_CODE		_IOWR(N1_MAGIC, N1_INIT_CODE, Csp1InitBuffer)
#define IOCTL_N1_SOFT_RESET_CODE	_IOWR(N1_MAGIC, N1_SOFT_RESET_CODE,Uint32)
#define IOCTL_N1_API_TEST_CODE		_IO(N1_MAGIC, N1_API_TEST_CODE)
#define IOCTL_N1_GET_RANDOM_CODE	_IOWR(N1_MAGIC, N1_GET_RANDOM_CODE, \
						n1_operation_buffer)
#define IOCTL_N1_GET_DEV_TYPE	_IOR(N1_MAGIC, N1_GET_DEVICE_TYPE, \
						Uint32)

#define IOCTL_CSP1_GET_CORE_ASSIGNMENT	_IOR(N1_MAGIC, N1_CORE_ASSIGNMENT,Csp1CoreAssignment)
#define IOCTL_CSP1_SET_CORE_ASSIGNMENT	_IOW(N1_MAGIC, N1_CORE_ASSIGNMENT,Csp1CoreAssignment)

#define IOCTL_N1_GET_ALL_REQUEST_STATUS _IOWR(N1_MAGIC, N1_GET_ALL_REQUEST_STATUS, Csp1StatusOperationBuffer)

#define IOCTL_N1_GET_DEV_CNT _IOR(N1_MAGIC, N1_GET_DEV_CNT, Csp1DevMask)

#define IOCTL_N1_GET_DRIVER_STATE _IOR(N1_MAGIC, N1_GET_DRIVER_STATE, uint8_t)

#define IOCTL_N1_GET_STATUS_DDR	_IOWR(N1_MAGIC, N1_GET_STATUS_DDR,Uint32)

#endif

/*
 * $Id: linux_ioctl.h,v 1.7 2009/09/09 14:14:45 aravikumar Exp $
 * $Log: linux_ioctl.h,v $
 * Revision 1.7  2009/09/09 14:14:45  aravikumar
 * NPLUS macro dependency removed and made it dynamic
 *
 * Revision 1.6  2008/07/30 10:40:04  aramesh
 * IOCTL arguments given properly.
 *
 * Revision 1.5  2008/07/29 14:52:23  aramesh
 * added IOCTL_GET_DDR_STATUS.
 *
 * Revision 1.4  2008/07/29 11:09:47  aramesh
 * argument added to SET_SOFT_RESET.
 *
 * Revision 1.3  2008/07/02 12:44:45  aramesh
 * deleted config part and corresponding flags.
 *
 * Revision 1.2  2007/07/04 04:50:48  kchunduri
 * --new IOCTL to return number of nitrox devices detected.
 *
 * Revision 1.1  2007/01/06 02:47:40  panicker
 * * first cut - NITROX PX driver
 *
 * Revision 1.6  2006/08/16 14:05:40  kchunduri
 * --modified definition of GET_REQUEST_STATUS to use Csp1RequestStatusBuffer
 *
 * Revision 1.5  2006/04/17 04:10:25  kchunduri
 * --new IOCTL to support Csp1GetAllResults
 *
 * Revision 1.4  2005/02/01 04:12:05  bimran
 * copyright fix
 *
 * Revision 1.3  2004/05/02 19:45:59  bimran
 * Added Copyright notice.
 *
 * Revision 1.2  2004/04/21 20:00:29  bimran
 * NPLUS support.
 *
 * Revision 1.1  2004/04/15 22:40:50  bimran
 * Checkin of the code from India with some cleanups.
 *
 */

