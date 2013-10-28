/* buffer_pool.h */
/*
 *
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
#ifndef _BUFFER_POOL_H_
#define _BUFFER_POOL_H_

#ifndef CAVIUM_OS
#define CAVIUM_OS
#endif

/*
 * buffer pool management
 */

/*
 * Buffer chunk size is reduced bye 16 bytes inorder to 
 * optimize the memory requirement from OS. 
 * Without this 16 bytes reduction, each chunk is taking double 
 * the size of it.
 */
#define HUGE_BUFFER_CHUNK_SIZE          ((32*1024)-16)

#define LARGE_BUFFER_CHUNK_SIZE         ((16*1024)-16)

#define MEDIUM_BUFFER_CHUNK_SIZE        ((8*1024)-16)

#define SMALL_BUFFER_CHUNK_SIZE         ((4*1024)-16)

#define TINY_BUFFER_CHUNK_SIZE		((2*1024)-16)

#define EX_TINY_BUFFER_CHUNK_SIZE       (1*1024)


typedef struct {
	Uint32  pool;
	Uint32 index;
} buffer_tag;


Uint32 init_buffer_pool(cavium_general_config *);
void free_buffer_pool(void);
Uint8 *get_buffer_from_pool(void *,int);
void put_buffer_in_pool(void *,Uint8 *);

#endif /*_BUFFER_POOL_H_*/


/*
 * $Id: buffer_pool.h,v 1.3 2008/09/30 13:15:17 jsrikanth Exp $
 * $Log: buffer_pool.h,v $
 * Revision 1.3  2008/09/30 13:15:17  jsrikanth
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
 * Revision 1.2  2008/02/22 07:18:17  aramesh
 * CAVIUM_OS flag is defined always.
 *
 * Revision 1.1  2007/01/06 02:47:40  panicker
 * * first cut - NITROX PX driver
 *
 * Revision 1.7  2005/12/21 07:51:02  kanantha
 * Modified the buffer chunk sizes, by reducing 16 bytes. So that OS allocates memory from the same size memory block including is tag (16 bytes) information.
 *
 * Revision 1.6  2005/09/28 15:50:26  ksadasivuni
 * - Merging FreeBSD 6.0 AMD64 Release with CVS Head
 * - Now context pointer given to user space applications is physical pointer.
 *   So there is no need to do cavium_vtophys() of context pointer.
 *
 * Revision 1.5  2005/06/13 06:35:42  rkumar
 * Changed copyright
 *
 * Revision 1.4  2005/02/01 04:11:07  bimran
 * copyright fix
 *
 * Revision 1.3  2004/06/28 20:37:42  tahuja
 * Fixed compiler warnings on NetBSD. changed mdelay in check_completion from 1ms to 2ms.
 *
 * Revision 1.2  2004/05/02 19:44:29  bimran
 * Added Copyright notice.
 *
 * Revision 1.1  2004/04/15 22:40:48  bimran
 * Checkin of the code from India with some cleanups.
 *
 */

