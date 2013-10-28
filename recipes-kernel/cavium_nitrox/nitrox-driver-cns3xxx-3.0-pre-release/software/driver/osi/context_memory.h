/* context_memory.h */
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

#ifndef _CONTEXT_MEMORY_H_
#define _CONTEXT_MEMORY_H_

#ifndef PX_ECC
#define PX_ECC
#endif


#ifdef  PX_ECC
//#define ECC_P256_CONTEXT_SIZE (5*1024)
#define ECC_P256_CONTEXT_SIZE (1024)
#define ECC_P384_CONTEXT_SIZE (2*1024)
//#define ECC_P384_CONTEXT_SIZE (12*1024)
#endif


/* SSL Context size */
#define SSL_CONTEXT_SIZE 1024

#ifdef CAVIUM_RESOURCE_CHECK
struct CTX_ENTRY {
	struct cavium_list_head list;
	Uint64 ctx;
	ContextType ctx_type;
        cavium_device *pkp_dev;

};
int
insert_ctx_entry(cavium_device *pdev,struct cavium_list_head *ctx_head, ContextType c, Uint64 addr);
#endif

/*
 * Initialize context buffers
 */
int init_context(cavium_device *pkp_dev); 

/*
 * Cleansup context buffers
 */
int cleanup_context(cavium_device *pkp_dev);

/*
 * Get next available context ID
 */
Uint64 alloc_context(cavium_device *, ContextType);

/*
 * Put back
 */
void dealloc_context(cavium_device *, ContextType, Uint64);

/*
 * Get next available context ID
 */
int alloc_context_id(cavium_device *, ContextType, ptrlong *);

/*
 * Put back
 */
int dealloc_context_id(cavium_device *, ContextType, ptrlong);

#if 0
/*
 * get virtual address
 */
Uint64 ctx_get_virt_addr(cavium_device *, int);
Uint32 tmp_ctx_get_virt_addr(cavium_device *, int);


/*
 * get phys address
 */
Uint64 ctx_get_bus_addr(cavium_device *, int);
#endif

#ifdef DUMP_FAILING_REQUESTS
Uint8 *
find_host_ctx(cavium_device *pkp_dev, Uint64 ctx_addr);
#endif


#endif


/*
 * $Id: context_memory.h,v 1.7 2008/09/30 13:15:17 jsrikanth Exp $
 * $Log: context_memory.h,v $
 * Revision 1.7  2008/09/30 13:15:17  jsrikanth
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
 * Revision 1.6  2008/03/14 06:31:47  aramesh
 * CTX_MEM_IS_HOST_MEM  flags is deleted from here
 *
 * Revision 1.5  2008/02/22 10:22:29  aramesh
 * defined ECC  related flags.
 *
 * Revision 1.4  2008/01/29 09:58:05  aramesh
 * Changed ECC Context memory size.
 *
 * Revision 1.3  2007/12/07 05:24:18  ksadasivuni
 * 1.  changed context memory to use buffer pool as px doesn't have DDR
 * 2.  PX_ECC_FreeContext now takes cid argument
 *
 * Revision 1.2  2007/09/10 10:56:18  kchunduri
 * --Maintain Context and KeyMemory resources per device.
 *
 * Revision 1.1  2007/01/06 02:47:40  panicker
 * * first cut - NITROX PX driver
 *
 * Revision 1.9  2005/12/22 10:17:35  ksadasivuni
 * - NPLUS Release. Freeswan klips code is assuming ipsec context size of 128, driver is assuming 256 for MC2.
 *   Moved IPSEC_CONTEXT_SIZE #define to cavium_common.h
 *
 * Revision 1.8  2005/09/28 15:50:26  ksadasivuni
 * - Merging FreeBSD 6.0 AMD64 Release with CVS Head
 * - Now context pointer given to user space applications is physical pointer.
 *   So there is no need to do cavium_vtophys() of context pointer.
 *
 * Revision 1.7  2005/06/13 06:35:42  rkumar
 * Changed copyright
 *
 * Revision 1.6  2005/02/01 04:11:07  bimran
 * copyright fix
 *
 * Revision 1.5  2004/06/03 21:22:56  bimran
 * included cavium_list.h
 * fixed list* calls to use cavium_list
 *
 * Revision 1.4  2004/05/04 20:48:34  bimran
 * Fixed RESOURCE_CHECK.
 *
 * Revision 1.3  2004/05/02 19:44:29  bimran
 * Added Copyright notice.
 *
 * Revision 1.2  2004/04/20 02:24:11  bimran
 * defined IPSEC and SSL context sizes, instead of ambiguous MIN and MAX context sizes.
 *
 * Revision 1.1  2004/04/15 22:40:48  bimran
 * Checkin of the code from India with some cleanups.
 *
 */

