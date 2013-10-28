/* key_memory.h */
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
#ifndef _KEY_MEMORY_H
#define _KEY_MEMORY_H

#ifdef CAVIUM_RESOURCE_CHECK
struct KEY_ENTRY {
	struct cavium_list_head list;
	Uint64 key_handle;
        cavium_device *pkp_dev;

};
int
insert_key_entry(cavium_device *pdev,struct cavium_list_head *key_head, Uint64 key_handle);
#endif

struct KEYMEM_ALLOC_ENTRY {
	struct cavium_list_head list;
	Uint64 key_handle;
	cavium_pid_t proc_pid;
	Uint32 index;
	Uint16 loc;
};

int init_key_memory(cavium_device * );
void cleanup_key_memory(cavium_device *);
int store_key_mem(cavium_device *, n1_write_key_buf, int);
Uint64 alloc_key_memory(cavium_device *);
void dealloc_key_memory(cavium_device *, Uint64 );
void flush_key_memory(cavium_device *);
#endif

/*
 * $Id: key_memory.h,v 1.5 2009/09/09 11:26:19 aravikumar Exp $
 * $Log: key_memory.h,v $
 * Revision 1.5  2009/09/09 11:26:19  aravikumar
 * NPLUS macro dependency removed and made it dynamic
 *
 * Revision 1.4  2007/09/10 10:56:18  kchunduri
 * --Maintain Context and KeyMemory resources per device.
 *
 * Revision 1.3  2007/03/06 03:15:03  panicker
 * * store_key_mem() uses same  prototype as N1 for PX.
 *
 * Revision 1.2  2007/01/11 02:10:58  panicker
 * - store_key_mem() use in non-NPLUS mode for PX.
 *
 * Revision 1.1  2007/01/06 02:47:40  panicker
 * * first cut - NITROX PX driver
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
 * Revision 1.3  2004/05/02 19:45:31  bimran
 * Added Copyright notice.
 *
 * Revision 1.2  2004/04/21 19:18:58  bimran
 * NPLUS support.
 *
 * Revision 1.1  2004/04/15 22:40:49  bimran
 * Checkin of the code from India with some cleanups.
 *
 */

