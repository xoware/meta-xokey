/* init_cfg.h */
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
#ifndef _INIT_CFG_H
#define _INIT_CFG_H

typedef struct _CAVIUM_CONFIG
{

	Uint32 device_id;
	void *dev;	/* platfomr dependent device pointer */
	Uint32 bus_number;
	Uint32 dev_number;
	Uint32 func_number;
	Uint32 px_flag;
//#if defined(NITROX_PX)
	ptrlong bar_px_hw;
	void  *bar_px;
//#else
	ptrlong bar_0;
	ptrlong bar_2;
//#endif
	Uint32 command_queue_max;
	/* context memory size to be pre-allocated,
	 * if DDR memory is not found.
	 * Otherwise, actual size will be used */
	Uint32 context_max; 
}cavium_config;


typedef struct _CAVIUM_GENERAL_CONFIG
{
	Uint32 pending_max; /* number of pending response structures to be pre-allocated. */
	Uint32 direct_max;	/* number of operation structures to be pre-allocated. */
	Uint32 sg_max;		/* number of operation structures to be pre-allocated. */
	Uint32 sg_dma_list_max; /* number of scatter/gather lists to be pre-allocated. */
	Uint32 huge_buffer_max; /* number in huge 32K buffer pool */
	Uint32 large_buffer_max; /* number in large 16K buffer pool */
	Uint32 medium_buffer_max; /* number in medium 8K buffer pool */
	Uint32 small_buffer_max; /* number in small 4K buffer pool */
	Uint32 tiny_buffer_max; /* number in tiny 2K buffer pool */
	Uint32 ex_tiny_buffer_max; /* number in ex tiny 1K buffer pool */
}cavium_general_config;

/* Initialization and cleanup functions */
int cavium_init(cavium_config *config);
int cavium_general_init(cavium_general_config *gconfig);
void cavium_cleanup(void *pdev);
int cavium_general_cleanup(void);
int do_init(cavium_device * pkp_dev);
void do_pci_write_config(cavium_device *pkp_dev);
int load_microcode(cavium_device * pkp_dev, int type);
int pkp_init_board (cavium_device * pkp_dev);
int init_ms_key(cavium_device *pkp_dev, int ucode_idx);
int cavium_common_init(cavium_general_config *gconfig);
int cavium_devres_init(cavium_general_config *gconfig,cavium_device *pkp_dev);
int cavium_common_cleanup(void);
int cavium_devres_cleanup(cavium_device *pkp_dev);

#endif


/*
 * $Id: init_cfg.h,v 1.12 2009/09/09 11:26:19 aravikumar Exp $
 * $Log: init_cfg.h,v $
 * Revision 1.12  2009/09/09 11:26:19  aravikumar
 * NPLUS macro dependency removed and made it dynamic
 *
 * Revision 1.11  2008/07/18 05:53:43  aramesh
 * px_flag is defined.
 *
 * Revision 1.10  2008/07/08 04:43:10  aramesh
 * bar_0 and bar_2 are changed to ptrlong type.
 *
 * Revision 1.9  2008/07/02 12:35:26  aramesh
 * deleted part number and corresponding flags.
 *
 * Revision 1.8  2007/11/19 11:11:55  lpathy
 * ported to 64 bit windows.
 *
 * Revision 1.7  2007/07/31 14:08:05  tghoriparti
 * changes to cavium_common_cleanup revoked
 *
 * Revision 1.6  2007/07/31 10:11:08  tghoriparti
 * N1 related changes done
 *
 * Revision 1.5  2007/07/24 12:51:41  kchunduri
 * --added new init function declarations. This is required for multi-card support on FreeBSD.
 *
 * Revision 1.4  2007/05/01 06:39:57  kchunduri
 * * fix compiler warnings.
 *
 * Revision 1.3  2007/03/06 03:15:24  panicker
 * * init_ms_key() uses same  prototype as N1 for PX.
 *
 * Revision 1.2  2007/01/11 02:08:44  panicker
 * - init_ms_key() use non-NPLUS mode in PX
 *
 * Revision 1.1  2007/01/06 02:47:40  panicker
 * * first cut - NITROX PX driver
 *
 * Revision 1.6  2005/06/13 06:35:42  rkumar
 * Changed copyright
 *
 * Revision 1.5  2005/02/01 04:11:07  bimran
 * copyright fix
 *
 * Revision 1.4  2004/05/02 19:44:29  bimran
 * Added Copyright notice.
 *
 * Revision 1.3  2004/04/21 19:18:58  bimran
 * NPLUS support.
 *
 * Revision 1.2  2004/04/20 02:26:41  bimran
 * Removed context chunk size field from cavium_config structure.
 *
 * Revision 1.1  2004/04/15 22:40:49  bimran
 * Checkin of the code from India with some cleanups.
 *
 */

