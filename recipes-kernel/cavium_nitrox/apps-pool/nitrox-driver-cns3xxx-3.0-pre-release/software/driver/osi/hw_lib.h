/* hw_lib.h */
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
#ifndef _PKP_HW_LIB_H
#define _PKP_HW_LIB_H

void    find_cfg_part_initialize(cavium_device *);
void 	enable_request_unit(cavium_device * pkp_dev);

void 	disable_request_unit(cavium_device * pkp_dev);

void 	enable_all_exec_units(cavium_device * pkp_dev);

void	enable_exec_units(cavium_device * pkp_dev);

void 	disable_all_exec_units(cavium_device * pkp_dev);

void 	setup_request_queue(cavium_device * pkp_dev);

void 	enable_data_swap(cavium_device * pkp_dev);

void	set_PCIX_split_transactions(cavium_device *);

void	set_PCI_cache_line(cavium_device * pkp_dev);

Uint32 	get_exec_units(cavium_device * pkp_dev);

void 	set_soft_reset(cavium_device * pkp_dev);

int     do_soft_reset(cavium_device * pkp_dev);

int 	count_set_bits(Uint32 value, int bit_count);

Uint32	cavium_pow(Uint32 x, Uint32 y);

Uint32  get_exec_units_part(cavium_device * pkp_dev);

int	check_core_mask(Uint32 uen_mask);

void	enable_local_ddr(cavium_device *pkp_dev);

void	check_dram(cavium_device *);

void	enable_rnd_entropy(cavium_device *);

Uint32	get_first_available_core(Uint32, Uint32);

Uint32	get_unit_id(Uint32);

void	enable_exec_units_from_mask(cavium_device *, Uint32);

void	disable_exec_units_from_mask(cavium_device *, Uint32);

void	setup_request_queues(cavium_device *);

int 	init_twsi(cavium_device *);

unsigned int get_core_mask(cavium_device *pdev, int ucode_idx);
Uint32 get_enabled_units(cavium_device *pdev);
void cycle_exec_units_from_mask(cavium_device *pdev, Uint32 mask);

//#if !defined(NITROX_PX)
/*
 * returns 0 if it finds atleast one core pair
 * otherwise returns non-zero
 */
int get_core_pair(cavium_device *pdev, Uint32 mask);
//#endif


#endif /*_PKP_HW_LIB_H*/



/*
 * $Id: hw_lib.h,v 1.4 2009/09/09 11:26:19 aravikumar Exp $
 * $Log: hw_lib.h,v $
 * Revision 1.4  2009/09/09 11:26:19  aravikumar
 * NPLUS macro dependency removed and made it dynamic
 *
 * Revision 1.3  2008/07/02 12:35:26  aramesh
 * deleted part number and corresponding flags.
 *
 * Revision 1.2  2007/01/11 02:02:41  panicker
 * * get_core_pair() is used when !(NITROX_PX).
 *
 * Revision 1.1  2007/01/06 02:47:40  panicker
 * * first cut - NITROX PX driver
 *
 * Revision 1.7  2006/01/25 05:59:27  ksadasivuni
 * - removed wrong inline
 *
 * Revision 1.6  2005/06/13 06:35:42  rkumar
 * Changed copyright
 *
 * Revision 1.5  2005/02/01 04:11:07  bimran
 * copyright fix
 *
 * Revision 1.4  2005/01/26 20:34:56  bimran
 * Added NPLUS specific functions to check for available core pairs for Modexp operation.
 *
 * Revision 1.3  2004/05/02 19:44:29  bimran
 * Added Copyright notice.
 *
 * Revision 1.2  2004/04/21 19:18:58  bimran
 * NPLUS support.
 *
 * Revision 1.1  2004/04/15 22:40:49  bimran
 * Checkin of the code from India with some cleanups.
 *
 */

