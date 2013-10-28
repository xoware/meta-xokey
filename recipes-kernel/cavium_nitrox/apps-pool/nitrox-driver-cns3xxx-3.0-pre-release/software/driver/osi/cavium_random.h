/* cavium_random.h */
/*
 * Copyright (c) 2003-2006 Cavium Networks (support@cavium.com). All rights 
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
#ifndef _CAV_RANDOM_H
#define _CAV_RANDOM_H

/* Reducing: 16 bytes (See buffer_pool.h for more details)
 * 8 bytes for completion code
 */
#define RND_MAX		(32768-16-8)

int init_rnd_buffer(cavium_device *);
void cleanup_rnd_buffer(cavium_device *);

int  fill_rnd_buffer(cavium_device *, int);
int get_rnd(cavium_device *, Uint8 *, Uint16, int);

#endif 

/*
 * $Id: cavium_random.h,v 1.4 2009/09/09 11:26:19 aravikumar Exp $
 * $Log: cavium_random.h,v $
 * Revision 1.4  2009/09/09 11:26:19  aravikumar
 * NPLUS macro dependency removed and made it dynamic
 *
 * Revision 1.3  2007/03/06 03:16:02  panicker
 * * fill_rnd_buffer() and get_rnd() uses same  prototype as N1 for PX in PLUS
 *   mode.
 *
 * Revision 1.2  2007/01/13 03:14:49  panicker
 * * compilation warnings fixed.
 * * get_rnd() and fill_rnd_buffer() use non-NPLUS mode call for PX.
 *
 * Revision 1.1  2007/01/06 02:47:40  panicker
 * * first cut - NITROX PX driver
 *
 * Revision 1.10  2006/02/27 07:18:42  sgadam
 *    - Copyright updated.
 *
 * Revision 1.9  2006/02/22 11:18:49  rkumar
 * Random buffer size reduced by 8 bytes to hold completion code. If not, this will
 * cause random crashes
 *
 * Revision 1.8  2005/06/13 06:35:42  rkumar
 * Changed copyright
 *
 * Revision 1.7  2005/02/01 04:11:07  bimran
 * copyright fix
 *
 * Revision 1.6  2004/06/02 02:08:02  tsingh
 * removed get_id() (bimran).
 *
 * Revision 1.5  2004/05/11 03:10:39  bimran
 * some performance opt.
 *
 * Revision 1.4  2004/05/05 06:45:30  bimran
 * Added another function to get request ids from random pool.
 *
 * Revision 1.3  2004/05/02 19:44:29  bimran
 * Added Copyright notice.
 *
 * Revision 1.2  2004/04/21 19:18:58  bimran
 * NPLUS support.
 *
 * Revision 1.1  2004/04/15 22:40:48  bimran
 * Checkin of the code from India with some cleanups.
 *
 */

