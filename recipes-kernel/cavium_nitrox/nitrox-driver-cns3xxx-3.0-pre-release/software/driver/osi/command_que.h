/* command_queue.h */
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
#ifndef _COMMAND_QUE_H
#define _COMMAND_QUE_H

void reset_command_queue(cavium_device *, int);
void inc_front_command_queue(cavium_device *, int);
int cleanup_command_queue(cavium_device *, int);
int init_command_queue(cavium_device *, Uint32);

#define unlock_command_queue(pdev, q) cavium_spin_unlock_softirqrestore(&(pdev)->command_queue_lock[(q)])
#define lock_command_queue(pdev, q) cavium_spin_lock_softirqsave(&(pdev)->command_queue_lock[(q)])


#endif

/*
 * $Id: command_que.h,v 1.1 2007/01/06 02:47:40 panicker Exp $
 * $Log: command_que.h,v $
 * Revision 1.1  2007/01/06 02:47:40  panicker
 * * first cut - NITROX PX driver
 *
 * Revision 1.8  2005/08/31 18:10:30  bimran
 * Fixed several warnings.
 * Fixed the corerct use of ALIGNMENT and related macros.
 *
 * Revision 1.7  2005/06/13 06:35:42  rkumar
 * Changed copyright
 *
 * Revision 1.6  2005/02/01 04:11:07  bimran
 * copyright fix
 *
 * Revision 1.5  2004/06/23 19:50:01  bimran
 * Fixed init_command_queue function proto.
 *
 * Revision 1.4  2004/05/02 19:44:29  bimran
 * Added Copyright notice.
 *
 * Revision 1.3  2004/04/30 01:38:17  tsingh
 * changed inc_front_* to inline.
 *
 * Revision 1.2  2004/04/30 00:01:21  bimran
 * changed spin_lock/unlock to spin_lock/unlock_softirq*
 *
 * Revision 1.1  2004/04/15 22:40:48  bimran
 * Checkin of the code from India with some cleanups.
 *
 */

