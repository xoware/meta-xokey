/* cavium_be.h */
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
#ifndef _CAVIUM_ENDIAN_H
#define _CAVIUM_ENDIAN_H

#define CAVIUM_ENDIAN	__CAVIUM_BIG_ENDIAN

#if 0
#define COMPLETION_CODE_VALUE((p))	(Uint8 *)((p) >> COMPLETION_CODE_SHIFT)
#endif

#define ENDIAN_SWAP_8_BYTE(_i) \
  ((((((Uint64)(_i)) >>  0) & (Uint64)0xff) << 56) | \
   (((((Uint64)(_i)) >>  8) & (Uint64)0xff) << 48) | \
   (((((Uint64)(_i)) >> 16) & (Uint64)0xff) << 40) | \
   (((((Uint64)(_i)) >> 24) & (Uint64)0xff) << 32) | \
   (((((Uint64)(_i)) >> 32) & (Uint64)0xff) << 24) | \
   (((((Uint64)(_i)) >> 40) & (Uint64)0xff) << 16) | \
   (((((Uint64)(_i)) >> 48) & (Uint64)0xff) <<  8) | \
   (((((Uint64)(_i)) >> 56) & (Uint64)0xff) <<  0))

#ifndef htobe64
#define htobe64(_i)	(_i)
#define htobe32(_i)	(_i)
#define htobe16(_i)	(_i)
#endif

#ifndef htole64
#define htole64(_i) ENDIAN_SWAP_8_BYTE((_i))
#endif

#define betoh64(_i)	(_i)
#define letoh64(_i) ENDIAN_SWAP_8_BYTE((_i))
#define betoh32(_i)	(_i)
#define betoh16(_i)	(_i)

#endif

/*
 * $Id: cavium_be.h,v 1.3 2009/06/11 08:02:33 aravikumar Exp $
 * $Log: cavium_be.h,v $
 * Revision 1.3  2009/06/11 08:02:33  aravikumar
 * Changes made for FC-10
 *
 * Revision 1.2  2007/02/02 02:36:13  panicker
 * * _ENDIAN definition in linux_sysdep.h
 *
 * Revision 1.1  2007/01/06 02:47:40  panicker
 * * first cut - NITROX PX driver
 *
 * Revision 1.2  2005/02/01 04:12:05  bimran
 * copyright fix
 *
 * Revision 1.1  2004/06/10 05:14:41  bimran
 * big endian macros
 *
 */

