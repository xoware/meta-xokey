/*
 * pots_dd.h:
 */
/*
 * Copyright (c) 2003-2005, Cavium Networks. All rights reserved.
 *
 * This Software is the property of Cavium Networks. The Software and all 
 * accompanying documentation are copyrighted. The Software made available here 
 * constitutes the proprietary information of Cavium Networks. You agree to take * 
 * reasonable steps to prevent the disclosure, unauthorized use or unauthorized 
 * distribution of the Software. You shall use this Software solely with Cavium 
 * hardware. 
 *
 * Except as expressly permitted in a separate Software License Agreement 
 * between You and Cavium Networks, You shall not modify, decompile, 
 * disassemble, extract, or otherwise reverse engineer this Software. You shall
 * not make any copy of the Software or its accompanying documentation, except 
 * for copying incident to the ordinary and intended use of the Software and 
 * the Underlying Program and except for the making of a single archival copy.
 *
 * This Software, including technical data, may be subject to U.S. export 
 * control laws, including the U.S. Export Administration Act and its 
 * associated regulations, and may be subject to export or import regulations 
 * in other countries. You warrant that You will comply strictly in all 
 * respects with all such regulations and acknowledge that you have the 
 * responsibility to obtain licenses to export, re-export or import the 
 * Software.
 *
 * TO THE MAXIMUM EXTENT PERMITTED BY LAW, THE SOFTWARE IS PROVIDED "AS IS" AND 
 * WITH ALL FAULTS AND CAVIUM MAKES NO PROMISES, REPRESENTATIONS OR WARRANTIES, 
 * EITHER EXPRESS,IMPLIED, STATUTORY,OR OTHERWISE, WITH RESPECT TO THE SOFTWARE,
 * INCLUDING ITS CONDITION,ITS CONFORMITY TO ANY REPRESENTATION OR DESCRIPTION, 
 * OR THE EXISTENCE OF ANY LATENT OR PATENT DEFECTS, AND CAVIUM SPECIFICALLY 
 * DISCLAIMS ALL IMPLIED (IF ANY) WARRANTIES OF TITLE, MERCHANTABILITY, 
 * NONINFRINGEMENT, FITNESS FOR A PARTICULAR PURPOSE,LACK OF VIRUSES,ACCURACY OR
 * COMPLETENESS, QUIET ENJOYMENT, QUIET POSSESSION OR CORRESPONDENCE TO 
 * DESCRIPTION. THE ENTIRE RISK ARISING OUT OF USE OR PERFORMANCE OF THE 
 * SOFTWARE LIES WITH YOU.
 *
 */



struct pots_dd_intf_struct {
	Uint32 cmd;		// FOR NOW
	int  intr_flag;	// for self id ins - r/w field
	Uint8 inbuf[8];	// for our tag
	Uint8 cmd_copy[8];
	Uint8  dptr_copy[8];
	Uint8  cptr_copy[8];
	Uint8  rptr[208];
};
typedef struct pots_dd_intf_struct pots_dd_intf_sts;


/* ioctl #'s for pots related ioctl's */
#define			CSP1_POTS_TEST				30
#define			CSP1_POTS_INIT_CODE			31
#define			CSP1_POTS_SOFT_RESET_CODE	32

/* 
 * for CSP1_POTS_TEST ioctl, the cmd determines what is returned
 * back from kernel to user, etc.
 */
#define			POTS_GET_DDR_SIZE			1
#define			POTS_RUN_SELF_ID_INS		2
#define			POTS_RUN_ENDIAN_INS		3

#define IOCTL_CSP1_POTS_TEST \
	_IOWR(CSP1_MAGIC, CSP1_POTS_TEST, sizeof(pots_dd_intf_sts))

#define IOCTL_CSP1_POTS_INIT_CODE   \
	_IOWR(CSP1_MAGIC, CSP1_POTS_INIT_CODE, Csp1InitBuffer)

#define IOCTL_CSP1_POTS_SOFT_RESET_CODE   		\
	_IO(CSP1_MAGIC, CSP1_POTS_SOFT_RESET_CODE)

/*****
#define IOCTL_CSP1_ADMIN_OPERATION   \
	_IOWR(CSP1_MAGIC, CSP1_ADMIN_OPERATION_CODE,Csp1OperationBuffer)

static const unsigned long IOCTL_CSP1_ADMIN_OPERATION = 
IOCTL_CODER(CSP1_DEVICE_TYPE, (CSP1_ADMIN_OPERATION_CODE | 0x800), METHOD_BUFFERED, \
			FILE_READ_DATA|FILE_WRITE_DATA);
***/

/* function prototypes */
//int pots_ioctl(void *pkp_devp, pots_dd_intf_sts *pots_dd_intf_stp);

/*
 * $Id: pots_dd.h,v 1.2 2008/03/10 10:22:58 kkiran Exp $
 * $Log: pots_dd.h,v $
 * Revision 1.2  2008/03/10 10:22:58  kkiran
 *  - Cavium Copyright added.
 *
 * Revision 1.1  2007/02/20 23:43:29  panicker
 * * Utilities checked in
 *
 * Revision 1.1  2004/04/15 22:40:51  bimran
 * Checkin of the code from India with some cleanups.
 *
 */

