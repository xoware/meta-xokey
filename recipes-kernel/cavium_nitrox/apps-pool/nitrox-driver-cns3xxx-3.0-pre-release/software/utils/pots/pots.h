/*
 * pots.h:
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

#ifndef _CAVIUM_POTS_H_
#define _CAVIUM_POTS_H_

/* misc. */
#include <errno.h>
#include "cavium_common.h"
/*#ifdef NPLUS
#define GET_SSL_IDX microcode_type = (device==NPX_DEVICE || ssl_mlm )? SSL_MLM_IDX : SSL_SPM_IDX
#define GET_IPSEC_IDX microcode_type = (device==NPX_DEVICE || !ssl_mlm )? IPSEC_MLM_IDX : IPSEC_SPM_IDX
#endif*/

extern int errno;

int reg_r_w_flg;

#define OP_IPSEC_PACKET_INBOUND                 0x10
#define OP_IPSEC_PACKET_OUTBOUND                0x11
#ifdef MC2
#define OP_WRITE_INBOUND_IPSEC_SA		0x2014
#define OP_WRITE_OUTBOUND_IPSEC_SA		0x4014
#else 
#define OP_WRITE_IPSEC_SA                         0x14
#endif

/* default name of conf file */
#ifdef CNS3000
#define		PT_CONF_FNAME		"pots.cnf"
#define		PT_AES_DATA_FNAME	"aes.txt"
#else
#define		PT_CONF_FNAME		"../../utils/pots/pots.cnf"
#define		PT_AES_DATA_FNAME	"../../utils/pots/aes.txt"
#endif

/* default names for some test results files */
#ifdef CNS3000
#define		PT_LOG_FNAME		"logs/pots.log"
#define		PT_RESULTS_FNAME	"logs/results.log"
#define		PT_RC4_RESULTS_FNAME	"logs/rc4.log"
#define		PT_HMAC_RESULTS_FNAME	"logs/hmac.log"
#define		PT_3DES_RESULTS_FNAME	"logs/3des.log"
#define		PT_AES_RESULTS_FNAME	"logs/aes.log"
#define		PT_MODEX_RESULTS_FNAME	"logs/modex.log"
#else
#define		PT_LOG_FNAME		"../../utils/pots/logs/pots.log"
#define		PT_RESULTS_FNAME	"../../utils/pots/logs/results.log"
#define		PT_RC4_RESULTS_FNAME	"../../utils/pots/logs/rc4.log"
#define		PT_HMAC_RESULTS_FNAME	"../../utils/pots/logs/hmac.log"
#define		PT_3DES_RESULTS_FNAME	"../../utils/pots/logs/3des.log"
#define		PT_AES_RESULTS_FNAME	"../../utils/pots/logs/aes.log"
#define		PT_MODEX_RESULTS_FNAME	"../../utils/pots/logs/modex.log"
#endif

/* default ucode file names */
#define		PT_BOOT_FNAME		"boot.out"
#define		PT_MAIN_SSL_FNAME		"main_ssl.out"
#define		PT_MAIN_IPSEC_FNAME		"main_ipsec.out"
#define		PT_POTS_UCODE_FNAME	"pots_boot.out"

//#define		PT_ADMIN_FNAME		"admin.out"

/* programs log levels */
#define		PT_LOG_NONE		0x0000
#define		PT_LOG_FATAL		0x0001
#define		PT_LOG_SEVERE		0x0002
#define		PT_LOG_ERROR		0x0004
#define		PT_LOG_WARNING		0x0008
#define		PT_LOG_INFO		0x0010
#define		PT_LOG_DEBUG		0x0020
#define		PT_LOG_ALWAYS		0xFFFF

/* define fo # of cores */
#define		MAX_CORES		26

/* defines for working with REQUEST_UNIT reg */
/************
#define		PT_RU_NONE			0
#define		PT_RU_DISABLE_RU		1
#define		PT_RU_ENABLE_RU			2
#define		PT_RU_DISABLE_ALL_EX		3
#define		PT_RU_ENABLE_ALL_EX		4
**********/

/* 
 * define a struct that keeps track of configuration 
 * options read from pots.cnf for the 5 diff crypto
 * tests (RC4, HMAC, 3DES, AES, MOD_EX)
 */
#define MAX_CRYPTO_TEST_CNF			5

/* amx buffer size for holding msg to be encrypted/decrypted */
#define MAX_CRYPTO_MSG_SZ			(64 * 1024)		/* 16*1024 */
#define MAX_CRYPTO_KEY_SZ			256		/* 2048 bits */
//#define MAX_CRYPTO_MOD_SZ			256
#define MAX_CRYPTO_MOD_SZ			512
#define MAX_CRYPTO_EXP_SZ			24
/* #define MAX_CRYPTO_EXP_SZ			20 */

//#define MAX_CRYPTO_MSGBUF_SZ		16384+256	/* 16*1024 */
#define MAX_CRYPTO_MSGBUF_SZ		((64 * 1024 ) + 256)	/* 16*1024 */
#define MAX_CRYPTO_KEYBUF_SZ		256+1		/* 2048 bits */

/* valid test ids & names are: */
#define	PT_TESTID_RC4				0		
#define	PT_TESTID_HMAC				1
#define	PT_TESTID_3DES				2
#define	PT_TESTID_AES				3
#define	PT_TESTID_MOD_EX			4

#define	PT_TESTNAME_RC4				"RC4"
#define	PT_TESTNAME_HMAC			"HMAC"
#define	PT_TESTNAME_3DES			"3DES"
#define	PT_TESTNAME_AES				"AES"
#define	PT_TESTNAME_MOD_EX			"MOD_EX"

struct pots_crypto_test_cnf {
	int cc_test_id;
	char cc_test_name[36];
	int cc_start_key_sz;
	int cc_end_key_sz;
	int cc_key_incr;
	int cc_start_msg_sz;
	int cc_end_msg_sz;
	int cc_msg_incr;
};
	

/*
 * This is a pure user level struct
 * pots_sts struct contains the state of the pots test and the
 * shim and device driver, like 
 * 		- is microcode loaded or not ?
 * 		- are cores enabled or not
 *
 *
 */
struct pots_struct {
	FILE *pt_lfp;				/* ptr to log file */
	FILE *pt_rfp;				/* ptr to results file */
	FILE *pt_cfp;				/* ptr to cnf file */
	int pt_dd_fd;				/* dd's fd */
	int pt_prog_loglvl;			/* log level for program */
	int pt_init;				/* is this struct initialized?*/
	int pt_ddr_size;			/* size of ddr context memory */
	int pt_load_ucode_on_startup;
	char pt_boot_ucode_fname[256];
	char pt_admin_ucode_fname[256];
	char pt_main_ucode_fname[256];
	char pt_pots_ucode_fname[256];
	int pt_ucode_loaded;		/* is microcode loaded ? */
	int pt_pots_sp_ucode_loaded;    /* is pots specific microcode loaded? */
	int pt_ru_enabled;		/* is request unit enabled ? */
	unsigned long pt_bar0;		/* value of bar0 */
	unsigned long pt_bar2;		/* value of bar2 */
	unsigned long pt_bist_regval;	/* which cores are enabled ? */
	unsigned long pt_cores_enabled;	/* which cores are enabled ? */
	unsigned long pt_cores_present;	/* which cores are present ? */
	struct pots_crypto_test_cnf pt_test_cnf[MAX_CRYPTO_TEST_CNF];
#ifdef CAVIUM_MULTICARD_API
        unsigned int dev_cnt;
	Uint8 dev_mask;
        Uint32 dev_id;
#endif
};
typedef struct pots_struct pots_sts;


/* defines for various tests */
#define			PT_ALL				0xFFFF
#define			PT_NONE				-1
#define			PT_INVALID			0

#define                 PT_SOFT_RESET                   1
#define                 PT_LOAD_MICROCODE               2
#define                 PT_UCODE_LOADED                 3
#define                 PT_READ_WRITE_REGS              4
#define                 PT_CHECK_BIST_REG               5
#define                 PT_READ_WRITE_DDR               6
#define                 PT_RANDOM_NR_GEN                7
#define                 PT_CRYPTO_RC4                   8
#define                 PT_CRYPTO_HMAC                  9
#define                 PT_CRYPTO_3DES                  10
#define                 PT_CRYPTO_AES                   11
#define                 PT_CRYPTO_MOD_EX                12
#define                 PT_KEY_MEMORY                   13
#define                 PT_CHECK_UNIT_ENABLE_REG        14
#define                 PT_CHECK_NR_EXEC_UNITS          15
#define                 PT_DISABLE_RU                   16
#define                 PT_ENABLE_RU                    17
#define                 PT_DISABLE_ALL_EU               18
#define                 PT_ENABLE_ALL_EU                19
#define                 PT_GET_CHIP_CSR                 20
#define                 PT_GET_PCI_CSR                  21
#define                 PT_GET_PCI_CONFIG_REG           22

/* IPSec Constants */
#define                 PT_INBOUND_TEST                 23
#define                 PT_OUTBOUND_TEST                24

//#define                       PT_GET_DDR_SIZE                 20
#define                 PT_POTS_SP_INIT_CODE            25
#define                 PT_INTERRUPT                    26
#define                 PT_TEST_CORES_FOR_SELF_ID_INS   27
#define                 PT_ARBITER                      28
#define                 PT_ENDIAN_TEST                  29
#define                 PT_MAX_TEST                     31


#define			PT_DISABLE_EU_FROM_MASK		100
#define			PT_ENABLE_EU_FROM_MASK		101
#define			PT_NO_OP			301
#define			PT_POTS_SOFT_RESET		302

#define			PT_PCI_EEPROM			50
#define			PT_TWSI				51
#define			PT_QUEUE			52
#define			PT_VIRTUAL_RESET		53
#define			PT_POTS_INIT_CODE		54


/* calc_method for various crypto calls */
#define			CM_INVALID			0
#define			CM_ONE_CALL			1
#define			CM_MULTIPLE_CALLS		2

/* # of crypto tests to run */
#define			PT_MAX_HMAC_TESTS		5
#define			PT_MAX_RC4_TESTS		5
#define			PT_MAX_3DES_TESTS		5
#define			PT_MAX_AES_TESTS		3
#define			PT_MAX_MOD_EX_TESTS		5

extern int base_b_offset;

/* name of device driver file */
//#if  defined(NITROX_PX)
//#define			DD_FILENAME			"/dev/pkp_nle_dev"
//#define 		BASE_B_OFFSET			0x0100
//#else
#define			DD_FILENAME			"/dev/pkp_dev"

#define 		BASE_B_OFFSET			base_b_offset
//#endif
/* max key memory */
#define			MAX_KEYMEM			8192
/* for max ddr memory */
#define			MAX_MEM				8192
#define			MAX_DDR_MEM_TO_TEST		16*1024*1024 /* 16 meg*/

/* max atomic keymem write */
#define			MAX_ATOMIC_KEYMEM_RW	512
#define			MAX_ATOMIC_MEM_RW	512

#define			PT_RAND_BUF_SZ		2500

/* #define		MAX_ATOMIC_KEYMEM_RW	1024 */

/* various pkp registers offset from bar0 */

/* BAR 0 */
#define COMMAND_STATUS				0X00
#define UNIT_ENABLE				0x10
#define IMR_REG					0X20
#define ISR_REG					0x28 
#define FAILING_SEQ_REG				0x30
#define FAILING_EXEC_REG			0x38
#define ECH_STAT_COUNTER_HIGH_REG		0x88
#define ECH_STAT_COUNTER_LOW_REG		0x90
#define EPC_STAT_COUNTER_HIGH_REG		0x98
#define EPC_STAT_COUNTER_LOW_REG		0xA0
#define PMLT_STAT_COUNTER_LOW_REG		0xA8
#define PMLT_STAT_COUNTER_HIGH_REG		0xB0
#define CLK_STAT_COUNTER_HIGH_REG		0xB8
#define CLK_STAT_COUNTER_LOW_REG		0xC0
#define PCI_ERR_REG				0xD0 
#define DEBUG_REG				0x68
#define CMC_CTL_REG				0xD8
#define UCODE_LOAD				0x18
#define PSE_TO_HOST_DATA			0x58
#define HOST_TO_PSE_DATA			0x60

/* BAR 1 */
#define  REQ0_BASE_HIGH				BASE_B_OFFSET + 0x00
#define  REQ0_BASE_LOW				BASE_B_OFFSET + 0x08
#define  REQ0_SIZE				BASE_B_OFFSET + 0x10

#define  REQ1_BASE_HIGH				BASE_B_OFFSET + 0x20
#define  REQ1_BASE_LOW				BASE_B_OFFSET + 0x28
#define  REQ1_SIZE				BASE_B_OFFSET + 0x30

#define  REQ2_BASE_HIGH				BASE_B_OFFSET + 0x40
#define  REQ2_BASE_LOW				BASE_B_OFFSET + 0x48
#define  REQ2_SIZE				BASE_B_OFFSET + 0x50

#define  REQ3_BASE_HIGH				BASE_B_OFFSET + 0x60
#define  REQ3_BASE_LOW				BASE_B_OFFSET + 0x68
#define  REQ3_SIZE				BASE_B_OFFSET + 0x70

#define REQ0_DOOR_BELL				BASE_B_OFFSET + 0x18
#define REQ1_DOOR_BELL				BASE_B_OFFSET + 0x38
#define REQ2_DOOR_BELL				BASE_B_OFFSET + 0x58
#define REQ3_DOOR_BELL				BASE_B_OFFSET + 0x78

/*LDT specific registers */
#define LMT_CONTROL_REG				0xC0
#define LMT_INTERRUPT_CONTROL_REG		0xC8
#define LMT_INTERRUPT_DESTINATION_REG		0xD0
#define LMT_ERROR_REG				0xD8
#define LMT_EXPECTED_CRC_REG			0xE0
#define LMT_RCVD_CRC_REG			0xE8

#ifdef SSL
#define CONTEXT_SIZE				1024
#else
#ifdef MC2
#define CONTEXT_SIZE				256
#else
#define CONTEXT_SIZE				128
#endif
#endif

#endif	/* _CAVIUM_POTS_H */


/*
 * $Id: pots.h,v 1.14 2009/09/22 09:57:08 aravikumar Exp $
 * $Log: pots.h,v $
 * Revision 1.14  2009/09/22 09:57:08  aravikumar
 * made list of test options to constant for both plus and non-nplus
 *
 * Revision 1.13  2009/09/09 15:01:46  aravikumar
 * NPLUS macro dependency removed and made it dynamic
 *
 * Revision 1.12  2008/11/05 06:45:57  ysandeep
 * Added NPLUS support for N1/NLite
 *
 * Revision 1.11  2008/10/31 10:51:29  ysandeep
 * MULTICARD support added for ipsec.
 * nplus_handle removed (NPLUS).
 *
 * Revision 1.10  2008/10/24 08:43:51  ysandeep
 * NPLUS support added
 *
 * Revision 1.9  2008/07/29 11:02:46  aramesh
 * dev_id is Uint32.
 *
 * Revision 1.8  2008/07/07 13:00:18  aramesh
 * dev_mask is added.
 * ----------------------------------------------------------------------
 *
 * Revision 1.7  2008/07/03 05:22:58  aramesh
 * deleted NITROX_PX flag.
 *
 * Revision 1.6  2008/03/10 10:22:58  kkiran
 *  - Cavium Copyright added.
 *
 * Revision 1.5  2008/02/22 10:49:03  aramesh
 * included the cavium_common.h file
 *
 * Revision 1.4  2008/01/18 07:58:39  tghoriparti
 * IPSEC random test number changed to 5 and option "all" to run all the tests
 *
 * Revision 1.3  2007/09/11 14:09:02  kchunduri
 * --provide option to run POTS on each PX device.
 *
 * Revision 1.2  2007/07/06 13:07:19  tghoriparti
 * PX changes done
 *
 * Revision 1.1  2007/02/20 23:43:29  panicker
 * * Utilities checked in
 *
 * Revision 1.3  2005/10/04 07:32:06  sgadam
 * - Key memory test and BIST tests swapped
 *
 * Revision 1.2  2005/05/21 05:17:31  rkumar
 * Merge with India CVS Head
 *
 * Revision 1.1  2004/04/15 22:40:51  bimran
 * Checkin of the code from India with some cleanups.
 *
 */

