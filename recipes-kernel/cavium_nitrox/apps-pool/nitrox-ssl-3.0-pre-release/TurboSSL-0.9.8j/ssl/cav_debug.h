
/* Copyright (c) 2003-2005 Cavium Networks (support@cavium.com) All rights reserved. 
 *
 * Redistribution and use in source and binary forms, with or without modification,
 * are permitted provided that the following conditions are met:

 * 1. Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice, 
 * this list of conditions and the following disclaimer in the documentation and/or 
 * other materials provided with the distribution.
 *
 * 3. Cavium Networks name may not be used to endorse or promote products derived 
 * from this software without specific prior written permission.
 *
 * This Software, including technical data, may be subject to U.S. export control laws, 
 * including the U.S. Export Administration Act and its associated regulations, and may be
 * subject to export or import regulations in other countries. You warrant that You will comply 
 * strictly in all respects with all such regulations and acknowledge that you have the responsibility 
 * to obtain licenses to export, re-export or import the Software.
 *
 * TO THE MAXIMUM EXTENT PERMITTED BY LAW, THE SOFTWARE IS PROVIDED "AS IS" AND WITH ALL FAULTS 
 * AND CAVIUM MAKES NO PROMISES, REPRESENTATIONS OR WARRANTIES, EITHER EXPRESS, IMPLIED, STATUTORY,
 * OR OTHERWISE, WITH RESPECT TO THE SOFTWARE, INCLUDING ITS CONDITION, ITS CONFORMITY TO ANY 
 * REPRESENTATION OR DESCRIPTION, OR THE EXISTENCE OF ANY LATENT OR PATENT DEFECTS, AND CAVIUM
 * SPECIFICALLY DISCLAIMS ALL IMPLIED (IF ANY) WARRANTIES OF TITLE, MERCHANTABILITY, NONINFRINGEMENT, 
 * FITNESS FOR A PARTICULAR PURPOSE, LACK OF VIRUSES, ACCURACY OR COMPLETENESS, QUIET ENJOYMENT, 
 * QUIET POSSESSION OR CORRESPONDENCE TO DESCRIPTION. THE ENTIRE RISK ARISING OUT OF USE OR PERFORMANCE 
 * OF THE SOFTWARE LIES WITH YOU.
*/
/*
 * cav_debug.h:
 *	Cavium Networks
 *  author: Naveed Cochinwala
 */
FILE *cav_nb_fp;

#ifdef CAV_DEBUG
#define cav_printf(format, args...)        printf(format, ##args)
#define cav_fprintf(cav_nb_fp, format, args...)   fprintf(cav_nb_fp, format, ##args)
#else
#define cav_printf(format, args...)
#define cav_fprintf(format, args...)       
#endif

/* name of log file = cav_nb.log.%d (pid) */
#define		CAV_NB_DEBUG_FILE			"cav_nb.log."


/*
 * define to indicate that more cavium crypto is needed
 */
#define		SSL_ERROR_WANT_CAVIUM_CRYPTO		54321

/*
 * defines for crypto states
 */
#define		CAV_ST_INVALID				-1
#define		CAV_ST_NONE				0
//#define		CAV_ST_IN_HANDSHAKE			1111
//#define		CAV_ST_IN_HANDSHAKE		        2132	
#define		CAV_ST_IN_DECRYPT			3333
#define		CAV_ST_IN_ENCRYPT			5555
#define		CAV_ST_IN_VRFY_CERT			8888
#define		CAV_ST_IN_RESUME_HANDSHAKE	        9999	
#define	        CAV_ST_IN_CHK_DEC_PEER                  2222 
#define		CAV_ST_IN_PRE_MASTER_KEY		4444
#define   	CAV_ST_IN_WRITE_CONTEXT			7777
#define         CAV_ST_IN_CHK_DEC_PEER_2		6666

/*
 * function prototypes
 */
extern int cav_print_state(SSL *s, char *fname);
extern void cav_set_nb_mode(SSL *s, int nb_mode);
extern int cav_get_nb_mode(SSL *s);
extern int cav_check_for_completion(SSL *s);


