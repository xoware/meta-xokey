
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
#include <errno.h>
#include "openssl/ssl.h"

#ifdef CAVIUM_SSL
#include "openssl/cav_crypto_engine.h"
#include "ssl_engine.h"
#include "openssl/cav_debug.h"
#include "ssl/cav_debug.h"
#endif


#ifdef CAVIUM_NB_CRYPTO
int cav_print_state(SSL *s, char *fname)
{
	cav_fprintf(cav_nb_fp,"%s: state = %d, 0x%0x\n", fname, s->state, s->state);
	
	switch (s->state) {

		case SSL_ST_RENEGOTIATE:
			cav_fprintf(cav_nb_fp,"%s: case SSL_ST_RENEGOTIATE\n", fname);
			break;

		case SSL_ST_BEFORE:
			cav_fprintf(cav_nb_fp,"%s: case SSL_ST_BEFORE\n", fname);

		case SSL_ST_ACCEPT:
			cav_fprintf(cav_nb_fp,"%s: case SSL_ST_ACCEPT\n", fname);
			break;

		case SSL_ST_BEFORE|SSL_ST_ACCEPT:
			cav_fprintf(cav_nb_fp,"%s: case SSL_ST_BEFORE|SSL_ST_ACCEPT\n", fname);
			break;

		case SSL_ST_OK|SSL_ST_ACCEPT:
			cav_fprintf(cav_nb_fp,"%s: case SSL_ST_OK|SSL_ST_ACCEPT\n", fname);
			break;

		case SSL3_ST_SW_HELLO_REQ_A:
			cav_fprintf(cav_nb_fp,"%s: case SSL3_ST_SW_HELLO_REQ_A\n", fname);
			break;

		case SSL3_ST_SW_HELLO_REQ_B:
			cav_fprintf(cav_nb_fp,"%s: case SSL3_ST_SW_HELLO_REQ_B\n", fname);
			break;

		case SSL3_ST_SW_HELLO_REQ_C:
			cav_fprintf(cav_nb_fp,"%s: case SSL3_ST_SW_HELLO_REQ_C\n", fname);
			break;

		case SSL3_ST_SR_CLNT_HELLO_A:
			cav_fprintf(cav_nb_fp,"%s: case SSL3_ST_SR_CLNT_HELLO_A\n", fname);
			break;

		case SSL3_ST_SR_CLNT_HELLO_B:
			cav_fprintf(cav_nb_fp,"%s: case SSL3_ST_SR_CLNT_HELLO_B\n", fname);
			break;

		case SSL3_ST_SR_CLNT_HELLO_C:
			cav_fprintf(cav_nb_fp,"%s: case SSL3_ST_SR_CLNT_HELLO_C\n", fname);
			break;

		case SSL3_ST_SW_SRVR_HELLO_A:
			cav_fprintf(cav_nb_fp,"%s: case SSL3_ST_SW_SRVR_HELLO_A\n", fname);
			break;

		case SSL3_ST_SW_SRVR_HELLO_B:
			cav_fprintf(cav_nb_fp,"%s: case SSL3_ST_SW_SRVR_HELLO_B\n", fname);
			break;

		case SSL3_ST_SW_CERT_A:
			cav_fprintf(cav_nb_fp,"%s: case SSL3_ST_SW_CERT_A\n", fname);
			break;

		case SSL3_ST_SW_CERT_B:
			cav_fprintf(cav_nb_fp,"%s: case SSL3_ST_SW_CERT_B\n", fname);
			break;

		case SSL3_ST_SW_KEY_EXCH_A:
			cav_fprintf(cav_nb_fp,"%s: case SSL3_ST_SW_KEY_EXCH_A\n", fname);
			break;

		case SSL3_ST_SW_KEY_EXCH_B:
			cav_fprintf(cav_nb_fp,"%s: case SSL3_ST_SW_KEY_EXCH_B\n", fname);
			break;

		case SSL3_ST_SW_CERT_REQ_A:
			cav_fprintf(cav_nb_fp,"%s: case SSL3_ST_SW_CERT_REQ_A\n", fname);
			break;

		case SSL3_ST_SW_CERT_REQ_B:
			cav_fprintf(cav_nb_fp,"%s: case SSL3_ST_SW_CERT_REQ_B\n", fname);
			break;

		case SSL3_ST_SW_SRVR_DONE_A:
			cav_fprintf(cav_nb_fp,"%s: case SSL3_ST_SW_SRVR_DONE_A\n", fname);
			break;

		case SSL3_ST_SW_SRVR_DONE_B:
			cav_fprintf(cav_nb_fp,"%s: case SSL3_ST_SW_SRVR_DONE_B\n", fname);
			break;

		case SSL3_ST_SW_FLUSH:
			cav_fprintf(cav_nb_fp,"%s: case SSL3_ST_SW_FLUSH\n", fname);
			break;

		case SSL3_ST_SR_CERT_A:
			cav_fprintf(cav_nb_fp,"%s: case SSL3_ST_SR_CERT_A\n", fname);
			break;

		case SSL3_ST_SR_CERT_B:
			cav_fprintf(cav_nb_fp,"%s: case SSL3_ST_SR_CERT_B\n", fname);
			break;

		case SSL3_ST_SR_KEY_EXCH_A:
			cav_fprintf(cav_nb_fp,"%s: case SSL3_ST_SR_KEY_EXCH_A\n", fname);
			break;

		case SSL3_ST_SR_KEY_EXCH_B:
			cav_fprintf(cav_nb_fp,"%s: case SSL3_ST_SR_KEY_EXCH_B\n", fname);
			break;

		case SSL3_ST_SR_CERT_VRFY_A:
			cav_fprintf(cav_nb_fp,"%s: case SSL3_ST_SR_CERT_VRFY_A\n", fname);
			break;

		case SSL3_ST_SR_CERT_VRFY_B:
			cav_fprintf(cav_nb_fp,"%s: case SSL3_ST_SR_CERT_VRFY_B\n", fname);
			break;

		case SSL3_ST_SR_FINISHED_A:
			cav_fprintf(cav_nb_fp,"%s: case SSL3_ST_SR_FINISHED_A\n", fname);
			break;

		case SSL3_ST_SR_FINISHED_B:
			cav_fprintf(cav_nb_fp,"%s: case SSL3_ST_SR_FINISHED_B\n", fname);
			break;

		case SSL3_ST_SW_CHANGE_A:
			cav_fprintf(cav_nb_fp,"%s: case SSL3_ST_SW_CHANGE_A\n", fname);
			break;

		case SSL3_ST_SW_CHANGE_B:
			cav_fprintf(cav_nb_fp,"%s: case SSL3_ST_SW_CHANGE_B\n", fname);
			break;

		case SSL3_ST_SW_FINISHED_A:
			cav_fprintf(cav_nb_fp,"%s: case SSL3_ST_SW_FINISHED_A\n", fname);
			break;

		case SSL3_ST_SW_FINISHED_B:
			cav_fprintf(cav_nb_fp,"%s: case SSL3_ST_SW_FINISHED_B\n", fname);
			break;

		case SSL_ST_OK:
			cav_fprintf(cav_nb_fp,"%s: case SSL_ST_OK\n", fname);
			break;

		case CAV_ST_IN_HANDSHAKE:
			cav_fprintf(cav_nb_fp,"%s: case CAV_ST_IN_HANDSHAKE\n", fname);
			break;

		case CAV_ST_IN_VRFY_CERT:
			cav_fprintf(cav_nb_fp,"%s: case CAV_ST_IN_VRFY_CERT\n", fname);
			break;

		default:
			cav_fprintf(cav_nb_fp,"%s: default\n", fname);
			break;

	} // end switch

	return(0);

} // end cav_print_state()


void cav_set_nb_mode(SSL *s, int nb_mode)
{
#ifndef CAVIUM_FIPS
	if ( nb_mode ) 
		s->cav_nb_mode = CAVIUM_NON_BLOCKING;
	else
		s->cav_nb_mode = CAVIUM_BLOCKING;
#else
	if ( nb_mode ) 
		s->cav_nb_mode = OP_NON_BLOCKING;
	else
		s->cav_nb_mode = OP_BLOCKING;
#endif
}


int cav_get_nb_mode(SSL *s)
{
	return(s->cav_nb_mode);
}


int cav_check_for_completion(SSL *s)
{
	int rc;
	
#ifdef CAVIUM_FIPS
			rc = Cfm1CheckForCompletion(s->cav_req_id);
#else
#ifdef CAVIUM_MULTICARD_API
	rc = Csp1CheckForCompletion(s->cav_req_id,s->dev_id);
#else
	rc = Csp1CheckForCompletion(s->cav_req_id);
#endif
#endif
	//if ( rc == 0 )
	if ( rc != EAGAIN )
		s->cav_req_id_check_done = 1;

	return(rc);
}

void print_hex(char *label, Uint8 *datap, int len)
{
int i;

	if ( label != NULL )
		cav_fprintf(cav_nb_fp, "%s\n", label);
		for (i = 0; i < len; i++) {
			cav_fprintf(cav_nb_fp, "0x%0x ", datap[i]);
		}
		cav_fprintf(cav_nb_fp, "\n");
}

#else
int cav_print_state(SSL *s, char *fname) { }

void print_hex(char *label, Uint8 *datap, int len)
{
int i;

	if ( label != NULL )
		cav_fprintf(cav_nb_fp, "%s\n", label);
		for (i = 0; i < len; i++) {
			cav_fprintf(cav_nb_fp, "0x%0x ", datap[i]);
		}
		cav_fprintf(cav_nb_fp, "\n");
}
#endif
