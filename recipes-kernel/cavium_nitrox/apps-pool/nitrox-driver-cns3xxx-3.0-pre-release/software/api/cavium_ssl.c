/* cavium_ssl.c */
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

#ifdef _WIN32
#include <windows.h>
#include <winioctl.h>

#include <stdio.h>
#include <stdarg.h>
#include <errno.h>
#include <fcntl.h>
#undef	NO_ERROR

int	open (const char *, int);
int	close (int);
int	ioctl (int, int, ...);
#endif
#include <cavium_sysdep.h>
#include <cavium_common.h>
#include <cavium_ioctl.h>
#include <cavium_endian.h>
#include <cavium_ioctl.h>
#include <cavium_ssl.h>
#include <stdlib.h>
#include <string.h>

extern Csp1DmaMode global_dma_mode;
extern int CSP1_driver_handle;

#ifdef CAVIUM_MULTICARD_API
extern int gpkpdev_hdlr[];
#endif


#ifndef UINT64_C 
#define UINT64_C(x)   ((unsigned long long) (x ## ull))
#endif

#ifndef MC2
static void pkp_leftfill (unsigned char input[], int length,
			  unsigned char output[], int finallength);
static void swap_word_openssl (unsigned char *d, unsigned char *s, int len);
#endif



/*+****************************************************************************
 *
 * Csp1GetDmaMode
 * 
 * Returns the current DMA mode
 *
 * Input
 *  none
 * 
 * Ouput
 *  none
 *
 * Return Value
 *	DmaMode: CAVIUM_DIRECT, CAVIUM_SCATTER_GATHER
 *
 *-***************************************************************************/
DmaMode
Csp1GetDmaMode (void)
{
  return global_dma_mode;
}




/*+****************************************************************************
 *
 * Csp1GetDriverState
 * 
 * Function to check whether the driver handle is initialized or not.
 *
 * Input
 *  none
 * 
 * Ouput
 *  none
 *
 * Return Value
 *	0  = driver handle is ready.
 *	-1 = driver handle is not initialized
 *-***************************************************************************/
int
#ifdef CAVIUM_MULTICARD_API
Csp1GetDriverState (Uint32 dev_id)
#else
Csp1GetDriverState ()
#endif
{
#ifdef CAVIUM_MULTICARD_API
  if (gpkpdev_hdlr[dev_id] != -1)
#else
  if (CSP1_driver_handle != -1)
#endif
    return 0;
  else
    return -1;
}


/*+****************************************************************************
 *
 * Csp1SetEncryptedMasterSecretKey
 *
 * Sets the key material for encryption of master secrets used by resume 
 * operations.
 *
 * Input
 *		key = pointer to 48 bytes of key material
 *
 * Return Value
 *		0  = success 
 *		>0 = failure or pending
 *		see error_codes.txt
 *-***************************************************************************/
Uint32
#ifdef CAVIUM_MULTICARD_API
Csp1SetEncryptedMasterSecretKey (Uint8 * key,Uint32 dev_id)
#else
Csp1SetEncryptedMasterSecretKey (Uint8 * key)
#endif
{
  Uint32 ret_val;
  Uint32 dummy = 0;
#ifdef CAVIUM_MULTICARD_API
  Uint64 tmp_keyhdl=0;
  ret_val = Csp1WriteEpci (CAVIUM_BLOCKING,&tmp_keyhdl, 48, key, &dummy,dev_id);
#else
  ret_val = Csp1WriteEpci (CAVIUM_BLOCKING, 0, 48, key, &dummy);
#endif
  return ret_val;

}

#ifndef MC2
/*+****************************************************************************
 *
 * Csp1Handshake
 *
 * Calculates the hashes needed by the SSL handshake.
 *
 * Input
 *		request_type = CAVIUM_BLOCKING or CAVIUM_NON_BLOCKING
 *		context_handle = 64-bit pointer to context (context_handle%8=0)
 *		message_length = size of input in bytes (0<=message_length<=2^16-1)
 *		message = pointer to length bytes of input
 *
 * Output
 *		md5_final_hash = pointer to the 4-halfword handshake final result 
 *		sha1_final_hash = pointer to the 5-halfword handshake final result 
 *		request_id = Unique ID for this request
 *
 * Return Value
 *		0  = success 
 *		>0 = failure or pending
 *		see error_codes.txt
 *
 *-***************************************************************************/
Uint32
Csp1Handshake (n1_request_type request_type,
	       Uint64 context_handle,
	       Uint16 message_length,
	       Uint8 * message,
	       Uint8 * md5_final_hash,
	       Uint8 * sha1_final_hash, 
#ifdef CAVIUM_MULTICARD_API
	       Uint32 * request_id,Uint32 dev_id
#else
	       Uint32 * request_id
#endif
              )
{
  Csp1OperationBuffer buffer;
  Uint32 cond_code;
  Uint32 ret_val;

  Uint32 md5_hash_size = 16;
  Uint32 sha1_hash_size = 20;

  if ((context_handle & UINT64_C(0x8000000000000000)) != 0)
    {

      if ((context_handle & 0xf) != 0)
		  return ERR_ILLEGAL_CONTEXT_HANDLE;

    }
  else
    {

      if ((context_handle & 0x7) != 0)
		  return ERR_ILLEGAL_CONTEXT_HANDLE;

    }


  buffer.opcode = (0x3 << 9) | (global_dma_mode << 7) | MAJOR_OP_HANDSHAKE;
  buffer.size = message_length;
  buffer.param = 0;
  buffer.dlen = (ROUNDUP8 (message_length)) >> 3;
  buffer.rlen = (16 + 24 + 8) >> 3;
  buffer.ctx_ptr = context_handle;
  buffer.group = CAVIUM_SSL_GRP;

  buffer.incnt = 1;
  buffer.outcnt = 2;

  buffer.inptr[0] = CAST_TO_X_PTR( message);
  buffer.insize[0] = message_length;
  buffer.inoffset[0] = ROUNDUP8 (message_length);
  buffer.inunit[0] = UNIT_8_BIT;

  buffer.outptr[0] =CAST_TO_X_PTR( md5_final_hash);
  buffer.outsize[0] = md5_hash_size;
  buffer.outoffset[0] = 16;
  buffer.outunit[0] = UNIT_8_BIT;
  buffer.outptr[1] = CAST_TO_X_PTR( sha1_final_hash);
  buffer.outsize[1] = sha1_hash_size;
  buffer.outoffset[1] = 24;
  buffer.outunit[1] = UNIT_8_BIT;

  buffer.req_type = request_type;
  buffer.req_queue = SSL_QUEUE;
  buffer.res_order = CAVIUM_RESPONSE_ORDERED;
  buffer.dma_mode = global_dma_mode;
  buffer.status = 0;

  cond_code =
#ifdef CAVIUM_MULTICARD_API
    ioctl (gpkpdev_hdlr[dev_id], IOCTL_N1_OPERATION_CODE, (ptrlong) & buffer);
#else
    ioctl (CSP1_driver_handle, IOCTL_N1_OPERATION_CODE, (ptrlong) & buffer);
#endif

  *request_id = buffer.request_id;

  if(cond_code)
     ret_val = cond_code; /*return error val*/
  else
     ret_val = buffer.status;/*return OPERATION STATUS: SUCCESS('0')/EAGAIN */

  return ret_val;
}



/*+****************************************************************************
 *
 * Csp1HandshakeStart
 *
 * Calculates the partial hashes needed by the SSL handshake.
 *
 * Input
 *		request_type = CAVIUM_BLOCKING or CAVIUM_NON_BLOCKING
 *		context_handle = 64-bit pointer to context (context_handle%8=0)
 *		message_length = size of input in bytes (0<=message_length<=2^16-1)
 *		message = pointer to length bytes of input
 *
 * Output
 *		request_id = Unique ID for this request
 *
 * Return Value
 *		0  = success 
 *		>0 = failure or pending
 *		see error_codes.txt
 *
 *-***************************************************************************/
Uint32
Csp1HandshakeStart (n1_request_type request_type,
		    Uint64 context_handle,
		    Uint16 message_length,
		    Uint8 * message, 
#ifdef CAVIUM_MULTICARD_API
                    Uint32 * request_id, Uint32 dev_id
#else
                    Uint32 * request_id
#endif
                   )
{
  Csp1OperationBuffer buffer;
  Uint32 cond_code;
  Uint32 ret_val;
  memset(&buffer,0,sizeof(Csp1OperationBuffer));

  if ((context_handle & UINT64_C(0x8000000000000000)) != 0)
    {

      if ((context_handle & 0xf) != 0)
		  return ERR_ILLEGAL_CONTEXT_HANDLE;
    }
  else
    {

      if ((context_handle & 0x7) != 0)
		  return ERR_ILLEGAL_CONTEXT_HANDLE;
    }

  buffer.opcode = (0x1 << 9) | (global_dma_mode << 7) | MAJOR_OP_HANDSHAKE;
  buffer.size = message_length;
  buffer.param = 0;
  buffer.dlen = (ROUNDUP8 (message_length)) >> 3;
  buffer.rlen = (8) >> 3;
  buffer.ctx_ptr = context_handle;
  buffer.group = CAVIUM_SSL_GRP;

  buffer.incnt = 1;
  buffer.outcnt = 0;

  buffer.inptr[0] = CAST_TO_X_PTR( message);
  buffer.insize[0] = message_length;
  buffer.inoffset[0] = ROUNDUP8 (message_length);
  buffer.inunit[0] = UNIT_8_BIT;

  buffer.req_type = request_type;
  buffer.req_queue = SSL_QUEUE;
  buffer.res_order = CAVIUM_RESPONSE_ORDERED;
  buffer.dma_mode = global_dma_mode;
  buffer.status = 0;

  cond_code =
#ifdef CAVIUM_MULTICARD_API
    ioctl (gpkpdev_hdlr[dev_id], IOCTL_N1_OPERATION_CODE, (ptrlong) & buffer);
#else
    ioctl (CSP1_driver_handle, IOCTL_N1_OPERATION_CODE, (ptrlong) & buffer);
#endif

  *request_id = buffer.request_id;

  if(cond_code)
     ret_val = cond_code; /*return error val*/
  else
     ret_val = buffer.status;/*return OPERATION STATUS: SUCCESS('0')/EAGAIN */

  return ret_val;
}



/*+****************************************************************************
 *
 * Csp1HandshakeUpdate
 *
 * Calculates the partial hashes needed by the SSL handshake.
 *
 * Input
 *		request_type = CAVIUM_BLOCKING or CAVIUM_NON_BLOCKING
 *		context_handle = 64-bit pointer to context (context_handle%8=0)
 *		message_length = size of input in bytes (0<=message_length<=2^16-1)
 *		message = pointer to length bytes of input
 * Output
 *		request_id = Unique ID for this request
 *
 * Return Value
 *		0  = success 
 *		>0 = failure or pending
 *		see error_codes.txt
 *
 *-***************************************************************************/
Uint32
Csp1HandshakeUpdate (n1_request_type request_type,
		     Uint64 context_handle,
		     Uint16 message_length,
		     Uint8 * message, 
#ifdef CAVIUM_MULTICARD_API
                     Uint32 * request_id, Uint32 dev_id
#else
                     Uint32 * request_id
#endif
                    )
{
  Csp1OperationBuffer buffer;
  Uint32 cond_code;
  Uint32 ret_val;
  memset(&buffer,0,sizeof(Csp1OperationBuffer));

  if ((context_handle & UINT64_C(0x8000000000000000)) != 0)
    {

      if ((context_handle & 0xf) != 0)
		  return ERR_ILLEGAL_CONTEXT_HANDLE;
    }
  else
    {

      if ((context_handle & 0x7) != 0)
		  return ERR_ILLEGAL_CONTEXT_HANDLE;
    }

  buffer.opcode = (0x0 << 9) | (global_dma_mode << 7) | MAJOR_OP_HANDSHAKE;
  buffer.size = message_length;
  buffer.param = 0;
  buffer.dlen = (ROUNDUP8 (message_length)) >> 3;
  buffer.rlen = (8) >> 3;
  buffer.ctx_ptr = context_handle;
  buffer.group = CAVIUM_SSL_GRP;

  buffer.incnt = 1;
  buffer.outcnt = 0;

  buffer.inptr[0] = CAST_TO_X_PTR( message);
  buffer.insize[0] = message_length;
  buffer.inoffset[0] = ROUNDUP8 (message_length);
  buffer.inunit[0] = UNIT_8_BIT;

  buffer.req_type = request_type;
  buffer.req_queue = SSL_QUEUE;
  buffer.res_order = CAVIUM_RESPONSE_ORDERED;
  buffer.dma_mode = global_dma_mode;
  buffer.status = 0;

  cond_code =
#ifdef CAVIUM_MULTICARD_API
    ioctl (gpkpdev_hdlr[dev_id], IOCTL_N1_OPERATION_CODE, (ptrlong) & buffer);
#else
    ioctl (CSP1_driver_handle, IOCTL_N1_OPERATION_CODE, (ptrlong) & buffer);
#endif

  *request_id = buffer.request_id;

  if(cond_code)
     ret_val = cond_code; /*return error val*/
  else
     ret_val = buffer.status;/*return OPERATION STATUS: SUCCESS('0')/EAGAIN */

  return ret_val;
}



/*+****************************************************************************
 *
 * Csp1HandshakeFinish
 *
 * Input
 *		request_type = CAVIUM_BLOCKING or CAVIUM_NON_BLOCKING
 *		context_handle = 64-bit pointer to context (context_handle%8=0)
 *		message_length = size of input in bytes (0<=message_length<=2^16-1)
 *		message = pointer to length bytes of input
 *
 * Output
 *		md5_final_hash = pointer to the 4-word handshake final result 
 *		sha1_final_hash = pointer to the 5-word handshake final result 
 *		request_id = Unique ID for this request
 *
 * Return Value
 *		0  = success 
 *		>0 = failure or pending
 *		see error_codes.txt
 *
 *-***************************************************************************/
Uint32
Csp1HandshakeFinish (n1_request_type request_type,
		     Uint64 context_handle,
		     Uint16 message_length,
		     Uint8 *message,
		     Uint8 *md5_final_hash,
		     Uint8 *sha1_final_hash, 
#ifdef CAVIUM_MULTICARD_API
			 Uint32 *request_id,Uint32 dev_id
#else
			 Uint32 *request_id
#endif
                    )
{
  Csp1OperationBuffer buffer;
  Uint32 cond_code;
  Uint32 ret_val;

  Uint32 md5_hash_size = 16;
  Uint32 sha1_hash_size = 20;
  memset(&buffer,0,sizeof(Csp1OperationBuffer));

  if ((context_handle & UINT64_C(0x8000000000000000)) != 0)
    {
      if ((context_handle & 0xf) != 0)
		  return ERR_ILLEGAL_CONTEXT_HANDLE;
    }
  else
    {
      if ((context_handle & 0x7) != 0)
		  return ERR_ILLEGAL_CONTEXT_HANDLE;
    }

  buffer.opcode = (0x2 << 9) | (global_dma_mode << 7) | MAJOR_OP_HANDSHAKE;
  buffer.size = message_length;
  buffer.param = 0;
  buffer.dlen = (ROUNDUP8 (message_length)) >> 3;
  buffer.rlen = (16 + 24 + 8) >> 3;
  buffer.ctx_ptr = context_handle;
  buffer.group = CAVIUM_SSL_GRP;

  buffer.incnt = 1;
  buffer.outcnt = 2;

  buffer.inptr[0] = CAST_TO_X_PTR(message);
  buffer.insize[0] = message_length;
  buffer.inoffset[0] = ROUNDUP8 (message_length);
  buffer.inunit[0] = UNIT_8_BIT;

  buffer.outptr[0] = CAST_TO_X_PTR( md5_final_hash);
  buffer.outsize[0] = md5_hash_size;
  buffer.outoffset[0] = 16;
  buffer.outunit[0] = UNIT_8_BIT;
  buffer.outptr[1] = CAST_TO_X_PTR( sha1_final_hash);
  buffer.outsize[1] = sha1_hash_size;
  buffer.outoffset[1] = 24;
  buffer.outunit[1] = UNIT_8_BIT;

  buffer.req_type = request_type;
  buffer.req_queue = SSL_QUEUE;
  buffer.res_order = CAVIUM_RESPONSE_ORDERED;
  buffer.dma_mode = global_dma_mode;
  buffer.status = 0;

  cond_code =
#ifdef CAVIUM_MULTICARD_API
    ioctl (gpkpdev_hdlr[dev_id], IOCTL_N1_OPERATION_CODE, (ptrlong) & buffer);
#else
    ioctl (CSP1_driver_handle, IOCTL_N1_OPERATION_CODE, (ptrlong) & buffer);
#endif

  *request_id = buffer.request_id;

  if(cond_code)
     ret_val = cond_code; /*return error val*/
  else
     ret_val = buffer.status;/*return OPERATION STATUS: SUCCESS('0')/EAGAIN */

  return ret_val;
}

#endif /* MC2 */


/*+****************************************************************************
 *
 * Csp1RsaServerFullRc4
 *
 * Does a full handshake on the server with RSA <= 1024. This entry point 
 * handles all the RC4 cases. The handshake message data for this request 
 * should include all handshake message data after (and including) the client 
 * hello message up until (but not including) the first finished message. 
 *
 * Input
 *		request_type = CAVIUM_BLOCKING or CAVIUM_NON_BLOCKING
 *		context_handle = 64-bit byte-pointer to context (context_handle%8=0)
 *		key_handle = pointer to 64-bit key memory handle
 *		hash_type = MD5_TYPE or SHA1_TYPE
 *		ssl_version = VER3_0 or VER_TLS
 *		rc4_type = RC4_128, RC4_EXPORT_40, or RC4_EXPORT_56
 *		master_secret_ret = NOT_RETURNED or RETURN_ENCRYPTED
 *		modlength = size of RSA operation in bytes (64<=modlength<=512, modlength%8=0)
 *	#ifdef MC2
 *		encrypt_premaster_secret = pointer to modlength-byte value.
 *	#else
 *		encrypt_premaster_secret = pointer to modlength-byte value in integer format
 *	#endif
 *		client_random = pointer to 32 bytes of random data
 *		server_random = pointer to 32 bytes of random data
 *		handshake_length = size in bytes of the handshake message data
 *		handshake = pointer to the handshake message data
 *
 * Output
 *		client_finished_message = pointer to encrypted part of client finished message 
 *		server_finished_message = pointer to encrypted part of server finished message 
 *		encrypt_master_secret = (master_secret_ret == RETURN_ENCRYPTED) ? pointer to
 *									returned encrypted master secret : don't care
 *		request_id = Unique ID for this request
 *
 * Return Value
 *		0  = success 
 *		>0 = failure or pending
 *		see error_codes.txt
 *-***************************************************************************/
Uint32
Csp1RsaServerFullRc4 (n1_request_type request_type,
		      Uint64 context_handle,
		      Uint64 * key_handle,
		      HashType hash_type,
		      SslVersion ssl_version,
		      Rc4Type rc4_type,
		      MasterSecretReturn master_secret_ret,
		      Uint16 modlength,
		      Uint8 * encrypt_premaster_secret,
		      Uint8 * client_random,
		      Uint8 * server_random,
		      Uint16 handshake_length,
		      Uint8 * handshake,
		      Uint8 * client_finished_message,
		      Uint8 * server_finished_message,
		      Uint8 * encrypt_master_secret, 
#ifdef CAVIUM_MULTICARD_API
			  Uint32 *request_id,Uint32 dev_id
#else
			  Uint32 *request_id
#endif
                    )
{
  Csp1OperationBuffer buffer;
  Uint32 cond_code;
  Uint32 ret_val;
#ifndef MC2
  Uint16 param = 0;
#endif
  Uint16 finished_size;
  Uint16 hash_size;
  memset(&buffer,0,sizeof(Csp1OperationBuffer));

  if ((context_handle & UINT64_C(0x8000000000000000)) != 0)
    {
      if ((context_handle & 0xf) != 0)
		  return ERR_ILLEGAL_CONTEXT_HANDLE;
    }
  else
    {
      if ((context_handle & 0x7) != 0)
		  return ERR_ILLEGAL_CONTEXT_HANDLE;
    }

#ifndef MC2
  if ((modlength & 0x7) != 0)
	  return ERR_ILLEGAL_INPUT_LENGTH;
#endif

  if ((modlength >= 64) && (modlength <= 128))
    {
#ifdef MC2
      buffer.opcode =
	(master_secret_ret << 14) | (0x1 << 13) | (global_dma_mode << 7) |
	MAJOR_OP_RSASERVER;
#else

      param = (modlength >> 3) - 1;
      buffer.opcode =
	(master_secret_ret << 15) | (0x3 << 13) | (rc4_type << 10) |
	(ssl_version << 9) | (hash_type << 8) | (global_dma_mode << 7) |
	MAJOR_OP_RSASERVER;
#endif

    }
  else if ((modlength > 128) && (modlength <= 512))
    {
#ifdef MC2
      buffer.opcode =
	(master_secret_ret << 14) | (0x1 << 13) | (global_dma_mode << 7) |
	MAJOR_OP_RSASERVER_LARGE;
#else
      param = (modlength >> 3) - 17;
      buffer.opcode =
	(master_secret_ret << 15) | (0x3 << 13) | (rc4_type << 10) |
	(ssl_version << 9) | (hash_type << 8) | (global_dma_mode << 7) |
	MAJOR_OP_RSASERVER_LARGE;
#endif

#if defined(CSP1_API_DEBUG)
    }
  else
    {

      return ERR_ILLEGAL_INPUT_LENGTH;
#endif
    }

  finished_size = 16 + 24 * ssl_version;

#ifdef MC2
  hash_size = (hash_type == SHA1_TYPE) ? 20 : 16;
  buffer.size = modlength;
  buffer.param =
    (hash_type) | (ssl_version << 2) | (rc4_type << 3) | (1 << 7);
  buffer.dlen = 8 + modlength + 32 + 32 + handshake_length;
  buffer.rlen = 2 * (finished_size + hash_size);
#else
  hash_size = 20 - (hash_type << 2);

  buffer.size = handshake_length;
  buffer.param = param;
  buffer.dlen = (8 + modlength + 32 + 32 + ROUNDUP8 (handshake_length)) >> 3;
  buffer.rlen = (ROUNDUP8 (finished_size + hash_size)
		 + ROUNDUP8 (finished_size + hash_size) + 8) >> 3;
#endif
  buffer.ctx_ptr = context_handle;
  buffer.group = CAVIUM_SSL_GRP;

  buffer.incnt = 5;

  buffer.inptr[0] = CAST_TO_X_PTR((Uint8 *)  key_handle);
  buffer.insize[0] = 8;
  buffer.inoffset[0] = 8;
  buffer.inunit[0] = UNIT_64_BIT;
  buffer.inptr[1] = CAST_TO_X_PTR(  encrypt_premaster_secret);
  buffer.insize[1] = modlength;
  buffer.inoffset[1] = modlength;
  buffer.inunit[1] = UNIT_8_BIT;
  buffer.inptr[2] = CAST_TO_X_PTR( client_random);
  buffer.insize[2] = 32;
  buffer.inoffset[2] = 32;
  buffer.inunit[2] = UNIT_8_BIT;
  buffer.inptr[3] = CAST_TO_X_PTR( server_random);
  buffer.insize[3] = 32;
  buffer.inoffset[3] = 32;
  buffer.inunit[3] = UNIT_8_BIT;
  buffer.inptr[4] = CAST_TO_X_PTR( handshake);
  buffer.insize[4] = handshake_length;
  buffer.inoffset[4] = ROUNDUP8 (handshake_length);
  buffer.inunit[4] = UNIT_8_BIT;

#ifndef MC2
  buffer.outptr[0] = CAST_TO_X_PTR( server_finished_message);
  buffer.outsize[0] = finished_size + hash_size;
  buffer.outoffset[0] = ROUNDUP8 (finished_size + hash_size);
  buffer.outunit[0] = UNIT_8_BIT;
  buffer.outptr[1] = CAST_TO_X_PTR( client_finished_message);
  buffer.outsize[1] = finished_size + hash_size;
  buffer.outoffset[1] = ROUNDUP8 (finished_size + hash_size);
  buffer.outunit[1] = UNIT_8_BIT;

  if (master_secret_ret == RETURN_ENCRYPTED)
    {

      buffer.rlen += (48 >> 3);

      buffer.outcnt = 3;

      buffer.outptr[2] = CAST_TO_X_PTR( encrypt_master_secret);
      buffer.outsize[2] = 48;
      buffer.outoffset[2] = 48;
      buffer.outunit[2] = UNIT_8_BIT;

    }
  else if (master_secret_ret == NOT_RETURNED)

    buffer.outcnt = 2;
#else
  if (master_secret_ret == RETURN_ENCRYPTED)
    {
      buffer.rlen += 48;
      buffer.outcnt = 3;

      buffer.outptr[0] = CAST_TO_X_PTR( encrypt_master_secret);
      buffer.outsize[0] = 48;
      buffer.outoffset[0] = 48;
      buffer.outunit[0] = UNIT_8_BIT;

      buffer.outptr[1] = CAST_TO_X_PTR( client_finished_message);
      buffer.outsize[1] = finished_size + hash_size;
      buffer.outoffset[1] = finished_size + hash_size;
      buffer.outunit[1] = UNIT_8_BIT;
      buffer.outptr[2] = CAST_TO_X_PTR( server_finished_message);
      buffer.outsize[2] = finished_size + hash_size;
      buffer.outoffset[2] = finished_size + hash_size;
      buffer.outunit[2] = UNIT_8_BIT;
    }
  else
    {
      buffer.outcnt = 2;
      buffer.outptr[0] = CAST_TO_X_PTR( client_finished_message);
      buffer.outsize[0] = finished_size + hash_size;
      buffer.outoffset[0] = finished_size + hash_size;
      buffer.outunit[0] = UNIT_8_BIT;
      buffer.outptr[1] = CAST_TO_X_PTR( server_finished_message);
      buffer.outsize[1] = finished_size + hash_size;
      buffer.outoffset[1] = finished_size + hash_size;
      buffer.outunit[1] = UNIT_8_BIT;
    }
#endif
  buffer.req_type = request_type;
  buffer.req_queue = SSL_QUEUE;
  buffer.res_order = CAVIUM_RESPONSE_ORDERED;
  buffer.dma_mode = global_dma_mode;
  buffer.status = 0;

  cond_code =
#ifdef CAVIUM_MULTICARD_API
    ioctl (gpkpdev_hdlr[dev_id], IOCTL_N1_OPERATION_CODE, (ptrlong) & buffer);
#else
    ioctl (CSP1_driver_handle, IOCTL_N1_OPERATION_CODE, (ptrlong) & buffer);
#endif
  *request_id = (buffer.request_id);

  if(cond_code)
     ret_val = cond_code; /*return error val*/
  else
     ret_val = buffer.status;/*return OPERATION STATUS: SUCCESS('0')/EAGAIN */

  return ret_val;
}



#ifndef MC2
/*+****************************************************************************
 *
 * Csp1RsaServerFullRc4Finish
 *
 * Does a full handshake on the server with RSA <= 1024. This entry point 
 * handles all the RC4 cases. The handshake data is accumulated prior to this 
 * request by calls to Handshake*, and this request appends the 
 * included handshake message data to the pre-existing handshake hash state.
 * The handshake message data for this request (previously hashed plus included 
 * messsage data) should include all handshake message data after (and 
 * including) the client hello message up until (but not including) the first 
 * finished message. 
 *
 * Input
 *		request_type = CAVIUM_BLOCKING or CAVIUM_NON_BLOCKING
 *		context_handle = 64-bit byte-pointer to context (context_handle%8=0)
 *		key_handle = pointer to 64-bit key memory handle
 *		hash_type = MD5_TYPE or SHA1_TYPE
 *		ssl_version = VER3_0 or VER_TLS
 *		rc4_type = RC4_128, RC4_EXPORT_40, or RC4_EXPORT_56
 *		master_secret_ret = NOT_RETURNED or RETURN_ENCRYPTED
 *		modlength = size of RSA operation in bytes (64<=modlength<=256, modlength%8=0)
 *		encrypt_premaster_secret = pointer to modlength-byte value in integer format
 *		client_random = pointer to 32 bytes of random data
 *		server_random = pointer to 32 bytes of random data
 *		handshake_length = size in bytes of the handshake message data
 *		handshake = pointer to the handshake message data
 *
 * Output
 *		client_finished_message = pointer to encrypted part of client finished message 
 *		server_finished_message = pointer to encrypted part of server finished message 
 *		encrypt_master_secret = (master_secret_ret == RETURN_ENCRYPTED) ? pointer to
 *								returned encrypted master secret : don't care
 *		request_id = Unique ID for this request
 *
 * Return Value
 *		0  = success 
 *		>0 = failure or pending
 *		see error_codes.txt
 *-***************************************************************************/
Uint32
Csp1RsaServerFullRc4Finish (n1_request_type request_type,
			    Uint64 context_handle,
			    Uint64 * key_handle,
			    HashType hash_type,
			    SslVersion ssl_version,
			    Rc4Type rc4_type,
			    MasterSecretReturn master_secret_ret,
			    Uint16 modlength,
			    Uint8 * encrypt_premaster_secret,
			    Uint8 * client_random,
			    Uint8 * server_random,
			    Uint16 handshake_length,
			    Uint8 * handshake,
			    Uint8 * client_finished_message,
			    Uint8 * server_finished_message,
			    Uint8 * encrypt_master_secret,
#ifdef CAVIUM_MULTICARD_API
			    Uint32 * request_id, Uint32 dev_id
#else
			    Uint32 * request_id
#endif
                          )
{
  Csp1OperationBuffer buffer;
  Uint32 cond_code;
  Uint32 ret_val;
  Uint16 param = 0;
  Uint16 finished_size;
  Uint16 hash_size;

  memset(&buffer,0,sizeof(Csp1OperationBuffer));
  if ((context_handle & UINT64_C(0x8000000000000000)) != 0)
    {
      if ((context_handle & 0xf) != 0)
		  return ERR_ILLEGAL_CONTEXT_HANDLE;
    }
  else
    {
      if ((context_handle & 0x7) != 0)
		  return ERR_ILLEGAL_CONTEXT_HANDLE;

    }

  if ((modlength & 0x7) != 0)
	  return ERR_ILLEGAL_INPUT_LENGTH;

  if ((modlength >= 64) && (modlength <= 128))
    {

      param = (modlength >> 3) - 1;
      buffer.opcode =
	(master_secret_ret << 15) | (0x2 << 13) | (rc4_type << 10) |
	(ssl_version << 9) | (hash_type << 8) | (global_dma_mode << 7) |
	MAJOR_OP_RSASERVER;


    }
  else if ((modlength > 128) && (modlength <= 256))
    {

      param = (modlength >> 3) - 17;
      buffer.opcode =
	(master_secret_ret << 15) | (0x2 << 13) | (rc4_type << 10) |
	(ssl_version << 9) | (hash_type << 8) | (global_dma_mode << 7) |
	MAJOR_OP_RSASERVER_LARGE;

#if defined(CSP1_API_DEBUG)
    }
  else
    {

      return ERR_ILLEGAL_INPUT_LENGTH;
#endif
    }

  hash_size = 20 - (hash_type << 2);
  finished_size = 16 + 24 * ssl_version;

  buffer.size = handshake_length;
  buffer.param = param;
  buffer.dlen = (8 + modlength + 32 + 32 + ROUNDUP8 (handshake_length)) >> 3;
  buffer.rlen = (ROUNDUP8 (finished_size + hash_size)
		 + ROUNDUP8 (finished_size + hash_size) + 8) >> 3;
  buffer.ctx_ptr = context_handle;
  buffer.group = CAVIUM_SSL_GRP;

  buffer.incnt = 5;

  buffer.inptr[0] = CAST_TO_X_PTR((Uint8 *)  key_handle);
  buffer.insize[0] = 8;
  buffer.inoffset[0] = 8;
  buffer.inunit[0] = UNIT_64_BIT;
  buffer.inptr[1] = CAST_TO_X_PTR(  encrypt_premaster_secret);
  buffer.insize[1] = modlength;
  buffer.inoffset[1] = modlength;
  buffer.inunit[1] = UNIT_8_BIT;
  buffer.inptr[2] = CAST_TO_X_PTR( client_random);
  buffer.insize[2] = 32;
  buffer.inoffset[2] = 32;
  buffer.inunit[2] = UNIT_8_BIT;
  buffer.inptr[3] = CAST_TO_X_PTR( server_random);
  buffer.insize[3] = 32;
  buffer.inoffset[3] = 32;
  buffer.inunit[3] = UNIT_8_BIT;
  buffer.inptr[4] = CAST_TO_X_PTR( handshake);
  buffer.insize[4] = handshake_length;
  buffer.inoffset[4] = ROUNDUP8 (handshake_length);
  buffer.inunit[4] = UNIT_8_BIT;

  buffer.outptr[0] = CAST_TO_X_PTR( server_finished_message);
  buffer.outsize[0] = finished_size + hash_size;
  buffer.outoffset[0] = ROUNDUP8 (finished_size + hash_size);
  buffer.outunit[0] = UNIT_8_BIT;
  buffer.outptr[1] = CAST_TO_X_PTR( client_finished_message);
  buffer.outsize[1] = finished_size + hash_size;
  buffer.outoffset[1] = ROUNDUP8 (finished_size + hash_size);
  buffer.outunit[1] = UNIT_8_BIT;

  if (master_secret_ret == RETURN_ENCRYPTED)
    {

      buffer.rlen += (48 >> 3);

      buffer.outcnt = 3;

      buffer.outptr[2] = CAST_TO_X_PTR( encrypt_master_secret);
      buffer.outsize[2] = 48;
      buffer.outoffset[2] = 48;
      buffer.outunit[2] = UNIT_8_BIT;

    }
  else if (master_secret_ret == NOT_RETURNED)

    buffer.outcnt = 2;

  buffer.req_type = request_type;
  buffer.req_queue = SSL_QUEUE;
  buffer.res_order = CAVIUM_RESPONSE_ORDERED;
  buffer.dma_mode = global_dma_mode;
  buffer.status = 0;

  cond_code =
#ifdef CAVIUM_MULTICARD_API
    ioctl (gpkpdev_hdlr[dev_id], IOCTL_N1_OPERATION_CODE, (ptrlong) & buffer);
#else
    ioctl (CSP1_driver_handle, IOCTL_N1_OPERATION_CODE, (ptrlong) & buffer);
#endif

  *request_id = buffer.request_id;

  if(cond_code)
     ret_val = cond_code; /*return error val*/
  else
     ret_val = buffer.status;/*return OPERATION STATUS: SUCCESS('0')/EAGAIN */

  return ret_val;
}
#endif /* if !MC2 */

/*+****************************************************************************
 *
 * Csp1RsaServerVerifyRc4
 *
 * Do much of the full handshake - up to the point of the 
 * verify - in the case when client authentication is required. This is used in 
 * a full handshake on the server. This entry point handles all the RC4 cases.
 *
 * The handshake message data for this request should include all handshake 
 * message data after (and including) the client hello message up until (but 
 * not including) the client verify message.  
 *
 * Input
 *		request_type = CAVIUM_BLOCKING or CAVIUM_NON_BLOCKING
 *		context_handle = 64-bit byte-pointer to context (context_handle%8=0)
 *		key_handle = pointer to 64-bit key memory handle
 *		hash_type = MD5_TYPE or SHA1_TYPE
 *		ssl_version = VER3_0 or VER_TLS
 *		rc4_type = RC4_128, RC4_EXPORT_40, or RC4_EXPORT_56
 *		master_secret_ret = NOT_RETURNED or RETURN_ENCRYPTED
 *		modlength = size of RSA operation in bytes (64<=modlength<=512, modlength%8=0)
 *		encrypt_premaster_secret = pointer to modlength-byte value in integer format
 *		client_random = pointer to 32 bytes of random data
 *		server_random = pointer to 32 bytes of random data
 *		handshake_length = size in bytes of the handshake message data
 *		handshake = pointer to the handshake message data
 *
 * Output
 *		verify_data = pointer to 36 bytes of verify data 
 *		encrypt_master_secret = (master_secret_ret == RETURN_ENCRYPTED) ? pointer to
 *						returned encrypted master secret : don't care
 *		request_id = Unique ID for this request
 *
 * Return Value
 *		0  = success 
 *		>0 = failure or pending
 *		see error_codes.txt
 *
 *-***************************************************************************/
Uint32
Csp1RsaServerVerifyRc4 (n1_request_type request_type,
			Uint64 context_handle,
			Uint64 * key_handle,
			HashType hash_type,
			SslVersion ssl_version,
			Rc4Type rc4_type,
			MasterSecretReturn master_secret_ret,
			Uint16 modlength,
			Uint8 * encrypt_premaster_secret,
			Uint8 * client_random,
			Uint8 * server_random,
			Uint16 handshake_length,
			Uint8 * handshake,
			Uint8 * verify_data,
			Uint8 * encrypt_master_secret, 
#ifdef CAVIUM_MULTICARD_API
                        Uint32 * request_id,Uint32 dev_id
#else
                        Uint32 * request_id
#endif
                       )
{
  Csp1OperationBuffer buffer;
  Uint32 cond_code;
  Uint32 ret_val;
#ifndef MC2
  Uint16 param = 0;
#endif
  Uint16 hash_size;

  memset(&buffer,0,sizeof(Csp1OperationBuffer));
  if ((context_handle & UINT64_C(0x8000000000000000)) != 0)
    {
      if ((context_handle & 0xf) != 0)
		  return ERR_ILLEGAL_CONTEXT_HANDLE;
    }
  else
    {
      if ((context_handle & 0x7) != 0)
		  return ERR_ILLEGAL_CONTEXT_HANDLE;
    }

#ifndef MC2
  if ((modlength & 0x7) != 0)
	  return ERR_ILLEGAL_INPUT_LENGTH;
#endif

  if ((modlength >= 64) && (modlength <= 128))
    {

#ifdef MC2
      buffer.opcode =
	(master_secret_ret << 14) | (global_dma_mode << 7) |
	MAJOR_OP_RSASERVER;
#else
      param = (modlength >> 3) - 1;
      buffer.opcode =
	(master_secret_ret << 15) | (0x1 << 13) | (rc4_type << 10) |
	(ssl_version << 9) | (hash_type << 8) | (global_dma_mode << 7) |
	MAJOR_OP_RSASERVER;
#endif


    }
  else if ((modlength > 128) && (modlength <= 512))
    {

#ifdef MC2
      buffer.opcode =
	(master_secret_ret << 14) | (global_dma_mode << 7) |
	MAJOR_OP_RSASERVER_LARGE;
#else
      param = (modlength >> 3) - 17;
      buffer.opcode =
	(master_secret_ret << 15) | (0x1 << 13) | (rc4_type << 10) |
	(ssl_version << 9) | (hash_type << 8) | (global_dma_mode << 7) |
	MAJOR_OP_RSASERVER_LARGE;
#endif

#if defined(CSP1_API_DEBUG)
    }
  else
    {

      return ERR_ILLEGAL_INPUT_LENGTH;
#endif
    }
#ifdef MC2
  hash_size = (hash_type == SHA1_TYPE) ? 20 : 16;
  buffer.size = modlength;
  buffer.param =
    (hash_type) | (ssl_version << 2) | (rc4_type << 3) | (1 << 7);
  buffer.dlen = 8 + modlength + 32 + 32 + handshake_length;
#else
  hash_size = 20 - (hash_type << 2);

  buffer.size = handshake_length;
  buffer.param = param;
  buffer.dlen = (8 + modlength + 32 + 32 + ROUNDUP8 (handshake_length)) >> 3;
  buffer.rlen = (40 + 8) >> 3;
#endif

  buffer.ctx_ptr = context_handle;
  buffer.group = CAVIUM_SSL_GRP;

  buffer.incnt = 5;

  buffer.inptr[0] = CAST_TO_X_PTR((Uint8 *) key_handle);
  buffer.insize[0] = 8;
  buffer.inoffset[0] = 8;
  buffer.inunit[0] = UNIT_64_BIT;
  buffer.inptr[1] = CAST_TO_X_PTR( encrypt_premaster_secret);
  buffer.insize[1] = modlength;
  buffer.inoffset[1] = modlength;
  buffer.inunit[1] = UNIT_8_BIT;
  buffer.inptr[2] = CAST_TO_X_PTR( client_random);
  buffer.insize[2] = 32;
  buffer.inoffset[2] = 32;
  buffer.inunit[2] = UNIT_8_BIT;
  buffer.inptr[3] = CAST_TO_X_PTR( server_random);
  buffer.insize[3] = 32;
  buffer.inoffset[3] = 32;
  buffer.inunit[3] = UNIT_8_BIT;
  buffer.inptr[4] = CAST_TO_X_PTR( handshake);
  buffer.insize[4] = handshake_length;
#ifdef MC2
  buffer.inoffset[4] = handshake_length;
#else
  buffer.inoffset[4] = ROUNDUP8 (handshake_length);
#endif
  buffer.inunit[4] = UNIT_8_BIT;


#ifdef MC2
  if (master_secret_ret == RETURN_ENCRYPTED)
    {
      buffer.rlen = 48 + 36;
      buffer.outcnt = 2;

      buffer.outptr[0] = CAST_TO_X_PTR( encrypt_master_secret);
      buffer.outsize[0] = 48;
      buffer.outoffset[0] = 48;
      buffer.outunit[0] = UNIT_8_BIT;

      buffer.outptr[1] =CAST_TO_X_PTR(  verify_data);
      buffer.outsize[1] = 36;
      buffer.outoffset[1] = 36;
      buffer.outunit[1] = UNIT_8_BIT;
    }
  else
    {
      buffer.rlen = 36;
      buffer.outcnt = 1;

      buffer.outptr[0] = CAST_TO_X_PTR( verify_data);
      buffer.outsize[0] = 36;
      buffer.outoffset[0] = 36;
      buffer.outunit[0] = UNIT_8_BIT;
    }
#else

  buffer.outptr[0] = CAST_TO_X_PTR( verify_data);
  buffer.outsize[0] = 36;
  buffer.outoffset[0] = 40;
  buffer.outunit[0] = UNIT_8_BIT;
  if (master_secret_ret == RETURN_ENCRYPTED)
    {

      buffer.rlen += (48 >> 3);

      buffer.outcnt = 2;

      buffer.outptr[1] =CAST_TO_X_PTR(  encrypt_master_secret);
      buffer.outsize[1] = 48;
      buffer.outoffset[1] = 48;
      buffer.outunit[1] = UNIT_8_BIT;

    }
  else if (master_secret_ret == NOT_RETURNED)

    buffer.outcnt = 1;

#endif
  buffer.req_type = request_type;
  buffer.req_queue = SSL_QUEUE;
  buffer.res_order = CAVIUM_RESPONSE_ORDERED;
  buffer.dma_mode = global_dma_mode;
  buffer.status = 0;

  cond_code =
#ifdef CAVIUM_MULTICARD_API
    ioctl (gpkpdev_hdlr[dev_id], IOCTL_N1_OPERATION_CODE, (ptrlong) & buffer);
#else
    ioctl (CSP1_driver_handle, IOCTL_N1_OPERATION_CODE, (ptrlong) & buffer);
#endif

  *request_id = buffer.request_id;

  if(cond_code)
     ret_val = cond_code; /*return error val*/
  else
     ret_val = buffer.status;/*return OPERATION STATUS: SUCCESS('0')/EAGAIN */

  return ret_val;
}


#ifndef MC2
/*+****************************************************************************
 *
 * Csp1RsaServerVerifyRc4Finish
 *
 * Do much of the full handshake - up to the point of the 
 * verify - in the case when client authentication is required. This is used in 
 * a full handshake on the server. This entry point handles all the RC4 cases.
 *
 * Handshake data can be accumulated prior to this request by calls to 
 * Handshake*, and this request will append the included handshake 
 * message data to the pre-existing handshake hash state. The handshake message 
 * data for this request (previously hashed plus included messsage data) should 
 * include all handshake message data after (and including) the client hello 
 * message up until (but not including) the client verify message. 
 *
 * Input
 *		request_type = CAVIUM_BLOCKING or CAVIUM_NON_BLOCKING
 *		context_handle = 64-bit byte-pointer to context (context_handle%8=0)
 *		key_handle = pointer to 64-bit key memory handle
 *		hash_type = MD5_TYPE or SHA1_TYPE
 *		ssl_version = VER3_0 or VER_TLS
 *		rc4_type = RC4_128, RC4_EXPORT_40, or RC4_EXPORT_56
 *		master_secret_ret = NOT_RETURNED or RETURN_ENCRYPTED
 *		modlength = size of RSA operation in bytes (64<=modlength<=256, modlength%8=0)
 *		encrypt_premaster_secret = pointer to modlength-byte value in integer format
 *		client_random = pointer to 32 bytes of random data
 *		server_random = pointer to 32 bytes of random data
 *		handshake_length = size in bytes of the handshake message data
 *		handshake = pointer to the handshake message data
 *
 * Output
 *		verify_data = pointer to 36 bytes of verify data 
 *		encrypt_master_secret = (master_secret_ret == RETURN_ENCRYPTED) ? pointer to
 *				returned encrypted master secret : don't care
 *		request_id = Unique ID for this request
 *
 * Return Value
 *		0  = success 
 *		>0 = failure or pending
 *		see error_codes.txt
 *
 *-***************************************************************************/
Uint32
Csp1RsaServerVerifyRc4Finish (n1_request_type request_type,
			      Uint64 context_handle,
			      Uint64 * key_handle,
			      HashType hash_type,
			      SslVersion ssl_version,
			      Rc4Type rc4_type,
			      MasterSecretReturn master_secret_ret,
			      Uint16 modlength,
			      Uint8 * encrypt_premaster_secret,
			      Uint8 * client_random,
			      Uint8 * server_random,
			      Uint16 handshake_length,
			      Uint8 * handshake,
			      Uint8 * verify_data,
			      Uint8 * encrypt_master_secret,
#ifdef CAVIUM_MULTICARD_API
			      Uint32 * request_id, Uint32 dev_id
#else
			      Uint32 * request_id
#endif
                              )
{
  Csp1OperationBuffer buffer;
  Uint32 cond_code;
  Uint32 ret_val;
  Uint16 param;
  Uint16 hash_size;
  memset(&buffer,0,sizeof(Csp1OperationBuffer));

  if ((context_handle & UINT64_C(0x8000000000000000)) != 0)
    {
      if ((context_handle & 0xf) != 0)
		  return ERR_ILLEGAL_CONTEXT_HANDLE;
    }
  else
    {
      if ((context_handle & 0x7) != 0)
		  return ERR_ILLEGAL_CONTEXT_HANDLE;
    }

  if ((modlength & 0x7) != 0)
	  return ERR_ILLEGAL_INPUT_LENGTH;


  if ((modlength >= 64) && (modlength <= 128))
    {

      param = (modlength >> 3) - 1;
      buffer.opcode =
	(master_secret_ret << 15) | (0x0 << 13) | (rc4_type << 10) |
	(ssl_version << 9) | (hash_type << 8) | (global_dma_mode << 7) |
	MAJOR_OP_RSASERVER;


    }
  else if ((modlength > 128) && (modlength <= 256))
    {

      param = (modlength >> 3) - 17;
      buffer.opcode =
	(master_secret_ret << 15) | (0x0 << 13) | (rc4_type << 10) |
	(ssl_version << 9) | (hash_type << 8) | (global_dma_mode << 7) |
	MAJOR_OP_RSASERVER_LARGE;

    }
  else

    return ERR_ILLEGAL_INPUT_LENGTH;

  hash_size = 20 - (hash_type << 2);

  buffer.size = handshake_length;
  buffer.param = param;
  buffer.dlen = (8 + modlength + 32 + 32 + ROUNDUP8 (handshake_length)) >> 3;
  buffer.rlen = (40 + 8) >> 3;
  buffer.ctx_ptr = context_handle;
  buffer.group = CAVIUM_SSL_GRP;

  buffer.incnt = 5;

  buffer.inptr[0] = CAST_TO_X_PTR((Uint8 *) key_handle);
  buffer.insize[0] = 8;
  buffer.inoffset[0] = 8;
  buffer.inunit[0] = UNIT_64_BIT;
  buffer.inptr[1] = CAST_TO_X_PTR( encrypt_premaster_secret);
  buffer.insize[1] = modlength;
  buffer.inoffset[1] = modlength;
  buffer.inunit[1] = UNIT_8_BIT;
  buffer.inptr[2] = CAST_TO_X_PTR( client_random);
  buffer.insize[2] = 32;
  buffer.inoffset[2] = 32;
  buffer.inunit[2] = UNIT_8_BIT;
  buffer.inptr[3] = CAST_TO_X_PTR( server_random);
  buffer.insize[3] = 32;
  buffer.inoffset[3] = 32;
  buffer.inunit[3] = UNIT_8_BIT;
  buffer.inptr[4] = CAST_TO_X_PTR( handshake);
  buffer.insize[4] = handshake_length;
  buffer.inoffset[4] = ROUNDUP8 (handshake_length);
  buffer.inunit[4] = UNIT_8_BIT;

  buffer.outptr[0] = CAST_TO_X_PTR( verify_data);
  buffer.outsize[0] = 36;
  buffer.outoffset[0] = 40;
  buffer.outunit[0] = UNIT_8_BIT;

  if (master_secret_ret == RETURN_ENCRYPTED)
    {

      buffer.rlen += (48 >> 3);

      buffer.outcnt = 2;

      buffer.outptr[1] = CAST_TO_X_PTR( encrypt_master_secret);
      buffer.outsize[1] = 48;
      buffer.outoffset[1] = 48;
      buffer.outunit[1] = UNIT_8_BIT;

    }
  else if (master_secret_ret == NOT_RETURNED)

    buffer.outcnt = 1;

  buffer.req_type = request_type;
  buffer.req_queue = SSL_QUEUE;
  buffer.res_order = CAVIUM_RESPONSE_ORDERED;
  buffer.dma_mode = global_dma_mode;
  buffer.status = 0;

  cond_code =
#ifdef CAVIUM_MULTICARD_API
    ioctl (gpkpdev_hdlr[dev_id], IOCTL_N1_OPERATION_CODE, (ptrlong) & buffer);
#else
    ioctl (CSP1_driver_handle, IOCTL_N1_OPERATION_CODE, (ptrlong) & buffer);
#endif

  *request_id = buffer.request_id;

  if(cond_code)
     ret_val = cond_code; /*return error val*/
  else
     ret_val = buffer.status;/*return OPERATION STATUS: SUCCESS('0')/EAGAIN */

  return ret_val;
}
#endif /*if !MC2 */


/*+****************************************************************************
 *
 * Csp1RsaServerFull3Des
 *
 * Does a full handshake on the server with RSA <= 1024. This entry point 
 * handles all the DES cases. The handshake message data for this request 
 * should include all handshake message data after (and including) the client 
 * hello message up until (but not including) the first finished message. 
 *
 * Input
 *		request_type = CAVIUM_BLOCKING or CAVIUM_NON_BLOCKING
 *		context_handle = 64-bit byte-pointer to context (context_handle%8=0)
 *		key_handle = pointer to 64-bit key memory handle
 *		hash_type = MD5_TYPE or SHA1_TYPE
 *		ssl_version = VER3_0 or VER_TLS
 *		des_type = DES, DES_EXPORT_40 or DES3_192
 *		master_secret_ret = NOT_RETURNED or RETURN_ENCRYPTED
 *		clnt_fin_msg_out = RETURN_CFM_ENCRYPTED or RETURN_CFM_UNENCRYPTED
 *		srvr_fin_msg_out = RETURN_SFM_ENCRYPTED or RETURN_SFM_UNENCRYPTED
 *		client_pad_length = number of 64-bit words to pad above min
 *		server_pad_length = number of 64-bit words to pad above min
 *		modlength = size of RSA operation in bytes (64<=modlength<=512, modlength%8=0)
 *	#ifdef MC2
 *		encrypt_premaster_secret = pointer to modlength-byte value.
 *	#else
 *		encrypt_premaster_secret = pointer to modlength-byte value in integer format
 *	#endif
 *		client_random = pointer to 32 bytes of random data
 *		server_random = pointer to 32 bytes of random data
 *		handshake_length = size in bytes of the handshake message data
 *		handshake = pointer to the handshake message data
 *
 * Output
 *		client_finished_message = pointer to encrypted part of client finished message 
 *		server_finished_message = pointer to encrypted part of server finished message 
 *		encrypt_master_secret = (master_secret_ret == RETURN_ENCRYPTED) ? pointer to
 *							returned encrypted master secret : don't care
 *		request_id = Unique ID for this request
 *
 * Return Value
 *		0  = success 
 *		>0 = failure or pending
 *		see error_codes.txt
 *
 *-***************************************************************************/
Uint32
Csp1RsaServerFull3Des (n1_request_type request_type,
		       Uint64 context_handle,
		       Uint64 * key_handle,
		       HashType hash_type,
		       SslVersion ssl_version,
		       DesType des_type,
		       MasterSecretReturn master_secret_ret,
		       ClientFinishMessageOutput clnt_fin_msg_out,
		       ServerFinishMessageOutput srvr_fin_msg_out,
		       Uint16 client_pad_length,
		       Uint16 server_pad_length,
		       Uint16 modlength,
		       Uint8 * encrypt_premaster_secret,
		       Uint8 * client_random,
		       Uint8 * server_random,
		       Uint16 handshake_length,
		       Uint8 * handshake,
		       Uint8 * client_finished_message,
		       Uint8 * server_finished_message,
		       Uint8 * encrypt_master_secret, 
#ifdef CAVIUM_MULTICARD_API
                       Uint32 * request_id, Uint32 dev_id
#else
                       Uint32 * request_id
#endif
                      )
{
  Csp1OperationBuffer buffer;
  Uint32 cond_code;
  Uint32 ret_val;
  Uint16 param = 0;
  Uint16 finished_size;
  Uint16 hash_size;

  memset(&buffer,0,sizeof(Csp1OperationBuffer));
  if ((context_handle & UINT64_C(0x8000000000000000)) != 0)
    {
      if ((context_handle & 0xf) != 0)
		  return ERR_ILLEGAL_CONTEXT_HANDLE;
    }
  else
    {
      if ((context_handle & 0x7) != 0)
		  return ERR_ILLEGAL_CONTEXT_HANDLE;
    }

#ifdef MC2
  if ((modlength & 0x7) != 0)
    return ERR_ILLEGAL_INPUT_LENGTH;
#endif

  if ((modlength >= 64) && (modlength <= 128))
    {
#ifdef MC2
      buffer.opcode =
	(master_secret_ret << 14) | (0x1 << 13) | (global_dma_mode << 7) |
	MAJOR_OP_RSASERVER;
#else
      param = (modlength >> 3) - 1;
      buffer.opcode =
	(master_secret_ret << 15) | (0x7 << 12) | (des_type << 10) |
	(ssl_version << 9) | (hash_type << 8) | (global_dma_mode << 7) |
	MAJOR_OP_RSASERVER;
#endif


    }
  else if ((modlength > 128) && (modlength <= 512))
    {

#ifdef MC2
      buffer.opcode =
	(master_secret_ret << 14) | (0x1 << 13) | (global_dma_mode << 7) |
	MAJOR_OP_RSASERVER_LARGE;
#else
      param = (modlength >> 3) - 17;
      buffer.opcode =
	(master_secret_ret << 15) | (0x7 << 12) | (des_type << 10) |
	(ssl_version << 9) | (hash_type << 8) | (global_dma_mode << 7) |
	MAJOR_OP_RSASERVER_LARGE;
#endif

#if defined(CSP1_API_DEBUG)
    }
  else
    {

      return ERR_ILLEGAL_INPUT_LENGTH;
#endif
    }

  finished_size = 16 + 24 * ssl_version;
#ifdef MC2
  param = (hash_type) | (ssl_version << 2) | (des_type << 3) | (1 << 7);

  if (clnt_fin_msg_out == RETURN_CFM_UNENCRYPTED)
    param |= (1 << 8);

  if (srvr_fin_msg_out == RETURN_SFM_UNENCRYPTED)
    param |= (1 << 9);

  hash_size = (hash_type == SHA1_TYPE) ? 20 : 16;

  buffer.size = modlength;
  buffer.dlen = 8 + modlength + 32 + 32 + handshake_length;
  buffer.rlen = 0;
#else

  param |= (server_pad_length << 11) | (client_pad_length << 6);

  if (clnt_fin_msg_out == RETURN_CFM_UNENCRYPTED)

    param |= 0x1f << 6;

  if (srvr_fin_msg_out == RETURN_SFM_UNENCRYPTED)

    param |= 0x1f << 11;

  hash_size = 20 - (hash_type << 2);

  buffer.size = handshake_length;
  buffer.dlen = (8 + modlength + 32 + 32 + ROUNDUP8 (handshake_length)) >> 3;
  buffer.rlen = 8 >> 3;
#endif
  buffer.ctx_ptr = context_handle;
  buffer.group = CAVIUM_SSL_GRP;
  buffer.param = param;

  buffer.incnt = 5;

  buffer.inptr[0] = CAST_TO_X_PTR((Uint8 *) key_handle);
  buffer.insize[0] = 8;
  buffer.inoffset[0] = 8;
  buffer.inunit[0] = UNIT_64_BIT;
  buffer.inptr[1] =CAST_TO_X_PTR( encrypt_premaster_secret);
  buffer.insize[1] = modlength;
  buffer.inoffset[1] = modlength;
  buffer.inunit[1] = UNIT_8_BIT;
  buffer.inptr[2] =CAST_TO_X_PTR(  client_random);
  buffer.insize[2] = 32;
  buffer.inoffset[2] = 32;
  buffer.inunit[2] = UNIT_8_BIT;
  buffer.inptr[3] = CAST_TO_X_PTR( server_random);
  buffer.insize[3] = 32;
  buffer.inoffset[3] = 32;
  buffer.inunit[3] = UNIT_8_BIT;
  buffer.inptr[4] = CAST_TO_X_PTR( handshake);
  buffer.insize[4] = handshake_length;
#ifdef MC2
  buffer.inoffset[4] = handshake_length;
#else
  buffer.inoffset[4] = ROUNDUP8 (handshake_length);
#endif
  buffer.inunit[4] = UNIT_8_BIT;


#ifdef MC2

  if (master_secret_ret == RETURN_ENCRYPTED)
    {
      buffer.rlen = 48;

      buffer.outcnt = 3;

      buffer.outptr[0] = CAST_TO_X_PTR( encrypt_master_secret);
      buffer.outsize[0] = 48;
      buffer.outoffset[0] = 48;
      buffer.outunit[0] = UNIT_8_BIT;

      buffer.outptr[1] = CAST_TO_X_PTR( client_finished_message);

      if (clnt_fin_msg_out == RETURN_CFM_ENCRYPTED)
	{
	  buffer.rlen += ROUNDUP8 (finished_size + hash_size + 1);

	  buffer.outsize[1] = ROUNDUP8 (finished_size + hash_size + 1);
	  buffer.outoffset[1] = ROUNDUP8 (finished_size + hash_size + 1);

	}
      else if (clnt_fin_msg_out == RETURN_CFM_UNENCRYPTED)
	{
	  buffer.rlen += finished_size;

	  buffer.outsize[1] = finished_size;
	  buffer.outoffset[1] = finished_size;
	}

      buffer.outunit[1] = UNIT_8_BIT;

      buffer.outptr[2] = CAST_TO_X_PTR( server_finished_message);

      if (srvr_fin_msg_out == RETURN_SFM_ENCRYPTED)
	{
	  buffer.rlen += ROUNDUP8 (finished_size + hash_size + 1);

	  buffer.outsize[2] = ROUNDUP8 (finished_size + hash_size + 1);
	  buffer.outoffset[2] = ROUNDUP8 (finished_size + hash_size + 1);

	}
      else if (srvr_fin_msg_out == RETURN_SFM_UNENCRYPTED)
	{
	  buffer.rlen += finished_size;

	  buffer.outsize[2] = finished_size;
	  buffer.outoffset[2] = finished_size;
	}

      buffer.outunit[2] = UNIT_8_BIT;

    }
  else if (master_secret_ret == NOT_RETURNED)
    {
      buffer.outcnt = 2;
      buffer.outptr[0] = CAST_TO_X_PTR( client_finished_message);

      if (clnt_fin_msg_out == RETURN_CFM_ENCRYPTED)
	{
	  buffer.rlen += ROUNDUP8 (finished_size + hash_size + 1);

	  buffer.outsize[0] = ROUNDUP8 (finished_size + hash_size + 1);
	  buffer.outoffset[0] = ROUNDUP8 (finished_size + hash_size + 1);

	}
      else if (clnt_fin_msg_out == RETURN_CFM_UNENCRYPTED)
	{
	  buffer.rlen += finished_size;

	  buffer.outsize[0] = finished_size;
	  buffer.outoffset[0] = finished_size;
	}

      buffer.outunit[0] = UNIT_8_BIT;

      buffer.outptr[1] = CAST_TO_X_PTR( server_finished_message);

      if (srvr_fin_msg_out == RETURN_SFM_ENCRYPTED)
	{
	  buffer.rlen += ROUNDUP8 (finished_size + hash_size + 1);

	  buffer.outsize[1] = ROUNDUP8 (finished_size + hash_size + 1);
	  buffer.outoffset[1] = ROUNDUP8 (finished_size + hash_size + 1);

	}
      else if (srvr_fin_msg_out == RETURN_SFM_UNENCRYPTED)
	{
	  buffer.rlen += finished_size;

	  buffer.outsize[1] = finished_size;
	  buffer.outoffset[1] = finished_size;
	}

      buffer.outunit[1] = UNIT_8_BIT;
    }
#else
  buffer.outptr[0] = CAST_TO_X_PTR( server_finished_message);

  if (srvr_fin_msg_out == RETURN_SFM_ENCRYPTED)
    {

      buffer.rlen +=
	((ROUNDUP8 (finished_size + hash_size + 1) +
	  8 * server_pad_length) >> 3);

      buffer.outsize[0] =
	ROUNDUP8 (finished_size + hash_size + 1) + 8 * server_pad_length;
      buffer.outoffset[0] =
	ROUNDUP8 (finished_size + hash_size + 1) + 8 * server_pad_length;

    }
  else if (srvr_fin_msg_out == RETURN_SFM_UNENCRYPTED)
    {

      buffer.rlen += (finished_size >> 3);

      buffer.outsize[0] = finished_size;
      buffer.outoffset[0] = finished_size;

    }

  buffer.outunit[0] = UNIT_8_BIT;

  buffer.outptr[1] = CAST_TO_X_PTR( client_finished_message);

  if (clnt_fin_msg_out == RETURN_CFM_ENCRYPTED)
    {

      buffer.rlen +=
	((ROUNDUP8 (finished_size + hash_size + 1) +
	  8 * client_pad_length) >> 3);

      buffer.outsize[1] =
	ROUNDUP8 (finished_size + hash_size + 1) + 8 * client_pad_length;
      buffer.outoffset[1] =
	ROUNDUP8 (finished_size + hash_size + 1) + 8 * client_pad_length;

    }
  else if (clnt_fin_msg_out == RETURN_CFM_UNENCRYPTED)
    {

      buffer.rlen += (finished_size >> 3);

      buffer.outsize[1] = finished_size;
      buffer.outoffset[1] = finished_size;

    }

  buffer.outunit[1] = UNIT_8_BIT;

  if (master_secret_ret == RETURN_ENCRYPTED)
    {

      buffer.rlen += (48 >> 3);

      buffer.outcnt = 3;

      buffer.outptr[2] = CAST_TO_X_PTR( encrypt_master_secret);
      buffer.outsize[2] = 48;
      buffer.outoffset[2] = 48;
      buffer.outunit[2] = UNIT_8_BIT;

    }
  else if (master_secret_ret == NOT_RETURNED)

    buffer.outcnt = 2;
#endif

  buffer.req_type = request_type;
  buffer.req_queue = SSL_QUEUE;
  buffer.res_order = CAVIUM_RESPONSE_ORDERED;
  buffer.dma_mode = global_dma_mode;
  buffer.status = 0;

  cond_code =
#ifdef CAVIUM_MULTICARD_API
    ioctl (gpkpdev_hdlr[dev_id], IOCTL_N1_OPERATION_CODE, (ptrlong) & buffer);
#else
    ioctl (CSP1_driver_handle, IOCTL_N1_OPERATION_CODE, (ptrlong) & buffer);
#endif

  *request_id = buffer.request_id;

  if(cond_code)
     ret_val = cond_code; /*return error val*/
  else
     ret_val = buffer.status;/*return OPERATION STATUS: SUCCESS('0')/EAGAIN */

  return ret_val;
}


#ifndef MC2

/*+****************************************************************************
 *
 * Csp1RsaServerFull3DesFinish
 *
 * Does a full handshake on the server. This entry point 
 * handles all the DES cases. The handshake data is accumulated prior to this 
 * request by calls to Handshake*, and this request appends the 
 * included handshake message data to the pre-existing handshake hash state.
 * The handshake message data for this request should include all handshake 
 * message data after (and including) the client hello message up until 
 * (but not including) the first finished message. 
 *
 * Input
 *		request_type = CAVIUM_BLOCKING or CAVIUM_NON_BLOCKING
 *		context_handle = 64-bit byte-pointer to context (context_handle%8=0)
 *		key_handle = pointer to 64-bit key memory handle
 *		hash_type = MD5_TYPE or SHA1_TYPE
 *		ssl_version = VER3_0 or VER_TLS
 *		des_type = DES, DES_EXPORT_40 or DES3_192
 *		master_secret_ret = NOT_RETURNED or RETURN_ENCRYPTED
 *		clnt_fin_msg_out = RETURN_CFM_ENCRYPTED or RETURN_CFM_UNENCRYPTED
 *		srvr_fin_msg_out = RETURN_SFM_ENCRYPTED or RETURN_SFM_UNENCRYPTED
 *		client_pad_length = number of 64-bit words to pad above min
 *		server_pad_length = number of 64-bit words to pad above min
 *		modlength = size of RSA operation in bytes (64<=modlength<=256, modlength%8=0)
 *	#ifdef MC2
 *		encrypt_premaster_secret = pointer to modlength-byte value.
 *	#else
 *		encrypt_premaster_secret = pointer to modlength-byte value in integer format
 *	#endif
 *		client_random = pointer to 32 bytes of random data
 *		server_random = pointer to 32 bytes of random data
 *		handshake_length = size in bytes of the handshake message data
 *		handshake = pointer to the handshake message data
 *
 * Output
 *		client_finished_message = pointer to encrypted part of client finished message 
 *		server_finished_message = pointer to encrypted part of server finished message 
 *		encrypt_master_secret = (master_secret_ret == RETURN_ENCRYPTED) ? pointer to
 *							returned encrypted master secret : don't care
 *		request_id = Unique ID for this request
 *
 * Return Value
 *		0  = success 
 *		>0 = failure or pending
 *		see error_codes.txt
 *
 *-***************************************************************************/
Uint32
Csp1RsaServerFull3DesFinish (n1_request_type request_type,
			     Uint64 context_handle,
			     Uint64 * key_handle,
			     HashType hash_type,
			     SslVersion ssl_version,
			     DesType des_type,
			     MasterSecretReturn master_secret_ret,
			     ClientFinishMessageOutput clnt_fin_msg_out,
			     ServerFinishMessageOutput srvr_fin_msg_out,
			     Uint16 client_pad_length,
			     Uint16 server_pad_length,
			     Uint16 modlength,
			     Uint8 * encrypt_premaster_secret,
			     Uint8 * client_random,
			     Uint8 * server_random,
			     Uint16 handshake_length,
			     Uint8 * handshake,
			     Uint8 * client_finished_message,
			     Uint8 * server_finished_message,
			     Uint8 * encrypt_master_secret,
#ifdef CAVIUM_MULTICARD_API
			     Uint32 * request_id, Uint32 dev_id
#else
			     Uint32 * request_id
#endif
                           )
{
  Csp1OperationBuffer buffer;
  Uint32 cond_code;
  Uint32 ret_val;
  Uint16 param = 0;
  Uint16 finished_size;
  Uint16 hash_size;
  memset(&buffer,0,sizeof(Csp1OperationBuffer));

  if ((context_handle & UINT64_C(0x8000000000000000)) != 0)
    {
      if ((context_handle & 0xf) != 0)
		  return ERR_ILLEGAL_CONTEXT_HANDLE;
    }
  else
    {
      if ((context_handle & 0x7) != 0)
		  return ERR_ILLEGAL_CONTEXT_HANDLE;
    }

  if ((modlength & 0x7) != 0)
	  return ERR_ILLEGAL_INPUT_LENGTH;


  if ((modlength >= 64) && (modlength <= 128))
    {

      param = (modlength >> 3) - 1;
      buffer.opcode =
	(master_secret_ret << 15) | (0x5 << 12) | (des_type << 10) |
	(ssl_version << 9) | (hash_type << 8) | (global_dma_mode << 7) |
	MAJOR_OP_RSASERVER;


    }
  else if ((modlength > 128) && (modlength <= 256))
    {

      param = (modlength >> 3) - 17;
      buffer.opcode =
	(master_secret_ret << 15) | (0x5 << 12) | (des_type << 10) |
	(ssl_version << 9) | (hash_type << 8) | (global_dma_mode << 7) |
	MAJOR_OP_RSASERVER_LARGE;

#if defined(CSP1_API_DEBUG)
    }
  else
    {

      return ERR_ILLEGAL_INPUT_LENGTH;
#endif
    }

  param |= (server_pad_length << 11) | (client_pad_length << 6);

  if (clnt_fin_msg_out == RETURN_CFM_UNENCRYPTED)

    param |= 0x1f << 6;

  if (srvr_fin_msg_out == RETURN_SFM_UNENCRYPTED)

    param |= 0x1f << 11;

  hash_size = 20 - (hash_type << 2);
  finished_size = 16 + 24 * ssl_version;

  buffer.size = handshake_length;
  buffer.param = param;
  buffer.dlen = (8 + modlength + 32 + 32 + ROUNDUP8 (handshake_length)) >> 3;
  buffer.rlen = 8 >> 3;
  buffer.ctx_ptr = context_handle;
  buffer.group = CAVIUM_SSL_GRP;

  buffer.incnt = 5;

  buffer.inptr[0] = CAST_TO_X_PTR((Uint8 *) key_handle);
  buffer.insize[0] = 8;
  buffer.inoffset[0] = 8;
  buffer.inunit[0] = UNIT_64_BIT;
  buffer.inptr[1] = CAST_TO_X_PTR( encrypt_premaster_secret);
  buffer.insize[1] = modlength;
  buffer.inoffset[1] = modlength;
  buffer.inunit[1] = UNIT_8_BIT;
  buffer.inptr[2] = CAST_TO_X_PTR( client_random);
  buffer.insize[2] = 32;
  buffer.inoffset[2] = 32;
  buffer.inunit[2] = UNIT_8_BIT;
  buffer.inptr[3] = CAST_TO_X_PTR( server_random);
  buffer.insize[3] = 32;
  buffer.inoffset[3] = 32;
  buffer.inunit[3] = UNIT_8_BIT;
  buffer.inptr[4] = CAST_TO_X_PTR( handshake);
  buffer.insize[4] = handshake_length;
  buffer.inoffset[4] = ROUNDUP8 (handshake_length);
  buffer.inunit[4] = UNIT_8_BIT;

  buffer.outptr[0] = CAST_TO_X_PTR( server_finished_message);

  if (srvr_fin_msg_out == RETURN_SFM_ENCRYPTED)
    {

      buffer.rlen +=
	((ROUNDUP8 (finished_size + hash_size + 1) +
	  8 * server_pad_length) >> 3);

      buffer.outsize[0] =
	ROUNDUP8 (finished_size + hash_size + 1) + 8 * server_pad_length;
      buffer.outoffset[0] =
	ROUNDUP8 (finished_size + hash_size + 1) + 8 * server_pad_length;

    }
  else if (srvr_fin_msg_out == RETURN_SFM_UNENCRYPTED)
    {

      buffer.rlen += (finished_size >> 3);

      buffer.outsize[0] = finished_size;
      buffer.outoffset[0] = finished_size;

    }

  buffer.outunit[0] = UNIT_8_BIT;

  buffer.outptr[1] = CAST_TO_X_PTR( client_finished_message);

  if (clnt_fin_msg_out == RETURN_CFM_ENCRYPTED)
    {

      buffer.rlen +=
	((ROUNDUP8 (finished_size + hash_size + 1) +
	  8 * client_pad_length) >> 3);

      buffer.outsize[1] =
	ROUNDUP8 (finished_size + hash_size + 1) + 8 * client_pad_length;
      buffer.outoffset[1] =
	ROUNDUP8 (finished_size + hash_size + 1) + 8 * client_pad_length;

    }
  else if (clnt_fin_msg_out == RETURN_CFM_UNENCRYPTED)
    {

      buffer.rlen += (finished_size >> 3);

      buffer.outsize[1] = finished_size;
      buffer.outoffset[1] = finished_size;

    }

  buffer.outunit[1] = UNIT_8_BIT;

  if (master_secret_ret == RETURN_ENCRYPTED)
    {

      buffer.rlen += (48 >> 3);

      buffer.outcnt = 3;

      buffer.outptr[2] = CAST_TO_X_PTR( encrypt_master_secret);
      buffer.outsize[2] = 48;
      buffer.outoffset[2] = 48;
      buffer.outunit[2] = UNIT_8_BIT;

    }
  else if (master_secret_ret == NOT_RETURNED)

    buffer.outcnt = 2;

  buffer.req_type = request_type;
  buffer.req_queue = SSL_QUEUE;
  buffer.res_order = CAVIUM_RESPONSE_ORDERED;
  buffer.dma_mode = global_dma_mode;
  buffer.status = 0;

  cond_code =
#ifdef CAVIUM_MULTICARD_API
    ioctl (gpkpdev_hdlr[dev_id], IOCTL_N1_OPERATION_CODE, (ptrlong) & buffer);
#else
    ioctl (CSP1_driver_handle, IOCTL_N1_OPERATION_CODE, (ptrlong) & buffer);
#endif

  *request_id = buffer.request_id;

  if(cond_code)
     ret_val = cond_code; /*return error val*/
  else
     ret_val = buffer.status;/*return OPERATION STATUS: SUCCESS('0')/EAGAIN */

  return ret_val;
}
#endif /* if !MC2 */


/*+****************************************************************************
 *
 * Csp1RsaServerVerify3Des
 *
 * Do much of the full handshake - up to the point of the 
 * verify - in the case when client authentication is required. This is used in 
 * a full handshake on the server. This entry point handles all the DES/3DES 
 * cases.
 *
 * The handshake message data for this request should include all handshake 
 * message data after (and including) the client hello message up until (but 
 * not including) the client verify message. 
 *
 * Input
 *		request_type = CAVIUM_BLOCKING or CAVIUM_NON_BLOCKING
 *		context_handle = 64-bit byte-pointer to context (context_handle%8=0)
 *		key_handle = pointer to 64-bit key memory handle
 *		hash_type = MD5_TYPE or SHA1_TYPE
 *		ssl_version = VER3_0 or VER_TLS
 *		des_type = DES, DES_EXPORT_40, DES3_192
 *		master_secret_ret = NOT_RETURNED or RETURN_ENCRYPTED
 *		modlength = size of RSA operation in bytes (64<=modlength<=512, modlength%8=0)
 *	#ifdef MC2
 *		encrypt_premaster_secret = pointer to modlength-byte value
 *	#else
 *		encrypt_premaster_secret = pointer to modlength-byte value in integer format
 *	#endif
 *		client_random = pointer to 32 bytes of random data
 *		server_random = pointer to 32 bytes of random data
 *		handshake_length = size in bytes of the handshake message data
 *		handshake = pointer to the handshake message data
 *
 * Output
 *		verify_data = pointer to 36 bytes of verify data 
 *		encrypt_master_secret = (master_secret_ret == RETURN_ENCRYPTED) ? pointer to
 *				returned encrypted master secret : don't care
 *		request_id = Unique ID for this request
 *
 * Return Value
 *		0  = success 
 *		>0 = failure or pending
 *		see error_codes.txt
 *-***************************************************************************/
Uint32
Csp1RsaServerVerify3Des (n1_request_type request_type,
			 Uint64 context_handle,
			 Uint64 * key_handle,
			 HashType hash_type,
			 SslVersion ssl_version,
			 DesType des_type,
			 MasterSecretReturn master_secret_ret,
			 Uint16 modlength,
			 Uint8 * encrypt_premaster_secret,
			 Uint8 * client_random,
			 Uint8 * server_random,
			 Uint16 handshake_length,
			 Uint8 * handshake,
			 Uint8 * verify_data,
			 Uint8 * encrypt_master_secret, 
#ifdef CAVIUM_MULTICARD_API
                         Uint32 * request_id,Uint32 dev_id
#else
                         Uint32 * request_id
#endif
                        )
{
  Csp1OperationBuffer buffer;
  Uint32 cond_code;
  Uint32 ret_val;
#ifndef MC2
  Uint16 param = 0;
#endif
  Uint16 hash_size;

  memset(&buffer,0,sizeof(Csp1OperationBuffer));

  if ((context_handle & UINT64_C(0x8000000000000000)) != 0)
    {
      if ((context_handle & 0xf) != 0)

	return ERR_ILLEGAL_CONTEXT_HANDLE;

    }
  else
    {

      if ((context_handle & 0x7) != 0)

	return ERR_ILLEGAL_CONTEXT_HANDLE;

    }

#ifndef MC2
  if ((modlength & 0x7) != 0)

    return ERR_ILLEGAL_INPUT_LENGTH;
#endif

  if ((modlength >= 64) && (modlength <= 128))
    {
#ifdef MC2
      buffer.opcode =
	(master_secret_ret << 14) | (global_dma_mode << 7) |
	MAJOR_OP_RSASERVER;
#else
      param = (modlength >> 3) - 1;
      buffer.opcode =
	(master_secret_ret << 15) | (0x3 << 12) | (des_type << 10) |
	(ssl_version << 9) | (hash_type << 8) | (global_dma_mode << 7) |
	MAJOR_OP_RSASERVER;
#endif

    }
  else if ((modlength > 128) && (modlength <= 512))
    {
#ifdef MC2
      buffer.opcode =
	(master_secret_ret << 14) | (global_dma_mode << 7) |
	MAJOR_OP_RSASERVER_LARGE;
#else
      param = (modlength >> 3) - 17;
      buffer.opcode =
	(master_secret_ret << 15) | (0x3 << 12) | (des_type << 10) |
	(ssl_version << 9) | (hash_type << 8) | (global_dma_mode << 7) |
	MAJOR_OP_RSASERVER_LARGE;
#endif

#if defined(CSP1_API_DEBUG)
    }
  else
    {

      return ERR_ILLEGAL_INPUT_LENGTH;
#endif
    }

#ifdef MC2
  hash_size = (hash_type == SHA1_TYPE) ? 20 : 16;
  buffer.size = modlength;
  buffer.param =
    (hash_type) | (ssl_version << 2) | (des_type << 3) | (1 << 7);
  buffer.dlen = 8 + modlength + 32 + 32 + handshake_length;
#else
  hash_size = 20 - (hash_type << 2);
  buffer.size = handshake_length;
  buffer.param = param;
  buffer.dlen = (8 + modlength + 32 + 32 + ROUNDUP8 (handshake_length)) >> 3;
  buffer.rlen = (40 + 8) >> 3;
#endif

  buffer.ctx_ptr = context_handle;
  buffer.group = CAVIUM_SSL_GRP;
  buffer.incnt = 5;
  buffer.inptr[0] = CAST_TO_X_PTR((Uint8 *) key_handle);
  buffer.insize[0] = 8;
  buffer.inoffset[0] = 8;
  buffer.inunit[0] = UNIT_64_BIT;
  buffer.inptr[1] = CAST_TO_X_PTR( encrypt_premaster_secret);
  buffer.insize[1] = modlength;
  buffer.inoffset[1] = modlength;
  buffer.inunit[1] = UNIT_8_BIT;
  buffer.inptr[2] = CAST_TO_X_PTR( client_random);
  buffer.insize[2] = 32;
  buffer.inoffset[2] = 32;
  buffer.inunit[2] = UNIT_8_BIT;
  buffer.inptr[3] = CAST_TO_X_PTR( server_random);
  buffer.insize[3] = 32;
  buffer.inoffset[3] = 32;
  buffer.inunit[3] = UNIT_8_BIT;
  buffer.inptr[4] = CAST_TO_X_PTR( handshake);
  buffer.insize[4] = handshake_length;
#ifdef MC2
  buffer.inoffset[4] = handshake_length;
#else
  buffer.inoffset[4] = ROUNDUP8 (handshake_length);
#endif
  buffer.inunit[4] = UNIT_8_BIT;



#ifdef MC2
  if (master_secret_ret == RETURN_ENCRYPTED)
    {
      buffer.rlen = 48 + 36;
      buffer.outcnt = 2;

      buffer.outptr[0] = CAST_TO_X_PTR( encrypt_master_secret);
      buffer.outsize[0] = 48;
      buffer.outoffset[0] = 48;
      buffer.outunit[0] = UNIT_8_BIT;

      buffer.outptr[1] = CAST_TO_X_PTR( verify_data);
      buffer.outsize[1] = 36;
      buffer.outoffset[1] = 36;
      buffer.outunit[1] = UNIT_8_BIT;
    }
  else
    {
      buffer.rlen = 36;
      buffer.outcnt = 1;

      buffer.outptr[0] = CAST_TO_X_PTR( verify_data);
      buffer.outsize[0] = 36;
      buffer.outoffset[0] = 36;
      buffer.outunit[0] = UNIT_8_BIT;
    }
#else

  buffer.outptr[0] = CAST_TO_X_PTR( verify_data);
  buffer.outsize[0] = 36;
  buffer.outoffset[0] = 40;
  buffer.outunit[0] = UNIT_8_BIT;
  if (master_secret_ret == RETURN_ENCRYPTED)
    {

      buffer.rlen += (48 >> 3);

      buffer.outcnt = 2;

      buffer.outptr[1] = CAST_TO_X_PTR( encrypt_master_secret);
      buffer.outsize[1] = 48;
      buffer.outoffset[1] = 48;
      buffer.outunit[1] = UNIT_8_BIT;

    }
  else if (master_secret_ret == NOT_RETURNED)

    buffer.outcnt = 1;
#endif
  buffer.req_type = request_type;
  buffer.req_queue = SSL_QUEUE;
  buffer.res_order = CAVIUM_RESPONSE_ORDERED;
  buffer.dma_mode = global_dma_mode;
  buffer.status = 0;

  cond_code =
#ifdef CAVIUM_MULTICARD_API
    ioctl (gpkpdev_hdlr[dev_id], IOCTL_N1_OPERATION_CODE, (ptrlong) & buffer);
#else
    ioctl (CSP1_driver_handle, IOCTL_N1_OPERATION_CODE, (ptrlong) & buffer);
#endif

  *request_id = buffer.request_id;

  if(cond_code)
     ret_val = cond_code; /*return error val*/
  else
     ret_val = buffer.status;/*return OPERATION STATUS: SUCCESS('0')/EAGAIN */

  return ret_val;
}


#ifndef MC2

/*+****************************************************************************
 *
 * Csp1RsaServerVerify3DesFinish
 *
 * Do much of the full handshake - up to the point of the 
 * verify - in the case when client authentication is required. This is used in 
 * a full handshake on the server. This entry point handles all the DES/3DES 
 * cases.
 *
 * The handshake message data for this request should include all handshake 
 * message data after (and including) the client hello message up until (but not
 * including) the client verify message. Handshake data can be accumulated prior 
 * to this request by calls to Handshake*, and this request will append 
 * the included handshake message data to the pre-existing handshake hash state.
 *
 * Input
 *		request_type = CAVIUM_BLOCKING or CAVIUM_NON_BLOCKING
 *		context_handle = 64-bit byte-pointer to context (context_handle%8=0)
 *		key_handle = pointer to 64-bit key memory handle
 *		hash_type = MD5_TYPE or SHA1_TYPE
 *		ssl_version = VER3_0 or VER_TLS
 *		des_type = DES, DES_EXPORT_40 or DES3_192
 *		master_secret_ret = NOT_RETURNED or RETURN_ENCRYPTED
 *		modlength = size of RSA operation in bytes (64<=modlength<=256, modlength%8=0)
 *		encrypt_premaster_secret = pointer to modlength-byte value in integer format
 *		client_random = pointer to 32 bytes of random data
 *		server_random = pointer to 32 bytes of random data
 *		handshake_length = size in bytes of the handshake message data
 *		handshake = pointer to the handshake message data
 *
 * Output
 *		verify_data = pointer to 36 bytes of verify data 
 *		encrypt_master_secret = (master_secret_ret == RETURN_ENCRYPTED) ? pointer to
 *				returned encrypted master secret : don't care
 *		request_id = Unique ID for this request
 *
 * Return Value
 *		0  = success 
 *		>0 = failure or pending
 *		see error_codes.txt
 *
 *-***************************************************************************/
Uint32
Csp1RsaServerVerify3DesFinish (n1_request_type request_type,
			       Uint64 context_handle,
			       Uint64 * key_handle,
			       HashType hash_type,
			       SslVersion ssl_version,
			       DesType des_type,
			       MasterSecretReturn master_secret_ret,
			       Uint16 modlength,
			       Uint8 * encrypt_premaster_secret,
			       Uint8 * client_random,
			       Uint8 * server_random,
			       Uint16 handshake_length,
			       Uint8 * handshake,
			       Uint8 * verify_data,
			       Uint8 * encrypt_master_secret,
#ifdef CAVIUM_MULTICARD_API
			       Uint32 * request_id, Uint32 dev_id
#else
			       Uint32 * request_id
#endif
                              )
{
  Csp1OperationBuffer buffer;
  Uint32 cond_code;
  Uint32 ret_val;
  Uint16 param = 0;
  Uint16 hash_size;
  memset(&buffer,0,sizeof(Csp1OperationBuffer));

  if ((context_handle & UINT64_C(0x8000000000000000)) != 0)
    {

      if ((context_handle & 0xf) != 0)

	return ERR_ILLEGAL_CONTEXT_HANDLE;

    }
  else
    {

      if ((context_handle & 0x7) != 0)

	return ERR_ILLEGAL_CONTEXT_HANDLE;

    }

  if ((modlength & 0x7) != 0)

    return ERR_ILLEGAL_INPUT_LENGTH;

  if ((modlength >= 64) && (modlength <= 128))
    {

      param = (modlength >> 3) - 1;
      buffer.opcode =
	(master_secret_ret << 15) | (0x1 << 12) | (des_type << 10) |
	(ssl_version << 9) | (hash_type << 8) | (global_dma_mode << 7) |
	MAJOR_OP_RSASERVER;


    }
  else if ((modlength > 128) && (modlength <= 256))
    {

      param = (modlength >> 3) - 17;
      buffer.opcode =
	(master_secret_ret << 15) | (0x1 << 12) | (des_type << 10) |
	(ssl_version << 9) | (hash_type << 8) | (global_dma_mode << 7) |
	MAJOR_OP_RSASERVER_LARGE;

#if defined(CSP1_API_DEBUG)
    }
  else
    {

      return ERR_ILLEGAL_INPUT_LENGTH;
#endif
    }

  hash_size = 20 - (hash_type << 2);

  buffer.size = handshake_length;
  buffer.param = param;
  buffer.dlen = (8 + modlength + 32 + 32 + ROUNDUP8 (handshake_length)) >> 3;
  buffer.rlen = (40 + 8) >> 3;
  buffer.ctx_ptr = context_handle;
  buffer.group = CAVIUM_SSL_GRP;

  buffer.incnt = 5;

  buffer.inptr[0] = CAST_TO_X_PTR((Uint8 *) key_handle);
  buffer.insize[0] = 8;
  buffer.inoffset[0] = 8;
  buffer.inunit[0] = UNIT_64_BIT;
  buffer.inptr[1] = CAST_TO_X_PTR( encrypt_premaster_secret);
  buffer.insize[1] = modlength;
  buffer.inoffset[1] = modlength;
  buffer.inunit[1] = UNIT_8_BIT;
  buffer.inptr[2] = CAST_TO_X_PTR( client_random);
  buffer.insize[2] = 32;
  buffer.inoffset[2] = 32;
  buffer.inunit[2] = UNIT_8_BIT;
  buffer.inptr[3] = CAST_TO_X_PTR( server_random);
  buffer.insize[3] = 32;
  buffer.inoffset[3] = 32;
  buffer.inunit[3] = UNIT_8_BIT;
  buffer.inptr[4] = CAST_TO_X_PTR( handshake);
  buffer.insize[4] = handshake_length;
  buffer.inoffset[4] = ROUNDUP8 (handshake_length);
  buffer.inunit[4] = UNIT_8_BIT;

  buffer.outptr[0] = CAST_TO_X_PTR( verify_data);
  buffer.outsize[0] = 36;
  buffer.outoffset[0] = 40;
  buffer.outunit[0] = UNIT_8_BIT;

  if (master_secret_ret == RETURN_ENCRYPTED)
    {

      buffer.rlen += (48 >> 3);

      buffer.outcnt = 2;

      buffer.outptr[1] = CAST_TO_X_PTR( encrypt_master_secret);
      buffer.outsize[1] = 48;
      buffer.outoffset[1] = 48;
      buffer.outunit[1] = UNIT_8_BIT;

    }
  else if (master_secret_ret == NOT_RETURNED)

    buffer.outcnt = 1;

  buffer.req_type = request_type;
  buffer.req_queue = SSL_QUEUE;
  buffer.res_order = CAVIUM_RESPONSE_ORDERED;
  buffer.dma_mode = global_dma_mode;
  buffer.status = 0;

  cond_code =
#ifdef CAVIUM_MULTICARD_API
    ioctl (gpkpdev_hdlr[dev_id], IOCTL_N1_OPERATION_CODE, (ptrlong) & buffer);
#else
    ioctl (CSP1_driver_handle, IOCTL_N1_OPERATION_CODE, (ptrlong) & buffer);
#endif

  *request_id = buffer.request_id;

  if(cond_code)
     ret_val = cond_code; /*return error val*/
  else
     ret_val = buffer.status;/*return OPERATION STATUS: SUCCESS('0')/EAGAIN */

  return ret_val;
}
#endif /* if !MC2 */


/*+****************************************************************************
 *
 * Csp1RsaServerFullAes
 *
 * Does a full handshake on the server. This entry point 
 * handles all the AES cases. The handshake message data for this request 
 * should include all handshake message data after (and including) the client 
 * hello message up until (but not including) the first finished message. 
 *
 * Input
 *		request_type = CAVIUM_BLOCKING or CAVIUM_NON_BLOCKING
 *		context_handle = 64-bit byte-pointer to context (context_handle%8=0)
 *		key_handle = pointer to 64-bit key memory handle
 *		hash_type = MD5_TYPE or SHA1_TYPE
 *		ssl_version = VER3_0 or VER_TLS
 *		aes_type = AES_128 or AES_256
 *		master_secret_ret = NOT_RETURNED or RETURN_ENCRYPTED
 *		clnt_fin_msg_out = RETURN_CFM_ENCRYPTED or RETURN_CFM_UNENCRYPTED
 *		srvr_fin_msg_out = RETURN_SFM_ENCRYPTED or RETURN_SFM_UNENCRYPTED
 *		client_pad_length = number of 128-bit words to pad above min
 *		server_pad_length = number of 128-bit words to pad above min
 *		modlength = size of RSA operation in bytes (64<=modlength<=512, modlength%8=0)
 *	#ifdef MC2
 *		encrypt_premaster_secret = pointer to modlength-byte value.
 *	#else
 *		encrypt_premaster_secret = pointer to modlength-byte value in integer format
 *	#endif
 *		client_random = pointer to 32 bytes of random data
 *		server_random = pointer to 32 bytes of random data
 *		handshake_length = size in bytes of the handshake message data
 *		handshake = pointer to the handshake message data
 *
 * Output
 *		client_finished_message = pointer to encrypted part of client finished message 
 *		server_finished_message = pointer to encrypted part of server finished message 
 *		encrypt_master_secret = (master_secret_ret == RETURN_ENCRYPTED) ? pointer to
 *						returned encrypted master secret : don't care
 *		request_id = Unique ID for this request
 *
 * Return Value
 *		0  = success 
 *		>0 = failure or pending
 *		see error_codes.txt
 *
 *-***************************************************************************/
Uint32
Csp1RsaServerFullAes (n1_request_type request_type,
		      Uint64 context_handle,
		      Uint64 * key_handle,
		      HashType hash_type,
		      SslVersion ssl_version,
		      AesType aes_type,
		      MasterSecretReturn master_secret_ret,
		      ClientFinishMessageOutput clnt_fin_msg_out,
		      ServerFinishMessageOutput srvr_fin_msg_out,
		      Uint16 client_pad_length,
		      Uint16 server_pad_length,
		      Uint16 modlength,
		      Uint8 * encrypt_premaster_secret,
		      Uint8 * client_random,
		      Uint8 * server_random,
		      Uint16 handshake_length,
		      Uint8 * handshake,
		      Uint8 * client_finished_message,
		      Uint8 * server_finished_message,
		      Uint8 * encrypt_master_secret,
#ifdef CAVIUM_MULTICARD_API
                      Uint32 * request_id, Uint32 dev_id
#else
                      Uint32 * request_id
#endif
                    )
{
  Csp1OperationBuffer buffer;
  Uint32 cond_code;
  Uint32 ret_val;
  Uint16 param = 0;
  Uint16 finished_size;
  Uint16 hash_size;
  memset(&buffer,0,sizeof(Csp1OperationBuffer));


  if ((context_handle & UINT64_C(0x8000000000000000)) != 0)
    {

      if ((context_handle & 0xf) != 0)

	return ERR_ILLEGAL_CONTEXT_HANDLE;

    }
  else
    {

      if ((context_handle & 0x7) != 0)

	return ERR_ILLEGAL_CONTEXT_HANDLE;

    }

#ifndef MC2
  if ((modlength & 0x7) != 0)

    return ERR_ILLEGAL_INPUT_LENGTH;
#endif

  if ((modlength >= 64) && (modlength <= 128))
    {
#ifdef MC2
      buffer.opcode =
	(master_secret_ret << 14) | (0x1 << 13) | (global_dma_mode << 7) |
	MAJOR_OP_RSASERVER;
#else
      param = (modlength >> 3) - 1;
      buffer.opcode =
	(master_secret_ret << 15) | (0xd << 11) | ((aes_type >> 1) << 10) |
	(ssl_version << 9) | (hash_type << 8) | (global_dma_mode << 7) |
	MAJOR_OP_RSASERVER;
#endif

    }
  else if ((modlength > 128) && (modlength <= 512))
    {
#ifdef MC2
      buffer.opcode =
	(master_secret_ret << 14) | (0x1 << 13) | (global_dma_mode << 7) |
	MAJOR_OP_RSASERVER_LARGE;
#else
      param = (modlength >> 3) - 17;
      buffer.opcode =
	(master_secret_ret << 15) | (0xd << 11) | ((aes_type >> 1) << 10) |
	(ssl_version << 9) | (hash_type << 8) | (global_dma_mode << 7) |
	MAJOR_OP_RSASERVER_LARGE;
#endif

#if defined(CSP1_API_DEBUG)
    }
  else
    {

      return ERR_ILLEGAL_INPUT_LENGTH;
#endif
    }

  finished_size = 16 + 24 * ssl_version;

#ifdef MC2

  param = (hash_type) | (ssl_version << 2) | (aes_type << 3) | (1 << 7);

  if (clnt_fin_msg_out == RETURN_CFM_UNENCRYPTED)
    param |= (1 << 8);

  if (srvr_fin_msg_out == RETURN_SFM_UNENCRYPTED)
    param |= (1 << 9);

  hash_size = (hash_type == SHA1_TYPE) ? 20 : 16;

  buffer.size = modlength;
  buffer.dlen = 8 + modlength + 32 + 32 + handshake_length;
  buffer.rlen = 0;
#else

  param |= (server_pad_length << 11) | (client_pad_length << 6);

  if (clnt_fin_msg_out == RETURN_CFM_UNENCRYPTED)

    param |= 0x1f << 6;

  if (srvr_fin_msg_out == RETURN_SFM_UNENCRYPTED)

    param |= 0x1f << 11;

  hash_size = 20 - (hash_type << 2);

  buffer.size = handshake_length;
  buffer.dlen = (8 + modlength + 32 + 32 + ROUNDUP8 (handshake_length)) >> 3;
  buffer.rlen = 8 >> 3;
#endif
  buffer.param = param;
  buffer.ctx_ptr = context_handle;
  buffer.group = CAVIUM_SSL_GRP;

  buffer.incnt = 5;

  buffer.inptr[0] = CAST_TO_X_PTR((Uint8 *) key_handle);
  buffer.insize[0] = 8;
  buffer.inoffset[0] = 8;
  buffer.inunit[0] = UNIT_64_BIT;
  buffer.inptr[1] = CAST_TO_X_PTR( encrypt_premaster_secret);
  buffer.insize[1] = modlength;
  buffer.inoffset[1] = modlength;
  buffer.inunit[1] = UNIT_8_BIT;
  buffer.inptr[2] = CAST_TO_X_PTR( client_random);
  buffer.insize[2] = 32;
  buffer.inoffset[2] = 32;
  buffer.inunit[2] = UNIT_8_BIT;
  buffer.inptr[3] = CAST_TO_X_PTR( server_random);
  buffer.insize[3] = 32;
  buffer.inoffset[3] = 32;
  buffer.inunit[3] = UNIT_8_BIT;
  buffer.inptr[4] = CAST_TO_X_PTR( handshake);
  buffer.insize[4] = handshake_length;
#ifdef MC2
  buffer.inoffset[4] = handshake_length;
#else
  buffer.inoffset[4] = ROUNDUP8 (handshake_length);
#endif
  buffer.inunit[4] = UNIT_8_BIT;

#ifdef MC2
  if (master_secret_ret == RETURN_ENCRYPTED)
    {
      buffer.rlen = 48;

      buffer.outcnt = 3;

      buffer.outptr[0] = CAST_TO_X_PTR( encrypt_master_secret);
      buffer.outsize[0] = 48;
      buffer.outoffset[0] = 48;
      buffer.outunit[0] = UNIT_8_BIT;

      buffer.outptr[1] = CAST_TO_X_PTR( client_finished_message);

      if (clnt_fin_msg_out == RETURN_CFM_ENCRYPTED)
	{
	  buffer.rlen += ROUNDUP16 (finished_size + hash_size + 1);

	  buffer.outsize[1] = ROUNDUP16 (finished_size + hash_size + 1);
	  buffer.outoffset[1] = ROUNDUP16 (finished_size + hash_size + 1);

	}
      else if (clnt_fin_msg_out == RETURN_CFM_UNENCRYPTED)
	{
	  buffer.rlen += finished_size;

	  buffer.outsize[1] = finished_size;
	  buffer.outoffset[1] = finished_size;
	}

      buffer.outunit[1] = UNIT_8_BIT;

      buffer.outptr[2] = CAST_TO_X_PTR( server_finished_message);

      if (srvr_fin_msg_out == RETURN_SFM_ENCRYPTED)
	{
	  buffer.rlen += ROUNDUP16 (finished_size + hash_size + 1);

	  buffer.outsize[2] = ROUNDUP16 (finished_size + hash_size + 1);
	  buffer.outoffset[2] = ROUNDUP16 (finished_size + hash_size + 1);

	}
      else if (srvr_fin_msg_out == RETURN_SFM_UNENCRYPTED)
	{
	  buffer.rlen += finished_size;

	  buffer.outsize[2] = finished_size;
	  buffer.outoffset[2] = finished_size;
	}

      buffer.outunit[2] = UNIT_8_BIT;

    }
  else if (master_secret_ret == NOT_RETURNED)
    {
      buffer.outcnt = 2;
      buffer.outptr[0] = CAST_TO_X_PTR( client_finished_message);

      if (clnt_fin_msg_out == RETURN_CFM_ENCRYPTED)
	{
	  buffer.rlen += ROUNDUP16 (finished_size + hash_size + 1);

	  buffer.outsize[0] = ROUNDUP16 (finished_size + hash_size + 1);
	  buffer.outoffset[0] = ROUNDUP16 (finished_size + hash_size + 1);

	}
      else if (clnt_fin_msg_out == RETURN_CFM_UNENCRYPTED)
	{
	  buffer.rlen += finished_size;

	  buffer.outsize[0] = finished_size;
	  buffer.outoffset[0] = finished_size;
	}

      buffer.outunit[0] = UNIT_8_BIT;

      buffer.outptr[1] = CAST_TO_X_PTR( server_finished_message);

      if (srvr_fin_msg_out == RETURN_SFM_ENCRYPTED)
	{
	  buffer.rlen += ROUNDUP16 (finished_size + hash_size + 1);

	  buffer.outsize[1] = ROUNDUP16 (finished_size + hash_size + 1);
	  buffer.outoffset[1] = ROUNDUP16 (finished_size + hash_size + 1);

	}
      else if (srvr_fin_msg_out == RETURN_SFM_UNENCRYPTED)
	{
	  buffer.rlen += finished_size;

	  buffer.outsize[1] = finished_size;
	  buffer.outoffset[1] = finished_size;
	}

      buffer.outunit[1] = UNIT_8_BIT;
    }
#else
  
  buffer.outptr[0] = CAST_TO_X_PTR( server_finished_message);

  if (srvr_fin_msg_out == RETURN_SFM_ENCRYPTED)
    {

      buffer.rlen +=
	((ROUNDUP16 (finished_size + hash_size + 1) +
	  16 * server_pad_length) >> 3);

      buffer.outsize[0] =
	ROUNDUP16 (finished_size + hash_size + 1) + 16 * server_pad_length;
      buffer.outoffset[0] =
	ROUNDUP16 (finished_size + hash_size + 1) + 16 * server_pad_length;

    }
  else if (srvr_fin_msg_out == RETURN_SFM_UNENCRYPTED)
    {

      buffer.rlen += (finished_size >> 3);

      buffer.outsize[0] = finished_size;
      buffer.outoffset[0] = finished_size;

    }

  buffer.outunit[0] = UNIT_8_BIT;

  buffer.outptr[1] = CAST_TO_X_PTR( client_finished_message);

  if (clnt_fin_msg_out == RETURN_CFM_ENCRYPTED)
    {

      buffer.rlen +=
	((ROUNDUP16 (finished_size + hash_size + 1) +
	  16 * client_pad_length) >> 3);

      buffer.outsize[1] =
	ROUNDUP16 (finished_size + hash_size + 1) + 16 * client_pad_length;
      buffer.outoffset[1] =
	ROUNDUP16 (finished_size + hash_size + 1) + 16 * client_pad_length;

    }
  else if (clnt_fin_msg_out == RETURN_CFM_UNENCRYPTED)
    {

      buffer.rlen += (finished_size >> 3);

      buffer.outsize[1] = finished_size;
      buffer.outoffset[1] = finished_size;

    }

  buffer.outunit[1] = UNIT_8_BIT;

  if (master_secret_ret == RETURN_ENCRYPTED)
    {

      buffer.rlen += (48 >> 3);

      buffer.outcnt = 3;

      buffer.outptr[2] = CAST_TO_X_PTR( encrypt_master_secret);
      buffer.outsize[2] = 48;
      buffer.outoffset[2] = 48;
      buffer.outunit[2] = UNIT_8_BIT;

    }
  else if (master_secret_ret == NOT_RETURNED)

    buffer.outcnt = 2;
#endif
  buffer.req_type = request_type;
  buffer.req_queue = SSL_QUEUE;
  buffer.res_order = CAVIUM_RESPONSE_ORDERED;
  buffer.dma_mode = global_dma_mode;
  buffer.status = 0;

  cond_code =
#ifdef CAVIUM_MULTICARD_API
    ioctl (gpkpdev_hdlr[dev_id], IOCTL_N1_OPERATION_CODE, (ptrlong) & buffer);
#else
    ioctl (CSP1_driver_handle, IOCTL_N1_OPERATION_CODE, (ptrlong) & buffer);
#endif

  *request_id = buffer.request_id;

  if(cond_code)
     ret_val = cond_code; /*return error val*/
  else
     ret_val = buffer.status;/*return OPERATION STATUS: SUCCESS('0')/EAGAIN */


  return ret_val;
}



#ifndef MC2
/*+****************************************************************************
 *
 * Csp1RsaServerFullAesFinish
 *
 * Does a full handshake on the server. This entry point 
 * handles all the aes cases. The handshake data is accumulated prior to this 
 * request by calls to Handshake*, and this request appends the 
 * included handshake message data to the pre-existing handshake hash state.
 * The handshake message data for this request should include all handshake 
 * message data after (and including) the client hello message up until 
 * (but not including) the first finished message. 
 *
 * Input
 *		request_type = CAVIUM_BLOCKING or CAVIUM_NON_BLOCKING
 *		context_handle = 64-bit byte-pointer to context (context_handle%8=0)
 *		key_handle = pointer to 64-bit key memory handle
 *		hash_type = MD5_TYPE or SHA1_TYPE
 *		ssl_version = VER3_0 or VER_TLS
 *		aes_type = AES_128 or AES_256
 *		master_secret_ret = NOT_RETURNED or RETURN_ENCRYPTED
 *		clnt_fin_msg_out = RETURN_CFM_ENCRYPTED or RETURN_CFM_UNENCRYPTED
 *		srvr_fin_msg_out = RETURN_SFM_ENCRYPTED or RETURN_SFM_UNENCRYPTED
 *		client_pad_length = number of 128-bit words to pad above min
 *		server_pad_length = number of 128-bit words to pad above min
 *		modlength = size of RSA operation in bytes (64<=modlength<=256, modlength%8=0)
 *		encrypt_premaster_secret = pointer to modlength-byte value in integer format
 *		client_random = pointer to 32 bytes of random data
 *		server_random = pointer to 32 bytes of random data
 *		handshake_length = size in bytes of the handshake message data
 *		handshake = pointer to the handshake message data
 *
 * Output
 *		client_finished_message = pointer to encrypted part of client finished message 
 *		server_finished_message = pointer to encrypted part of server finished message 
 *		encrypt_master_secret = (master_secret_ret == RETURN_ENCRYPTED) ? pointer to
 *				returned encrypted master secret : don't care
 *		request_id = Unique ID for this request
 *
 * Return Value
 *		0  = success 
 *		>0 = failure or pending
 *		see error_codes.txt
 *
 *-***************************************************************************/
Uint32
Csp1RsaServerFullAesFinish (n1_request_type request_type,
			    Uint64 context_handle,
			    Uint64 * key_handle,
			    HashType hash_type,
			    SslVersion ssl_version,
			    AesType aes_type,
			    MasterSecretReturn master_secret_ret,
			    ClientFinishMessageOutput clnt_fin_msg_out,
			    ServerFinishMessageOutput srvr_fin_msg_out,
			    Uint16 client_pad_length,
			    Uint16 server_pad_length,
			    Uint16 modlength,
			    Uint8 * encrypt_premaster_secret,
			    Uint8 * client_random,
			    Uint8 * server_random,
			    Uint16 handshake_length,
			    Uint8 * handshake,
			    Uint8 * client_finished_message,
			    Uint8 * server_finished_message,
			    Uint8 * encrypt_master_secret,
#ifdef CAVIUM_MULTICARD_API
			    Uint32 * request_id, Uint32 dev_id
#else
			    Uint32 * request_id
#endif
                       )
{
  Csp1OperationBuffer buffer;
  Uint32 cond_code;
  Uint32 ret_val;
  Uint16 param = 0;
  Uint16 finished_size;
  Uint16 hash_size;

  memset(&buffer,0,sizeof(Csp1OperationBuffer));
  if ((context_handle & UINT64_C(0x8000000000000000)) != 0)
    {

      if ((context_handle & 0xf) != 0)

	return ERR_ILLEGAL_CONTEXT_HANDLE;

    }
  else
    {

      if ((context_handle & 0x7) != 0)

	return ERR_ILLEGAL_CONTEXT_HANDLE;

    }

  if ((modlength & 0x7) != 0)

    return ERR_ILLEGAL_INPUT_LENGTH;


  if ((modlength >= 64) && (modlength <= 128))
    {

      param = (modlength >> 3) - 1;
      buffer.opcode =
	(master_secret_ret << 15) | (0x9 << 11) | ((aes_type >> 1) << 10) |
	(ssl_version << 9) | (hash_type << 8) | (global_dma_mode << 7) |
	MAJOR_OP_RSASERVER;


    }
  else if ((modlength > 128) && (modlength <= 256))
    {

      param = (modlength >> 3) - 17;
      buffer.opcode =
	(master_secret_ret << 15) | (0x9 << 11) | ((aes_type >> 1) << 10) |
	(ssl_version << 9) | (hash_type << 8) | (global_dma_mode << 7) |
	MAJOR_OP_RSASERVER_LARGE;

#if defined(CSP1_API_DEBUG)
    }
  else
    {

      return ERR_ILLEGAL_INPUT_LENGTH;
#endif
    }

  param |= (server_pad_length << 11) | (client_pad_length << 6);

  if (clnt_fin_msg_out == RETURN_CFM_UNENCRYPTED)

    param |= 0x1f << 6;

  if (srvr_fin_msg_out == RETURN_SFM_UNENCRYPTED)

    param |= 0x1f << 11;

  hash_size = 20 - (hash_type << 2);
  finished_size = 16 + 24 * ssl_version;

  buffer.size = handshake_length;
  buffer.param = param;
  buffer.dlen = (8 + modlength + 32 + 32 + ROUNDUP8 (handshake_length)) >> 3;
  buffer.rlen = 8 >> 3;
  buffer.ctx_ptr = context_handle;
  buffer.group = CAVIUM_SSL_GRP;

  buffer.incnt = 5;

  buffer.inptr[0] = CAST_TO_X_PTR((Uint8 *) key_handle);
  buffer.insize[0] = 8;
  buffer.inoffset[0] = 8;
  buffer.inunit[0] = UNIT_64_BIT;
  buffer.inptr[1] = CAST_TO_X_PTR( encrypt_premaster_secret);
  buffer.insize[1] = modlength;
  buffer.inoffset[1] = modlength;
  buffer.inunit[1] = UNIT_8_BIT;
  buffer.inptr[2] = CAST_TO_X_PTR( client_random);
  buffer.insize[2] = 32;
  buffer.inoffset[2] = 32;
  buffer.inunit[2] = UNIT_8_BIT;
  buffer.inptr[3] = CAST_TO_X_PTR( server_random);
  buffer.insize[3] = 32;
  buffer.inoffset[3] = 32;
  buffer.inunit[3] = UNIT_8_BIT;
  buffer.inptr[4] = CAST_TO_X_PTR( handshake);
  buffer.insize[4] = handshake_length;
  buffer.inoffset[4] = ROUNDUP8 (handshake_length);
  buffer.inunit[4] = UNIT_8_BIT;

  buffer.outptr[0] = CAST_TO_X_PTR( server_finished_message);

  if (srvr_fin_msg_out == RETURN_SFM_ENCRYPTED)
    {

      buffer.rlen +=
	((ROUNDUP16 (finished_size + hash_size + 1) +
	  16 * server_pad_length) >> 3);

      buffer.outsize[0] =
	ROUNDUP16 (finished_size + hash_size + 1) + 16 * server_pad_length;
      buffer.outoffset[0] =
	ROUNDUP16 (finished_size + hash_size + 1) + 16 * server_pad_length;

    }
  else if (srvr_fin_msg_out == RETURN_SFM_UNENCRYPTED)
    {

      buffer.rlen += (finished_size >> 3);

      buffer.outsize[0] = finished_size;
      buffer.outoffset[0] = finished_size;

    }

  buffer.outunit[0] = UNIT_8_BIT;

  buffer.outptr[1] = CAST_TO_X_PTR( client_finished_message);

  if (clnt_fin_msg_out == RETURN_CFM_ENCRYPTED)
    {

      buffer.rlen +=
	((ROUNDUP16 (finished_size + hash_size + 1) +
	  16 * client_pad_length) >> 3);

      buffer.outsize[1] =
	ROUNDUP16 (finished_size + hash_size + 1) + 16 * client_pad_length;
      buffer.outoffset[1] =
	ROUNDUP16 (finished_size + hash_size + 1) + 16 * client_pad_length;

    }
  else if (clnt_fin_msg_out == RETURN_CFM_UNENCRYPTED)
    {

      buffer.rlen += (finished_size >> 3);

      buffer.outsize[1] = finished_size;
      buffer.outoffset[1] = finished_size;

    }

  buffer.outunit[1] = UNIT_8_BIT;

  if (master_secret_ret == RETURN_ENCRYPTED)
    {

      buffer.rlen += (48 >> 3);

      buffer.outcnt = 3;

      buffer.outptr[2] = CAST_TO_X_PTR( encrypt_master_secret);
      buffer.outsize[2] = 48;
      buffer.outoffset[2] = 48;
      buffer.outunit[2] = UNIT_8_BIT;

    }
  else if (master_secret_ret == NOT_RETURNED)

    buffer.outcnt = 2;

  buffer.req_type = request_type;
  buffer.req_queue = SSL_QUEUE;
  buffer.res_order = CAVIUM_RESPONSE_ORDERED;
  buffer.dma_mode = global_dma_mode;
  buffer.status = 0;

  cond_code =
#ifdef CAVIUM_MULTICARD_API
    ioctl (gpkpdev_hdlr[dev_id], IOCTL_N1_OPERATION_CODE, (ptrlong) & buffer);
#else
    ioctl (CSP1_driver_handle, IOCTL_N1_OPERATION_CODE, (ptrlong) & buffer);
#endif

  *request_id = buffer.request_id;

  if(cond_code)
     ret_val = cond_code; /*return error val*/
  else
     ret_val = buffer.status;/*return OPERATION STATUS: SUCCESS('0')/EAGAIN */

  return ret_val;
}
#endif /* if !MC2 */


/*+****************************************************************************
 *
 * Csp1RsaServerVerifyAes
 *
 * Do much of the full handshake - up to the point of the 
 * verify - in the case when client authentication is required. This is used in 
 * a full handshake on the server. This entry point handles all the AES cases.
 *
 * The handshake message data for this request should include all handshake 
 * message data after (and including) the client hello message up until (but 
 * not including) the client verify message. 
 *
 * Input
 *		request_type = CAVIUM_BLOCKING or CAVIUM_NON_BLOCKING
 *		context_handle = 64-bit byte-pointer to context (context_handle%8=0)
 *		key_handle = pointer to 64-bit key memory handle
 *		hash_type = MD5_TYPE or SHA1_TYPE
 *		ssl_version = VER3_0 or VER_TLS
 *		aes_type = AES_128 or AES_256
 *		master_secret_ret = NOT_RETURNED or RETURN_ENCRYPTED
 *		modlength = size of RSA operation in bytes (64<=modlength<=512, modlength%8=0)
 *	#ifdef MC2
 *		encrypt_premaster_secret = pointer to modlength-byte value.
 *	#else
 *		encrypt_premaster_secret = pointer to modlength-byte value in integer format
 *	#endif
 *		client_random = pointer to 32 bytes of random data
 *		server_random = pointer to 32 bytes of random data
 *		handshake_length = size in bytes of the handshake message data
 *		handshake = pointer to the handshake message data
 *
 * Output
 *		verify_data = pointer to 36 bytes of verify data 
 *		encrypt_master_secret = (master_secret_ret == RETURN_ENCRYPTED) ? pointer to
 *				returned encrypted master secret : don't care
 *		request_id = Unique ID for this request
 *
 * Return Value
 *		0  = success 
 *		>0 = failure or pending
 *		see error_codes.txt
 *
 *-***************************************************************************/
Uint32
Csp1RsaServerVerifyAes (n1_request_type request_type,
			Uint64 context_handle,
			Uint64 * key_handle,
			HashType hash_type,
			SslVersion ssl_version,
			AesType aes_type,
			MasterSecretReturn master_secret_ret,
			Uint16 modlength,
			Uint8 * encrypt_premaster_secret,
			Uint8 * client_random,
			Uint8 * server_random,
			Uint16 handshake_length,
			Uint8 * handshake,
			Uint8 * verify_data,
			Uint8 * encrypt_master_secret,
#ifdef CAVIUM_MULTICARD_API 
                        Uint32 * request_id, Uint32 dev_id
#else
                        Uint32 * request_id
#endif
                       )
{
  Csp1OperationBuffer buffer;
  Uint32 cond_code;
  Uint32 ret_val;
#ifndef MC2
  Uint16 param = 0;
#endif
  Uint16 hash_size;

  memset(&buffer,0,sizeof(Csp1OperationBuffer));
  if ((context_handle & UINT64_C(0x8000000000000000)) != 0)
    {

      if ((context_handle & 0xf) != 0)

	return ERR_ILLEGAL_CONTEXT_HANDLE;

    }
  else
    {

      if ((context_handle & 0x7) != 0)

	return ERR_ILLEGAL_CONTEXT_HANDLE;

    }

#ifndef MC2
  if ((modlength & 0x7) != 0)

    return ERR_ILLEGAL_INPUT_LENGTH;
#endif

  if ((modlength >= 64) && (modlength <= 128))
    {
#ifdef MC2
      buffer.opcode =
	(master_secret_ret << 14) | (global_dma_mode << 7) |
	MAJOR_OP_RSASERVER;
#else
      param = (modlength >> 3) - 1;
      buffer.opcode =
	(master_secret_ret << 15) | (0x5 << 11) | ((aes_type >> 1) << 10) |
	(ssl_version << 9) | (hash_type << 8) | (global_dma_mode << 7) |
	MAJOR_OP_RSASERVER;
#endif

    }
  else if ((modlength > 128) && (modlength <= 512))
    {
#ifdef MC2
      buffer.opcode =
	(master_secret_ret << 14) | (global_dma_mode << 7) |
	MAJOR_OP_RSASERVER_LARGE;
#else
      param = (modlength >> 3) - 17;
      buffer.opcode =
	(master_secret_ret << 15) | (0x5 << 11) | ((aes_type >> 1) << 10) |
	(ssl_version << 9) | (hash_type << 8) | (global_dma_mode << 7) |
	MAJOR_OP_RSASERVER_LARGE;
#endif

#if defined(CSP1_API_DEBUG)
    }
  else
    {

      return ERR_ILLEGAL_INPUT_LENGTH;
#endif
    }

#ifdef MC2
  hash_size = (hash_type == SHA1_TYPE) ? 20 : 16;
  buffer.size = modlength;
  buffer.param =
    (hash_type) | (ssl_version << 2) | (aes_type << 3) | (1 << 7);
  buffer.dlen = 8 + modlength + 32 + 32 + handshake_length;
#else
  hash_size = 20 - (hash_type << 2);
  buffer.size = handshake_length;
  buffer.param = param;
  buffer.dlen = (8 + modlength + 32 + 32 + ROUNDUP8 (handshake_length)) >> 3;
  buffer.rlen = (40 + 8) >> 3;
#endif
  buffer.ctx_ptr = context_handle;
  buffer.group = CAVIUM_SSL_GRP;

  buffer.incnt = 5;

  buffer.inptr[0] = CAST_TO_X_PTR((Uint8 *) key_handle);
  buffer.insize[0] = 8;
  buffer.inoffset[0] = 8;
  buffer.inunit[0] = UNIT_64_BIT;
  buffer.inptr[1] = CAST_TO_X_PTR( encrypt_premaster_secret);
  buffer.insize[1] = modlength;
  buffer.inoffset[1] = modlength;
  buffer.inunit[1] = UNIT_8_BIT;
  buffer.inptr[2] = CAST_TO_X_PTR( client_random);
  buffer.insize[2] = 32;
  buffer.inoffset[2] = 32;
  buffer.inunit[2] = UNIT_8_BIT;
  buffer.inptr[3] = CAST_TO_X_PTR( server_random);
  buffer.insize[3] = 32;
  buffer.inoffset[3] = 32;
  buffer.inunit[3] = UNIT_8_BIT;
  buffer.inptr[4] = CAST_TO_X_PTR( handshake);
  buffer.insize[4] = handshake_length;
#ifdef MC2
  buffer.inoffset[4] = handshake_length;
#else
  buffer.inoffset[4] = ROUNDUP8 (handshake_length);
#endif
  buffer.inunit[4] = UNIT_8_BIT;

#ifdef MC2
  if (master_secret_ret == RETURN_ENCRYPTED)
    {
      buffer.rlen = 48 + 36;
      buffer.outcnt = 2;

      buffer.outptr[0] = CAST_TO_X_PTR( encrypt_master_secret);
      buffer.outsize[0] = 48;
      buffer.outoffset[0] = 48;
      buffer.outunit[0] = UNIT_8_BIT;

      buffer.outptr[1] = CAST_TO_X_PTR( verify_data);
      buffer.outsize[1] = 36;
      buffer.outoffset[1] = 36;
      buffer.outunit[1] = UNIT_8_BIT;
    }
  else
    {
      buffer.rlen = 36;
      buffer.outcnt = 1;

      buffer.outptr[0] = CAST_TO_X_PTR( verify_data);
      buffer.outsize[0] = 36;
      buffer.outoffset[0] = 36;
      buffer.outunit[0] = UNIT_8_BIT;
    }

#else

  buffer.outptr[0] = CAST_TO_X_PTR( verify_data);
  buffer.outsize[0] = 36;
  buffer.outoffset[0] = 40;
  buffer.outunit[0] = UNIT_8_BIT;
  if (master_secret_ret == RETURN_ENCRYPTED)
    {

      buffer.rlen += (48 >> 3);

      buffer.outcnt = 2;

      buffer.outptr[1] = CAST_TO_X_PTR( encrypt_master_secret);
      buffer.outsize[1] = 48;
      buffer.outoffset[1] = 48;
      buffer.outunit[1] = UNIT_8_BIT;

    }
  else if (master_secret_ret == NOT_RETURNED)

    buffer.outcnt = 1;
#endif

  buffer.req_type = request_type;
  buffer.req_queue = SSL_QUEUE;
  buffer.res_order = CAVIUM_RESPONSE_ORDERED;
  buffer.dma_mode = global_dma_mode;
  buffer.status = 0;

  cond_code =
#ifdef CAVIUM_MULTICARD_API
    ioctl (gpkpdev_hdlr[dev_id], IOCTL_N1_OPERATION_CODE, (ptrlong) & buffer);
#else
    ioctl (CSP1_driver_handle, IOCTL_N1_OPERATION_CODE, (ptrlong) & buffer);
#endif

  *request_id = buffer.request_id;

  if(cond_code)
     ret_val = cond_code; /*return error val*/
  else
     ret_val = buffer.status;/*return OPERATION STATUS: SUCCESS('0')/EAGAIN */

  return ret_val;
}



#ifndef MC2
/*+****************************************************************************
 *
 * Csp1RsaServerVerifyAesFinish
 *
 * Do much of the full handshake - up to the point of the 
 * verify - in the case when client authentication is required. This is used in 
 * a full handshake on the server. This entry point handles all the AES cases.
 *
 * The handshake message data for this request should include all handshake 
 * message data after (and including) the client hello message up until (but 
 * not including) the client verify message. Handshake data can be accumulated 
 * prior to this request by calls to Handshake*, and this request will 
 * append the included handshake message data to the pre-existing handshake 
 * hash state.
 *
 * Input
 *	request_type = CAVIUM_BLOCKING or CAVIUM_NON_BLOCKING
 *	context_handle = 64-bit byte-pointer to context (context_handle%8=0)
 *	key_handle = pointer to 64-bit key memory handle
 *	hash_type = MD5_TYPE or SHA1_TYPE
 *	ssl_version = VER3_0 or VER_TLS
 *	aes_type = AES_128 or AES_256
 *	master_secret_ret = NOT_RETURNED or RETURN_ENCRYPTED
 *	modlength = size of RSA operation in bytes (64<=modlength<=256, modlength%8=0)
 *	encrypt_premaster_secret = pointer to modlength-byte value in integer format
 *	client_random = pointer to 32 bytes of random data
 *	server_random = pointer to 32 bytes of random data
 *	handshake_length = size in bytes of the handshake message data
 *	handshake = pointer to the handshake message data
 *
 * Output
 *	verify_data = pointer to 36 bytes of verify data 
 *	encrypt_master_secret = (master_secret_ret == RETURN_ENCRYPTED) ? pointer to
 *		returned encrypted master secret : don't care
 *	request_id = Unique ID for this request
 *
 * Return Value
 *	0  = success 
 * >0 = failure or pending
 * see error_codes.txt
 *
 *-***************************************************************************/
Uint32
Csp1RsaServerVerifyAesFinish (n1_request_type request_type,
			      Uint64 context_handle,
			      Uint64 * key_handle,
			      HashType hash_type,
			      SslVersion ssl_version,
			      AesType aes_type,
			      MasterSecretReturn master_secret_ret,
			      Uint16 modlength,
			      Uint8 * encrypt_premaster_secret,
			      Uint8 * client_random,
			      Uint8 * server_random,
			      Uint16 handshake_length,
			      Uint8 * handshake,
			      Uint8 * verify_data,
			      Uint8 * encrypt_master_secret,
#ifdef CAVIUM_MULTICARD_API
			      Uint32 * request_id, Uint32 dev_id
#else
			      Uint32 * request_id
#endif
                         )
{
  Csp1OperationBuffer buffer;
  Uint32 cond_code;
  Uint32 ret_val;
  Uint16 param = 0;
  Uint16 hash_size;

  memset(&buffer,0,sizeof(Csp1OperationBuffer));
  if ((context_handle & UINT64_C(0x8000000000000000)) != 0)
    {

      if ((context_handle & 0xf) != 0)

	return ERR_ILLEGAL_CONTEXT_HANDLE;

    }
  else
    {

      if ((context_handle & 0x7) != 0)

	return ERR_ILLEGAL_CONTEXT_HANDLE;

    }

  if ((modlength & 0x7) != 0)

    return ERR_ILLEGAL_INPUT_LENGTH;


  if ((modlength >= 64) && (modlength <= 128))
    {

      param = (modlength >> 3) - 1;
      buffer.opcode =
	(master_secret_ret << 15) | (0x1 << 11) | ((aes_type >> 1) << 10) |
	(ssl_version << 9) | (hash_type << 8) | (global_dma_mode << 7) |
	MAJOR_OP_RSASERVER;


    }
  else if ((modlength > 128) && (modlength <= 256))
    {

      param = (modlength >> 3) - 17;
      buffer.opcode =
	(master_secret_ret << 15) | (0x1 << 11) | ((aes_type >> 1) << 10) |
	(ssl_version << 9) | (hash_type << 8) | (global_dma_mode << 7) |
	MAJOR_OP_RSASERVER_LARGE;

#if defined(CSP1_API_DEBUG)
    }
  else
    {

      return ERR_ILLEGAL_INPUT_LENGTH;
#endif
    }

  hash_size = 20 - (hash_type << 2);

  buffer.size = handshake_length;
  buffer.param = param;
  buffer.dlen = (8 + modlength + 32 + 32 + ROUNDUP8 (handshake_length)) >> 3;
  buffer.rlen = (40 + 8) >> 3;
  buffer.ctx_ptr = context_handle;
  buffer.group = CAVIUM_SSL_GRP;

  buffer.incnt = 5;

  buffer.inptr[0] = CAST_TO_X_PTR((Uint8 *) key_handle);
  buffer.insize[0] = 8;
  buffer.inoffset[0] = 8;
  buffer.inunit[0] = UNIT_64_BIT;
  buffer.inptr[1] = CAST_TO_X_PTR( encrypt_premaster_secret);
  buffer.insize[1] = modlength;
  buffer.inoffset[1] = modlength;
  buffer.inunit[1] = UNIT_8_BIT;
  buffer.inptr[2] = CAST_TO_X_PTR( client_random);
  buffer.insize[2] = 32;
  buffer.inoffset[2] = 32;
  buffer.inunit[2] = UNIT_8_BIT;
  buffer.inptr[3] = CAST_TO_X_PTR( server_random);
  buffer.insize[3] = 32;
  buffer.inoffset[3] = 32;
  buffer.inunit[3] = UNIT_8_BIT;
  buffer.inptr[4] = CAST_TO_X_PTR( handshake);
  buffer.insize[4] = handshake_length;
  buffer.inoffset[4] = ROUNDUP8 (handshake_length);
  buffer.inunit[4] = UNIT_8_BIT;

  buffer.outptr[0] = CAST_TO_X_PTR( verify_data);
  buffer.outsize[0] = 36;
  buffer.outoffset[0] = 40;
  buffer.outunit[0] = UNIT_8_BIT;

  if (master_secret_ret == RETURN_ENCRYPTED)
    {

      buffer.rlen += (48 >> 3);

      buffer.outcnt = 2;

      buffer.outptr[1] = CAST_TO_X_PTR( encrypt_master_secret);
      buffer.outsize[1] = 48;
      buffer.outoffset[1] = 48;
      buffer.outunit[1] = UNIT_8_BIT;

    }
  else if (master_secret_ret == NOT_RETURNED)

    buffer.outcnt = 1;

  buffer.req_type = request_type;
  buffer.req_queue = SSL_QUEUE;
  buffer.res_order = CAVIUM_RESPONSE_ORDERED;
  buffer.dma_mode = global_dma_mode;
  buffer.status = 0;

  cond_code =
#ifdef CAVIUM_MULTICARD_API
    ioctl (gpkpdev_hdlr[dev_id], IOCTL_N1_OPERATION_CODE, (ptrlong) & buffer);
#else
    ioctl (CSP1_driver_handle, IOCTL_N1_OPERATION_CODE, (ptrlong) & buffer);
#endif

  *request_id = buffer.request_id;

  if(cond_code)
     ret_val = cond_code; /*return error val*/
  else
     ret_val = buffer.status;/*return OPERATION STATUS: SUCCESS('0')/EAGAIN */

  return ret_val;
}
#endif /* if !MC2 */


/*+****************************************************************************
 *
 * Csp1OtherFullRc4
 *
 * Do a full handshake without RSA operation. The pre-master secret is read
 * from the context and the rest of the handshake is completed. This is used
 * by both the server and the client. This entry point handles all the RC4
 * cases.
 *
 * The handshake message data for this request should include all handshake 
 * message data after (and including) the client hello message up until (but 
 * not including) the first finished message. 
 *
 * Input
 *	request_type = CAVIUM_BLOCKING or CAVIUM_NON_BLOCKING
 *	context_handle = 64-bit pointer to context (context_handle%8=0)
 *	hash_type = MD5_TYPE or SHA1_TYPE
 *	ssl_version = VER3_0 or VER_TLS
 *	rc4_type = RC4_128, RC4_EXPORT_40, or RC4_EXPORT_56
 *	master_secret_ret = NOT_RETURNED or RETURN_ENCRYPTED
 *	pre_master_length = size of premaster secret in bytes 
 *		(SSLv3: 4<=modlength<=256, modlength%4=0; 
 *		 TLS: 16<=modlength<=128, modlength%16=0)
 *	client_random = pointer to 32 bytes of random data
 *	server_random = pointer to 32 bytes of random data
 *	handshake_length = size in bytes of the handshake message data
 *	handshake = pointer to the handshake message data
 *
 * Output
 *	client_finished_message = pointer to encrypted part of client finished message 
 *	server_finished_message = pointer to encrypted part of server finished message 
 *	encrypt_master_secret = (master_secret_ret == RETURN_ENCRYPTED) ? pointer to
 *		returned encrypted master secret : don't care
 *	request_id = Unique ID for this request
 *
 * Return Value
 *	0  = success 
 * >0 = failure or pending
 * see error_codes.txt
 *
 *-***************************************************************************/
Uint32
Csp1OtherFullRc4 (n1_request_type request_type,
		  Uint64 context_handle,
		  HashType hash_type,
		  SslVersion ssl_version,
		  Rc4Type rc4_type,
		  MasterSecretReturn master_secret_ret,
		  Uint16 pre_master_length,
		  Uint8 * client_random,
		  Uint8 * server_random,
		  Uint16 handshake_length,
		  Uint8 * handshake,
		  Uint8 * client_finished_message,
		  Uint8 * server_finished_message,
		  Uint8 * encrypt_master_secret,
#ifdef CAVIUM_MULTICARD_API
                  Uint32 * request_id, Uint32 dev_id
#else
                  Uint32 * request_id
#endif
                 )
{
  Csp1OperationBuffer buffer;
  Uint32 cond_code;
  Uint32 ret_val;
  Uint16 param;
  Uint16 finished_size;
  Uint16 hash_size;

  memset(&buffer,0,sizeof(Csp1OperationBuffer));
  if ((context_handle & UINT64_C(0x8000000000000000)) != 0)
    {

      if ((context_handle & 0xf) != 0)

	return ERR_ILLEGAL_CONTEXT_HANDLE;

    }
  else
    {

      if ((context_handle & 0x7) != 0)

	return ERR_ILLEGAL_CONTEXT_HANDLE;

    }

  if ((ssl_version == VER3_0)
      && (((pre_master_length & 0x3) != 0) || (pre_master_length > 256)))

    return ERR_ILLEGAL_INPUT_LENGTH;

  if ((ssl_version == VER_TLS)
      && (((pre_master_length & 0xf) != 0) || (pre_master_length > 128)))

    return ERR_ILLEGAL_INPUT_LENGTH;

  finished_size = 16 + 24 * ssl_version;

#ifdef MC2
  param = (hash_type) | (ssl_version << 2) | (rc4_type << 3) | (1 << 7);

  buffer.opcode = (master_secret_ret << 14) | (0x1 << 13) | (global_dma_mode << 7) |
       MAJOR_OP_OTHER;
  buffer.size = pre_master_length;

  hash_size = (hash_type == SHA1_TYPE)? 20:16;

  buffer.dlen = 32 + 32 + handshake_length;
  buffer.rlen = 2 * (finished_size + hash_size);
   
#else
  param = (pre_master_length >> 2) - 1;

  buffer.opcode = (master_secret_ret << 15) | (0x3 << 13) | (rc4_type << 10)
    | (ssl_version << 9) | (hash_type << 8) | (global_dma_mode << 7) |
    MAJOR_OP_OTHER;

  buffer.size = handshake_length;

  hash_size = 20 - (hash_type << 2);

  buffer.dlen = (32 + 32 + ROUNDUP8 (handshake_length))>>3;

  buffer.rlen = (ROUNDUP8 (finished_size + hash_size)
		 + ROUNDUP8 (finished_size + hash_size) + 8) >> 3;
#endif

  buffer.param = param;
  
  buffer.ctx_ptr = context_handle;
  buffer.group = CAVIUM_SSL_GRP;

  buffer.incnt = 3;

  buffer.inptr[0] = CAST_TO_X_PTR( client_random);
  buffer.insize[0] = 32;
  buffer.inoffset[0] = 32;
  buffer.inunit[0] = UNIT_8_BIT;
  buffer.inptr[1] = CAST_TO_X_PTR( server_random);
  buffer.insize[1] = 32;
  buffer.inoffset[1] = 32;
  buffer.inunit[1] = UNIT_8_BIT;
  buffer.inptr[2] = CAST_TO_X_PTR( handshake);
  buffer.insize[2] = handshake_length;
#ifdef MC2
  buffer.inoffset[2] = handshake_length;
#else
  buffer.inoffset[2] = ROUNDUP8 (handshake_length);
#endif
  buffer.inunit[2] = UNIT_8_BIT;

#ifndef MC2
  buffer.outptr[0] = CAST_TO_X_PTR( server_finished_message);
  buffer.outsize[0] = finished_size + hash_size;
  buffer.outoffset[0] = ROUNDUP8 (finished_size + hash_size);
  buffer.outunit[0] = UNIT_8_BIT;
  buffer.outptr[1] = CAST_TO_X_PTR( client_finished_message);
  buffer.outsize[1] = finished_size + hash_size;
  buffer.outoffset[1] = ROUNDUP8 (finished_size + hash_size);
  buffer.outunit[1] = UNIT_8_BIT;

  if (master_secret_ret == RETURN_ENCRYPTED)
    {

      buffer.rlen += (48 >> 3);

      buffer.outcnt = 3;

      buffer.outptr[2] = CAST_TO_X_PTR( encrypt_master_secret);
      buffer.outsize[2] = 48;
      buffer.outoffset[2] = 48;
      buffer.outunit[2] = UNIT_8_BIT;

    }
  else if (master_secret_ret == NOT_RETURNED)

    buffer.outcnt = 2;
#else
  if (master_secret_ret == RETURN_ENCRYPTED)
    {
      buffer.rlen += 48;
      buffer.outcnt = 3;

      buffer.outptr[0] = CAST_TO_X_PTR( encrypt_master_secret);
      buffer.outsize[0] = 48;
      buffer.outoffset[0] = 48;
      buffer.outunit[0] = UNIT_8_BIT;

      buffer.outptr[1] = CAST_TO_X_PTR( client_finished_message);
      buffer.outsize[1] = finished_size + hash_size;
      buffer.outoffset[1] = finished_size + hash_size;
      buffer.outunit[1] = UNIT_8_BIT;
      buffer.outptr[2] = CAST_TO_X_PTR( server_finished_message);
      buffer.outsize[2] = finished_size + hash_size;
      buffer.outoffset[2] = finished_size + hash_size;
      buffer.outunit[2] = UNIT_8_BIT;
    }
  else
    {
      buffer.outcnt = 2;
      buffer.outptr[0] = CAST_TO_X_PTR( client_finished_message);
      buffer.outsize[0] = finished_size + hash_size;
      buffer.outoffset[0] = finished_size + hash_size;
      buffer.outunit[0] = UNIT_8_BIT;
      buffer.outptr[1] = CAST_TO_X_PTR( server_finished_message);
      buffer.outsize[1] = finished_size + hash_size;
      buffer.outoffset[1] = finished_size + hash_size;
      buffer.outunit[1] = UNIT_8_BIT;
    }
#endif

  buffer.req_type = request_type;
  buffer.req_queue = SSL_QUEUE;
  buffer.res_order = CAVIUM_RESPONSE_ORDERED;
  buffer.dma_mode = global_dma_mode;
  buffer.status = 0;

  cond_code =
#ifdef CAVIUM_MULTICARD_API
    ioctl (gpkpdev_hdlr[dev_id], IOCTL_N1_OPERATION_CODE, (ptrlong) & buffer);
#else
    ioctl (CSP1_driver_handle, IOCTL_N1_OPERATION_CODE, (ptrlong) & buffer);
#endif

  *request_id = buffer.request_id;

  if(cond_code)
     ret_val = cond_code; /*return error val*/
  else
     ret_val = buffer.status;/*return OPERATION STATUS: SUCCESS('0')/EAGAIN */

  return ret_val;
}



#ifndef MC2
/*+****************************************************************************
 *
 * Csp1OtherFullRc4Finish
 *
 * Do a full handshake without RSA operation. The pre-master secret is read
 * from the context and the rest of the handshake is completed. This is used
 * by both the server and the client. This entry point handles all the rc4
 * cases.
 *
 * The handshake message data for this request should include all handshake 
 * message data after (and including) the client hello message up until (but 
 * not including) the first finished message. Handshake data can be accumulated 
 * prior to this request by calls to Handshake*, and this request will 
 * append the included handshake message data to the pre-existing handshake 
 * hash state.
 *
 * Input
 *	request_type = CAVIUM_BLOCKING or CAVIUM_NON_BLOCKING
 *	context_handle = 64-bit pointer to context (context_handle%8=0)
 *	hash_type = MD5_TYPE or SHA1_TYPE
 *	ssl_version = VER3_0 or VER_TLS
 *	rc4_type = RC4_128, RC4_EXPORT_40, or RC4_EXPORT_56
 *	master_secret_ret = NOT_RETURNED or RETURN_ENCRYPTED
 *	pre_master_length = size of premaster secret in bytes 
 *		(SSLv3: 4<=modlength<=256, modlength%4=0; 
 *		 TLS: 16<=modlength<=128, modlength%16=0)
 *	client_random = pointer to 32 bytes of random data
 *	server_random = pointer to 32 bytes of random data
 *	handshake_length = size in bytes of the handshake message data
 *	handshake = pointer to the handshake message data
 *
 * Output
 *	client_finished_message = pointer to encrypted part of client finished message 
 *	server_finished_message = pointer to encrypted part of server finished message 
 *	encrypt_master_secret = (master_secret_ret == RETURN_ENCRYPTED) ? pointer to
 *		returned encrypted master secret : don't care
 *	request_id = Unique ID for this request
 *
 * Return Value
 *	0  = success 
 * >0 = failure or pending
 * see error_codes.txt
 *
 *-***************************************************************************/
Uint32
Csp1OtherFullRc4Finish (n1_request_type request_type,
			Uint64 context_handle,
			HashType hash_type,
			SslVersion ssl_version,
			Rc4Type rc4_type,
			MasterSecretReturn master_secret_ret,
			Uint16 pre_master_length,
			Uint8 * client_random,
			Uint8 * server_random,
			Uint16 handshake_length,
			Uint8 * handshake,
			Uint8 * client_finished_message,
			Uint8 * server_finished_message,
			Uint8 * encrypt_master_secret, 
#ifdef CAVIUM_MULTICARD_API
                        Uint32 * request_id,Uint32 dev_id
#else
                        Uint32 * request_id
#endif
                       )
{
  Csp1OperationBuffer buffer;
  Uint32 cond_code;
  Uint32 ret_val;
  Uint16 param;
  Uint16 finished_size;
  Uint16 hash_size;

  memset(&buffer,0,sizeof(Csp1OperationBuffer));
#if defined(CSP1_API_DEBUG)
  if ((context_handle & UINT64_C(0x8000000000000000)) != 0)
    {

      if ((context_handle & 0xf) != 0)

	return ERR_ILLEGAL_CONTEXT_HANDLE;

    }
  else
    {

      if ((context_handle & 0x7) != 0)

	return ERR_ILLEGAL_CONTEXT_HANDLE;

    }

  if ((ssl_version == VER3_0)
      && (((pre_master_length & 0x3) != 0) || (pre_master_length > 256)))

    return ERR_ILLEGAL_INPUT_LENGTH;

  if ((ssl_version == VER_TLS)
      && (((pre_master_length & 0xf) != 0) || (pre_master_length > 128)))

    return ERR_ILLEGAL_INPUT_LENGTH;
#endif

  param = (pre_master_length >> 2) - 1;

  buffer.opcode = (master_secret_ret << 15) | (0x2 << 13) | (rc4_type << 10)
    | (ssl_version << 9) | (hash_type << 8) | (global_dma_mode << 7) |
    MAJOR_OP_OTHER;
  hash_size = 20 - (hash_type << 2);
  finished_size = 16 + 24 * ssl_version;

  buffer.size = handshake_length;
  buffer.param = param;
  buffer.dlen = (32 + 32 + ROUNDUP8 (handshake_length)) >> 3;
  buffer.rlen = (ROUNDUP8 (finished_size + hash_size)
		 + ROUNDUP8 (finished_size + hash_size) + 8) >> 3;
  buffer.ctx_ptr = context_handle;
  buffer.group = CAVIUM_SSL_GRP;

  buffer.incnt = 3;

  buffer.inptr[0] = CAST_TO_X_PTR( client_random);
  buffer.insize[0] = 32;
  buffer.inoffset[0] = 32;
  buffer.inunit[0] = UNIT_8_BIT;
  buffer.inptr[1] = CAST_TO_X_PTR( server_random);
  buffer.insize[1] = 32;
  buffer.inoffset[1] = 32;
  buffer.inunit[1] = UNIT_8_BIT;
  buffer.inptr[2] = CAST_TO_X_PTR( handshake);
  buffer.insize[2] = handshake_length;
  buffer.inoffset[2] = ROUNDUP8 (handshake_length);
  buffer.inunit[2] = UNIT_8_BIT;

  buffer.outptr[0] = CAST_TO_X_PTR( server_finished_message);
  buffer.outsize[0] = finished_size + hash_size;
  buffer.outoffset[0] = ROUNDUP8 (finished_size + hash_size);
  buffer.outunit[0] = UNIT_8_BIT;
  buffer.outptr[1] = CAST_TO_X_PTR( client_finished_message);
  buffer.outsize[1] = finished_size + hash_size;
  buffer.outoffset[1] = ROUNDUP8 (finished_size + hash_size);
  buffer.outunit[1] = UNIT_8_BIT;

  if (master_secret_ret == RETURN_ENCRYPTED)
    {

      buffer.rlen += (48 >> 3);

      buffer.outcnt = 3;

      buffer.outptr[2] = CAST_TO_X_PTR( encrypt_master_secret);
      buffer.outsize[2] = 48;
      buffer.outoffset[2] = 48;
      buffer.outunit[2] = UNIT_8_BIT;

    }
  else if (master_secret_ret == NOT_RETURNED)

    buffer.outcnt = 2;

  buffer.req_type = request_type;
  buffer.req_queue = SSL_QUEUE;
  buffer.res_order = CAVIUM_RESPONSE_ORDERED;
  buffer.dma_mode = global_dma_mode;
   buffer.status = 0; 

  cond_code =
#ifdef CAVIUM_MULTICARD_API
    ioctl (gpkpdev_hdlr[dev_id], IOCTL_N1_OPERATION_CODE, (ptrlong) & buffer);
#else
    ioctl (CSP1_driver_handle, IOCTL_N1_OPERATION_CODE, (ptrlong) & buffer);
#endif

  *request_id = buffer.request_id;

  if(cond_code)
     ret_val = cond_code; /*return error val*/
  else
     ret_val = buffer.status;/*return OPERATION STATUS: SUCCESS('0')/EAGAIN */

  return ret_val;
}
#endif /* if !MC2 */


/*+****************************************************************************
 *
 * Csp1OtherVerifyRc4
 *
 * Do a full handshake - up to the point of the
 * verify operation. The pre-master secret is read from the context.
 * This is used by both the server and the client. This entry point
 * handles all the RC4 cases.
 *
 * The handshake message data for this request should include all handshake 
 * message data after (and including) the client hello message up until (but 
 * not including) the client verify message. 
 *
 * Input
 *	request_type = CAVIUM_BLOCKING or CAVIUM_NON_BLOCKING
 *	context_handle = 64-bit pointer to context (context_handle%8=0)
 *	hash_type = MD5_TYPE or SHA1_TYPE
 *	ssl_version = VER3_0 or VER_TLS
 *	rc4_type = RC4_128, RC4_EXPORT_40, or RC4_EXPORT_56
 *	master_secret_ret = NOT_RETURNED or RETURN_ENCRYPTED
 *	pre_master_length = size of premaster secret in bytes 
 *		(SSLv3: 4<=modlength<=256, modlength%4=0; 
 *		 TLS: 16<=modlength<=128, modlength%16=0)
 *	client_random = pointer to 32 bytes of random data
 *	server_random = pointer to 32 bytes of random data
 *	handshake_length = size in bytes of the handshake message data
 *	handshake = pointer to the handshake message data
 *
 * Output
 *	verify_data = pointer to 36 bytes of verify data 
 *	encrypt_master_secret = (master_secret_ret == RETURN_ENCRYPTED) ? pointer to
 *		returned encrypted master secret : don't care
 *	request_id = Unique ID for this request
 *
 * Return Value
 *	0  = success 
 * >0 = failure or pending
 * see error_codes.txt
 *
 *-***************************************************************************/
Uint32
Csp1OtherVerifyRc4 (n1_request_type request_type,
		    Uint64 context_handle,
		    HashType hash_type,
		    SslVersion ssl_version,
		    Rc4Type rc4_type,
		    MasterSecretReturn master_secret_ret,
		    Uint16 pre_master_length,
		    Uint8 * client_random,
		    Uint8 * server_random,
		    Uint16 handshake_length,
		    Uint8 * handshake,
		    Uint8 * verify_data,
		    Uint8 * encrypt_master_secret, 
#ifdef CAVIUM_MULTICARD_API
                    Uint32 * request_id,Uint32 dev_id
#else
                    Uint32 * request_id
#endif
                   )
{
  Csp1OperationBuffer buffer;
  Uint32 cond_code;
  Uint32 ret_val;
  Uint16 param;
  Uint16 hash_size;

  memset(&buffer,0,sizeof(Csp1OperationBuffer));
  if ((context_handle & UINT64_C(0x8000000000000000)) != 0)
    {

      if ((context_handle & 0xf) != 0)

	return ERR_ILLEGAL_CONTEXT_HANDLE;

    }
  else
    {

      if ((context_handle & 0x7) != 0)

	return ERR_ILLEGAL_CONTEXT_HANDLE;

    }

  if ((ssl_version == VER3_0)
      && (((pre_master_length & 0x3) != 0) || (pre_master_length > 256)))

    return ERR_ILLEGAL_INPUT_LENGTH;

  if ((ssl_version == VER_TLS)
      && (((pre_master_length & 0xf) != 0) || (pre_master_length > 128)))

    return ERR_ILLEGAL_INPUT_LENGTH;


#ifdef MC2
  param = (hash_type) | (ssl_version << 2) | (rc4_type << 3) | (1 << 7);

  buffer.opcode = (master_secret_ret << 14) | (global_dma_mode << 7) |
       MAJOR_OP_OTHER;
  buffer.size = pre_master_length;

  hash_size = (hash_type == SHA1_TYPE)? 20:16;

  buffer.dlen = 32 + 32 + handshake_length;
  buffer.rlen = 36;

#else
  param = (pre_master_length >> 2) - 1;

  buffer.opcode = (master_secret_ret << 15) | (0x1 << 13) | (rc4_type << 10)
    | (ssl_version << 9) | (hash_type << 8) | (global_dma_mode << 7) |
    MAJOR_OP_OTHER;
  hash_size = 20 - (hash_type << 2);

  buffer.size = handshake_length;
  buffer.dlen = (32 + 32 + ROUNDUP8 (handshake_length)) >> 3;
  buffer.rlen = (40 + 8) >> 3;
#endif
  buffer.param = param;
  buffer.ctx_ptr = context_handle;
  buffer.group = CAVIUM_SSL_GRP;

  buffer.incnt = 3;

  buffer.inptr[0] = CAST_TO_X_PTR( client_random);
  buffer.insize[0] = 32;
  buffer.inoffset[0] = 32;
  buffer.inunit[0] = UNIT_8_BIT;
  buffer.inptr[1] = CAST_TO_X_PTR( server_random);
  buffer.insize[1] = 32;
  buffer.inoffset[1] = 32;
  buffer.inunit[1] = UNIT_8_BIT;
  buffer.inptr[2] = CAST_TO_X_PTR( handshake);
  buffer.insize[2] = handshake_length;
#ifdef MC2
  buffer.inoffset[2] = handshake_length;
#else
  buffer.inoffset[2] = ROUNDUP8 (handshake_length);
#endif
  buffer.inunit[2] = UNIT_8_BIT;

#ifndef MC2
  buffer.outptr[0] = CAST_TO_X_PTR( verify_data);
  buffer.outsize[0] = 36;
  buffer.outoffset[0] = 40;
  buffer.outunit[0] = UNIT_8_BIT;

  if (master_secret_ret == RETURN_ENCRYPTED)
    {

      buffer.rlen += (48 >> 3);

      buffer.outcnt = 2;

      buffer.outptr[1] = CAST_TO_X_PTR( encrypt_master_secret);
      buffer.outsize[1] = 48;
      buffer.outoffset[1] = 48;
      buffer.outunit[1] = UNIT_8_BIT;

    }
  else if (master_secret_ret == NOT_RETURNED)

    buffer.outcnt = 1;

#else
  if (master_secret_ret == RETURN_ENCRYPTED)
    {
      buffer.rlen += 48;
      buffer.outcnt = 2;

      buffer.outptr[0] = CAST_TO_X_PTR( encrypt_master_secret);
      buffer.outsize[0] = 48;
      buffer.outoffset[0] = 48;
      buffer.outunit[0] = UNIT_8_BIT;

      buffer.outptr[1] = CAST_TO_X_PTR( verify_data);
      buffer.outsize[1] = 36;
      buffer.outoffset[1] = 36;
      buffer.outunit[1] = UNIT_8_BIT;
    }
  else
    {
      buffer.outcnt = 1;
      buffer.outptr[0] = CAST_TO_X_PTR( verify_data);
      buffer.outsize[0] = 36;
      buffer.outoffset[0] = 36;
      buffer.outunit[0] = UNIT_8_BIT;
    }

#endif


  buffer.req_type = request_type;
  buffer.req_queue = SSL_QUEUE;
  buffer.res_order = CAVIUM_RESPONSE_ORDERED;
  buffer.dma_mode = global_dma_mode;
  buffer.status = 0;

  cond_code =
#ifdef CAVIUM_MULTICARD_API
    ioctl (gpkpdev_hdlr[dev_id], IOCTL_N1_OPERATION_CODE, (ptrlong) & buffer);
#else
    ioctl (CSP1_driver_handle, IOCTL_N1_OPERATION_CODE, (ptrlong) & buffer);
#endif

  *request_id = buffer.request_id;
  
  if(cond_code)
     ret_val = cond_code; /*return error val*/
  else
     ret_val = buffer.status;/*return OPERATION STATUS: SUCCESS('0')/EAGAIN */

  return ret_val;
}


#ifndef MC2
/*+****************************************************************************
 *
 * Csp1OtherVerifyRc4Finish
 *
 * Do a full handshake - up to the point of the
 * verify operation. The pre-master secret is read from the context.
 * This is used by both the server and the client. This entry point
 * handles all the rc4 cases.
 *
 * The handshake message data for this request should include all handshake message
 * data after (and including) the client hello message up until (but not
 * including) the client verify message. Handshake data can be accumulated prior 
 * to this request by calls to Handshake*, and this request will append 
 * the included handshake message data to the pre-existing handshake hash state.
 *
 * Input
 *	request_type = CAVIUM_BLOCKING or CAVIUM_NON_BLOCKING
 *	context_handle = 64-bit pointer to context (context_handle%8=0)
 *	hash_type = MD5_TYPE or SHA1_TYPE
 *	ssl_version = VER3_0 or VER_TLS
 *	rc4_type = RC4_128, RC4_EXPORT_40, or RC4_EXPORT_56
 *	master_secret_ret = NOT_RETURNED or RETURN_ENCRYPTED
 *	pre_master_length = size of premaster secret in bytes 
 *		(SSLv3: 4<=modlength<=256, modlength%4=0; 
 *		 TLS: 16<=modlength<=128, modlength%16=0)
 *	client_random = pointer to 32 bytes of random data
 *	server_random = pointer to 32 bytes of random data
 *	handshake_length = size in bytes of the handshake message data
 *	handshake = pointer to the handshake message data
 *
 * Output
 *	verify_data = pointer to 36 bytes of verify data 
 *	encrypt_master_secret = (master_secret_ret == RETURN_ENCRYPTED) ? pointer to
 *		returned encrypted master secret : don't care
 *	request_id = Unique ID for this request
 *
 * Return Value
 *	0  = success 
 * >0 = failure or pending
 * see error_codes.txt
 *
 *-***************************************************************************/
Uint32
Csp1OtherVerifyRc4Finish (n1_request_type request_type,
			  Uint64 context_handle,
			  HashType hash_type,
			  SslVersion ssl_version,
			  Rc4Type rc4_type,
			  MasterSecretReturn master_secret_ret,
			  Uint16 pre_master_length,
			  Uint8 * client_random,
			  Uint8 * server_random,
			  Uint16 handshake_length,
			  Uint8 * handshake,
			  Uint8 * verify_data,
			  Uint8 * encrypt_master_secret, 
#ifdef CAVIUM_MULTICARD_API
                          Uint32 * request_id,Uint32 dev_id
#else
                          Uint32 * request_id
#endif
                        )
{
  Csp1OperationBuffer buffer;
  Uint32 cond_code;
  Uint32 ret_val;
  Uint16 param;
  Uint16 hash_size;

  memset(&buffer,0,sizeof(Csp1OperationBuffer));
  if ((context_handle & UINT64_C(0x8000000000000000)) != 0)
    {

      if ((context_handle & 0xf) != 0)

	return ERR_ILLEGAL_CONTEXT_HANDLE;

    }
  else
    {

      if ((context_handle & 0x7) != 0)

	return ERR_ILLEGAL_CONTEXT_HANDLE;

    }

  if ((ssl_version == VER3_0)
      && (((pre_master_length & 0x3) != 0) || (pre_master_length > 256)))

    return ERR_ILLEGAL_INPUT_LENGTH;

  if ((ssl_version == VER_TLS)
      && (((pre_master_length & 0xf) != 0) || (pre_master_length > 128)))

    return ERR_ILLEGAL_INPUT_LENGTH;


  param = (pre_master_length >> 2) - 1;

#ifdef MC2
  buffer.opcode = (global_dma_mode << 7) | MAJOR_OP_FINISHED;
  hash_size = (hash_type == SHA1_TYPE) ? 20 : 16;

  buffer.size = 0;
  buffer.param = (hash_type) | (ssl_version << 2) | (RC4_128 << 3);
  buffer.dlen = handshake_length;
  buffer.rlen = 2 * (finished_size + hash_size);
#else

  buffer.opcode = (master_secret_ret << 15) | (0x0 << 13) | (rc4_type << 10)
    | (ssl_version << 9) | (hash_type << 8) | (global_dma_mode << 7) |
    MAJOR_OP_OTHER;
  hash_size = 20 - (hash_type << 2);

  buffer.size = handshake_length;
  buffer.param = param;
  buffer.dlen = (32 + 32 + ROUNDUP8 (handshake_length)) >> 3;
  buffer.rlen = (40 + 8) >> 3;
#endif
  buffer.ctx_ptr = context_handle;
  buffer.group = CAVIUM_SSL_GRP;

  buffer.incnt = 3;

  buffer.inptr[0] = CAST_TO_X_PTR( client_random);
  buffer.insize[0] = 32;
  buffer.inoffset[0] = 32;
  buffer.inunit[0] = UNIT_8_BIT;
  buffer.inptr[1] = CAST_TO_X_PTR( server_random);
  buffer.insize[1] = 32;
  buffer.inoffset[1] = 32;
  buffer.inunit[1] = UNIT_8_BIT;
  buffer.inptr[2] = CAST_TO_X_PTR( handshake);
  buffer.insize[2] = handshake_length;
  buffer.inoffset[2] = ROUNDUP8 (handshake_length);
  buffer.inunit[2] = UNIT_8_BIT;

#ifdef MC2
  buffer.inoffset[0] = handshake_length;
#endif

#ifdef MC2
  buffer.outptr[0] = CAST_TO_X_PTR( client_finished_message);
  buffer.outsize[0] = finished_size + hash_size;
  buffer.outoffset[0] = finished_size + hash_size;
  buffer.outunit[0] = UNIT_8_BIT;
  buffer.outptr[1] = CAST_TO_X_PTR( server_finished_message);
  buffer.outsize[1] = finished_size + hash_size;
  buffer.outoffset[1] = finished_size + hash_size;
  buffer.outunit[1] = UNIT_8_BIT;
#else
  buffer.outptr[0] = CAST_TO_X_PTR( verify_data);
  buffer.outsize[0] = 36;
  buffer.outoffset[0] = 40;
  buffer.outunit[0] = UNIT_8_BIT;

#endif


  if (master_secret_ret == RETURN_ENCRYPTED)
    {

      buffer.rlen += (48 >> 3);

      buffer.outcnt = 2;

      buffer.outptr[1] = CAST_TO_X_PTR( encrypt_master_secret);
      buffer.outsize[1] = 48;
      buffer.outoffset[1] = 48;
      buffer.outunit[1] = UNIT_8_BIT;

    }
  else if (master_secret_ret == NOT_RETURNED)

    buffer.outcnt = 1;

  buffer.req_type = request_type;
  buffer.req_queue = SSL_QUEUE;
  buffer.res_order = CAVIUM_RESPONSE_ORDERED;
  buffer.dma_mode = global_dma_mode;
  buffer.status = 0;

  cond_code =
#ifdef CAVIUM_MULTICARD_API
    ioctl (gpkpdev_hdlr[dev_id], IOCTL_N1_OPERATION_CODE, (ptrlong) & buffer);
#else
    ioctl (CSP1_driver_handle, IOCTL_N1_OPERATION_CODE, (ptrlong) & buffer);
#endif

  *request_id = buffer.request_id;

  if(cond_code)
     ret_val = cond_code; /*return error val*/
  else
     ret_val = buffer.status;/*return OPERATION STATUS: SUCCESS('0')/EAGAIN */

  return ret_val;
}
#endif /* if !MC2 */


/*+****************************************************************************
 *
 * Csp1OtherFull3Des
 *
 * Do a full handshake. The pre-master secret is read
 * from the context and the rest of the handshake is completed. This is used
 * by both the server and the client. This entry point handles all the DES/
 * 3DES cases.
 *
 * The handshake message data for this request should include all handshake 
 * message data after (and including) the client hello message up until (but 
 * not including) the first finished message. 
 *
 * Input
 *	request_type = CAVIUM_BLOCKING or CAVIUM_NON_BLOCKING
 *	context_handle = 64-bit pointer to context (context_handle%8=0)
 *	hash_type = MD5_TYPE or SHA1_TYPE
 *	ssl_version = VER3_0 or VER_TLS
 *	des_type = DES, DES_EXPORT_40 or DES3_192
 *	master_secret_ret = NOT_RETURNED or RETURN_ENCRYPTED
 *	clnt_fin_msg_out = RETURN_CFM_ENCRYPTED or RETURN_CFM_UNENCRYPTED
 *	srvr_fin_msg_out = RETURN_SFM_ENCRYPTED or RETURN_SFM_UNENCRYPTED
 *	client_pad_length = number of 64-bit words to pad above min
 *	server_pad_length = number of 64-bit words to pad above min
 *	pre_master_length = size of premaster secret in bytes 
 *		(SSLv3: 4<=modlength<=256, modlength%4=0; 
 *		 TLS: 16<=modlength<=128, modlength%16=0)
 *	client_random = pointer to 32 bytes of random data
 *	server_random = pointer to 32 bytes of random data
 *	handshake_length = size in bytes of the handshake message data
 *	handshake = pointer to the handshake message data
 *
 * Output
 *	client_finished_message = pointer to encrypted part of client finished message 
 *	server_finished_message = pointer to encrypted part of server finished message 
 *	encrypt_master_secret = (master_secret_ret == RETURN_ENCRYPTED) ? pointer to
 *		returned encrypted master secret : don't care
 *	request_id = Unique ID for this request
 *
 * Return Value
 *	0  = success 
 * >0 = failure or pending
 * see error_codes.txt
 *
 *-***************************************************************************/
Uint32
Csp1OtherFull3Des (n1_request_type request_type,
		   Uint64 context_handle,
		   HashType hash_type,
		   SslVersion ssl_version,
		   DesType des_type,
		   MasterSecretReturn master_secret_ret,
		   ClientFinishMessageOutput clnt_fin_msg_out,
		   ServerFinishMessageOutput srvr_fin_msg_out,
		   Uint16 client_pad_length,
		   Uint16 server_pad_length,
		   Uint16 pre_master_length,
		   Uint8 * client_random,
		   Uint8 * server_random,
		   Uint16 handshake_length,
		   Uint8 * handshake,
		   Uint8 * client_finished_message,
		   Uint8 * server_finished_message,
		   Uint8 * encrypt_master_secret, 
#ifdef CAVIUM_MULTICARD_API
                   Uint32 * request_id,Uint32 dev_id
#else
                   Uint32 * request_id
#endif
                  )
{
  Csp1OperationBuffer buffer;
  Uint32 cond_code;
  Uint32 ret_val;
  Uint16 param;
  Uint16 finished_size;
  Uint16 hash_size;

  memset(&buffer,0,sizeof(Csp1OperationBuffer));
  if ((context_handle & UINT64_C(0x8000000000000000)) != 0)
    {

      if ((context_handle & 0xf) != 0)

	return ERR_ILLEGAL_CONTEXT_HANDLE;

    }
  else
    {

      if ((context_handle & 0x7) != 0)

	return ERR_ILLEGAL_CONTEXT_HANDLE;

    }

  if ((ssl_version == VER3_0)
      && (((pre_master_length & 0x3) != 0) || (pre_master_length > 256)))

    return ERR_ILLEGAL_INPUT_LENGTH;

  if ((ssl_version == VER_TLS)
      && (((pre_master_length & 0xf) != 0) || (pre_master_length > 128)))

    return ERR_ILLEGAL_INPUT_LENGTH;


  finished_size = 16 + 24 * ssl_version;

#ifdef MC2
  param = (hash_type) | (ssl_version << 2) | (des_type << 3) | (1 << 7);

  if (clnt_fin_msg_out == RETURN_CFM_UNENCRYPTED)
    param |= (1 << 8);

  if (srvr_fin_msg_out == RETURN_SFM_UNENCRYPTED)
    param |= (1 << 9);

  buffer.opcode = (master_secret_ret << 14) | (0x1 << 13) | (global_dma_mode << 7) |
       MAJOR_OP_OTHER;
  buffer.size = pre_master_length;

  hash_size = (hash_type == SHA1_TYPE)? 20:16;

  buffer.dlen = 32 + 32 + handshake_length;

  buffer.rlen = 0;

#else
  param = (pre_master_length >> 2) - 1;

  param |= (server_pad_length << 11) | (client_pad_length << 6);

  if (clnt_fin_msg_out == RETURN_CFM_UNENCRYPTED)

    param |= 0x1f << 6;

  if (srvr_fin_msg_out == RETURN_SFM_UNENCRYPTED)

    param |= 0x1f << 11;

  buffer.opcode = (master_secret_ret << 15) | (0x7 << 12) | (des_type << 10)
    | (ssl_version << 9) | (hash_type << 8) | (global_dma_mode << 7) |
    MAJOR_OP_OTHER;
  hash_size = 20 - (hash_type << 2);
  
  buffer.dlen = (32 + 32 + ROUNDUP8 (handshake_length)) >> 3;
  
  buffer.rlen = 8 >> 3;

  buffer.size = handshake_length;
#endif

  buffer.param = param;
  
  buffer.ctx_ptr = context_handle;
  buffer.group = CAVIUM_SSL_GRP;

  buffer.incnt = 3;

  buffer.inptr[0] = CAST_TO_X_PTR( client_random);
  buffer.insize[0] = 32;
  buffer.inoffset[0] = 32;
  buffer.inunit[0] = UNIT_8_BIT;
  buffer.inptr[1] = CAST_TO_X_PTR( server_random);
  buffer.insize[1] = 32;
  buffer.inoffset[1] = 32;
  buffer.inunit[1] = UNIT_8_BIT;
  buffer.inptr[2] = CAST_TO_X_PTR( handshake);
  buffer.insize[2] = handshake_length;
#ifdef MC2
  buffer.inoffset[2] = handshake_length;
#else
  buffer.inoffset[2] = ROUNDUP8 (handshake_length);
#endif
  buffer.inunit[2] = UNIT_8_BIT;

#ifdef MC2
  if (master_secret_ret == RETURN_ENCRYPTED)
  {
      buffer.rlen = 48;

      buffer.outcnt = 3;

      buffer.outptr[0] = CAST_TO_X_PTR( encrypt_master_secret);
      buffer.outsize[0] = 48;
      buffer.outoffset[0] = 48;
      buffer.outunit[0] = UNIT_8_BIT;

      buffer.outptr[1] = CAST_TO_X_PTR( client_finished_message);

      if (clnt_fin_msg_out == RETURN_CFM_ENCRYPTED)
      {
         buffer.rlen += ROUNDUP8 (finished_size + hash_size + 1);

         buffer.outsize[1] = ROUNDUP8 (finished_size + hash_size + 1);
         buffer.outoffset[1] = ROUNDUP8 (finished_size + hash_size + 1);

      }
      else if (clnt_fin_msg_out == RETURN_CFM_UNENCRYPTED)
      {
         buffer.rlen += finished_size;

         buffer.outsize[1] = finished_size;
         buffer.outoffset[1] = finished_size;
      }

      buffer.outunit[1] = UNIT_8_BIT;

      buffer.outptr[2] = CAST_TO_X_PTR( server_finished_message);

      if (srvr_fin_msg_out == RETURN_SFM_ENCRYPTED)
      {
         buffer.rlen += ROUNDUP8 (finished_size + hash_size + 1);

         buffer.outsize[2] = ROUNDUP8 (finished_size + hash_size + 1);
         buffer.outoffset[2] = ROUNDUP8 (finished_size + hash_size + 1);
      }

      else if (srvr_fin_msg_out == RETURN_SFM_UNENCRYPTED)
      {
         buffer.rlen += finished_size;

         buffer.outsize[2] = finished_size;
         buffer.outoffset[2] = finished_size;
      }

      buffer.outunit[2] = UNIT_8_BIT;

    }
  else if (master_secret_ret == NOT_RETURNED)
    {
      buffer.outcnt = 2;
      buffer.outptr[0] = CAST_TO_X_PTR( client_finished_message);

      if (clnt_fin_msg_out == RETURN_CFM_ENCRYPTED)
      {
         buffer.rlen += ROUNDUP8 (finished_size + hash_size + 1);

         buffer.outsize[0] = ROUNDUP8 (finished_size + hash_size + 1);
         buffer.outoffset[0] = ROUNDUP8 (finished_size + hash_size + 1);
      }
      else if (clnt_fin_msg_out == RETURN_CFM_UNENCRYPTED)
      {
         buffer.rlen += finished_size;

         buffer.outsize[0] = finished_size;
         buffer.outoffset[0] = finished_size;
      }

      buffer.outunit[0] = UNIT_8_BIT;

      buffer.outptr[1] = CAST_TO_X_PTR( server_finished_message);

      if (srvr_fin_msg_out == RETURN_SFM_ENCRYPTED)
      {
         buffer.rlen += ROUNDUP8 (finished_size + hash_size + 1);

         buffer.outsize[1] = ROUNDUP8 (finished_size + hash_size + 1);
         buffer.outoffset[1] = ROUNDUP8 (finished_size + hash_size + 1);
      }
      else if (srvr_fin_msg_out == RETURN_SFM_UNENCRYPTED)
      {
         buffer.rlen += finished_size;

         buffer.outsize[1] = finished_size;
         buffer.outoffset[1] = finished_size;
      }

      buffer.outunit[1] = UNIT_8_BIT;
    }
#else
  buffer.outptr[0] = CAST_TO_X_PTR( server_finished_message);

  if (srvr_fin_msg_out == RETURN_SFM_ENCRYPTED)
    {

      buffer.rlen +=
	((ROUNDUP8 (finished_size + hash_size + 1) +
	  8 * server_pad_length) >> 3);

      buffer.outsize[0] =
	ROUNDUP8 (finished_size + hash_size + 1) + 8 * server_pad_length;
      buffer.outoffset[0] =
	ROUNDUP8 (finished_size + hash_size + 1) + 8 * server_pad_length;

    }
  else if (srvr_fin_msg_out == RETURN_SFM_UNENCRYPTED)
    {

      buffer.rlen += (finished_size >> 3);

      buffer.outsize[0] = finished_size;
      buffer.outoffset[0] = finished_size;

    }

  buffer.outunit[0] = UNIT_8_BIT;

  buffer.outptr[1] = CAST_TO_X_PTR( client_finished_message);

  if (clnt_fin_msg_out == RETURN_CFM_ENCRYPTED)
    {

      buffer.rlen +=
	((ROUNDUP8 (finished_size + hash_size + 1) +
	  8 * client_pad_length) >> 3);

      buffer.outsize[1] =
	ROUNDUP8 (finished_size + hash_size + 1) + 8 * client_pad_length;
      buffer.outoffset[1] =
	ROUNDUP8 (finished_size + hash_size + 1) + 8 * client_pad_length;

    }
  else if (clnt_fin_msg_out == RETURN_CFM_UNENCRYPTED)
    {

      buffer.rlen += (finished_size >> 3);

      buffer.outsize[1] = finished_size;
      buffer.outoffset[1] = finished_size;

    }

  buffer.outunit[1] = UNIT_8_BIT;

  if (master_secret_ret == RETURN_ENCRYPTED)
    {

      buffer.rlen += (48 >> 3);

      buffer.outcnt = 3;

      buffer.outptr[2] = CAST_TO_X_PTR( encrypt_master_secret);
      buffer.outsize[2] = 48;
      buffer.outoffset[2] = 48;
      buffer.outunit[2] = UNIT_8_BIT;

    }
  else if (master_secret_ret == NOT_RETURNED)

    buffer.outcnt = 2;

#endif /* MC2 */

  buffer.req_type = request_type;
  buffer.req_queue = SSL_QUEUE;
  buffer.res_order = CAVIUM_RESPONSE_ORDERED;
  buffer.dma_mode = global_dma_mode;
  buffer.status = 0;

  cond_code =
#ifdef CAVIUM_MULTICARD_API
    ioctl (gpkpdev_hdlr[dev_id], IOCTL_N1_OPERATION_CODE, (ptrlong) & buffer);
#else
    ioctl (CSP1_driver_handle, IOCTL_N1_OPERATION_CODE, (ptrlong) & buffer);
#endif

  *request_id = buffer.request_id;

  if(cond_code)
     ret_val = cond_code; /*return error val*/
  else
     ret_val = buffer.status;/*return OPERATION STATUS: SUCCESS('0')/EAGAIN */

  return ret_val;
}

#ifndef MC2
/*+****************************************************************************
 *
 * Csp1OtherFull3DesFinish
 *
 * Do a full handshake. The pre-master secret is read
 * from the context and the rest of the handshake is completed. This is used
 * by both the server and the client. This entry point handles all the DES/
 * 3DES cases.
 *
 * The handshake message data for this request should include all handshake 
 * message data after (and including) the client hello message up until (but 
 * not including) the first finished message. Handshake data can be accumulated 
 * prior to this request by calls to Handshake*, and this request will 
 * append the included handshake message data to the pre-existing handshake 
 * hash state.
 *
 * Input
 *	request_type = CAVIUM_BLOCKING or CAVIUM_NON_BLOCKING
 *	context_handle = 64-bit pointer to context (context_handle%8=0)
 *	hash_type = MD5_TYPE or SHA1_TYPE
 *	ssl_version = VER3_0 or VER_TLS
 *	des_type = DES, DES_EXPORT_40 or DES3_192
 *	master_secret_ret = NOT_RETURNED or RETURN_ENCRYPTED
 *	clnt_fin_msg_out = RETURN_CFM_ENCRYPTED or RETURN_CFM_UNENCRYPTED
 *	srvr_fin_msg_out = RETURN_SFM_ENCRYPTED or RETURN_SFM_UNENCRYPTED
 *	client_pad_length = number of 64-bit words to pad above min
 *	server_pad_length = number of 64-bit words to pad above min
 *	pre_master_length = size of premaster secret in bytes 
 *		(SSLv3: 4<=modlength<=256, modlength%4=0; 
 *		 TLS: 16<=modlength<=128, modlength%16=0)
 *	client_random = pointer to 32 bytes of random data
 *	server_random = pointer to 32 bytes of random data
 *	handshake_length = size in bytes of the handshake message data
 *	handshake = pointer to the handshake message data
 *
 * Output
 *	client_finished_message = pointer to encrypted part of client finished message 
 *	server_finished_message = pointer to encrypted part of server finished message 
 *	encrypt_master_secret = (master_secret_ret == RETURN_ENCRYPTED) ? pointer to
 *		returned encrypted master secret : don't care
 *	request_id = Unique ID for this request
 *
 * Return Value
 *	0  = success 
 * >0 = failure or pending
 * see error_codes.txt
 *
 *-***************************************************************************/
Uint32
Csp1OtherFull3DesFinish (n1_request_type request_type,
			 Uint64 context_handle,
			 HashType hash_type,
			 SslVersion ssl_version,
			 DesType des_type,
			 MasterSecretReturn master_secret_ret,
			 ClientFinishMessageOutput clnt_fin_msg_out,
			 ServerFinishMessageOutput srvr_fin_msg_out,
			 Uint16 client_pad_length,
			 Uint16 server_pad_length,
			 Uint16 pre_master_length,
			 Uint8 * client_random,
			 Uint8 * server_random,
			 Uint16 handshake_length,
			 Uint8 * handshake,
			 Uint8 * client_finished_message,
			 Uint8 * server_finished_message,
			 Uint8 * encrypt_master_secret, 
#ifdef CAVIUM_MULTICARD_API
                         Uint32 * request_id,Uint32 dev_id
#else
                         Uint32 * request_id
#endif
                      )
{
  Csp1OperationBuffer buffer;
  Uint32 cond_code;
  Uint32 ret_val;
  Uint16 param;
  Uint16 finished_size;
  Uint16 hash_size;
  memset(&buffer,0,sizeof(Csp1OperationBuffer));

  if ((context_handle & UINT64_C(0x8000000000000000)) != 0)
    {

      if ((context_handle & 0xf) != 0)

	return ERR_ILLEGAL_CONTEXT_HANDLE;

    }
  else
    {

      if ((context_handle & 0x7) != 0)

	return ERR_ILLEGAL_CONTEXT_HANDLE;

    }

  if ((ssl_version == VER3_0)
      && (((pre_master_length & 0x3) != 0) || (pre_master_length > 256)))

    return ERR_ILLEGAL_INPUT_LENGTH;

  if ((ssl_version == VER_TLS)
      && (((pre_master_length & 0xf) != 0) || (pre_master_length > 128)))

    return ERR_ILLEGAL_INPUT_LENGTH;

#ifdef MC2
  buffer.opcode = (global_dma_mode << 7) | MAJOR_OP_FINISHED;
  hash_size = (hash_type == SHA1_TYPE) ? 20 : 16;

  buffer.size = 0;
  buffer.param = (hash_type) | (ssl_version << 2) | (DES << 3);

  if (clnt_fin_msg_out == RETURN_CFM_UNENCRYPTED)
    buffer.param |= (Uint16) (1 << 8);

  if (srvr_fin_msg_out == RETURN_SFM_UNENCRYPTED)
    buffer.param |= (Uint16) (1 << 9);

  buffer.dlen = handshake_length;
  buffer.rlen = 0;

#else

  param = (pre_master_length >> 2) - 1;

  param |= (server_pad_length << 11) | (client_pad_length << 6);

  if (clnt_fin_msg_out == RETURN_CFM_UNENCRYPTED)

    param |= 0x1f << 6;

  if (srvr_fin_msg_out == RETURN_SFM_UNENCRYPTED)

    param |= 0x1f << 11;

  buffer.opcode = (master_secret_ret << 15) | (0x5 << 12) | (des_type << 10)
    | (ssl_version << 9) | (hash_type << 8) | (global_dma_mode << 7) |
    MAJOR_OP_OTHER;
  hash_size = 20 - (hash_type << 2);
  finished_size = 16 + 24 * ssl_version;

  buffer.size = handshake_length;
  buffer.param = param;
  buffer.dlen = (32 + 32 + ROUNDUP8 (handshake_length)) >> 3;
  buffer.rlen = 8 >> 3;
#endif
  buffer.ctx_ptr = context_handle;
  buffer.group = CAVIUM_SSL_GRP;

  buffer.incnt = 3;

  buffer.inptr[0] = CAST_TO_X_PTR( client_random);
  buffer.insize[0] = 32;
  buffer.inoffset[0] = 32;
  buffer.inunit[0] = UNIT_8_BIT;
  buffer.inptr[1] = CAST_TO_X_PTR( server_random);
  buffer.insize[1] = 32;
  buffer.inoffset[1] = 32;
  buffer.inunit[1] = UNIT_8_BIT;
  buffer.inptr[2] = CAST_TO_X_PTR( handshake);
  buffer.insize[2] = handshake_length;
  buffer.inoffset[2] = ROUNDUP8 (handshake_length);
  buffer.inunit[2] = UNIT_8_BIT;

#ifdef MC2
  buffer.inoffset[0] = handshake_length;
#endif
  buffer.outptr[0] = CAST_TO_X_PTR( server_finished_message);

#ifdef MC2

  buffer.outptr[0] =CAST_TO_X_PTR( client_finished_message);

  if (clnt_fin_msg_out == RETURN_CFM_ENCRYPTED)
    {
      buffer.rlen = ROUNDUP8 (finished_size + hash_size + 1);
      buffer.outsize[0] = ROUNDUP8 (finished_size + hash_size + 1);
      buffer.outoffset[0] = ROUNDUP8 (finished_size + hash_size + 1);

    }
  else if (clnt_fin_msg_out == RETURN_CFM_UNENCRYPTED)
    {
      buffer.rlen = finished_size;
      buffer.outsize[0] = finished_size;
      buffer.outoffset[0] = finished_size;
    }
  buffer.outunit[0] = UNIT_8_BIT;

  buffer.outptr[1] = CAST_TO_X_PTR( server_finished_message);

  if (srvr_fin_msg_out == RETURN_SFM_ENCRYPTED)
    {
      buffer.rlen += ROUNDUP8 (finished_size + hash_size + 1);
      buffer.outsize[1] = ROUNDUP8 (finished_size + hash_size + 1);
      buffer.outoffset[1] = ROUNDUP8 (finished_size + hash_size + 1);

    }
  else if (srvr_fin_msg_out == RETURN_SFM_UNENCRYPTED)
    {
      buffer.rlen += finished_size;
      buffer.outsize[1] = finished_size;
      buffer.outoffset[1] = finished_size;
    }
  buffer.outunit[1] = UNIT_8_BIT;

#else
  if (srvr_fin_msg_out == RETURN_SFM_ENCRYPTED)
    {

      buffer.rlen +=
	((ROUNDUP8 (finished_size + hash_size + 1) +
	  8 * server_pad_length) >> 3);

      buffer.outsize[0] =
	ROUNDUP8 (finished_size + hash_size + 1) + 8 * server_pad_length;
      buffer.outoffset[0] =
	ROUNDUP8 (finished_size + hash_size + 1) + 8 * server_pad_length;

    }
  else if (srvr_fin_msg_out == RETURN_SFM_UNENCRYPTED)
    {

      buffer.rlen += (finished_size >> 3);

      buffer.outsize[0] = finished_size;
      buffer.outoffset[0] = finished_size;

    }

  buffer.outunit[0] = UNIT_8_BIT;

  buffer.outptr[1] = CAST_TO_X_PTR( client_finished_message);

  if (clnt_fin_msg_out == RETURN_CFM_ENCRYPTED)
    {

      buffer.rlen +=
	((ROUNDUP8 (finished_size + hash_size + 1) +
	  8 * client_pad_length) >> 3);

      buffer.outsize[1] =
	ROUNDUP8 (finished_size + hash_size + 1) + 8 * client_pad_length;
      buffer.outoffset[1] =
	ROUNDUP8 (finished_size + hash_size + 1) + 8 * client_pad_length;

    }
  else if (clnt_fin_msg_out == RETURN_CFM_UNENCRYPTED)
    {

      buffer.rlen += (finished_size >> 3);

      buffer.outsize[1] = finished_size;
      buffer.outoffset[1] = finished_size;

    }

  buffer.outunit[1] = UNIT_8_BIT;

  if (master_secret_ret == RETURN_ENCRYPTED)
    {

      buffer.rlen += (48 >> 3);

      buffer.outcnt = 3;

      buffer.outptr[2] = CAST_TO_X_PTR( encrypt_master_secret);
      buffer.outsize[2] = 48;
      buffer.outoffset[2] = 48;
      buffer.outunit[2] = UNIT_8_BIT;

    }
  else if (master_secret_ret == NOT_RETURNED)

    buffer.outcnt = 2;
#endif
  buffer.req_type = request_type;
  buffer.req_queue = SSL_QUEUE;
  buffer.res_order = CAVIUM_RESPONSE_ORDERED;
  buffer.dma_mode = global_dma_mode;
  buffer.status = 0;

  cond_code =
#ifdef CAVIUM_MULTICARD_API
    ioctl (gpkpdev_hdlr[dev_id], IOCTL_N1_OPERATION_CODE, (ptrlong) & buffer);
#else
    ioctl (CSP1_driver_handle, IOCTL_N1_OPERATION_CODE, (ptrlong) & buffer);
#endif

  *request_id = buffer.request_id;

  if(cond_code)
     ret_val = cond_code; /*return error val*/
  else
     ret_val = buffer.status;/*return OPERATION STATUS: SUCCESS('0')/EAGAIN */

  return ret_val;
}
#endif /* if ! MC2 */


/*+****************************************************************************
 *
 * Csp1OtherVerify3Des
 *
 * do a full handshake - up to the point of the
 * verify operation. The pre-master secret is read from the context.
 * This is used by both the server and the client. This entry point handles all 
 * the DES/3DES cases.
 *
 * The handshake message data for this request should include all handshake 
 * message data after (and including) the client hello message up until (but 
 * not including) the client verify message. 
 *
 * Input
 *	request_type = CAVIUM_BLOCKING or CAVIUM_NON_BLOCKING
 *	context_handle = 64-bit pointer to context (context_handle%8=0)
 *	hash_type = MD5_TYPE or SHA1_TYPE
 *	ssl_version = VER3_0 or VER_TLS
 *	des_type = DES, DES_EXPORT_40, DES3_192
 *	master_secret_ret = NOT_RETURNED or RETURN_ENCRYPTED
 *	pre_master_length = size of premaster secret in bytes 
 *		(SSLv3: 4<=modlength<=256, modlength%4=0; 
 *		 TLS: 16<=modlength<=128, modlength%16=0)
 *	client_random = pointer to 32 bytes of random data
 *	server_random = pointer to 32 bytes of random data
 *	handshake_length = size in bytes of the handshake message data
 *	handshake = pointer to the handshake message data
 *
 * Output
 *	verify_data = pointer to 36 bytes of verify data 
 *	encrypt_master_secret = (master_secret_ret == RETURN_ENCRYPTED) ? pointer to
 *		returned encrypted master secret : don't care
 *	request_id = Unique ID for this request
 *
 * Return Value
 *	0  = success 
 * >0 = failure or pending
 * see error_codes.txt
 *
 *-***************************************************************************/
Uint32
Csp1OtherVerify3Des (n1_request_type request_type,
		     Uint64 context_handle,
		     HashType hash_type,
		     SslVersion ssl_version,
		     DesType des_type,
		     MasterSecretReturn master_secret_ret,
		     Uint16 pre_master_length,
		     Uint8 * client_random,
		     Uint8 * server_random,
		     Uint16 handshake_length,
		     Uint8 * handshake,
		     Uint8 * verify_data,
		     Uint8 * encrypt_master_secret,
#ifdef CAVIUM_MULTICARD_API 
                     Uint32 * request_id,Uint32 dev_id
#else
                     Uint32 * request_id
#endif
                   )
{
  Csp1OperationBuffer buffer;
  Uint32 cond_code;
  Uint32 ret_val;
  Uint16 param;
  Uint16 hash_size;

  memset(&buffer,0,sizeof(Csp1OperationBuffer));
  if ((context_handle & UINT64_C(0x8000000000000000)) != 0)
    {

      if ((context_handle & 0xf) != 0)

	return ERR_ILLEGAL_CONTEXT_HANDLE;

    }
  else
    {

      if ((context_handle & 0x7) != 0)

	return ERR_ILLEGAL_CONTEXT_HANDLE;

    }

  if ((ssl_version == VER3_0)
      && (((pre_master_length & 0x3) != 0) || (pre_master_length > 256)))

    return ERR_ILLEGAL_INPUT_LENGTH;

  if ((ssl_version == VER_TLS)
      && (((pre_master_length & 0xf) != 0) || (pre_master_length > 128)))

    return ERR_ILLEGAL_INPUT_LENGTH;

#ifdef MC2
  param = (hash_type) | (ssl_version << 2) | (des_type << 3) | (1 << 7);

  buffer.opcode = (master_secret_ret << 14) | (global_dma_mode << 7) |
       MAJOR_OP_OTHER;

  buffer.size = pre_master_length;

  hash_size = (hash_type == SHA1_TYPE)? 20:16;

  buffer.dlen = 32 + 32 + handshake_length;

  buffer.rlen = 36;

#else

  param = (pre_master_length >> 2) - 1;

  buffer.opcode = (master_secret_ret << 15) | (0x3 << 12) | (des_type << 10)
    | (ssl_version << 9) | (hash_type << 8) | (global_dma_mode << 7) |
    MAJOR_OP_OTHER;
  hash_size = 20 - (hash_type << 2);

  buffer.size = handshake_length;
  buffer.dlen = (32 + 32 + ROUNDUP8 (handshake_length)) >> 3;
  buffer.rlen = (40 + 8) >> 3;
#endif

  buffer.param = param;

  buffer.ctx_ptr = context_handle;
  buffer.group = CAVIUM_SSL_GRP;

  buffer.incnt = 3;

  buffer.inptr[0] = CAST_TO_X_PTR( client_random);
  buffer.insize[0] = 32;
  buffer.inoffset[0] = 32;
  buffer.inunit[0] = UNIT_8_BIT;
  buffer.inptr[1] = CAST_TO_X_PTR( server_random);
  buffer.insize[1] = 32;
  buffer.inoffset[1] = 32;
  buffer.inunit[1] = UNIT_8_BIT;
  buffer.inptr[2] = CAST_TO_X_PTR( handshake);
  buffer.insize[2] = handshake_length;
#ifdef MC2
  buffer.inoffset[2] = handshake_length;
#else
  buffer.inoffset[2] = ROUNDUP8 (handshake_length);
#endif
  buffer.inunit[2] = UNIT_8_BIT;

#ifndef MC2

  buffer.outptr[0] = CAST_TO_X_PTR( verify_data);
  buffer.outsize[0] = 36;
  buffer.outoffset[0] = 40;
  buffer.outunit[0] = UNIT_8_BIT;

  if (master_secret_ret == RETURN_ENCRYPTED)
    {

      buffer.rlen += (48 >> 3);

      buffer.outcnt = 2;

      buffer.outptr[1] = CAST_TO_X_PTR( encrypt_master_secret);
      buffer.outsize[1] = 48;
      buffer.outoffset[1] = 48;
      buffer.outunit[1] = UNIT_8_BIT;

    }
  else if (master_secret_ret == NOT_RETURNED)

    buffer.outcnt = 1;

#else
  if (master_secret_ret == RETURN_ENCRYPTED)
    {
      buffer.rlen += 48;
      buffer.outcnt = 2;

      buffer.outptr[0] = CAST_TO_X_PTR( encrypt_master_secret);
      buffer.outsize[0] = 48;
      buffer.outoffset[0] = 48;
      buffer.outunit[0] = UNIT_8_BIT;

      buffer.outptr[1] = CAST_TO_X_PTR( verify_data);
      buffer.outsize[1] = 36;
      buffer.outoffset[1] = 36;
      buffer.outunit[1] = UNIT_8_BIT;
    }
  else
    {
      buffer.outcnt = 1;
      buffer.outptr[0] = CAST_TO_X_PTR( verify_data);
      buffer.outsize[0] = 36;
      buffer.outoffset[0] = 36;
      buffer.outunit[0] = UNIT_8_BIT;
    }
#endif

  buffer.req_type = request_type;
  buffer.req_queue = SSL_QUEUE;
  buffer.res_order = CAVIUM_RESPONSE_ORDERED;
  buffer.dma_mode = global_dma_mode;
  buffer.status = 0;

  cond_code =
#ifdef CAVIUM_MULTICARD_API
    ioctl (gpkpdev_hdlr[dev_id], IOCTL_N1_OPERATION_CODE, (ptrlong) & buffer);
#else
    ioctl (CSP1_driver_handle, IOCTL_N1_OPERATION_CODE, (ptrlong) & buffer);
#endif


  *request_id = buffer.request_id;

  if(cond_code)
     ret_val = cond_code; /*return error val*/
  else
     ret_val = buffer.status;/*return OPERATION STATUS: SUCCESS('0')/EAGAIN */

  return ret_val;
}

#ifndef MC2
/*+****************************************************************************
 *
 * Csp1OtherVerify3DesFinish
 *
 * do a full handshake - up to the point of the
 * verify operation. The pre-master secret is read from the context.
 * This is used by both the server and the client. This entry point handles all 
 * the DES/3DES cases.
 *
 * The handshake message data for this request should include all handshake 
 * message data after (and including) the client hello message up until (but 
 * not including) the client verify message. Handshake data can be accumulated 
 * prior to this request by calls to Handshake*, and this request will 
 * append the included handshake message data to the pre-existing handshake 
 * hash state.
 *
 * Input
 *	request_type = CAVIUM_BLOCKING or CAVIUM_NON_BLOCKING
 *	context_handle = 64-bit pointer to context (context_handle%8=0)
 *	hash_type = MD5_TYPE or SHA1_TYPE
 *	ssl_version = VER3_0 or VER_TLS
 *	des_type = DES, DES_EXPORT_40 or DES3_192
 *	master_secret_ret = NOT_RETURNED or RETURN_ENCRYPTED
 *	pre_master_length = size of premaster secret in bytes 
 *		(SSLv3: 4<=modlength<=256, modlength%4=0; 
 *		 TLS: 16<=modlength<=128, modlength%16=0)
 *	client_random = pointer to 32 bytes of random data
 *	server_random = pointer to 32 bytes of random data
 *	handshake_length = size in bytes of the handshake message data
 *	handshake = pointer to the handshake message data
 *
 * Output
 *	verify_data = pointer to 36 bytes of verify data 
 *	encrypt_master_secret = (master_secret_ret == RETURN_ENCRYPTED) ? pointer to
 *		returned encrypted master secret : don't care
 *	request_id = Unique ID for this request
 *
 * Return Value
 *	0  = success 
 * >0 = failure or pending
 * see error_codes.txt
 *
 *-***************************************************************************/
Uint32
Csp1OtherVerify3DesFinish (n1_request_type request_type,
			   Uint64 context_handle,
			   HashType hash_type,
			   SslVersion ssl_version,
			   DesType des_type,
			   MasterSecretReturn master_secret_ret,
			   Uint16 pre_master_length,
			   Uint8 * client_random,
			   Uint8 * server_random,
			   Uint16 handshake_length,
			   Uint8 * handshake,
			   Uint8 * verify_data,
			   Uint8 * encrypt_master_secret,
#ifdef CAVIUM_MULTICARD_API
                           Uint32 * request_id,Uint32 dev_id
#else
                           Uint32 * request_id
#endif
                   )
{
  Csp1OperationBuffer buffer;
  Uint32 cond_code;
  Uint32 ret_val;
  Uint16 param;
  Uint16 hash_size;

  memset(&buffer,0,sizeof(Csp1OperationBuffer));
  if ((context_handle & UINT64_C(0x8000000000000000)) != 0)
    {

      if ((context_handle & 0xf) != 0)

	return ERR_ILLEGAL_CONTEXT_HANDLE;

    }
  else
    {

      if ((context_handle & 0x7) != 0)

	return ERR_ILLEGAL_CONTEXT_HANDLE;

    }

  if ((ssl_version == VER3_0)
      && (((pre_master_length & 0x3) != 0) || (pre_master_length > 256)))

    return ERR_ILLEGAL_INPUT_LENGTH;

  if ((ssl_version == VER_TLS)
      && (((pre_master_length & 0xf) != 0) || (pre_master_length > 128)))

    return ERR_ILLEGAL_INPUT_LENGTH;

  param = (pre_master_length >> 2) - 1;

  buffer.opcode = (master_secret_ret << 15) | (0x1 << 12) | (des_type << 10)
    | (ssl_version << 9) | (hash_type << 8) | (global_dma_mode << 7) |
    MAJOR_OP_OTHER;
  hash_size = 20 - (hash_type << 2);

  buffer.size = handshake_length;
  buffer.param = param;
  buffer.dlen = (32 + 32 + ROUNDUP8 (handshake_length)) >> 3;
  buffer.rlen = (40 + 8) >> 3;
  buffer.ctx_ptr = context_handle;
  buffer.group = CAVIUM_SSL_GRP;

  buffer.incnt = 3;

  buffer.inptr[0] = CAST_TO_X_PTR( client_random);
  buffer.insize[0] = 32;
  buffer.inoffset[0] = 32;
  buffer.inunit[0] = UNIT_8_BIT;
  buffer.inptr[1] = CAST_TO_X_PTR( server_random);
  buffer.insize[1] = 32;
  buffer.inoffset[1] = 32;
  buffer.inunit[1] = UNIT_8_BIT;
  buffer.inptr[2] = CAST_TO_X_PTR( handshake);
  buffer.insize[2] = handshake_length;
  buffer.inoffset[2] = ROUNDUP8 (handshake_length);
  buffer.inunit[2] = UNIT_8_BIT;

  buffer.outptr[0] = CAST_TO_X_PTR( verify_data);
  buffer.outsize[0] = 36;
  buffer.outoffset[0] = 40;
  buffer.outunit[0] = UNIT_8_BIT;

  if (master_secret_ret == RETURN_ENCRYPTED)
    {

      buffer.rlen += (48 >> 3);

      buffer.outcnt = 2;

      buffer.outptr[1] = CAST_TO_X_PTR( encrypt_master_secret);
      buffer.outsize[1] = 48;
      buffer.outoffset[1] = 48;
      buffer.outunit[1] = UNIT_8_BIT;

    }
  else if (master_secret_ret == NOT_RETURNED)

    buffer.outcnt = 1;

  buffer.req_type = request_type;
  buffer.req_queue = SSL_QUEUE;
  buffer.res_order = CAVIUM_RESPONSE_ORDERED;
  buffer.dma_mode = global_dma_mode;
  buffer.status = 0;

  cond_code =
#ifdef CAVIUM_MULTICARD_API
    ioctl (gpkpdev_hdlr[dev_id], IOCTL_N1_OPERATION_CODE, (ptrlong) & buffer);
#else
    ioctl (CSP1_driver_handle, IOCTL_N1_OPERATION_CODE, (ptrlong) & buffer);
#endif


  *request_id = buffer.request_id;

  if(cond_code)
     ret_val = cond_code; /*return error val*/
  else
     ret_val = buffer.status;/*return OPERATION STATUS: SUCCESS('0')/EAGAIN */

  return ret_val;
}
#endif /* if !MC2 */


/*+****************************************************************************
 *
 * Csp1OtherFullAes
 *
 * Do a full handshake. The pre-master secret is read
 * from the context and the rest of the handshake is completed. This is used
 * by both the server and the client. This entry point handles all the
 * AES cases.
 *
 * The handshake message data for this request should include all handshake 
 * message data after (and including) the client hello message up until (but 
 * not including) the first finished message. 
 *
 * Input
 *	request_type = CAVIUM_BLOCKING or CAVIUM_NON_BLOCKING
 *	context_handle = 64-bit pointer to context (context_handle%8=0)
 *	hash_type = MD5_TYPE or SHA1_TYPE
 *	ssl_version = VER3_0 or VER_TLS
 *	aes_type = AES_128 or AES_256
 *	master_secret_ret = NOT_RETURNED or RETURN_ENCRYPTED
 *	clnt_fin_msg_out = RETURN_CFM_ENCRYPTED or RETURN_CFM_UNENCRYPTED
 *	srvr_fin_msg_out = RETURN_SFM_ENCRYPTED or RETURN_SFM_UNENCRYPTED
 *	client_pad_length = number of 128-bit words to pad above min
 *	server_pad_length = number of 128-bit words to pad above min
 *	pre_master_length = size of premaster secret in bytes 
 *		(SSLv3: 4<=modlength<=256, modlength%4=0; 
 *		 TLS: 16<=modlength<=128, modlength%16=0)
 *	client_random = pointer to 32 bytes of random data
 *	server_random = pointer to 32 bytes of random data
 *	handshake_length = size in bytes of the handshake message data
 *	handshake = pointer to the handshake message data
 *
 * Output
 *	client_finished_message = pointer to encrypted part of client finished message 
 *	server_finished_message = pointer to encrypted part of server finished message 
 *	encrypt_master_secret = (master_secret_ret == RETURN_ENCRYPTED) ? pointer to
 *		returned encrypted master secret : don't care
 *	request_id = Unique ID for this request
 *
 * Return Value
 *	0  = success 
 * >0 = failure or pending
 * see error_codes.txt
 *
 *-***************************************************************************/
Uint32
Csp1OtherFullAes (n1_request_type request_type,
		  Uint64 context_handle,
		  HashType hash_type,
		  SslVersion ssl_version,
		  AesType aes_type,
		  MasterSecretReturn master_secret_ret,
		  ClientFinishMessageOutput clnt_fin_msg_out,
		  ServerFinishMessageOutput srvr_fin_msg_out,
		  Uint16 client_pad_length,
		  Uint16 server_pad_length,
		  Uint16 pre_master_length,
		  Uint8 * client_random,
		  Uint8 * server_random,
		  Uint16 handshake_length,
		  Uint8 * handshake,
		  Uint8 * client_finished_message,
		  Uint8 * server_finished_message,
		  Uint8 * encrypt_master_secret,
#ifdef CAVIUM_MULTICARD_API
                  Uint32 * request_id,Uint32 dev_id
#else
                  Uint32 * request_id
#endif
                   )
{
  Csp1OperationBuffer buffer;
  Uint32 cond_code;
  Uint32 ret_val;
  Uint16 param;
  Uint16 finished_size;
  Uint16 hash_size;

  memset(&buffer,0,sizeof(Csp1OperationBuffer));
  if ((context_handle & UINT64_C(0x8000000000000000)) != 0)
    {

      if ((context_handle & 0xf) != 0)

	return ERR_ILLEGAL_CONTEXT_HANDLE;

    }
  else
    {

      if ((context_handle & 0x7) != 0)

	return ERR_ILLEGAL_CONTEXT_HANDLE;

    }

  if ((ssl_version == VER3_0)
      && (((pre_master_length & 0x3) != 0) || (pre_master_length > 256)))

    return ERR_ILLEGAL_INPUT_LENGTH;

  if ((ssl_version == VER_TLS)
      && (((pre_master_length & 0xf) != 0) || (pre_master_length > 128)))

    return ERR_ILLEGAL_INPUT_LENGTH;

  finished_size = 16 + 24 * ssl_version;

#ifdef MC2
  param = (hash_type) | (ssl_version << 2) | (aes_type << 3) | (1 << 7);

  if (clnt_fin_msg_out == RETURN_CFM_UNENCRYPTED)
    param |= (1 << 8);

  if (srvr_fin_msg_out == RETURN_SFM_UNENCRYPTED)
    param |= (1 << 9);

  buffer.opcode = (master_secret_ret << 14) | (0x1 << 13) | (global_dma_mode << 7) |
       MAJOR_OP_OTHER;
  buffer.size = pre_master_length;

  hash_size = (hash_type == SHA1_TYPE)? 20:16;

  buffer.dlen = 32 + 32 + handshake_length;

  buffer.rlen = 0;

#else
  param = (pre_master_length >> 2) - 1;

  param |= (server_pad_length << 11) | (client_pad_length << 6);

  if (clnt_fin_msg_out == RETURN_CFM_UNENCRYPTED)

    param |= 0x1f << 6;

  if (srvr_fin_msg_out == RETURN_SFM_UNENCRYPTED)

    param |= 0x1f << 11;

  buffer.opcode =
    (master_secret_ret << 15) | (0xd << 11) | ((aes_type >> 1) << 10) |
    (ssl_version << 9) | (hash_type << 8) | (global_dma_mode << 7) |
    MAJOR_OP_OTHER;
  hash_size = 20 - (hash_type << 2);

  buffer.size = handshake_length;

  buffer.dlen = (32 + 32 + ROUNDUP8 (handshake_length)) >> 3;
  buffer.rlen = 8 >> 3;
#endif

  buffer.param = param;
  
  buffer.ctx_ptr = context_handle;
  buffer.group = CAVIUM_SSL_GRP;

  buffer.incnt = 3;

  buffer.inptr[0] = CAST_TO_X_PTR( client_random);
  buffer.insize[0] = 32;
  buffer.inoffset[0] = 32;
  buffer.inunit[0] = UNIT_8_BIT;
  buffer.inptr[1] = CAST_TO_X_PTR( server_random);
  buffer.insize[1] = 32;
  buffer.inoffset[1] = 32;
  buffer.inunit[1] = UNIT_8_BIT;
  buffer.inptr[2] = CAST_TO_X_PTR( handshake);
  buffer.insize[2] = handshake_length;
#ifdef MC2
  buffer.inoffset[2] = handshake_length;
#else
  buffer.inoffset[2] = ROUNDUP8 (handshake_length);
#endif
  buffer.inunit[2] = UNIT_8_BIT;

#ifdef MC2
  if (master_secret_ret == RETURN_ENCRYPTED)
  {
      buffer.rlen = 48;

      buffer.outcnt = 3;

      buffer.outptr[0] = CAST_TO_X_PTR( encrypt_master_secret);
      buffer.outsize[0] = 48;
      buffer.outoffset[0] = 48;
      buffer.outunit[0] = UNIT_8_BIT;

      buffer.outptr[1] = CAST_TO_X_PTR( client_finished_message);

      if (clnt_fin_msg_out == RETURN_CFM_ENCRYPTED)
      {
         buffer.rlen += ROUNDUP16 (finished_size + hash_size + 1);

         buffer.outsize[1] = ROUNDUP16 (finished_size + hash_size + 1);
         buffer.outoffset[1] = ROUNDUP16 (finished_size + hash_size + 1);
      }
      else if (clnt_fin_msg_out == RETURN_CFM_UNENCRYPTED)
      {
         buffer.rlen += finished_size;

         buffer.outsize[1] = finished_size;
         buffer.outoffset[1] = finished_size;
      }

      buffer.outunit[1] = UNIT_8_BIT;

      buffer.outptr[2] = CAST_TO_X_PTR( server_finished_message);

      if (srvr_fin_msg_out == RETURN_SFM_ENCRYPTED)
      {
         buffer.rlen += ROUNDUP16 (finished_size + hash_size + 1);

         buffer.outsize[2] = ROUNDUP16 (finished_size + hash_size + 1);
         buffer.outoffset[2] = ROUNDUP16 (finished_size + hash_size + 1);
      }
      else if (srvr_fin_msg_out == RETURN_SFM_UNENCRYPTED)
      {
         buffer.rlen += finished_size;

         buffer.outsize[2] = finished_size;
         buffer.outoffset[2] = finished_size;
      }

      buffer.outunit[2] = UNIT_8_BIT;

  }
  else if (master_secret_ret == NOT_RETURNED)
  {
      buffer.outcnt = 2;
      buffer.outptr[0] = CAST_TO_X_PTR( client_finished_message);

      if (clnt_fin_msg_out == RETURN_CFM_ENCRYPTED)
      {
         buffer.rlen += ROUNDUP16 (finished_size + hash_size + 1);

         buffer.outsize[0] = ROUNDUP16 (finished_size + hash_size + 1);
         buffer.outoffset[0] = ROUNDUP16 (finished_size + hash_size + 1);
      }
      else if (clnt_fin_msg_out == RETURN_CFM_UNENCRYPTED)
      {
         buffer.rlen += finished_size;

         buffer.outsize[0] = finished_size;
         buffer.outoffset[0] = finished_size;
      }

      buffer.outunit[0] = UNIT_8_BIT;

      buffer.outptr[1] = CAST_TO_X_PTR( server_finished_message);

      if (srvr_fin_msg_out == RETURN_SFM_ENCRYPTED)
      {
         buffer.rlen += ROUNDUP16 (finished_size + hash_size + 1);

         buffer.outsize[1] = ROUNDUP16 (finished_size + hash_size + 1);
         buffer.outoffset[1] = ROUNDUP16 (finished_size + hash_size + 1);
      }
      else if (srvr_fin_msg_out == RETURN_SFM_UNENCRYPTED)
      {
         buffer.rlen += finished_size;

         buffer.outsize[1] = finished_size;
         buffer.outoffset[1] = finished_size;
      }

      buffer.outunit[1] = UNIT_8_BIT;
   }

#else

  buffer.outptr[0] = CAST_TO_X_PTR( server_finished_message);

  if (srvr_fin_msg_out == RETURN_SFM_ENCRYPTED)
    {

      buffer.rlen +=
	((ROUNDUP16 (finished_size + hash_size + 1) +
	  16 * server_pad_length) >> 3);

      buffer.outsize[0] =
	ROUNDUP16 (finished_size + hash_size + 1) + 16 * server_pad_length;
      buffer.outoffset[0] =
	ROUNDUP16 (finished_size + hash_size + 1) + 16 * server_pad_length;

    }
  else if (srvr_fin_msg_out == RETURN_SFM_UNENCRYPTED)
    {

      buffer.rlen += (finished_size >> 3);

      buffer.outsize[0] = finished_size;
      buffer.outoffset[0] = finished_size;

    }

  buffer.outunit[0] = UNIT_8_BIT;

  buffer.outptr[1] = CAST_TO_X_PTR( client_finished_message);

  if (clnt_fin_msg_out == RETURN_CFM_ENCRYPTED)
    {

      buffer.rlen +=
	((ROUNDUP16 (finished_size + hash_size + 1) +
	  16 * client_pad_length) >> 3);

      buffer.outsize[1] =
	ROUNDUP16 (finished_size + hash_size + 1) + 16 * client_pad_length;
      buffer.outoffset[1] =
	ROUNDUP16 (finished_size + hash_size + 1) + 16 * client_pad_length;

    }
  else if (clnt_fin_msg_out == RETURN_CFM_UNENCRYPTED)
    {

      buffer.rlen += (finished_size >> 3);

      buffer.outsize[1] = finished_size;
      buffer.outoffset[1] = finished_size;

    }

  buffer.outunit[1] = UNIT_8_BIT;

  if (master_secret_ret == RETURN_ENCRYPTED)
    {

      buffer.rlen += (48 >> 3);

      buffer.outcnt = 3;

      buffer.outptr[2] = CAST_TO_X_PTR( encrypt_master_secret);
      buffer.outsize[2] = 48;
      buffer.outoffset[2] = 48;
      buffer.outunit[2] = UNIT_8_BIT;

    }
  else if (master_secret_ret == NOT_RETURNED)

    buffer.outcnt = 2;
#endif /* MC2 */

  buffer.req_type = request_type;
  buffer.req_queue = SSL_QUEUE;
  buffer.res_order = CAVIUM_RESPONSE_ORDERED;
  buffer.dma_mode = global_dma_mode;
  buffer.status = 0;

  cond_code =
#ifdef CAVIUM_MULTICARD_API
    ioctl (gpkpdev_hdlr[dev_id], IOCTL_N1_OPERATION_CODE, (ptrlong) & buffer);
#else
    ioctl (CSP1_driver_handle, IOCTL_N1_OPERATION_CODE, (ptrlong) & buffer);
#endif


  *request_id = buffer.request_id;

  if(cond_code)
     ret_val = cond_code; /*return error val*/
  else
     ret_val = buffer.status;/*return OPERATION STATUS: SUCCESS('0')/EAGAIN */

  return ret_val;
}


#ifndef MC2
/*+****************************************************************************
 *
 * Csp1OtherFullAesFinish
 *
 * When not (RSA <= 1024), do a full handshake. The pre-master secret is read
 * from the context and the rest of the handshake is completed. This is used
 * by both the server and the client. This entry point handles all the
 * AES cases.
 *
 * The handshake message data for this request should include all handshake 
 * message data after (and including) the client hello message up until (but 
 * not including) the first finished message. Handshake data can be accumulated 
 * prior to this request by calls to Handshake*, and this request will 
 * append the included handshake message data to the pre-existing handshake 
 * hash state.
 *
 * Input
 *	request_type = CAVIUM_BLOCKING or CAVIUM_NON_BLOCKING
 *	context_handle = 64-bit pointer to context (context_handle%8=0)
 *	hash_type = MD5_TYPE or SHA1_TYPE
 *	ssl_version = VER3_0 or VER_TLS
 *	aes_type = AES_128 or AES_256
 *	master_secret_ret = NOT_RETURNED or RETURN_ENCRYPTED
 *	clnt_fin_msg_out = RETURN_CFM_ENCRYPTED or RETURN_CFM_UNENCRYPTED
 *	srvr_fin_msg_out = RETURN_SFM_ENCRYPTED or RETURN_SFM_UNENCRYPTED
 *	client_pad_length = number of 128-bit words to pad above min
 *	server_pad_length = number of 128-bit words to pad above min
 *	pre_master_length = size of premaster secret in bytes 
 *		(SSLv3: 4<=modlength<=256, modlength%4=0; 
 *		 TLS: 16<=modlength<=128, modlength%16=0)
 *	client_random = pointer to 32 bytes of random data
 *	server_random = pointer to 32 bytes of random data
 *	handshake_length = size in bytes of the handshake message data
 *	handshake = pointer to the handshake message data
 *
 * Output
 *	client_finished_message = pointer to encrypted part of client finished message 
 *	server_finished_message = pointer to encrypted part of server finished message 
 *	encrypt_master_secret = (master_secret_ret == RETURN_ENCRYPTED) ? pointer to
 *		returned encrypted master secret : don't care
 *	request_id = Unique ID for this request
 *
 * Return Value
 *	0  = success 
 * >0 = failure or pending
 * see error_codes.txt
 *
 *-***************************************************************************/
Uint32
Csp1OtherFullAesFinish (n1_request_type request_type,
			Uint64 context_handle,
			HashType hash_type,
			SslVersion ssl_version,
			AesType aes_type,
			MasterSecretReturn master_secret_ret,
			ClientFinishMessageOutput clnt_fin_msg_out,
			ServerFinishMessageOutput srvr_fin_msg_out,
			Uint16 client_pad_length,
			Uint16 server_pad_length,
			Uint16 pre_master_length,
			Uint8 * client_random,
			Uint8 * server_random,
			Uint16 handshake_length,
			Uint8 * handshake,
			Uint8 * client_finished_message,
			Uint8 * server_finished_message,
			Uint8 * encrypt_master_secret, 
#ifdef CAVIUM_MULTICARD_API
                        Uint32 * request_id,Uint32 dev_id
#else
                        Uint32 * request_id
#endif
                   )
{
  Csp1OperationBuffer buffer;
  Uint32 cond_code;
  Uint32 ret_val;
  Uint16 param;
  Uint16 finished_size;
  Uint16 hash_size;

  memset(&buffer,0,sizeof(Csp1OperationBuffer));
  if ((context_handle & UINT64_C(0x8000000000000000)) != 0)
    {

      if ((context_handle & 0xf) != 0)

	return ERR_ILLEGAL_CONTEXT_HANDLE;

    }
  else
    {

      if ((context_handle & 0x7) != 0)

	return ERR_ILLEGAL_CONTEXT_HANDLE;

    }

  if ((ssl_version == VER3_0)
      && (((pre_master_length & 0x3) != 0) || (pre_master_length > 256)))

    return ERR_ILLEGAL_INPUT_LENGTH;

  if ((ssl_version == VER_TLS)
      && (((pre_master_length & 0xf) != 0) || (pre_master_length > 128)))

    return ERR_ILLEGAL_INPUT_LENGTH;

  param = (pre_master_length >> 2) - 1;

  param |= (server_pad_length << 11) | (client_pad_length << 6);

  if (clnt_fin_msg_out == RETURN_CFM_UNENCRYPTED)

    param |= 0x1f << 6;

  if (srvr_fin_msg_out == RETURN_SFM_UNENCRYPTED)

    param |= 0x1f << 11;

  buffer.opcode =
    (master_secret_ret << 15) | (0x9 << 11) | ((aes_type >> 1) << 10) |
    (ssl_version << 9) | (hash_type << 8) | (global_dma_mode << 7) |
    MAJOR_OP_OTHER;
  hash_size = 20 - (hash_type << 2);
  finished_size = 16 + 24 * ssl_version;

  buffer.size = handshake_length;
  buffer.param = param;
  buffer.dlen = (32 + 32 + ROUNDUP8 (handshake_length)) >> 3;
  buffer.rlen = 8 >> 3;
  buffer.ctx_ptr = context_handle;
  buffer.group = CAVIUM_SSL_GRP;

  buffer.incnt = 3;

  buffer.inptr[0] = CAST_TO_X_PTR( client_random);
  buffer.insize[0] = 32;
  buffer.inoffset[0] = 32;
  buffer.inunit[0] = UNIT_8_BIT;
  buffer.inptr[1] = CAST_TO_X_PTR( server_random);
  buffer.insize[1] = 32;
  buffer.inoffset[1] = 32;
  buffer.inunit[1] = UNIT_8_BIT;
  buffer.inptr[2] = CAST_TO_X_PTR( handshake);
  buffer.insize[2] = handshake_length;
  buffer.inoffset[2] = ROUNDUP8 (handshake_length);
  buffer.inunit[2] = UNIT_8_BIT;

  buffer.outptr[0] = CAST_TO_X_PTR( server_finished_message);

  if (srvr_fin_msg_out == RETURN_SFM_ENCRYPTED)
    {

      buffer.rlen +=
	((ROUNDUP16 (finished_size + hash_size + 1) +
	  16 * server_pad_length) >> 3);

      buffer.outsize[0] =
	ROUNDUP16 (finished_size + hash_size + 1) + 16 * server_pad_length;
      buffer.outoffset[0] =
	ROUNDUP16 (finished_size + hash_size + 1) + 16 * server_pad_length;

    }
  else if (srvr_fin_msg_out == RETURN_SFM_UNENCRYPTED)
    {

      buffer.rlen += (finished_size >> 3);

      buffer.outsize[0] = finished_size;
      buffer.outoffset[0] = finished_size;

    }

  buffer.outunit[0] = UNIT_8_BIT;

  buffer.outptr[1] = CAST_TO_X_PTR( client_finished_message);

  if (clnt_fin_msg_out == RETURN_CFM_ENCRYPTED)
    {

      buffer.rlen +=
	((ROUNDUP16 (finished_size + hash_size + 1) +
	  16 * client_pad_length) >> 3);

      buffer.outsize[1] =
	ROUNDUP16 (finished_size + hash_size + 1) + 16 * client_pad_length;
      buffer.outoffset[1] =
	ROUNDUP16 (finished_size + hash_size + 1) + 16 * client_pad_length;

    }
  else if (clnt_fin_msg_out == RETURN_CFM_UNENCRYPTED)
    {

      buffer.rlen += (finished_size >> 3);

      buffer.outsize[1] = finished_size;
      buffer.outoffset[1] = finished_size;

    }

  buffer.outunit[1] = UNIT_8_BIT;

  if (master_secret_ret == RETURN_ENCRYPTED)
    {

      buffer.rlen += (48 >> 3);

      buffer.outcnt = 3;

      buffer.outptr[2] = CAST_TO_X_PTR( encrypt_master_secret);
      buffer.outsize[2] = 48;
      buffer.outoffset[2] = 48;
      buffer.outunit[2] = UNIT_8_BIT;

    }
  else if (master_secret_ret == NOT_RETURNED)

    buffer.outcnt = 2;

  buffer.req_type = request_type;
  buffer.req_queue = SSL_QUEUE;
  buffer.res_order = CAVIUM_RESPONSE_ORDERED;
  buffer.dma_mode = global_dma_mode;
  buffer.status = 0;

  cond_code =
#ifdef CAVIUM_MULTICARD_API
    ioctl (gpkpdev_hdlr[dev_id], IOCTL_N1_OPERATION_CODE, (ptrlong) & buffer);
#else
    ioctl (CSP1_driver_handle, IOCTL_N1_OPERATION_CODE, (ptrlong) & buffer);
#endif


  *request_id = buffer.request_id;

  if(cond_code)
     ret_val = cond_code; /*return error val*/
  else
     ret_val = buffer.status;/*return OPERATION STATUS: SUCCESS('0')/EAGAIN */

  return ret_val;
}
#endif /* if !MC2 */


/*+****************************************************************************
 *
 * Csp1OtherVerifyAes
 *
 * Do a full handshake - up to the point of the
 * verify operation. The pre-master secret is read from the context.
 * This is used by both the server and the client. This entry point handles all 
 * the AES cases.
 *
 * The handshake message data for this request should include all handshake 
 * message data after (and including) the client hello message up until (but 
 * not including) the client verify message. 
 *
 * Input
 *	request_type = CAVIUM_BLOCKING or CAVIUM_NON_BLOCKING
 *	context_handle = 64-bit pointer to context (context_handle%8=0)
 *	hash_type = MD5_TYPE or SHA1_TYPE
 *	ssl_version = VER3_0 or VER_TLS
 *	aes_type = AES_128 or AES_256
 *	master_secret_ret = NOT_RETURNED or RETURN_ENCRYPTED
 *	pre_master_length = size of premaster secret in bytes 
 *		(SSLv3: 4<=modlength<=256, modlength%4=0; 
 *		 TLS: 16<=modlength<=128, modlength%16=0)
 *	client_random = pointer to 32 bytes of random data
 *	server_random = pointer to 32 bytes of random data
 *	handshake_length = size in bytes of the handshake message data
 *	handshake = pointer to the handshake message data
 *
 * Output
 *	verify_data = pointer to 36 bytes of verify data 
 *	encrypt_master_secret = (master_secret_ret == RETURN_ENCRYPTED) ? pointer to
 *		returned encrypted master secret : don't care
 *	request_id = Unique ID for this request
 *
 * Return Value
 *	0  = success 
 * >0 = failure or pending
 * see error_codes.txt
 *
 *-***************************************************************************/
Uint32
Csp1OtherVerifyAes (n1_request_type request_type,
		    Uint64 context_handle,
		    HashType hash_type,
		    SslVersion ssl_version,
		    AesType aes_type,
		    MasterSecretReturn master_secret_ret,
		    Uint16 pre_master_length,
		    Uint8 * client_random,
		    Uint8 * server_random,
		    Uint16 handshake_length,
		    Uint8 * handshake,
		    Uint8 * verify_data,
		    Uint8 * encrypt_master_secret, 
#ifdef CAVIUM_MULTICARD_API
                    Uint32 * request_id,Uint32 dev_id
#else
                    Uint32 * request_id
#endif
                   )
{
  Csp1OperationBuffer buffer;
  Uint32 cond_code;
  Uint32 ret_val;
  Uint16 param;
  Uint16 hash_size;

  memset(&buffer,0,sizeof(Csp1OperationBuffer));
  if ((context_handle & UINT64_C(0x8000000000000000)) != 0)
    {

      if ((context_handle & 0xf) != 0)

	return ERR_ILLEGAL_CONTEXT_HANDLE;

    }
  else
    {

      if ((context_handle & 0x7) != 0)

	return ERR_ILLEGAL_CONTEXT_HANDLE;

    }

  if ((ssl_version == VER3_0)
      && (((pre_master_length & 0x3) != 0) || (pre_master_length > 256)))

    return ERR_ILLEGAL_INPUT_LENGTH;

  if ((ssl_version == VER_TLS)
      && (((pre_master_length & 0xf) != 0) || (pre_master_length > 128)))

    return ERR_ILLEGAL_INPUT_LENGTH;

#ifdef MC2
  param = (hash_type) | (ssl_version << 2) | (aes_type << 3) | (1 << 7);

  buffer.opcode = (master_secret_ret << 14) | (global_dma_mode << 7) |
       MAJOR_OP_OTHER;

  buffer.size = pre_master_length;

  hash_size = (hash_type == SHA1_TYPE)? 20:16;

  buffer.dlen = 32 + 32 + handshake_length;

  buffer.rlen = 36;

#else

  param = (pre_master_length >> 2) - 1;

  buffer.opcode =
    (master_secret_ret << 15) | (0x5 << 11) | ((aes_type >> 1) << 10) |
    (ssl_version << 9) | (hash_type << 8) | (global_dma_mode << 7) |
    MAJOR_OP_OTHER;
  hash_size = 20 - (hash_type << 2);

  buffer.size = handshake_length;
  buffer.dlen = (32 + 32 + ROUNDUP8 (handshake_length)) >> 3;
  buffer.rlen = (40 + 8) >> 3;
#endif

  buffer.param = param;

  buffer.ctx_ptr = context_handle;
  buffer.group = CAVIUM_SSL_GRP;

  buffer.incnt = 3;

  buffer.inptr[0] = CAST_TO_X_PTR( client_random);
  buffer.insize[0] = 32;
  buffer.inoffset[0] = 32;
  buffer.inunit[0] = UNIT_8_BIT;
  buffer.inptr[1] = CAST_TO_X_PTR( server_random);
  buffer.insize[1] = 32;
  buffer.inoffset[1] = 32;
  buffer.inunit[1] = UNIT_8_BIT;
  buffer.inptr[2] = CAST_TO_X_PTR( handshake);
  buffer.insize[2] = handshake_length;
#ifdef MC2
  buffer.inoffset[2] = handshake_length;
#else
  buffer.inoffset[2] = ROUNDUP8 (handshake_length);
#endif
  buffer.inunit[2] = UNIT_8_BIT;

#ifndef MC2

  buffer.outptr[0] = CAST_TO_X_PTR( verify_data);
  buffer.outsize[0] = 36;
  buffer.outoffset[0] = 40;
  buffer.outunit[0] = UNIT_8_BIT;

  if (master_secret_ret == RETURN_ENCRYPTED)
    {
      buffer.rlen += (48 >> 3);

      buffer.outcnt = 2;

      buffer.outptr[1] = CAST_TO_X_PTR( encrypt_master_secret);
      buffer.outsize[1] = 48;
      buffer.outoffset[1] = 48;
      buffer.outunit[1] = UNIT_8_BIT;

    }
  else if (master_secret_ret == NOT_RETURNED)

    buffer.outcnt = 1;
#else
  if (master_secret_ret == RETURN_ENCRYPTED)
    {
      buffer.rlen += 48;
      buffer.outcnt = 2;

      buffer.outptr[0] = CAST_TO_X_PTR( encrypt_master_secret);
      buffer.outsize[0] = 48;
      buffer.outoffset[0] = 48;
      buffer.outunit[0] = UNIT_8_BIT;

      buffer.outptr[1] = CAST_TO_X_PTR( verify_data);
      buffer.outsize[1] = 36;
      buffer.outoffset[1] = 36;
      buffer.outunit[1] = UNIT_8_BIT;
    }
  else
    {
      buffer.outcnt = 1;
      buffer.outptr[0] = CAST_TO_X_PTR( verify_data);
      buffer.outsize[0] = 36;
      buffer.outoffset[0] = 36;
      buffer.outunit[0] = UNIT_8_BIT;
    }
#endif

  buffer.req_type = request_type;
  buffer.req_queue = SSL_QUEUE;
  buffer.res_order = CAVIUM_RESPONSE_ORDERED;
  buffer.dma_mode = global_dma_mode;
  buffer.status = 0;

  cond_code =
#ifdef CAVIUM_MULTICARD_API
    ioctl (gpkpdev_hdlr[dev_id], IOCTL_N1_OPERATION_CODE, (ptrlong) & buffer);
#else
    ioctl (CSP1_driver_handle, IOCTL_N1_OPERATION_CODE, (ptrlong) & buffer);
#endif


  *request_id = buffer.request_id;

  if(cond_code)
     ret_val = cond_code; /*return error val*/
  else
     ret_val = buffer.status;/*return OPERATION STATUS: SUCCESS('0')/EAGAIN */

  return ret_val;
}



#ifndef MC2
/*+****************************************************************************
 *
 * Csp1OtherVerifyAesFinish
 *
 * do a full handshake - up to the point of the
 * verify operation. The pre-master secret is read from the context.
 * This is used by both the server and the client. This entry point handles all 
 * the AES cases.
 *
 * The handshake message data for this request should include all handshake 
 * message data after (and including) the client hello message up until (but 
 * not including) the client verify message. Handshake data can be accumulated 
 * prior to this request by calls to Handshake*, and this request will 
 * append the included handshake message data to the pre-existing handshake 
 * hash state.
 *
 * Input
 *	request_type = CAVIUM_BLOCKING or CAVIUM_NON_BLOCKING
 *	context_handle = 64-bit pointer to context (context_handle%8=0)
 *	hash_type = MD5_TYPE or SHA1_TYPE
 *	ssl_version = VER3_0 or VER_TLS
 *	aes_type = AES_128 or AES_256
 *	master_secret_ret = NOT_RETURNED or RETURN_ENCRYPTED
 *	pre_master_length = size of premaster secret in bytes 
 *		(SSLv3: 4<=modlength<=256, modlength%4=0; 
 *		 TLS: 16<=modlength<=128, modlength%16=0)
 *	client_random = pointer to 32 bytes of random data
 *	server_random = pointer to 32 bytes of random data
 *	handshake_length = size in bytes of the handshake message data
 *	handshake = pointer to the handshake message data
 *
 * Output
 *	verify_data = pointer to 36 bytes of verify data 
 *	encrypt_master_secret = (master_secret_ret == RETURN_ENCRYPTED) ? pointer to
 *		returned encrypted master secret : don't care
 *	request_id = Unique ID for this request
 *
 * Return Value
 *	0  = success 
 * >0 = failure or pending
 * see error_codes.txt
 *
 *-***************************************************************************/
Uint32
Csp1OtherVerifyAesFinish (n1_request_type request_type,
			  Uint64 context_handle,
			  HashType hash_type,
			  SslVersion ssl_version,
			  AesType aes_type,
			  MasterSecretReturn master_secret_ret,
			  Uint16 pre_master_length,
			  Uint8 * client_random,
			  Uint8 * server_random,
			  Uint16 handshake_length,
			  Uint8 * handshake,
			  Uint8 * verify_data,
			  Uint8 * encrypt_master_secret, 
#ifdef CAVIUM_MULTICARD_API
                          Uint32 * request_id, Uint32 dev_id
#else
                          Uint32 * request_id
#endif
                   )
{
  Csp1OperationBuffer buffer;
  Uint32 cond_code;
  Uint32 ret_val;
  Uint16 param;
  Uint16 hash_size;

  memset(&buffer,0,sizeof(Csp1OperationBuffer));
  if ((context_handle & UINT64_C(0x8000000000000000)) != 0)
    {

      if ((context_handle & 0xf) != 0)

	return ERR_ILLEGAL_CONTEXT_HANDLE;

    }
  else
    {

      if ((context_handle & 0x7) != 0)

	return ERR_ILLEGAL_CONTEXT_HANDLE;

    }

  if ((ssl_version == VER3_0)
      && (((pre_master_length & 0x3) != 0) || (pre_master_length > 256)))

    return ERR_ILLEGAL_INPUT_LENGTH;

  if ((ssl_version == VER_TLS)
      && (((pre_master_length & 0xf) != 0) || (pre_master_length > 128)))

    return ERR_ILLEGAL_INPUT_LENGTH;

  param = (pre_master_length >> 2) - 1;

  buffer.opcode =
    (master_secret_ret << 15) | (0x1 << 11) | ((aes_type >> 1) << 10) |
    (ssl_version << 9) | (hash_type << 8) | (global_dma_mode << 7) |
    MAJOR_OP_OTHER;
  hash_size = 20 - (hash_type << 2);

  buffer.size = handshake_length;
  buffer.param = param;
  buffer.dlen = (32 + 32 + ROUNDUP8 (handshake_length)) >> 3;
  buffer.rlen = (40 + 8) >> 3;
  buffer.ctx_ptr = context_handle;
  buffer.group = CAVIUM_SSL_GRP;

  buffer.incnt = 3;

  buffer.inptr[0] = CAST_TO_X_PTR( client_random);
  buffer.insize[0] = 32;
  buffer.inoffset[0] = 32;
  buffer.inunit[0] = UNIT_8_BIT;
  buffer.inptr[1] = CAST_TO_X_PTR( server_random);
  buffer.insize[1] = 32;
  buffer.inoffset[1] = 32;
  buffer.inunit[1] = UNIT_8_BIT;
  buffer.inptr[2] = CAST_TO_X_PTR( handshake);
  buffer.insize[2] = handshake_length;
  buffer.inoffset[2] = ROUNDUP8 (handshake_length);
  buffer.inunit[2] = UNIT_8_BIT;

  buffer.outptr[0] = CAST_TO_X_PTR( verify_data);
  buffer.outsize[0] = 36;
  buffer.outoffset[0] = 40;
  buffer.outunit[0] = UNIT_8_BIT;

  if (master_secret_ret == RETURN_ENCRYPTED)
    {

      buffer.rlen += (48 >> 3);

      buffer.outcnt = 2;

      buffer.outptr[1] = CAST_TO_X_PTR( encrypt_master_secret);
      buffer.outsize[1] = 48;
      buffer.outoffset[1] = 48;
      buffer.outunit[1] = UNIT_8_BIT;

    }
  else if (master_secret_ret == NOT_RETURNED)

    buffer.outcnt = 1;

  buffer.req_type = request_type;
  buffer.req_queue = SSL_QUEUE;
  buffer.res_order = CAVIUM_RESPONSE_ORDERED;
  buffer.dma_mode = global_dma_mode;
  buffer.status = 0;

  cond_code =
#ifdef CAVIUM_MULTICARD_API
    ioctl (gpkpdev_hdlr[dev_id], IOCTL_N1_OPERATION_CODE, (ptrlong) & buffer);
#else
    ioctl (CSP1_driver_handle, IOCTL_N1_OPERATION_CODE, (ptrlong) & buffer);
#endif


  *request_id = buffer.request_id;

  if(cond_code)
     ret_val = cond_code; /*return error val*/
  else
     ret_val = buffer.status;/*return OPERATION STATUS: SUCCESS('0')/EAGAIN */

  return ret_val;
}
#endif /* if !MC2 */



/*+****************************************************************************
 *
 * Csp1FinishedRc4Finish
 *
 * Finish off the handshake hash and generate the finished messages for a full 
 * handshake. This is used in a full handshake with client authentication on 
 * either the client or the server. This follows RsaserverVerify or 
 * OtherVerify in that case. This entry point handles all the RC4 cases.
 *
 * The handshake hash context should include handshake messages from the
 * client hello message up until (but not including) the client verify message. 
 * This state should have been set up by a prior RsaserverVerifyRc4* or 
 * OtherVerifyRc4*. The handshake message data for this request should include 
 * the certificate verify message.
 *
 * Input
 *	request_type = CAVIUM_BLOCKING or CAVIUM_NON_BLOCKING
 *	context_handle = 64-bit pointer to context (context_handle%8=0)
 *	hash_type = MD5_TYPE or SHA1_TYPE
 *	ssl_version = VER3_0 or VER_TLS
 *	handshake_length = size in bytes of the handshake message data
 *	handshake = pointer to the handshake message data
 *
 * Output
 *	client_finished_message = pointer to encrypted part of client finished message 
 *	server_finished_message = pointer to encrypted part of server finished message 
 *	request_id = Unique ID for this request
 *
 * Return Value
 *	0  = success 
 * >0 = failure or pending
 * see error_codes.txt
 *
 *-***************************************************************************/
Uint32
Csp1FinishedRc4Finish (n1_request_type request_type,
		       Uint64 context_handle,
		       HashType hash_type,
		       SslVersion ssl_version,
		       Uint16 handshake_length,
		       Uint8 * handshake,
		       Uint8 * client_finished_message,
		       Uint8 * server_finished_message, 
#ifdef CAVIUM_MULTICARD_API
                       Uint32 * request_id,Uint32 dev_id
#else
                       Uint32 * request_id
#endif
                   )
{
  Csp1OperationBuffer buffer;
  Uint32 cond_code;
  Uint32 ret_val;
  Uint16 finished_size;
  Uint16 hash_size;

  memset(&buffer,0,sizeof(Csp1OperationBuffer));
  if ((context_handle & UINT64_C(0x8000000000000000)) != 0)
    {

      if ((context_handle & 0xf) != 0)

	return ERR_ILLEGAL_CONTEXT_HANDLE;

    }
  else
    {

      if ((context_handle & 0x7) != 0)

	return ERR_ILLEGAL_CONTEXT_HANDLE;

    }

  finished_size = 16 + 24 * ssl_version;
#ifdef MC2
  buffer.opcode = (global_dma_mode << 7) | MAJOR_OP_FINISHED;
  hash_size = (hash_type == SHA1_TYPE) ? 20 : 16;

  buffer.size = 0;
  buffer.param = (hash_type) | (ssl_version << 2) | (RC4_128 << 3);
  buffer.dlen = handshake_length;
  buffer.rlen = 2 * (finished_size + hash_size);
#else
  buffer.opcode = (0x0 << 10) | (ssl_version << 9) | (hash_type << 8)
    | (global_dma_mode << 7) | MAJOR_OP_FINISHED;
  hash_size = 20 - (hash_type << 2);

  buffer.size = handshake_length;
  buffer.param = 0;
  buffer.dlen = (ROUNDUP8 (handshake_length)) >> 3;
  buffer.rlen = (ROUNDUP8 (finished_size + hash_size)
		 + ROUNDUP8 (finished_size + hash_size) + 8) >> 3;
#endif
  buffer.ctx_ptr = context_handle;
  buffer.group = CAVIUM_SSL_GRP;

  buffer.incnt = 1;
  buffer.outcnt = 2;

  buffer.inptr[0] = CAST_TO_X_PTR( handshake);
  buffer.insize[0] = handshake_length;
#ifdef MC2
  buffer.inoffset[0] = handshake_length;
#else
  buffer.inoffset[0] = ROUNDUP8 (handshake_length);
#endif
  buffer.inunit[0] = UNIT_8_BIT;

#ifdef MC2
  buffer.outptr[0] = CAST_TO_X_PTR( client_finished_message);
  buffer.outsize[0] = finished_size + hash_size;
  buffer.outoffset[0] = finished_size + hash_size;
  buffer.outunit[0] = UNIT_8_BIT;
  buffer.outptr[1] = CAST_TO_X_PTR( server_finished_message);
  buffer.outsize[1] = finished_size + hash_size;
  buffer.outoffset[1] = finished_size + hash_size;
  buffer.outunit[1] = UNIT_8_BIT;
#else
  buffer.outptr[0] = CAST_TO_X_PTR( server_finished_message);
  buffer.outsize[0] = finished_size + hash_size;
  buffer.outoffset[0] = ROUNDUP8 (finished_size + hash_size);
  buffer.outunit[0] = UNIT_8_BIT;
  buffer.outptr[1] = CAST_TO_X_PTR( client_finished_message);
  buffer.outsize[1] = finished_size + hash_size;
  buffer.outoffset[1] = ROUNDUP8 (finished_size + hash_size);
  buffer.outunit[1] = UNIT_8_BIT;
#endif

  buffer.req_type = request_type;
  buffer.req_queue = SSL_QUEUE;
  buffer.res_order = CAVIUM_RESPONSE_ORDERED;
  buffer.dma_mode = global_dma_mode;
  buffer.status=0;


  cond_code =
#ifdef CAVIUM_MULTICARD_API
    ioctl (gpkpdev_hdlr[dev_id], IOCTL_N1_OPERATION_CODE, (ptrlong) & buffer);
#else
    ioctl (CSP1_driver_handle, IOCTL_N1_OPERATION_CODE, (ptrlong) & buffer);
#endif


  *request_id = buffer.request_id;

  if(cond_code)
     ret_val = cond_code; /*return error val*/
  else
     ret_val = buffer.status;/*return OPERATION STATUS: SUCCESS('0')/EAGAIN */

  return ret_val;
}




/*+****************************************************************************
 *
 * Csp1Finished3DesFinish
 *
 * Finish off the handshake hash and generate the finished messages for a full 
 * handshake. This is used in a full handshake with client authentication on 
 * either the client or the server. This follows RsaserverVerify or 
 * OtherVerify in that case. This entry point handles all DES/3DES 
 * cases.
 *
 * The handshake hash context should include handshake messages from the
 * client hello message up until (but not including) the client verify message. 
 * This state should have been set up by a prior RsaserverVerify3Des* or 
 * OtherVerify3Des*. The handshake message data for this request should include 
 * the certificate verify message.
 *
 * Input
 *	request_type = CAVIUM_BLOCKING or CAVIUM_NON_BLOCKING
 *	context_handle = 64-bit pointer to context (context_handle%8=0)
 *	hash_type = MD5_TYPE or SHA1_TYPE
 *	ssl_version = VER3_0 or VER_TLS
 *	clnt_fin_msg_out = RETURN_CFM_ENCRYPTED or RETURN_CFM_UNENCRYPTED
 *	srvr_fin_msg_out = RETURN_SFM_ENCRYPTED or RETURN_SFM_UNENCRYPTED
 *	client_pad_length = number of 64-bit words to pad above min
 *	server_pad_length = number of 64-bit words to pad above min
 *	handshake_length = size in bytes of the handshake message data
 *	handshake = pointer to the handshake message data
 *
 * Output
 *	client_finished_message = pointer to encrypted part of client finished message 
 *	server_finished_message = pointer to encrypted part of server finished message 
 *	request_id = Unique ID for this request
 *
 * Return Value
 *	0  = success 
 * >0 = failure or pending
 * see error_codes.txt
 *
 *-***************************************************************************/
Uint32
Csp1Finished3DesFinish (n1_request_type request_type,
			Uint64 context_handle,
			HashType hash_type,
			SslVersion ssl_version,
			ClientFinishMessageOutput clnt_fin_msg_out,
			ServerFinishMessageOutput srvr_fin_msg_out,
			Uint16 client_pad_length,
			Uint16 server_pad_length,
			Uint16 handshake_length,
			Uint8 * handshake,
			Uint8 * client_finished_message,
			Uint8 * server_finished_message, 
#ifdef CAVIUM_MULTICARD_API
                        Uint32 * request_id,Uint32 dev_id
#else
                        Uint32 * request_id
#endif
                   )
{
  Csp1OperationBuffer buffer;
  Uint32 cond_code;
  Uint32 ret_val;
  Uint16 finished_size;
  Uint16 hash_size;

  memset(&buffer,0,sizeof(Csp1OperationBuffer));
  if ((context_handle & UINT64_C(0x8000000000000000)) != 0)
    {

      if ((context_handle & 0xf) != 0)

	return ERR_ILLEGAL_CONTEXT_HANDLE;

    }
  else
    {

      if ((context_handle & 0x7) != 0)

	return ERR_ILLEGAL_CONTEXT_HANDLE;

    }

  finished_size = 16 + 24 * ssl_version;
#ifdef MC2
  buffer.opcode = (global_dma_mode << 7) | MAJOR_OP_FINISHED;
  hash_size = (hash_type == SHA1_TYPE) ? 20 : 16;

  buffer.size = 0;
  buffer.param = (hash_type) | (ssl_version << 2) | (DES << 3);

  if (clnt_fin_msg_out == RETURN_CFM_UNENCRYPTED)
    buffer.param |= (Uint16) (1 << 8);

  if (srvr_fin_msg_out == RETURN_SFM_UNENCRYPTED)
    buffer.param |= (Uint16) (1 << 9);

  buffer.dlen = handshake_length;
  buffer.rlen = 0;

#else
  buffer.opcode = (0x1 << 10) | (ssl_version << 9) | (hash_type << 8)
    | (global_dma_mode << 7) | MAJOR_OP_FINISHED;
  hash_size = 20 - (hash_type << 2);

  buffer.size = handshake_length;
  buffer.param = (server_pad_length << 11) | (client_pad_length << 6);
  buffer.dlen = (ROUNDUP8 (handshake_length)) >> 3;
  buffer.rlen = 8 >> 3;

  if (clnt_fin_msg_out == RETURN_CFM_UNENCRYPTED)

    buffer.param |= 0x1f << 6;

  if (srvr_fin_msg_out == RETURN_SFM_UNENCRYPTED)

    buffer.param |= 0x1f << 11;
#endif

  buffer.ctx_ptr = context_handle;
  buffer.group = CAVIUM_SSL_GRP;
  buffer.incnt = 1;
  buffer.outcnt = 2;

  buffer.inptr[0] = CAST_TO_X_PTR( handshake);
  buffer.insize[0] = handshake_length;
#ifdef MC2
  buffer.inoffset[0] = handshake_length;
#else
  buffer.inoffset[0] = ROUNDUP8 (handshake_length);
#endif
  buffer.inunit[0] = UNIT_8_BIT;

  buffer.outptr[0] = CAST_TO_X_PTR( server_finished_message);


#ifdef MC2

  buffer.outptr[0] = CAST_TO_X_PTR( client_finished_message);

  if (clnt_fin_msg_out == RETURN_CFM_ENCRYPTED)
    {
      buffer.rlen = ROUNDUP8 (finished_size + hash_size + 1);
      buffer.outsize[0] = ROUNDUP8 (finished_size + hash_size + 1);
      buffer.outoffset[0] = ROUNDUP8 (finished_size + hash_size + 1);

    }
  else if (clnt_fin_msg_out == RETURN_CFM_UNENCRYPTED)
    {
      buffer.rlen = finished_size;
      buffer.outsize[0] = finished_size;
      buffer.outoffset[0] = finished_size;
    }
  buffer.outunit[0] = UNIT_8_BIT;

  buffer.outptr[1] = CAST_TO_X_PTR( server_finished_message);

  if (srvr_fin_msg_out == RETURN_SFM_ENCRYPTED)
    {
      buffer.rlen += ROUNDUP8 (finished_size + hash_size + 1);
      buffer.outsize[1] = ROUNDUP8 (finished_size + hash_size + 1);
      buffer.outoffset[1] = ROUNDUP8 (finished_size + hash_size + 1);

    }
  else if (srvr_fin_msg_out == RETURN_SFM_UNENCRYPTED)
    {
      buffer.rlen += finished_size;
      buffer.outsize[1] = finished_size;
      buffer.outoffset[1] = finished_size;
    }
  buffer.outunit[1] = UNIT_8_BIT;

#else
  if (srvr_fin_msg_out == RETURN_SFM_ENCRYPTED)
    {

      buffer.rlen +=
	((ROUNDUP8 (finished_size + hash_size + 1) +
	  8 * server_pad_length) >> 3);

      buffer.outsize[0] =
	ROUNDUP8 (finished_size + hash_size + 1) + 8 * server_pad_length;
      buffer.outoffset[0] =
	ROUNDUP8 (finished_size + hash_size + 1) + 8 * server_pad_length;

    }
  else if (srvr_fin_msg_out == RETURN_SFM_UNENCRYPTED)
    {

      buffer.rlen += (finished_size >> 3);

      buffer.outsize[0] = finished_size;
      buffer.outoffset[0] = finished_size;

    }

  buffer.outunit[0] = UNIT_8_BIT;

  buffer.outptr[1] = CAST_TO_X_PTR( client_finished_message);

  if (clnt_fin_msg_out == RETURN_CFM_ENCRYPTED)
    {

      buffer.rlen +=
	((ROUNDUP8 (finished_size + hash_size + 1) +
	  8 * client_pad_length) >> 3);

      buffer.outsize[1] =
	ROUNDUP8 (finished_size + hash_size + 1) + 8 * client_pad_length;
      buffer.outoffset[1] =
	ROUNDUP8 (finished_size + hash_size + 1) + 8 * client_pad_length;

    }
  else if (clnt_fin_msg_out == RETURN_CFM_UNENCRYPTED)
    {

      buffer.rlen += (finished_size >> 3);

      buffer.outsize[1] = finished_size;
      buffer.outoffset[1] = finished_size;

    }

  buffer.outunit[1] = UNIT_8_BIT;
#endif
  buffer.req_type = request_type;
  buffer.req_queue = SSL_QUEUE;
  buffer.res_order = CAVIUM_RESPONSE_ORDERED;
  buffer.dma_mode = global_dma_mode;

  buffer.status=0;

  cond_code =
#ifdef CAVIUM_MULTICARD_API
    ioctl (gpkpdev_hdlr[dev_id], IOCTL_N1_OPERATION_CODE, (ptrlong) & buffer);
#else
    ioctl (CSP1_driver_handle, IOCTL_N1_OPERATION_CODE, (ptrlong) & buffer);
#endif


  *request_id = buffer.request_id;

  if(cond_code)
     ret_val = cond_code; /*return error val*/
  else
     ret_val = buffer.status;/*return OPERATION STATUS: SUCCESS('0')/EAGAIN */

  return ret_val;
}





/*+****************************************************************************
 *
 * Csp1FinishedAesFinish
 *
 * Finish off the handshake hash and generate the finished messages for a full 
 * handshake. This is used in a full handshake with client authentication on 
 * either the client or the server. This follows RsaserverVerify or 
 * OtherVerify in that case. This entry point handles all the AES cases.
 *
 * The handshake hash context should include handshake messages from the
 * client hello message up until (but not including) the client verify message. 
 * This state should have been set up by a prior RsaserverVerifyAes* or 
 * OtherVerifyAes*. The handshake message data for this request should include 
 * the certificate verify message.
 *
 * Input
 *	request_type = CAVIUM_BLOCKING or CAVIUM_NON_BLOCKING
 *	context_handle = 64-bit pointer to context (context_handle%8=0)
 *	hash_type = MD5_TYPE or SHA1_TYPE
 *	ssl_version = VER3_0 or VER_TLS
 *	aes_type = AES_128 or AES_256
 *	clnt_fin_msg_out = RETURN_CFM_ENCRYPTED or RETURN_CFM_UNENCRYPTED
 *	srvr_fin_msg_out = RETURN_SFM_ENCRYPTED or RETURN_SFM_UNENCRYPTED
 *	client_pad_length = number of 128-bit words to pad above min
 *	server_pad_length = number of 128-bit words to pad above min
 *	handshake_length = size in bytes of the handshake message data
 *	handshake = pointer to the handshake message data
 *
 * Output
 *	client_finished_message = pointer to encrypted part of client finished message 
 *	server_finished_message = pointer to encrypted part of server finished message 
 *	request_id = Unique ID for this request
 *
 * Return Value
 *	0  = success 
 * >0 = failure or pending
 * see error_codes.txt
 *
 *-***************************************************************************/
Uint32
Csp1FinishedAesFinish (n1_request_type request_type,
		       Uint64 context_handle,
		       HashType hash_type,
		       SslVersion ssl_version,
		       AesType aes_type,
		       ClientFinishMessageOutput clnt_fin_msg_out,
		       ServerFinishMessageOutput srvr_fin_msg_out,
		       Uint16 client_pad_length,
		       Uint16 server_pad_length,
		       Uint16 handshake_length,
		       Uint8 * handshake,
		       Uint8 * client_finished_message,
		       Uint8 * server_finished_message,
#ifdef CAVIUM_MULTICARD_API
                        Uint32 * request_id,Uint32 dev_id
#else
                        Uint32 * request_id
#endif
                   )
{

  Csp1OperationBuffer buffer;
  Uint32 cond_code;
  Uint32 ret_val;
  Uint16 finished_size;
  Uint16 hash_size;

  memset(&buffer,0,sizeof(Csp1OperationBuffer));
  if ((context_handle & UINT64_C(0x8000000000000000)) != 0)
    {

      if ((context_handle & 0xf) != 0)

	return ERR_ILLEGAL_CONTEXT_HANDLE;

    }
  else
    {

      if ((context_handle & 0x7) != 0)

	return ERR_ILLEGAL_CONTEXT_HANDLE;

    }

  finished_size = 16 + 24 * ssl_version;
#ifdef MC2
  buffer.opcode = (global_dma_mode << 7) | MAJOR_OP_FINISHED;
  hash_size = (hash_type == SHA1_TYPE) ? 20 : 16;

  buffer.size = 0;
  buffer.param = (hash_type) | (ssl_version << 2) | (aes_type << 3);

  if (clnt_fin_msg_out == RETURN_CFM_UNENCRYPTED)
    buffer.param |= (Uint16) (1 << 8);

  if (srvr_fin_msg_out == RETURN_SFM_UNENCRYPTED)
    buffer.param |= (Uint16) (1 << 9);

  buffer.dlen = handshake_length;
  buffer.rlen = 0;

#else
  buffer.opcode = (0x1 << 11) | ((aes_type >> 1) << 10) | (ssl_version << 9)
    | (hash_type << 8) | (global_dma_mode << 7) | MAJOR_OP_FINISHED;
  hash_size = 20 - (hash_type << 2);

  buffer.size = handshake_length;
  buffer.param = (server_pad_length << 11) | (client_pad_length << 6);
  buffer.dlen = (ROUNDUP8 (handshake_length)) >> 3;
  buffer.rlen = 8 >> 3;

  if (clnt_fin_msg_out == RETURN_CFM_UNENCRYPTED)

    buffer.param |= 0x1f << 6;

  if (srvr_fin_msg_out == RETURN_SFM_UNENCRYPTED)

    buffer.param |= 0x1f << 11;
#endif
  buffer.ctx_ptr = context_handle;
  buffer.group = CAVIUM_SSL_GRP;
  buffer.incnt = 1;
  buffer.outcnt = 2;

  buffer.inptr[0] = CAST_TO_X_PTR( handshake);
  buffer.insize[0] = handshake_length;
  buffer.inoffset[0] = ROUNDUP8 (handshake_length);
  buffer.inunit[0] = UNIT_8_BIT;

#ifdef MC2
  buffer.inoffset[0] = handshake_length;
#endif

#ifdef MC2

  buffer.outptr[0] = CAST_TO_X_PTR( client_finished_message);

  if (clnt_fin_msg_out == RETURN_CFM_ENCRYPTED)
    {
      buffer.rlen = ROUNDUP16 (finished_size + hash_size + 1);
      buffer.outsize[0] = ROUNDUP16 (finished_size + hash_size + 1);
      buffer.outoffset[0] = ROUNDUP16 (finished_size + hash_size + 1);

    }
  else if (clnt_fin_msg_out == RETURN_CFM_UNENCRYPTED)
    {
      buffer.rlen = finished_size;
      buffer.outsize[0] = finished_size;
      buffer.outoffset[0] = finished_size;
    }
  buffer.outunit[0] = UNIT_8_BIT;

  buffer.outptr[1] = CAST_TO_X_PTR( server_finished_message);

  if (srvr_fin_msg_out == RETURN_SFM_ENCRYPTED)
    {
      buffer.rlen += ROUNDUP16 (finished_size + hash_size + 1);
      buffer.outsize[1] = ROUNDUP16 (finished_size + hash_size + 1);
      buffer.outoffset[1] = ROUNDUP16 (finished_size + hash_size + 1);

    }
  else if (srvr_fin_msg_out == RETURN_SFM_UNENCRYPTED)
    {
      buffer.rlen += finished_size;
      buffer.outsize[1] = finished_size;
      buffer.outoffset[1] = finished_size;
    }
  buffer.outunit[1] = UNIT_8_BIT;

#else
  buffer.outptr[0] = CAST_TO_X_PTR( server_finished_message);

  if (srvr_fin_msg_out == RETURN_SFM_ENCRYPTED)
    {

      buffer.rlen +=
	((ROUNDUP16 (finished_size + hash_size + 1) +
	  16 * server_pad_length) >> 3);

      buffer.outsize[0] =
	ROUNDUP16 (finished_size + hash_size + 1) + 16 * server_pad_length;
      buffer.outoffset[0] =
	ROUNDUP16 (finished_size + hash_size + 1) + 16 * server_pad_length;

    }
  else if (srvr_fin_msg_out == RETURN_SFM_UNENCRYPTED)
    {

      buffer.rlen += (finished_size >> 3);

      buffer.outsize[0] = finished_size;
      buffer.outoffset[0] = finished_size;

    }

  buffer.outunit[0] = UNIT_8_BIT;

  buffer.outptr[1] = CAST_TO_X_PTR( client_finished_message);

  if (clnt_fin_msg_out == RETURN_CFM_ENCRYPTED)
    {

      buffer.rlen +=
	((ROUNDUP16 (finished_size + hash_size + 1) +
	  16 * client_pad_length) >> 3);

      buffer.outsize[1] =
	ROUNDUP16 (finished_size + hash_size + 1) + 16 * client_pad_length;
      buffer.outoffset[1] =
	ROUNDUP16 (finished_size + hash_size + 1) + 16 * client_pad_length;

    }
  else if (clnt_fin_msg_out == RETURN_CFM_UNENCRYPTED)
    {

      buffer.rlen += (finished_size >> 3);

      buffer.outsize[1] = finished_size;
      buffer.outoffset[1] = finished_size;

    }

  buffer.outunit[1] = UNIT_8_BIT;
#endif
  buffer.req_type = request_type;
  buffer.req_queue = SSL_QUEUE;
  buffer.res_order = CAVIUM_RESPONSE_ORDERED;
  buffer.dma_mode = global_dma_mode;
  buffer.status=0;


  cond_code =
#ifdef CAVIUM_MULTICARD_API
    ioctl (gpkpdev_hdlr[dev_id], IOCTL_N1_OPERATION_CODE, (ptrlong) & buffer);
#else
    ioctl (CSP1_driver_handle, IOCTL_N1_OPERATION_CODE, (ptrlong) & buffer);
#endif


  *request_id = buffer.request_id;

  if(cond_code)
     ret_val = cond_code; /*return error val*/
  else
     ret_val = buffer.status;/*return OPERATION STATUS: SUCCESS('0')/EAGAIN */

  return ret_val;
}


/*+****************************************************************************
 *
 * Csp1ResumeRc4
 *
 * Completes a resume on either the client or the server. This entry point 
 * handles all the RC4 cases.
 *
 * The handshake message data for this request should include all handshake 
 * message data after (and including) the most-recent client hello message up 
 * until (but not including) the first finished message. 
 *
 * Input
 *	request_type = CAVIUM_BLOCKING or CAVIUM_NON_BLOCKING
 *	context_handle = 64-bit pointer to context (context_handle%8=0)
 *	hash_type = MD5_TYPE or SHA1_TYPE
 *	ssl_version = VER3_0 or VER_TLS
 *	rc4_type = RC4_128, RC4_EXPORT_40, or RC4_EXPORT_56
 *	master_secret_inp = READ_FROM_CONTEXT or INPUT_ENCRYPTED
 *	client_random = pointer to 32 bytes of random data
 *	server_random = pointer to 32 bytes of random data
 *	encrypt_master_secret = pointer to 48-byte secret
 *	handshake_length = size in bytes of the handshake message data
 *	handshake = pointer to the handshake message data
 *
 * Output
 *	client_finished_message = pointer to encrypted part of client finished message 
 *	server_finished_message = pointer to encrypted part of server finished message 
 *	request_id = Unique ID for this request
 *
 * Return Value
 *	0  = success 
 * >0 = failure or pending
 * see error_codes.txt
 *
 *-***************************************************************************/
Uint32
Csp1ResumeRc4 (n1_request_type request_type,
	       Uint64 context_handle,
	       HashType hash_type,
	       SslVersion ssl_version,
	       Rc4Type rc4_type,
	       MasterSecretInput master_secret_inp,
	       Uint8 * client_random,
	       Uint8 * server_random,
	       Uint8 * encrypt_master_secret,
	       Uint16 handshake_length,
	       Uint8 * handshake,
	       Uint8 * client_finished_message,
	       Uint8 * server_finished_message,
#ifdef CAVIUM_MULTICARD_API
               Uint32 * request_id,Uint32 dev_id
#else
               Uint32 * request_id
#endif
               )
{
  Csp1OperationBuffer buffer;
  Uint32 cond_code;
  Uint32 ret_val;
  Uint16 finished_size;
  Uint16 hash_size;

  memset(&buffer,0,sizeof(Csp1OperationBuffer));
  if ((context_handle & UINT64_C(0x8000000000000000)) != 0)
    {

      if ((context_handle & 0xf) != 0)

	return ERR_ILLEGAL_CONTEXT_HANDLE;

    }
  else
    {

      if ((context_handle & 0x7) != 0)

	return ERR_ILLEGAL_CONTEXT_HANDLE;

    }

  finished_size = 16 + 24 * ssl_version;

#ifdef MC2
  hash_size = (hash_type == SHA1_TYPE) ? 20 : 16;

  buffer.opcode = (master_secret_inp << 14) | MAJOR_OP_RESUME;
  buffer.size = 0;
  buffer.param =
    (hash_type) | (ssl_version << 2) | (rc4_type << 3) | (1 << 7);
  buffer.dlen = 32 + 32 + handshake_length;
  buffer.rlen = 2 * (finished_size + hash_size);
#else

  buffer.opcode = (master_secret_inp << 15) | (0x1 << 13) | (rc4_type << 10)
    | (ssl_version << 9) | (hash_type << 8) | (global_dma_mode << 7) |
    MAJOR_OP_RESUME;
  hash_size = 20 - (hash_type << 2);

  buffer.size = handshake_length;
  buffer.param = 0;
  buffer.dlen = (32 + 32 + ROUNDUP8 (handshake_length)) >> 3;
  buffer.rlen = (ROUNDUP8 (finished_size + hash_size)
		 + ROUNDUP8 (finished_size + hash_size) + 8) >> 3;
#endif
  buffer.ctx_ptr = context_handle;
  buffer.group = CAVIUM_SSL_GRP;

  if (master_secret_inp == INPUT_ENCRYPTED)
    {

#ifdef MC2
      buffer.dlen += 48;
#else
      buffer.dlen += (48 >> 3);
#endif

      buffer.incnt = 4;

      buffer.inptr[0] = CAST_TO_X_PTR( encrypt_master_secret);
      buffer.insize[0] = 48;
      buffer.inoffset[0] = 48;
      buffer.inunit[0] = UNIT_8_BIT;
      buffer.inptr[1] = CAST_TO_X_PTR( client_random);
      buffer.insize[1] = 32;
      buffer.inoffset[1] = 32;
      buffer.inunit[1] = UNIT_8_BIT;
      buffer.inptr[2] = CAST_TO_X_PTR( server_random);
      buffer.insize[2] = 32;
      buffer.inoffset[2] = 32;
      buffer.inunit[2] = UNIT_8_BIT;
      buffer.inptr[3] = CAST_TO_X_PTR( handshake);
      buffer.insize[3] = handshake_length;
      buffer.inoffset[3] = ROUNDUP8 (handshake_length);
      buffer.inunit[3] = UNIT_8_BIT;

#ifdef MC2
      buffer.inoffset[3] = handshake_length;
#endif
    }
  else if (master_secret_inp == READ_FROM_CONTEXT)
    {

      buffer.incnt = 3;

      buffer.inptr[0] = CAST_TO_X_PTR( client_random);
      buffer.insize[0] = 32;
      buffer.inoffset[0] = 32;
      buffer.inunit[0] = UNIT_8_BIT;
      buffer.inptr[1] = CAST_TO_X_PTR( server_random);
      buffer.insize[1] = 32;
      buffer.inoffset[1] = 32;
      buffer.inunit[1] = UNIT_8_BIT;
      buffer.inptr[2] = CAST_TO_X_PTR( handshake);
      buffer.insize[2] = handshake_length;
      buffer.inoffset[2] = ROUNDUP8 (handshake_length);
      buffer.inunit[2] = UNIT_8_BIT;

    }

  buffer.outcnt = 2;

  buffer.outptr[0] = CAST_TO_X_PTR( client_finished_message);
  buffer.outsize[0] = finished_size + hash_size;
  buffer.outoffset[0] = ROUNDUP8 (finished_size + hash_size);
  buffer.outunit[0] = UNIT_8_BIT;
  buffer.outptr[1] = CAST_TO_X_PTR( server_finished_message);
  buffer.outsize[1] = finished_size + hash_size;
#ifdef MC2
  buffer.outoffset[1] = finished_size + hash_size;
#else
  buffer.outoffset[1] = ROUNDUP8 (finished_size + hash_size);
#endif
  buffer.outunit[1] = UNIT_8_BIT;

#ifdef MC2
  buffer.outoffset[0] = finished_size + hash_size;
#endif

  buffer.req_type = request_type;
  buffer.req_queue = SSL_QUEUE;
  buffer.res_order = CAVIUM_RESPONSE_ORDERED;
  buffer.dma_mode = global_dma_mode;
  buffer.status=0;


  cond_code =
#ifdef CAVIUM_MULTICARD_API
    ioctl (gpkpdev_hdlr[dev_id], IOCTL_N1_OPERATION_CODE, (ptrlong) & buffer);
#else
    ioctl (CSP1_driver_handle, IOCTL_N1_OPERATION_CODE, (ptrlong) & buffer);
#endif


  *request_id = buffer.request_id;

  if(cond_code)
     ret_val = cond_code; /*return error val*/
  else
     ret_val = buffer.status;/*return OPERATION STATUS: SUCCESS('0')/EAGAIN */

  return ret_val;
}


#ifndef MC2
/*+****************************************************************************
 *
 * Csp1ResumeRc4Finish
 *
 * Completes a resume on either the client or the server. This entry point 
 * handles all the RC4 cases.
 *
 * The handshake message data for this request should include all handshake 
 * message data after (and including) the most-recent client hello message up 
 * until (but not including) the first finished message. Handshake data can be 
 * accumulated prior to this request by calls to Handshake*, and this 
 * request will append the included handshake message data to the pre-existing
 * handshake hash state.
 *
 * Input
 *	request_type = CAVIUM_BLOCKING or CAVIUM_NON_BLOCKING
 *	context_handle = 64-bit pointer to context (context_handle%8=0)
 *	hash_type = MD5_TYPE or SHA1_TYPE
 *	ssl_version = VER3_0 or VER_TLS
 *	rc4_type = RC4_128, RC4_EXPORT_40, or RC4_EXPORT_56
 *	master_secret_inp = READ_FROM_CONTEXT or INPUT_ENCRYPTED
 *	client_random = pointer to 32 bytes of random data
 *	server_random = pointer to 32 bytes of random data
 *	encrypt_master_secret = pointer to 48-byte secret
 *	handshake_length = size in bytes of the handshake message data
 *	handshake = pointer to the handshake message data
 *
 * Output
 *	client_finished_message = pointer to encrypted part of client finished message 
 *	server_finished_message = pointer to encrypted part of server finished message 
 *	request_id = Unique ID for this request
 *
 * Return Value
 *	0  = success 
 * >0 = failure or pending
 * see error_codes.txt
 *
 *-***************************************************************************/
Uint32
Csp1ResumeRc4Finish (n1_request_type request_type,
		     Uint64 context_handle,
		     HashType hash_type,
		     SslVersion ssl_version,
		     Rc4Type rc4_type,
		     MasterSecretInput master_secret_inp,
		     Uint8 * client_random,
		     Uint8 * server_random,
		     Uint8 * encrypt_master_secret,
		     Uint16 handshake_length,
		     Uint8 * handshake,
		     Uint8 * client_finished_message,
		     Uint8 * server_finished_message,
#ifdef CAVIUM_MULTICARD_API
                     Uint32 * request_id,Uint32 dev_id
#else
                     Uint32 * request_id
#endif
                   )
{
  Csp1OperationBuffer buffer;
  Uint32 cond_code;
  Uint32 ret_val;
  Uint16 finished_size;
  Uint16 hash_size;

  memset(&buffer,0,sizeof(Csp1OperationBuffer));
  if ((context_handle & UINT64_C(0x8000000000000000)) != 0)
    {

      if ((context_handle & 0xf) != 0)

	return ERR_ILLEGAL_CONTEXT_HANDLE;

    }
  else
    {

      if ((context_handle & 0x7) != 0)

	return ERR_ILLEGAL_CONTEXT_HANDLE;

    }

  buffer.opcode = (master_secret_inp << 15) | (0x0 << 13) | (rc4_type << 10)
    | (ssl_version << 9) | (hash_type << 8) | (global_dma_mode << 7) |
    MAJOR_OP_RESUME;
  hash_size = 20 - (hash_type << 2);
  finished_size = 16 + 24 * ssl_version;

  buffer.size = handshake_length;
  buffer.param = 0;
  buffer.dlen = (32 + 32 + ROUNDUP8 (handshake_length)) >> 3;
  buffer.rlen = (ROUNDUP8 (finished_size + hash_size)
		 + ROUNDUP8 (finished_size + hash_size) + 8) >> 3;
  buffer.ctx_ptr = context_handle;
  buffer.group = CAVIUM_SSL_GRP;

  if (master_secret_inp == INPUT_ENCRYPTED)
    {

      buffer.dlen += (48 >> 3);

      buffer.incnt = 4;

      buffer.inptr[0] = CAST_TO_X_PTR( encrypt_master_secret);
      buffer.insize[0] = 48;
      buffer.inoffset[0] = 48;
      buffer.inunit[0] = UNIT_8_BIT;
      buffer.inptr[1] = CAST_TO_X_PTR( client_random);
      buffer.insize[1] = 32;
      buffer.inoffset[1] = 32;
      buffer.inunit[1] = UNIT_8_BIT;
      buffer.inptr[2] = CAST_TO_X_PTR( server_random);
      buffer.insize[2] = 32;
      buffer.inoffset[2] = 32;
      buffer.inunit[2] = UNIT_8_BIT;
      buffer.inptr[3] = CAST_TO_X_PTR( handshake);
      buffer.insize[3] = handshake_length;
      buffer.inoffset[3] = ROUNDUP8 (handshake_length);
      buffer.inunit[3] = UNIT_8_BIT;

    }
  else if (master_secret_inp == READ_FROM_CONTEXT)
    {

      buffer.incnt = 3;

      buffer.inptr[0] = CAST_TO_X_PTR( client_random);
      buffer.insize[0] = 32;
      buffer.inoffset[0] = 32;
      buffer.inunit[0] = UNIT_8_BIT;
      buffer.inptr[1] =CAST_TO_X_PTR(  server_random);
      buffer.insize[1] = 32;
      buffer.inoffset[1] = 32;
      buffer.inunit[1] = UNIT_8_BIT;
      buffer.inptr[2] = CAST_TO_X_PTR( handshake);
      buffer.insize[2] = handshake_length;
      buffer.inoffset[2] = ROUNDUP8 (handshake_length);
      buffer.inunit[2] = UNIT_8_BIT;

    }

  buffer.outcnt = 2;

  buffer.outptr[0] = CAST_TO_X_PTR( client_finished_message);
  buffer.outsize[0] = finished_size + hash_size;
  buffer.outoffset[0] = ROUNDUP8 (finished_size + hash_size);
  buffer.outunit[0] = UNIT_8_BIT;
  buffer.outptr[1] = CAST_TO_X_PTR( server_finished_message);
  buffer.outsize[1] = finished_size + hash_size;
  buffer.outoffset[1] = ROUNDUP8 (finished_size + hash_size);
  buffer.outunit[1] = UNIT_8_BIT;

  buffer.req_type = request_type;
  buffer.req_queue = SSL_QUEUE;
  buffer.res_order = CAVIUM_RESPONSE_ORDERED;
  buffer.dma_mode = global_dma_mode;
  buffer.status=0;


  cond_code =
#ifdef CAVIUM_MULTICARD_API
    ioctl (gpkpdev_hdlr[dev_id], IOCTL_N1_OPERATION_CODE, (ptrlong) & buffer);
#else
    ioctl (CSP1_driver_handle, IOCTL_N1_OPERATION_CODE, (ptrlong) & buffer);
#endif


  *request_id = buffer.request_id;

  if(cond_code)
     ret_val = cond_code; /*return error val*/
  else
     ret_val = buffer.status;/*return OPERATION STATUS: SUCCESS('0')/EAGAIN */

  return ret_val;
}
#endif /* if !MC2 */


/*+****************************************************************************
 *
 * Csp1Resume3Des
 *
 * Completes a resume on either the client or the server. This entry point 
 * handles all the DES/3DES cases.
 *
 * The handshake message data for this request should include all handshake 
 * message data after (and including) the most-recent client hello message up 
 * until (but not including) the first finished message. 
 *
 * Input
 *	request_type = CAVIUM_BLOCKING or CAVIUM_NON_BLOCKING
 *	context_handle = 64-bit pointer to context (context_handle%8=0)
 *	hash_type = MD5_TYPE or SHA1_TYPE
 *	ssl_version = VER3_0 or VER_TLS
 *	des_type = DES, DES_EXPORT_40 or DES3_192
 *	master_secret_inp = READ_FROM_CONTEXT or INPUT_ENCRYPTED
 *	clnt_fin_msg_out = RETURN_CFM_ENCRYPTED or RETURN_CFM_UNENCRYPTED
 *	srvr_fin_msg_out = RETURN_SFM_ENCRYPTED or RETURN_SFM_UNENCRYPTED
 *	client_pad_length = number of 64-bit words to pad above min(not applicable to MC2)
 *	server_pad_length = number of 64-bit words to pad above min(not applicable to MC2)
 *	client_random = pointer to 32 bytes of random data
 *	server_random = pointer to 32 bytes of random data
 *	encrypt_master_secret = pointer to 48-byte secret
 *	handshake_length = size in bytes of the handshake message data
 *	handshake = pointer to the handshake message data
 *
 * Output
 *	client_finished_message = pointer to encrypted part of client finished message 
 *	server_finished_message = pointer to encrypted part of server finished message 
 *	request_id = Unique ID for this request
 *
 * Return Value
 *	0  = success 
 * >0 = failure or pending
 * see error_codes.txt
 *
 *-***************************************************************************/
Uint32
Csp1Resume3Des (n1_request_type request_type,
		Uint64 context_handle,
		HashType hash_type,
		SslVersion ssl_version,
		DesType des_type,
		MasterSecretInput master_secret_inp,
		ClientFinishMessageOutput clnt_fin_msg_out,
		ServerFinishMessageOutput srvr_fin_msg_out,
		Uint16 client_pad_length,
		Uint16 server_pad_length,
		Uint8 * client_random,
		Uint8 * server_random,
		Uint8 * encrypt_master_secret,
		Uint16 handshake_length,
		Uint8 * handshake,
		Uint8 * client_finished_message,
		Uint8 * server_finished_message,
#ifdef CAVIUM_MULTICARD_API
                Uint32 * request_id,Uint32 dev_id
#else
                Uint32 * request_id
#endif
                   )
{
  Csp1OperationBuffer buffer;
  Uint32 cond_code;
  Uint32 ret_val;
  Uint16 finished_size;
  Uint16 hash_size;

  memset(&buffer,0,sizeof(Csp1OperationBuffer));
  if ((context_handle & UINT64_C(0x8000000000000000)) != 0)
    {

      if ((context_handle & 0xf) != 0)

	return ERR_ILLEGAL_CONTEXT_HANDLE;

    }
  else
    {

      if ((context_handle & 0x7) != 0)

	return ERR_ILLEGAL_CONTEXT_HANDLE;

    }

  finished_size = 16 + 24 * ssl_version;

#ifdef MC2
  hash_size = (hash_type == SHA1_TYPE) ? 20 : 16;
  buffer.opcode = (master_secret_inp << 14) | MAJOR_OP_RESUME;
  buffer.size = 0;

  buffer.param =
    (hash_type) | (ssl_version << 2) | (des_type << 3) | (1 << 7);
  if (clnt_fin_msg_out == RETURN_CFM_UNENCRYPTED)
    buffer.param |= (Uint16) (1 << 8);
  if (srvr_fin_msg_out == RETURN_SFM_UNENCRYPTED)
    buffer.param |= (Uint16) (1 << 9);

  buffer.dlen = 32 + 32 + handshake_length;
  buffer.rlen = 0;
#else
  buffer.opcode = (master_secret_inp << 15) | (0x3 << 12) | (des_type << 10)
    | (ssl_version << 9) | (hash_type << 8) | (global_dma_mode << 7) |
    MAJOR_OP_RESUME;
  hash_size = 20 - (hash_type << 2);

  buffer.size = handshake_length;
  buffer.param = (client_pad_length << 11) | (server_pad_length << 6);
  buffer.dlen = (32 + 32 + ROUNDUP8 (handshake_length)) >> 3;
  buffer.rlen = 8 >> 3;

  if (srvr_fin_msg_out == RETURN_SFM_UNENCRYPTED)

    buffer.param |= 0x1f << 6;

  if (clnt_fin_msg_out == RETURN_CFM_UNENCRYPTED)

    buffer.param |= 0x1f << 11;
#endif
  buffer.ctx_ptr = context_handle;
  buffer.group = CAVIUM_SSL_GRP;
  if (master_secret_inp == INPUT_ENCRYPTED)
    {

#ifdef MC2
      buffer.dlen += 48;
#else
      buffer.dlen += (48 >> 3);
#endif
      buffer.incnt = 4;

      buffer.inptr[0] = CAST_TO_X_PTR( encrypt_master_secret);
      buffer.insize[0] = 48;
      buffer.inoffset[0] = 48;
      buffer.inunit[0] = UNIT_8_BIT;
      buffer.inptr[1] = CAST_TO_X_PTR( client_random);
      buffer.insize[1] = 32;
      buffer.inoffset[1] = 32;
      buffer.inunit[1] = UNIT_8_BIT;
      buffer.inptr[2] = CAST_TO_X_PTR( server_random);
      buffer.insize[2] = 32;
      buffer.inoffset[2] = 32;
      buffer.inunit[2] = UNIT_8_BIT;
      buffer.inptr[3] =CAST_TO_X_PTR(  handshake);
      buffer.insize[3] = handshake_length;
#ifdef MC2
      buffer.inoffset[3] = handshake_length;
#else
      buffer.inoffset[3] = ROUNDUP8 (handshake_length);
#endif
      buffer.inunit[3] = UNIT_8_BIT;
    }
  else if (master_secret_inp == READ_FROM_CONTEXT)
    {

      buffer.incnt = 3;

      buffer.inptr[0] = CAST_TO_X_PTR( client_random);
      buffer.insize[0] = 32;
      buffer.inoffset[0] = 32;
      buffer.inunit[0] = UNIT_8_BIT;
      buffer.inptr[1] = CAST_TO_X_PTR( server_random);
      buffer.insize[1] = 32;
      buffer.inoffset[1] = 32;
      buffer.inunit[1] = UNIT_8_BIT;
      buffer.inptr[2] = CAST_TO_X_PTR( handshake);
      buffer.insize[2] = handshake_length;
#ifdef MC2
      buffer.inoffset[2] = handshake_length;
#else
      buffer.inoffset[2] = ROUNDUP8 (handshake_length);
#endif
      buffer.inunit[2] = UNIT_8_BIT;

    }

  buffer.outcnt = 2;

  buffer.outptr[0] = CAST_TO_X_PTR( client_finished_message);

  if (clnt_fin_msg_out == RETURN_CFM_ENCRYPTED)
  {

#ifdef MC2
      buffer.rlen += ROUNDUP8 (finished_size + hash_size + 1);

      buffer.outsize[0] = ROUNDUP8 (finished_size + hash_size + 1);
      buffer.outoffset[0] = ROUNDUP8 (finished_size + hash_size + 1);
#else
      buffer.rlen +=
	((ROUNDUP8 (finished_size + hash_size + 1) +
	  8 * client_pad_length) >> 3);

      buffer.outsize[0] =
	ROUNDUP8 (finished_size + hash_size + 1) + 8 * client_pad_length;
      buffer.outoffset[0] =
	ROUNDUP8 (finished_size + hash_size + 1) + 8 * client_pad_length;
#endif
    }
  else if (clnt_fin_msg_out == RETURN_CFM_UNENCRYPTED)
    {

#ifdef MC2
      buffer.rlen += finished_size;
#else
      buffer.rlen += (finished_size >> 3);
#endif
      buffer.outsize[0] = finished_size;
      buffer.outoffset[0] = finished_size;

    }

  buffer.outunit[0] = UNIT_8_BIT;

  buffer.outptr[1] = CAST_TO_X_PTR( server_finished_message);

  if (srvr_fin_msg_out == RETURN_SFM_ENCRYPTED)
    {
#ifdef MC2
      buffer.rlen += ROUNDUP8 (finished_size + hash_size + 1);

      buffer.outsize[1] = ROUNDUP8 (finished_size + hash_size + 1);
      buffer.outoffset[1] = ROUNDUP8 (finished_size + hash_size + 1);
#else
      buffer.rlen +=
	((ROUNDUP8 (finished_size + hash_size + 1) +
	  8 * server_pad_length) >> 3);

      buffer.outsize[1] =
	ROUNDUP8 (finished_size + hash_size + 1) + 8 * server_pad_length;
      buffer.outoffset[1] =
	ROUNDUP8 (finished_size + hash_size + 1) + 8 * server_pad_length;
#endif
    }
  else if (srvr_fin_msg_out == RETURN_SFM_UNENCRYPTED)
    {

#ifdef MC2
      buffer.rlen += finished_size;
#else
      buffer.rlen += (finished_size >> 3);
#endif
      buffer.outsize[1] = finished_size;
      buffer.outoffset[1] = finished_size;
    }

  buffer.outunit[1] = UNIT_8_BIT;

  buffer.req_type = request_type;
  buffer.req_queue = SSL_QUEUE;
  buffer.res_order = CAVIUM_RESPONSE_ORDERED;
  buffer.dma_mode = global_dma_mode;
  buffer.status=0;


  cond_code =
#ifdef CAVIUM_MULTICARD_API
    ioctl (gpkpdev_hdlr[dev_id], IOCTL_N1_OPERATION_CODE, (ptrlong) & buffer);
#else
    ioctl (CSP1_driver_handle, IOCTL_N1_OPERATION_CODE, (ptrlong) & buffer);
#endif


  *request_id = buffer.request_id;

  if(cond_code)
     ret_val = cond_code; /*return error val*/
  else
     ret_val = buffer.status;/*return OPERATION STATUS: SUCCESS('0')/EAGAIN */

  return ret_val;
}



#ifndef MC2
/*+****************************************************************************
 *
 * Csp1Resume3DesFinish
 *
 * Completes a resume on either the client or the server. This entry point 
 * handles all the DES/3DES cases.
 *
 * The handshake message data for this request should include all handshake 
 * message data after (and including) the most-recent client hello message up 
 * until (but not including) the first finished message. Handshake data can be 
 * accumulated prior to this request by calls to Handshake*, and this 
 * request will append the included handshake message data to the pre-existing
 * handshake hash state.
 *
 * Input
 *	request_type = CAVIUM_BLOCKING or CAVIUM_NON_BLOCKING
 *	context_handle = 64-bit pointer to context (context_handle%8=0)
 *	hash_type = MD5_TYPE or SHA1_TYPE
 *	ssl_version = VER3_0 or VER_TLS
 *	des_type = DES, DES_EXPORT_40 or DES3_192
 *	master_secret_inp = READ_FROM_CONTEXT or INPUT_ENCRYPTED
 *	clnt_fin_msg_out = RETURN_CFM_ENCRYPTED or RETURN_CFM_UNENCRYPTED
 *	srvr_fin_msg_out = RETURN_SFM_ENCRYPTED or RETURN_SFM_UNENCRYPTED
 *	client_pad_length = number of 64-bit words to pad above min
 *	server_pad_length = number of 64-bit words to pad above min
 *	client_random = pointer to 32 bytes of random data
 *	server_random = pointer to 32 bytes of random data
 *	encrypt_master_secret = pointer to 48-byte secret
 *	handshake_length = size in bytes of the handshake message data
 *	handshake = pointer to the handshake message data
 *
 * Output
 *	client_finished_message = pointer to encrypted part of client finished message 
 *	server_finished_message = pointer to encrypted part of server finished message 
 *	request_id = Unique ID for this request
 *
 * Return Value
 *	0  = success 
 * >0 = failure or pending
 * see error_codes.txt
 *
 *-***************************************************************************/
Uint32
Csp1Resume3DesFinish (n1_request_type request_type,
		      Uint64 context_handle,
		      HashType hash_type,
		      SslVersion ssl_version,
		      DesType des_type,
		      MasterSecretInput master_secret_inp,
		      ClientFinishMessageOutput clnt_fin_msg_out,
		      ServerFinishMessageOutput srvr_fin_msg_out,
		      Uint16 client_pad_length,
		      Uint16 server_pad_length,
		      Uint8 * client_random,
		      Uint8 * server_random,
		      Uint8 * encrypt_master_secret,
		      Uint16 handshake_length,
		      Uint8 * handshake,
		      Uint8 * client_finished_message,
		      Uint8 * server_finished_message,
#ifdef CAVIUM_MULTICARD_API
                      Uint32 * request_id,Uint32 dev_id
#else
                      Uint32 * request_id
#endif
                   )
{
  Csp1OperationBuffer buffer;
  Uint32 cond_code;
  Uint32 ret_val;
  Uint16 finished_size;
  Uint16 hash_size;

  memset(&buffer,0,sizeof(Csp1OperationBuffer));
  if ((context_handle & UINT64_C(0x8000000000000000)) != 0)
    {

      if ((context_handle & 0xf) != 0)

	return ERR_ILLEGAL_CONTEXT_HANDLE;

    }
  else
    {

      if ((context_handle & 0x7) != 0)

	return ERR_ILLEGAL_CONTEXT_HANDLE;

    }

  buffer.opcode = (master_secret_inp << 15) | (0x1 << 12) | (des_type << 10)
    | (ssl_version << 9) | (hash_type << 8) | (global_dma_mode << 7) |
    MAJOR_OP_RESUME;
  hash_size = 20 - (hash_type << 2);
  finished_size = 16 + 24 * ssl_version;

  buffer.size = handshake_length;
  buffer.param = (client_pad_length << 11) | (server_pad_length << 6);
  buffer.dlen = (32 + 32 + ROUNDUP8 (handshake_length)) >> 3;
  buffer.rlen = 8 >> 3;
  buffer.ctx_ptr = context_handle;
  buffer.group = CAVIUM_SSL_GRP;

  if (srvr_fin_msg_out == RETURN_SFM_UNENCRYPTED)

    buffer.param |= 0x1f << 6;

  if (clnt_fin_msg_out == RETURN_CFM_UNENCRYPTED)

    buffer.param |= 0x1f << 11;

  if (master_secret_inp == INPUT_ENCRYPTED)
    {

      buffer.dlen += (48 >> 3);

      buffer.incnt = 4;

      buffer.inptr[0] = CAST_TO_X_PTR( encrypt_master_secret);
      buffer.insize[0] = 48;
      buffer.inoffset[0] = 48;
      buffer.inunit[0] = UNIT_8_BIT;
      buffer.inptr[1] = CAST_TO_X_PTR( client_random);
      buffer.insize[1] = 32;
      buffer.inoffset[1] = 32;
      buffer.inunit[1] = UNIT_8_BIT;
      buffer.inptr[2] = CAST_TO_X_PTR( server_random);
      buffer.insize[2] = 32;
      buffer.inoffset[2] = 32;
      buffer.inunit[2] = UNIT_8_BIT;
      buffer.inptr[3] = CAST_TO_X_PTR( handshake);
      buffer.insize[3] = handshake_length;
      buffer.inoffset[3] = ROUNDUP8 (handshake_length);
      buffer.inunit[3] = UNIT_8_BIT;

    }
  else if (master_secret_inp == READ_FROM_CONTEXT)
    {

      buffer.incnt = 3;

      buffer.inptr[0] = CAST_TO_X_PTR( client_random);
      buffer.insize[0] = 32;
      buffer.inoffset[0] = 32;
      buffer.inunit[0] = UNIT_8_BIT;
      buffer.inptr[1] = CAST_TO_X_PTR( server_random);
      buffer.insize[1] = 32;
      buffer.inoffset[1] = 32;
      buffer.inunit[1] = UNIT_8_BIT;
      buffer.inptr[2] = CAST_TO_X_PTR( handshake);
      buffer.insize[2] = handshake_length;
      buffer.inoffset[2] = ROUNDUP8 (handshake_length);
      buffer.inunit[2] = UNIT_8_BIT;

    }

  buffer.outcnt = 2;

  buffer.outptr[0] = CAST_TO_X_PTR( client_finished_message);

  if (clnt_fin_msg_out == RETURN_CFM_ENCRYPTED)
    {

      buffer.rlen +=
	((ROUNDUP8 (finished_size + hash_size + 1) +
	  8 * client_pad_length) >> 3);

      buffer.outsize[0] =
	ROUNDUP8 (finished_size + hash_size + 1) + 8 * client_pad_length;
      buffer.outoffset[0] =
	ROUNDUP8 (finished_size + hash_size + 1) + 8 * client_pad_length;

    }
  else if (clnt_fin_msg_out == RETURN_CFM_UNENCRYPTED)
    {

      buffer.rlen += (finished_size >> 3);

      buffer.outsize[0] = finished_size;
      buffer.outoffset[0] = finished_size;

    }

  buffer.outunit[0] = UNIT_8_BIT;

  buffer.outptr[1] = CAST_TO_X_PTR( server_finished_message);

  if (srvr_fin_msg_out == RETURN_SFM_ENCRYPTED)
    {

      buffer.rlen +=
	((ROUNDUP8 (finished_size + hash_size + 1) +
	  8 * server_pad_length) >> 3);

      buffer.outsize[1] =
	ROUNDUP8 (finished_size + hash_size + 1) + 8 * server_pad_length;
      buffer.outoffset[1] =
	ROUNDUP8 (finished_size + hash_size + 1) + 8 * server_pad_length;

    }
  else if (srvr_fin_msg_out == RETURN_SFM_UNENCRYPTED)
    {

      buffer.rlen += (finished_size >> 3);

      buffer.outsize[1] = finished_size;
      buffer.outoffset[1] = finished_size;

    }

  buffer.outunit[1] = UNIT_8_BIT;

  buffer.req_type = request_type;
  buffer.req_queue = SSL_QUEUE;
  buffer.res_order = CAVIUM_RESPONSE_ORDERED;
  buffer.dma_mode = global_dma_mode;
  buffer.status=0;


  cond_code =
#ifdef CAVIUM_MULTICARD_API
    ioctl (gpkpdev_hdlr[dev_id], IOCTL_N1_OPERATION_CODE, (ptrlong) & buffer);
#else
    ioctl (CSP1_driver_handle, IOCTL_N1_OPERATION_CODE, (ptrlong) & buffer);
#endif


  *request_id = buffer.request_id;

  if(cond_code)
     ret_val = cond_code; /*return error val*/
  else
     ret_val = buffer.status;/*return OPERATION STATUS: SUCCESS('0')/EAGAIN */

  return ret_val;
}
#endif /* if !MC2 */



/*+****************************************************************************
 *
 * Csp1ResumeAes
 *
 * Completes a resume on either the client or the server. This entry point 
 * handles all the AES cases.
 *
 * The handshake message data for this request should include all handshake 
 * message data after (and including) the most-recent client hello message up 
 * until (but not including) the first finished message. 
 *
 * Input
 *	request_type = CAVIUM_BLOCKING or CAVIUM_NON_BLOCKING
 *	context_handle = 64-bit pointer to context (context_handle%8=0)
 *	hash_type = MD5_TYPE or SHA1_TYPE
 *	ssl_version = VER3_0 or VER_TLS
 *	aes_type = AES_128 or AES_256
 *	master_secret_inp = READ_FROM_CONTEXT or INPUT_ENCRYPTED
 *	clnt_fin_msg_out = RETURN_CFM_ENCRYPTED or RETURN_CFM_UNENCRYPTED
 *	srvr_fin_msg_out = RETURN_SFM_ENCRYPTED or RETURN_SFM_UNENCRYPTED
 *	client_pad_length = number of 128-bit words to pad above min(not applicable to MC2)
 *	server_pad_length = number of 128-bit words to pad above min(not applicable to MC2)
 *	client_random = pointer to 32 bytes of random data
 *	server_random = pointer to 32 bytes of random data
 *	encrypt_master_secret = pointer to 48-byte secret
 *	handshake_length = size in bytes of the handshake message data
 *	handshake = pointer to the handshake message data
 *
 * Output
 *	client_finished_message = pointer to encrypted part of client finished message 
 *	server_finished_message = pointer to encrypted part of server finished message 
 *	request_id = Unique ID for this request
 *
 * Return Value
 *	0  = success 
 * >0 = failure or pending
 * see error_codes.txt
 *
 *-***************************************************************************/
Uint32
Csp1ResumeAes (n1_request_type request_type,
	       Uint64 context_handle,
	       HashType hash_type,
	       SslVersion ssl_version,
	       AesType aes_type,
	       MasterSecretInput master_secret_inp,
	       ClientFinishMessageOutput clnt_fin_msg_out,
	       ServerFinishMessageOutput srvr_fin_msg_out,
	       Uint16 client_pad_length,
	       Uint16 server_pad_length,
	       Uint8 * client_random,
	       Uint8 * server_random,
	       Uint8 * encrypt_master_secret,
	       Uint16 handshake_length,
	       Uint8 * handshake,
	       Uint8 * client_finished_message,
	       Uint8 * server_finished_message,
#ifdef CAVIUM_MULTICARD_API
               Uint32 * request_id,Uint32 dev_id
#else
               Uint32 * request_id
#endif
              )
{
  Csp1OperationBuffer buffer;
  Uint32 cond_code;
  Uint32 ret_val;
  Uint16 finished_size;
  Uint16 hash_size;

  memset(&buffer,0,sizeof(Csp1OperationBuffer));
  if ((context_handle & UINT64_C(0x8000000000000000)) != 0)
    {

      if ((context_handle & 0xf) != 0)

	return ERR_ILLEGAL_CONTEXT_HANDLE;

    }
  else
    {

      if ((context_handle & 0x7) != 0)

	return ERR_ILLEGAL_CONTEXT_HANDLE;

    }

  finished_size = 16 + 24 * ssl_version;

#ifdef MC2
  hash_size = (hash_type == SHA1_TYPE) ? 20 : 16;
  buffer.opcode = (master_secret_inp << 14) | MAJOR_OP_RESUME;
  buffer.size = 0;

  buffer.param =
    (hash_type) | (ssl_version << 2) | (aes_type << 3) | (1 << 7);
  if (clnt_fin_msg_out == RETURN_CFM_UNENCRYPTED)
    buffer.param |= (Uint16) (1 << 8);
  if (srvr_fin_msg_out == RETURN_SFM_UNENCRYPTED)
    buffer.param |= (Uint16) (1 << 9);

  buffer.dlen = 32 + 32 + handshake_length;
  buffer.rlen = 0;

#else
  buffer.opcode =
    (master_secret_inp << 15) | (0x5 << 11) | ((aes_type >> 1) << 10) |
    (ssl_version << 9) | (hash_type << 8) | (global_dma_mode << 7) |
    MAJOR_OP_RESUME;
  hash_size = 20 - (hash_type << 2);

  buffer.size = handshake_length;
  buffer.param = (client_pad_length << 11) | (server_pad_length << 6);
  buffer.dlen = (32 + 32 + ROUNDUP8 (handshake_length)) >> 3;
  buffer.rlen = 8 >> 3;
  buffer.ctx_ptr = context_handle;

  if (srvr_fin_msg_out == RETURN_SFM_UNENCRYPTED)

    buffer.param |= 0x1f << 6;

  if (clnt_fin_msg_out == RETURN_CFM_UNENCRYPTED)

    buffer.param |= 0x1f << 11;
#endif
  buffer.ctx_ptr = context_handle;
  buffer.group = CAVIUM_SSL_GRP;
  if (master_secret_inp == INPUT_ENCRYPTED)
    {

#ifdef MC2
      buffer.dlen += 48;
#else
      buffer.dlen += (48 >> 3);
#endif
      buffer.incnt = 4;

      buffer.inptr[0] = CAST_TO_X_PTR( encrypt_master_secret);
      buffer.insize[0] = 48;
      buffer.inoffset[0] = 48;
      buffer.inunit[0] = UNIT_8_BIT;
      buffer.inptr[1] = CAST_TO_X_PTR( client_random);
      buffer.insize[1] = 32;
      buffer.inoffset[1] = 32;
      buffer.inunit[1] = UNIT_8_BIT;
      buffer.inptr[2] = CAST_TO_X_PTR( server_random);
      buffer.insize[2] = 32;
      buffer.inoffset[2] = 32;
      buffer.inunit[2] = UNIT_8_BIT;
      buffer.inptr[3] = CAST_TO_X_PTR( handshake);
      buffer.insize[3] = handshake_length;
      buffer.inoffset[3] = ROUNDUP8 (handshake_length);
      buffer.inunit[3] = UNIT_8_BIT;
#ifdef MC2
      buffer.inoffset[3] = handshake_length;
#endif

    }
  else if (master_secret_inp == READ_FROM_CONTEXT)
    {

      buffer.incnt = 3;

      buffer.inptr[0] = CAST_TO_X_PTR( client_random);
      buffer.insize[0] = 32;
      buffer.inoffset[0] = 32;
      buffer.inunit[0] = UNIT_8_BIT;
      buffer.inptr[1] = CAST_TO_X_PTR( server_random);
      buffer.insize[1] = 32;
      buffer.inoffset[1] = 32;
      buffer.inunit[1] = UNIT_8_BIT;
      buffer.inptr[2] = CAST_TO_X_PTR( handshake);
      buffer.insize[2] = handshake_length;
      buffer.inoffset[2] = ROUNDUP8 (handshake_length);
      buffer.inunit[2] = UNIT_8_BIT;
#ifdef MC2
      buffer.inoffset[2] = handshake_length;
#endif
    }

  buffer.outcnt = 2;

  buffer.outptr[0] = CAST_TO_X_PTR( client_finished_message);

  if (clnt_fin_msg_out == RETURN_CFM_ENCRYPTED)
    {
#ifdef MC2
      buffer.rlen += ROUNDUP16 (finished_size + hash_size + 1);

      buffer.outsize[0] = ROUNDUP16 (finished_size + hash_size + 1);
      buffer.outoffset[0] = ROUNDUP16 (finished_size + hash_size + 1);
#else
      buffer.rlen +=
	((ROUNDUP16 (finished_size + hash_size + 1) +
	  16 * client_pad_length) >> 3);

      buffer.outsize[0] =
	ROUNDUP16 (finished_size + hash_size + 1) + 16 * client_pad_length;
      buffer.outoffset[0] =
	ROUNDUP16 (finished_size + hash_size + 1) + 16 * client_pad_length;
#endif
    }
  else if (clnt_fin_msg_out == RETURN_CFM_UNENCRYPTED)
    {

#ifdef MC2
      buffer.rlen += finished_size;
#else
      buffer.rlen += (finished_size >> 3);
#endif
      buffer.outsize[0] = finished_size;
      buffer.outoffset[0] = finished_size;

    }

  buffer.outunit[0] = UNIT_8_BIT;

  buffer.outptr[1] = CAST_TO_X_PTR( server_finished_message);

  if (srvr_fin_msg_out == RETURN_SFM_ENCRYPTED)
    {

#ifdef MC2
      buffer.rlen += ROUNDUP16 (finished_size + hash_size + 1);

      buffer.outsize[1] = ROUNDUP16 (finished_size + hash_size + 1);
      buffer.outoffset[1] = ROUNDUP16 (finished_size + hash_size + 1);
#else
      buffer.rlen +=
	((ROUNDUP16 (finished_size + hash_size + 1) +
	  16 * server_pad_length) >> 3);

      buffer.outsize[1] =
	ROUNDUP16 (finished_size + hash_size + 1) + 16 * server_pad_length;
      buffer.outoffset[1] =
	ROUNDUP16 (finished_size + hash_size + 1) + 16 * server_pad_length;
#endif
    }
  else if (srvr_fin_msg_out == RETURN_SFM_UNENCRYPTED)
    {

#ifdef MC2
      buffer.rlen += finished_size;
#else
      buffer.rlen += (finished_size >> 3);
#endif
      buffer.outsize[1] = finished_size;
      buffer.outoffset[1] = finished_size;

    }

  buffer.outunit[1] = UNIT_8_BIT;

  buffer.req_type = request_type;
  buffer.req_queue = SSL_QUEUE;
  buffer.res_order = CAVIUM_RESPONSE_ORDERED;
  buffer.dma_mode = global_dma_mode;
  buffer.status=0;
  buffer.group = CAVIUM_SSL_GRP;


  cond_code =
#ifdef CAVIUM_MULTICARD_API
    ioctl (gpkpdev_hdlr[dev_id], IOCTL_N1_OPERATION_CODE, (ptrlong) & buffer);
#else
    ioctl (CSP1_driver_handle, IOCTL_N1_OPERATION_CODE, (ptrlong) & buffer);
#endif


  *request_id = buffer.request_id;

  if(cond_code)
     ret_val = cond_code; /*return error val*/
  else
     ret_val = buffer.status;/*return OPERATION STATUS: SUCCESS('0')/EAGAIN */

  return ret_val;
}



#ifndef MC2
/*+****************************************************************************
 *
 * Csp1ResumeAesFinish
 *
 * Completes a resume on either the client or the server. This entry point 
 * handles all the AES cases.
 *
 * The handshake message data for this request should include all handshake 
 * message data after (and including) the most-recent client hello message up 
 * until (but not including) the first finished message. Handshake data can be 
 * accumulated prior to this request by calls to Handshake*, and this 
 * request will append the included handshake message data to the pre-existing
 * handshake hash state.
 *
 * Input
 *	request_type = CAVIUM_BLOCKING or CAVIUM_NON_BLOCKING
 *	context_handle = 64-bit pointer to context (context_handle%8=0)
 *	hash_type = MD5_TYPE or SHA1_TYPE
 *	ssl_version = VER3_0 or VER_TLS
 *	aes_type = AES_128 or AES_256
 *	master_secret_inp = READ_FROM_CONTEXT or INPUT_ENCRYPTED
 *	clnt_fin_msg_out = RETURN_CFM_ENCRYPTED or RETURN_CFM_UNENCRYPTED
 *	srvr_fin_msg_out = RETURN_SFM_ENCRYPTED or RETURN_SFM_UNENCRYPTED
 *	client_pad_length = number of 128-bit words to pad above min
 *	server_pad_length = number of 128-bit words to pad above min
 *	client_random = pointer to 32 bytes of random data
 *	server_random = pointer to 32 bytes of random data
 *	encrypt_master_secret = pointer to 48-byte secret
 *	handshake_length = size in bytes of the handshake message data
 *	handshake = pointer to the handshake message data
 *
 * Output
 *	client_finished_message = pointer to encrypted part of client finished message 
 *	server_finished_message = pointer to encrypted part of server finished message 
 *	request_id = Unique ID for this request
 *
 * Return Value
 *	0  = success 
 * >0 = failure or pending
 * see error_codes.txt
 *
 *-***************************************************************************/
Uint32
Csp1ResumeAesFinish (n1_request_type request_type,
		     Uint64 context_handle,
		     HashType hash_type,
		     SslVersion ssl_version,
		     AesType aes_type,
		     MasterSecretInput master_secret_inp,
		     ClientFinishMessageOutput clnt_fin_msg_out,
		     ServerFinishMessageOutput srvr_fin_msg_out,
		     Uint16 client_pad_length,
		     Uint16 server_pad_length,
		     Uint8 * client_random,
		     Uint8 * server_random,
		     Uint8 * encrypt_master_secret,
		     Uint16 handshake_length,
		     Uint8 * handshake,
		     Uint8 * client_finished_message,
		     Uint8 * server_finished_message,
#ifdef CAVIUM_MULTICARD_API
                     Uint32 * request_id,Uint32 dev_id
#else
                     Uint32 * request_id
#endif
                   )
{
  Csp1OperationBuffer buffer;
  Uint32 cond_code;
  Uint32 ret_val;
  Uint16 finished_size;
  Uint16 hash_size;

  memset(&buffer,0,sizeof(Csp1OperationBuffer));
  if ((context_handle & UINT64_C(0x8000000000000000)) != 0)
    {

      if ((context_handle & 0xf) != 0)

	return ERR_ILLEGAL_CONTEXT_HANDLE;

    }
  else
    {

      if ((context_handle & 0x7) != 0)

	return ERR_ILLEGAL_CONTEXT_HANDLE;

    }


  buffer.opcode =
    (master_secret_inp << 15) | (0x1 << 11) | ((aes_type >> 1) << 10) |
    (ssl_version << 9) | (hash_type << 8) | (global_dma_mode << 7) |
    MAJOR_OP_RESUME;
  hash_size = 20 - (hash_type << 2);
  finished_size = 16 + 24 * ssl_version;

  buffer.size = handshake_length;
  buffer.param = (client_pad_length << 11) | (server_pad_length << 6);
  buffer.dlen = (32 + 32 + ROUNDUP8 (handshake_length)) >> 3;
  buffer.rlen = 8 >> 3;
  buffer.ctx_ptr = context_handle;
  buffer.group = CAVIUM_SSL_GRP;

  if (srvr_fin_msg_out == RETURN_SFM_UNENCRYPTED)

    buffer.param |= 0x1f << 6;

  if (clnt_fin_msg_out == RETURN_CFM_UNENCRYPTED)

    buffer.param |= 0x1f << 11;

  if (master_secret_inp == INPUT_ENCRYPTED)
    {

      buffer.dlen += (48 >> 3);

      buffer.incnt = 4;

      buffer.inptr[0] = CAST_TO_X_PTR( encrypt_master_secret);
      buffer.insize[0] = 48;
      buffer.inoffset[0] = 48;
      buffer.inunit[0] = UNIT_8_BIT;
      buffer.inptr[1] = CAST_TO_X_PTR( client_random);
      buffer.insize[1] = 32;
      buffer.inoffset[1] = 32;
      buffer.inunit[1] = UNIT_8_BIT;
      buffer.inptr[2] = CAST_TO_X_PTR( server_random);
      buffer.insize[2] = 32;
      buffer.inoffset[2] = 32;
      buffer.inunit[2] = UNIT_8_BIT;
      buffer.inptr[3] = CAST_TO_X_PTR( handshake);
      buffer.insize[3] = handshake_length;
      buffer.inoffset[3] = ROUNDUP8 (handshake_length);
      buffer.inunit[3] = UNIT_8_BIT;

    }
  else if (master_secret_inp == READ_FROM_CONTEXT)
    {

      buffer.incnt = 3;

      buffer.inptr[0] = CAST_TO_X_PTR( client_random);
      buffer.insize[0] = 32;
      buffer.inoffset[0] = 32;
      buffer.inunit[0] = UNIT_8_BIT;
      buffer.inptr[1] = CAST_TO_X_PTR( server_random);
      buffer.insize[1] = 32;
      buffer.inoffset[1] = 32;
      buffer.inunit[1] = UNIT_8_BIT;
      buffer.inptr[2] = CAST_TO_X_PTR( handshake);
      buffer.insize[2] = handshake_length;
      buffer.inoffset[2] = ROUNDUP8 (handshake_length);
      buffer.inunit[2] = UNIT_8_BIT;

    }

  buffer.outcnt = 2;

  buffer.outptr[0] = CAST_TO_X_PTR( client_finished_message);

  if (clnt_fin_msg_out == RETURN_CFM_ENCRYPTED)
    {

      buffer.rlen +=
	((ROUNDUP16 (finished_size + hash_size + 1) +
	  16 * client_pad_length) >> 3);

      buffer.outsize[0] =
	ROUNDUP16 (finished_size + hash_size + 1) + 16 * client_pad_length;
      buffer.outoffset[0] =
	ROUNDUP16 (finished_size + hash_size + 1) + 16 * client_pad_length;

    }
  else if (clnt_fin_msg_out == RETURN_CFM_UNENCRYPTED)
    {

      buffer.rlen += (finished_size >> 3);

      buffer.outsize[0] = finished_size;
      buffer.outoffset[0] = finished_size;

    }

  buffer.outunit[0] = UNIT_8_BIT;

  buffer.outptr[1] = CAST_TO_X_PTR( server_finished_message);

  if (srvr_fin_msg_out == RETURN_SFM_ENCRYPTED)
    {

      buffer.rlen +=
	((ROUNDUP16 (finished_size + hash_size + 1) +
	  16 * server_pad_length) >> 3);

      buffer.outsize[1] =
	ROUNDUP16 (finished_size + hash_size + 1) + 16 * server_pad_length;
      buffer.outoffset[1] =
	ROUNDUP16 (finished_size + hash_size + 1) + 16 * server_pad_length;

    }
  else if (srvr_fin_msg_out == RETURN_SFM_UNENCRYPTED)
    {

      buffer.rlen += (finished_size >> 3);

      buffer.outsize[1] = finished_size;
      buffer.outoffset[1] = finished_size;

    }

  buffer.outunit[1] = UNIT_8_BIT;

  buffer.req_type = request_type;
  buffer.req_queue = SSL_QUEUE;
  buffer.res_order = CAVIUM_RESPONSE_ORDERED;
  buffer.dma_mode = global_dma_mode;
  buffer.status=0;


  cond_code =
#ifdef CAVIUM_MULTICARD_API
    ioctl (gpkpdev_hdlr[dev_id], IOCTL_N1_OPERATION_CODE, (ptrlong) & buffer);
#else
    ioctl (CSP1_driver_handle, IOCTL_N1_OPERATION_CODE, (ptrlong) & buffer);
#endif


  *request_id = buffer.request_id;

  if(cond_code)
     ret_val = cond_code; /*return error val*/
  else
     ret_val = buffer.status;/*return OPERATION STATUS: SUCCESS('0')/EAGAIN */

  return ret_val;
}
#endif /* if !MC2 */



/*+****************************************************************************
 *
 * Csp1EncryptRecordRc4
 *
 * Input
 *	request_type = CAVIUM_BLOCKING or CAVIUM_NON_BLOCKING
 *	context_handle = 64-bit pointer to context (context_handle%8=0)
 *	hash_type = MD5_TYPE or SHA1_TYPE 
 *	ssl_version = VER3_0 or VER_TLS
 *	message_type = CHANGE_CIPHER_SPEC, ALERT, HANDSHAKE, or APP_DATA
 *	message_length = size of message in bytes (0<=length<=2^14+1024)
 *	message = pointer to length-byte message 
 *
 * Output
 *	record = pointer to (length + hash_size) bytes of encrypted record 
 *	request_id = Unique ID for this request
 *
 * Return Value
 *	0  = success 
 * >0 = failure or pending
 * see error_codes.txt
 *
 *-***************************************************************************/
Uint32
Csp1EncryptRecordRc4 (n1_request_type request_type,
		      Uint64 context_handle,
		      HashType hash_type,
		      SslVersion ssl_version,
		      SslPartyType ssl_party,
		      MessageType message_type,
		      Uint16 message_length,
		      Uint8 * message, Uint8 * record,
#ifdef CAVIUM_MULTICARD_API
                      Uint32 * request_id,Uint32 dev_id
#else
                      Uint32 * request_id
#endif
                   )
{
  Csp1OperationBuffer buffer;
  Uint32 cond_code;
  Uint32 ret_val;
  Uint16 hash_size;
  Uint64 context_offset;

  memset(&buffer,0,sizeof(Csp1OperationBuffer));
  if (ssl_party == SSL_SERVER)
    context_offset = 8 * 62;
  else
    context_offset = 8 * 22;

  if ((context_handle & UINT64_C(0x8000000000000000)) != 0)
    {

      if ((context_handle & 0xf) != 0)

	return ERR_ILLEGAL_CONTEXT_HANDLE;

    }
  else
    {

      if ((context_handle & 0x7) != 0)

	return ERR_ILLEGAL_CONTEXT_HANDLE;

    }

  if (message_length > 0x4400)

    return ERR_ILLEGAL_INPUT_LENGTH;

#ifdef MC2
  buffer.opcode =
    (0x1 << 14) | (message_type << 12) | (global_dma_mode << 7) |
    MAJOR_OP_ENCRYPT_DECRYPT_RECORD;
  hash_size = (hash_type == SHA1_TYPE) ? 20 : 16;
  buffer.param = (hash_type) | (ssl_version << 2) | (RC4_128 << 3);
  buffer.dlen = message_length;
  buffer.rlen = message_length + hash_size;
#else

  buffer.opcode = (0x0 << 15) | (message_type << 12) | (0x0 << 10)
    | (ssl_version << 9) | (hash_type << 8) | (global_dma_mode << 7)
    | MAJOR_OP_ENCRYPT_DECRYPT_RECORD;
  hash_size = 20 - (hash_type << 2);

  buffer.size = message_length;
  buffer.param = 0;
  buffer.dlen = (ROUNDUP8 (message_length)) >> 3;
  buffer.rlen = (ROUNDUP8 (message_length + hash_size) + 8) >> 3;
#endif

  buffer.size = message_length;
  buffer.ctx_ptr = context_handle + context_offset;
  buffer.group = CAVIUM_SSL_GRP;

  buffer.incnt = 1;
  buffer.outcnt = 1;

  buffer.inptr[0] = CAST_TO_X_PTR( message);
  buffer.insize[0] = message_length;
  buffer.inoffset[0] = ROUNDUP8 (message_length);
  buffer.inunit[0] = UNIT_8_BIT;
#ifdef MC2
  buffer.inoffset[0] = message_length;
#endif

  buffer.outptr[0] = CAST_TO_X_PTR( record);
  buffer.outsize[0] = message_length + hash_size;

#ifdef MC2
  buffer.outoffset[0] = message_length + hash_size;
#else
  buffer.outoffset[0] =
    (global_dma_mode ==
     CAVIUM_DIRECT) ? ROUNDUP8 (message_length +
				hash_size) : (message_length + hash_size);
#endif
  buffer.outunit[0] = UNIT_8_BIT;

  buffer.req_type = request_type;
  buffer.req_queue = SSL_QUEUE;
  buffer.res_order = CAVIUM_RESPONSE_ORDERED;
  buffer.dma_mode = global_dma_mode;
  buffer.status=0;


  cond_code =
#ifdef CAVIUM_MULTICARD_API
    ioctl (gpkpdev_hdlr[dev_id], IOCTL_N1_OPERATION_CODE, (ptrlong) & buffer);
#else
    ioctl (CSP1_driver_handle, IOCTL_N1_OPERATION_CODE, (ptrlong) & buffer);
#endif


  *request_id = buffer.request_id;

  if(cond_code)
     ret_val = cond_code; /*return error val*/
  else
     ret_val = buffer.status;/*return OPERATION STATUS: SUCCESS('0')/EAGAIN */

  return ret_val;
}



/*+****************************************************************************
 *
 * Csp1DecryptRecordRc4
 *
 * Input
 *	request_type = CAVIUM_BLOCKING or CAVIUM_NON_BLOCKING
 *	context_handle = 64-bit pointer to context (context_handle%8=0)
 *	hash_type = MD5_TYPE or SHA1_TYPE 
 *	ssl_version = VER3_0 or VER_TLS
 *	message_type = CHANGE_CIPHER_SPEC, ALERT, HANDSHAKE, or APP_DATA
 *	record_length = size of record in bytes (0<=length<=2^14+1024)
 *	record = pointer to length-byte encrypted part of record 
 *
 * Output
 *	message = pointer to (record length - hash size) bytes 
 *	request_id = Unique ID for this request
 *
 * Return Value
 *	0  = success 
 * >0 = failure or pending
 * see error_codes.txt
 *
 *-***************************************************************************/
Uint32
Csp1DecryptRecordRc4 (n1_request_type request_type,
		      Uint64 context_handle,
		      HashType hash_type,
		      SslVersion ssl_version,
		      SslPartyType ssl_party,
		      MessageType message_type,
		      Uint16 record_length,
		      Uint8 * record, Uint8 * message,
#ifdef CAVIUM_MULTICARD_API
                      Uint32 * request_id,Uint32 dev_id
#else
                      Uint32 * request_id
#endif
                   )
{
  Csp1OperationBuffer buffer;
  Uint32 cond_code;
  Uint32 ret_val;
  Uint16 hash_size;
  Uint64 context_offset;

  memset(&buffer,0,sizeof(Csp1OperationBuffer));
  if (ssl_party == SSL_SERVER)
    context_offset = 8 * 22;
  else
    context_offset = 8 * 62;

  if ((context_handle & UINT64_C(0x8000000000000000)) != 0)
    {

      if ((context_handle & 0xf) != 0)

	return ERR_ILLEGAL_CONTEXT_HANDLE;

    }
  else
    {

      if ((context_handle & 0x7) != 0)

	return ERR_ILLEGAL_CONTEXT_HANDLE;

    }

  if (record_length > 0x4400)

    return ERR_ILLEGAL_INPUT_LENGTH;

#ifdef MC2
  buffer.opcode =
    ((0xb << 12) & (message_type << 12)) | (global_dma_mode << 7) |
    MAJOR_OP_ENCRYPT_DECRYPT_RECORD;
  hash_size = (hash_type == SHA1_TYPE) ? 20 : 16;
  buffer.param = (hash_type) | (ssl_version << 2) | (RC4_128 << 3) | (1 << 7);
  buffer.dlen = record_length;
  buffer.rlen = record_length;
  buffer.size = record_length;
#else
  buffer.opcode = (0x1 << 15) | (message_type << 12) | (0x0 << 10)
    | (ssl_version << 9) | (hash_type << 8) | (global_dma_mode << 7)
    | MAJOR_OP_ENCRYPT_DECRYPT_RECORD;
  hash_size = 20 - (hash_type << 2);

  buffer.size = record_length;
  buffer.param = 0;
  buffer.dlen = (ROUNDUP8 (record_length)) >> 3;
  buffer.rlen = (ROUNDUP8 (record_length) + 8) >> 3;
#endif
  buffer.ctx_ptr = context_handle + context_offset;
  buffer.group = CAVIUM_SSL_GRP;

  buffer.incnt = 1;
  buffer.outcnt = 1;

  buffer.inptr[0] = CAST_TO_X_PTR( record);
  buffer.insize[0] = record_length;
  buffer.inoffset[0] = ROUNDUP8 (record_length);
  buffer.inunit[0] = UNIT_8_BIT;

#ifdef MC2
  buffer.inoffset[0] = record_length;
#endif
  buffer.outptr[0] = CAST_TO_X_PTR( message);
  buffer.outsize[0] = record_length;
#ifdef MC2
  buffer.outoffset[0] = record_length;
#else
  buffer.outoffset[0] =
    (global_dma_mode ==
     CAVIUM_DIRECT) ? ROUNDUP8 (record_length) : record_length;
#endif
  buffer.outunit[0] = UNIT_8_BIT;

#ifdef MC2
  buffer.outoffset[0] = record_length;
#endif

  buffer.req_type = request_type;
  buffer.req_queue = SSL_QUEUE;
  buffer.res_order = CAVIUM_RESPONSE_ORDERED;
  buffer.dma_mode = global_dma_mode;
  buffer.status=0;


  cond_code =
#ifdef CAVIUM_MULTICARD_API
    ioctl (gpkpdev_hdlr[dev_id], IOCTL_N1_OPERATION_CODE, (ptrlong) & buffer);
#else
    ioctl (CSP1_driver_handle, IOCTL_N1_OPERATION_CODE, (ptrlong) & buffer);
#endif


  *request_id = buffer.request_id;

  if(cond_code)
     ret_val = cond_code; /*return error val*/
  else
     ret_val = buffer.status;/*return OPERATION STATUS: SUCCESS('0')/EAGAIN */

  return ret_val;
}



/*+****************************************************************************
 *
 * Csp1EncryptRecord3Des
 *
 * Input
 *	request_type = CAVIUM_BLOCKING or CAVIUM_NON_BLOCKING
 *	context_handle = 64-bit pointer to context (context_handle%8=0)
 *	hash_type = MD5_TYPE or SHA1_TYPE 
 *	ssl_version = VER3_0 or VER_TLS
 *	message_type = CHANGE_CIPHER_SPEC, ALERT, HANDSHAKE, or APP_DATA
 *	pad_length = size of extra padding in 8-byte blocks
 *	message_length = size of input in bytes (0<=length<=2^14+1024)
 *	message = pointer to length-byte input message
 *
 * Output
 *	record_length = pointer to length of the encrypted part of the record in bytes
 *	record = pointer to *record_length-byte output 
 *	request_id = Unique ID for this request
 *
 * Return Value
 *	0  = success 
 * >0 = failure or pending
 * see error_codes.txt
 *
 *-***************************************************************************/
Uint32
Csp1EncryptRecord3Des (n1_request_type request_type,
		       Uint64 context_handle,
		       HashType hash_type,
		       SslVersion ssl_version,
		       SslPartyType ssl_party,
		       MessageType message_type,
		       Uint16 pad_length,
		       Uint16 message_length,
		       Uint8 * message,
		       Uint16 * record_length,
		       Uint8 * record,
#ifdef CAVIUM_MULTICARD_API
                       Uint32 * request_id,Uint32 dev_id
#else
                       Uint32 * request_id
#endif
                   )
{
  Csp1OperationBuffer buffer;
  Uint32 cond_code;
  Uint32 ret_val;
  Uint16 hash_size;
  Uint64 context_offset;

  memset(&buffer,0,sizeof(Csp1OperationBuffer));
  if (ssl_party == SSL_SERVER)
    context_offset = 8 * 34;
  else
    context_offset = 8 * 22;

  if ((context_handle & UINT64_C(0x8000000000000000)) != 0)
    {

      if ((context_handle & 0xf) != 0)

	return ERR_ILLEGAL_CONTEXT_HANDLE;

    }
  else
    {

      if ((context_handle & 0x7) != 0)

	return ERR_ILLEGAL_CONTEXT_HANDLE;

    }

  if (message_length > 0x4400)

    return ERR_ILLEGAL_INPUT_LENGTH;

#ifdef MC2
  buffer.opcode =
    (0x1 << 14) | (message_type << 12) | (global_dma_mode << 7) |
    MAJOR_OP_ENCRYPT_DECRYPT_RECORD;
  hash_size = (hash_type == SHA1_TYPE) ? 20 : 16;

  *record_length = ROUNDUP8 (message_length + hash_size + 1);
  buffer.size = message_length;
  buffer.param = (hash_type) | (ssl_version << 2) | (DES << 3);
  buffer.dlen = message_length;
  buffer.rlen = *record_length;
#else

  buffer.opcode = (0x0 << 14) | (message_type << 12) | (0x1 << 10)
    | (ssl_version << 9) | (hash_type << 8) | (global_dma_mode << 7)
    | MAJOR_OP_ENCRYPT_DECRYPT_RECORD;
  hash_size = 20 - (hash_type << 2);

  *record_length = ROUNDUP8 (message_length + hash_size + 1) + 8 * pad_length;

  buffer.size = message_length;
  buffer.param = pad_length;
  buffer.dlen = (ROUNDUP8 (message_length)) >> 3;
  buffer.rlen = (*record_length + 8) >> 3;
#endif
  buffer.ctx_ptr = context_handle + context_offset;
  buffer.group = CAVIUM_SSL_GRP;

  buffer.incnt = 1;
  buffer.outcnt = 1;

  buffer.inptr[0] = CAST_TO_X_PTR( message);
  buffer.insize[0] = message_length;
  buffer.inoffset[0] = ROUNDUP8 (message_length);
  buffer.inunit[0] = UNIT_8_BIT;

#ifdef MC2
  buffer.inoffset[0] = message_length;
#endif
  buffer.outptr[0] = CAST_TO_X_PTR( record);
  buffer.outsize[0] = *record_length;
  buffer.outoffset[0] = *record_length;
  buffer.outunit[0] = UNIT_8_BIT;

  buffer.req_type = request_type;

  buffer.req_queue = SSL_QUEUE;
  buffer.res_order = CAVIUM_RESPONSE_ORDERED;
  buffer.dma_mode = global_dma_mode;
  buffer.status=0;

  
  cond_code =
#ifdef CAVIUM_MULTICARD_API
    ioctl (gpkpdev_hdlr[dev_id], IOCTL_N1_OPERATION_CODE, (ptrlong) & buffer);
#else
    ioctl (CSP1_driver_handle, IOCTL_N1_OPERATION_CODE, (ptrlong) & buffer);
#endif


  *request_id = buffer.request_id;

  if(cond_code)
     ret_val = cond_code; /*return error val*/
  else
     ret_val = buffer.status;/*return OPERATION STATUS: SUCCESS('0')/EAGAIN */

  return ret_val;
}



/*+****************************************************************************
 *
 * Csp1DecryptRecord3Des
 *
 * Input
 *	request_type = CAVIUM_BLOCKING or CAVIUM_NON_BLOCKING
 *	context_handle = 64-bit pointer to context (context_handle%8=0)
 *	hash_type = MD5_TYPE or SHA1_TYPE 
 *	ssl_version = VER3_0 or VER_TLS
 *	message_type = CHANGE_CIPHER_SPEC, ALERT, HANDSHAKE, or APP_DATA
 *	record_length = size of the encrypted part of the input record in bytes 
 *		(length%8=0, 0<=length<=2^14+1024)
 *	record = pointer to length-byte encrypted part of the input record
 *
 * Output
 *	message_length = pointer to length in bytes of the decrypted message
 *	message = pointer to *message_length-byte output 
 *	request_id = Unique ID for this request
 *
 * Return Value
 *	0  = success 
 * >0 = failure or pending
 * see error_codes.txt
 *
 *-***************************************************************************/
Uint32
Csp1DecryptRecord3Des (n1_request_type request_type,
		       Uint64 context_handle,
		       HashType hash_type,
		       SslVersion ssl_version,
		       SslPartyType ssl_party,
		       MessageType message_type,
		       Uint16 record_length,
		       Uint8 * record,
		       Uint16 * message_length,
		       Uint8 * message,
#ifdef CAVIUM_MULTICARD_API
                       Uint32 * request_id,Uint32 dev_id
#else
                       Uint32 * request_id
#endif
                   )
{
  Csp1OperationBuffer buffer;
  Uint32 cond_code;
  Uint32 ret_val;
  Uint16 hash_size;
  Uint64 context_offset;

  memset(&buffer,0,sizeof(Csp1OperationBuffer));
  if (ssl_party == SSL_SERVER)
    context_offset = 8 * 22;
  else
    context_offset = 8 * 34;
#if defined(CSP1_API_DEBUG)
  if ((context_handle & UINT64_C(0x8000000000000000)) != 0)
    {

      if ((context_handle & 0xf) != 0)

	return ERR_ILLEGAL_CONTEXT_HANDLE;

    }
  else
    {

      if ((context_handle & 0x7) != 0)

	return ERR_ILLEGAL_CONTEXT_HANDLE;

    }

  if ((record_length > 0x4400) || ((record_length & 0x7) != 0))

    return ERR_ILLEGAL_INPUT_LENGTH;
#endif

#ifdef MC2
  buffer.opcode =
    ((0xb << 12) & (message_type << 12)) | (global_dma_mode << 7) |
    MAJOR_OP_ENCRYPT_DECRYPT_RECORD;
  hash_size = (hash_type == SHA1_TYPE) ? 20 : 16;

  buffer.size = record_length;
  buffer.param = (hash_type) | (ssl_version << 2) | (DES << 3) | (1 << 7);
  buffer.dlen = 16 + record_length;
  buffer.rlen = record_length;

#else
  buffer.opcode = (0x2 << 14) | (message_type << 12) | (0x1 << 10)
    | (ssl_version << 9) | (hash_type << 8) | (global_dma_mode << 7)
    | MAJOR_OP_ENCRYPT_DECRYPT_RECORD;
  hash_size = 20 - (hash_type << 2);

  buffer.size = record_length;
  buffer.param = 0;
  buffer.dlen = (16 + record_length) >> 3;
  buffer.rlen = (record_length + 8) >> 3;
#endif
  buffer.ctx_ptr = context_handle + context_offset;
  buffer.group = CAVIUM_SSL_GRP;

  buffer.incnt = 2;
  buffer.outcnt = 1;

  buffer.inptr[0] = CAST_TO_X_PTR(record + record_length - 16);
  buffer.insize[0] = 16;
  buffer.inoffset[0] = 16;
  buffer.inunit[0] = UNIT_8_BIT;
  buffer.inptr[1] = CAST_TO_X_PTR( record);
  buffer.insize[1] = record_length;
  buffer.inoffset[1] = record_length;
  buffer.inunit[1] = UNIT_8_BIT;

  buffer.outptr[0] = CAST_TO_X_PTR( message);
  buffer.outsize[0] = record_length;
  buffer.outoffset[0] = record_length;
  buffer.outunit[0] = UNIT_8_BIT;

  buffer.req_type = request_type;

  buffer.req_queue = SSL_QUEUE;
  buffer.res_order = CAVIUM_RESPONSE_ORDERED;
  buffer.dma_mode = global_dma_mode;
  buffer.status=0;


  cond_code =
#ifdef CAVIUM_MULTICARD_API
    ioctl (gpkpdev_hdlr[dev_id], IOCTL_N1_OPERATION_CODE, (ptrlong) & buffer);
#else
    ioctl (CSP1_driver_handle, IOCTL_N1_OPERATION_CODE, (ptrlong) & buffer);
#endif


  *request_id = buffer.request_id;

  if(cond_code)
     ret_val = cond_code; /*return error val*/
  else
     ret_val = buffer.status;/*return OPERATION STATUS: SUCCESS('0')/EAGAIN */

  *message_length = record_length - hash_size
    - *(Uint8 *) (message + record_length - 1) - 1;

  return ret_val;
}


#ifndef MC2
/*+****************************************************************************
 *
 * Csp1DecryptRecord3DesRecover
 *
 * Input
 *	request_type = CAVIUM_BLOCKING or CAVIUM_NON_BLOCKING
 *	context_handle = 64-bit pointer to context (context_handle%8=0)
 *	hash_type = MD5_TYPE or SHA1_TYPE 
 *	ssl_version = VER3_0 or VER_TLS
 *	message_type = CHANGE_CIPHER_SPEC, ALERT, HANDSHAKE, or APP_DATA
 *	record_length = size of the encrypted part of the input record in bytes 
 *		(length%8=0, 0<=length<=2^14+1024)
 *	record = pointer to length-byte encrypted part of the input record
 *
 * Output
 *	message_length = pointer to length in bytes of the decrypted message
 *	message = pointer to *message_length-byte output, 
 *	request_id = Unique ID for this request
 *
 * Return Value
 *	0  = success 
 * >0 = failure or pending
 * see error_codes.txt
 *
 *-***************************************************************************/
Uint32
Csp1DecryptRecord3DesRecover (n1_request_type request_type,
			      Uint64 context_handle,
			      HashType hash_type,
			      SslVersion ssl_version,
			      SslPartyType ssl_party,
			      MessageType message_type,
			      Uint16 record_length,
			      Uint8 * record,
			      Uint16 * message_length,
			      Uint8 * message,
#ifdef CAVIUM_MULTICARD_API
                              Uint32 * request_id,Uint32 dev_id
#else
                              Uint32 * request_id
#endif
                   )
{
  Csp1OperationBuffer buffer;
  Uint32 cond_code;
  Uint32 ret_val;
  Uint16 hash_size;
  Uint64 context_offset;

  memset(&buffer,0,sizeof(Csp1OperationBuffer));
  if (ssl_party == SSL_SERVER)
    context_offset = 8 * 22;
  else
    context_offset = 8 * 34;

  if ((context_handle & UINT64_C(0x8000000000000000)) != 0)
    {

      if ((context_handle & 0xf) != 0)

	return ERR_ILLEGAL_CONTEXT_HANDLE;

    }
  else
    {

      if ((context_handle & 0x7) != 0)

	return ERR_ILLEGAL_CONTEXT_HANDLE;

    }

  if ((record_length > 0x4400) || ((record_length & 0x7) != 0))

    return ERR_ILLEGAL_INPUT_LENGTH;


  buffer.opcode = (0x3 << 14) | (message_type << 12) | (0x1 << 10)
    | (ssl_version << 9) | (hash_type << 8) | (global_dma_mode << 7)
    | MAJOR_OP_ENCRYPT_DECRYPT_RECORD;
  hash_size = 20 - (hash_type << 2);

  buffer.size = record_length;
  buffer.param = 0;
  buffer.dlen = (16 + record_length) >> 3;
  buffer.rlen = (record_length + 8) >> 3;
  buffer.ctx_ptr = context_handle + context_offset;
  buffer.group = CAVIUM_SSL_GRP;

  buffer.incnt = 2;
  buffer.outcnt = 1;

  buffer.inptr[0] = CAST_TO_X_PTR(record + record_length - 16);
  buffer.insize[0] = 16;
  buffer.inoffset[0] = 16;
  buffer.inunit[0] = UNIT_8_BIT;
  buffer.inptr[1] = CAST_TO_X_PTR( record);
  buffer.insize[1] = record_length;
  buffer.inoffset[1] = record_length;
  buffer.inunit[1] = UNIT_8_BIT;

  buffer.outptr[0] = CAST_TO_X_PTR( message);
  buffer.outsize[0] = record_length;
  buffer.outoffset[0] = record_length;
  buffer.outunit[0] = UNIT_8_BIT;

  buffer.req_type = request_type;

  buffer.req_queue = SSL_QUEUE;
  buffer.res_order = CAVIUM_RESPONSE_ORDERED;
  buffer.dma_mode = global_dma_mode;
  buffer.status=0;


  cond_code =
#ifdef CAVIUM_MULTICARD_API
    ioctl (gpkpdev_hdlr[dev_id], IOCTL_N1_OPERATION_CODE, (ptrlong) & buffer);
#else
    ioctl (CSP1_driver_handle, IOCTL_N1_OPERATION_CODE, (ptrlong) & buffer);
#endif


  *request_id = buffer.request_id;
  
  if(cond_code)
     ret_val = cond_code; /*return error val*/
  else
     ret_val = buffer.status;/*return OPERATION STATUS: SUCCESS('0')/EAGAIN */

  *message_length = record_length - hash_size
    - *(Uint8 *) (message + record_length - 1) - 1;

  return ret_val;
}
#endif



/*+****************************************************************************
 *
 * Csp1EncryptRecordAes
 *
 * Input
 *	request_type = CAVIUM_BLOCKING or CAVIUM_NON_BLOCKING
 *	context_handle = 64-bit pointer to context (context_handle%8=0)
 *	hash_type = MD5_TYPE or SHA1_TYPE (MD5 hash_size = 16, SHA1 hash_size = 20)
 *	ssl_version = VER3_0 or VER_TLS
 *	aes_type = AES_128 or AES_256
 *	message_type = CHANGE_CIPHER_SPEC, ALERT, HANDSHAKE, or APP_DATA
 *	pad_length = size of extra padding in 8-byte blocks
 *	message_length = size of input in bytes (0<=length<=2^14+1024)
 *	message = pointer to length-byte input
 *
 * Output
 *	record_length = pointer to length of the encrypted part of the record in bytes
 *	record = pointer to *record_length-byte output, 
 *	request_id = Unique ID for this request
 *
 * Return Value
 *	0  = success 
 * >0 = failure or pending
 * see error_codes.txt
 *
 *-***************************************************************************/
Uint32
Csp1EncryptRecordAes (n1_request_type request_type,
		      Uint64 context_handle,
		      HashType hash_type,
		      SslVersion ssl_version,
		      SslPartyType ssl_party,
		      AesType aes_type,
		      MessageType message_type,
		      Uint16 pad_length,
		      Uint16 message_length,
		      Uint8 * message,
		      Uint16 * record_length,
		      Uint8 * record,
#ifdef CAVIUM_MULTICARD_API
                      Uint32 * request_id,Uint32 dev_id
#else
                      Uint32 * request_id
#endif
                   )
{
  Csp1OperationBuffer buffer;
  Uint32 cond_code;
  Uint32 ret_val;
  Uint16 hash_size;
  Uint64 context_offset;

  memset(&buffer,0,sizeof(Csp1OperationBuffer));
  if (ssl_party == SSL_SERVER)
    context_offset = 8 * 38;
  else
    context_offset = 8 * 22;

  if ((context_handle & UINT64_C(0x8000000000000000)) != 0)
    {

      if ((context_handle & 0xf) != 0)

	return ERR_ILLEGAL_CONTEXT_HANDLE;

    }
  else
    {

      if ((context_handle & 0x7) != 0)

	return ERR_ILLEGAL_CONTEXT_HANDLE;

    }

  if (message_length > 0x4400)

    return ERR_ILLEGAL_INPUT_LENGTH;

#ifdef MC2
  buffer.opcode =
    (0x1 << 14) | (message_type << 12) | (global_dma_mode << 7) |
    MAJOR_OP_ENCRYPT_DECRYPT_RECORD;
  hash_size = (hash_type == SHA1_TYPE) ? 20 : 16;

  *record_length = ROUNDUP16 (message_length + hash_size + 1);
  buffer.size = message_length;
  buffer.param = (hash_type) | (ssl_version << 2) | (aes_type << 3);
  buffer.dlen = message_length;
  buffer.rlen = *record_length;
#else
  buffer.opcode =
    (0x0 << 14) | (message_type << 12) | (0x1 << 11) | ((aes_type >> 1) << 10)
    | (ssl_version << 9) | (hash_type << 8) | (global_dma_mode << 7) |
    MAJOR_OP_ENCRYPT_DECRYPT_RECORD;
  hash_size = 20 - (hash_type << 2);

  *record_length =
    ROUNDUP16 (message_length + hash_size + 1) + 16 * pad_length;

  buffer.size = message_length;
  buffer.param = (Uint16) (pad_length);
  buffer.dlen = (ROUNDUP8 (message_length)) >> 3;
  buffer.rlen = (*record_length + 8) >> 3;
#endif
  buffer.ctx_ptr = context_handle + context_offset;
  buffer.group = CAVIUM_SSL_GRP;

  buffer.incnt = 1;
  buffer.outcnt = 1;

  buffer.inptr[0] = CAST_TO_X_PTR( message);
  buffer.insize[0] = message_length;
  buffer.inoffset[0] = ROUNDUP8 (message_length);
  buffer.inunit[0] = UNIT_8_BIT;

#ifdef MC2
  buffer.inoffset[0] = message_length;
#endif
  buffer.outptr[0] = CAST_TO_X_PTR( record);
  buffer.outsize[0] = *record_length;
  buffer.outoffset[0] = *record_length;
  buffer.outunit[0] = UNIT_8_BIT;

  buffer.req_type = request_type;


  buffer.req_queue = SSL_QUEUE;
  buffer.res_order = CAVIUM_RESPONSE_ORDERED;
  buffer.dma_mode = global_dma_mode;
  buffer.status=0;


  cond_code =
#ifdef CAVIUM_MULTICARD_API
    ioctl (gpkpdev_hdlr[dev_id], IOCTL_N1_OPERATION_CODE, (ptrlong) & buffer);
#else
    ioctl (CSP1_driver_handle, IOCTL_N1_OPERATION_CODE, (ptrlong) & buffer);
#endif


  *request_id = buffer.request_id;

  if(cond_code)
     ret_val = cond_code; /*return error val*/
  else
     ret_val = buffer.status;/*return OPERATION STATUS: SUCCESS('0')/EAGAIN */

  return ret_val;
}



/*+****************************************************************************
 *
 * Csp1DecryptRecordAes
 *
 * Input
 *	request_type = CAVIUM_BLOCKING or CAVIUM_NON_BLOCKING
 *	context_handle = 64-bit pointer to context (context_handle%8=0)
 *	hash_type = MD5_TYPE or SHA1_TYPE 
 *	ssl_version = VER3_0 or VER_TLS
 *	aes_type = AES_128 or AES_256
 *	message_type = CHANGE_CIPHER_SPEC, ALERT, HANDSHAKE, or APP_DATA
 *	record_length = size of input in bytes (length%16=0, 0<=length<=2^14+1024)
 *	record = pointer to length-byte input
 *
 * Output
 *	message_length = pointer to length in bytes of the decrypted message
 *	message = pointer to *message_length-byte output
 *	request_id = Unique ID for this request
 *
 * Return Value
 *	0  = success 
 * >0 = failure or pending
 * see error_codes.txt
 *
 *-***************************************************************************/
Uint32
Csp1DecryptRecordAes (n1_request_type request_type,
		      Uint64 context_handle,
		      HashType hash_type,
		      SslVersion ssl_version,
		      SslPartyType ssl_party,
		      AesType aes_type,
		      MessageType message_type,
		      Uint16 record_length,
		      Uint8 * record,
		      Uint16 * message_length,
		      Uint8 * message,
#ifdef CAVIUM_MULTICARD_API
                      Uint32 * request_id,Uint32 dev_id
#else
                      Uint32 * request_id
#endif
                   )
{
  Csp1OperationBuffer buffer;
  Uint32 cond_code;
  Uint32 ret_val;
  Uint16 hash_size;
  Uint64 context_offset;

  memset(&buffer,0,sizeof(Csp1OperationBuffer));
  if (ssl_party == SSL_SERVER)
    context_offset = 8 * 22;
  else
    context_offset = 8 * 38;

  if ((context_handle & UINT64_C(0x8000000000000000)) != 0)
    {

      if ((context_handle & 0xf) != 0)

	return ERR_ILLEGAL_CONTEXT_HANDLE;

    }
  else
    {

      if ((context_handle & 0x7) != 0)

	return ERR_ILLEGAL_CONTEXT_HANDLE;

    }

  if ((record_length > 0x4400) || ((record_length & 0xf) != 0))

    return ERR_ILLEGAL_INPUT_LENGTH;

#ifdef MC2
  buffer.opcode =
    ((0xb << 12) & (message_type << 12)) | (global_dma_mode << 7) |
    MAJOR_OP_ENCRYPT_DECRYPT_RECORD;
  hash_size = (hash_type == SHA1_TYPE) ? 20 : 16;

  buffer.size = record_length;
  buffer.param =
    (hash_type) | (ssl_version << 2) | (aes_type << 3) | (1 << 7);
  buffer.dlen = 32 + record_length;
  buffer.rlen = record_length;
#else
  buffer.opcode =
    (0x2 << 14) | (message_type << 12) | (0x1 << 11) | ((aes_type >> 1) << 10)
    | (ssl_version << 9) | (hash_type << 8) | (global_dma_mode << 7) |
    MAJOR_OP_ENCRYPT_DECRYPT_RECORD;
  hash_size = 20 - (hash_type << 2);

  buffer.size = record_length;
  buffer.param = 0;
  buffer.dlen = (32 + record_length) >> 3;
  buffer.rlen = (record_length + 8) >> 3;
#endif
  buffer.ctx_ptr = context_handle + context_offset;
  buffer.group = CAVIUM_SSL_GRP;

  buffer.incnt = 2;
  buffer.outcnt = 1;

  buffer.inptr[0] = CAST_TO_X_PTR(record + record_length - 32);
  buffer.insize[0] = 32;
  buffer.inoffset[0] = 32;
  buffer.inunit[0] = UNIT_8_BIT;
  buffer.inptr[1] = CAST_TO_X_PTR( record);
  buffer.insize[1] = record_length;
  buffer.inoffset[1] = record_length;
  buffer.inunit[1] = UNIT_8_BIT;

  buffer.outptr[0] = CAST_TO_X_PTR( message);
  buffer.outsize[0] = record_length;
  buffer.outoffset[0] = record_length;
  buffer.outunit[0] = UNIT_8_BIT;

  buffer.req_type = request_type;

  buffer.req_queue = SSL_QUEUE;
  buffer.res_order = CAVIUM_RESPONSE_ORDERED;
  buffer.dma_mode = global_dma_mode;
  buffer.status=0;


  cond_code =
#ifdef CAVIUM_MULTICARD_API
    ioctl (gpkpdev_hdlr[dev_id], IOCTL_N1_OPERATION_CODE, (ptrlong) & buffer);
#else
    ioctl (CSP1_driver_handle, IOCTL_N1_OPERATION_CODE, (ptrlong) & buffer);
#endif


  *request_id = buffer.request_id;

  if(cond_code)
     ret_val = cond_code; /*return error val*/
  else
     ret_val = buffer.status;/*return OPERATION STATUS: SUCCESS('0')/EAGAIN */

  *message_length = record_length - hash_size
    - *(Uint8 *) (message + record_length - 1) - 1;

  return ret_val;
}

#ifndef MC2

/*+****************************************************************************
 *
 * Csp1DecryptRecordAesRecover
 *
 * Input
 *	request_type = CAVIUM_BLOCKING or CAVIUM_NON_BLOCKING
 *	context_handle = 64-bit pointer to context (context_handle%8=0)
 *	hash_type = MD5_TYPE or SHA1_TYPE (MD5 hash_size = 16, SHA1 hash_size = 20)
 *	ssl_version = VER3_0 or VER_TLS
 *	aes_type = AES_128 or AES_256
 *	message_type = CHANGE_CIPHER_SPEC, ALERT, HANDSHAKE, or APP_DATA
 *	record_length = size of input in bytes (length%16=0, 0<=length<=2^14+1024)
 *	record = pointer to length-byte input
 *
 * Output
 *	message_length = pointer to length in bytes of the decrypted message
 *	message = pointer to *message_length-byte output
 *	request_id = Unique ID for this request
 *
 * Return Value
 *	0  = success 
 * >0 = failure or pending
 * see error_codes.txt
 *
 *-***************************************************************************/
Uint32
Csp1DecryptRecordAesRecover (n1_request_type request_type,
			     Uint64 context_handle,
			     HashType hash_type,
			     SslVersion ssl_version,
			     SslPartyType ssl_party,
			     AesType aes_type,
			     MessageType message_type,
			     Uint16 record_length,
			     Uint8 * record,
			     Uint16 * message_length,
			     Uint8 * message,
#ifdef CAVIUM_MULTICARD_API
                             Uint32 * request_id,Uint32 dev_id
#else
                             Uint32 * request_id
#endif
                   )
{
  Csp1OperationBuffer buffer;
  Uint32 cond_code;
  Uint32 ret_val;
  Uint16 hash_size;
  Uint64 context_offset;

  memset(&buffer,0,sizeof(Csp1OperationBuffer));
  if (ssl_party == SSL_SERVER)
    context_offset = 8 * 22;
  else
    context_offset = 8 * 38;

  if ((context_handle & UINT64_C(0x8000000000000000)) != 0)
    {

      if ((context_handle & 0xf) != 0)

	return ERR_ILLEGAL_CONTEXT_HANDLE;

    }
  else
    {

      if ((context_handle & 0x7) != 0)

	return ERR_ILLEGAL_CONTEXT_HANDLE;

    }

  if ((record_length > 0x4400) || ((record_length & 0xf) != 0))

    return ERR_ILLEGAL_INPUT_LENGTH;


  buffer.opcode =
    (0x3 << 14) | (message_type << 12) | (0x1 << 11) | ((aes_type >> 1) << 10)
    | (ssl_version << 9) | (hash_type << 8) | (global_dma_mode << 7) |
    MAJOR_OP_ENCRYPT_DECRYPT_RECORD;
  hash_size = 20 - (hash_type << 2);

  buffer.size = record_length;
  buffer.param = 0;
  buffer.dlen = (32 + record_length) >> 3;
  buffer.rlen = (record_length + 8) >> 3;
  buffer.ctx_ptr = context_handle + context_offset;
  buffer.group = CAVIUM_SSL_GRP;

  buffer.incnt = 2;
  buffer.outcnt = 1;

  buffer.inptr[0] = CAST_TO_X_PTR (record + record_length - 32);
  buffer.insize[0] = 32;
  buffer.inoffset[0] = 32;
  buffer.inunit[0] = UNIT_8_BIT;
  buffer.inptr[1] = CAST_TO_X_PTR(record);
  buffer.insize[1] = record_length;
  buffer.inoffset[1] = record_length;
  buffer.inunit[1] = UNIT_8_BIT;

  buffer.outptr[0] = CAST_TO_X_PTR(message);
  buffer.outsize[0] = record_length;
  buffer.outoffset[0] = record_length;
  buffer.outunit[0] = UNIT_8_BIT;

  buffer.req_type = request_type;

  buffer.req_queue = SSL_QUEUE;
  buffer.res_order = CAVIUM_RESPONSE_ORDERED;
  buffer.dma_mode = global_dma_mode;
  buffer.status=0;


  cond_code =
#ifdef CAVIUM_MULTICARD_API
    ioctl (gpkpdev_hdlr[dev_id], IOCTL_N1_OPERATION_CODE, (ptrlong) & buffer);
#else
    ioctl (CSP1_driver_handle, IOCTL_N1_OPERATION_CODE, (ptrlong) & buffer);
#endif


  *request_id = buffer.request_id;
  
  if(cond_code)
     ret_val = cond_code; /*return error val*/
  else
     ret_val = buffer.status;/*return OPERATION STATUS: SUCCESS('0')/EAGAIN */

  *message_length = record_length - hash_size
    - *(Uint8 *) (message + record_length - 1) - 1;

  return ret_val;
}

#endif



/*+****************************************************************************
 *
 * Csp1RsaSsl20ServerFullRc4
 *
 * Does a full SSL2.0 handshake on the server with RSA <= 2048 bits. 
 *
 *
 * Supported ciphers
 *	SSL_CK_RC4_128_WITH_MD5
 *	SSL_CK_RC4_128_EXPORT40_WITH_MD5
 *
 *
 * Input
 *	request_type = CAVIUM_BLOCKING or CAVIUM_NON_BLOCKING
 *	context_handle = 64-bit byte-pointer to context (context_handle%8=0)
 *	key_handle = pointer to 64-bit key memory handle
 *	rc4_type = RC4_128 or RC4_EXPORT_40
 *	client_master_secret = master key received in client-master-key handshake message.
 *	clear_master_secret_length = length (in bytes) of clear portion of client_master_secret
 *	encrypted_master_secret_length = length (in bytes) of encrypted portion of client_master_secret
 *	modlength = size of RSA operation in bytes (64<=modlength<=256, modlength%8=0)	
 *	challenge = pointer to challenge data.
 *	challenge_length = length (in bytes) of challenge data.
 *	connection_id = pointer to 16 bytes of connection ID.
 *	session_id = pointer to 16 bytes of Session ID.
 *
 *
 * Output
 *	client_finished = pointer to encrypted part of client finished message 
 *	server_finished = pointer to encrypted part of server finished message 
 *	server_verify =  pointer to encrypted part of server verify message 
 *	master_secret = master secret to used in session caching for reuse.
 *	master_secret_length = size in bytes of master secret.
 *	request_id = Unique ID for this request
 *
 * Return Value
 *	0  = success 
 * >0 = failure or pending
 * see error_codes.txt
 *
 *
 * Context format:
 *	Context is left in a state where it can be used for record processing:
 *	Word	
 *	0-15	reserved for hashing
 *	16-21	master secret
 *	To server
 *	22		Sequence number
 *	23		Unused
 *	24-15	Rc4 Key
 *	26-59	Rc4 State
 *	To client
 *	60		Sequence number
 *	61		Unused
 *	62-63	Rc4 Key
 *	64-97	Rc4 State
 *
 *
 *-***************************************************************************/

Uint32
Csp1RsaSsl20ServerFullRc4 (n1_request_type request_type,
			   Uint64 context_handle,
			   Uint64 * key_handle,
			   Rc4Type rc4_type,
			   Uint8 * client_master_secret,
			   Uint16 clear_master_secret_length,
			   Uint16 encrypted_master_secret_length,
			   Uint16 modlength,
			   Uint8 * challenge,
			   Uint16 challenge_length,
			   Uint8 * connection_id,
			   Uint8 * session_id,
			   Uint8 * client_finished,
			   Uint8 * server_finished,
			   Uint8 * server_verify,
			   Uint8 * master_secret,
			   Uint16 * master_secret_length,
#ifdef CAVIUM_MULTICARD_API
                           Uint32 * request_id,Uint32 dev_id
#else
                           Uint32 * request_id
#endif
                   )
{
#ifdef MC2
  return ERR_OPERATION_NOT_SUPPORTED;
#else

  int ek, key_size, finished_size, ret = 1, i = 0, is_export = 0;
  Uint64 ctx_ptr, out_length = 0;
  Uint64 read_seq = 0, write_seq = 0;
  Uint32 seq = 0, dummy = 0;
  Uint8 *enc_ms = NULL, *temp = NULL, *ms, *p, md5_1[16],
    md5_2[16], temp_hash[24], mac[16], local_client_finished[40];

  enc_ms = alloca (modlength);
  if (enc_ms == NULL)
    {
      ret = ERR_MEMORY_ALLOC_FAILURE;
      goto err_full;
    }
  memset (enc_ms, 0, modlength);

  temp = alloca (modlength);
  if (temp == NULL)
    {
      ret = ERR_MEMORY_ALLOC_FAILURE;
      goto err_full;
    }

  ms = alloca (modlength);
  if (ms == NULL)
    {
      ret = ERR_MEMORY_ALLOC_FAILURE;
      goto err_full;
    }

  if (encrypted_master_secret_length < modlength)
    {
      p = &client_master_secret[clear_master_secret_length];
      pkp_leftfill (p, encrypted_master_secret_length, temp, modlength);
      memcpy (enc_ms, temp, modlength);
      memset (temp, 0, modlength);
    }
  else				/* encrypted master secret length should be equal to modlength or we are deep in trouble. */
    memcpy (enc_ms, &client_master_secret[clear_master_secret_length],
	    encrypted_master_secret_length);

  swap_word_openssl (temp, enc_ms, modlength);

  if (*key_handle & 0x1000000000000ULL)
    {
      /* key is in crt form */
      ret = Csp1Pkcs1v15CrtDec (CAVIUM_BLOCKING,
				RESULT_PTR,
				0,
				KEY_HANDLE,
				*key_handle,
				BT2,
				modlength,
				NULL,
				NULL,
				NULL,
				NULL, NULL, temp, ms, &out_length,
#ifdef CAVIUM_MULTICARD_API 
                                &dummy,dev_id
#else
                                &dummy
#endif
                   );

    }
  else
    {
      ret = Csp1Pkcs1v15Dec (CAVIUM_BLOCKING,
			     RESULT_PTR,
			     0,
			     KEY_HANDLE,
			     *key_handle,
			     BT2,
			     modlength,
			     NULL, NULL, temp, ms, &out_length,
#ifdef CAVIUM_MULTICARD_API
                             &dummy,dev_id
#else
                             &dummy
#endif
                   );
    }

  if (ret)
    {
      goto err_full;
    }


  /* check for bad decrypt */
  if (rc4_type == RC4_EXPORT_40)
    {
      is_export = 1;
      key_size = 16;		/* bytes */
      ek = 5;
    }
  else if (rc4_type == RC4_128)
    {
      is_export = 0;
      ek = 16;
      key_size = 16;
    }
  else
    {
      ret = ERR_OPERATION_NOT_SUPPORTED;
      goto err_full;
    }


  if ((!is_export && (out_length != key_size)) ||
      (is_export
       && ((out_length != ek)
	   || (clear_master_secret_length + out_length != key_size))))
    {
      ret = ERR_BAD_PKCS_PAD_OR_LENGTH;
      goto err_full;
    }

  memset (temp, 0, modlength);

  /*  ms will now have complete master secret */
  memcpy (temp, ms, (Uint32) out_length);
  memcpy (ms, client_master_secret, clear_master_secret_length);
  memcpy (&ms[clear_master_secret_length], temp, (Uint32) out_length);

  /* now store complete master secret to context memory */
  ctx_ptr = context_handle + (8 * OFFSET_SSL2_MASTER_SECRET);
  ret = Csp1WriteContext (CAVIUM_BLOCKING, ctx_ptr,
			  (Uint16) (clear_master_secret_length +
				    (Uint32) out_length), ms,
#ifdef CAVIUM_MULTICARD_API
                               &dummy,dev_id
#else
                               &dummy
#endif
                   );

  if (ret)
    {
      goto err_full;
    }

  /* generate key material */
  i = clear_master_secret_length + (Uint32) out_length;
  p = temp;

  memcpy (temp, ms, i);
  temp += i;

  memcpy (temp, "\x30", 1);
  temp += 1;

  memcpy (temp, challenge, challenge_length);
  temp += challenge_length;

  memcpy (temp, connection_id, 16);
  temp = p;

  ret =
    Csp1Handshake (CAVIUM_BLOCKING, context_handle,
		   (i + 1 + challenge_length + 16), temp, md5_1, temp_hash,
#ifdef CAVIUM_MULTICARD_API
                    &dummy,dev_id
#else
                    &dummy
#endif
                   );
  if (ret)
    {
      goto err_full;
    }

  temp[i] = '\x31';
  ret =
    Csp1Handshake (CAVIUM_BLOCKING, context_handle,
		   (i + 1 + challenge_length + 16), temp, md5_2, temp_hash,
#ifdef CAVIUM_MULTICARD_API
		   &dummy,dev_id
#else
		   &dummy
#endif
                   );
  if (ret)
    {
      goto err_full;
    }

  /* generate rc4 state and store key */
  /* To client */
  ctx_ptr = context_handle + (8 * OFFSET_SSL2_RC4_SERVER_WRITE_KM);
#ifdef CAVIUM_MULTICARD_API
  ret = Csp1WriteContext (CAVIUM_BLOCKING, ctx_ptr, 16, md5_1, &dummy,dev_id);
#else
  ret = Csp1WriteContext (CAVIUM_BLOCKING, ctx_ptr, 16, md5_1, &dummy);
#endif
  if (ret)
    {
      goto err_full;
    }

  ctx_ptr = context_handle + (8 * OFFSET_SSL2_RC4_SERVER_WRITE_STATE);
#ifdef CAVIUM_MULTICARD_API
  ret = Csp1InitializeRc4 (CAVIUM_BLOCKING, ctx_ptr, 16, md5_1, &dummy,dev_id);
#else
  ret = Csp1InitializeRc4 (CAVIUM_BLOCKING, ctx_ptr, 16, md5_1, &dummy);
#endif
  if (ret)
    {
      goto err_full;
    }

  /* To server */
  ctx_ptr = context_handle + (8 * OFFSET_SSL2_RC4_SERVER_READ_KM);
#ifdef CAVIUM_MULTICARD_API
  ret = Csp1WriteContext (CAVIUM_BLOCKING, ctx_ptr, 16, md5_2, &dummy,dev_id);
#else
  ret = Csp1WriteContext (CAVIUM_BLOCKING, ctx_ptr, 16, md5_2, &dummy);
#endif
  if (ret)
    {
      goto err_full;
    }

  ctx_ptr = context_handle + (8 * OFFSET_SSL2_RC4_SERVER_READ_STATE);
#ifdef CAVIUM_MULTICARD_API
  ret = Csp1InitializeRc4 (CAVIUM_BLOCKING, ctx_ptr, 16, md5_2, &dummy,dev_id);
#else
  ret = Csp1InitializeRc4 (CAVIUM_BLOCKING, ctx_ptr, 16, md5_2, &dummy);
#endif
  if (ret)
    {
      goto err_full;
    }

  /* client finish decryption and validation */
  finished_size = 16 + 16 + 1;	/* 16 = connection id, 16 = md5 mac, 1=message type */
  ctx_ptr = context_handle + (8 * OFFSET_SSL2_RC4_SERVER_READ_STATE);

  ret = Csp1EncryptRc4 (CAVIUM_BLOCKING,
			ctx_ptr,
			CAVIUM_UPDATE,
			finished_size,
			client_finished, local_client_finished,
#ifdef CAVIUM_MULTICARD_API
                         &dummy,dev_id
#else
                         &dummy
#endif
                   );
  if (ret)
    {
      goto err_full;
    }

  /* mac */
  read_seq = 2;			/* client hello, client_master_secret */
  seq = htobe32 ((Uint32) read_seq);

  p = temp;
  memcpy (temp, md5_2, 16);
  temp += 16;

  memcpy (temp, &local_client_finished[16], 17);
  temp += 17;

  memcpy (temp, (Uint8 *) & seq, 4);

  temp = p;
  i = 16 + 17 + 4;

  ret = Csp1Handshake (CAVIUM_BLOCKING,
		       context_handle, i, temp, mac, temp_hash,
#ifdef CAVIUM_MULTICARD_API
                       &dummy,dev_id
#else
                       &dummy
#endif
                   );
  if (ret)
    {
      goto err_full;
    }

  /* compare mac */
  if (memcmp (local_client_finished, mac, 16))
    {
      ret = ERR_BAD_CIPHER_OR_MAC;
      goto err_full;
    }

  INC32 (read_seq);

  /* compare client finished with connection id */
  if (memcmp (&local_client_finished[16 + 1], connection_id, 16))
    {
      ret = ERR_BAD_CIPHER_OR_MAC;	/*??? */
      goto err_full;
    }


  /* generate server verify message */
  /* mac */

  write_seq = 1;		/* server hello */
  seq = htobe32 ((Uint32) write_seq);
  p = temp;

  memcpy (temp, md5_1, 16);
  temp += 16;

  temp[0] = 5;
  temp++;

  memcpy (temp, challenge, challenge_length);
  temp += challenge_length;

  memcpy (temp, (Uint8 *) & seq, 4);

  temp = p;
  i = 16 + 1 + challenge_length + 4;

  ret = Csp1Handshake (CAVIUM_BLOCKING,
		       context_handle, i, temp, mac, temp_hash,
#ifdef CAVIUM_MULTICARD_API
                       &dummy,dev_id
#else
                       &dummy
#endif
                   );
  if (ret)
    {
      goto err_full;
    }

  memcpy (server_verify, mac, 16);
  server_verify[16] = 5;	/* message type */
  memcpy (&server_verify[17], challenge, challenge_length);


  finished_size = 16 + 1 + challenge_length;	/* 16 = md5 mac, 1 = message type, */
  ctx_ptr = context_handle + (8 * OFFSET_SSL2_RC4_SERVER_WRITE_STATE);

  ret = Csp1EncryptRc4 (CAVIUM_BLOCKING,
			ctx_ptr,
			CAVIUM_UPDATE,
			finished_size, server_verify, server_verify,
#ifdef CAVIUM_MULTICARD_API
                        &dummy,dev_id
#else
                        &dummy
#endif
                   );
  if (ret)
    {
      goto err_full;
    }

  INC32 (write_seq);


  /* generate server finish message */
  /* mac */
  seq = htobe32 ((Uint32) write_seq);
  p = temp;

  memcpy (temp, md5_1, 16);
  temp += 16;

  temp[0] = 6;			/* finished message type */
  temp++;

  memcpy (temp, session_id, 16);
  temp += 16;

  memcpy (temp, (Uint8 *) & seq, 4);

  temp = p;
  i = 16 + 1 + 16 + 4;

  ret = Csp1Handshake (CAVIUM_BLOCKING,
		       context_handle, i, temp, mac, temp_hash,
#ifdef CAVIUM_MULTICARD_API
                       &dummy,dev_id
#else
                       &dummy
#endif
                   );
  if (ret)
    {
      goto err_full;
    }

  memcpy (server_finished, mac, 16);
  server_finished[16] = 6;	/* message type */
  memcpy (&server_finished[17], session_id, 16);


  finished_size = 16 + 1 + 16;	/* 16 = session_id, 1 = message type 16 = md5 mac */
  ctx_ptr = context_handle + (8 * OFFSET_SSL2_RC4_SERVER_WRITE_STATE);

  ret = Csp1EncryptRc4 (CAVIUM_BLOCKING,
			ctx_ptr,
			CAVIUM_UPDATE,
			finished_size,
			server_finished, server_finished,
#ifdef CAVIUM_MULTICARD_API
                        &dummy,dev_id
#else
                        &dummy
#endif
                   );
  if (ret)
    {
      goto err_full;
    }

  INC32 (write_seq);

  /* copy write sequence and read sequence to context memory */
  ctx_ptr = context_handle + (8 * OFFSET_SSL2_RC4_SERVER_READ_SEQ);
  ret =
    Csp1WriteContext (CAVIUM_BLOCKING, ctx_ptr, 8, (Uint8 *) & read_seq,
#ifdef CAVIUM_MULTICARD_API
                        &dummy,dev_id
#else
                        &dummy
#endif
                   );
  if (ret)
    {
      goto err_full;
    }

  ctx_ptr = context_handle + (8 * OFFSET_SSL2_RC4_SERVER_WRITE_SEQ);
  ret =
    Csp1WriteContext (CAVIUM_BLOCKING, ctx_ptr, 8, (Uint8 *) & write_seq,
#ifdef CAVIUM_MULTICARD_API
                       &dummy,dev_id
#else                
                        &dummy
#endif
                   );
  if (ret)
    {
      goto err_full;
    }


  /* return master secret */
  memcpy (master_secret, ms,
	  clear_master_secret_length + (Uint32) out_length);
  *master_secret_length = clear_master_secret_length + (Uint32) out_length;
  ret = 0;

err_full:
  return ret;
#endif
}				/* Csp1RsaSsl20ServerFullRc4 */



/*+****************************************************************************
 *
 * Csp1RsaSsl20ServerClientAuthRc4
 *
 * Generates key material, and certificate req, verify messages.
 *
 *
 * Supported ciphers
 *	SSL_CK_RC4_128_WITH_MD5
 *	SSL_CK_RC4_128_EXPORT40_WITH_MD5
 *
 *
 * Input
 *	request_type = CAVIUM_BLOCKING or CAVIUM_NON_BLOCKING
 *	context_handle = 64-bit byte-pointer to context (context_handle%8=0)
 *	key_handle = pointer to 64-bit key memory handle
 *	rc4_type = RC4_128 or RC4_EXPORT_40
 *	client_master_secret = master key received in client-master-key handshake message.
 *	clear_master_secret_length = length (in bytes) of clear portion of client_master_secret
 *	encrypted_master_secret_length = length (in bytes) of encrypted portion of client_master_secret
 *	modlength = size of RSA operation in bytes (64<=modlength<=256, modlength%8=0)	
 *	challenge = pointer to challenge data.
 *	challenge_length = length (in bytes) of challenge data.
 *	connection_id = pointer to 16 bytes of connection ID.
 *	session_id = pointer to 16 bytes of Session ID.
 *
 *
 * Output
 *	client_finished = pointer to encrypted part of client finished message 
 *	server_verify =  pointer to encrypted part of server verify message 
 *	master_secret = master secret to used in session caching for reuse.
 *	master_secret_length = size in bytes of master secret.
 *	request_id = Unique ID for this request
 *
 * Return Value
 *	0  = success 
 * >0 = failure or pending
 * see error_codes.txt
 *
 * Context format:
 *	Context is left in a state where it can be used for record processing:
 *	Word	
 *	0-15	reserved for hashing
 *	16-21	master secret
 *	To server
 *	22		Sequence number
 *	23		Unused
 *	24-15	Rc4 Key
 *	26-59	Rc4 State
 *	To client
 *	60		Sequence number
 *	61		Unused
 *	62-63	Rc4 Key
 *	64-97	Rc4 State
 *
 *
 *-***************************************************************************/

Uint32
Csp1RsaSsl20ServerClientAuthRc4 (n1_request_type request_type,
				 Uint64 context_handle,
				 Uint64 * key_handle,
				 Rc4Type rc4_type,
				 Uint8 * client_master_secret,
				 Uint16 clear_master_secret_length,
				 Uint16 encrypted_master_secret_length,
				 Uint16 modlength,
				 Uint8 * challenge,
				 Uint16 challenge_length,
				 Uint8 * connection_id,
				 Uint8 * session_id,
				 Uint8 * client_finished,
				 Uint8 auth_type,
				 Uint8 * cert_challenge,
				 Uint8 * cert_request,
				 Uint8 * server_verify,
				 Uint8 * master_secret,
				 Uint16 * master_secret_length,
#ifdef CAVIUM_MULTICARD_API
                                 Uint32 * request_id,Uint32 dev_id
#else
                                 Uint32 * request_id
#endif
                   )
{
#ifdef MC2
  return ERR_OPERATION_NOT_SUPPORTED;
#else
  int ek, key_size, finished_size, ret = 1, i = 0, is_export = 0;
  Uint64 ctx_ptr, out_length = 0;
  Uint64 read_seq = 0, write_seq = 0;
  Uint32 seq = 0, dummy = 0;
  Uint8 *enc_ms = NULL, *temp = NULL, *ms, *p, md5_1[16],
    md5_2[16], temp_hash[24], mac[16], local_client_finished[40];

  enc_ms = alloca (modlength);
  if (enc_ms == NULL)
    {
      ret = ERR_MEMORY_ALLOC_FAILURE;
      goto err_full_client_auth;
    }
  memset (enc_ms, 0, modlength);

  temp = alloca (modlength);
  if (temp == NULL)
    {
      ret = ERR_MEMORY_ALLOC_FAILURE;
      goto err_full_client_auth;
    }

  ms = alloca (modlength);
  if (ms == NULL)
    {
      ret = ERR_MEMORY_ALLOC_FAILURE;
      goto err_full_client_auth;
    }

  if (encrypted_master_secret_length < modlength)
    {
      p = &client_master_secret[clear_master_secret_length];
      pkp_leftfill (p, encrypted_master_secret_length, temp, modlength);
      memcpy (enc_ms, temp, modlength);
      memset (temp, 0, modlength);
    }
  else				/* encrypted master secret length should be equal to modlength or we are deep in trouble. */
    memcpy (enc_ms, &client_master_secret[clear_master_secret_length],
	    encrypted_master_secret_length);

  swap_word_openssl (temp, enc_ms, modlength);

  if (*key_handle & 0x1000000000000ULL)
    {
      /* key is in crt form */
      ret = Csp1Pkcs1v15CrtDec (CAVIUM_BLOCKING,
				RESULT_PTR,
				0,
				KEY_HANDLE,
				*key_handle,
				BT2,
				modlength,
				NULL,
				NULL,
				NULL,
				NULL, NULL, temp, ms, &out_length,
#ifdef CAVIUM_MULTICARD_API
                               &dummy,dev_id
#else
                               &dummy
#endif
                   );

    }
  else
    {
      ret = Csp1Pkcs1v15Dec (CAVIUM_BLOCKING,
			     RESULT_PTR,
			     0,
			     KEY_HANDLE,
			     *key_handle,
			     BT2,
			     modlength,
			     NULL, NULL, temp, ms, &out_length,
#ifdef CAVIUM_MULTICARD_API
                             &dummy,dev_id
#else
                             &dummy
#endif
                   );
    }

  if (ret)
    {
      goto err_full_client_auth;
    }


  /* check for bad decrypt */
  if (rc4_type == RC4_EXPORT_40)
    {
      is_export = 1;
      key_size = 16;		/* bytes */
      ek = 5;
    }
  else if (rc4_type == RC4_128)
    {
      is_export = 0;
      ek = 16;
      key_size = 16;
    }
  else
    {
      ret = ERR_OPERATION_NOT_SUPPORTED;
      goto err_full_client_auth;
    }


  if ((!is_export && (out_length != key_size)) ||
      (is_export
       && ((out_length != ek)
	   || (clear_master_secret_length + out_length != key_size))))
    {
      ret = ERR_BAD_PKCS_PAD_OR_LENGTH;
      goto err_full_client_auth;
    }

  memset (temp, 0, modlength);

  /*  ms will now have complete master secret */
  memcpy (temp, ms, (Uint32) out_length);
  memcpy (ms, client_master_secret, clear_master_secret_length);
  memcpy (&ms[clear_master_secret_length], temp, (Uint32) out_length);

  /* now store complete master secret to context memory */
  ctx_ptr = context_handle + (8 * OFFSET_SSL2_MASTER_SECRET);
  ret = Csp1WriteContext (CAVIUM_BLOCKING, ctx_ptr,
			  (Uint16) (clear_master_secret_length +
				    (Uint32) out_length), ms,
#ifdef CAVIUM_MULTICARD_API
                               &dummy,dev_id
#else
                               &dummy
#endif
                   );

  if (ret)
    {
      goto err_full_client_auth;
    }

  /* generate key material */
  i = clear_master_secret_length + (Uint32) out_length;
  p = temp;

  memcpy (temp, ms, i);
  temp += i;

  memcpy (temp, "\x30", 1);
  temp += 1;

  memcpy (temp, challenge, challenge_length);
  temp += challenge_length;

  memcpy (temp, connection_id, 16);
  temp = p;

  ret =
    Csp1Handshake (CAVIUM_BLOCKING, context_handle,
		   (i + 1 + challenge_length + 16), temp, md5_1, temp_hash,
#ifdef CAVIUM_MULTICARD_API
                    &dummy,dev_id
#else
                    &dummy
#endif
                   );
  if (ret)
    {
      goto err_full_client_auth;
    }

  temp[i] = '\x31';
  ret =
    Csp1Handshake (CAVIUM_BLOCKING, context_handle,
		   (i + 1 + challenge_length + 16), temp, md5_2, temp_hash,
#ifdef CAVIUM_MULTICARD_API
                    &dummy,dev_id
#else
                    &dummy
#endif
                   );
  if (ret)
    {
      goto err_full_client_auth;
    }

  /* generate rc4 state and store key */
  /* To client */
  ctx_ptr = context_handle + (8 * OFFSET_SSL2_RC4_SERVER_WRITE_KM);
#ifdef CAVIUM_MULTICARD_API
  ret = Csp1WriteContext (CAVIUM_BLOCKING, ctx_ptr, 16, md5_1, &dummy,dev_id);
#else
  ret = Csp1WriteContext (CAVIUM_BLOCKING, ctx_ptr, 16, md5_1, &dummy);
#endif
  if (ret)
    {
      goto err_full_client_auth;
    }

  ctx_ptr = context_handle + (8 * OFFSET_SSL2_RC4_SERVER_WRITE_STATE);
#ifdef CAVIUM_MULTICARD_API
  ret = Csp1InitializeRc4 (CAVIUM_BLOCKING, ctx_ptr, 16, md5_1, &dummy,dev_id);
#else
  ret = Csp1InitializeRc4 (CAVIUM_BLOCKING, ctx_ptr, 16, md5_1, &dummy);
#endif
  if (ret)
    {
      goto err_full_client_auth;
    }

  /* To server */
  ctx_ptr = context_handle + (8 * OFFSET_SSL2_RC4_SERVER_READ_KM);
#ifdef CAVIUM_MULTICARD_API
  ret = Csp1WriteContext (CAVIUM_BLOCKING, ctx_ptr, 16, md5_2, &dummy,dev_id);
#else
  ret = Csp1WriteContext (CAVIUM_BLOCKING, ctx_ptr, 16, md5_2, &dummy);
#endif
  if (ret)
    {
      goto err_full_client_auth;
    }

  ctx_ptr = context_handle + (8 * OFFSET_SSL2_RC4_SERVER_READ_STATE);
#ifdef CAVIUM_MULTICARD_API
  ret = Csp1InitializeRc4 (CAVIUM_BLOCKING, ctx_ptr, 16, md5_2, &dummy,dev_id);
#else
  ret = Csp1InitializeRc4 (CAVIUM_BLOCKING, ctx_ptr, 16, md5_2, &dummy);
#endif
  if (ret)
    {
      goto err_full_client_auth;
    }

  /* client finish decryption and validation */
  finished_size = 16 + 16 + 1;	/* 16 = connection id, 16 = md5 mac, 1=message type */
  ctx_ptr = context_handle + (8 * OFFSET_SSL2_RC4_SERVER_READ_STATE);

  ret = Csp1EncryptRc4 (CAVIUM_BLOCKING,
			ctx_ptr,
			CAVIUM_UPDATE,
			finished_size,
			client_finished, local_client_finished,
#ifdef CAVIUM_MULTICARD_API
                        &dummy,dev_id
#else
                        &dummy
#endif
                   );
  if (ret)
    {
      goto err_full_client_auth;
    }

  /* mac */
  read_seq = 2;			/* client hello, client_master_secret */
  seq = htobe32 ((Uint32) read_seq);

  p = temp;
  memcpy (temp, md5_2, 16);
  temp += 16;

  memcpy (temp, &local_client_finished[16], 17);
  temp += 17;

  memcpy (temp, (Uint8 *) & seq, 4);

  temp = p;
  i = 16 + 17 + 4;

  ret = Csp1Handshake (CAVIUM_BLOCKING,
		       context_handle, i, temp, mac, temp_hash,
#ifdef CAVIUM_MULTICARD_API
                       &dummy,dev_id
#else
                       &dummy
#endif
                   );
  if (ret)
    {
      goto err_full_client_auth;
    }

  /* compare mac */
  if (memcmp (local_client_finished, mac, 16))
    {
      ret = ERR_BAD_CIPHER_OR_MAC;
      goto err_full_client_auth;
    }

  INC32 (read_seq);

  /* compare client finished with connection id */
  if (memcmp (&local_client_finished[16 + 1], connection_id, 16))
    {
      ret = ERR_BAD_CIPHER_OR_MAC;	/*??? */
      goto err_full_client_auth;
    }


  /* generate server verify message */
  /* mac */

  write_seq = 1;		/* server hello */
  seq = htobe32 ((Uint32) write_seq);
  p = temp;

  memcpy (temp, md5_1, 16);
  temp += 16;

  temp[0] = 5;
  temp++;

  memcpy (temp, challenge, challenge_length);
  temp += challenge_length;

  memcpy (temp, (Uint8 *) & seq, 4);

  temp = p;
  i = 16 + 1 + challenge_length + 4;

  ret = Csp1Handshake (CAVIUM_BLOCKING,
		       context_handle, i, temp, mac, temp_hash,
#ifdef CAVIUM_MULTICARD_API
                       &dummy,dev_id
#else
                       &dummy
#endif
                   );
  if (ret)
    {
      goto err_full_client_auth;
    }

  memcpy (server_verify, mac, 16);
  server_verify[16] = 5;	/* message type */
  memcpy (&server_verify[17], challenge, challenge_length);


  finished_size = 16 + 1 + challenge_length;	/* 16 = md5 mac, 1 = message type, */
  ctx_ptr = context_handle + (8 * OFFSET_SSL2_RC4_SERVER_WRITE_STATE);

  ret = Csp1EncryptRc4 (CAVIUM_BLOCKING,
			ctx_ptr,
			CAVIUM_UPDATE,
			finished_size, server_verify, server_verify,
#ifdef CAVIUM_MULTICARD_API
                        &dummy,dev_id
#else
                        &dummy
#endif
                   );
  if (ret)
    {
      goto err_full_client_auth;
    }

  INC32 (write_seq);


  /* generate cert req message */
  /* mac */
  seq = htobe32 ((Uint32) write_seq);
  p = temp;

  memcpy (temp, md5_1, 16);
  temp += 16;

  temp[0] = 7;			/* cert req message type */
  temp++;

  temp[0] = auth_type;
  temp++;

  memcpy (temp, cert_challenge, 16);
  temp += 16;

  memcpy (temp, (Uint8 *) & seq, 4);

  temp = p;
  i = 16 + 1 + 1 + 16 + 4;	/* mac, message type, auth_type, cert_challenge, seq */

  ret = Csp1Handshake (CAVIUM_BLOCKING,
		       context_handle, i, temp, mac, temp_hash,
#ifdef CAVIUM_MULTICARD_API
                       &dummy,dev_id
#else
                       &dummy
#endif
                   );
  if (ret)
    {
      goto err_full_client_auth;
    }

  memcpy (cert_request, mac, 16);
  cert_request[16] = 7;		/* message type */
  cert_request[17] = auth_type;
  memcpy (&cert_request[18], cert_challenge, 16);


  finished_size = 16 + 1 + 1 + 16;	/* mac, 1 = message type, 1=auth type,  16 = cert challenge */
  ctx_ptr = context_handle + (8 * OFFSET_SSL2_RC4_SERVER_WRITE_STATE);

  ret = Csp1EncryptRc4 (CAVIUM_BLOCKING,
			ctx_ptr,
			CAVIUM_UPDATE,
			finished_size, cert_request, cert_request,
#ifdef CAVIUM_MULTICARD_API
                        &dummy,dev_id
#else
                        &dummy
#endif
                   );
  if (ret)
    {
      goto err_full_client_auth;
    }

  INC32 (write_seq);

  /* copy write sequence and read sequence to context memory */
  ctx_ptr = context_handle + (8 * OFFSET_SSL2_RC4_SERVER_READ_SEQ);
  ret =
    Csp1WriteContext (CAVIUM_BLOCKING, ctx_ptr, 8, (Uint8 *) & read_seq,
#ifdef CAVIUM_MULTICARD_API
                      &dummy,dev_id
#else
                      &dummy
#endif
                   );
  if (ret)
    {
      goto err_full_client_auth;
    }

  ctx_ptr = context_handle + (8 * OFFSET_SSL2_RC4_SERVER_WRITE_SEQ);
  ret =
    Csp1WriteContext (CAVIUM_BLOCKING, ctx_ptr, 8, (Uint8 *) & write_seq,
#ifdef CAVIUM_MULTICARD_API
                      &dummy,dev_id
#else
                      &dummy
#endif
                   );
  if (ret)
    {
      goto err_full_client_auth;
    }


  /* return master secret */
  memcpy (master_secret, ms,
	  clear_master_secret_length + (Uint32) out_length);
  *master_secret_length = clear_master_secret_length + (Uint32) out_length;
  ret = 0;

err_full_client_auth:
  return ret;
#endif
}				/*Csp1RsaSsl20ServerClientAuthRc4 */




/*+****************************************************************************
 *
 * Csp1Ssl20ResumeRc4
 *
 * Resumes a previously negotiated session.
 *
 *
 * Supported ciphers
 *	SSL_CK_RC4_128_WITH_MD5
 *	SSL_CK_RC4_128_EXPORT40_WITH_MD5
 *
 *
 * Input
 *	request_type = CAVIUM_BLOCKING or CAVIUM_NON_BLOCKING
 *	context_handle = 64-bit byte-pointer to context (context_handle%8=0)
 *	key_handle = pointer to 64-bit key memory handle
 *	rc4_type = RC4_128 or RC4_EXPORT_40
 *	master_secret = master secret from previous session.
 *	master_secret_length = size in bytes of master secret.
 *	challenge = pointer to challenge data.
 *	challenge_length = length (in bytes) of challenge data.
 *	connection_id = pointer to 16 bytes of connection ID.
 *	session_id = pointer to 16 bytes of Session ID.
 *
 *
 * Output
 *	client_finished = pointer to encrypted part of client finished message 
 *	server_finished = pointer to encrypted part of server finished message 
 *	server_verify =  pointer to encrypted part of server verify message 
 *	request_id = Unique ID for this request
 *
 * Return Value
 *	0  = success 
 * >0 = failure or pending
 * see error_codes.txt
 *
 *
 * Context format:
 *	Context is left in a state where it can be used for record processing:
 *	Word	
 *	0-15	reserved for hashing
 *	16-21	master secret
 *	To server
 *	22		Sequence number
 *	23		Unused
 *	24-15	Rc4 Key
 *	26-59	Rc4 State
 *	To client
 *	60		Sequence number
 *	61		Unused
 *	62-63	Rc4 Key
 *	64-97	Rc4 State
 *
 *
 *-***************************************************************************/

Uint32
Csp1Ssl20ResumeRc4 (n1_request_type request_type,
		    Uint64 context_handle,
		    Uint64 * key_handle,
		    Rc4Type rc4_type,
		    Uint8 * master_secret,
		    Uint16 master_secret_length,
		    Uint8 * challenge,
		    Uint16 challenge_length,
		    Uint8 * connection_id,
		    Uint8 * session_id,
		    Uint8 * client_finished,
		    Uint8 * server_finished,
		    Uint8 * server_verify,
#ifdef CAVIUM_MULTICARD_API
                    Uint32 * request_id,Uint32 dev_id

#else
                    Uint32 * request_id

#endif
                   )
{
#ifdef MC2
  return ERR_OPERATION_NOT_SUPPORTED;
#else

  int key_size, finished_size, ret = 1, i = 0;
  Uint64 ctx_ptr;
  Uint64 read_seq = 0, write_seq = 0;
  Uint32 seq = 0, dummy = 0;
  Uint8 *temp = NULL, *p, md5_1[16], md5_2[16], temp_hash[24], mac[16],
    local_client_finished[40];
  temp = alloca (256);
  if (temp == NULL)
    {
      ret = ERR_MEMORY_ALLOC_FAILURE;
      goto err_resume;
    }

  /* Set key sizes */
  if (rc4_type == RC4_EXPORT_40)
    key_size = 16;		/* bytes */
  else if (rc4_type == RC4_128)
    key_size = 16;
  else
    {
      ret = ERR_OPERATION_NOT_SUPPORTED;
      goto err_resume;
    }

  /* store master secret to context memory */
  ctx_ptr = context_handle + (8 * OFFSET_SSL2_MASTER_SECRET);
  ret =
    Csp1WriteContext (CAVIUM_BLOCKING, ctx_ptr, master_secret_length,
		      master_secret,
#ifdef CAVIUM_MULTICARD_API
                      &dummy,dev_id
#else
                      &dummy
#endif
                   );
  if (ret)
    {
      goto err_resume;
    }

  /* generate key material */
  i = master_secret_length;
  p = temp;

  memcpy (temp, master_secret, i);
  temp += i;

  memcpy (temp, "\x30", 1);
  temp += 1;

  memcpy (temp, challenge, challenge_length);
  temp += challenge_length;

  memcpy (temp, connection_id, 16);
  temp = p;

  ret =
    Csp1Handshake (CAVIUM_BLOCKING, context_handle,
		   (i + 1 + challenge_length + 16), temp, md5_1, temp_hash,
#ifdef CAVIUM_MULTICARD_API
                    &dummy,dev_id
#else
                    &dummy
#endif
                   );
  if (ret)
    {
      goto err_resume;
    }

  temp[i] = '\x31';
  ret =
    Csp1Handshake (CAVIUM_BLOCKING, context_handle,
		   (i + 1 + challenge_length + 16), temp, md5_2, temp_hash,
#ifdef CAVIUM_MULTICARD_API
                   &dummy,dev_id
#else
                   &dummy
#endif
                   );
  if (ret)
    {
      goto err_resume;
    }

  /* generate rc4 state and store key */
  /* To client */
  ctx_ptr = context_handle + (8 * OFFSET_SSL2_RC4_SERVER_WRITE_KM);
#ifdef CAVIUM_MULTICARD_API
  ret = Csp1WriteContext (CAVIUM_BLOCKING, ctx_ptr, 16, md5_1, &dummy,dev_id);
#else
  ret = Csp1WriteContext (CAVIUM_BLOCKING, ctx_ptr, 16, md5_1, &dummy);
#endif
  if (ret)
    {
      goto err_resume;
    }

  ctx_ptr = context_handle + (8 * OFFSET_SSL2_RC4_SERVER_WRITE_STATE);
#ifdef CAVIUM_MULTICARD_API
  ret = Csp1InitializeRc4 (CAVIUM_BLOCKING, ctx_ptr, 16, md5_1, &dummy,dev_id);
#else
  ret = Csp1InitializeRc4 (CAVIUM_BLOCKING, ctx_ptr, 16, md5_1, &dummy);
#endif
  if (ret)
    {
      goto err_resume;
    }

  /* To server */
  ctx_ptr = context_handle + (8 * OFFSET_SSL2_RC4_SERVER_READ_KM);
#ifdef CAVIUM_MULTICARD_API
  ret = Csp1WriteContext (CAVIUM_BLOCKING, ctx_ptr, 16, md5_2, &dummy,dev_id);
#else
  ret = Csp1WriteContext (CAVIUM_BLOCKING, ctx_ptr, 16, md5_2, &dummy);
#endif
  if (ret)
    {
      goto err_resume;
    }

  ctx_ptr = context_handle + (8 * OFFSET_SSL2_RC4_SERVER_READ_STATE);
#ifdef CAVIUM_MULTICARD_API
  ret = Csp1InitializeRc4 (CAVIUM_BLOCKING, ctx_ptr, 16, md5_2, &dummy,dev_id);
#else
  ret = Csp1InitializeRc4 (CAVIUM_BLOCKING, ctx_ptr, 16, md5_2, &dummy);
#endif
  if (ret)
    {
      goto err_resume;
    }

  /* client finish decryption and validation */
  finished_size = 16 + 16 + 1;	/* 16 = connection id, 16 = md5 mac, 1=message type */
  ctx_ptr = context_handle + (8 * OFFSET_SSL2_RC4_SERVER_READ_STATE);

  ret = Csp1EncryptRc4 (CAVIUM_BLOCKING,
			ctx_ptr,
			CAVIUM_UPDATE,
			finished_size,
			client_finished, local_client_finished,
#ifdef CAVIUM_MULTICARD_API
                        &dummy,dev_id
#else
                        &dummy
#endif
                   );
  if (ret)
    {
      goto err_resume;
    }

  /* mac */
  read_seq = 1;			/* client hello */
  seq = htobe32 ((Uint32) read_seq);

  p = temp;
  memcpy (temp, md5_2, 16);
  temp += 16;

  memcpy (temp, &local_client_finished[16], 17);
  temp += 17;

  memcpy (temp, (Uint8 *) & seq, 4);

  temp = p;
  i = 16 + 17 + 4;

  ret = Csp1Handshake (CAVIUM_BLOCKING,
		       context_handle, i, temp, mac, temp_hash,
#ifdef CAVIUM_MULTICARD_API
                       &dummy,dev_id
#else
                       &dummy
#endif
                   );
  if (ret)
    {
      goto err_resume;
    }

  /* compare mac */
  if (memcmp (local_client_finished, mac, 16))
    {
      ret = ERR_BAD_CIPHER_OR_MAC;
      goto err_resume;
    }

  INC32 (read_seq);

  /* compare client finished with connection id */
  if (memcmp (&local_client_finished[16 + 1], connection_id, 16))
    {
      ret = ERR_BAD_CIPHER_OR_MAC;	/*??? */
      goto err_resume;
    }


  /* generate server verify message */
  /* mac */

  write_seq = 1;		/* server hello */
  seq = htobe32 ((Uint32) write_seq);
  p = temp;

  memcpy (temp, md5_1, 16);
  temp += 16;

  temp[0] = 5;
  temp++;

  memcpy (temp, challenge, challenge_length);
  temp += challenge_length;

  memcpy (temp, (Uint8 *) & seq, 4);

  temp = p;
  i = 16 + 1 + challenge_length + 4;

  ret = Csp1Handshake (CAVIUM_BLOCKING,
		       context_handle, i, temp, mac, temp_hash,
#ifdef CAVIUM_MULTICARD_API
                       &dummy,dev_id
#else
                       &dummy
#endif
                   );
  if (ret)
    {
      goto err_resume;
    }

  memcpy (server_verify, mac, 16);
  server_verify[16] = 5;	/* message type */
  memcpy (&server_verify[17], challenge, challenge_length);


  finished_size = 16 + 1 + challenge_length;	/* 16 = md5 mac, 1 = message type, */
  ctx_ptr = context_handle + (8 * OFFSET_SSL2_RC4_SERVER_WRITE_STATE);

  ret = Csp1EncryptRc4 (CAVIUM_BLOCKING,
			ctx_ptr,
			CAVIUM_UPDATE,
			finished_size, server_verify, server_verify,
#ifdef CAVIUM_MULTICARD_API
                        &dummy,dev_id
#else
                        &dummy
#endif
                   );
  if (ret)
    {
      goto err_resume;
    }

  INC32 (write_seq);


  /* generate server finish message */
  /* mac */
  seq = htobe32 ((Uint32) write_seq);
  p = temp;

  memcpy (temp, md5_1, 16);
  temp += 16;

  temp[0] = 6;			/* finished message type */
  temp++;

  memcpy (temp, session_id, 16);
  temp += 16;

  memcpy (temp, (Uint8 *) & seq, 4);

  temp = p;
  i = 16 + 1 + 16 + 4;

  ret = Csp1Handshake (CAVIUM_BLOCKING,
		       context_handle, i, temp, mac, temp_hash,
#ifdef CAVIUM_MULTICARD_API
                       &dummy,dev_id
#else
                       &dummy
#endif
                   );
  if (ret)
    {
      goto err_resume;
    }

  memcpy (server_finished, mac, 16);
  server_finished[16] = 6;	/* message type */
  memcpy (&server_finished[17], session_id, 16);


  finished_size = 16 + 1 + 16;	/* 16 = session_id, 1 = message type 16 = md5 mac */
  ctx_ptr = context_handle + (8 * OFFSET_SSL2_RC4_SERVER_WRITE_STATE);

  ret = Csp1EncryptRc4 (CAVIUM_BLOCKING,
			ctx_ptr,
			CAVIUM_UPDATE,
			finished_size,
			server_finished, server_finished,
#ifdef CAVIUM_MULTICARD_API
                        &dummy,dev_id
#else
                        &dummy
#endif
                   );
  if (ret)
    {
      goto err_resume;
    }

  INC32 (write_seq);

  /* copy write sequence and read sequence to context memory */
  ctx_ptr = context_handle + (8 * OFFSET_SSL2_RC4_SERVER_READ_SEQ);
  ret =
    Csp1WriteContext (CAVIUM_BLOCKING, ctx_ptr, 8, (Uint8 *) & read_seq,
#ifdef CAVIUM_MULTICARD_API
                      &dummy,dev_id
#else
                      &dummy
#endif
                   );
  if (ret)
    {
      goto err_resume;
    }

  ctx_ptr = context_handle + (8 * OFFSET_SSL2_RC4_SERVER_WRITE_SEQ);
  ret =
    Csp1WriteContext (CAVIUM_BLOCKING, ctx_ptr, 8, (Uint8 *) & write_seq,
#ifdef CAVIUM_MULTICARD_API
                       &dummy,dev_id
#else
                       &dummy
#endif
                   );
  if (ret)
    {
      goto err_resume;
    }

  ret = 0;

err_resume:
  return ret;
#endif
}				/* Csp1Ssl20Resumec4 */







/*+****************************************************************************
 *
 * Csp1Ssl20ResumeClientAuthRc4
 *
 * Uses master key from a previous session, generates key material, cert req,
 * and verify messages.
 *
 *
 * Supported ciphers
 *	SSL_CK_RC4_128_WITH_MD5
 *	SSL_CK_RC4_128_EXPORT40_WITH_MD5
 *
 *
 * Input
 *	request_type = CAVIUM_BLOCKING or CAVIUM_NON_BLOCKING
 *	context_handle = 64-bit byte-pointer to context (context_handle%8=0)
 *	key_handle = pointer to 64-bit key memory handle
 *	rc4_type = RC4_128 or RC4_EXPORT_40
 *	master_secret = master secret from previous session.
 *	master_secret_length = size in bytes of master secret.
 *	challenge = pointer to challenge data.
 *	challenge_length = length (in bytes) of challenge data.
 *	connection_id = pointer to 16 bytes of connection ID.
 *	session_id = pointer to 16 bytes of Session ID.
 *	client_finished = pointer to encrypted part of client finished message 
 *	auth_type = client auth type
 *	cert_challenge = cert challenge
 *
 * Output
 *	cert_request = pointer to encrypted part of cert request message 
 *	server_verify =  pointer to encrypted part of server verify message 
 *	request_id = Unique ID for this request
 *
 * Return Value
 *	0  = success 
 * >0 = failure or pending
 * see error_codes.txt
 *
 * Context format:
 *	Context is left in a state where it can be used for record processing:
 *	Word	
 *	0-15	reserved for hashing
 *	16-21	master secret
 *	To server
 *	22		Sequence number
 *	23		Unused
 *	24-15	Rc4 Key
 *	26-59	Rc4 State
 *	To client
 *	60		Sequence number
 *	61		Unused
 *	62-63	Rc4 Key
 *	64-97	Rc4 State
 *
 *
 *-***************************************************************************/

Uint32
Csp1Ssl20ResumeClientAuthRc4 (n1_request_type request_type,
			      Uint64 context_handle,
			      Uint64 * key_handle,
			      Rc4Type rc4_type,
			      Uint8 * master_secret,
			      Uint16 master_secret_length,
			      Uint8 * challenge,
			      Uint16 challenge_length,
			      Uint8 * connection_id,
			      Uint8 * session_id,
			      Uint8 * client_finished,
			      Uint8 auth_type,
			      Uint8 * cert_challenge,
			      Uint8 * cert_request,
			      Uint8 * server_verify,
#ifdef CAVIUM_MULTICARD_API
                              Uint32 * request_id,Uint32 dev_id
#else
                              Uint32 * request_id
#endif
                   )
{
#ifdef MC2
  return ERR_OPERATION_NOT_SUPPORTED;
#else

  int key_size, finished_size, ret = 1, i = 0;
  Uint64 ctx_ptr;
  Uint64 read_seq = 0, write_seq = 0;
  Uint32 seq = 0, dummy = 0;
  Uint8 *temp = NULL, *p, md5_1[16], md5_2[16], temp_hash[24], mac[16],
    local_client_finished[40];
  temp = alloca (256);
  if (temp == NULL)
    {
      ret = ERR_MEMORY_ALLOC_FAILURE;
      goto err_resume_client_auth;
    }

  /* Set key sizes */
  if (rc4_type == RC4_EXPORT_40)
    key_size = 16;		/* bytes */
  else if (rc4_type == RC4_128)
    key_size = 16;
  else
    {
      ret = ERR_OPERATION_NOT_SUPPORTED;
      goto err_resume_client_auth;
    }

  /* store master secret to context memory */
  ctx_ptr = context_handle + (8 * OFFSET_SSL2_MASTER_SECRET);
  ret =
    Csp1WriteContext (CAVIUM_BLOCKING, ctx_ptr, master_secret_length,
		      master_secret,
#ifdef CAVIUM_MULTICARD_API
                      &dummy,dev_id
#else
                      &dummy
#endif
                   );
  if (ret)
    {
      goto err_resume_client_auth;
    }

  /* generate key material */
  i = master_secret_length;
  p = temp;

  memcpy (temp, master_secret, i);
  temp += i;

  memcpy (temp, "\x30", 1);
  temp += 1;

  memcpy (temp, challenge, challenge_length);
  temp += challenge_length;

  memcpy (temp, connection_id, 16);
  temp = p;

  ret =
    Csp1Handshake (CAVIUM_BLOCKING, context_handle,
		   (i + 1 + challenge_length + 16), temp, md5_1, temp_hash,
#ifdef CAVIUM_MULTICARD_API
                   &dummy,dev_id
#else
                   &dummy
#endif
                   );
  if (ret)
    {
      goto err_resume_client_auth;
    }

  temp[i] = '\x31';
  ret =
    Csp1Handshake (CAVIUM_BLOCKING, context_handle,
		   (i + 1 + challenge_length + 16), temp, md5_2, temp_hash,
#ifdef CAVIUM_MULTICARD_API
                    &dummy,dev_id
#else
                    &dummy
#endif
                   );
  if (ret)
    {
      goto err_resume_client_auth;
    }

  /* generate rc4 state and store key */
  /* To client */
  ctx_ptr = context_handle + (8 * OFFSET_SSL2_RC4_SERVER_WRITE_KM);
#ifdef CAVIUM_MULTICARD_API
  ret = Csp1WriteContext (CAVIUM_BLOCKING, ctx_ptr, 16, md5_1, &dummy,dev_id);
#else
  ret = Csp1WriteContext (CAVIUM_BLOCKING, ctx_ptr, 16, md5_1, &dummy);
#endif
  if (ret)
    {
      goto err_resume_client_auth;
    }

  ctx_ptr = context_handle + (8 * OFFSET_SSL2_RC4_SERVER_WRITE_STATE);
#ifdef CAVIUM_MULTICARD_API
  ret = Csp1InitializeRc4 (CAVIUM_BLOCKING, ctx_ptr, 16, md5_1, &dummy,dev_id);
#else
  ret = Csp1InitializeRc4 (CAVIUM_BLOCKING, ctx_ptr, 16, md5_1, &dummy);
#endif
  if (ret)
    {
      goto err_resume_client_auth;
    }

  /* To server */
  ctx_ptr = context_handle + (8 * OFFSET_SSL2_RC4_SERVER_READ_KM);
#ifdef CAVIUM_MULTICARD_API
  ret = Csp1WriteContext (CAVIUM_BLOCKING, ctx_ptr, 16, md5_2, &dummy,dev_id);
#else
  ret = Csp1WriteContext (CAVIUM_BLOCKING, ctx_ptr, 16, md5_2, &dummy);
#endif
  if (ret)
    {
      goto err_resume_client_auth;
    }

  ctx_ptr = context_handle + (8 * OFFSET_SSL2_RC4_SERVER_READ_STATE);
#ifdef CAVIUM_MULTICARD_API
  ret = Csp1InitializeRc4 (CAVIUM_BLOCKING, ctx_ptr, 16, md5_2, &dummy,dev_id);
#else
  ret = Csp1InitializeRc4 (CAVIUM_BLOCKING, ctx_ptr, 16, md5_2, &dummy);
#endif
  if (ret)
    {
      goto err_resume_client_auth;
    }

  /* client finish decryption and validation */
  finished_size = 16 + 16 + 1;	/* 16 = connection id, 16 = md5 mac, 1=message type */
  ctx_ptr = context_handle + (8 * OFFSET_SSL2_RC4_SERVER_READ_STATE);

  ret = Csp1EncryptRc4 (CAVIUM_BLOCKING,
			ctx_ptr,
			CAVIUM_UPDATE,
			finished_size,
			client_finished, local_client_finished,
#ifdef CAVIUM_MULTICARD_API
                        &dummy,dev_id
#else
                        &dummy
#endif
                   );
  if (ret)
    {
      goto err_resume_client_auth;
    }

  /* mac */
  read_seq = 1;			/* client hello */
  seq = htobe32 ((Uint32) read_seq);

  p = temp;
  memcpy (temp, md5_2, 16);
  temp += 16;

  memcpy (temp, &local_client_finished[16], 17);
  temp += 17;

  memcpy (temp, (Uint8 *) & seq, 4);

  temp = p;
  i = 16 + 17 + 4;

  ret = Csp1Handshake (CAVIUM_BLOCKING,
		       context_handle, i, temp, mac, temp_hash,
#ifdef CAVIUM_MULTICARD_API
                       &dummy,dev_id
#else
                       &dummy
#endif
                   );
  if (ret)
    {
      goto err_resume_client_auth;
    }

  /* compare mac */
  if (memcmp (local_client_finished, mac, 16))
    {
      ret = ERR_BAD_CIPHER_OR_MAC;
      goto err_resume_client_auth;
    }

  INC32 (read_seq);

  /* compare client finished with connection id */
  if (memcmp (&local_client_finished[16 + 1], connection_id, 16))
    {
      ret = ERR_BAD_CIPHER_OR_MAC;	/*??? */
      goto err_resume_client_auth;
    }


  /* generate server verify message */
  /* mac */

  write_seq = 1;		/* server hello */
  seq = htobe32 ((Uint32) write_seq);
  p = temp;

  memcpy (temp, md5_1, 16);
  temp += 16;

  temp[0] = 5;
  temp++;

  memcpy (temp, challenge, challenge_length);
  temp += challenge_length;

  memcpy (temp, (Uint8 *) & seq, 4);

  temp = p;
  i = 16 + 1 + challenge_length + 4;

  ret = Csp1Handshake (CAVIUM_BLOCKING,
		       context_handle, i, temp, mac, temp_hash,
#ifdef CAVIUM_MULTICARD_API
                       &dummy,dev_id
#else
                       &dummy
#endif
                   );
  if (ret)
    {
      goto err_resume_client_auth;
    }

  memcpy (server_verify, mac, 16);
  server_verify[16] = 5;	/* message type */
  memcpy (&server_verify[17], challenge, challenge_length);


  finished_size = 16 + 1 + challenge_length;	/* 16 = md5 mac, 1 = message type, */
  ctx_ptr = context_handle + (8 * OFFSET_SSL2_RC4_SERVER_WRITE_STATE);

  ret = Csp1EncryptRc4 (CAVIUM_BLOCKING,
			ctx_ptr,
			CAVIUM_UPDATE,
			finished_size, server_verify, server_verify,
#ifdef CAVIUM_MULTICARD_API
                         &dummy,dev_id
#else
                         &dummy
#endif
                   );
  if (ret)
    {
      goto err_resume_client_auth;
    }

  INC32 (write_seq);


  /* generate cert req message */
  /* mac */
  seq = htobe32 ((Uint32) write_seq);
  p = temp;

  memcpy (temp, md5_1, 16);
  temp += 16;

  temp[0] = 7;			/* cert req message type */
  temp++;

  temp[0] = auth_type;
  temp++;

  memcpy (temp, cert_challenge, 16);
  temp += 16;

  memcpy (temp, (Uint8 *) & seq, 4);

  temp = p;
  i = 16 + 1 + 1 + 16 + 4;	/* mac, message type, auth_type, cert_challenge, seq */

  ret = Csp1Handshake (CAVIUM_BLOCKING,
		       context_handle, i, temp, mac, temp_hash,
#ifdef CAVIUM_MULTICARD_API
                        &dummy,dev_id
#else
                        &dummy
#endif
                   );
  if (ret)
    {
      goto err_resume_client_auth;
    }

  memcpy (cert_request, mac, 16);
  cert_request[16] = 7;		/* message type */
  cert_request[17] = auth_type;
  memcpy (&cert_request[18], cert_challenge, 16);


  finished_size = 16 + 1 + 1 + 16;	/* mac, 1 = message type, 1=auth type,  16 = cert challenge */
  ctx_ptr = context_handle + (8 * OFFSET_SSL2_RC4_SERVER_WRITE_STATE);

  ret = Csp1EncryptRc4 (CAVIUM_BLOCKING,
			ctx_ptr,
			CAVIUM_UPDATE,
			finished_size, cert_request, cert_request,
#ifdef CAVIUM_MULTICARD_API
                        &dummy,dev_id
#else
                        &dummy
#endif
                   );
  if (ret)
    {
      goto err_resume_client_auth;
    }


  INC32 (write_seq);

  /* copy write sequence and read sequence to context memory */
  ctx_ptr = context_handle + (8 * OFFSET_SSL2_RC4_SERVER_READ_SEQ);
  ret =
    Csp1WriteContext (CAVIUM_BLOCKING, ctx_ptr, 8, (Uint8 *) & read_seq,
#ifdef CAVIUM_MULTICARD_API
                      &dummy,dev_id
#else
                      &dummy
#endif
                   );
  if (ret)
    {
      goto err_resume_client_auth;
    }

  ctx_ptr = context_handle + (8 * OFFSET_SSL2_RC4_SERVER_WRITE_SEQ);
  ret =
    Csp1WriteContext (CAVIUM_BLOCKING, ctx_ptr, 8, (Uint8 *) & write_seq,
#ifdef CAVIUM_MULTICARD_API
                      &dummy,dev_id
#else
                      &dummy
#endif
                   );
  if (ret)
    {
      goto err_resume_client_auth;
    }

  ret = 0;

err_resume_client_auth:
  return ret;
#endif
}				/* Csp1Ssl20ResumeClientAuthRc4 */




/*+****************************************************************************
 *
 * Csp1RsaSsl20ServerFull3Des
 *
 * Does a full SSL2.0 handshake on the server with RSA <= 2048 bits. 
 *
 *
 * Supported ciphers
 *	SSL_CK_DES_64_CBC_WITH_MD5
	SSL_CK_DES_192_EDE3_CBC_WITH_MD5
 *
 *
 * Input
 *	request_type = CAVIUM_BLOCKING or CAVIUM_NON_BLOCKING
 *	context_handle = 64-bit byte-pointer to context (context_handle%8=0)
 *	key_handle = pointer to 64-bit key memory handle
 *	des_type = DES or DES3_192
 *	client_master_secret = master key received in client-master-key handshake message.
 *	clear_master_secret_length = length (in bytes) of clear portion of client_master_secret
 *	encrypted_master_secret_length = length (in bytes) of encrypted portion of client_master_secret
 *	modlength = size of RSA operation in bytes (64<=modlength<=256, modlength%8=0)	
 *	challenge = pointer to challenge data.
 *	challenge_length = length (in bytes) of challenge data.
 *	connection_id = pointer to 16 bytes of connection ID.
 *	session_id = pointer to 16 bytes of Session ID.
 *	iv = initialization vectore sent by client
 *
 *
 * Output
 *	client_finished = pointer to encrypted part of client finished message 
 *	server_finished = pointer to encrypted part of server finished message 
 *	server_verify =  pointer to encrypted part of server verify message 
 *	master_secret = master secret to used in session caching for reuse.
 *	master_secret_length = size in bytes of master secret.
 *	request_id = Unique ID for this request
 *
 * Return Value
 *	0  = success 
 * >0 = failure or pending
 * see error_codes.txt
 *
 *
 * Context format:
 *	Context is left in a state where it can be used for record processing:
 *	Word	
 *	0-15	reserved for hashing
 *	16-21	master secret
 *	To server
 *	22		Sequence number
 *	23		Unused
 *	24		IV
 *	25-27	3Des Keys
 *	To client
 *	28		Sequence number
 *	29		Unused
 *	30		IV
 *	31-33	3Des Keys
 *
 *
 *-***************************************************************************/
Uint32
Csp1RsaSsl20ServerFull3Des (n1_request_type request_type,
			    Uint64 context_handle,
			    Uint64 * key_handle,
			    DesType des_type,
			    Uint8 * client_master_secret,
			    Uint16 clear_master_secret_length,
			    Uint16 encrypted_master_secret_length,
			    Uint16 modlength,
			    Uint8 * challenge,
			    Uint16 challenge_length,
			    Uint8 * connection_id,
			    Uint8 * session_id,
			    Uint8 * iv,
			    Uint8 * client_finished,
			    Uint8 * server_finished,
			    Uint8 * server_verify,
			    Uint8 * master_secret,
			    Uint16 * master_secret_length,
#ifdef CAVIUM_MULTICARD_API
                            Uint32 * request_id,Uint32 dev_id
#else
                            Uint32 * request_id
#endif
                   )
{
#ifdef MC2
  return ERR_OPERATION_NOT_SUPPORTED;
#else

  int ms_size, ek, key_size, finished_size, pad, ret = 1, i = 0, is_export =
    0;
  Uint64 ctx_ptr, out_length = 0;
  Uint64 read_seq = 0, write_seq = 0;
  Uint32 seq = 0, dummy = 0;
  Uint8 *enc_ms = NULL, *temp = NULL, *ms, *p, km[48],
    server_write_key[24], server_read_key[24],
    temp_hash[24], mac[16], local_client_finished[64], padb[8];

  memset (padb, 0, 8);
  enc_ms = alloca (modlength);
  if (enc_ms == NULL)
    {
      ret = ERR_MEMORY_ALLOC_FAILURE;
      goto err_full;
    }
  memset (enc_ms, 0, modlength);

  temp = alloca (modlength);
  if (temp == NULL)
    {
      ret = ERR_MEMORY_ALLOC_FAILURE;
      goto err_full;
    }

  ms = alloca (modlength);
  if (ms == NULL)
    {
      ret = ERR_MEMORY_ALLOC_FAILURE;
      goto err_full;
    }

  if (encrypted_master_secret_length < modlength)
    {
      p = &client_master_secret[clear_master_secret_length];
      pkp_leftfill (p, encrypted_master_secret_length, temp, modlength);
      memcpy (enc_ms, temp, modlength);
      memset (temp, 0, modlength);
    }
  else				/* encrypted master secret length should be equal to modlength or we are deep in trouble. */
    memcpy (enc_ms, &client_master_secret[clear_master_secret_length],
	    encrypted_master_secret_length);

  swap_word_openssl (temp, enc_ms, modlength);

  if (*key_handle & 0x1000000000000ULL)
    {
      /* key is in crt form */
      ret = Csp1Pkcs1v15CrtDec (CAVIUM_BLOCKING,
				RESULT_PTR,
				0,
				KEY_HANDLE,
				*key_handle,
				BT2,
				modlength,
				NULL,
				NULL,
				NULL,
				NULL, NULL, temp, ms, &out_length,
#ifdef CAVIUM_MULTICARD_API
                               &dummy,dev_id
#else
                               &dummy
#endif
                   );

    }
  else
    {
      ret = Csp1Pkcs1v15Dec (CAVIUM_BLOCKING,
			     RESULT_PTR,
			     0,
			     KEY_HANDLE,
			     *key_handle,
			     BT2,
			     modlength,
			     NULL, NULL, temp, ms, &out_length,
#ifdef CAVIUM_MULTICARD_API
                               &dummy,dev_id
#else
                               &dummy
#endif
                   );
    }

  if (ret)
    {
      goto err_full;
    }


  /* check for bad decrypt */
  if (des_type == DES)
    {
      is_export = 0;
      key_size = 8;		/* bytes */
      ek = 8;
    }
  else if (des_type == DES3_192)
    {
      is_export = 0;
      ek = 24;
      key_size = 24;
    }
  else
    {
      ret = ERR_OPERATION_NOT_SUPPORTED;
      goto err_full;
    }


  if ((!is_export && (out_length != key_size)) ||
      (is_export
       && ((out_length != ek)
	   || (clear_master_secret_length + out_length != key_size))))
    {
      ret = ERR_BAD_PKCS_PAD_OR_LENGTH;
      goto err_full;
    }


  memset (temp, 0, modlength);

  /*  ms will now have complete master secret */
  memcpy (temp, ms, (Uint32) out_length);
  memcpy (ms, client_master_secret, clear_master_secret_length);
  memcpy (&ms[clear_master_secret_length], temp, (Uint32) out_length);

  /* now store complete master secret to context memory */
  ctx_ptr = context_handle + (8 * OFFSET_SSL2_MASTER_SECRET);
  ret = Csp1WriteContext (CAVIUM_BLOCKING, ctx_ptr,
			  (Uint16) (clear_master_secret_length +
				    (Uint32) out_length), ms,
#ifdef CAVIUM_MULTICARD_API
                          &dummy,dev_id
#else
                          &dummy
#endif
                   );

  if (ret)
    {
      goto err_full;
    }

  /* generate key material */
  ms_size = clear_master_secret_length + (Uint32) out_length;
  p = temp;

  memcpy (temp, ms, ms_size);
  temp += ms_size;

  memcpy (temp, "\x30", 1);
  temp += 1;

  memcpy (temp, challenge, challenge_length);
  temp += challenge_length;

  memcpy (temp, connection_id, 16);
  temp = p;

  for (i = 0; i < (key_size * 2); i += 16)
    {
      ret = Csp1Handshake (CAVIUM_BLOCKING, context_handle,
			   (ms_size + 1 + challenge_length + 16),
			   temp, &km[i], temp_hash,
#ifdef CAVIUM_MULTICARD_API
                            &dummy,dev_id
#else
                            &dummy
#endif
                   );
      if (ret)
	{
	  goto err_full;
	}

      temp[ms_size]++;
    }


  /* store keys and IV to context memory */

  memcpy (temp, iv, 8);

  /* To client */
  if (key_size == 8)
    {
      memcpy (&temp[8], km, 8);
      memcpy (&temp[16], km, 8);
      memcpy (&temp[24], km, 8);
    }

  if (key_size == 24)
    {
      memcpy (&temp[8], km, 8);
      memcpy (&temp[16], &km[8], 8);
      memcpy (&temp[24], &km[16], 8);
    }

  memcpy (server_write_key, &temp[8], 24);

  ctx_ptr = context_handle + (8 * OFFSET_SSL2_3DES_SERVER_WRITE_KM);
#ifdef CAVIUM_MULTICARD_API
  ret = Csp1WriteContext (CAVIUM_BLOCKING, ctx_ptr, 32, temp, &dummy,dev_id);
#else
  ret = Csp1WriteContext (CAVIUM_BLOCKING, ctx_ptr, 32, temp, &dummy);
#endif
  if (ret)
    {
      goto err_full;
    }


  /* To server */
  if (key_size == 8)
    {
      memcpy (&temp[8], &km[8], 8);
      memcpy (&temp[16], &km[8], 8);
      memcpy (&temp[24], &km[8], 8);
    }

  if (key_size == 24)
    {
      memcpy (&temp[8], &km[24], 8);
      memcpy (&temp[16], &km[32], 8);
      memcpy (&temp[24], &km[40], 8);
    }

  memcpy (server_read_key, &temp[8], 24);

  ctx_ptr = context_handle + (8 * OFFSET_SSL2_3DES_SERVER_READ_KM);
#ifdef CAVIUM_MULTICARD_API
  ret = Csp1WriteContext (CAVIUM_BLOCKING, ctx_ptr, 32, temp, &dummy,dev_id);
#else
  ret = Csp1WriteContext (CAVIUM_BLOCKING, ctx_ptr, 32, temp, &dummy);
#endif
  if (ret)
    {
      goto err_full;
    }


  /* client finished decryption and validation. */
  finished_size = 16 + 16 + 1;	/* 16 = mc, 16 = conn_id_len, 1=message type */
  pad = 8 - (finished_size % 8);

  /* finished size after padding */
  finished_size += pad;

  ctx_ptr = context_handle + (8 * OFFSET_SSL2_3DES_SERVER_READ_KM);

  ret = Csp1Decrypt3Des (CAVIUM_BLOCKING,
			 ctx_ptr,
			 CAVIUM_UPDATE,
			 finished_size,
			 client_finished, local_client_finished,
#ifdef CAVIUM_MULTICARD_API
                         &dummy,dev_id
#else
                         &dummy
#endif
                         );
  if (ret)
    {
      goto err_full;
    }

  /* mac */
  read_seq = 2;			/* client hello, client_master_secret */
  seq = htobe32 ((Uint32) read_seq);

  p = temp;
  memcpy (temp, server_read_key, key_size);
  temp += key_size;

  memcpy (temp, &local_client_finished[16], finished_size - 16);
  temp += (finished_size - 16);

  memcpy (temp, (Uint8 *) & seq, 4);

  temp = p;
  i = key_size + (finished_size - 16) + 4;

  ret = Csp1Handshake (CAVIUM_BLOCKING,
		       context_handle, i, temp, mac, temp_hash,
#ifdef CAVIUM_MULTICARD_API
                       &dummy,dev_id
#else
                       &dummy
#endif
                 );
  if (ret)
    {
      goto err_full;
    }

  /* compare mac */
  if (memcmp (local_client_finished, mac, 16))
    {
      ret = ERR_BAD_CIPHER_OR_MAC;
      goto err_full;
    }

  INC32 (read_seq);

  /* compare client finished with connection id */
  if (memcmp (&local_client_finished[16 + 1], connection_id, 16))
    {
      ret = ERR_BAD_CIPHER_OR_MAC;	/*??? */
      goto err_full;
    }


  /* generate server verify message */
  /* mac */
  pad = 8 - ((16 + 1 + challenge_length) % 8);

  write_seq = 1;		/* server hello */
  seq = htobe32 ((Uint32) write_seq);
  p = temp;

  memcpy (temp, server_write_key, key_size);
  temp += key_size;

  temp[0] = 5;
  temp++;

  memcpy (temp, challenge, challenge_length);
  temp += challenge_length;

  memcpy (temp, padb, pad);
  temp += pad;

  memcpy (temp, (Uint8 *) & seq, 4);

  temp = p;
  i = key_size + 1 + challenge_length + pad + 4;

  ret = Csp1Handshake (CAVIUM_BLOCKING,
		       context_handle, i, temp, mac, temp_hash,
#ifdef CAVIUM_MULTICARD_API
                       &dummy,dev_id
#else
                       &dummy
#endif
                 );
  if (ret)
    {
      goto err_full;
    }

  memcpy (server_verify, mac, 16);
  server_verify[16] = 5;	/* message type */
  memcpy (&server_verify[17], challenge, challenge_length);
  memcpy (&server_verify[17 + challenge_length], padb, pad);


  finished_size = 16 + 1 + challenge_length + pad;	/* 16 = md5 mac, 1 = message type, */
  ctx_ptr = context_handle + (8 * OFFSET_SSL2_3DES_SERVER_WRITE_KM);

  ret = Csp1Encrypt3Des (CAVIUM_BLOCKING,
			 ctx_ptr,
			 CAVIUM_UPDATE,
			 finished_size, server_verify, server_verify,
#ifdef CAVIUM_MULTICARD_API
                         &dummy,dev_id
#else
                         &dummy
#endif
                 );
  if (ret)
    {
      goto err_full;
    }

  INC32 (write_seq);


  /* generate server finish message */
  /* mac */
  pad = 8 - ((16 + 1 + 16) % 8);

  seq = htobe32 ((Uint32) write_seq);
  p = temp;

  memcpy (temp, server_write_key, key_size);
  temp += key_size;

  temp[0] = 6;			/* finished message type */
  temp++;

  memcpy (temp, session_id, 16);
  temp += 16;

  memcpy (temp, padb, pad);
  temp += pad;

  memcpy (temp, (Uint8 *) & seq, 4);

  temp = p;
  i = key_size + 1 + 16 + pad + 4;

  ret = Csp1Handshake (CAVIUM_BLOCKING,
		       context_handle, i, temp, mac, temp_hash,
#ifdef CAVIUM_MULTICARD_API
                       &dummy,dev_id
#else
                       &dummy
#endif
                 );
  if (ret)
    {
      goto err_full;
    }

  memcpy (server_finished, mac, 16);
  server_finished[16] = 6;	/* message type */
  memcpy (&server_finished[17], session_id, 16);
  memcpy (&server_finished[17 + 16], padb, pad);


  finished_size = 16 + 1 + 16 + pad;	/* 16 = session_id, 1 = message type 16 = md5 mac */
  ctx_ptr = context_handle + (8 * OFFSET_SSL2_3DES_SERVER_WRITE_KM);

  ret = Csp1Encrypt3Des (CAVIUM_BLOCKING,
			 ctx_ptr,
			 CAVIUM_UPDATE,
			 finished_size,
			 server_finished, server_finished,
#ifdef CAVIUM_MULTICARD_API
                         &dummy,dev_id
#else
                         &dummy
#endif
                 );
  if (ret)
    {
      goto err_full;
    }

  INC32 (write_seq);

  /* copy write sequence and read sequence to context memory */
  ctx_ptr = context_handle + (8 * OFFSET_SSL2_3DES_SERVER_READ_SEQ);
  ret =
    Csp1WriteContext (CAVIUM_BLOCKING, ctx_ptr, 8, (Uint8 *) & read_seq,
#ifdef CAVIUM_MULTICARD_API
                      &dummy,dev_id
#else
                      &dummy
#endif
                 );
  if (ret)
    {
      goto err_full;
    }

  ctx_ptr = context_handle + (8 * OFFSET_SSL2_3DES_SERVER_WRITE_SEQ);
  ret =
    Csp1WriteContext (CAVIUM_BLOCKING, ctx_ptr, 8, (Uint8 *) & write_seq,
#ifdef CAVIUM_MULTICARD_API
                      &dummy,dev_id
#else
                      &dummy
#endif
                 );
  if (ret)
    {
      goto err_full;
    }


  /* return master secret */
  memcpy (master_secret, ms,
	  clear_master_secret_length + (Uint32) out_length);
  *master_secret_length = clear_master_secret_length + (Uint32) out_length;
  ret = 0;

err_full:
  return ret;
#endif
}				/* Csp1RsaSsl20ServerFull3Des */



/*+****************************************************************************
 *
 * Csp1RsaSsl20ServerClientAuth3Des
 *
 * Generates key material, verifies cllient finished msg, creates server verify
 * and cert request messages.
 *
 *
 * Supported ciphers
 *	SSL_CK_DES_64_CBC_WITH_MD5
	SSL_CK_DES_192_EDE3_CBC_WITH_MD5
 *
 *
 * Input
 *	request_type = CAVIUM_BLOCKING or CAVIUM_NON_BLOCKING
 *	context_handle = 64-bit byte-pointer to context (context_handle%8=0)
 *	key_handle = pointer to 64-bit key memory handle
 *	des_type = DES or DES3_192
 *	client_master_secret = master key received in client-master-key handshake message.
 *	clear_master_secret_length = length (in bytes) of clear portion of client_master_secret
 *	encrypted_master_secret_length = length (in bytes) of encrypted portion of client_master_secret
 *	modlength = size of RSA operation in bytes (64<=modlength<=256, modlength%8=0)	
 *	challenge = pointer to challenge data.
 *	challenge_length = length (in bytes) of challenge data.
 *	connection_id = pointer to 16 bytes of connection ID.
 *	session_id = pointer to 16 bytes of Session ID.
 *	iv = initialization vectore sent by client
 *	auth_type =  client auth type
 *	cert_challenge =  certficate challenge.
 *
 *
 * Output
 *	client_finished = pointer to encrypted part of client finished message 
 *	cert_request = pointer to encrypted part of certificate request message 
 *	server_verify =  pointer to encrypted part of server verify message 
 *	master_secret = master secret to used in session caching for reuse.
 *	master_secret_length = size in bytes of master secret.
 *	request_id = Unique ID for this request
 *
 * Return Value
 *	0  = success 
 * >0 = failure or pending
 * see error_codes.txt
 *
 *
 * Context format:
 *	Context is left in a state where it can be used for record processing:
 *	Word	
 *	0-15	reserved for hashing
 *	16-21	master secret
 *	To server
 *	22		Sequence number
 *	23		Unused
 *	24		IV
 *	25-27	3Des Keys
 *	To client
 *	28		Sequence number
 *	29		Unused
 *	30		IV
 *	31-33	3Des Keys
 *
 *
 *-***************************************************************************/

Uint32
Csp1RsaSsl20ServerClientAuth3Des (n1_request_type request_type,
				  Uint64 context_handle,
				  Uint64 * key_handle,
				  DesType des_type,
				  Uint8 * client_master_secret,
				  Uint16 clear_master_secret_length,
				  Uint16 encrypted_master_secret_length,
				  Uint16 modlength,
				  Uint8 * challenge,
				  Uint16 challenge_length,
				  Uint8 * connection_id,
				  Uint8 * session_id,
				  Uint8 * iv,
				  Uint8 * client_finished,
				  Uint8 auth_type,
				  Uint8 * cert_challenge,
				  Uint8 * cert_request,
				  Uint8 * server_verify,
				  Uint8 * master_secret,
				  Uint16 * master_secret_length,
#ifdef CAVIUM_MULTICARD_API
                                  Uint32 * request_id,Uint32 dev_id
#else
                                  Uint32 * request_id
#endif
                 )
{
#ifdef MC2
  return ERR_OPERATION_NOT_SUPPORTED;
#else
  int ms_size, ek, key_size, finished_size, pad, ret = 1, i = 0, is_export =
    0;
  Uint64 ctx_ptr, out_length = 0;
  Uint64 read_seq = 0, write_seq = 0;
  Uint32 seq = 0, dummy = 0;
  Uint8 *enc_ms = NULL, *temp = NULL, *ms, *p, km[48],
    server_write_key[24], server_read_key[24],
    temp_hash[24], mac[16], local_client_finished[64], padb[8];

  memset (padb, 0, 8);
  enc_ms = alloca (modlength);
  if (enc_ms == NULL)
    {
      ret = ERR_MEMORY_ALLOC_FAILURE;
      goto err_full_client_auth;
    }
  memset (enc_ms, 0, modlength);

  temp = alloca (modlength);
  if (temp == NULL)
    {
      ret = ERR_MEMORY_ALLOC_FAILURE;
      goto err_full_client_auth;
    }

  ms = alloca (modlength);
  if (ms == NULL)
    {
      ret = ERR_MEMORY_ALLOC_FAILURE;
      goto err_full_client_auth;
    }

  if (encrypted_master_secret_length < modlength)
    {
      p = &client_master_secret[clear_master_secret_length];
      pkp_leftfill (p, encrypted_master_secret_length, temp, modlength);
      memcpy (enc_ms, temp, modlength);
      memset (temp, 0, modlength);
    }
  else				/* encrypted master secret length should be equal to modlength or we are deep in trouble. */
    memcpy (enc_ms, &client_master_secret[clear_master_secret_length],
	    encrypted_master_secret_length);

  swap_word_openssl (temp, enc_ms, modlength);

  if (*key_handle & 0x1000000000000ULL)
    {
      /* key is in crt form */
      ret = Csp1Pkcs1v15CrtDec (CAVIUM_BLOCKING,
				RESULT_PTR,
				0,
				KEY_HANDLE,
				*key_handle,
				BT2,
				modlength,
				NULL,
				NULL,
				NULL,
				NULL, NULL, temp, ms, &out_length,
#ifdef CAVIUM_MULTICARD_API
                               &dummy,dev_id
#else
                               &dummy
#endif
                 );

    }
  else
    {
      ret = Csp1Pkcs1v15Dec (CAVIUM_BLOCKING,
			     RESULT_PTR,
			     0,
			     KEY_HANDLE,
			     *key_handle,
			     BT2,
			     modlength,
			     NULL, NULL, temp, ms, &out_length,
#ifdef CAVIUM_MULTICARD_API
                               &dummy,dev_id
#else
                               &dummy
#endif
                 );
    }

  if (ret)
    {
      goto err_full_client_auth;
    }


  /* check for bad decrypt */
  if (des_type == DES)
    {
      is_export = 0;
      key_size = 8;		/* bytes */
      ek = 8;
    }
  else if (des_type == DES3_192)
    {
      is_export = 0;
      ek = 24;
      key_size = 24;
    }
  else
    {
      ret = ERR_OPERATION_NOT_SUPPORTED;
      goto err_full_client_auth;
    }


  if ((!is_export && (out_length != key_size)) ||
      (is_export
       && ((out_length != ek)
	   || (clear_master_secret_length + out_length != key_size))))
    {
      ret = ERR_BAD_PKCS_PAD_OR_LENGTH;
      goto err_full_client_auth;
    }


  memset (temp, 0, modlength);

  /*  ms will now have complete master secret */
  memcpy (temp, ms, (Uint32) out_length);
  memcpy (ms, client_master_secret, clear_master_secret_length);
  memcpy (&ms[clear_master_secret_length], temp, (Uint32) out_length);

  /* now store complete master secret to context memory */
  ctx_ptr = context_handle + (8 * OFFSET_SSL2_MASTER_SECRET);
  ret = Csp1WriteContext (CAVIUM_BLOCKING, ctx_ptr,
			  (Uint16) (clear_master_secret_length +
				    (Uint32) out_length), ms,
#ifdef CAVIUM_MULTICARD_API
                           &dummy,dev_id
#else
                           &dummy
#endif
                 );

  if (ret)
    {
      goto err_full_client_auth;
    }

  /* generate key material */
  ms_size = clear_master_secret_length + (Uint32) out_length;
  p = temp;

  memcpy (temp, ms, ms_size);
  temp += ms_size;

  memcpy (temp, "\x30", 1);
  temp += 1;

  memcpy (temp, challenge, challenge_length);
  temp += challenge_length;

  memcpy (temp, connection_id, 16);
  temp = p;

  for (i = 0; i < (key_size * 2); i += 16)
    {
      ret = Csp1Handshake (CAVIUM_BLOCKING, context_handle,
			   (ms_size + 1 + challenge_length + 16),
			   temp, &km[i], temp_hash,
#ifdef CAVIUM_MULTICARD_API
                           &dummy,dev_id
#else
                           &dummy
#endif
                 );
      if (ret)
	{
	  goto err_full_client_auth;
	}

      temp[ms_size]++;
    }


  /* store keys and IV to context memory */

  memcpy (temp, iv, 8);

  /* To client */
  if (key_size == 8)
    {
      memcpy (&temp[8], km, 8);
      memcpy (&temp[16], km, 8);
      memcpy (&temp[24], km, 8);
    }

  if (key_size == 24)
    {
      memcpy (&temp[8], km, 8);
      memcpy (&temp[16], &km[8], 8);
      memcpy (&temp[24], &km[16], 8);
    }

  memcpy (server_write_key, &temp[8], 24);

  ctx_ptr = context_handle + (8 * OFFSET_SSL2_3DES_SERVER_WRITE_KM);
#ifdef CAVIUM_MULTICARD_API
  ret = Csp1WriteContext (CAVIUM_BLOCKING, ctx_ptr, 32, temp, &dummy,dev_id);
#else
  ret = Csp1WriteContext (CAVIUM_BLOCKING, ctx_ptr, 32, temp, &dummy);
#endif
  if (ret)
    {
      goto err_full_client_auth;
    }


  /* To server */
  if (key_size == 8)
    {
      memcpy (&temp[8], &km[8], 8);
      memcpy (&temp[16], &km[8], 8);
      memcpy (&temp[24], &km[8], 8);
    }

  if (key_size == 24)
    {
      memcpy (&temp[8], &km[24], 8);
      memcpy (&temp[16], &km[32], 8);
      memcpy (&temp[24], &km[40], 8);
    }

  memcpy (server_read_key, &temp[8], 24);

  ctx_ptr = context_handle + (8 * OFFSET_SSL2_3DES_SERVER_READ_KM);
#ifdef CAVIUM_MULTICARD_API
  ret = Csp1WriteContext (CAVIUM_BLOCKING, ctx_ptr, 32, temp, &dummy,dev_id);
#else
  ret = Csp1WriteContext (CAVIUM_BLOCKING, ctx_ptr, 32, temp, &dummy);
#endif
  if (ret)
    {
      goto err_full_client_auth;
    }


  /* client finished decryption and validation. */
  finished_size = 16 + 16 + 1;	/* 16 = mc, 16 = conn_id_len, 1=message type */
  pad = 8 - (finished_size % 8);

  /* finished size after padding */
  finished_size += pad;

  ctx_ptr = context_handle + (8 * OFFSET_SSL2_3DES_SERVER_READ_KM);

  ret = Csp1Decrypt3Des (CAVIUM_BLOCKING,
			 ctx_ptr,
			 CAVIUM_UPDATE,
			 finished_size,
			 client_finished, local_client_finished,
#ifdef CAVIUM_MULTICARD_API
                         &dummy,dev_id
#else
                         &dummy
#endif
                 );
  if (ret)
    {
      goto err_full_client_auth;
    }

  /* mac */
  read_seq = 2;			/* client hello, client_master_secret */
  seq = htobe32 ((Uint32) read_seq);

  p = temp;
  memcpy (temp, server_read_key, key_size);
  temp += key_size;

  memcpy (temp, &local_client_finished[16], finished_size - 16);
  temp += (finished_size - 16);

  memcpy (temp, (Uint8 *) & seq, 4);

  temp = p;
  i = key_size + (finished_size - 16) + 4;

  ret = Csp1Handshake (CAVIUM_BLOCKING,
		       context_handle, i, temp, mac, temp_hash,
#ifdef CAVIUM_MULTICARD_API
                        &dummy,dev_id
#else
                        &dummy
#endif
                 );
  if (ret)
    {
      goto err_full_client_auth;
    }

  /* compare mac */
  if (memcmp (local_client_finished, mac, 16))
    {
      ret = ERR_BAD_CIPHER_OR_MAC;
      goto err_full_client_auth;
    }

  INC32 (read_seq);

  /* compare client finished with connection id */
  if (memcmp (&local_client_finished[16 + 1], connection_id, 16))
    {
      ret = ERR_BAD_CIPHER_OR_MAC;	/*??? */
      goto err_full_client_auth;
    }


  /* generate server verify message */
  /* mac */
  pad = 8 - ((16 + 1 + challenge_length) % 8);

  write_seq = 1;		/* server hello */
  seq = htobe32 ((Uint32) write_seq);
  p = temp;

  memcpy (temp, server_write_key, key_size);
  temp += key_size;

  temp[0] = 5;
  temp++;

  memcpy (temp, challenge, challenge_length);
  temp += challenge_length;

  memcpy (temp, padb, pad);
  temp += pad;

  memcpy (temp, (Uint8 *) & seq, 4);

  temp = p;
  i = key_size + 1 + challenge_length + pad + 4;

  ret = Csp1Handshake (CAVIUM_BLOCKING,
		       context_handle, i, temp, mac, temp_hash,
#ifdef CAVIUM_MULTICARD_API
                       &dummy,dev_id
#else
                       &dummy
#endif
                 );
  if (ret)
    {
      goto err_full_client_auth;
    }

  memcpy (server_verify, mac, 16);
  server_verify[16] = 5;	/* message type */
  memcpy (&server_verify[17], challenge, challenge_length);
  memcpy (&server_verify[17 + challenge_length], padb, pad);


  finished_size = 16 + 1 + challenge_length + pad;	/* 16 = md5 mac, 1 = message type, */
  ctx_ptr = context_handle + (8 * OFFSET_SSL2_3DES_SERVER_WRITE_KM);

  ret = Csp1Encrypt3Des (CAVIUM_BLOCKING,
			 ctx_ptr,
			 CAVIUM_UPDATE,
			 finished_size, server_verify, server_verify,
#ifdef CAVIUM_MULTICARD_API
                         &dummy,dev_id
#else
                         &dummy
#endif
                 );
  if (ret)
    {
      goto err_full_client_auth;
    }

  INC32 (write_seq);


  /* generate cert request message */
  /* mac */
  pad = 8 - ((16 + 1 + 1 + 16) % 8);

  seq = htobe32 ((Uint32) write_seq);
  p = temp;

  memcpy (temp, server_write_key, key_size);
  temp += key_size;

  temp[0] = 7;			/* cert req message type */
  temp++;

  temp[0] = auth_type;
  temp++;

  memcpy (temp, cert_challenge, 16);
  temp += 16;

  memcpy (temp, padb, pad);
  temp += pad;

  memcpy (temp, (Uint8 *) & seq, 4);

  temp = p;
  i = key_size + 1 + 1 + 16 + pad + 4;

  ret = Csp1Handshake (CAVIUM_BLOCKING,
		       context_handle, i, temp, mac, temp_hash,
#ifdef CAVIUM_MULTICARD_API
                       &dummy,dev_id
#else
                       &dummy
#endif
                 );
  if (ret)
    {
      goto err_full_client_auth;
    }

  memcpy (cert_request, mac, 16);
  cert_request[16] = 7;		/* message type */
  cert_request[17] = auth_type;
  memcpy (&cert_request[18], cert_challenge, 16);
  memcpy (&cert_request[18 + 16], padb, pad);


  finished_size = 16 + 1 + 1 + 16 + pad;	/* 16 = mac, 1 = message type, 1= auth_type 16 = cert_challenge */
  ctx_ptr = context_handle + (8 * OFFSET_SSL2_3DES_SERVER_WRITE_KM);

  ret = Csp1Encrypt3Des (CAVIUM_BLOCKING,
			 ctx_ptr,
			 CAVIUM_UPDATE,
			 finished_size, cert_request, cert_request,
#ifdef CAVIUM_MULTICARD_API
                         &dummy,dev_id
#else
                         &dummy
#endif
                 );
  if (ret)
    {
      goto err_full_client_auth;
    }

  INC32 (write_seq);

  /* copy write sequence and read sequence to context memory */
  ctx_ptr = context_handle + (8 * OFFSET_SSL2_3DES_SERVER_READ_SEQ);
  ret =
    Csp1WriteContext (CAVIUM_BLOCKING, ctx_ptr, 8, (Uint8 *) & read_seq,
#ifdef CAVIUM_MULTICARD_API
                      &dummy,dev_id
#else
                      &dummy
#endif
                 );
  if (ret)
    {
      goto err_full_client_auth;
    }

  ctx_ptr = context_handle + (8 * OFFSET_SSL2_3DES_SERVER_WRITE_SEQ);
  ret =
    Csp1WriteContext (CAVIUM_BLOCKING, ctx_ptr, 8, (Uint8 *) & write_seq,
#ifdef CAVIUM_MULTICARD_API
                      &dummy,dev_id
#else
                      &dummy
#endif
                 );
  if (ret)
    {
      goto err_full_client_auth;
    }


  /* return master secret */
  memcpy (master_secret, ms,
	  clear_master_secret_length + (Uint32) out_length);
  *master_secret_length = clear_master_secret_length + (Uint32) out_length;
  ret = 0;

err_full_client_auth:
  return ret;

#endif
}				/*Csp1RsaSsl20ServerClientAuth3Des */




/*+****************************************************************************
 *
 * Csp1Ssl20Resume3Des
 *
 * Resumes a previouly negotiated handshake. 
 *
 *
 * Supported ciphers
 *	SSL_CK_DES_64_CBC_WITH_MD5
 *	SSL_CK_DES_192_EDE3_CBC_WITH_MD5
 *
 *
 * Input
 *	request_type = CAVIUM_BLOCKING or CAVIUM_NON_BLOCKING
 *	context_handle = 64-bit byte-pointer to context (context_handle%8=0)
 *	key_handle = pointer to 64-bit key memory handle
 *	des_type = DES or DES3_192
 *	master_secret = master key generated in previous handshake
 *	master_secret_length = size in bytes of master secret.
 *	challenge = pointer to challenge data.
 *	challenge_length = length (in bytes) of challenge data.
 *	connection_id = pointer to 16 bytes of connection ID.
 *	session_id = pointer to 16 bytes of Session ID.
 *	iv = initialization vectore sent by client
 *
 *
 * Output
 *	client_finished = pointer to encrypted part of client finished message 
 *	server_finished = pointer to encrypted part of server finished message 
 *	server_verify =  pointer to encrypted part of server verify message 
 *	request_id = Unique ID for this request
 *
 * Return Value
 *	0  = success 
 * >0 = failure or pending
 * see error_codes.txt
 *
 *
 * Context format:
 *	Context is left in a state where it can be used for record processing:
 *	Word	
 *	0-15	reserved for hashing
 *	16-21	master secret
 *	To server
 *	22		Sequence number
 *	23		Unused
 *	24		IV
 *	25-27	3Des Keys
 *	To client
 *	28		Sequence number
 *	29		Unused
 *	30		IV
 *	31-33	3Des Keys
 *
 *
 *-***************************************************************************/
Uint32
Csp1Ssl20Resume3Des (n1_request_type request_type,
		     Uint64 context_handle,
		     Uint64 * key_handle,
		     DesType des_type,
		     Uint8 * master_secret,
		     Uint16 master_secret_length,
		     Uint8 * challenge,
		     Uint16 challenge_length,
		     Uint8 * connection_id,
		     Uint8 * session_id,
		     Uint8 * iv,
		     Uint8 * client_finished,
		     Uint8 * server_finished,
		     Uint8 * server_verify,
#ifdef CAVIUM_MULTICARD_API
                     Uint32 * request_id,Uint32 dev_id
#else
                     Uint32 * request_id
#endif
                 )
{
#ifdef MC2
  return ERR_OPERATION_NOT_SUPPORTED;
#else
  int ms_size, key_size, finished_size, pad, ret = 1, i = 0;
  Uint64 ctx_ptr;
  Uint64 read_seq = 0, write_seq = 0;
  Uint32 seq = 0, dummy = 0;
  Uint8 *temp = NULL, *p, km[48],
    server_write_key[24], server_read_key[24],
    temp_hash[24], mac[16], local_client_finished[64], padb[8];

  memset (padb, 0, 8);
  temp = alloca (256);
  if (temp == NULL)
    {
      ret = ERR_MEMORY_ALLOC_FAILURE;
      goto err_resume;
    }


  /* check for bad decrypt */
  if (des_type == DES)
    key_size = 8;		/* bytes */
  else if (des_type == DES3_192)
    key_size = 24;
  else
    {
      ret = ERR_OPERATION_NOT_SUPPORTED;
      goto err_resume;
    }


  /* store complete master secret to context memory */
  ctx_ptr = context_handle + (8 * OFFSET_SSL2_MASTER_SECRET);
  ret =
    Csp1WriteContext (CAVIUM_BLOCKING, ctx_ptr, master_secret_length,
		      master_secret,
#ifdef CAVIUM_MULTICARD_API
                      &dummy,dev_id
#else
                      &dummy
#endif
                 );
  if (ret)
    {
      goto err_resume;
    }

  /* generate key material */
  ms_size = master_secret_length;
  p = temp;

  memcpy (temp, master_secret, ms_size);
  temp += ms_size;

  memcpy (temp, "\x30", 1);
  temp += 1;

  memcpy (temp, challenge, challenge_length);
  temp += challenge_length;

  memcpy (temp, connection_id, 16);
  temp = p;

  for (i = 0; i < (key_size * 2); i += 16)
    {
      ret = Csp1Handshake (CAVIUM_BLOCKING, context_handle,
			   (ms_size + 1 + challenge_length + 16),
			   temp, &km[i], temp_hash,
#ifdef CAVIUM_MULTICARD_API
                            &dummy,dev_id
#else
                            &dummy
#endif
                 );
      if (ret)
	{
	  goto err_resume;
	}

      temp[ms_size]++;
    }


  /* store keys and IV to context memory */

  memcpy (temp, iv, 8);

  /* To client */
  if (key_size == 8)
    {
      memcpy (&temp[8], km, 8);
      memcpy (&temp[16], km, 8);
      memcpy (&temp[24], km, 8);
    }

  if (key_size == 24)
    {
      memcpy (&temp[8], km, 8);
      memcpy (&temp[16], &km[8], 8);
      memcpy (&temp[24], &km[16], 8);
    }

  memcpy (server_write_key, &temp[8], 24);

  ctx_ptr = context_handle + (8 * OFFSET_SSL2_3DES_SERVER_WRITE_KM);
#ifdef CAVIUM_MULTICARD_API
  ret = Csp1WriteContext (CAVIUM_BLOCKING, ctx_ptr, 32, temp, &dummy,dev_id);
#else
  ret = Csp1WriteContext (CAVIUM_BLOCKING, ctx_ptr, 32, temp, &dummy);
#endif
  if (ret)
    {
      goto err_resume;
    }


  /* To server */
  if (key_size == 8)
    {
      memcpy (&temp[8], &km[8], 8);
      memcpy (&temp[16], &km[8], 8);
      memcpy (&temp[24], &km[8], 8);
    }

  if (key_size == 24)
    {
      memcpy (&temp[8], &km[24], 8);
      memcpy (&temp[16], &km[32], 8);
      memcpy (&temp[24], &km[40], 8);
    }

  memcpy (server_read_key, &temp[8], 24);

  ctx_ptr = context_handle + (8 * OFFSET_SSL2_3DES_SERVER_READ_KM);
#ifdef CAVIUM_MULTICARD_API
  ret = Csp1WriteContext (CAVIUM_BLOCKING, ctx_ptr, 32, temp, &dummy,dev_id);
#else
  ret = Csp1WriteContext (CAVIUM_BLOCKING, ctx_ptr, 32, temp, &dummy);
#endif
  if (ret)
    {
      goto err_resume;
    }


  /* client finished decryption and validation. */
  finished_size = 16 + 16 + 1;	/* 16 = mc, 16 = conn_id_len, 1=message type */
  pad = 8 - (finished_size % 8);

  /* finished size after padding */
  finished_size += pad;

  ctx_ptr = context_handle + (8 * OFFSET_SSL2_3DES_SERVER_READ_KM);

  ret = Csp1Decrypt3Des (CAVIUM_BLOCKING,
			 ctx_ptr,
			 CAVIUM_UPDATE,
			 finished_size,
			 client_finished, local_client_finished,
#ifdef CAVIUM_MULTICARD_API
                         &dummy,dev_id
#else
                         &dummy
#endif
                 );
  if (ret)
    {
      goto err_resume;
    }

  /* mac */
  read_seq = 1;			/* client hello */
  seq = htobe32 ((Uint32) read_seq);

  p = temp;
  memcpy (temp, server_read_key, key_size);
  temp += key_size;

  memcpy (temp, &local_client_finished[16], finished_size - 16);
  temp += (finished_size - 16);

  memcpy (temp, (Uint8 *) & seq, 4);

  temp = p;
  i = key_size + (finished_size - 16) + 4;

  ret = Csp1Handshake (CAVIUM_BLOCKING,
		       context_handle, i, temp, mac, temp_hash,
#ifdef CAVIUM_MULTICARD_API
                        &dummy,dev_id
#else
                        &dummy
#endif
                 );
  if (ret)
    {
      goto err_resume;
    }

  /* compare mac */
  if (memcmp (local_client_finished, mac, 16))
    {
      ret = ERR_BAD_CIPHER_OR_MAC;
      goto err_resume;
    }

  INC32 (read_seq);

  /* compare client finished with connection id */
  if (memcmp (&local_client_finished[16 + 1], connection_id, 16))
    {
      ret = ERR_BAD_CIPHER_OR_MAC;	/*??? */
      goto err_resume;
    }


  /* generate server verify message */
  /* mac */
  pad = 8 - ((16 + 1 + challenge_length) % 8);

  write_seq = 1;		/* server hello */
  seq = htobe32 ((Uint32) write_seq);
  p = temp;

  memcpy (temp, server_write_key, key_size);
  temp += key_size;

  temp[0] = 5;
  temp++;

  memcpy (temp, challenge, challenge_length);
  temp += challenge_length;

  memcpy (temp, padb, pad);
  temp += pad;

  memcpy (temp, (Uint8 *) & seq, 4);

  temp = p;
  i = key_size + 1 + challenge_length + pad + 4;

  ret = Csp1Handshake (CAVIUM_BLOCKING,
		       context_handle, i, temp, mac, temp_hash,
#ifdef CAVIUM_MULTICARD_API
                       &dummy,dev_id
#else
                       &dummy
#endif
                 );
  if (ret)
    {
      goto err_resume;
    }

  memcpy (server_verify, mac, 16);
  server_verify[16] = 5;	/* message type */
  memcpy (&server_verify[17], challenge, challenge_length);
  memcpy (&server_verify[17 + challenge_length], padb, pad);


  finished_size = 16 + 1 + challenge_length + pad;	/* 16 = md5 mac, 1 = message type, */
  ctx_ptr = context_handle + (8 * OFFSET_SSL2_3DES_SERVER_WRITE_KM);

  ret = Csp1Encrypt3Des (CAVIUM_BLOCKING,
			 ctx_ptr,
			 CAVIUM_UPDATE,
			 finished_size, server_verify, server_verify,
#ifdef CAVIUM_MULTICARD_API
                         &dummy,dev_id
#else
                         &dummy
#endif
                 );
  if (ret)
    {
      goto err_resume;
    }

  INC32 (write_seq);


  /* generate server finish message */
  /* mac */
  pad = 8 - ((16 + 1 + 16) % 8);

  seq = htobe32 ((Uint32) write_seq);
  p = temp;

  memcpy (temp, server_write_key, key_size);
  temp += key_size;

  temp[0] = 6;			/* finished message type */
  temp++;

  memcpy (temp, session_id, 16);
  temp += 16;

  memcpy (temp, padb, pad);
  temp += pad;

  memcpy (temp, (Uint8 *) & seq, 4);

  temp = p;
  i = key_size + 1 + 16 + pad + 4;

  ret = Csp1Handshake (CAVIUM_BLOCKING,
		       context_handle, i, temp, mac, temp_hash,
#ifdef CAVIUM_MULTICARD_API
                       &dummy,dev_id
#else
                       &dummy
#endif
                 );
  if (ret)
    {
      goto err_resume;
    }

  memcpy (server_finished, mac, 16);
  server_finished[16] = 6;	/* message type */
  memcpy (&server_finished[17], session_id, 16);
  memcpy (&server_finished[17 + 16], padb, pad);


  finished_size = 16 + 1 + 16 + pad;	/* 16 = session_id, 1 = message type 16 = md5 mac */
  ctx_ptr = context_handle + (8 * OFFSET_SSL2_3DES_SERVER_WRITE_KM);

  ret = Csp1Encrypt3Des (CAVIUM_BLOCKING,
			 ctx_ptr,
			 CAVIUM_UPDATE,
			 finished_size,
			 server_finished, server_finished,
#ifdef CAVIUM_MULTICARD_API
                         &dummy,dev_id
#else
                         &dummy
#endif
                 );
  if (ret)
    {
      goto err_resume;
    }

  INC32 (write_seq);

  /* copy write sequence and read sequence to context memory */
  ctx_ptr = context_handle + (8 * OFFSET_SSL2_3DES_SERVER_READ_SEQ);
  ret =
    Csp1WriteContext (CAVIUM_BLOCKING, ctx_ptr, 8, (Uint8 *) & read_seq,
#ifdef CAVIUM_MULTICARD_API
                       &dummy,dev_id
#else
                       &dummy
#endif
                 );
  if (ret)
    {
      goto err_resume;
    }

  ctx_ptr = context_handle + (8 * OFFSET_SSL2_3DES_SERVER_WRITE_SEQ);
  ret =
    Csp1WriteContext (CAVIUM_BLOCKING, ctx_ptr, 8, (Uint8 *) & write_seq,
#ifdef CAVIUM_MULTICARD_API
                       &dummy,dev_id
#else
                       &dummy
#endif
                 );
  if (ret)
    {
      goto err_resume;
    }


  ret = 0;

err_resume:
  return ret;
#endif
}				/* Csp1Ssl20Resume3Des */





/*+****************************************************************************
 *
 * Csp1Ssl20ResumeClientAuth3Des
 *
 * Uses master key from a previous session, generates key material, cert req,
 * and verify messages.
 *
 *
 * Supported ciphers
 *	SSL_CK_DES_64_CBC_WITH_MD5
	SSL_CK_DES_192_EDE3_CBC_WITH_MD5
 *
 *
 * Input
 *	request_type = CAVIUM_BLOCKING or CAVIUM_NON_BLOCKING
 *	context_handle = 64-bit byte-pointer to context (context_handle%8=0)
 *	key_handle = pointer to 64-bit key memory handle
 *	des_type = DES or DES3_192
 *	master_secret = master key generated in previous handshake
 *	master_secret_length = size in bytes of master secret.
 *	challenge = pointer to challenge data.
 *	challenge_length = length (in bytes) of challenge data.
 *	connection_id = pointer to 16 bytes of connection ID.
 *	session_id = pointer to 16 bytes of Session ID.
 *	iv = initialization vectore sent by client
 *	client_finished = pointer to encrypted part of client finished message 
 *	auth_type =  client authentication type
 *	cert_challenge = cert request challenge
 *	cert_request = certificate request
 *
 *
 * Output
 *
 *	cert_request = pointer to encrypted part of cert request message 
 *	server_verify =  pointer to encrypted part of server verify message 
 *  request_id = Unique ID for this request
 *
 * Return Value
 *	0  = success 
 * >0 = failure or pending
 * see error_codes.txt
 *
 *
 * Context format:
 *	Context is left in a state where it can be used for record processing:
 *	Word	
 *	0-15	reserved for hashing
 *	16-21	master secret
 *	To server
 *	22		Sequence number
 *	23		Unused
 *	24		IV
 *	25-27	3Des Keys
 *	To client
 *	28		Sequence number
 *	29		Unused
 *	30		IV
 *	31-33	3Des Keys
 *
 *
 *-***************************************************************************/
Uint32
Csp1Ssl20ResumeClientAuth3Des (n1_request_type request_type,
			       Uint64 context_handle,
			       Uint64 * key_handle,
			       DesType des_type,
			       Uint8 * master_secret,
			       Uint16 master_secret_length,
			       Uint8 * challenge,
			       Uint16 challenge_length,
			       Uint8 * connection_id,
			       Uint8 * session_id,
			       Uint8 * iv,
			       Uint8 * client_finished,
			       Uint8 auth_type,
			       Uint8 * cert_challenge,
			       Uint8 * cert_request,
			       Uint8 * server_verify,
#ifdef CAVIUM_MULTICARD_API
                               Uint32 * request_id,Uint32 dev_id
#else
                               Uint32 * request_id
#endif
                 )
{
#ifdef MC2
  return ERR_OPERATION_NOT_SUPPORTED;
#else
  int ms_size, key_size, finished_size, pad, ret = 1, i = 0;
  Uint64 ctx_ptr;
  Uint64 read_seq = 0, write_seq = 0;
  Uint32 seq = 0, dummy = 0;
  Uint8 *temp = NULL, *p, km[48],
    server_write_key[24], server_read_key[24],
    temp_hash[24], mac[16], local_client_finished[64], padb[8];

  memset (padb, 0, 8);
  temp = alloca (256);
  if (temp == NULL)
    {
      ret = ERR_MEMORY_ALLOC_FAILURE;
      goto err_resume_client_auth;
    }


  /* check for bad decrypt */
  if (des_type == DES)
    key_size = 8;		/* bytes */
  else if (des_type == DES3_192)
    key_size = 24;
  else
    {
      ret = ERR_OPERATION_NOT_SUPPORTED;
      goto err_resume_client_auth;
    }


  /* store complete master secret to context memory */
  ctx_ptr = context_handle + (8 * OFFSET_SSL2_MASTER_SECRET);
  ret =
    Csp1WriteContext (CAVIUM_BLOCKING, ctx_ptr, master_secret_length,
		      master_secret,
#ifdef CAVIUM_MULTICARD_API
                      &dummy,dev_id
#else
                      &dummy
#endif
                 );
  if (ret)
    {
      goto err_resume_client_auth;
    }

  /* generate key material */
  ms_size = master_secret_length;
  p = temp;

  memcpy (temp, master_secret, ms_size);
  temp += ms_size;

  memcpy (temp, "\x30", 1);
  temp += 1;

  memcpy (temp, challenge, challenge_length);
  temp += challenge_length;

  memcpy (temp, connection_id, 16);
  temp = p;

  for (i = 0; i < (key_size * 2); i += 16)
    {
      ret = Csp1Handshake (CAVIUM_BLOCKING, context_handle,
			   (ms_size + 1 + challenge_length + 16),
			   temp, &km[i], temp_hash,
#ifdef CAVIUM_MULTICARD_API
                            &dummy,dev_id
#else
                            &dummy
#endif
                 );
      if (ret)
	{
	  goto err_resume_client_auth;
	}

      temp[ms_size]++;
    }


  /* store keys and IV to context memory */

  memcpy (temp, iv, 8);

  /* To client */
  if (key_size == 8)
    {
      memcpy (&temp[8], km, 8);
      memcpy (&temp[16], km, 8);
      memcpy (&temp[24], km, 8);
    }

  if (key_size == 24)
    {
      memcpy (&temp[8], km, 8);
      memcpy (&temp[16], &km[8], 8);
      memcpy (&temp[24], &km[16], 8);
    }

  memcpy (server_write_key, &temp[8], 24);

  ctx_ptr = context_handle + (8 * OFFSET_SSL2_3DES_SERVER_WRITE_KM);
#ifdef CAVIUM_MULTICARD_API
  ret = Csp1WriteContext (CAVIUM_BLOCKING, ctx_ptr, 32, temp, &dummy,dev_id);
#else
  ret = Csp1WriteContext (CAVIUM_BLOCKING, ctx_ptr, 32, temp, &dummy);
#endif
  if (ret)
    {
      goto err_resume_client_auth;
    }


  /* To server */
  if (key_size == 8)
    {
      memcpy (&temp[8], &km[8], 8);
      memcpy (&temp[16], &km[8], 8);
      memcpy (&temp[24], &km[8], 8);
    }

  if (key_size == 24)
    {
      memcpy (&temp[8], &km[24], 8);
      memcpy (&temp[16], &km[32], 8);
      memcpy (&temp[24], &km[40], 8);
    }

  memcpy (server_read_key, &temp[8], 24);

  ctx_ptr = context_handle + (8 * OFFSET_SSL2_3DES_SERVER_READ_KM);
#ifdef CAVIUM_MULTICARD_API
  ret = Csp1WriteContext (CAVIUM_BLOCKING, ctx_ptr, 32, temp, &dummy,dev_id);
#else
  ret = Csp1WriteContext (CAVIUM_BLOCKING, ctx_ptr, 32, temp, &dummy);
#endif
  if (ret)
    {
      goto err_resume_client_auth;
    }


  /* client finished decryption and validation. */
  finished_size = 16 + 16 + 1;	/* 16 = mc, 16 = conn_id_len, 1=message type */
  pad = 8 - (finished_size % 8);

  /* finished size after padding */
  finished_size += pad;

  ctx_ptr = context_handle + (8 * OFFSET_SSL2_3DES_SERVER_READ_KM);

  ret = Csp1Decrypt3Des (CAVIUM_BLOCKING,
			 ctx_ptr,
			 CAVIUM_UPDATE,
			 finished_size,
			 client_finished, local_client_finished,
#ifdef CAVIUM_MULTICARD_API
                         &dummy,dev_id
#else
                         &dummy
#endif
                 );
  if (ret)
    {
      goto err_resume_client_auth;
    }

  /* mac */
  read_seq = 1;			/* client hello */
  seq = htobe32 ((Uint32) read_seq);

  p = temp;
  memcpy (temp, server_read_key, key_size);
  temp += key_size;

  memcpy (temp, &local_client_finished[16], finished_size - 16);
  temp += (finished_size - 16);

  memcpy (temp, (Uint8 *) & seq, 4);

  temp = p;
  i = key_size + (finished_size - 16) + 4;

  ret = Csp1Handshake (CAVIUM_BLOCKING,
		       context_handle, i, temp, mac, temp_hash,
#ifdef CAVIUM_MULTICARD_API
                       &dummy,dev_id
#else
                       &dummy
#endif
                 );
  if (ret)
    {
      goto err_resume_client_auth;
    }

  /* compare mac */
  if (memcmp (local_client_finished, mac, 16))
    {
      ret = ERR_BAD_CIPHER_OR_MAC;
      goto err_resume_client_auth;
    }

  INC32 (read_seq);

  /* compare client finished with connection id */
  if (memcmp (&local_client_finished[16 + 1], connection_id, 16))
    {
      ret = ERR_BAD_CIPHER_OR_MAC;	/*??? */
      goto err_resume_client_auth;
    }


  /* generate server verify message */
  /* mac */
  pad = 8 - ((16 + 1 + challenge_length) % 8);

  write_seq = 1;		/* server hello */
  seq = htobe32 ((Uint32) write_seq);
  p = temp;

  memcpy (temp, server_write_key, key_size);
  temp += key_size;

  temp[0] = 5;
  temp++;

  memcpy (temp, challenge, challenge_length);
  temp += challenge_length;

  memcpy (temp, padb, pad);
  temp += pad;

  memcpy (temp, (Uint8 *) & seq, 4);

  temp = p;
  i = key_size + 1 + challenge_length + pad + 4;

  ret = Csp1Handshake (CAVIUM_BLOCKING,
		       context_handle, i, temp, mac, temp_hash,
#ifdef CAVIUM_MULTICARD_API
                       &dummy,dev_id
#else
                       &dummy
#endif
                 );
  if (ret)
    {
      goto err_resume_client_auth;
    }

  memcpy (server_verify, mac, 16);
  server_verify[16] = 5;	/* message type */
  memcpy (&server_verify[17], challenge, challenge_length);
  memcpy (&server_verify[17 + challenge_length], padb, pad);


  finished_size = 16 + 1 + challenge_length + pad;	/* 16 = md5 mac, 1 = message type, */
  ctx_ptr = context_handle + (8 * OFFSET_SSL2_3DES_SERVER_WRITE_KM);

  ret = Csp1Encrypt3Des (CAVIUM_BLOCKING,
			 ctx_ptr,
			 CAVIUM_UPDATE,
			 finished_size, server_verify, server_verify,
#ifdef CAVIUM_MULTICARD_API
                         &dummy,dev_id
#else
                         &dummy
#endif
                 );
  if (ret)
    {
      goto err_resume_client_auth;
    }

  INC32 (write_seq);


  /* generate cert request message */
  /* mac */
  pad = 8 - ((16 + 1 + 1 + 16) % 8);

  seq = htobe32 ((Uint32) write_seq);
  p = temp;

  memcpy (temp, server_write_key, key_size);
  temp += key_size;

  temp[0] = 7;			/* cert req message type */
  temp++;

  temp[0] = auth_type;
  temp++;

  memcpy (temp, cert_challenge, 16);
  temp += 16;

  memcpy (temp, padb, pad);
  temp += pad;

  memcpy (temp, (Uint8 *) & seq, 4);

  temp = p;
  i = key_size + 1 + 1 + 16 + pad + 4;

  ret = Csp1Handshake (CAVIUM_BLOCKING,
		       context_handle, i, temp, mac, temp_hash,
#ifdef CAVIUM_MULTICARD_API
                       &dummy,dev_id
#else
                       &dummy
#endif
                 );
  if (ret)
    {
      goto err_resume_client_auth;
    }

  memcpy (cert_request, mac, 16);
  cert_request[16] = 7;		/* message type */
  cert_request[17] = auth_type;
  memcpy (&cert_request[18], cert_challenge, 16);
  memcpy (&cert_request[18 + 16], padb, pad);


  finished_size = 16 + 1 + 1 + 16 + pad;	/* 16 = mac, 1 = message type, 1= auth_type 16 = cert_challenge */
  ctx_ptr = context_handle + (8 * OFFSET_SSL2_3DES_SERVER_WRITE_KM);

  ret = Csp1Encrypt3Des (CAVIUM_BLOCKING,
			 ctx_ptr,
			 CAVIUM_UPDATE,
			 finished_size, cert_request, cert_request,
#ifdef CAVIUM_MULTICARD_API
                          &dummy,dev_id
#else
                          &dummy
#endif
                 );
  if (ret)
    {
      goto err_resume_client_auth;
    }

  INC32 (write_seq);

  /* copy write sequence and read sequence to context memory */
  ctx_ptr = context_handle + (8 * OFFSET_SSL2_3DES_SERVER_READ_SEQ);
  ret =
    Csp1WriteContext (CAVIUM_BLOCKING, ctx_ptr, 8, (Uint8 *) & read_seq,
#ifdef CAVIUM_MULTICARD_API
                      &dummy,dev_id
#else
                      &dummy
#endif
                 );
  if (ret)
    {
      goto err_resume_client_auth;
    }

  ctx_ptr = context_handle + (8 * OFFSET_SSL2_3DES_SERVER_WRITE_SEQ);
  ret =
    Csp1WriteContext (CAVIUM_BLOCKING, ctx_ptr, 8, (Uint8 *) & write_seq,
#ifdef CAVIUM_MULTICARD_API
                      &dummy,dev_id
#else
                      &dummy
#endif
                 );
  if (ret)
    {
      goto err_resume_client_auth;
    }


  ret = 0;

err_resume_client_auth:
  return ret;
#endif
}				/* Csp1Ssl20ResumeClientAuth3Des */




/*+****************************************************************************
 *
 * Csp1Ssl20DecryptRecordRc4
 *
 * Input
 *	request_type = CAVIUM_BLOCKING or CAVIUM_NON_BLOCKING
 *	context_handle = 64-bit pointer to context (context_handle%8=0)
 *	record_length = size of record in bytes (0<=length<=2^16-1)
 *	record = pointer to length-byte encrypted part of record 
 *
 * Output
 *	message = pointer to decrypted message 
 *	request_id = Unique ID for this request
 *
 * Return Value
 *	0  = success 
 * >0 = failure or pending
 * see error_codes.txt
 *
 *-***************************************************************************/

Uint32
Csp1Ssl20DecryptRecordRc4 (n1_request_type request_type,
			   Uint64 context_handle,
			   Uint16 record_length,
			   Uint8 * record,
			   Uint8 * message,
#ifdef CAVIUM_MULTICARD_API
                           Uint32 * request_id,Uint32 dev_id
#else
                           Uint32 * request_id
#endif
                 )
{
#ifdef MC2
  return ERR_OPERATION_NOT_SUPPORTED;
#else
  int ret, seq, mac_size, key_size, act_size;
  Uint8 mac[36], read_key[24];
  Uint64 ctx_ptr, read_seq;
  Uint32 dummy = 0;

  mac_size = 16;
  key_size = 16;
  act_size = record_length - mac_size;

  ctx_ptr = context_handle + (8 * OFFSET_SSL2_RC4_SERVER_READ_STATE);
  ret = Csp1EncryptRc4 (CAVIUM_BLOCKING,
			ctx_ptr,
			CAVIUM_UPDATE,
			record_length, record, message,
#ifdef CAVIUM_MULTICARD_API
                         &dummy,dev_id
#else
                         &dummy
#endif
                 );
  if (ret)
    {
      goto err;
    }

  /* mac */
  /* read sequence */

  read_seq = 0;
  ctx_ptr = context_handle + (8 * OFFSET_SSL2_RC4_SERVER_READ_SEQ);

  ret =
    Csp1ReadContext (CAVIUM_BLOCKING, ctx_ptr, 8, (Uint8 *) & read_seq,
#ifdef CAVIUM_MULTICARD_API
                     &dummy,dev_id
#else
                     &dummy
#endif
                 );
  if (ret)
    {
      goto err;
    }
  seq = htobe32 ((Uint32) read_seq);

  /* read key */
  ctx_ptr = context_handle + (8 * OFFSET_SSL2_RC4_SERVER_READ_KM);

  ret =
#ifdef CAVIUM_MULTICARD_API
    Csp1ReadContext (CAVIUM_BLOCKING, ctx_ptr, key_size, read_key, &dummy,dev_id);
#else
    Csp1ReadContext (CAVIUM_BLOCKING, ctx_ptr, key_size, read_key, &dummy);
#endif
  if (ret)
    {
      goto err;
    }


  ret = Csp1HandshakeStart (CAVIUM_BLOCKING,
			    context_handle, key_size, read_key,
#ifdef CAVIUM_MULTICARD_API
                            &dummy,dev_id
#else
                            &dummy
#endif
                 );
  if (ret)
    {
      goto err;
    }

  ret = Csp1HandshakeUpdate (CAVIUM_BLOCKING,
			     context_handle, act_size, &message[16],
#ifdef CAVIUM_MULTICARD_API
                               &dummy,dev_id
#else
                               &dummy
#endif
                 );
  if (ret)
    {
      goto err;
    }

  ret = Csp1HandshakeFinish (CAVIUM_BLOCKING,
			     context_handle,
			     4, (Uint8 *) & seq, mac, &mac[16],
#ifdef CAVIUM_MULTICARD_API
                               &dummy,dev_id
#else
                               &dummy
#endif
                 );
  if (ret)
    {
      goto err;
    }

  /* compare mac */
  if (memcmp (message, mac, mac_size))
    {
      ret = ERR_BAD_CIPHER_OR_MAC;
      goto err;
    }

  /* expect the next number */
  INC32 (read_seq);

  /* copy read sequence to context memory */
  ctx_ptr = context_handle + (8 * OFFSET_SSL2_RC4_SERVER_READ_SEQ);
  ret =
    Csp1WriteContext (CAVIUM_BLOCKING, ctx_ptr, 8, (Uint8 *) & read_seq,
#ifdef CAVIUM_MULTICARD_API
                      &dummy,dev_id
#else
                      &dummy
#endif
                 );
  if (ret)
    {

      goto err;
    }

  ret = 0;
err:
  return ret;
#endif
}


/*+****************************************************************************
 *
 * Csp1Ssl20EncryptRecordRc4
 *
 * Input
 *	request_type = CAVIUM_BLOCKING or CAVIUM_NON_BLOCKING
 *	context_handle = 64-bit pointer to context (context_handle%8=0)
 *	message_length = size of message in bytes (0<=length<=2^16-1)
 *	message = pointer to length-byte message 
 *
 * Output
 *	record = pointer to encrypted record 
 *	request_id = Unique ID for this request
 *
 * Return Value
 *	0  = success 
 * >0 = failure or pending
 * see error_codes.txt
 *
 *-***************************************************************************/

Uint32
Csp1Ssl20EncryptRecordRc4 (n1_request_type request_type,
			   Uint64 context_handle,
			   Uint16 message_length,
			   Uint8 * message,
			   Uint8 * record,
#ifdef CAVIUM_MULTICARD_API
                           Uint32 * request_id,Uint32 dev_id
#else
                           Uint32 * request_id
#endif
                 )
{
#ifdef MC2
  return ERR_OPERATION_NOT_SUPPORTED;
#else
  int ret, seq, mac_size, key_size, act_size, l;
  Uint8 mac[36], write_key[24];
  Uint64 ctx_ptr, write_seq;
  Uint32 dummy = 0;

  key_size = 16;
  mac_size = 16;
  act_size = message_length;

  /* mac */
  /* read write seq */
  write_seq = 0;
  ctx_ptr = context_handle + (8 * OFFSET_SSL2_RC4_SERVER_WRITE_SEQ);

  ret =
    Csp1ReadContext (CAVIUM_BLOCKING, ctx_ptr, 8, (Uint8 *) & write_seq,
#ifdef CAVIUM_MULTICARD_API
                     &dummy,dev_id
#else
                     &dummy
#endif
                 );
  if (ret)
    {
      goto err;
    }
  seq = htobe32 ((Uint32) write_seq);

  /* read key */
  ctx_ptr = context_handle + (8 * OFFSET_SSL2_RC4_SERVER_WRITE_KM);

  ret =
#ifdef CAVIUM_MULTICARD_API
    Csp1ReadContext (CAVIUM_BLOCKING, ctx_ptr, key_size, write_key, &dummy,dev_id);
#else
    Csp1ReadContext (CAVIUM_BLOCKING, ctx_ptr, key_size, write_key, &dummy);
#endif
  if (ret)
    {
      goto err;
    }


  ret = Csp1HandshakeStart (CAVIUM_BLOCKING,
			    context_handle, key_size, write_key,
#ifdef CAVIUM_MULTICARD_API
                            &dummy,dev_id
#else
                            &dummy
#endif
                 );
  if (ret)
    {
      goto err;
    }

  ret = Csp1HandshakeUpdate (CAVIUM_BLOCKING,
			     context_handle, message_length, message,
#ifdef CAVIUM_MULTICARD_API
                             &dummy,dev_id
#else
                             &dummy
#endif
                 );
  if (ret)
    {
      goto err;
    }

  ret = Csp1HandshakeFinish (CAVIUM_BLOCKING,
			     context_handle,
			     4, (Uint8 *) & seq, mac, &mac[16],
#ifdef CAVIUM_MULTICARD_API
                               &dummy,dev_id
#else
                               &dummy
#endif
                 );
  if (ret)
    {
      goto err;
    }


  memcpy (record, mac, mac_size);
  memcpy (&record[mac_size], message, message_length);

  l = mac_size + act_size;
  ctx_ptr = context_handle + (8 * OFFSET_SSL2_RC4_SERVER_WRITE_STATE);

  ret = Csp1EncryptRc4 (CAVIUM_BLOCKING,
			ctx_ptr, CAVIUM_UPDATE, l, record, record,
#ifdef CAVIUM_MULTICARD_API
                         &dummy,dev_id
#else
                         &dummy
#endif
                 );
  if (ret)
    {
      goto err;
    }

  /* expect the next number */
  INC32 (write_seq);

  /* copy write sequence to context memory */
  ctx_ptr = context_handle + (8 * OFFSET_SSL2_RC4_SERVER_WRITE_SEQ);
  ret =
    Csp1WriteContext (CAVIUM_BLOCKING, ctx_ptr, 8, (Uint8 *) & write_seq,
#ifdef CAVIUM_MULTICARD_API
                           &dummy,dev_id
#else
                           &dummy
#endif
                 );
  if (ret)
    {
      goto err;
    }

  ret = 0;
err:
  return ret;
#endif
}




/*+****************************************************************************
 *
 * Csp1Ssl20DecryptRecord3Des
 *
 * Input
 *	request_type = CAVIUM_BLOCKING or CAVIUM_NON_BLOCKING
 *	context_handle = 64-bit pointer to context (context_handle%8=0)
 *	des_type = DES or DES3_192
 *	record_length = size of record in bytes (0<=length<=2^16-1)
 *	record = pointer to length-byte encrypted part of record 
 *
 * Output
 *	message = pointer to decrypted message 
 *	request_id = Unique ID for this request
 *
 * Return Value
 *	0  = success 
 * >0 = failure or pending
 * see error_codes.txt
 *
 *-***************************************************************************/

Uint32
Csp1Ssl20DecryptRecord3Des (n1_request_type request_type,
			    Uint64 context_handle,
			    DesType des_type,
			    Uint16 record_length,
			    Uint8 * record,
			    Uint8 * message,
#ifdef CAVIUM_MULTICARD_API
                            Uint32 * request_id,Uint32 dev_id
#else
                            Uint32 * request_id
#endif
                 )
{
#ifdef MC2
  return ERR_OPERATION_NOT_SUPPORTED;
#else
  int ret, seq, mac_size, key_size;
  Uint8 mac[36], read_key[32];	/*read IV also. */
  Uint64 ctx_ptr, read_seq;
  Uint32 dummy = 0;
  mac_size = 16;
  if (des_type == DES)
    key_size = 8;
  else if (des_type == DES3_192)
    key_size = 24;
  else
    {
      ret = ERR_OPERATION_NOT_SUPPORTED;
      goto err;
    }

  ctx_ptr = context_handle + (8 * OFFSET_SSL2_3DES_SERVER_READ_KM);

  ret = Csp1Decrypt3Des (CAVIUM_BLOCKING,
			 ctx_ptr,
			 CAVIUM_UPDATE,
			 record_length, record, message,
#ifdef CAVIUM_MULTICARD_API
                         &dummy,dev_id
#else
                         &dummy
#endif
                 );
  if (ret)
    {
      goto err;
    }

  /* mac */

  /* read sequence number */
  read_seq = 0;
  ctx_ptr = context_handle + (8 * OFFSET_SSL2_3DES_SERVER_READ_SEQ);

  ret =
    Csp1ReadContext (CAVIUM_BLOCKING, ctx_ptr, 8, (Uint8 *) & read_seq,
#ifdef CAVIUM_MULTICARD_API
                      &dummy,dev_id
#else
                      &dummy
#endif
                 );
  if (ret)
    {
      goto err;
    }
  seq = htobe32 ((Uint32) read_seq);

  /* read key */
  ctx_ptr = context_handle + (8 * OFFSET_SSL2_3DES_SERVER_READ_KM);

  ret =
    Csp1ReadContext (CAVIUM_BLOCKING, ctx_ptr, key_size + 8, read_key,
#ifdef CAVIUM_MULTICARD_API
                      &dummy,dev_id
#else
                      &dummy
#endif
                 );
  if (ret)
    {
      goto err;
    }

  ret = Csp1HandshakeStart (CAVIUM_BLOCKING, context_handle, key_size, &read_key[8],
#ifdef CAVIUM_MULTICARD_API
              &dummy,dev_id
#else
              &dummy
#endif
              );

  if (ret)
    {
      goto err;
    }

  ret = Csp1HandshakeUpdate (CAVIUM_BLOCKING,
			     context_handle,
			     record_length - 16, &message[16],
#ifdef CAVIUM_MULTICARD_API
                             &dummy,dev_id
#else
                             &dummy
#endif
                 );
  if (ret)
    {
      goto err;
    }

  ret = Csp1HandshakeFinish (CAVIUM_BLOCKING,
			     context_handle,
			     4, (Uint8 *) & seq, mac, &mac[16],
#ifdef CAVIUM_MULTICARD_API
                               &dummy,dev_id
#else
                               &dummy
#endif
                 );
  if (ret)
    {
      goto err;
    }

  /* compare mac */
  if (memcmp (message, mac, 16))
    {
      ret = ERR_BAD_CIPHER_OR_MAC;
      goto err;
    }

  INC32 (read_seq);


  /* copy read sequence to context memory */
  ctx_ptr = context_handle + (8 * OFFSET_SSL2_3DES_SERVER_READ_SEQ);
  ret =
    Csp1WriteContext (CAVIUM_BLOCKING, ctx_ptr, 8, (Uint8 *) & read_seq,
#ifdef CAVIUM_MULTICARD_API
                      &dummy,dev_id
#else
                      &dummy
#endif
                 );
  if (ret)
    {
      goto err;
    }

  ret = 0;
err:
  return ret;
#endif
}



/*+****************************************************************************
 *
 * Csp1Ssl20EncryptRecord3Des
 *
 * Input
 *	request_type = CAVIUM_BLOCKING or CAVIUM_NON_BLOCKING
 *	context_handle = 64-bit pointer to context (context_handle%8=0)
 *	des_type = DES or DES3_192
 *	message_length = size of message in bytes (0<=length<=2^16-1)
 *	message = pointer to length-byte message 
 *
 * Output
 *	record = pointer to encrypted record 
 *	request_id = Unique ID for this request
 *
 * Return Value
 *	0  = success 
 * >0 = failure or pending
 * see error_codes.txt
 *
 *-***************************************************************************/

Uint32
Csp1Ssl20EncryptRecord3Des (n1_request_type request_type,
			    Uint64 context_handle,
			    DesType des_type,
			    Uint16 message_length,
			    Uint8 * message,
			    Uint16 * record_length,
			    Uint8 * record,
#ifdef CAVIUM_MULTICARD_API
                            Uint32 * request_id,Uint32 dev_id
#else
                            Uint32 * request_id
#endif
                 )
{
#ifdef MC2
  return ERR_OPERATION_NOT_SUPPORTED;
#else

  int ret, seq, mac_size, key_size, act_size, l, pad;
  Uint8 mac[36], write_key[32], padb[8];
  Uint64 ctx_ptr, write_seq;
  Uint32 dummy = 0;
  if (des_type == DES)
    key_size = 8;
  else if (des_type == DES3_192)
    key_size = 24;
  else
    {
      ret = ERR_OPERATION_NOT_SUPPORTED;
      goto err;
    }

  memset (padb, 0, 8);
  mac_size = 16;
  pad = 8 - ((mac_size + message_length) % 8);
  act_size = message_length + pad;


  /* append pad bytes to the message */
  memcpy (&message[message_length], padb, pad);

  /* mac */
  /* read write seq */

  write_seq = 0;
  ctx_ptr = context_handle + (8 * OFFSET_SSL2_3DES_SERVER_WRITE_SEQ);

  ret =
    Csp1ReadContext (CAVIUM_BLOCKING, ctx_ptr, 8, (Uint8 *) & write_seq,
#ifdef CAVIUM_MULTICARD_API
                      &dummy,dev_id
#else
                      &dummy
#endif
                 );
  if (ret)
    {
      goto err;
    }
  seq = htobe32 ((Uint32) write_seq);

  /* read key */
  ctx_ptr = context_handle + (8 * OFFSET_SSL2_3DES_SERVER_WRITE_KM);

  ret = Csp1ReadContext (CAVIUM_BLOCKING, ctx_ptr, key_size + 8, write_key,
#ifdef CAVIUM_MULTICARD_API
                          &dummy,dev_id
#else
                          &dummy
#endif
                 );
  if (ret)
    {
      goto err;
    }


  ret = Csp1HandshakeStart (CAVIUM_BLOCKING,
			    context_handle, key_size, &write_key[8],
#ifdef CAVIUM_MULTICARD_API
                            &dummy,dev_id
#else
                            &dummy
#endif
                 );
  if (ret)
    {
      goto err;
    }

  ret = Csp1HandshakeUpdate (CAVIUM_BLOCKING,
			     context_handle, act_size, message,
#ifdef CAVIUM_MULTICARD_API
                             &dummy,dev_id
#else
                             &dummy
#endif
                 );
  if (ret)
    {
      goto err;
    }

  ret = Csp1HandshakeFinish (CAVIUM_BLOCKING,
			     context_handle,
			     4, (Uint8 *) & seq, mac, &mac[16],
#ifdef CAVIUM_MULTICARD_API
                               &dummy,dev_id
#else
                               &dummy
#endif
                 );
  if (ret)
    {
      goto err;
    }


  memcpy (record, mac, mac_size);
  memcpy (&record[mac_size], message, act_size);

  l = mac_size + act_size;
  ctx_ptr = context_handle + (8 * OFFSET_SSL2_3DES_SERVER_WRITE_KM);

  ret = Csp1Encrypt3Des (CAVIUM_BLOCKING,
			 ctx_ptr, CAVIUM_UPDATE, l, record, record,
#ifdef CAVIUM_MULTICARD_API
                         &dummy,dev_id
#else
                         &dummy
#endif
                 );
  if (ret)
    {
      goto err;
    }

  /* expect the next number */
  INC32 (write_seq);

  /* copy write sequence to context memory */
  ctx_ptr = context_handle + (8 * OFFSET_SSL2_3DES_SERVER_WRITE_SEQ);
  ret =
    Csp1WriteContext (CAVIUM_BLOCKING, ctx_ptr, 8, (Uint8 *) & write_seq,
#ifdef CAVIUM_MULTICARD_API
                       &dummy,dev_id
#else
                       &dummy
#endif
                 );
  if (ret)
    {
      goto err;
    }

  *record_length = l;
  ret = 0;
err:
  return ret;
#endif
}



#ifndef MC2
/* some utility functions */

static void
pkp_leftfill (unsigned char input[], int length, unsigned char output[],
	      int finallength)
{
  int i;
  int j;
  memset (output, 0, finallength);
  j = finallength - 1;
  for (i = length - 1; i >= 0; i--)
    {
      output[j] = input[i];
      j = j - 1;
    }
}



static void
swap_word_openssl (unsigned char *d, unsigned char *s, int len)
{
  int i, j;
  Uint64 *ps;
  Uint64 *pd;

  j = 0;

  ps = (Uint64 *) s;
  pd = (Uint64 *) d;

  for (i = (len >> 3) - 1; i >= 0; i--)
    {
      pd[j] = ps[i];
      j++;
    }

}
#endif /* MC2 */

/*
 * $Id: cavium_ssl.c,v 1.13 2009/10/19 09:05:36 aravikumar Exp $
 * $Log: cavium_ssl.c,v $
 * Revision 1.13  2009/10/19 09:05:36  aravikumar
 * CAIUM_SSL_GRP state added for AesResume
 *
 * Revision 1.12  2009/09/11 06:50:40  aravikumar
 * Added buffer.group=CAVIUM_SSL_GRP statement to all APIs
 *
 * Revision 1.11  2009/06/25 05:21:09  aravikumar
 * fifteenth bit of opcode set to 1 for encryption and 0 for decryption to
 * identitify
 *
 * Revision 1.10  2008/08/12 10:48:46  aramesh
 * deleted gpkpdev_keyhandle
 *
 * Revision 1.9  2008/06/05 06:44:56  sshekkari
 * Modified Rsa Handshake operations to support modlength upto 4096-bits.
 *
 * Revision 1.8  2007/10/26 13:48:37  kchunduri
 * --memset 'Csp1OperationBuffer' to zero to overcome issues observed with gcc-4.1.
 *
 * Revision 1.7  2007/10/24 05:21:21  aramesh
 * unused variable tmp_keyhd1 warning fixed
 *
 * Revision 1.6  2007/10/18 09:35:09  lpathy
 * Added windows support.
 *
 * Revision 1.5  2007/09/17 09:18:06  kchunduri
 * --Cannot send NULL Key handler Pointer.
 *
 * Revision 1.4  2007/09/10 10:15:22  kchunduri
 * --API changed to accept 'dev_id' as input parameter.
 *
 * Revision 1.3  2007/06/18 06:26:14  tghoriparti
 * header files for memset, alloca, memcpy added
 *
 * Revision 1.2  2007/05/01 05:45:37  kchunduri
 * * modified UIT64_C macro.
 *
 * Revision 1.1  2007/01/15 23:17:42  panicker
 * *** empty log message ***
 *
 * Revision 1.24  2006/08/16 14:38:06  kchunduri
 * --the status of IOCTL_N1_OPERATION is available in 'status' field. Earlier the status is a return parameter.
 *
 * Revision 1.23  2006/08/11 10:51:51  kchunduri
 * --fix compilation problem on freebsd-4.11
 *
 * Revision 1.22  2006/05/16 13:46:36  kchunduri
 * --fix compilation warning
 *
 * Revision 1.21  2006/05/16 09:56:04  kchunduri
 * --changes to support re-aligned API structures
 *
 * Revision 1.20  2006/01/27 06:19:34  ksadasivuni
 * - rolled back ssl queue changes
 *
 * Revision 1.19  2006/01/24 12:58:50  ksadasivuni
 * -  All SSL requests now use queue 1(data plane) instead of
 *    queue 0( control plane).
 *
 * Revision 1.18  2005/11/17 13:31:09  kanantha
 * Updating with the 64 bit modifications, with proper matching of data types
 *
 * Revision 1.17  2005/09/29 12:22:18  sgadam
 * Moving the FreeBSD AMD64 changes back to the head
 *
 * Revision 1.15  2005/09/28 15:39:30  ksadasivuni
 * - Merging FreeBSD 6.0 ADM64 release with CVS Head
 * - In ipsec_mc2.c the change is due to passing of physical context pointer
 * directly to userspace application. So no need for vtophys
 *
 * Revision 1.14  2005/09/27 07:47:36  sgadam
 * Fixed Warnings on FC4
 *
 * Revision 1.13  2005/09/02 11:13:59  ksadasivuni
 * - Added ULL suffix to long constants.
 *   Latest versions of gcc gives warning without it.
 *
 * Revision 1.12  2005/02/01 04:04:56  bimran
 * copyright fix
 *
 * Revision 1.11  2004/05/02 19:35:13  bimran
 * Added Copyright notice.
 *
 * Revision 1.10  2004/05/01 05:57:44  bimran
 * Fixed a function descriptions on each function to match with the latest microcode and driver.
 *
 * Revision 1.9  2004/04/30 21:20:20  bimran
 * Recover functiosn are only applicable to MC1.
 *
 * Revision 1.8  2004/04/29 03:39:49  bimran
 * Added MC2 support to OtherVerify* functions so that client auth would work with export ciphers.
 *
 * Revision 1.7  2004/04/28 22:05:32  bimran
 * Fixed OtherFullRc4 for MC1.
 *
 * Revision 1.6  2004/04/28 03:16:03  bimran
 * Fixed comments.
 *
 * Revision 1.5  2004/04/28 01:24:08  bimran
 * Added MC2 support to all OtherFull* functions.
 *
 * Revision 1.4  2004/04/26 22:32:02  tsingh
 * Fixed RsaServerFullAes.
 *
 * Revision 1.3  2004/04/23 21:47:15  bimran
 * Lot of cleanup.
 * Removed all OS dependencies.
 * It should all be just ioctl.
 *
 * Revision 1.2  2004/04/16 23:56:46  bimran
 * Fixed include directives. It is our API headfer file, it should not have any reference to openssl.
 * Fixed indentation.
 *
 * Revision 1.1  2004/04/15 22:38:38  bimran
 * Checkin of the code from India with some cleanups.
 *
 */
