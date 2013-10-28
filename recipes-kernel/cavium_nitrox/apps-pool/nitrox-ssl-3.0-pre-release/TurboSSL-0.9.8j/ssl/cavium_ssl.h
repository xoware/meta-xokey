
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
/******************************************/
/* cavium_ssl.h                           */
/*                                        */
/* Copyright 2001 by Caveo Networks, Inc. */
/*                                        */
/* Structs used to transfer data between  */
/* the shim layer and the driver.         */ 
/******************************************/


#ifndef _CAVIUM_SSL_H_
#define _CAVIUM_SSL_H_

#ifndef CSP1_KERNEL


typedef enum {VER_TLS = 0, VER3_0 = 1} SslVersion;
#ifdef MC2
typedef enum {UNSUPPORTED_RC4 = -1, RC4_128 = 8, RC4_EXPORT_40 = 9, RC4_EXPORT_56 = 11} Rc4Type;
typedef enum {UNSUPPORTED_DES = -1, DES = 12, DES_EXPORT_40 = 13, DES3_192 = 14} DesType;
#else
typedef enum {UNSUPPORTED_RC4 = -1, RC4_128 = 0, RC4_EXPORT_40 = 1, RC4_EXPORT_56 = 7} Rc4Type;
typedef enum {UNSUPPORTED_DES = -1, DES = 0, DES_EXPORT_40 = 1, DES3_192 = 2} DesType;
#endif
typedef enum {CHANGE_CIPHER_SPEC = 0, ALERT = 1, HANDSHAKE = 2, APP_DATA = 3} MessageType;
typedef enum {NOT_RETURNED = 0, RETURN_ENCRYPTED = 1} MasterSecretReturn;
typedef enum {READ_FROM_CONTEXT = 0, INPUT_ENCRYPTED = 1} MasterSecretInput;
typedef enum {RETURN_CFM_ENCRYPTED = 0, RETURN_CFM_UNENCRYPTED = 1} ClientFinishMessageOutput;
typedef enum {RETURN_SFM_ENCRYPTED = 0, RETURN_SFM_UNENCRYPTED = 1} ServerFinishMessageOutput;
typedef enum {SSL_SERVER = 0, SSL_CLIENT = 1} SslPartyType;


/* SSLv2 specific Context Offsets */

#define OFFSET_SSL2_MASTER_SECRET				16

#define OFFSET_SSL2_3DES_SERVER_READ_SEQ		22
#define OFFSET_SSL2_3DES_SERVER_READ_KM			24
#define OFFSET_SSL2_3DES_SERVER_WRITE_SEQ		28
#define OFFSET_SSL2_3DES_SERVER_WRITE_KM		30

#define OFFSET_SSL2_RC4_SERVER_READ_SEQ			22
#define OFFSET_SSL2_RC4_SERVER_READ_KM			24
#define OFFSET_SSL2_RC4_SERVER_READ_STATE		26
#define OFFSET_SSL2_RC4_SERVER_WRITE_SEQ		60
#define OFFSET_SSL2_RC4_SERVER_WRITE_KM			62
#define OFFSET_SSL2_RC4_SERVER_WRITE_STATE		64



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
 * DmaMode: DIRECT=0, SCATTER_GATHER=1.
 *
 *-***************************************************************************/
DmaMode 
Csp1GetDmaMode(void);



/*+****************************************************************************
 *
 * Csp1GetDriverState
 * 
 * Function to check whether the driver handle is initialzed or not.
 *
 * Input
 *  none
 * 
 * Ouput
 *  none
 *
 * Return Value
 * 0  = driver handle is ready.
 * -1 = driver handle is not initialized
 *-***************************************************************************/
int 
Csp1GetDriverState(void);

/*+****************************************************************************
 *
 * Csp1SetEncryptedMasterSecretKey
 *
 * Sets the key material for encryption of master secrets used by resume 
 * operations.
 *
 * Input
 *	key = pointer to 48 bytes of key material
 *
 * Return Value
 *	completion code = 0 (for success), ERR_BAD_IOCTL, or 
 *	ERR_BAD_KEY_HANDLE
 *
 *-***************************************************************************/
Uint32 
Csp1SetEncryptedMasterSecretKey(Uint8 *key);

/*+****************************************************************************
 *
 * Csp1Handshake
 *
 * Calculates the hashes needed by the SSL handshake.
 *
 * Input
 *	context_handle = 64-bit pointer to context (context_handle%8=0)
 *	message_length = size of input in bytes (0<=message_length<=2^16-1)
 *	message = pointer to length bytes of input
 *
 * Output
 *	md5_final_hash = pointer to the 4-word handshake intermediate result 
 *	sha1_final_hash = pointer to the 5-word handshake intermediate result 
 *
 * Return Value
 *	completion code = 0 (for success), ERR_BAD_SIZE_OR_DLEN_VAL, 
 *	ERR_BAD_IOCTL, ERR_INSTRUCTION_TIMEOUT, or ERR_ILLEGAL_CONTEXT_HANDLE 
 *
 *-***************************************************************************/
Uint32 
Csp1Handshake(Csp1RequestType request_type,
			  Uint64 context_handle, 
			  Uint16 message_length, 
			  Uint8 *message, 
			  Uint8 *md5_final_hash, 
			  Uint8 *sha1_final_hash,
			  Uint32 *request_id);


/*+****************************************************************************
 *
 * Csp1HandshakeStart
 *
 * Calculates the partial hashes needed by the SSL handshake.
 *
 * Input
 *	context_handle = 64-bit pointer to context (context_handle%8=0)
 *	message_length = size of input in bytes (0<=message_length<=2^16-1)
 *	message = pointer to length bytes of input
 *
 * Return Value
 *	completion code = 0 (for success), ERR_BAD_SIZE_OR_DLEN_VAL, 
 *	ERR_BAD_IOCTL, ERR_INSTRUCTION_TIMEOUT, or ERR_ILLEGAL_CONTEXT_HANDLE 
 *
 *-***************************************************************************/
Uint32 
Csp1HandshakeStart(Csp1RequestType request_type,
				   Uint64 context_handle, 
				   Uint16 message_length, 
				   Uint8 *message,
				   Uint32 *request_id);


/*+****************************************************************************
 *
 * Csp1HandshakeUpdate
 *
 * Calculates the partial hashes needed by the SSL handshake.
 *
 * Input
 *	context_handle = 64-bit pointer to context (context_handle%8=0)
 *	message_length = size of input in bytes (0<=message_length<=2^16-1)
 *	message = pointer to length bytes of input
 *
 * Return Value
 *	completion code = 0 (for success), ERR_BAD_SIZE_OR_DLEN_VAL, 
 *	ERR_BAD_IOCTL, ERR_INSTRUCTION_TIMEOUT, or ERR_ILLEGAL_CONTEXT_HANDLE
 *
 *-***************************************************************************/
Uint32 
Csp1HandshakeUpdate(n1_request_type request_type,
					Uint64 context_handle, 
				    Uint16 message_length, 
				    Uint8 *message,
					Uint32 *request_id);


/*+****************************************************************************
 *
 * Csp1HandshakeFinish
 *
 * Input
 *	context_handle = 64-bit pointer to context (context_handle%8=0)
 *	message_length = size of input in bytes (0<=message_length<=2^16-1)
 *	message = pointer to length bytes of input
 *
 * Output
 *	md5_final_hash = pointer to the 4-word handshake final result 
 *	sha1_final_hash = pointer to the 5-word handshake final result 
 *
 * Return Value
 *	completion code = 0 (for success), ERR_BAD_SIZE_OR_DLEN_VAL, 
 *	ERR_BAD_IOCTL, ERR_INSTRUCTION_TIMEOUT, or ERR_ILLEGAL_CONTEXT_HANDLE
 *
 *-***************************************************************************/
Uint32 
Csp1HandshakeFinish(n1_request_type request_type,
					Uint64 context_handle, 
				    Uint16 message_length, 
				    Uint8 *message, 
				    Uint8 *md5_final_hash, 
				    Uint8 *sha1_final_hash,
					Uint32 *request_id);



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
 *	context_handle = 64-bit byte-pointer to context (context_handle%8=0)
 *	key_handle = pointer to 64-bit key memory handle
 *	hash_type = MD5_TYPE or SHA1_TYPE
 *	ssl_version = VER3_0 or VER_TLS
 *	rc4_type = RC4_128, RC4_EXPORT_40, or RC4_EXPORT_56
 *	master_secret_ret = NOT_RETURNED or RETURN_ENCRYPTED
 *	modlength = size of RSA operation in bytes (64<=modlength<=256, modlength%8=0)
 *	encrypt_premaster_secret = pointer to modlength-byte value in integer format
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
 *
 * Return Value
 *	completion code = 0 (for success), ERR_BAD_SIZE_OR_DLEN_VAL, 
 *	ERR_BAD_PKCS_PAD_OR_LENGTH, ERR_BAD_PKCS_TYPE, ERR_BAD_IOCTL, 
 *	ERR_INSTRUCTION_TIMEOUT, ERR_ILLEGAL_CONTEXT_HANDLE,  
 *	ERR_ILLEGAL_KEY_HANDLE, or ERR_ILLEGAL_INPUT_LENGTH 
 *
 *-***************************************************************************/
Uint32 
Csp1RsaServerFullRc4(n1_request_type request_type,
					 Uint64 context_handle, 
				     Uint64 *key_handle, 
				     HashType hash_type, 
				     SslVersion ssl_version, 
				     Rc4Type rc4_type,
				     MasterSecretReturn master_secret_ret,
				     Uint16 modlength, 
				     Uint8 *encrypt_premaster_secret, 
				     Uint8 *client_random, 
				     Uint8 *server_random, 
				     Uint16 handshake_length, 
				     Uint8 *handshake, 
				     Uint8 *client_finished_message,
				     Uint8 *server_finished_message, 
					 Uint8 *encrypt_master_secret,
					 Uint32 *request_id);


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
 *	context_handle = 64-bit byte-pointer to context (context_handle%8=0)
 *	key_handle = pointer to 64-bit key memory handle
 *	hash_type = MD5_TYPE or SHA1_TYPE
 *	ssl_version = VER3_0 or VER_TLS
 *	rc4_type = RC4_128, RC4_EXPORT_40, or RC4_EXPORT_56
 *	master_secret_ret = NOT_RETURNED or RETURN_ENCRYPTED
 *	modlength = size of RSA operation in bytes (64<=modlength<=256, modlength%8=0)
 *	encrypt_premaster_secret = pointer to modlength-byte value in integer format
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
 *
 * Return Value
 *	completion code = 0 (for success), ERR_BAD_SIZE_OR_DLEN_VAL, 
 *	ERR_BAD_PKCS_PAD_OR_LENGTH, ERR_BAD_PKCS_TYPE, ERR_BAD_IOCTL, 
 *	ERR_INSTRUCTION_TIMEOUT, ERR_ILLEGAL_CONTEXT_HANDLE, 
 *	ERR_ILLEGAL_KEY_HANDLE, or ERR_ILLEGAL_INPUT_LENGTH
 *
 *-***************************************************************************/
Uint32 
Csp1RsaServerFullRc4Finish(n1_request_type request_type,
						   Uint64 context_handle, 
				           Uint64 *key_handle, 
					       HashType hash_type, 
					       SslVersion ssl_version, 
					       Rc4Type rc4_type, 
					       MasterSecretReturn master_secret_ret,
					       Uint16 modlength, 
					       Uint8 *encrypt_premaster_secret, 
					       Uint8 *client_random, 
					       Uint8 *server_random, 
					       Uint16 handshake_length, 
					       Uint8 *handshake, 
					       Uint8 *client_finished_message,
					       Uint8 *server_finished_message, 
					       Uint8 *encrypt_master_secret,
						   Uint32 *request_id);


/*+****************************************************************************
 *
 * Csp1RsaServerVerifyRc4
 *
 * With RSA <= 1024, do much of the full handshake - up to the point of the 
 * verify - in the case when client authentication is required. This is used in 
 * a full handshake on the server. This entry point handles all the RC4 cases.
 *
 * The handshake message data for this request should include all handshake 
 * message data after (and including) the client hello message up until (but 
 * not including) the client verify message.  
 *
 * Input
 *	context_handle = 64-bit byte-pointer to context (context_handle%8=0)
 *	key_handle = pointer to 64-bit key memory handle
 *	hash_type = MD5_TYPE or SHA1_TYPE
 *	ssl_version = VER3_0 or VER_TLS
 *	rc4_type = RC4_128, RC4_EXPORT_40, or RC4_EXPORT_56
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
 *
 * Return Value
 *	completion code = 0 (for success), ERR_BAD_SIZE_OR_DLEN_VAL, 
 *	ERR_BAD_PKCS_PAD_OR_LENGTH, ERR_BAD_PKCS_TYPE, ERR_BAD_IOCTL, 
 *	ERR_INSTRUCTION_TIMEOUT, ERR_ILLEGAL_CONTEXT_HANDLE, 
 *	ERR_ILLEGAL_KEY_HANDLE, or ERR_ILLEGAL_INPUT_LENGTH
 *
 *-***************************************************************************/
Uint32 
Csp1RsaServerVerifyRc4(n1_request_type request_type,
					   Uint64 context_handle, 
				       Uint64 *key_handle, 
				       HashType hash_type, 
				       SslVersion ssl_version, 
				       Rc4Type rc4_type, 
				       MasterSecretReturn master_secret_ret,
				       Uint16 modlength, 
				       Uint8 *encrypt_premaster_secret, 
				       Uint8 *client_random, 
				       Uint8 *server_random, 
				       Uint16 handshake_length, 
				       Uint8 *handshake, 
				       Uint8 *verify_data,
					   Uint8 *encrypt_master_secret,
					   Uint32 *request_id);


/*+****************************************************************************
 *
 * Csp1RsaServerVerifyRc4Finish
 *
 * With RSA <= 1024, do much of the full handshake - up to the point of the 
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
 *	context_handle = 64-bit byte-pointer to context (context_handle%8=0)
 *	key_handle = pointer to 64-bit key memory handle
 *	hash_type = MD5_TYPE or SHA1_TYPE
 *	ssl_version = VER3_0 or VER_TLS
 *	rc4_type = RC4_128, RC4_EXPORT_40, or RC4_EXPORT_56
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
 *
 * Return Value
 *	completion code = 0 (for success), ERR_BAD_SIZE_OR_DLEN_VAL, 
 *	ERR_BAD_PKCS_PAD_OR_LENGTH, ERR_BAD_PKCS_TYPE, ERR_BAD_IOCTL, 
 *	ERR_INSTRUCTION_TIMEOUT, ERR_ILLEGAL_CONTEXT_HANDLE, 
 *	ERR_ILLEGAL_KEY_HANDLE, or ERR_ILLEGAL_INPUT_LENGTH
 *
 *-***************************************************************************/
Uint32 
Csp1RsaServerVerifyRc4Finish(n1_request_type request_type,
							 Uint64 context_handle, 
				             Uint64 *key_handle, 
						     HashType hash_type, 
						     SslVersion ssl_version, 
						     Rc4Type rc4_type, 
						     MasterSecretReturn master_secret_ret,
						     Uint16 modlength, 
						     Uint8 *encrypt_premaster_secret, 
						     Uint8 *client_random, 
						     Uint8 *server_random, 
						     Uint16 handshake_length, 
						     Uint8 *handshake, 
						     Uint8 *verify_data,
					         Uint8 *encrypt_master_secret,
							 Uint32 *request_id);


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
 *	context_handle = 64-bit byte-pointer to context (context_handle%8=0)
 *	key_handle = pointer to 64-bit key memory handle
 *	hash_type = MD5_TYPE or SHA1_TYPE
 *	ssl_version = VER3_0 or VER_TLS
 *	des_type = DES, DES_EXPORT_40 or DES3_192
 *	master_secret_ret = NOT_RETURNED or RETURN_ENCRYPTED
 *	clnt_fin_msg_out = RETURN_ENCRYPTED or RETURN_UNENCRYPTED
 *	srvr_fin_msg_out = RETURN_ENCRYPTED or RETURN_UNENCRYPTED
 *	client_pad_length = number of 64-bit words to pad above min
 *	server_pad_length = number of 64-bit words to pad above min
 *	modlength = size of RSA operation in bytes (64<=modlength<=256, modlength%8=0)
 *	encrypt_premaster_secret = pointer to modlength-byte value in integer format
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
 *
 * Return Value
 *	completion code = 0 (for success), ERR_BAD_SIZE_OR_DLEN_VAL,
 *	ERR_BAD_PKCS_PAD_OR_LENGTH, ERR_BAD_PKCS_TYPE, ERR_BAD_IOCTL, 
 *	ERR_INSTRUCTION_TIMEOUT, ERR_ILLEGAL_CONTEXT_HANDLE, 
 *	ERR_ILLEGAL_KEY_HANDLE, or ERR_ILLEGAL_INPUT_LENGTH 
 *
 *-***************************************************************************/
Uint32 
Csp1RsaServerFull3Des(n1_request_type request_type,
					  Uint64 context_handle, 
				      Uint64 *key_handle, 
				      HashType hash_type, 
				      SslVersion ssl_version, 
				      DesType des_type, 
				      MasterSecretReturn master_secret_ret,
					  ClientFinishMessageOutput clnt_fin_msg_out,
					  ServerFinishMessageOutput srvr_fin_msg_out,
				      Uint16 client_pad_length,
				      Uint16 server_pad_length,
				      Uint16 modlength, 
				      Uint8 *encrypt_premaster_secret, 
				      Uint8 *client_random, 
				      Uint8 *server_random, 
				      Uint16 handshake_length, 
				      Uint8 *handshake, 
				      Uint8 *client_finished_message,
				      Uint8 *server_finished_message, 
					  Uint8 *encrypt_master_secret,
					  Uint32 *request_id);


/*+****************************************************************************
 *
 * Csp1RsaServerFull3DesFinish
 *
 * Does a full handshake on the server with RSA <= 1024. This entry point 
 * handles all the DES cases. The handshake data is accumulated prior to this 
 * request by calls to Handshake*, and this request appends the 
 * included handshake message data to the pre-existing handshake hash state.
 * The handshake message data for this request should include all handshake 
 * message data after (and including) the client hello message up until 
 * (but not including) the first finished message. 
 *
 * Input
 *	context_handle = 64-bit byte-pointer to context (context_handle%8=0)
 *	key_handle = pointer to 64-bit key memory handle
 *	hash_type = MD5_TYPE or SHA1_TYPE
 *	ssl_version = VER3_0 or VER_TLS
 *	des_type = DES, DES_EXPORT_40 or DES3_192
 *	master_secret_ret = NOT_RETURNED or RETURN_ENCRYPTED
 *	clnt_fin_msg_out = RETURN_ENCRYPTED or RETURN_UNENCRYPTED
 *	srvr_fin_msg_out = RETURN_ENCRYPTED or RETURN_UNENCRYPTED
 *	client_pad_length = number of 64-bit words to pad above min
 *	server_pad_length = number of 64-bit words to pad above min
 *	modlength = size of RSA operation in bytes (64<=modlength<=256, modlength%8=0)
 *	encrypt_premaster_secret = pointer to modlength-byte value in integer format
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
 *
 * Return Value
 *	completion code = 0 (for success), ERR_BAD_SIZE_OR_DLEN_VAL,
 *	ERR_BAD_PKCS_PAD_OR_LENGTH, ERR_BAD_PKCS_TYPE, ERR_BAD_IOCTL,  
 *	ERR_INSTRUCTION_TIMEOUT, ERR_ILLEGAL_CONTEXT_HANDLE,  
 *	ERR_ILLEGAL_KEY_HANDLE, or ERR_ILLEGAL_INPUT_LENGTH 
 *
 *-***************************************************************************/
Uint32 
Csp1RsaServerFull3DesFinish(n1_request_type request_type,
							Uint64 context_handle, 
				            Uint64 *key_handle, 
					        HashType hash_type, 
					        SslVersion ssl_version, 
					        DesType des_type, 
				            MasterSecretReturn master_secret_ret,
							ClientFinishMessageOutput clnt_fin_msg_out,
							ServerFinishMessageOutput srvr_fin_msg_out,
					        Uint16 client_pad_length,
					        Uint16 server_pad_length,
					        Uint16 modlength, 
					        Uint8 *encrypt_premaster_secret, 
					        Uint8 *client_random, 
					        Uint8 *server_random, 
					        Uint16 handshake_length, 
					        Uint8 *handshake, 
					        Uint8 *client_finished_message,
					        Uint8 *server_finished_message, 
					        Uint8 *encrypt_master_secret,
							Uint32 *request_id);


/*+****************************************************************************
 *
 * Csp1RsaServerVerify3Des
 *
 * With RSA <= 1024, do much of the full handshake - up to the point of the 
 * verify - in the case when client authentication is required. This is used in 
 * a full handshake on the server. This entry point handles all the DES/3DES 
 * cases.
 *
 * The handshake message data for this request should include all handshake 
 * message data after (and including) the client hello message up until (but 
 * not including) the client verify message. 
 *
 * Input
 *	context_handle = 64-bit byte-pointer to context (context_handle%8=0)
 *	key_handle = pointer to 64-bit key memory handle
 *	hash_type = MD5_TYPE or SHA1_TYPE
 *	ssl_version = VER3_0 or VER_TLS
 *	des_type = DES, DES_EXPORT_40, DES3_192
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
 *
 * Return Value
 *	completion code = 0 (for success), ERR_BAD_SIZE_OR_DLEN_VAL, 
 *	ERR_BAD_PKCS_PAD_OR_LENGTH, ERR_BAD_PKCS_TYPE, ERR_BAD_IOCTL, 
 *	ERR_INSTRUCTION_TIMEOUT, ERR_ILLEGAL_CONTEXT_HANDLE,  
 *	ERR_ILLEGAL_KEY_HANDLE, or ERR_ILLEGAL_INPUT_LENGTH
 *
 *-***************************************************************************/
Uint32 
Csp1RsaServerVerify3Des(n1_request_type request_type,
						Uint64 context_handle, 
				        Uint64 *key_handle, 
				        HashType hash_type, 
				        SslVersion ssl_version, 
				        DesType des_type, 
				        MasterSecretReturn master_secret_ret,
				        Uint16 modlength, 
				        Uint8 *encrypt_premaster_secret, 
				        Uint8 *client_random, 
				        Uint8 *server_random, 
				        Uint16 handshake_length, 
				        Uint8 *handshake, 
				        Uint8 *verify_data,
					    Uint8 *encrypt_master_secret,
						Uint32 *request_id);


/*+****************************************************************************
 *
 * Csp1RsaServerVerify3DesFinish
 *
 * With RSA <= 1024, do much of the full handshake - up to the point of the 
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
 *	context_handle = 64-bit byte-pointer to context (context_handle%8=0)
 *	key_handle = pointer to 64-bit key memory handle
 *	hash_type = MD5_TYPE or SHA1_TYPE
 *	ssl_version = VER3_0 or VER_TLS
 *	des_type = DES, DES_EXPORT_40 or DES3_192
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
 *
 * Return Value
 *	completion code = 0 (for success), ERR_BAD_SIZE_OR_DLEN_VAL, 
 *	ERR_BAD_PKCS_PAD_OR_LENGTH, ERR_BAD_PKCS_TYPE, ERR_BAD_IOCTL,  
 *	ERR_INSTRUCTION_TIMEOUT, ERR_ILLEGAL_CONTEXT_HANDLE, 
 *	ERR_ILLEGAL_KEY_HANDLE, or ERR_ILLEGAL_INPUT_LENGTH
 *
 *-***************************************************************************/
Uint32 
Csp1RsaServerVerify3DesFinish(n1_request_type request_type,
							  Uint64 context_handle, 
				              Uint64 *key_handle, 
						      HashType hash_type, 
						      SslVersion ssl_version, 
						      DesType des_type, 
						      MasterSecretReturn master_secret_ret,
						      Uint16 modlength, 
						      Uint8 *encrypt_premaster_secret, 
						      Uint8 *client_random, 
						      Uint8 *server_random, 
						      Uint16 handshake_length, 
						      Uint8 *handshake, 
						      Uint8 *verify_data,
					          Uint8 *encrypt_master_secret,
							  Uint32 *request_id);


/*+****************************************************************************
 *
 * Csp1RsaServerFullAes
 *
 * Does a full handshake on the server with RSA <= 1024. This entry point 
 * handles all the AES cases. The handshake message data for this request 
 * should include all handshake message data after (and including) the client 
 * hello message up until (but not including) the first finished message. 
 *
 * Input
 *	context_handle = 64-bit byte-pointer to context (context_handle%8=0)
 *	key_handle = pointer to 64-bit key memory handle
 *	hash_type = MD5_TYPE or SHA1_TYPE
 *	ssl_version = VER3_0 or VER_TLS
 *	aes_type = AES_128 or AES_256
 *	master_secret_ret = NOT_RETURNED or RETURN_ENCRYPTED
 *	clnt_fin_msg_out = RETURN_ENCRYPTED or RETURN_UNENCRYPTED
 *	srvr_fin_msg_out = RETURN_ENCRYPTED or RETURN_UNENCRYPTED
 *	client_pad_length = number of 128-bit words to pad above min
 *	server_pad_length = number of 128-bit words to pad above min
 *	modlength = size of RSA operation in bytes (64<=modlength<=256, modlength%8=0)
 *	encrypt_premaster_secret = pointer to modlength-byte value in integer format
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
 *
 * Return Value
 *	completion code = 0 (for success), ERR_BAD_SIZE_OR_DLEN_VAL, 
 *	ERR_BAD_PKCS_PAD_OR_LENGTH, ERR_BAD_PKCS_TYPE, ERR_BAD_IOCTL,  
 *	ERR_INSTRUCTION_TIMEOUT, ERR_ILLEGAL_CONTEXT_HANDLE,  
 *	ERR_ILLEGAL_KEY_HANDLE, or ERR_ILLEGAL_INPUT_LENGTH
 *
 *-***************************************************************************/
Uint32 
Csp1RsaServerFullAes(n1_request_type request_type,
					 Uint64 context_handle, 
				     Uint64 *key_handle, 
				     HashType hash_type, 
				     SslVersion ssl_version, 
				     AesType aes_type, 
				     MasterSecretReturn master_secret_ret,
					 ClientFinishMessageOutput clnt_fin_msg_out,
					 ServerFinishMessageOutput srvr_fin_msg_out,
				     Uint16 client_pad_length,
				     Uint16 server_pad_length,
				     Uint16 modlength, 
				     Uint8 *encrypt_premaster_secret, 
				     Uint8 *client_random, 
				     Uint8 *server_random, 
				     Uint16 handshake_length, 
				     Uint8 *handshake, 
				     Uint8 *client_finished_message,
				     Uint8 *server_finished_message, 
					 Uint8 *encrypt_master_secret,
					 Uint32 *request_id);


/*+****************************************************************************
 *
 * Csp1RsaServerFullAesFinish
 *
 * Does a full handshake on the server with RSA <= 1024. This entry point 
 * handles all the aes cases. The handshake data is accumulated prior to this 
 * request by calls to Handshake*, and this request appends the 
 * included handshake message data to the pre-existing handshake hash state.
 * The handshake message data for this request should include all handshake 
 * message data after (and including) the client hello message up until 
 * (but not including) the first finished message. 
 *
 * Input
 *	context_handle = 64-bit byte-pointer to context (context_handle%8=0)
 *	key_handle = pointer to 64-bit key memory handle
 *	hash_type = MD5_TYPE or SHA1_TYPE
 *	ssl_version = VER3_0 or VER_TLS
 *	aes_type = AES_128 or AES_256
 *	master_secret_ret = NOT_RETURNED or RETURN_ENCRYPTED
 *	clnt_fin_msg_out = RETURN_ENCRYPTED or RETURN_UNENCRYPTED
 *	srvr_fin_msg_out = RETURN_ENCRYPTED or RETURN_UNENCRYPTED
 *	client_pad_length = number of 128-bit words to pad above min
 *	server_pad_length = number of 128-bit words to pad above min
 *	modlength = size of RSA operation in bytes (64<=modlength<=256, modlength%8=0)
 *	encrypt_premaster_secret = pointer to modlength-byte value in integer format
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
 *
 * Return Value
 *	completion code = 0 (for success), ERR_BAD_SIZE_OR_DLEN_VAL, 
 *	ERR_BAD_PKCS_PAD_OR_LENGTH, ERR_BAD_PKCS_TYPE, ERR_BAD_IOCTL, 
 *	ERR_INSTRUCTION_TIMEOUT, ERR_ILLEGAL_CONTEXT_HANDLE, 
 *	ERR_ILLEGAL_KEY_HANDLE, or ERR_ILLEGAL_INPUT_LENGTH
 *
 *-***************************************************************************/
Uint32 
Csp1RsaServerFullAesFinish(n1_request_type request_type,
						   Uint64 context_handle, 
				           Uint64 *key_handle, 
					       HashType hash_type, 
					       SslVersion ssl_version, 
					       AesType aes_type, 
					       MasterSecretReturn master_secret_ret,
						   ClientFinishMessageOutput clnt_fin_msg_out,
						   ServerFinishMessageOutput srvr_fin_msg_out,
					       Uint16 client_pad_length,
					       Uint16 server_pad_length,
					       Uint16 modlength, 
					       Uint8 *encrypt_premaster_secret, 
					       Uint8 *client_random, 
					       Uint8 *server_random, 
					       Uint16 handshake_length, 
					       Uint8 *handshake, 
					       Uint8 *client_finished_message,
					       Uint8 *server_finished_message, 
					       Uint8 *encrypt_master_secret,
						   Uint32 *request_id);


/*+****************************************************************************
 *
 * Csp1RsaServerVerifyAes
 *
 * With RSA <= 1024, do much of the full handshake - up to the point of the 
 * verify - in the case when client authentication is required. This is used in 
 * a full handshake on the server. This entry point handles all the AES cases.
 *
 * The handshake message data for this request should include all handshake 
 * message data after (and including) the client hello message up until (but 
 * not including) the client verify message. 
 *
 * Input
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
 *
 * Return Value
 *	completion code = 0 (for success), ERR_BAD_SIZE_OR_DLEN_VAL, 
 *	ERR_BAD_PKCS_PAD_OR_LENGTH, ERR_BAD_PKCS_TYPE, ERR_BAD_IOCTL, 
 *	ERR_INSTRUCTION_TIMEOUT, ERR_ILLEGAL_CONTEXT_HANDLE, 
 *	ERR_ILLEGAL_KEY_HANDLE, or ERR_ILLEGAL_INPUT_LENGTH
 *
 *-***************************************************************************/
Uint32 
Csp1RsaServerVerifyAes(n1_request_type request_type,
					   Uint64 context_handle, 
				       Uint64 *key_handle, 
				       HashType hash_type, 
				       SslVersion ssl_version, 
				       AesType aes_type, 
				       MasterSecretReturn master_secret_ret,
				       Uint16 modlength, 
				       Uint8 *encrypt_premaster_secret, 
				       Uint8 *client_random, 
				       Uint8 *server_random, 
				       Uint16 handshake_length, 
				       Uint8 *handshake, 
				       Uint8 *verify_data,
					   Uint8 *encrypt_master_secret,
					   Uint32 *request_id);


/*+****************************************************************************
 *
 * Csp1RsaServerVerifyAesFinish
 *
 * With RSA <= 1024, do much of the full handshake - up to the point of the 
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
 *
 * Return Value
 *	completion code = 0 (for success), ERR_BAD_SIZE_OR_DLEN_VAL,
 *	ERR_BAD_PKCS_PAD_OR_LENGTH, ERR_BAD_PKCS_TYPE, ERR_BAD_IOCTL, 
 *	ERR_INSTRUCTION_TIMEOUT, ERR_ILLEGAL_CONTEXT_HANDLE, 
 *	ERR_ILLEGAL_KEY_HANDLE, or ERR_ILLEGAL_INPUT_LENGTH 
 *
 *-***************************************************************************/
Uint32 
Csp1RsaServerVerifyAesFinish(n1_request_type request_type,
							 Uint64 context_handle, 
				             Uint64 *key_handle, 
						     HashType hash_type, 
						     SslVersion ssl_version, 
						     AesType aes_type, 
						     MasterSecretReturn master_secret_ret,
						     Uint16 modlength, 
						     Uint8 *encrypt_premaster_secret, 
						     Uint8 *client_random, 
						     Uint8 *server_random, 
						     Uint16 handshake_length, 
						     Uint8 *handshake, 
						     Uint8 *verify_data,
					         Uint8 *encrypt_master_secret,
							 Uint32 *request_id);


/*+****************************************************************************
 *
 * Csp1OtherFullRc4
 *
 * When not (RSA <= 1024), do a full handshake. The pre-master secret is read
 * from the context and the rest of the handshake is completed. This is used
 * by both the server and the client. This entry point handles all the RC4
 * cases.
 *
 * The handshake message data for this request should include all handshake 
 * message data after (and including) the client hello message up until (but 
 * not including) the first finished message. 
 *
 * Input
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
 *
 * Return Value
 *	completion code = 0 (for success), ERR_BAD_SIZE_OR_DLEN_VAL, 
 *	ERR_BAD_IOCTL, ERR_INSTRUCTION_TIMEOUT, ERR_ILLEGAL_CONTEXT_HANDLE, or  
 *	ERR_ILLEGAL_INPUT_LENGTH
 *
 *-***************************************************************************/
Uint32 
Csp1OtherFullRc4(n1_request_type request_type,
				 Uint64 context_handle, 
			     HashType hash_type, 
			     SslVersion ssl_version, 
			     Rc4Type rc4_type, 
			     MasterSecretReturn master_secret_ret,
			     Uint16 pre_master_length, 
			     Uint8 *client_random, 
			     Uint8 *server_random, 
			     Uint16 handshake_length, 
			     Uint8 *handshake, 
			     Uint8 *client_finished_message,
			     Uint8 *server_finished_message, 
			     Uint8 *encrypt_master_secret,
				 Uint32 *request_id);


/*+****************************************************************************
 *
 * Csp1OtherFullRc4Finish
 *
 * When not (RSA <= 1024), do a full handshake. The pre-master secret is read
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
 *
 * Return Value
 *	completion code = 0 (for success), ERR_BAD_SIZE_OR_DLEN_VAL, 
 *	ERR_BAD_IOCTL, ERR_INSTRUCTION_TIMEOUT, ERR_ILLEGAL_CONTEXT_HANDLE, or  
 *	ERR_ILLEGAL_INPUT_LENGTH
 *
 *-***************************************************************************/
Uint32 
Csp1OtherFullRc4Finish(n1_request_type request_type,
					   Uint64 context_handle, 
				       HashType hash_type, 
				       SslVersion ssl_version, 
				       Rc4Type rc4_type, 
				       MasterSecretReturn master_secret_ret,
				       Uint16 pre_master_length, 
				       Uint8 *client_random, 
				       Uint8 *server_random, 
				       Uint16 handshake_length, 
				       Uint8 *handshake, 
				       Uint8 *client_finished_message,
				       Uint8 *server_finished_message, 
					   Uint8 *encrypt_master_secret,
					   Uint32 *request_id);


/*+****************************************************************************
 *
 * Csp1OtherVerifyRc4
 *
 * When not (RSA <= 1024), do a full handshake - up to the point of the
 * verify operation. The pre-master secret is read from the context.
 * This is used by both the server and the client. This entry point
 * handles all the RC4 cases.
 *
 * The handshake message data for this request should include all handshake 
 * message data after (and including) the client hello message up until (but 
 * not including) the client verify message. 
 *
 * Input
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
 *
 * Return Value
 *	completion code = 0 (for success), ERR_BAD_SIZE_OR_DLEN_VAL, 
 *	ERR_BAD_IOCTL, ERR_INSTRUCTION_TIMEOUT, ERR_ILLEGAL_CONTEXT_HANDLE, or  
 *	ERR_ILLEGAL_INPUT_LENGTH 
 *
 *-***************************************************************************/
Uint32 
Csp1OtherVerifyRc4(n1_request_type request_type,
				   Uint64 context_handle, 
			       HashType hash_type, 
			       SslVersion ssl_version, 
			       Rc4Type rc4_type, 
			       MasterSecretReturn master_secret_ret,
			       Uint16 pre_master_length, 
			       Uint8 *client_random, 
			       Uint8 *server_random, 
			       Uint16 handshake_length, 
			       Uint8 *handshake, 
			       Uint8 *verify_data,
				   Uint8 *encrypt_master_secret,
				   Uint32 *request_id);


/*+****************************************************************************
 *
 * Csp1OtherVerifyRc4Finish
 *
 * When not (RSA <= 1024), do a full handshake - up to the point of the
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
 *
 * Return Value
 *	completion code = 0 (for success), ERR_BAD_SIZE_OR_DLEN_VAL, 
 *	ERR_BAD_IOCTL, ERR_INSTRUCTION_TIMEOUT, ERR_ILLEGAL_CONTEXT_HANDLE, or  
 *	ERR_ILLEGAL_INPUT_LENGTH
 *
 *-***************************************************************************/
Uint32 
Csp1OtherVerifyRc4Finish(n1_request_type request_type,
						 Uint64 context_handle, 
					     HashType hash_type, 
					     SslVersion ssl_version, 
					     Rc4Type rc4_type, 
					     MasterSecretReturn master_secret_ret,
					     Uint16 pre_master_length, 
					     Uint8 *client_random, 
					     Uint8 *server_random, 
					     Uint16 handshake_length, 
					     Uint8 *handshake, 
					     Uint8 *verify_data,
					     Uint8 *encrypt_master_secret,
						 Uint32 *request_id);


/*+****************************************************************************
 *
 * Csp1OtherFull3Des
 *
 * When not (RSA <= 1024), do a full handshake. The pre-master secret is read
 * from the context and the rest of the handshake is completed. This is used
 * by both the server and the client. This entry point handles all the DES/
 * 3DES cases.
 *
 * The handshake message data for this request should include all handshake 
 * message data after (and including) the client hello message up until (but 
 * not including) the first finished message. 
 *
 * Input
 *	context_handle = 64-bit pointer to context (context_handle%8=0)
 *	hash_type = MD5_TYPE or SHA1_TYPE
 *	ssl_version = VER3_0 or VER_TLS
 *	des_type = DES, DES_EXPORT_40 or DES3_192
 *	master_secret_ret = NOT_RETURNED or RETURN_ENCRYPTED
 *	clnt_fin_msg_out = RETURN_ENCRYPTED or RETURN_UNENCRYPTED
 *	srvr_fin_msg_out = RETURN_ENCRYPTED or RETURN_UNENCRYPTED
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
 *
 * Return Value
 *	completion code = 0 (for success), ERR_BAD_SIZE_OR_DLEN_VAL, 
 *	ERR_BAD_IOCTL, ERR_INSTRUCTION_TIMEOUT, ERR_ILLEGAL_CONTEXT_HANDLE, or  
 *	ERR_ILLEGAL_INPUT_LENGTH 
 *
 *-***************************************************************************/
Uint32 
Csp1OtherFull3Des(n1_request_type request_type,
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
			      Uint8 *client_random, 
			      Uint8 *server_random, 
			      Uint16 handshake_length, 
			      Uint8 *handshake, 
			      Uint8 *client_finished_message,
			      Uint8 *server_finished_message, 
				  Uint8 *encrypt_master_secret,
				  Uint32 *request_id);


/*+****************************************************************************
 *
 * Csp1OtherFull3DesFinish
 *
 * When not (RSA <= 1024), do a full handshake. The pre-master secret is read
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
 *	context_handle = 64-bit pointer to context (context_handle%8=0)
 *	hash_type = MD5_TYPE or SHA1_TYPE
 *	ssl_version = VER3_0 or VER_TLS
 *	des_type = DES, DES_EXPORT_40 or DES3_192
 *	master_secret_ret = NOT_RETURNED or RETURN_ENCRYPTED
 *	clnt_fin_msg_out = RETURN_ENCRYPTED or RETURN_UNENCRYPTED
 *	srvr_fin_msg_out = RETURN_ENCRYPTED or RETURN_UNENCRYPTED
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
 *
 * Return Value
 *	completion code = 0 (for success), ERR_BAD_SIZE_OR_DLEN_VAL, 
 *	ERR_BAD_IOCTL, ERR_INSTRUCTION_TIMEOUT, ERR_ILLEGAL_CONTEXT_HANDLE, or  
 *	ERR_ILLEGAL_INPUT_LENGTH
 *
 *-***************************************************************************/
Uint32 
Csp1OtherFull3DesFinish(n1_request_type request_type,
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
				        Uint8 *client_random, 
				        Uint8 *server_random, 
				        Uint16 handshake_length, 
				        Uint8 *handshake, 
				        Uint8 *client_finished_message,
				        Uint8 *server_finished_message, 
					    Uint8 *encrypt_master_secret,
						Uint32 *request_id);


/*+****************************************************************************
 *
 * Csp1OtherVerify3Des
 *
 * When not (RSA <= 1024), do a full handshake - up to the point of the
 * verify operation. The pre-master secret is read from the context.
 * This is used by both the server and the client. This entry point handles all 
 * the DES/3DES cases.
 *
 * The handshake message data for this request should include all handshake 
 * message data after (and including) the client hello message up until (but 
 * not including) the client verify message. 
 *
 * Input
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
 *
 * Return Value
 *	completion code = 0 (for success), ERR_BAD_SIZE_OR_DLEN_VAL, 
 *	ERR_BAD_IOCTL, ERR_INSTRUCTION_TIMEOUT, ERR_ILLEGAL_CONTEXT_HANDLE, or  
 *	ERR_ILLEGAL_INPUT_LENGTH
 *
 *-***************************************************************************/
Uint32 
Csp1OtherVerify3Des(n1_request_type request_type,
					Uint64 context_handle, 
			        HashType hash_type, 
			        SslVersion ssl_version, 
			        DesType des_type, 
				    MasterSecretReturn master_secret_ret,
			        Uint16 pre_master_length, 
			        Uint8 *client_random, 
			        Uint8 *server_random, 
			        Uint16 handshake_length, 
			        Uint8 *handshake, 
			        Uint8 *verify_data,
					Uint8 *encrypt_master_secret,
					Uint32 *request_id);


/*+****************************************************************************
 *
 * Csp1OtherVerify3DesFinish
 *
 * When not (RSA <= 1024), do a full handshake - up to the point of the
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
 *
 * Return Value
 *	completion code = 0 (for success), ERR_BAD_SIZE_OR_DLEN_VAL, 
 *	ERR_BAD_IOCTL, ERR_INSTRUCTION_TIMEOUT, ERR_ILLEGAL_CONTEXT_HANDLE, or 
 *	ERR_ILLEGAL_INPUT_LENGTH
 *
 *-***************************************************************************/
Uint32 
Csp1OtherVerify3DesFinish(n1_request_type request_type,
						  Uint64 context_handle, 
					      HashType hash_type, 
					      SslVersion ssl_version, 
					      DesType des_type, 
					      MasterSecretReturn master_secret_ret,
					      Uint16 pre_master_length, 
					      Uint8 *client_random, 
					      Uint8 *server_random, 
					      Uint16 handshake_length, 
					      Uint8 *handshake, 
					      Uint8 *verify_data,
					      Uint8 *encrypt_master_secret,
						  Uint32 *request_id);


/*+****************************************************************************
 *
 * Csp1OtherFullAes
 *
 * When not (RSA <= 1024), do a full handshake. The pre-master secret is read
 * from the context and the rest of the handshake is completed. This is used
 * by both the server and the client. This entry point handles all the
 * AES cases.
 *
 * The handshake message data for this request should include all handshake 
 * message data after (and including) the client hello message up until (but 
 * not including) the first finished message. 
 *
 * Input
 *	context_handle = 64-bit pointer to context (context_handle%8=0)
 *	hash_type = MD5_TYPE or SHA1_TYPE
 *	ssl_version = VER3_0 or VER_TLS
 *	aes_type = AES_128 or AES_256
 *	master_secret_ret = NOT_RETURNED or RETURN_ENCRYPTED
 *	clnt_fin_msg_out = RETURN_ENCRYPTED or RETURN_UNENCRYPTED
 *	srvr_fin_msg_out = RETURN_ENCRYPTED or RETURN_UNENCRYPTED
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
 *
 * Return Value
 *	completion code = 0 (for success), ERR_BAD_SIZE_OR_DLEN_VAL, 
 *	ERR_BAD_IOCTL, ERR_INSTRUCTION_TIMEOUT, ERR_ILLEGAL_CONTEXT_HANDLE, or  
 *	ERR_ILLEGAL_INPUT_LENGTH 
 *
 *-***************************************************************************/
Uint32 
Csp1OtherFullAes(n1_request_type request_type,
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
			     Uint8 *client_random, 
			     Uint8 *server_random, 
			     Uint16 handshake_length, 
			     Uint8 *handshake, 
			     Uint8 *client_finished_message,
			     Uint8 *server_finished_message, 
				 Uint8 *encrypt_master_secret,
				 Uint32 *request_id);


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
 *	context_handle = 64-bit pointer to context (context_handle%8=0)
 *	hash_type = MD5_TYPE or SHA1_TYPE
 *	ssl_version = VER3_0 or VER_TLS
 *	aes_type = AES_128 or AES_256
 *	master_secret_ret = NOT_RETURNED or RETURN_ENCRYPTED
 *	clnt_fin_msg_out = RETURN_ENCRYPTED or RETURN_UNENCRYPTED
 *	srvr_fin_msg_out = RETURN_ENCRYPTED or RETURN_UNENCRYPTED
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
 *
 * Return Value
 *	completion code = 0 (for success), ERR_BAD_SIZE_OR_DLEN_VAL, 
 *	ERR_BAD_IOCTL, ERR_INSTRUCTION_TIMEOUT, ERR_ILLEGAL_CONTEXT_HANDLE, or  
 *	ERR_ILLEGAL_INPUT_LENGTH 
 *
 *-***************************************************************************/
Uint32 
Csp1OtherFullAesFinish(n1_request_type request_type,
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
				       Uint8 *client_random, 
				       Uint8 *server_random, 
				       Uint16 handshake_length, 
				       Uint8 *handshake, 
				       Uint8 *client_finished_message,
				       Uint8 *server_finished_message, 
					   Uint8 *encrypt_master_secret,
					   Uint32 *request_id);


/*+****************************************************************************
 *
 * Csp1OtherVerifyAes
 *
 * When not (RSA <= 1024), do a full handshake - up to the point of the
 * verify operation. The pre-master secret is read from the context.
 * This is used by both the server and the client. This entry point handles all 
 * the AES cases.
 *
 * The handshake message data for this request should include all handshake 
 * message data after (and including) the client hello message up until (but 
 * not including) the client verify message. 
 *
 * Input
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
 *
 * Return Value
 *	completion code = 0 (for success), ERR_BAD_SIZE_OR_DLEN_VAL, 
 *	ERR_BAD_IOCTL, ERR_INSTRUCTION_TIMEOUT, ERR_ILLEGAL_CONTEXT_HANDLE, or 
 *	ERR_ILLEGAL_INPUT_LENGTH 
 *
 *-***************************************************************************/
Uint32 
Csp1OtherVerifyAes(n1_request_type request_type,
				   Uint64 context_handle, 
			       HashType hash_type, 
			       SslVersion ssl_version, 
			       AesType aes_type, 
			       MasterSecretReturn master_secret_ret,
			       Uint16 pre_master_length, 
			       Uint8 *client_random, 
			       Uint8 *server_random, 
			       Uint16 handshake_length, 
			       Uint8 *handshake, 
			       Uint8 *verify_data,
				   Uint8 *encrypt_master_secret,
				   Uint32 *request_id);


/*+****************************************************************************
 *
 * Csp1OtherVerifyAesFinish
 *
 * When not (RSA <= 1024), do a full handshake - up to the point of the
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
 *
 * Return Value
 *	completion code = 0 (for success), ERR_BAD_SIZE_OR_DLEN_VAL, 
 *	ERR_BAD_IOCTL, ERR_INSTRUCTION_TIMEOUT, ERR_ILLEGAL_CONTEXT_HANDLE, or 
 *	ERR_ILLEGAL_INPUT_LENGTH
 *
 *-***************************************************************************/
Uint32 
Csp1OtherVerifyAesFinish(n1_request_type request_type,
						 Uint64 context_handle, 
					     HashType hash_type, 
				    	 SslVersion ssl_version, 
					     AesType aes_type, 
					     MasterSecretReturn master_secret_ret,
					     Uint16 pre_master_length, 
					     Uint8 *client_random, 
					     Uint8 *server_random, 
					     Uint16 handshake_length, 
				    	 Uint8 *handshake, 
				    	 Uint8 *verify_data,
					     Uint8 *encrypt_master_secret,
						 Uint32 *request_id);


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
 *	context_handle = 64-bit pointer to context (context_handle%8=0)
 *	hash_type = MD5_TYPE or SHA1_TYPE
 *	ssl_version = VER3_0 or VER_TLS
 *	handshake_length = size in bytes of the handshake message data
 *	handshake = pointer to the handshake message data
 *
 * Output
 *	client_finished_message = pointer to encrypted part of client finished message 
 *	server_finished_message = pointer to encrypted part of server finished message 
 *
 * Return Value
 *	completion code = 0 (for success), ERR_BAD_SIZE_OR_DLEN_VAL, 
 *	ERR_BAD_IOCTL, ERR_INSTRUCTION_TIMEOUT, or ERR_ILLEGAL_CONTEXT_HANDLE
 *
 *-***************************************************************************/
Uint32 
Csp1FinishedRc4Finish(n1_request_type request_type,
					  Uint64 context_handle, 
				      HashType hash_type, 
				      SslVersion ssl_version, 
				      Uint16 handshake_length, 
				      Uint8 *handshake, 
				      Uint8 *client_finished_message, 
				      Uint8 *server_finished_message,
					  Uint32 *request_id); 


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
 *	context_handle = 64-bit pointer to context (context_handle%8=0)
 *	hash_type = MD5_TYPE or SHA1_TYPE
 *	ssl_version = VER3_0 or VER_TLS
 *	clnt_fin_msg_out = RETURN_ENCRYPTED or RETURN_UNENCRYPTED
 *	srvr_fin_msg_out = RETURN_ENCRYPTED or RETURN_UNENCRYPTED
 *	client_pad_length = number of 64-bit words to pad above min
 *	server_pad_length = number of 64-bit words to pad above min
 *	handshake_length = size in bytes of the handshake message data
 *	handshake = pointer to the handshake message data
 *
 * Output
 *	client_finished_message = pointer to encrypted part of client finished message 
 *	server_finished_message = pointer to encrypted part of server finished message 
 *
 * Return Value
 *	completion code = 0 (for success), ERR_BAD_SIZE_OR_DLEN_VAL, 
 *	ERR_BAD_IOCTL, ERR_INSTRUCTION_TIMEOUT, or ERR_ILLEGAL_CONTEXT_HANDLE
 *
 *-***************************************************************************/
Uint32 
Csp1Finished3DesFinish(n1_request_type request_type,
					   Uint64 context_handle, 
				       HashType hash_type, 
				       SslVersion ssl_version, 
					   ClientFinishMessageOutput clnt_fin_msg_out,
					   ServerFinishMessageOutput srvr_fin_msg_out,
				       Uint16 client_pad_length,
				       Uint16 server_pad_length,
				       Uint16 handshake_length, 
				       Uint8 *handshake, 
				       Uint8 *client_finished_message, 
				       Uint8 *server_finished_message,
					   Uint32 *request_id); 


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
 *	context_handle = 64-bit pointer to context (context_handle%8=0)
 *	hash_type = MD5_TYPE or SHA1_TYPE
 *	ssl_version = VER3_0 or VER_TLS
 *	aes_type = AES_128 or AES_256
 *	clnt_fin_msg_out = RETURN_ENCRYPTED or RETURN_UNENCRYPTED
 *	srvr_fin_msg_out = RETURN_ENCRYPTED or RETURN_UNENCRYPTED
 *	client_pad_length = number of 128-bit words to pad above min
 *	server_pad_length = number of 128-bit words to pad above min
 *	handshake_length = size in bytes of the handshake message data
 *	handshake = pointer to the handshake message data
 *
 * Output
 *	client_finished_message = pointer to encrypted part of client finished message 
 *	server_finished_message = pointer to encrypted part of server finished message 
 *
 * Return Value
 *	completion code = 0 (for success), ERR_BAD_SIZE_OR_DLEN_VAL, 
 *	ERR_BAD_IOCTL, ERR_INSTRUCTION_TIMEOUT, or ERR_ILLEGAL_CONTEXT_HANDLE
 *
 *-***************************************************************************/
Uint32 
Csp1FinishedAesFinish(n1_request_type request_type,
					  Uint64 context_handle, 
				      HashType hash_type, 
				      SslVersion ssl_version, 
				      AesType aes_type, 
					  ClientFinishMessageOutput clnt_fin_msg_out,
					  ServerFinishMessageOutput srvr_fin_msg_out,
				      Uint16 client_pad_length,
				      Uint16 server_pad_length,
				      Uint16 handshake_length, 
				      Uint8 *handshake, 
				      Uint8 *client_finished_message, 
				      Uint8 *server_finished_message,
					  Uint32 *request_id);


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
 *
 * Return Value
 *	completion code = 0 (for success), ERR_BAD_SIZE_OR_DLEN_VAL, 
 *	ERR_BAD_IOCTL, ERR_INSTRUCTION_TIMEOUT, or ERR_ILLEGAL_CONTEXT_HANDLE
 *
 *-***************************************************************************/
Uint32 
Csp1ResumeRc4(n1_request_type request_type,
			  Uint64 context_handle, 
		      HashType hash_type, 
		      SslVersion ssl_version, 
		      Rc4Type rc4_type,
		      MasterSecretInput master_secret_inp,
		      Uint8 *client_random, 
		      Uint8 *server_random,
		      Uint8 *encrypt_master_secret,
		      Uint16 handshake_length, 
		      Uint8 *handshake, 
		      Uint8 *client_finished_message, 
		      Uint8 *server_finished_message,
			  Uint32 *request_id);


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
 *
 * Return Value
 *	completion code = 0 (for success), ERR_BAD_SIZE_OR_DLEN_VAL, 
 *	ERR_BAD_IOCTL, ERR_INSTRUCTION_TIMEOUT, or ERR_ILLEGAL_CONTEXT_HANDLE
 *
 *-***************************************************************************/
Uint32 
Csp1ResumeRc4Finish(n1_request_type request_type,
					Uint64 context_handle, 
			    	HashType hash_type, 
			    	SslVersion ssl_version, 
			    	Rc4Type rc4_type, 
			    	MasterSecretInput master_secret_inp,
			    	Uint8 *client_random, 
			    	Uint8 *server_random, 
			    	Uint8 *encrypt_master_secret,
			    	Uint16 handshake_length, 
			    	Uint8 *handshake, 
			    	Uint8 *client_finished_message, 
			    	Uint8 *server_finished_message,
					Uint32 *request_id); 


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
 *	context_handle = 64-bit pointer to context (context_handle%8=0)
 *	hash_type = MD5_TYPE or SHA1_TYPE
 *	ssl_version = VER3_0 or VER_TLS
 *	des_type = DES, DES_EXPORT_40 or DES3_192
 *	master_secret_inp = READ_FROM_CONTEXT or INPUT_ENCRYPTED
 *	clnt_fin_msg_out = RETURN_ENCRYPTED or RETURN_UNENCRYPTED
 *	srvr_fin_msg_out = RETURN_ENCRYPTED or RETURN_UNENCRYPTED
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
 *
 * Return Value
 *	completion code = 0 (for success), ERR_BAD_SIZE_OR_DLEN_VAL, 
 *	ERR_BAD_IOCTL, ERR_INSTRUCTION_TIMEOUT, or ERR_ILLEGAL_CONTEXT_HANDLE
 *
 *-***************************************************************************/
Uint32 
Csp1Resume3Des(n1_request_type request_type,
			   Uint64 context_handle, 
		       HashType hash_type, 
		       SslVersion ssl_version, 
		       DesType des_type, 
		       MasterSecretInput master_secret_inp,
			   ClientFinishMessageOutput clnt_fin_msg_out,
			   ServerFinishMessageOutput srvr_fin_msg_out,
		       Uint16 client_pad_length,
		       Uint16 server_pad_length,
		       Uint8 *client_random, 
		       Uint8 *server_random, 
		       Uint8 *encrypt_master_secret,
		       Uint16 handshake_length, 
	   	       Uint8 *handshake, 
		       Uint8 *client_finished_message, 
		       Uint8 *server_finished_message,
			   Uint32 *request_id);


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
 *	context_handle = 64-bit pointer to context (context_handle%8=0)
 *	hash_type = MD5_TYPE or SHA1_TYPE
 *	ssl_version = VER3_0 or VER_TLS
 *	des_type = DES, DES_EXPORT_40 or DES3_192
 *	master_secret_inp = READ_FROM_CONTEXT or INPUT_ENCRYPTED
 *	clnt_fin_msg_out = RETURN_ENCRYPTED or RETURN_UNENCRYPTED
 *	srvr_fin_msg_out = RETURN_ENCRYPTED or RETURN_UNENCRYPTED
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
 *
 * Return Value
 *	completion code = 0 (for success), ERR_BAD_SIZE_OR_DLEN_VAL, 
 *	ERR_BAD_IOCTL, ERR_INSTRUCTION_TIMEOUT, or ERR_ILLEGAL_CONTEXT_HANDLE
 *
 *-***************************************************************************/
Uint32 
Csp1Resume3DesFinish(n1_request_type request_type,
					 Uint64 context_handle, 
			    	 HashType hash_type, 
			    	 SslVersion ssl_version, 
			    	 DesType des_type, 
			    	 MasterSecretInput master_secret_inp,
					 ClientFinishMessageOutput clnt_fin_msg_out,
					 ServerFinishMessageOutput srvr_fin_msg_out,
			    	 Uint16 client_pad_length,
			    	 Uint16 server_pad_length,
			    	 Uint8 *client_random, 
			    	 Uint8 *server_random, 
			    	 Uint8 *encrypt_master_secret,
			    	 Uint16 handshake_length, 
			    	 Uint8 *handshake, 
			    	 Uint8 *client_finished_message, 
			    	 Uint8 *server_finished_message,
					 Uint32 *request_id);


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
 *	context_handle = 64-bit pointer to context (context_handle%8=0)
 *	hash_type = MD5_TYPE or SHA1_TYPE
 *	ssl_version = VER3_0 or VER_TLS
 *	aes_type = AES_128 or AES_256
 *	master_secret_inp = READ_FROM_CONTEXT or INPUT_ENCRYPTED
 *	clnt_fin_msg_out = RETURN_ENCRYPTED or RETURN_UNENCRYPTED
 *	srvr_fin_msg_out = RETURN_ENCRYPTED or RETURN_UNENCRYPTED
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
 *
 * Return Value
 *	completion code = 0 (for success), ERR_BAD_SIZE_OR_DLEN_VAL, 
 *	ERR_BAD_IOCTL, ERR_INSTRUCTION_TIMEOUT, or ERR_ILLEGAL_CONTEXT_HANDLE 
 *
 *-***************************************************************************/
Uint32 
Csp1ResumeAes(n1_request_type request_type,
			  Uint64 context_handle, 
	    	  HashType hash_type, 
	    	  SslVersion ssl_version, 
	    	  AesType aes_type, 
		      MasterSecretInput master_secret_inp,
			  ClientFinishMessageOutput clnt_fin_msg_out,
			  ServerFinishMessageOutput srvr_fin_msg_out,
		      Uint16 client_pad_length,
		      Uint16 server_pad_length,
		      Uint8 *client_random, 
	    	  Uint8 *server_random, 
		      Uint8 *encrypt_master_secret,
		      Uint16 handshake_length, 
		      Uint8 *handshake, 
		      Uint8 *client_finished_message, 
		      Uint8 *server_finished_message,
			  Uint32 *request_id);


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
 *	context_handle = 64-bit pointer to context (context_handle%8=0)
 *	hash_type = MD5_TYPE or SHA1_TYPE
 *	ssl_version = VER3_0 or VER_TLS
 *	aes_type = AES_128 or AES_256
 *	master_secret_inp = READ_FROM_CONTEXT or INPUT_ENCRYPTED
 *	clnt_fin_msg_out = RETURN_ENCRYPTED or RETURN_UNENCRYPTED
 *	srvr_fin_msg_out = RETURN_ENCRYPTED or RETURN_UNENCRYPTED
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
 *
 * Return Value
 *	completion code = 0 (for success), ERR_BAD_SIZE_OR_DLEN_VAL, 
 *	ERR_BAD_IOCTL, ERR_INSTRUCTION_TIMEOUT, or ERR_ILLEGAL_CONTEXT_HANDLE
 *
 *-***************************************************************************/
Uint32 
Csp1ResumeAesFinish(n1_request_type request_type,
					Uint64 context_handle, 
			    	HashType hash_type, 
			    	SslVersion ssl_version, 
			    	AesType aes_type, 
			    	MasterSecretInput master_secret_inp,
					ClientFinishMessageOutput clnt_fin_msg_out,
					ServerFinishMessageOutput srvr_fin_msg_out,
			    	Uint16 client_pad_length,
			    	Uint16 server_pad_length,
			    	Uint8 *client_random, 
			    	Uint8 *server_random, 
			    	Uint8 *encrypt_master_secret,
			    	Uint16 handshake_length, 
			    	Uint8 *handshake, 
			    	Uint8 *client_finished_message, 
			    	Uint8 *server_finished_message,
					Uint32 *request_id);


/*+****************************************************************************
 *
 * Csp1EncryptRecordRc4
 *
 * Input
 *	context_handle = 64-bit pointer to context (context_handle%8=0)
 *	hash_type = MD5_TYPE or SHA1_TYPE 
 *	ssl_version = VER3_0 or VER_TLS
 *	message_type = CHANGE_CIPHER_SPEC, ALERT, HANDSHAKE, or APP_DATA
 *	message_length = size of message in bytes (0<=length<=2^14+1024)
 *	message = pointer to length-byte message 
 *
 * Output
 *	record = pointer to (length + hash_size) bytes of encrypted record 
 *
 * Return Value
 *	completion_code = 0 (for success), ERR_BAD_SIZE_OR_DLEN_VAL, 
 *	ERR_BAD_IOCTL, ERR_INSTRUCTION_TIMEOUT, ERR_ILLEGAL_CONTEXT_HANDLE, or  
 *	ERR_ILLEGAL_INPUT_LENGTH 
 *
 *-***************************************************************************/
Uint32 
Csp1EncryptRecordRc4(n1_request_type request_type,
					 Uint64 context_handle, 
			HashType hash_type,  
			SslVersion ssl_version, 
			SslPartyType ssl_party,
			MessageType message_type,
			Uint16 message_length, 
			Uint8 *message, 
			Uint8 *record,
			Uint32 *request_id);


/*+****************************************************************************
 *
 * Csp1DecryptRecordRc4
 *
 * Input
 *	context_handle = 64-bit pointer to context (context_handle%8=0)
 *	hash_type = MD5_TYPE or SHA1_TYPE 
 *	ssl_version = VER3_0 or VER3_1
 *	message_type = CHANGE_CIPHER_SPEC, ALERT, HANDSHAKE, or APP_DATA
 *	record_length = size of record in bytes (0<=length<=2^14+1024)
 *	record = pointer to length-byte encrypted part of record 
 *
 * Output
 *	message = pointer to (record length - hash size) bytes 
 *
 * Return Value
 *	completion_code = 0 (for success), ERR_BAD_SIZE_OR_DLEN_VAL, 
 *	ERR_BAD_RECORD, ERR_BAD_IOCTL, ERR_INSTRUCTION_TIMEOUT, 
 *	ERR_ILLEGAL_CONTEXT_HANDLE, or ERR_ILLEGAL_INPUT_LENGTH
 *
 *-***************************************************************************/
Uint32 
Csp1DecryptRecordRc4(n1_request_type request_type,
					 Uint64 context_handle, 
					 HashType hash_type, 
					 SslVersion ssl_version, 
		 			 SslPartyType ssl_party,
					 MessageType message_type, 
					 Uint16 record_length, 
					 Uint8 *record, 
					 Uint8 *message,
					 Uint32 *request_id);


/*+****************************************************************************
 *
 * Csp1EncryptRecord3Des
 *
 * Input
 *	context_handle = 64-bit pointer to context (context_handle%8=0)
 *	hash_type = MD5_TYPE or SHA1_TYPE 
 *	ssl_version = VER3_0 or VER3_1
 *	pad_length = size of extra padding in 8-byte blocks
 *	message_type = CHANGE_CIPHER_SPEC, ALERT, HANDSHAKE, or APP_DATA
 *	message_length = size of input in bytes (0<=length<=2^14+1024)
 *	message = pointer to length-byte input message
 *
 * Output
 *	record_length = pointer to length of the encrypted part of the record in bytes
 *	record = pointer to *record_length-byte output 
 *
 * Return Value
 *	completion_code = 0 (for success), ERR_BAD_SIZE_OR_DLEN_VAL, 
 *	ERR_BAD_IOCTL, ERR_INSTRUCTION_TIMEOUT, ERR_ILLEGAL_CONTEXT_HANDLE, or  
 *	ERR_ILLEGAL_INPUT_LENGTH
 *
 *-***************************************************************************/
Uint32 
Csp1EncryptRecord3Des(n1_request_type request_type,
					  Uint64 context_handle, 
					  HashType hash_type, 
					  SslVersion ssl_version, 
					  SslPartyType ssl_party,
					  MessageType message_type, 
					  Uint16 pad_length,
					  Uint16 message_length, 
					  Uint8 *message, 
					  Uint16 *record_length, 
					  Uint8 *record,
					  Uint32 *request_id);


/*+****************************************************************************
 *
 * Csp1DecryptRecord3Des
 *
 * Input
 *	context_handle = 64-bit pointer to context (context_handle%8=0)
 *	hash_type = MD5_TYPE or SHA1_TYPE 
 *	ssl_version = VER3_0 or VER3_1
 *	message_type = CHANGE_CIPHER_SPEC, ALERT, HANDSHAKE, or APP_DATA
 *	record_length = size of the encrypted part of the input record in bytes 
 *		(length%8=0, 0<=length<=2^14+1024)
 *	record = pointer to length-byte encrypted part of the input record
 *
 * Output
 *	message_length = pointer to length in bytes of the decrypted message
 *	message = pointer to *message_length-byte output 
 *
 * Return Value
 *	completion_code = 0 (for success), ERR_BAD_SIZE_OR_DLEN_VAL, 
 *	ERR_BAD_RECORD, ERR_BAD_IOCTL, ERR_INSTRUCTION_TIMEOUT, 
 *	ERR_ILLEGAL_CONTEXT_HANDLE, or ERR_ILLEGAL_INPUT_LENGTH
 *
 *-***************************************************************************/
Uint32 
Csp1DecryptRecord3Des(n1_request_type request_type,
					  Uint64 context_handle, 
					  HashType hash_type, 
					  SslVersion ssl_version, 
					  SslPartyType ssl_party,
					  MessageType message_type,
					  Uint16 record_length, 
					  Uint8 *record, 
					  Uint16 *message_length, 
					  Uint8 *message,
					  Uint32 *request_id);


/*+****************************************************************************
 *
 * Csp1DecryptRecord3DesRecover
 *
 * Input
 *	context_handle = 64-bit pointer to context (context_handle%8=0)
 *	hash_type = MD5_TYPE or SHA1_TYPE 
 *	ssl_version = VER3_0 or VER3_1
 *	message_type = CHANGE_CIPHER_SPEC, ALERT, HANDSHAKE, or APP_DATA
 *	record_length = size of the encrypted part of the input record in bytes 
 *		(length%8=0, 0<=length<=2^14+1024)
 *	record = pointer to length-byte encrypted part of the input record
 *
 * Output
 *	message_length = pointer to length in bytes of the decrypted message
 *	message = pointer to *message_length-byte output, 
 *
 * Return Value
 *	completion_code = 0 (for success), ERR_BAD_SIZE_OR_DLEN_VAL, 
 *	ERR_BAD_RECORD, ERR_BAD_IOCTL, ERR_INSTRUCTION_TIMEOUT, 
 *	ERR_ILLEGAL_CONTEXT_HANDLE, or ERR_ILLEGAL_INPUT_LENGTH 
 *
 *-***************************************************************************/
Uint32 
Csp1DecryptRecord3DesRecover(n1_request_type request_type,
							 Uint64 context_handle, 
							 HashType hash_type, 
							 SslVersion ssl_version,
				 			 SslPartyType ssl_party,
							 MessageType message_type,
							 Uint16 record_length, 
							 Uint8 *record, 
							 Uint16 *message_length, 
							 Uint8 *message,
							 Uint32 *request_id);


/*+****************************************************************************
 *
 * Csp1EncryptRecordAes
 *
 * Input
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
 *
 * Return Value
 *	completion_code = 0 (for success), ERR_BAD_SIZE_OR_DLEN_VAL, 
 *	ERR_BAD_IOCTL, ERR_INSTRUCTION_TIMEOUT, ERR_ILLEGAL_CONTEXT_HANDLE, or  
 *	ERR_ILLEGAL_INPUT_LENGTH
 *
 *-***************************************************************************/
Uint32 
Csp1EncryptRecordAes(n1_request_type request_type,
					 Uint64 context_handle, 
					 HashType hash_type, 
					 SslVersion ssl_version, 
		 			 SslPartyType ssl_party,
					 AesType aes_type, 
					 MessageType message_type,
					 Uint16 pad_length,
					 Uint16 message_length, 
					 Uint8 *message, 
					 Uint16 *record_length, 
					 Uint8 *record,
					 Uint32 *request_id);


/*+****************************************************************************
 *
 * Csp1DecryptRecordAes
 *
 * Input
 *	context_handle = 64-bit pointer to context (context_handle%8=0)
 *	hash_type = MD5_TYPE or SHA1_TYPE 
 *	ssl_version = VER3_0 or VER3_1
 *	aes_type = AES_128 or AES_256
 *	message_type = CHANGE_CIPHER_SPEC, ALERT, HANDSHAKE, or APP_DATA
 *	record_length = size of input in bytes (length%16=0, 0<=length<=2^14+1024)
 *	record = pointer to length-byte input
 *
 * Output
 *	message_length = pointer to length in bytes of the decrypted message
 *	message = pointer to *message_length-byte output
 *
 * Return Value
 *	completion_code = 0 (for success), ERR_BAD_SIZE_OR_DLEN_VAL, 
 *	ERR_BAD_RECORD, ERR_BAD_IOCTL, ERR_INSTRUCTION_TIMEOUT, 
 *	ERR_ILLEGAL_CONTEXT_HANDLE, or ERR_ILLEGAL_INPUT_LENGTH  
 *
 *-***************************************************************************/
Uint32 
Csp1DecryptRecordAes(n1_request_type request_type,
					 Uint64 context_handle, 
					 HashType hash_type, 
					 SslVersion ssl_version, 
					 SslPartyType ssl_party,
					 AesType aes_type, 
					 MessageType message_type,
					 Uint16 record_length, 
					 Uint8 *record, 
					 Uint16 *message_length, 
					 Uint8 *message,
					 Uint32 *request_id);


/*+****************************************************************************
 *
 * Csp1DecryptRecordAesRecover
 *
 * Input
 *	context_handle = 64-bit pointer to context (context_handle%8=0)
 *	hash_type = MD5_TYPE or SHA1_TYPE (MD5 hash_size = 16, SHA1 hash_size = 20)
 *	ssl_version = VER3_0 or VER3_1
 *	aes_type = AES_128 or AES_256
 *	message_type = CHANGE_CIPHER_SPEC, ALERT, HANDSHAKE, or APP_DATA
 *	record_length = size of input in bytes (length%16=0, 0<=length<=2^14+1024)
 *	record = pointer to length-byte input
 *
 * Output
 *	message_length = pointer to length in bytes of the decrypted message
 *	message = pointer to *message_length-byte output
 *
 * Return Value
 *	completion_code = 0 (for success), ERR_BAD_SIZE_OR_DLEN_VAL, 
 *	ERR_BAD_RECORD, ERR_BAD_IOCTL, ERR_INSTRUCTION_TIMEOUT, 
 *	ERR_ILLEGAL_CONTEXT_HANDLE, or ERR_ILLEGAL_INPUT_LENGTH 
 *
 *-***************************************************************************/
Uint32 
Csp1DecryptRecordAesRecover(n1_request_type request_type,
							Uint64 context_handle, 
						    HashType hash_type, 
						    SslVersion ssl_version, 
						    AesType aes_type, 
							SslPartyType ssl_party,
					        MessageType message_type,
					        Uint16 record_length, 
						    Uint8 *record, 
						    Uint16 *message_length, 
						    Uint8 *message,
							Uint32 *request_id);






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
 *
 * Return Value
 *	completion code = 0 (for success), ERR_MEMORY_ALLOC_FAILURE,
 *	ERR_BAD_SIZE_OR_DLEN_VAL, ERR_BAD_PKCS_PAD_OR_LENGTH, ERR_BAD_PKCS_TYPE, 
 *	ERR_BAD_IOCTL, ERR_INSTRUCTION_TIMEOUT,ERR_OPERATION_NOT_SUPPORTED,
 *	ERR_BAD_RECORD
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
Csp1RsaSsl20ServerFullRc4(n1_request_type request_type,
						  Uint64 context_handle,
						  Uint64 *key_handle,
						  Rc4Type rc4_type,
						  Uint8 *client_master_secret,
						  Uint16 clear_master_secret_length,
						  Uint16 encrypted_master_secret_length,
						  Uint16 modlength,
						  Uint8 *challenge,
						  Uint16 challenge_length,	
						  Uint8 *connection_id,
						  Uint8 *session_id,
						  Uint8 *client_finished,	
						  Uint8 *server_finished,	
						  Uint8 *server_verify,		
						  Uint8 *master_secret,
						  Uint16 *master_secret_length,
						  Uint32 *request_id);


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
 *
 * Return Value
 *	completion code = 0 (for success), ERR_MEMORY_ALLOC_FAILURE,
 *	ERR_BAD_SIZE_OR_DLEN_VAL, ERR_BAD_PKCS_PAD_OR_LENGTH, ERR_BAD_PKCS_TYPE, 
 *	ERR_BAD_IOCTL, ERR_INSTRUCTION_TIMEOUT,ERR_OPERATION_NOT_SUPPORTED,
 *	ERR_BAD_RECORD
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
Csp1RsaSsl20ServerClientAuthRc4(
					n1_request_type request_type,
				 	Uint64 context_handle,
				  	Uint64 *key_handle,
				  	Rc4Type rc4_type,
				  	Uint8 *client_master_secret,
				  	Uint16 clear_master_secret_length,
				  	Uint16 encrypted_master_secret_length,
				  	Uint16 modlength,
				  	Uint8 *challenge,
				  	Uint16 challenge_length,	
				  	Uint8 *connection_id,		
				  	Uint8 *session_id,
				  	Uint8 *client_finished,	
					Uint8 auth_type,
					Uint8 *cert_challenge,
					Uint8 *cert_request,
				  	Uint8 *server_verify,		
				  	Uint8 *master_secret,
				  	Uint16 *master_secret_length,
					Uint32 *request_id);


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
 *
 * Return Value
 *	completion code = 0 (for success), ERR_MEMORY_ALLOC_FAILURE,
 *	ERR_BAD_SIZE_OR_DLEN_VAL, ERR_BAD_IOCTL, ERR_INSTRUCTION_TIMEOUT,
 *	ERR_OPERATION_NOT_SUPPORTED, ERR_BAD_RECORD
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
			Uint64 *key_handle,
			Rc4Type rc4_type,
			Uint8 *master_secret,
			Uint16 master_secret_length,
			Uint8 *challenge,
			Uint16 challenge_length,	
			Uint8 *connection_id,		
			Uint8 *session_id,
			Uint8 *client_finished,	
			Uint8 *server_finished,	
			Uint8 *server_verify,
			Uint32 *request_id);



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
 *
 * Return Value
 *	completion code = 0 (for success), ERR_MEMORY_ALLOC_FAILURE,
 *	ERR_BAD_SIZE_OR_DLEN_VAL, ERR_BAD_IOCTL, ERR_INSTRUCTION_TIMEOUT,
 *	ERR_OPERATION_NOT_SUPPORTED, ERR_BAD_RECORD
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
Csp1Ssl20ResumeClientAuthRc4 (n1_request_type request_type,
					Uint64 context_handle,
					Uint64 *key_handle,
					Rc4Type rc4_type,
					Uint8 *master_secret,
					Uint16 master_secret_length,
					Uint8 *challenge,
					Uint16 challenge_length,	
					Uint8 *connection_id,		
					Uint8 *session_id,
					Uint8 *client_finished,	
					Uint8 auth_type,
					Uint8 *cert_challenge,
					Uint8 *cert_request,
					Uint8 *server_verify,
					Uint32 *request_id);



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
 *
 * Return Value
 *	completion code = 0 (for success), ERR_MEMORY_ALLOC_FAILURE,
 *	ERR_BAD_SIZE_OR_DLEN_VAL, ERR_BAD_PKCS_PAD_OR_LENGTH, ERR_BAD_PKCS_TYPE, 
 *	ERR_BAD_IOCTL, ERR_INSTRUCTION_TIMEOUT,ERR_OPERATION_NOT_SUPPORTED,
 *	ERR_BAD_RECORD
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
Csp1RsaSsl20ServerFull3Des(n1_request_type request_type,
						   Uint64 context_handle,
						  Uint64 *key_handle,
						  DesType des_type,
						  Uint8 *client_master_secret,
						  Uint16 clear_master_secret_length,
						  Uint16 encrypted_master_secret_length,
						  Uint16 modlength,
						  Uint8 *challenge,
						  Uint16 challenge_length,	
						  Uint8 *connection_id,		
						  Uint8 *session_id,
						  Uint8 *iv,
						  Uint8 *client_finished,	
						  Uint8 *server_finished,	
						  Uint8 *server_verify,		
						  Uint8 *master_secret,
						  Uint16 *master_secret_length,
						  Uint32 *request_id);






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
 *
 * Return Value
 *	completion code = 0 (for success), ERR_MEMORY_ALLOC_FAILURE,
 *	ERR_BAD_SIZE_OR_DLEN_VAL, ERR_BAD_PKCS_PAD_OR_LENGTH, ERR_BAD_PKCS_TYPE, 
 *	ERR_BAD_IOCTL, ERR_INSTRUCTION_TIMEOUT,ERR_OPERATION_NOT_SUPPORTED,
 *	ERR_BAD_RECORD
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
Csp1RsaSsl20ServerClientAuth3Des(
						n1_request_type request_type,
						Uint64 context_handle,
						Uint64 *key_handle,
						DesType des_type,
						Uint8 *client_master_secret,
						Uint16 clear_master_secret_length,
						Uint16 encrypted_master_secret_length,
						Uint16 modlength,
						Uint8 *challenge,
						Uint16 challenge_length,	
						Uint8 *connection_id,		
						Uint8 *session_id,
						Uint8 *iv,
						Uint8 *client_finished,	
						Uint8 auth_type,
						Uint8 *cert_challenge,
						Uint8 *cert_request,	
						Uint8 *server_verify,		
						Uint8 *master_secret,
						Uint16 *master_secret_length,
						Uint32 *request_id);



/*+****************************************************************************
 *
 * Csp1Ssl20Resume3Des
 *
 * Resumes a previouly negotiated handshake. 
 *
 *
 * Supported ciphers
 *	SSL_CK_DES_64_CBC_WITH_MD5
	SSL_CK_DES_192_EDE3_CBC_WITH_MD5
 *
 *
 * Input
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
 *
 * Return Value
 *	completion code = 0 (for success), ERR_MEMORY_ALLOC_FAILURE,
 *	ERR_BAD_SIZE_OR_DLEN_VAL, ERR_BAD_IOCTL, ERR_INSTRUCTION_TIMEOUT,
 *	ERR_OPERATION_NOT_SUPPORTED,ERR_BAD_RECORD
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
Csp1Ssl20Resume3Des(
			n1_request_type request_type,
			Uint64 context_handle,
		  Uint64 *key_handle,
		  DesType des_type,
		  Uint8 *master_secret,
		  Uint16 master_secret_length,
		  Uint8 *challenge,
		  Uint16 challenge_length,	
		  Uint8 *connection_id,		
		  Uint8 *session_id,
		  Uint8 *iv,
		  Uint8 *client_finished,	
		  Uint8 *server_finished,	
		  Uint8 *server_verify,
		  Uint32 *request_id);



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

 *	cert_request = pointer to encrypted part of cert request message 
 *	server_verify =  pointer to encrypted part of server verify message 
 *
 * Return Value
 *	completion code = 0 (for success), ERR_MEMORY_ALLOC_FAILURE,
 *	ERR_BAD_SIZE_OR_DLEN_VAL, ERR_BAD_IOCTL, ERR_INSTRUCTION_TIMEOUT,
 *	ERR_OPERATION_NOT_SUPPORTED,ERR_BAD_RECORD
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
Csp1Ssl20ResumeClientAuth3Des(
			n1_request_type request_type,
			Uint64 context_handle,
		  Uint64 *key_handle,
		  DesType des_type,
		  Uint8 *master_secret,
		  Uint16 master_secret_length,
		  Uint8 *challenge,
		  Uint16 challenge_length,	
		  Uint8 *connection_id,		
		  Uint8 *session_id,
		  Uint8 *iv,
		  Uint8 *client_finished,
		  Uint8 auth_type,
		  Uint8 *cert_challenge,
		  Uint8 *cert_request,	
		  Uint8 *server_verify,
		  Uint32 *request_id);

/*+****************************************************************************
 *
 * Csp1Ssl20DecryptRecordRc4
 *
 * Input
 *	context_handle = 64-bit pointer to context (context_handle%8=0)
 *	record_length = size of record in bytes (0<=length<=2^16-1)
 *	record = pointer to length-byte encrypted part of record 
 *
 * Output
 *	message = pointer to decrypted message 
 *
 * Return Value
 *	completion_code = 0 (for success), ERR_BAD_SIZE_OR_DLEN_VAL, 
 *	ERR_BAD_RECORD, ERR_BAD_IOCTL, ERR_INSTRUCTION_TIMEOUT, 
 *	ERR_BAD_RECORD
 *
 *-***************************************************************************/
Uint32
Csp1Ssl20DecryptRecordRc4(
				n1_request_type request_type,
				Uint64 context_handle,
				Uint16 record_length,
				Uint8 *record,
				Uint8 *message,
				Uint32 *request_id);



/*+****************************************************************************
 *
 * Csp1Ssl20EncryptRecordRc4
 *
 * Input
 *	context_handle = 64-bit pointer to context (context_handle%8=0)
 *	message_length = size of message in bytes (0<=length<=2^16-1)
 *	message = pointer to length-byte message 
 *
 * Output
 *	record = pointer to encrypted record 
 *
 * Return Value
 *	completion_code = 0 (for success), ERR_BAD_SIZE_OR_DLEN_VAL, 
 *	ERR_BAD_IOCTL, ERR_INSTRUCTION_TIMEOUT
 *
 *-***************************************************************************/
Uint32
Csp1Ssl20EncryptRecordRc4(
				n1_request_type request_type,
				Uint64 context_handle,
				Uint16 message_length,
				Uint8 *message,
				Uint8 *record,
				Uint32 *request_id);


/*+****************************************************************************
 *
 * Csp1Ssl20DecryptRecord3Des
 *
 * Input
 *	context_handle = 64-bit pointer to context (context_handle%8=0)
 *	des_type = DES or DES3_192
 *	record_length = size of record in bytes (0<=length<=2^16-1)
 *	record = pointer to length-byte encrypted part of record 
 *
 * Output
 *	message = pointer to decrypted message 
 *
 * Return Value
 *	completion_code = 0 (for success), ERR_BAD_SIZE_OR_DLEN_VAL, 
 *	ERR_BAD_RECORD, ERR_BAD_IOCTL, ERR_INSTRUCTION_TIMEOUT, 
 *	ERR_BAD_RECORD
 *
 *-***************************************************************************/
Uint32 
Csp1Ssl20DecryptRecord3Des(
					n1_request_type request_type,
					Uint64 context_handle,
				   DesType des_type,
				   Uint16 record_length,
				   Uint8 *record,
				   Uint8 *message,
				   Uint32 *request_id);


/*+****************************************************************************
 *
 * Csp1Ssl20EncryptRecord3Des
 *
 * Input
 *	context_handle = 64-bit pointer to context (context_handle%8=0)
  *	des_type = DES or DES3_192
 *	message_length = size of message in bytes (0<=length<=2^16-1)
 *	message = pointer to length-byte message 
 *
 * Output
 *	record = pointer to encrypted record 
 *
 * Return Value
 *	completion_code = 0 (for success), ERR_BAD_SIZE_OR_DLEN_VAL, 
 *	ERR_BAD_IOCTL, ERR_INSTRUCTION_TIMEOUT
 *
 *-***************************************************************************/
Uint32
Csp1Ssl20EncryptRecord3Des(	
				n1_request_type request_type,
				Uint64 context_handle,
				DesType des_type,
				Uint16 message_length,
				Uint8 *message,
				Uint16 *record_length,
				Uint8 *record,
				Uint32 *request_id);




#endif /* CSP1_KERNEL */

#endif /* _CAVIUM_SSL_H_ */
