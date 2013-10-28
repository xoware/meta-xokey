/*
 * nb_app_perf.c:
 */
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

#include <stdio.h>
#include <stdlib.h>
#include <sys/time.h>
#include <getopt.h>
#include <unistd.h>
#include <openssl/sha.h>
#include <openssl/md5.h>
#include <openssl/hmac.h>
#include <openssl/rc4.h>
#include <openssl/err.h>
#include<openssl/rsa.h>
#include <cavium_be.h>
#include <cavium_le.h>
#include <cavium_common.h>
#include <assert.h>
#include "nb_app_perf.h"

#define AES_CIPHER        1
#define DES3_CIPHER       2
#define RC4_CIPHER        3
#define MD5_DIGEST        4
#define SHA_DIGEST        5
#define RSA_CRT           6
#define RSA_NOCRT         7
#define MODEXP            8
#define RSASERVERFULL     9
#define AES128_CIPHER     10
#define AES192_CIPHER     11
#define AES256_CIPHER     12

#define CRYPTO_PROCESS    0
#define RECORD_PROCESS    1

#define TLS1_VERSION      0
#define SSL3_VERSION      1

#define DEFAULT_DATA_LENGTH    1024
#define DEFAULT_KEY_VALUE      128
#define DEFAULT_MOD_LENGTH   128

#define PKP_CTL_REQ__DAT_RANDOM    32
#define PKP_CTL_REQ__DAT_SECRET    48
#define PKP_CTL_REQ__DAT_MAX_MODEXP    (64 * 8)
#define MAX_HANDSHAKE_SIZE             4000
#define HANDSHAKE_HEADER_LENGTH         4

typedef union Key_tag {
	struct {
		Uint8 q[PKP_CTL_REQ__DAT_MAX_MODEXP / 2];
		Uint8 eq[PKP_CTL_REQ__DAT_MAX_MODEXP / 2];
		Uint8 p[PKP_CTL_REQ__DAT_MAX_MODEXP / 2];
		Uint8 ep[PKP_CTL_REQ__DAT_MAX_MODEXP / 2];
		Uint8 iqmp[PKP_CTL_REQ__DAT_MAX_MODEXP / 2];
	} CRT;
	struct {
		Uint8 modulus[PKP_CTL_REQ__DAT_MAX_MODEXP];
		Uint8 exponent[PKP_CTL_REQ__DAT_MAX_MODEXP];
	} full;
} Key_t;

Uint8 clientRandom[PKP_CTL_REQ__DAT_RANDOM];
Uint8 serverRandom[PKP_CTL_REQ__DAT_RANDOM];
Uint8 client_finished[64];
Uint8 server_finished[64];
Key_t *rsa_key_t;

static int verbose_flag;
static int which_cipher = 0;
static int which_digest = 0;
static int which_operation = 0;
static int which_hs = 0;
static int isversion = 0;
static int record_flag = 0;
static int cipher_flag = 0;
static int digest_flag = 0;
static int crypto_flag = 0;
static int operation_flag = 0;
static int hs_flag = 0;
static int testTime = 10;
int modlength = DEFAULT_MOD_LENGTH;

unsigned char des_key[256], des_iv[32];
unsigned char aes_key[256], aes_iv[32];

Uint64 recLen;
int data = 30;
#ifdef CAVIUM_MULTICARD_API
Uint64 ctxHandle[4];
Uint32 k = 0;
#endif
AesType aes_type;
SslVersion ssl_version;
SslPartyType ssl_party;
MessageType message_type;
HashType hash_type;

/* Global variables to hold the request status information */
PENDING_BUFFER *pendingList = NULL;
Csp1RequestStatusBuffer *pollBuffer = NULL;
#ifdef CAVIUM_MULTICARD_API
int device_count = 0;
#endif

void show_options (char *command_name);
Uint32 nb_perf (
#ifndef CAVIUM_MULTICARD_API
	Uint64 ctxHandle,
#endif
	AesType aes_type,
	SslVersion ssl_version,
	SslPartyType ssl_party,
	MessageType message_type,
	HashType hash_type,
	unsigned char *iv, unsigned char *key, char *buffer, int bufferLen);

Uint32 RandRange (Uint32 min, Uint32 max);
void getrandom (Uint8 * buf, int len);
#ifndef CAVIUM_MULTICARD_API
int rsa_store_pkey (Key_t * pkey, Uint64 * key_handle, int modlength);
#else
int rsa_store_pkey (Key_t * pkey, Uint64 * key_handle, int modlength,
	int device_count);
#endif

void leftfill (unsigned char input[],
	int length, unsigned char output[], int finallength);

unsigned long apiTimeMS (void);
#ifndef CAVIUM_MULTICARD_API
Uint32 Csp1GetAllResults (Csp1RequestStatusBuffer * req_stat_buf,
	Uint32 buf_size, Uint32 * res_count);
#else
Uint32
Csp1GetAllResults (Csp1RequestStatusBuffer * req_stat_buf,
	Uint32 buf_size, Uint32 * res_count, Uint32 device_count);
#endif



int
main (int argc, char **argv)
{

	char buffer[DATA_LEN + 30];	/* Allow space for padding */
	signed char ch;
	int dlen = DEFAULT_DATA_LENGTH;
	char *cipher;
	char *digest;
	char *ver;
	char *operations;
	char *hs;
	int option_index = 0;
#ifndef CAVIUM_MULTICARD_API
	Uint64 ctxHandle = 0;
#else
	Uint32 device_id = 0;
	int dev_mask = 0;
#endif
	int i = 0;
	Uint64 bandWidth = -1;
	int max_key_length = 0;
	int options_count = 0;
	int select = 0;


	while (1) {
		static struct option long_options[] = {
			/*These options set a flag */
			{"verbose", no_argument, &verbose_flag, 1},
			{"brief", no_argument, &verbose_flag, 0},
			/*These options dont set the flag ,we distanguish them by their indices */
			{"help", no_argument, 0, 'h'},
			{"cipher", required_argument, 0, 'c'},
			{"dlen", required_argument, 0, 'l'},
			{"time", required_argument, 0, 't'},
			{"digest", required_argument, 0, 'd'},
			{"version", required_argument, 0, 's'},
			{"operations", required_argument, 0, 'p'},
			{"handshake", required_argument, 0, 'n'},
			{"moduluslength", required_argument, 0, 'm'},
			{0, 0, 0, 0}

		};						//long options structure

		ch = getopt_long (argc, argv, "hc:l:t:d:s:p:n:m:", long_options,
			&option_index);

		if (ch == -1 && options_count == 0) {
			//printf("options counts zero here\n");
			goto EndCases;
		}
		if (ch == -1) {
			//printf("coming from the options\n");
			break;
		}

		options_count++;

		switch (ch) {

		case 0:
			/*If this option set a flag ,do nothing else now */
			if (long_options[option_index].flag != 0)
				break;
			printf ("option %s\n", long_options[option_index].name);
			if (optarg)
				printf ("with arg %s\n", optarg);
			printf ("\n");
			break;

		case 'h':
			goto EndCases;
			break;

		case 'c':
			cipher = strdup (optarg);

			if ((!(strcmp (cipher, "aes"))) || (!(strcmp (cipher, "AES")))) {
				which_cipher = AES_CIPHER;
			} else if ((!(strcmp (cipher, "aes128"))) ||
				(!(strcmp (cipher, "AES128")))) {
				which_cipher = AES128_CIPHER;
			} else if ((!(strcmp (cipher, "aes192"))) ||
				(!(strcmp (cipher, "AES192")))) {
				which_cipher = AES192_CIPHER;
			} else if ((!(strcmp (cipher, "aes256"))) ||
				(!(strcmp (cipher, "AES256")))) {
				which_cipher = AES256_CIPHER;
			}

			else if ((!(strcmp (cipher, "3DES"))) ||
				(!(strcmp (cipher, "3DES"))) ||
				(!(strcmp (cipher, "DES3"))) ||
				(!(strcmp (cipher, "DES3"))) ||
				(!(strcmp (cipher, "3des"))) ||
				(!(strcmp (cipher, "3des"))) ||
				(!(strcmp (cipher, "des3"))) ||
				(!(strcmp (cipher, "des3")))) {
				which_cipher = DES3_CIPHER;
			} else if ((!(strcmp (cipher, "rc4"))) ||
				(!(strcmp (cipher, "RC4")))) {
				which_cipher = RC4_CIPHER;
			} else {
				printf
					("No support for this cipher,please refer the help\n");
				goto EndCases;
			}
			cipher_flag = 1;
			break;

		case 'l':
			dlen = atoi (optarg);
			data = dlen;
			if (dlen > DATA_LEN) {
				printf ("Oops Crossed the Maximum data length\n");
				printf ("The Maximum data length = %d\n", DATA_LEN);
				goto EndCases;
			}
			break;
		case 't':
			testTime = atoi (optarg);
			break;


		case 'd':
			digest = strdup (optarg);

			if ((!(strcmp (digest, "md5"))) || (!(strcmp (digest, "MD5")))) {
				which_digest = MD5_DIGEST;
			} else if ((!(strcmp (digest, "sha1"))) ||
				(!(strcmp (digest, "SHA1")))) {
				which_digest = SHA_DIGEST;
			} else {
				printf
					("No support for this digest ,please refer the help\n");
				goto EndCases;
			}
			digest_flag = 1;
			break;

		case 's':
			ver = strdup (optarg);

			if ((!(strcmp (ver, "tls1"))) || (!(strcmp (ver, "TLS1")))) {
				isversion = TLS1_VERSION;
			} else if ((!(strcmp (ver, "ssl3"))) ||
				(!(strcmp (ver, "SSL3")))) {
				isversion = SSL3_VERSION;
			} else {
				printf
					("No support for this version,please refer the help\n");
				goto EndCases;
			}
			break;

		case 'p':
			operations = strdup (optarg);

			if ((!(strcmp (operations, "RSA_CRT"))) ||
				(!(strcmp (operations, "rsa_crt")))) {
				which_operation = RSA_CRT;
			} else if ((!(strcmp (operations, "RSA_NOCRT"))) ||
				(!(strcmp (operations, "rsa_nocrt")))) {
				which_operation = RSA_NOCRT;
			} else if ((!(strcmp (operations, "MODEXP"))) ||
				(!(strcmp (operations, "modexp")))) {
				which_operation = MODEXP;
			} else {
				printf
					("No support for this rsa operation ,please refer the help\n");
				goto EndCases;
			}
			operation_flag = 1;
			break;

		case 'n':
			hs = strdup (optarg);

			if ((!(strcmp (hs, "RSASERVERFULL"))) ||
				(!(strcmp (hs, "rsaserverfull")))) {
				which_hs = RSASERVERFULL;
			} else {
				printf
					("No support for this rsa server full rc4 handshake operation ,please refer the help\n");
				goto EndCases;
			}
			hs_flag = 1;
			break;

		case 'm':
			modlength = atoi (optarg);
			if (modlength > 256) {
				printf ("Invalid modlength entered\n");
				printf ("Valid range of modlen: (64-256)\n");
				goto EndCases;
			}
			break;

		  EndCases:
			show_options (argv[0]);
			exit (0);

		}						//end of switch statement


	}							//while 1


	if (which_cipher == AES128_CIPHER) {
		aes_type = AES_128;
	} else if (which_cipher == AES192_CIPHER) {
		aes_type = AES_192;
	} else if (which_cipher == AES256_CIPHER) {
		aes_type = AES_256;
	} else {
		aes_type = AES_128;
	}

	if (which_cipher == AES128_CIPHER || which_cipher == AES192_CIPHER ||
		which_cipher == AES256_CIPHER) {
		which_cipher = AES_CIPHER;
	}

	if (cipher_flag && digest_flag) {
		if (isversion == SSL3_VERSION) {
			ssl_version = VER3_0;
		} else if (isversion == TLS1_VERSION) {
			ssl_version = VER_TLS;
		} else {
			ssl_version = VER_TLS;
		}

		if (which_digest == SHA_DIGEST) {
			hash_type = SHA1_TYPE;
		} else {
			hash_type = MD5_TYPE;
		}

		ssl_party = SSL_SERVER;
		message_type = APP_DATA;

		record_flag = 1;
	}
	if (cipher_flag == 1 && record_flag == 0) {
		record_flag = 0;
		crypto_flag = 1;
	}

	if ((cipher_flag || digest_flag) && operation_flag) {
		printf ("plz dont give the cipher and digest options\n");
		goto EndCases;
	}

	if ((cipher_flag || digest_flag || operation_flag) && hs_flag) {
		record_flag = 0;
		crypto_flag = 0;
		operation_flag = 0;
		//goto EndCases;
	}

	/* Initialize the plain data */
	for (i = 0; i < dlen; i++)
		buffer[i] = (char) i;

#ifndef CAVIUM_MULTICARD_API
	/* Allocate pending list */
	pendingList =
		(PENDING_BUFFER *) malloc ((MAX_PENDING +
			MAX_TO_POLL) * sizeof (PENDING_BUFFER));
	if (pendingList == NULL) {
		printf ("Not enough memory to allocate pendingList.\n");
		goto endTest;
	}
	/* Allocate poll buffer */
	pollBuffer =
		(Csp1RequestStatusBuffer *) malloc (MAX_TO_POLL *
		sizeof (Csp1RequestStatusBuffer));
	if (pollBuffer == NULL) {
		printf ("Not enough memory to allocate pollBuffer.\n");
		goto endTest;
	}
#ifdef CAVIUM_SCATTER_GATHER_MODE
	/* Initialize the chip in scatter gather mode */
	if (Csp1Initialize (CAVIUM_SCATTER_GATHER))
#else
	/* Initialize the chip in direct mode */
	if (Csp1Initialize (CAVIUM_DIRECT))
#endif
	{
		printf ("Unable to initialize the pkp device.\n");
		goto endTest;
	}

	/* Allocate a context handle - this will store the keys etc. */
	if (Csp1AllocContext (CONTEXT_SSL, &ctxHandle)) {
		printf ("Error allocating context.\n");
		goto endTest;
	}
#else
	if (Csp1Initialize (CAVIUM_DIRECT, CAVIUM_DEV_ID)) {
		printf ("pkp_init(): Cps1Initialize() failed. exiting\n");
		exit(-1); 
	}
	Csp1GetDevCnt ((Uint32 *) & device_count, (Uint8 *) & dev_mask);

	for (device_id = 1; device_id < device_count; device_id++) {
		if (Csp1Initialize (CAVIUM_DIRECT, device_id)) {
			printf ("pkp_init(): Cps1Initialize() failed for dev%d.\n",
				device_id);
			exit (-1);
		}
	}

	/* Allocate pending list */
	pendingList =
		(PENDING_BUFFER *) malloc (((MAX_PENDING +
				MAX_TO_POLL) * device_count) * sizeof (PENDING_BUFFER));
	if (pendingList == NULL) {
		printf ("Not enough memory to allocate pendingList.\n");
		goto endTest;
	}
	/* Allocate poll buffer */
	pollBuffer =
		(Csp1RequestStatusBuffer *) malloc (((MAX_TO_POLL +
		   MAX_PENDING)*device_count) * sizeof (Csp1RequestStatusBuffer));
	if (pollBuffer == NULL) {
		printf ("Not enough memory to allocate pollBuffer.\n");
		goto endTest;
	}

	for (device_id = 0; device_id < device_count; device_id++) {
		if (Csp1AllocContext (CONTEXT_SSL, &ctxHandle[device_id]
				, device_id)) {
			printf ("Error allocating context.\n");
			goto endTest;
		}
	}

#endif

	/* generate the 3DES key */
	for (i = 0; i < 24; i++) {
		des_key[i] = i;
		des_iv[i] = i + 64;
	}
	/* generate the AES key */
	if (aes_type == AES_128)
		max_key_length = 16;
	if (aes_type == AES_192)
		max_key_length = 24;
	if (aes_type == AES_256)
		max_key_length = 32;

	for (i = 0; i < max_key_length; i++) {
		aes_key[i] = i;
		aes_iv[i] = i + 64;
	}

	if ((cipher_flag || digest_flag) && (hs_flag != 1) &&
		(operation_flag != 1)) {
		select = which_cipher;
	} else if (operation_flag) {
		select = which_operation;
	} else if (hs_flag) {
		if (which_cipher == 0) {
			which_cipher = RC4_CIPHER;
			select = which_hs;
		} else if (which_digest == 0) {
			which_digest = SHA1_TYPE;
			select = which_hs;
		} else
			select = which_hs;
	}

	switch (select) {

	case DES3_CIPHER:
		bandWidth = nb_perf (
#ifndef CAVIUM_MULTICARD_API
			ctxHandle,
#endif
			aes_type,
			ssl_version,
			ssl_party,
			message_type, hash_type, aes_key, aes_iv, buffer, dlen);
		/* print the result */
		printf ("%20lld\n", (long long int) bandWidth);
		break;
	case AES_CIPHER:
		bandWidth = nb_perf (
#ifndef CAVIUM_MULTICARD_API
			ctxHandle,
#endif
			aes_type,
			ssl_version,
			ssl_party,
			message_type, hash_type, aes_key, aes_iv, buffer, dlen);
		/* print the result */
		printf ("%20lld\n", (long long int) bandWidth);
		break;
	case RC4_CIPHER:
		bandWidth = nb_perf (
#ifndef CAVIUM_MULTICARD_API
			ctxHandle,
#endif
			aes_type,
			ssl_version,
			ssl_party,
			message_type, hash_type, aes_key, aes_iv, buffer, dlen);
		/* print the result */
		printf ("%20lld\n", (long long int) bandWidth);
		break;
	case RSA_CRT:
		bandWidth = nb_perf (
#ifndef CAVIUM_MULTICARD_API
			ctxHandle,
#endif
			aes_type,
			ssl_version,
			ssl_party,
			message_type, hash_type, aes_key, aes_iv, buffer, dlen);
		break;
	case RSA_NOCRT:
		bandWidth = nb_perf (
#ifndef CAVIUM_MULTICARD_API
			ctxHandle,
#endif
			aes_type,
			ssl_version,
			ssl_party,
			message_type, hash_type, aes_key, aes_iv, buffer, dlen);
		break;
	case MODEXP:
		bandWidth = nb_perf (
#ifndef CAVIUM_MULTICARD_API
			ctxHandle,
#endif
			aes_type,
			ssl_version,
			ssl_party,
			message_type, hash_type, aes_key, aes_iv, buffer, dlen);
		break;
	case RSASERVERFULL:
		bandWidth = nb_perf (
#ifndef CAVIUM_MULTICARD_API
			ctxHandle,
#endif
			aes_type,
			ssl_version,
			ssl_party,
			message_type, hash_type, aes_key, aes_iv, buffer, dlen);
		printf ("\n");
		break;

	}							//end of which_cipher  switch

  endTest:

	/* Deallocate context */
#ifndef CAVIUM_MULTICARD_API
	if (ctxHandle)
		Csp1FreeContext (CONTEXT_SSL, ctxHandle);
	if (pollBuffer)
		free (pollBuffer);
#else
	for (device_id = 0; device_id < device_count; device_id++) {
		/* Deallocate context */
		if (ctxHandle[device_id]) {

			Csp1FreeContext (CONTEXT_SSL, ctxHandle[device_id], device_id);

		}
		Csp1Shutdown (device_id);
	}

#endif

	/* Free previously allocated memory */
	if (pendingList)
		free (pendingList);
	if (pollBuffer)
		free (pollBuffer);
	return (0);
}								//end of main function


Uint32
nb_perf (
#ifndef CAVIUM_MULTICARD_API
	Uint64 ctxHandle,
#endif
	AesType aes_type,
	SslVersion ssl_version,
	SslPartyType ssl_party,
	MessageType message_type,
	HashType hash_type,
	unsigned char *iv, unsigned char *key, char *buffer, int bufferLen)
{
	Uint16 pad_length;
	Uint32 ret, i, j, hit, hit_count, miss_count, pending_count, resCount;
	Uint32 count = 0;
	Uint32 retVal;
	Uint32 t1, t2;
	Uint32 time_elapsed = 0;
	Uint8 moretogo = 1;
	int bufflen = bufferLen;
	Uint32 operations;
	Uint32 throughput;


	if (record_flag) {

		t1 = apiTimeMS ();
#ifndef CAVIUM_MULTICARD_API
		for (i = 0; i < MAX_PENDING; i++) {
			pendingList[i].outlen = 0;
			pendingList[i].status = 0xff;

			if (which_cipher == AES_CIPHER) {
				retVal = Csp1EncryptRecordAes (CAVIUM_NON_BLOCKING,
					ctxHandle,
					hash_type,
					ssl_version,
					ssl_party,
					aes_type,
					message_type,
					pad_length,
					bufferLen,
					(Uint8 *) buffer,
					(Uint16 *) & recLen,
					(Uint8 *) buffer, &pendingList[i].reqid);
			}					//end of record aes

			else if (which_cipher == DES3_CIPHER) {
				retVal = Csp1EncryptRecord3Des (CAVIUM_NON_BLOCKING,
					ctxHandle,
					hash_type,
					ssl_version,
					ssl_party,
					message_type,
					pad_length,
					bufferLen,
					(Uint8 *) buffer,
					(Uint16 *) & recLen,
					(Uint8 *) buffer, &pendingList[i].reqid);
			}					//end of record des3
			else {
				retVal = Csp1EncryptRecordRc4 (CAVIUM_NON_BLOCKING,
					ctxHandle,
					hash_type,
					ssl_version,
					ssl_party,
					message_type,
					bufferLen,
					(Uint8 *) buffer,
					(Uint8 *) buffer, &pendingList[i].reqid);
			}					//end of record rc4

			if (retVal != EAGAIN) {
				printf
					("[%d] Csp1Encrypt : error sending encrypt request (error 0x%x).\n",
					i, retVal);
				/* now cleanup all the pending rrequests */
				count = 0;
				while (moretogo) {
					sleep (1);
					moretogo = 0;
					for (j = 0; j < i; j++) {
						pendingList[j].status =
							Csp1CheckForCompletion (pendingList[j].reqid);
						if (pendingList[j].status != 0x0)
							moretogo = 1;
					}

					if (count > 20)
						break;
				}
				return (-1);
			}

			pendingList[i].status = 1;
		}

		pending_count = MAX_PENDING;
		hit_count = miss_count = 0;
		int times = 0;
		while (1) {
			if ((times / 500)) {
				times -= 500;
				t2 = apiTimeMS ();
				if ((t2 - t1) >= testTime * 1000) {
					goto cleanup;
				}
			}
			for (i = 0; i < MAX_PENDING; i = i + MAX_TO_POLL) {
				hit = 1;
				for (j = 0; j < MAX_TO_POLL; j++) {
					if (pendingList[j + i].status == 0) {
						hit = 0;
						break;
					}
				}
				if (hit) {
					hit_count++;
					for (j = 0; j < MAX_TO_POLL; j++) {
						pollBuffer[j].request_id =
							pendingList[j + i].reqid;
						pollBuffer[j].status = 1;
					}

					ret = Csp1GetAllResults (pollBuffer,
						MAX_TO_POLL * sizeof (Csp1RequestStatusBuffer),
						&resCount);

					for (j = 0; j < MAX_TO_POLL; j++) {
						if (pollBuffer[j].status == 0) {
							count++;
							times++;
							/* send the request again */
							if (which_cipher == AES_CIPHER) {
								retVal =
									Csp1EncryptRecordAes
									(CAVIUM_NON_BLOCKING, ctxHandle,
									hash_type, ssl_version, ssl_party,
									aes_type, message_type, pad_length,
									bufferLen, (Uint8 *) buffer,
									(Uint16 *) & recLen, (Uint8 *) buffer,
									&pendingList[j + i].reqid);
							}	//end of record aes
							else if (which_cipher == DES3_CIPHER) {
								retVal =
									Csp1EncryptRecord3Des
									(CAVIUM_NON_BLOCKING, ctxHandle,
									hash_type, ssl_version, ssl_party,
									message_type, pad_length, bufferLen,
									(Uint8 *) buffer, (Uint16 *) & recLen,
									(Uint8 *) buffer,
									&pendingList[j + i].reqid);
							}	//end of record des3
							else {
								retVal =
									Csp1EncryptRecordRc4
									(CAVIUM_NON_BLOCKING, ctxHandle,
									hash_type, ssl_version, ssl_party,
									message_type, bufferLen,
									(Uint8 *) buffer, (Uint8 *) buffer,
									&pendingList[j + i].reqid);
							}	//end of record rc4

							if (retVal != EAGAIN) {
								printf
									("Csp1Encrypt : error sending request.\n");
								pendingList[j + i].status = 0;
								pending_count--;
								goto cleanup;
							}

							pendingList[j + i].status = 1;
						}

						else if (pollBuffer[j].status != ERR_REQ_PENDING) {
							pendingList[j + i].status = 0;
							pending_count--;
							printf
								("Request %d failed (error code 0x%X)\n",
								pendingList[j + i].reqid,
								pollBuffer[j].status);
							printf ("Success Count = %d\n", count);
							printf ("pending count = %d\n", pending_count);
							goto cleanup;
						}
					}			/* for j */
				} /* if all pending */
				else {
					miss_count++;
					for (j = 0; j < MAX_TO_POLL; j++) {
						if (pendingList[j + i].status) {
							pollBuffer[0].request_id =
								pendingList[j + i].reqid;
							pollBuffer[0].status = 1;
							ret = Csp1GetAllResults (pollBuffer,
								sizeof (Csp1RequestStatusBuffer),
								&resCount);
							if (pollBuffer[0].status == 0) {
								count++;
								if (which_cipher == AES_CIPHER) {
									retVal =
										Csp1EncryptRecordAes
										(CAVIUM_NON_BLOCKING, ctxHandle,
										hash_type, ssl_version, ssl_party,
										aes_type, message_type, pad_length,
										bufferLen, (Uint8 *) buffer,
										(Uint16 *) & recLen,
										(Uint8 *) buffer,
										&pendingList[j + i].reqid);
								}	//end of record aes
								else if (which_cipher == DES3_CIPHER) {
									retVal =
										Csp1EncryptRecord3Des
										(CAVIUM_NON_BLOCKING, ctxHandle,
										hash_type, ssl_version, ssl_party,
										message_type, pad_length,
										bufferLen, (Uint8 *) buffer,
										(Uint16 *) & recLen,
										(Uint8 *) buffer,
										&pendingList[j + i].reqid);
								}	//end of record des3
								else {
									retVal =
										Csp1EncryptRecordRc4
										(CAVIUM_NON_BLOCKING, ctxHandle,
										hash_type, ssl_version, ssl_party,
										message_type, bufferLen,
										(Uint8 *) buffer, (Uint8 *) buffer,
										&pendingList[j + i].reqid);
								}	//end of record rc4

								if (retVal != EAGAIN) {
									printf
										("Csp1Encrypt : error sending request.\n");
									pendingList[j + i].status = 0;
									pending_count--;
									goto cleanup;
								}
							} else if (pollBuffer[0].status !=
								ERR_REQ_PENDING) {
								pendingList[j + i].status = 0;
								pending_count--;
								printf
									("Request %d failed (error code 0x%X)\n",
									pendingList[j + i].reqid,
									pollBuffer[0].status);
								printf ("Success Count = %d\n", count);
								printf ("cleanup pending count = %d\n",
									pending_count);
								goto cleanup;
							}
						}
					}
				}
			}
		}
#else
		for (k = 0; k < device_count; k++) {
			for (i = 0; i < MAX_PENDING; i++) {
				pendingList[(k * MAX_PENDING) + i].outlen = 0;
				pendingList[(k * MAX_PENDING) + i].status = 0xff;
				if (which_cipher == AES_CIPHER) {
					retVal = Csp1EncryptRecordAes (CAVIUM_NON_BLOCKING,
						ctxHandle[k],
						hash_type,
						ssl_version,
						ssl_party,
						aes_type,
						message_type,
						pad_length,
						bufferLen,
						(Uint8 *) buffer,
						(Uint16 *) & recLen,
						(Uint8 *) buffer,
						&(pendingList[(k * MAX_PENDING) + i].reqid), k);
				}				//end of record aes

				else if (which_cipher == DES3_CIPHER) {
					retVal = Csp1EncryptRecord3Des (CAVIUM_NON_BLOCKING,
						ctxHandle[k],
						hash_type,
						ssl_version,
						ssl_party,
						message_type,
						pad_length,
						bufferLen,
						(Uint8 *) buffer,
						(Uint16 *) & recLen,
						(Uint8 *) buffer,
						&pendingList[(k * MAX_PENDING) + i].reqid, k);
				}				//end of record des3
				else {
					retVal = Csp1EncryptRecordRc4 (CAVIUM_NON_BLOCKING,
						ctxHandle[k],
						hash_type,
						ssl_version,
						ssl_party,
						message_type,
						bufferLen,
						(Uint8 *) buffer,
						(Uint8 *) buffer,
						&pendingList[(k * MAX_PENDING) + i].reqid, k);
				}				//end of record rc4



				if (retVal != EAGAIN) {
					printf
						("[%d] Csp1Encrypt : error sending encrypt request (error 0x%x).\n",
						i, retVal);
					/* now cleanup all the pending rrequests */
					count = 0;
					while (moretogo) {
						moretogo = 0;
						for (j = 0; j < i; j++) {
							pendingList[k * MAX_PENDING + j].status =
								Csp1CheckForCompletion (pendingList[k *
									MAX_PENDING + j].reqid, k);
							if (pendingList[k * MAX_PENDING + j].status !=
								0x0)
								moretogo = 1;
						}

						if (count > 20)
							break;
					}
					return (-1);
				}

				pendingList[k * MAX_PENDING + i].status = 1;

			}					//end of i

		}						//end  for k
		pending_count = MAX_PENDING * device_count;
		hit_count = miss_count = 0;
		int times = 0;
		while (1) {
			if ((times / 500)) {
				times -= 500;
				t2 = apiTimeMS ();
				if ((t2 - t1) >= testTime * 1000) {
					goto cleanup;
				}
			}
			//here needs a for loop for k=devicecount
			for (k = 0; k < device_count; k++) {
				for (j = 0; j < MAX_PENDING; j += MAX_TO_POLL) {

					for (i = 0; i < MAX_TO_POLL; i++) {
						hit = 1;
						if (pendingList[(k * MAX_PENDING) + j +
								i].status == 0) {
							hit = 0;
							break;
						}
					}
					if (hit) {
						hit_count++;
						for (i = 0; i < MAX_TO_POLL; i++) {
							pollBuffer[i].request_id =
								pendingList[(k * MAX_PENDING) + j +
								i].reqid;
							pollBuffer[i].status = 1;
						}
						ret = Csp1GetAllResults (pollBuffer,
							MAX_TO_POLL * sizeof (Csp1RequestStatusBuffer),
							&resCount, k);
						if (ret) {
							printf ("BAD ERROR j=%d---i=%d\n", i, j);
						}
						for (i = 0; i < MAX_TO_POLL; i++) {
							if (pollBuffer[i].status == 0) {
								count++;
								times++;
								if (which_cipher == AES_CIPHER) {
									retVal =
										Csp1EncryptRecordAes
										(CAVIUM_NON_BLOCKING, ctxHandle[k],
										hash_type, ssl_version, ssl_party,
										aes_type, message_type, pad_length,
										bufferLen, (Uint8 *) buffer,
										(Uint16 *) & recLen,
										(Uint8 *) buffer,
										&pendingList[(k * MAX_PENDING) +
											j + i].reqid, k);
								}	//end of record aes

								else if (which_cipher == DES3_CIPHER) {
									retVal =
										Csp1EncryptRecord3Des
										(CAVIUM_NON_BLOCKING, ctxHandle[k],
										hash_type, ssl_version, ssl_party,
										message_type, pad_length,
										bufferLen, (Uint8 *) buffer,
										(Uint16 *) & recLen,
										(Uint8 *) buffer,
										&pendingList[(k * MAX_PENDING) +
											j + i].reqid, k);
								}	//end of record des3
								else {
									retVal =
										Csp1EncryptRecordRc4
										(CAVIUM_NON_BLOCKING, ctxHandle[k],
										hash_type, ssl_version, ssl_party,
										message_type, bufferLen,
										(Uint8 *) buffer, (Uint8 *) buffer,
										&pendingList[(k * MAX_PENDING) +
											j + i].reqid, k);
								}	//end of record rc4


								if (retVal != EAGAIN) {
									printf
										("Hit Csp1Encrypt : error sending request.\n");
									pendingList[(k * MAX_PENDING) + j +
										i].status = 0;
									pending_count--;
									goto cleanup;
								}

								pendingList[(k * MAX_PENDING) + j +
									i].status = 1;
							} else if (((pollBuffer[(k * MAX_TO_POLL) +
											j].status) =
									!ERR_REQ_PENDING)) {
								pendingList[(k * MAX_TO_POLL) + i +
									j].status = 0;
								pending_count--;
								printf
									("hit Request %d failed (error code 0x%X) at j=%d\n",
									pendingList[(k * MAX_TO_POLL) + i +
										j].reqid,
									pollBuffer[(k * MAX_TO_POLL) +
										i].status, j);
								printf ("hit Success Count = %d\n", count);
								printf ("hit pending count = %d\n",
									pending_count);
								goto cleanup;
							}
						}		/* for i */
					} else {
						miss_count++;
						printf ("/n Miss\n");
						for (j = 0; j < MAX_TO_POLL; j++) {
							if (pendingList[(k * MAX_TO_POLL) + i +
									j].status) {
								pollBuffer[0].request_id =
									pendingList[(k * MAX_TO_POLL) + j +
									i].reqid;
								ret =
									Csp1GetAllResults (pollBuffer,
									sizeof (Csp1RequestStatusBuffer),
									&resCount, k);
								if (pollBuffer[j].status == 0) {
									count++;
									if (which_cipher == AES_CIPHER) {
										retVal =
											Csp1EncryptRecordAes
											(CAVIUM_NON_BLOCKING,
											ctxHandle[k], hash_type,
											ssl_version, ssl_party,
											aes_type, message_type,
											pad_length, bufferLen,
											(Uint8 *) buffer,
											(Uint16 *) & recLen,
											(Uint8 *) buffer,
											&pendingList[(k *
													MAX_PENDING) + i +
												j].reqid, k);
									}	//end of record aes

									else if (which_cipher == DES3_CIPHER) {
										retVal =
											Csp1EncryptRecord3Des
											(CAVIUM_NON_BLOCKING,
											ctxHandle[k], hash_type,
											ssl_version, ssl_party,
											message_type, pad_length,
											bufferLen, (Uint8 *) buffer,
											(Uint16 *) & recLen,
											(Uint8 *) buffer,
											&pendingList[(k *
													MAX_PENDING) + i +
												j].reqid, k);
									}	//end of record des3
									else {
										retVal =
											Csp1EncryptRecordRc4
											(CAVIUM_NON_BLOCKING,
											ctxHandle[k], hash_type,
											ssl_version, ssl_party,
											message_type, bufferLen,
											(Uint8 *) buffer,
											(Uint8 *) buffer,
											&pendingList[(k *
													MAX_PENDING) + i +
												j].reqid, k);
									}	//end of record rc4


									if (retVal != EAGAIN) {
										printf
											("Miss Csp1Encrypt : error sending request.\n");
										pendingList[(k * MAX_TO_POLL) + j +
											i].status = 0;
										pending_count--;
										goto cleanup;
									}
								} else if (pollBuffer[0].status !=
									ERR_REQ_PENDING) {
									pendingList[(k * MAX_TO_POLL) + j +
										i].status = 0;
									pending_count--;
									printf
										("Miss Request %d failed (error code 0x%X)\n",
										pendingList[(k * MAX_TO_POLL) + i +
											j].reqid,
										pollBuffer[0].status);
									printf ("Miss Success Count = %d\n",
										count);
									printf
										("Miss cleanup pending count = %d\n",
										pending_count);
									goto cleanup;
								}

							}
						}
					}

				}				//j loop
			}					//k
		}						//while 1 loop
#endif
		goto cleanup;
	}							//end of record flag 

	else if (crypto_flag) {

		Uint32 device=0;
		t1 = apiTimeMS ();

#ifndef CAVIUM_MULTICARD_API
		for (i = 0; i < MAX_PENDING; i++) {
			pendingList[i].outlen = 0;
			pendingList[i].status = 0xff;
			if (which_cipher == DES3_CIPHER) {
				retVal = Csp1Encrypt3Des (CAVIUM_NON_BLOCKING,
					ctxHandle,
					CAVIUM_NO_UPDATE,
					bufferLen,
					(Uint8 *) buffer,
					(Uint8 *) buffer,
					(Uint8 *) iv, (Uint8 *) key, &pendingList[i].reqid);
			}					//end of DES3cipher
			else if (which_cipher == AES_CIPHER) {
				Uint32 device=0;
				if(Csp1GetDevType(&device))
				{
					printf("failed in determining device");
					exit (-1);
				}
				if(device == N1_DEVICE){
					printf ("\n\tAES Not Supported for N1_DEVICE\n\n");
					exit (-1);
				}
				retVal = Csp1EncryptAes (CAVIUM_NON_BLOCKING,
					ctxHandle,
					CAVIUM_NO_UPDATE,
					aes_type,
					bufferLen,
					(Uint8 *) buffer,
					(Uint8 *) buffer,
					(Uint8 *) iv, (Uint8 *) key, &pendingList[i].reqid);
			}					//end of AES
			else {
				retVal = Csp1EncryptRc4 (CAVIUM_NON_BLOCKING,
					ctxHandle,
					CAVIUM_NO_UPDATE,
					bufferLen,
					(Uint8 *) buffer,
					(Uint8 *) buffer, &pendingList[i].reqid);
			}					//end of rc4
			if (retVal != EAGAIN) {
				printf
					("[%d] Csp1Encrypt : error sending encrypt request (error 0x%x).\n",
					i, retVal);
				/* now cleanup all the pending rrequests */
				count = 0;
				while (moretogo) {
					sleep (1);
					moretogo = 0;
					for (j = 0; j < i; j++) {
						pendingList[j].status =
							Csp1CheckForCompletion (pendingList[j].reqid);
						if (pendingList[j].status != 0x0)
							moretogo = 1;
					}
					if (count > 20)
						break;
				}
				return (-1);
			}
			pendingList[i].status = 1;
		}

		pending_count = MAX_PENDING;
		hit_count = miss_count = 0;
		int times = 0;
		while (1) {
			if ((times / 500)) {
				times -= 500;
				t2 = apiTimeMS ();
				if ((t2 - t1) >= testTime * 1000) {
					goto cleanup;
				}
			}
			for (i = 0; i < MAX_PENDING; i = i + MAX_TO_POLL) {
				hit = 1;
				for (j = 0; j < MAX_TO_POLL; j++) {
					if (pendingList[j + i].status == 0) {
						hit = 0;
						break;
					}
				}
				if (hit) {
					hit_count++;
					for (j = 0; j < MAX_TO_POLL; j++) {
						pollBuffer[j].request_id =
							pendingList[j + i].reqid;
						pollBuffer[j].status = 1;
					}

					ret = Csp1GetAllResults (pollBuffer,
						MAX_TO_POLL * sizeof (Csp1RequestStatusBuffer),
						&resCount);

					for (j = 0; j < MAX_TO_POLL; j++) {
						if (pollBuffer[j].status == 0) {
							count++;
							times++;
							/* send the request again */
							if (which_cipher == DES3_CIPHER) {
								retVal =
									Csp1Encrypt3Des (CAVIUM_NON_BLOCKING,
									ctxHandle, CAVIUM_NO_UPDATE, bufferLen,
									(Uint8 *) buffer, (Uint8 *) buffer,
									(Uint8 *) iv, (Uint8 *) key,
									&pendingList[j + i].reqid);
							}	//end of DES3cipher
							else if (which_cipher == AES_CIPHER) {
								retVal =
									Csp1EncryptAes (CAVIUM_NON_BLOCKING,
									ctxHandle, CAVIUM_NO_UPDATE, aes_type,
									bufferLen, (Uint8 *) buffer,
									(Uint8 *) buffer, (Uint8 *) iv,
									(Uint8 *) key,
									&pendingList[j + i].reqid);
							}	//end of AES
							else {
								retVal =
									Csp1EncryptRc4 (CAVIUM_NON_BLOCKING,
									ctxHandle, CAVIUM_NO_UPDATE, bufferLen,
									(Uint8 *) buffer, (Uint8 *) buffer,
									&pendingList[j + i].reqid);
							}	//end of rc4

							if (retVal != EAGAIN) {
								printf
									("Csp1Encrypt : error sending request.\n");
								pendingList[j + i].status = 0;
								pending_count--;
								goto cleanup;
							}

							pendingList[j + i].status = 1;
						}

						else if (pollBuffer[j].status != ERR_REQ_PENDING) {
							pendingList[j + i].status = 0;
							pending_count--;
							printf
								("Request %d failed (error code 0x%X)\n",
								pendingList[j + i].reqid,
								pollBuffer[j].status);
							printf ("Success Count = %d\n", count);
							printf ("pending count = %d\n", pending_count);
							goto cleanup;
						}
					}			/* for j */
				} /* if all pending */
				else {
					miss_count++;
					for (j = 0; j < MAX_TO_POLL; j++) {
						if (pendingList[j + i].status) {
							pollBuffer[0].request_id =
								pendingList[j + i].reqid;
							pollBuffer[0].status = 1;
							ret = Csp1GetAllResults (pollBuffer,
								sizeof (Csp1RequestStatusBuffer),
								&resCount);
							if (pollBuffer[0].status == 0) {
								count++;
								if (which_cipher == DES3_CIPHER) {
									retVal =
										Csp1Encrypt3Des
										(CAVIUM_NON_BLOCKING, ctxHandle,
										CAVIUM_NO_UPDATE, bufferLen,
										(Uint8 *) buffer, (Uint8 *) buffer,
										(Uint8 *) iv, (Uint8 *) key,
										&pendingList[j + i].reqid);
								}	//end of DES3cipher
								else if (which_cipher == AES_CIPHER) {
									retVal =
										Csp1EncryptAes
										(CAVIUM_NON_BLOCKING, ctxHandle,
										CAVIUM_NO_UPDATE, aes_type,
										bufferLen, (Uint8 *) buffer,
										(Uint8 *) buffer, (Uint8 *) iv,
										(Uint8 *) key,
										&pendingList[j + i].reqid);
								}	//end of AES
								else {
									retVal =
										Csp1EncryptRc4
										(CAVIUM_NON_BLOCKING, ctxHandle,
										CAVIUM_NO_UPDATE, bufferLen,
										(Uint8 *) buffer, (Uint8 *) buffer,
										&pendingList[j + i].reqid);
								}	//end of rc4
								if (retVal != EAGAIN) {
									printf
										("Csp1Encrypt : error sending request.\n");
									pendingList[j + i].status = 0;
									pending_count--;
									goto cleanup;
								}
							} else if (pollBuffer[0].status !=
								ERR_REQ_PENDING) {
								pendingList[j + i].status = 0;
								pending_count--;
								printf
									("Request %d failed (error code 0x%X)\n",
									pendingList[j + i].reqid,
									pollBuffer[0].status);
								printf ("Success Count = %d\n", count);
								printf ("pending count = %d\n",
									pending_count);
								goto cleanup;
							}
						}
					}
				}
			}
		}

#else
		if(Csp1GetDevType(&device))
		{
			printf("failed in determining device");
			exit (-1);
		}
		for (k = 0; k < device_count; k++) {
			for (i = 0; i < MAX_PENDING; i++) {
				pendingList[(k * MAX_PENDING) + i].outlen = 0;
				pendingList[(k * MAX_PENDING) + i].status = 0xff;
				if (which_cipher == DES3_CIPHER) {
					retVal = Csp1Encrypt3Des (CAVIUM_NON_BLOCKING,
						ctxHandle[k],
						CAVIUM_NO_UPDATE,
						bufferLen,
						(Uint8 *) buffer,
						(Uint8 *) buffer,
						(Uint8 *) iv,
						(Uint8 *) key,
						&pendingList[(k * MAX_PENDING) + i].reqid, k);
				}				//end of DES3cipher
				else if (which_cipher == AES_CIPHER) {
					if(device == N1_DEVICE){
						printf ("\n\tAES Not Supported for N1_DEVICE\n\n");
						exit (-1);
					}
					retVal = Csp1EncryptAes (CAVIUM_NON_BLOCKING,
						ctxHandle[k],
						CAVIUM_NO_UPDATE,
						aes_type,
						bufferLen,
						(Uint8 *) buffer,
						(Uint8 *) buffer,
						(Uint8 *) iv,
						(Uint8 *) key,
						&pendingList[(k * MAX_PENDING) + i].reqid, k);
				}				//end of AES
				else {
					retVal = Csp1EncryptRc4 (CAVIUM_NON_BLOCKING,
						ctxHandle[k],
						CAVIUM_NO_UPDATE,
						bufferLen,
						(Uint8 *) buffer,
						(Uint8 *) buffer,
						&pendingList[(k * MAX_PENDING) + i].reqid, k);
				}				//end of rc4


				if (retVal != EAGAIN) {
					printf
						("[%d] Csp1Encrypt : error sending encrypt request (error 0x%x).\n",
						i, retVal);
					/* now cleanup all the pending rrequests */
					exit (0);	
					count = 0;
					while (moretogo) {
						moretogo = 0;
						for (j = 0; j < i; j++) {
							pendingList[k * MAX_PENDING + j].status =
								Csp1CheckForCompletion (pendingList[k *
									MAX_PENDING + j].reqid, k);
							if (pendingList[k * MAX_PENDING + j].status !=
								0x0)
								moretogo = 1;
						}

						if (count > 20)
							break;
					}
					return (-1);
				}

				pendingList[k * MAX_PENDING + i].status = 1;

			}					//end of i

		}						//end  for k
		pending_count = MAX_PENDING * device_count;
		hit_count = miss_count = 0;

		int times = 0;
		while (1) {
			if ((times / 500)) {
				times -= 500;
				t2 = apiTimeMS ();
				if ((t2 - t1) >= testTime * 1000) {
					goto cleanup;
				}
			}
			//here needs a for loop for k=devicecount
			for (k = 0; k < device_count; k++) {
				for (j = 0; j < MAX_PENDING; j += MAX_TO_POLL) {

					for (i = 0; i < MAX_TO_POLL; i++) {
						hit = 1;
						if (pendingList[(k * MAX_PENDING) + j +
								i].status == 0) {
							hit = 0;
							break;
						}
					}
					if (hit) {
						hit_count++;
						for (i = 0; i < MAX_TO_POLL; i++) {
							pollBuffer[i].request_id =
								pendingList[(k * MAX_PENDING) + i +
								j].reqid;
							pollBuffer[i].status = 1;
						}
						ret = Csp1GetAllResults (pollBuffer,
							MAX_TO_POLL * sizeof (Csp1RequestStatusBuffer),
							&resCount, k);
						if (ret) {
							printf ("BAD ERROR j=%d---i=%d\n", i, j);
							exit (0);	
						}

						for (i = 0; i < MAX_TO_POLL; i++) {
							if (pollBuffer[i].status == 0) {
								count++;
								times++;
								if (which_cipher == DES3_CIPHER) {
									retVal =
										Csp1Encrypt3Des
										(CAVIUM_NON_BLOCKING, ctxHandle[k],
										CAVIUM_NO_UPDATE, bufferLen,
										(Uint8 *) buffer, (Uint8 *) buffer,
										(Uint8 *) iv, (Uint8 *) key,
										&pendingList[(k * MAX_PENDING) +
											i + j].reqid, k);
								}	//end of DES3cipher
								else if (which_cipher == AES_CIPHER) {
									retVal =
										Csp1EncryptAes
										(CAVIUM_NON_BLOCKING, ctxHandle[k],
										CAVIUM_NO_UPDATE, aes_type,
										bufferLen, (Uint8 *) buffer,
										(Uint8 *) buffer, (Uint8 *) iv,
										(Uint8 *) key,
										&pendingList[(k * MAX_PENDING) +
											i + j].reqid, k);
								}	//end of AES
								else {
									retVal =
										Csp1EncryptRc4
										(CAVIUM_NON_BLOCKING, ctxHandle[k],
										CAVIUM_NO_UPDATE, bufferLen,
										(Uint8 *) buffer, (Uint8 *) buffer,
										&pendingList[(k * MAX_PENDING) +
											i + j].reqid, k);
								}	//end of rc4


								if (retVal != EAGAIN) {
									printf
										("Hit Csp1Encrypt : error sending request.\n");
									pendingList[(k * MAX_PENDING) + i +
										j].status = 0;
									pending_count--;
									goto cleanup;
								}

								pendingList[(k * MAX_PENDING) + i +
									j].status = 1;
							}

							else if (((pollBuffer[(k * MAX_TO_POLL) +
											j].status) =
									!ERR_REQ_PENDING)) {
								pendingList[(k * MAX_TO_POLL) + i +
									j].status = 0;
								pending_count--;
								exit (0);	
								printf
									("hit Request %d failed (error code 0x%X) at j=%d\n",
									pendingList[(k * MAX_TO_POLL) + i +
										j].reqid,
									pollBuffer[(k * MAX_TO_POLL) +
										i].status, j);
								printf ("hit Success Count = %d\n", count);
								printf ("hit pending count = %d\n",
									pending_count);
								goto cleanup;
							}
						}		/* for j */
					} else {
						miss_count++;
						printf ("/n Miss\n");
						exit (0);
						for (j = 0; j < MAX_TO_POLL; j++) {
							if (pendingList[(k * MAX_TO_POLL) + i +
									j].status) {
								pollBuffer[0].request_id =
									pendingList[(k * MAX_TO_POLL) + j +
									i].reqid;
								ret =
									Csp1GetAllResults (pollBuffer,
									sizeof (Csp1RequestStatusBuffer),
									&resCount, k);
								if (pollBuffer[j].status == 0) {
									count++;
									if (which_cipher == DES3_CIPHER) {
										retVal =
											Csp1Encrypt3Des
											(CAVIUM_NON_BLOCKING,
											ctxHandle[k], CAVIUM_NO_UPDATE,
											bufferLen, (Uint8 *) buffer,
											(Uint8 *) buffer, (Uint8 *) iv,
											(Uint8 *) key,
											&pendingList[(k *
													MAX_PENDING) + i +
												j].reqid, k);
									}	//end of DES3cipher
									else if (which_cipher == AES_CIPHER) {
										retVal =
											Csp1EncryptAes
											(CAVIUM_NON_BLOCKING,
											ctxHandle[k], CAVIUM_NO_UPDATE,
											aes_type, bufferLen,
											(Uint8 *) buffer,
											(Uint8 *) buffer, (Uint8 *) iv,
											(Uint8 *) key,
											&pendingList[(k *
													MAX_PENDING) + i +
												j].reqid, k);
									}	//end of AES
									else {
										retVal =
											Csp1EncryptRc4
											(CAVIUM_NON_BLOCKING,
											ctxHandle[k], CAVIUM_NO_UPDATE,
											bufferLen, (Uint8 *) buffer,
											(Uint8 *) buffer,
											&pendingList[(k *
													MAX_PENDING) + i +
												j].reqid, k);
									}	//end of rc4


									if (retVal != EAGAIN) {
										printf
											("Miss Csp1Encrypt : error sending request.\n");
										pendingList[(k * MAX_TO_POLL) + j +
											i].status = 0;
										pending_count--;
										goto cleanup;
									}
								} else if (pollBuffer[0].status !=
									ERR_REQ_PENDING) {
									pendingList[(k * MAX_TO_POLL) + j +
										i].status = 0;
									pending_count--;
									printf
										("Miss Request %d failed (error code 0x%X)\n",
										pendingList[(k * MAX_TO_POLL) + i +
											j].reqid,
										pollBuffer[0].status);
									printf ("Miss Success Count = %d\n",
										count);
									printf
										("Miss cleanup pending count = %d\n",
										pending_count);
									goto cleanup;
								}

							}
						}
					}

				}				//max pending loop
			}					//k
		}						//while 1 loop


#endif
		goto cleanup;
	}							//End of crypto flag
	else if (operation_flag) {

		RsaBlockType block_type;
		block_type = BT2;
		int explength = 8;


		/* Depending on the size of MOD_LEN (x), declare the mod[x] here */
		/* E.g. for MOD_LEN 128, declare mod[128] with 128 bytes */
		unsigned char mod[256] = {
			0x0d, 0x4b, 0xb3, 0x81, 0x4c, 0x1d, 0x2d, 0x79,
			0x77, 0x25, 0x10, 0xe0, 0xbd, 0xd4, 0x0c, 0xf7,
			0x9f, 0x1e, 0x42, 0x5e, 0x0e, 0x70, 0x31, 0xa9,
			0x6f, 0x4a, 0x6c, 0x1a, 0x01, 0x9e, 0xb8, 0xc5,
			0x0a, 0x9a, 0x33, 0x54, 0xc2, 0x23, 0x28, 0x77,
			0x8e, 0xa7, 0x31, 0xf3, 0x0c, 0xb6, 0x4a, 0xe9,
			0x29, 0xf2, 0x1b, 0x90, 0xf5, 0xb0, 0xa4, 0xf3,
			0x42, 0x70, 0x93, 0xa0, 0xd0, 0x11, 0x37, 0xc6,
			0x0d, 0x4b, 0xb3, 0x81, 0x4c, 0x1d, 0x2d, 0x79,
			0x77, 0x25, 0x10, 0xe0, 0xbd, 0xd4, 0x0c, 0xf7,
			0x9f, 0x1e, 0x42, 0x5e, 0x0e, 0x70, 0x31, 0xa9,
			0x6f, 0x4a, 0x6c, 0x1a, 0x01, 0x9e, 0xb8, 0xc5,
			0x0a, 0x9a, 0x33, 0x54, 0xc2, 0x23, 0x28, 0x77,
			0x8e, 0xa7, 0x31, 0xf3, 0x0c, 0xb6, 0x4a, 0xe9,
			0x29, 0xf2, 0x1b, 0x90, 0xf5, 0xb0, 0xa4, 0xf3,
			0x42, 0x70, 0x93, 0xa0, 0xd0, 0x11, 0x37, 0xc6,
			0x0d, 0x4b, 0xb3, 0x81, 0x4c, 0x1d, 0x2d, 0x79,
			0x77, 0x25, 0x10, 0xe0, 0xbd, 0xd4, 0x0c, 0xf7,
			0x9f, 0x1e, 0x42, 0x5e, 0x0e, 0x70, 0x31, 0xa9,
			0x6f, 0x4a, 0x6c, 0x1a, 0x01, 0x9e, 0xb8, 0xc5,
			0x0a, 0x9a, 0x33, 0x54, 0xc2, 0x23, 0x28, 0x77,
			0x8e, 0xa7, 0x31, 0xf3, 0x0c, 0xb6, 0x4a, 0xe9,
			0x29, 0xf2, 0x1b, 0x90, 0xf5, 0xb0, 0xa4, 0xf3,
			0x42, 0x70, 0x93, 0xa0, 0xd0, 0x11, 0x37, 0xc6,
			0x0d, 0x4b, 0xb3, 0x81, 0x4c, 0x1d, 0x2d, 0x79,
			0x77, 0x25, 0x10, 0xe0, 0xbd, 0xd4, 0x0c, 0xf7,
			0x9f, 0x1e, 0x42, 0x5e, 0x0e, 0x70, 0x31, 0xa9,
			0x6f, 0x4a, 0x6c, 0x1a, 0x01, 0x9e, 0xb8, 0xc5,
			0x0a, 0x9a, 0x33, 0x54, 0xc2, 0x23, 0x28, 0x77,
			0x8e, 0xa7, 0x31, 0xf3, 0x0c, 0xb6, 0x4a, 0xe9,
			0x29, 0xf2, 0x1b, 0x90, 0xf5, 0xb0, 0xa4, 0xf3,
			0x42, 0x70, 0x93, 0xa0, 0xd0, 0x11, 0x37, 0xc6
		};
		unsigned char exp[22] = {
			0x0d, 0x4b, 0xb3, 0x81, 0x4c, 0x1d, 0x2d, 0x79
		};
		unsigned char pf_p[128] = {
			0xf1, 0xb9, 0x3a, 0x32, 0x70, 0xd8, 0xfd, 0x3e,
			0xc8, 0x7c, 0x1f, 0xfd, 0x76, 0xfc, 0xc1, 0x90,
			0xda, 0x4d, 0x83, 0xd6, 0x64, 0xd8, 0x06, 0x9a,
			0x2b, 0x7b, 0x47, 0x85, 0x8a, 0x95, 0xd3, 0xbe,
			0x32, 0x97, 0x15, 0x4a, 0xfe, 0x0d, 0x75, 0xe5,
			0x29, 0xb4, 0x63, 0x77, 0xec, 0xdc, 0x40, 0xba,
			0x44, 0x3d, 0x04, 0x21, 0x19, 0xb0, 0xb2, 0xd5,
			0xa1, 0xd3, 0xff, 0x1a, 0x57, 0x5f, 0xe8, 0xa3,
			0xf1, 0xb9, 0x3a, 0x32, 0x70, 0xd8, 0xfd, 0x3e,
			0xc8, 0x7c, 0x1f, 0xfd, 0x76, 0xfc, 0xc1, 0x90,
			0xda, 0x4d, 0x83, 0xd6, 0x64, 0xd8, 0x06, 0x9a,
			0x2b, 0x7b, 0x47, 0x85, 0x8a, 0x95, 0xd3, 0xbe,
			0x32, 0x97, 0x15, 0x4a, 0xfe, 0x0d, 0x75, 0xe5,
			0x29, 0xb4, 0x63, 0x77, 0xec, 0xdc, 0x40, 0xba,
			0x44, 0x3d, 0x04, 0x21, 0x19, 0xb0, 0xb2, 0xd5,
			0xa1, 0xd3, 0xff, 0x1a, 0x57, 0x5f, 0xe8, 0xa3
		};
		unsigned char pf_q[128] = {
			0xcf, 0xf9, 0x4f, 0xfd, 0x05, 0x5d, 0xb4, 0x6a,
			0xa9, 0xad, 0x6a, 0x76, 0x2c, 0x51, 0xa8, 0x89,
			0x5a, 0xd9, 0x87, 0x78, 0x59, 0x10, 0x46, 0xe7,
			0x07, 0x9a, 0x1b, 0xd8, 0x77, 0xf8, 0xa2, 0x04,
			0xca, 0xe5, 0x94, 0xff, 0xe3, 0x5d, 0xe5, 0x3f,
			0x32, 0x10, 0xee, 0xa4, 0x8d, 0x44, 0x5e, 0xdd,
			0x12, 0xce, 0xd5, 0x77, 0xc2, 0x06, 0x83, 0xae,
			0x5e, 0x5f, 0xc4, 0xde, 0x1b, 0x22, 0x1f, 0xa7,
			0xcf, 0xf9, 0x4f, 0xfd, 0x05, 0x5d, 0xb4, 0x6a,
			0xa9, 0xad, 0x6a, 0x76, 0x2c, 0x51, 0xa8, 0x89,
			0x5a, 0xd9, 0x87, 0x78, 0x59, 0x10, 0x46, 0xe7,
			0x07, 0x9a, 0x1b, 0xd8, 0x77, 0xf8, 0xa2, 0x04,
			0xca, 0xe5, 0x94, 0xff, 0xe3, 0x5d, 0xe5, 0x3f,
			0x32, 0x10, 0xee, 0xa4, 0x8d, 0x44, 0x5e, 0xdd,
			0x12, 0xce, 0xd5, 0x77, 0xc2, 0x06, 0x83, 0xae,
			0x5e, 0x5f, 0xc4, 0xde, 0x1b, 0x22, 0x1f, 0xa7
		};
		unsigned char exp_p[128] = {
			0x04, 0xe7, 0xcf, 0x68, 0x8a, 0xa5, 0xbc, 0xad,
			0xf3, 0x7f, 0xa1, 0x5e, 0x91, 0x75, 0x9b, 0xb0,
			0x06, 0xde, 0x1f, 0xd8, 0xcf, 0xff, 0x1a, 0x53,
			0x32, 0xa2, 0xb3, 0xd6, 0xdf, 0xf3, 0x1e, 0x72,
			0xf3, 0xaf, 0xe1, 0x3c, 0xbe, 0x5f, 0x23, 0x8f,
			0x5d, 0x03, 0x4e, 0x29, 0x76, 0xe3, 0x19, 0x65,
			0x2e, 0x51, 0x56, 0xae, 0x1d, 0x49, 0x5a, 0xb7,
			0xbf, 0x2b, 0x00, 0x38, 0x56, 0xa1, 0x99, 0xa5,
			0x04, 0xe7, 0xcf, 0x68, 0x8a, 0xa5, 0xbc, 0xad,
			0xf3, 0x7f, 0xa1, 0x5e, 0x91, 0x75, 0x9b, 0xb0,
			0x06, 0xde, 0x1f, 0xd8, 0xcf, 0xff, 0x1a, 0x53,
			0x32, 0xa2, 0xb3, 0xd6, 0xdf, 0xf3, 0x1e, 0x72,
			0xf3, 0xaf, 0xe1, 0x3c, 0xbe, 0x5f, 0x23, 0x8f,
			0x5d, 0x03, 0x4e, 0x29, 0x76, 0xe3, 0x19, 0x65,
			0x2e, 0x51, 0x56, 0xae, 0x1d, 0x49, 0x5a, 0xb7,
			0xbf, 0x2b, 0x00, 0x38, 0x56, 0xa1, 0x99, 0xa5
		};
		unsigned char exp_q[128] = {
			0x9a, 0xf8, 0xd9, 0x4c, 0xde, 0x69, 0xc3, 0xdd,
			0xd3, 0x50, 0x20, 0xcb, 0xac, 0x1c, 0xb1, 0x2c,
			0xa0, 0xe1, 0x05, 0x5c, 0x7d, 0x69, 0x6e, 0x9c,
			0x0b, 0x03, 0x20, 0x0a, 0xbe, 0xe3, 0x2b, 0xbf,
			0xcc, 0x7d, 0x24, 0xf9, 0x44, 0xb0, 0x9b, 0xf9,
			0xea, 0x51, 0xc9, 0xb2, 0x1e, 0x7e, 0x3a, 0xfe,
			0x1b, 0x5c, 0xba, 0x9e, 0xc1, 0x9a, 0xdf, 0x16,
			0xd8, 0xc6, 0x1e, 0x49, 0xaf, 0x08, 0x4f, 0x73,
			0x9a, 0xf8, 0xd9, 0x4c, 0xde, 0x69, 0xc3, 0xdd,
			0xd3, 0x50, 0x20, 0xcb, 0xac, 0x1c, 0xb1, 0x2c,
			0xa0, 0xe1, 0x05, 0x5c, 0x7d, 0x69, 0x6e, 0x9c,
			0x0b, 0x03, 0x20, 0x0a, 0xbe, 0xe3, 0x2b, 0xbf,
			0xcc, 0x7d, 0x24, 0xf9, 0x44, 0xb0, 0x9b, 0xf9,
			0xea, 0x51, 0xc9, 0xb2, 0x1e, 0x7e, 0x3a, 0xfe,
			0x1b, 0x5c, 0xba, 0x9e, 0xc1, 0x9a, 0xdf, 0x16,
			0xd8, 0xc6, 0x1e, 0x49, 0xaf, 0x08, 0x4f, 0x73
		};
		unsigned char q_inv[128] = {
			0x96, 0x92, 0xf2, 0x3a, 0xd0, 0x61, 0xac, 0xa8,
			0xd9, 0xc7, 0x49, 0x18, 0xc6, 0x71, 0x8d, 0x3c,
			0xfa, 0xcf, 0xb1, 0x35, 0xf0, 0xa5, 0x4f, 0xd8,
			0x72, 0x9a, 0x57, 0x2e, 0xde, 0xe7, 0xfc, 0x97,
			0x79, 0x24, 0x23, 0x87, 0x66, 0x8b, 0x0b, 0x30,
			0x02, 0xc6, 0x81, 0x97, 0x82, 0xa0, 0x14, 0xdb,
			0x1d, 0x0b, 0xe5, 0xf6, 0x69, 0xe9, 0xce, 0x5e,
			0x05, 0x68, 0x33, 0x6f, 0x29, 0x1c, 0x11, 0xff,
			0x96, 0x92, 0xf2, 0x3a, 0xd0, 0x61, 0xac, 0xa8,
			0xd9, 0xc7, 0x49, 0x18, 0xc6, 0x71, 0x8d, 0x3c,
			0xfa, 0xcf, 0xb1, 0x35, 0xf0, 0xa5, 0x4f, 0xd8,
			0x72, 0x9a, 0x57, 0x2e, 0xde, 0xe7, 0xfc, 0x97,
			0x79, 0x24, 0x23, 0x87, 0x66, 0x8b, 0x0b, 0x30,
			0x02, 0xc6, 0x81, 0x97, 0x82, 0xa0, 0x14, 0xdb,
			0x1d, 0x0b, 0xe5, 0xf6, 0x69, 0xe9, 0xce, 0x5e,
			0x05, 0x68, 0x33, 0x6f, 0x29, 0x1c, 0x11, 0xff
		};
		/*InPut Order: q,dq,p,dp,qinverse. */
		if (bufferLen > (modlength - 11)) {
			printf
				("Buffer length should not be more than modlength-11(modlength=%d)\n",
				modlength);
			exit (0);
		}
		t1 = apiTimeMS ();

#ifndef CAVIUM_MULTICARD_API

		for (i = 0; i < MAX_PENDING; i++) {
			pendingList[i].outlen = 0;
			pendingList[i].status = 0xff;

			if (which_operation == RSA_CRT) {
				retVal = Csp1Pkcs1v15CrtEnc (CAVIUM_NON_BLOCKING,
					(RsaBlockType) block_type,
					(Uint16) modlength,
					(Uint16) bufferLen,
					(Uint8 *) pf_p,
					(Uint8 *) pf_q,
					(Uint8 *) exp_p,
					(Uint8 *) exp_q,
					(Uint8 *) q_inv,
					(Uint8 *) buffer,
					(Uint8 *) buffer, &pendingList[i].reqid);
			}					//which RSA_CRT operation done
			else if (which_operation == RSA_NOCRT) {
				retVal = Csp1Pkcs1v15Enc (CAVIUM_NON_BLOCKING,
					(RsaBlockType) block_type,
					(Uint16) modlength,
					(Uint16) explength,
					(Uint16) bufferLen,
					(Uint8 *) mod,
					(Uint8 *) exp,
					(Uint8 *) buffer,
					(Uint8 *) buffer, &pendingList[i].reqid);
			}					//which RSA_NOCRT operation done
			else if (which_operation == MODEXP) {
				retVal = Csp1Me (CAVIUM_NON_BLOCKING,
					(Uint16) modlength,
					(Uint16) explength,
					(Uint16) bufferLen,
					(Uint8 *) mod,
					(Uint8 *) exp,
					(Uint8 *) buffer,
					(Uint8 *) buffer, &pendingList[i].reqid);
			}					//which RSA_NOCRT operation done

			if (retVal != EAGAIN) {
				printf
					("[%d] Csp1Encrypt : error sending encrypt request (error 0x%x).\n",
					i, retVal);

				/* now cleanup all the pending rrequests */
				count = 0;
				while (moretogo) {
					sleep (1);
					moretogo = 0;
					for (j = 0; j < i; j++) {
						pendingList[j].status =
							Csp1CheckForCompletion (pendingList[j].reqid);
						if (pendingList[j].status != 0x0)
							moretogo = 1;
					}

					if (count > 20)
						break;
				}
				return (-1);
			}
			pendingList[i].status = 1;
		}

		pending_count = MAX_PENDING;
		hit_count = miss_count = 0;

		int times = 0;
		while (1) {
			if ((times / 500)) {
				times -= 500;
				t2 = apiTimeMS ();
				if ((t2 - t1) >= testTime * 1000) {
					goto cleanup;
				}
			}

			for (i = 0; i < MAX_PENDING; i = i + MAX_TO_POLL) {
				hit = 1;
				for (j = 0; j < MAX_TO_POLL; j++) {
					if (pendingList[j + i].status == 0) {
						hit = 0;
						break;
					}
				}
				if (hit) {
					hit_count++;
					for (j = 0; j < MAX_TO_POLL; j++) {
						pollBuffer[j].request_id =
							pendingList[j + i].reqid;
						pollBuffer[j].status = 1;
					}

					ret = Csp1GetAllResults (pollBuffer,
						MAX_TO_POLL * sizeof (Csp1RequestStatusBuffer),
						&resCount);

					for (j = 0; j < MAX_TO_POLL; j++) {
						if (pollBuffer[j].status == 0) {
							count++;
							times++;
							/* send the request again */
							if (which_operation == RSA_CRT) {
								retVal =
									Csp1Pkcs1v15CrtEnc
									(CAVIUM_NON_BLOCKING,
									(RsaBlockType) block_type,
									(Uint16) modlength, (Uint16) bufferLen,
									(Uint8 *) pf_p, (Uint8 *) pf_q,
									(Uint8 *) exp_p, (Uint8 *) exp_q,
									(Uint8 *) q_inv, (Uint8 *) buffer,
									(Uint8 *) buffer,
									&pendingList[j + i].reqid);
							} else if (which_operation == RSA_NOCRT) {
								retVal =
									Csp1Pkcs1v15Enc (CAVIUM_NON_BLOCKING,
									(RsaBlockType) block_type,
									(Uint16) modlength, (Uint16) explength,
									(Uint16) bufferLen, (Uint8 *) mod,
									(Uint8 *) exp, (Uint8 *) buffer,
									(Uint8 *) buffer,
									&pendingList[j + i].reqid);
							} else if (which_operation == MODEXP) {
								retVal = Csp1Me (CAVIUM_NON_BLOCKING,
									(Uint16) modlength,
									(Uint16) explength,
									(Uint16) bufferLen,
									(Uint8 *) mod,
									(Uint8 *) exp,
									(Uint8 *) buffer,
									(Uint8 *) buffer,
									&pendingList[j + i].reqid);
							}

							if (retVal != EAGAIN) {
								printf
									("Csp1Encrypt : error sending request.\n");
								pendingList[j + i].status = 0;
								pending_count--;
								goto cleanup;
							}

							pendingList[j + i].status = 1;
						}

						else if (pollBuffer[j].status != ERR_REQ_PENDING) {
							pendingList[j + i].status = 0;
							pending_count--;
							printf
								("Request %d failed (error code 0x%X)\n",
								pendingList[j + i].reqid,
								pollBuffer[j].status);
							printf ("Success Count = %d\n", count);
							printf ("pending count = %d\n", pending_count);
							goto cleanup;
						}
					}			/* for j */
				} /* if all pending */
				else {
					miss_count++;
					for (j = 0; j < MAX_TO_POLL; j++) {
						if (pendingList[j + i].status) {
							pollBuffer[0].request_id =
								pendingList[j + i].reqid;
							pollBuffer[0].status = 1;
							ret = Csp1GetAllResults (pollBuffer,
								sizeof (Csp1RequestStatusBuffer),
								&resCount);
							if (pollBuffer[0].status == 0) {
								count++;

								if (which_operation == RSA_CRT) {
									retVal =
										Csp1Pkcs1v15CrtEnc
										(CAVIUM_NON_BLOCKING,
										(RsaBlockType) block_type,
										(Uint16) modlength,
										(Uint16) bufferLen, (Uint8 *) pf_p,
										(Uint8 *) pf_q, (Uint8 *) exp_p,
										(Uint8 *) exp_q, (Uint8 *) q_inv,
										(Uint8 *) buffer, (Uint8 *) buffer,
										&pendingList[j + i].reqid);
								} else if (which_operation == RSA_NOCRT) {
									retVal =
										Csp1Pkcs1v15Enc
										(CAVIUM_NON_BLOCKING,
										(RsaBlockType) block_type,
										(Uint16) modlength,
										(Uint16) explength,
										(Uint16) bufferLen, (Uint8 *) mod,
										(Uint8 *) exp, (Uint8 *) buffer,
										(Uint8 *) buffer,
										&pendingList[j + i].reqid);
								} else if (which_operation == MODEXP) {
									retVal = Csp1Me (CAVIUM_NON_BLOCKING,
										(Uint16) modlength,
										(Uint16) explength,
										(Uint16) bufferLen,
										(Uint8 *) mod,
										(Uint8 *) exp,
										(Uint8 *) buffer,
										(Uint8 *) buffer,
										&pendingList[j + i].reqid);
								}	//which RSA_NOCRT operation done

								if (retVal != EAGAIN) {
									printf
										("Csp1Encrypt : error sending request.\n");
									pendingList[j + i].status = 0;
									pending_count--;
									goto cleanup;
								}
							} else if (pollBuffer[0].status !=
								ERR_REQ_PENDING) {
								pendingList[j + i].status = 0;
								pending_count--;
								printf
									("Request %d failed (error code 0x%X)\n",
									pendingList[j + i].reqid,
									pollBuffer[0].status);
								printf ("Success Count = %d\n", count);
								printf ("pending count = %d\n",
									pending_count);
								goto cleanup;
							}
						}
					}
				}
			}
		}
#else

		for (k = 0; k < device_count; k++) {
			for (i = 0; i < MAX_PENDING; i++) {
				pendingList[(k * MAX_PENDING) + i].outlen = 0;
				pendingList[(k * MAX_PENDING) + i].status = 0xff;
				if (which_operation == RSA_CRT) {
					retVal = Csp1Pkcs1v15CrtEnc (CAVIUM_NON_BLOCKING,
						(RsaBlockType) block_type,
						(Uint16) modlength,
						(Uint16) bufferLen,
						(Uint8 *) pf_p,
						(Uint8 *) pf_q,
						(Uint8 *) exp_p,
						(Uint8 *) exp_q,
						(Uint8 *) q_inv,
						(Uint8 *) buffer,
						(Uint8 *) buffer,
						&pendingList[(k * MAX_PENDING) + i].reqid, k);
				}				//which RSA_CRT operation done
				else if (which_operation == RSA_NOCRT) {
					retVal = Csp1Pkcs1v15Enc (CAVIUM_NON_BLOCKING,
						(RsaBlockType) block_type,
						(Uint16) modlength,
						(Uint16) explength,
						(Uint16) bufferLen,
						(Uint8 *) mod,
						(Uint8 *) exp,
						(Uint8 *) buffer,
						(Uint8 *) buffer,
						&pendingList[(k * MAX_PENDING) + i].reqid, k);
				}				//which RSA_NOCRT operation done
				else if (which_operation == MODEXP) {
					retVal = Csp1Me (CAVIUM_NON_BLOCKING,
						(Uint16) modlength,
						(Uint16) explength,
						(Uint16) bufferLen,
						(Uint8 *) mod,
						(Uint8 *) exp,
						(Uint8 *) buffer,
						(Uint8 *) buffer,
						&pendingList[(k * MAX_PENDING) + i].reqid, k);
				}				//which RSA_NOCRT operation done


				if (retVal != EAGAIN) {
					printf
						("[%d] Csp1Encrypt : error sending encrypt request (error 0x%x).\n",
						i, retVal);
					/* now cleanup all the pending rrequests */
					count = 0;
					while (moretogo) {
						moretogo = 0;
						for (j = 0; j < i; j++) {
							pendingList[k * MAX_PENDING + j].status =
								Csp1CheckForCompletion (pendingList[k *
									MAX_PENDING + j].reqid, k);
							if (pendingList[k * MAX_PENDING + j].status !=
								0x0)
								moretogo = 1;
						}

						if (count > 20)
							break;
					}
					return (-1);
				}

				pendingList[k * MAX_PENDING + i].status = 1;

			}					//end of i

		}						//end  for k
		pending_count = MAX_PENDING * device_count;
		hit_count = miss_count = 0;

		int times = 0;
		while (1) {
			if ((times / 500)) {
				times -= 500;
				t2 = apiTimeMS ();
				if ((t2 - t1) >= testTime * 1000) {
					goto cleanup;
				}
			}
			//here needs a for loop for k=devicecount
			for (k = 0; k < device_count; k++) {
				for (j = 0; j < MAX_PENDING; j += MAX_TO_POLL) {

					for (i = 0; i < MAX_TO_POLL; i++) {
						hit = 1;
						if (pendingList[(k * MAX_PENDING) + j +
								i].status == 0) {
							hit = 0;
							break;
						}
					}
					if (hit) {
						hit_count++;
						for (i = 0; i < MAX_TO_POLL; i++) {
							pollBuffer[i].request_id =
								pendingList[(k * MAX_PENDING) + j +
								i].reqid;
							pollBuffer[i].status = 1;
						}
						ret = Csp1GetAllResults (pollBuffer,
							MAX_TO_POLL * sizeof (Csp1RequestStatusBuffer),
							&resCount, k);
						if (ret) {
							printf ("BAD ERROR j=%d---i=%d\n", i, j);
						}



						for (i = 0; i < MAX_TO_POLL; i++) {
							if (pollBuffer[i].status == 0) {
								count++;
								times++;
								if (which_operation == RSA_CRT) {
									retVal =
										Csp1Pkcs1v15CrtEnc
										(CAVIUM_NON_BLOCKING,
										(RsaBlockType) block_type,
										(Uint16) modlength,
										(Uint16) bufferLen, (Uint8 *) pf_p,
										(Uint8 *) pf_q, (Uint8 *) exp_p,
										(Uint8 *) exp_q, (Uint8 *) q_inv,
										(Uint8 *) buffer, (Uint8 *) buffer,
										&pendingList[(k * MAX_PENDING) +
											i + j].reqid, k);
								}	//which RSA_CRT operation done
								else if (which_operation == RSA_NOCRT) {
									retVal =
										Csp1Pkcs1v15Enc
										(CAVIUM_NON_BLOCKING,
										(RsaBlockType) block_type,
										(Uint16) modlength,
										(Uint16) explength,
										(Uint16) bufferLen, (Uint8 *) mod,
										(Uint8 *) exp, (Uint8 *) buffer,
										(Uint8 *) buffer,
										&pendingList[(k * MAX_PENDING) +
											i + j].reqid, k);
								}	//which RSA_NOCRT operation done
								else if (which_operation == MODEXP) {
									retVal = Csp1Me (CAVIUM_NON_BLOCKING,
										(Uint16) modlength,
										(Uint16) explength,
										(Uint16) bufferLen,
										(Uint8 *) mod,
										(Uint8 *) exp,
										(Uint8 *) buffer,
										(Uint8 *) buffer,
										&pendingList[(k * MAX_PENDING) +
											i + j].reqid, k);
								}	//which RSA_NOCRT operation done


								if (retVal != EAGAIN) {
									printf
										("Hit Csp1Encrypt : error sending request.\n");
									pendingList[(k * MAX_PENDING) + i +
										j].status = 0;
									pending_count--;
									goto cleanup;
								}

								pendingList[(k * MAX_PENDING) + i +
									j].status = 1;
							}

							else if (((pollBuffer[(k * MAX_TO_POLL) +
											j].status) =
									!ERR_REQ_PENDING)) {
								pendingList[(k * MAX_TO_POLL) + i +
									j].status = 0;
								pending_count--;
								printf
									("hit Request %d failed (error code 0x%X) at j=%d\n",
									pendingList[(k * MAX_TO_POLL) + i +
										j].reqid,
									pollBuffer[(k * MAX_TO_POLL) +
										i].status, j);
								printf ("hit Success Count = %d\n", count);
								printf ("hit pending count = %d\n",
									pending_count);
								goto cleanup;
							}
						}		/* for j */
					} else {
						miss_count++;
						printf ("/n Miss\n");
						for (j = 0; j < MAX_TO_POLL; j++) {
							if (pendingList[(k * MAX_TO_POLL) + i +
									j].status) {
								pollBuffer[0].request_id =
									pendingList[(k * MAX_TO_POLL) + j +
									i].reqid;
								ret =
									Csp1GetAllResults (pollBuffer,
									sizeof (Csp1RequestStatusBuffer),
									&resCount, k);
								if (pollBuffer[j].status == 0) {
									count++;
									if (which_operation == RSA_CRT) {
										retVal =
											Csp1Pkcs1v15CrtEnc
											(CAVIUM_NON_BLOCKING,
											(RsaBlockType) block_type,
											(Uint16) modlength,
											(Uint16) bufferLen,
											(Uint8 *) pf_p, (Uint8 *) pf_q,
											(Uint8 *) exp_p,
											(Uint8 *) exp_q,
											(Uint8 *) q_inv,
											(Uint8 *) buffer,
											(Uint8 *) buffer,
											&pendingList[(k *
													MAX_PENDING) + i +
												j].reqid, k);
									}	//which RSA_CRT operation done
									else if (which_operation == RSA_NOCRT) {
										retVal =
											Csp1Pkcs1v15Enc
											(CAVIUM_NON_BLOCKING,
											(RsaBlockType) block_type,
											(Uint16) modlength,
											(Uint16) explength,
											(Uint16) bufferLen,
											(Uint8 *) mod, (Uint8 *) exp,
											(Uint8 *) buffer,
											(Uint8 *) buffer,
											&pendingList[(k *
													MAX_PENDING) + i +
												j].reqid, k);
									}	//which RSA_NOCRT operation done
									else if (which_operation == MODEXP) {
										retVal =
											Csp1Me (CAVIUM_NON_BLOCKING,
											(Uint16) modlength,
											(Uint16) explength,
											(Uint16) bufferLen,
											(Uint8 *) mod, (Uint8 *) exp,
											(Uint8 *) buffer,
											(Uint8 *) buffer,
											&pendingList[(k *
													MAX_PENDING) + i +
												j].reqid, k);
									}	//which RSA_NOCRT operation done

									if (retVal != EAGAIN) {
										printf
											("Miss Csp1Encrypt : error sending request.\n");
										pendingList[(k * MAX_TO_POLL) + j +
											i].status = 0;
										pending_count--;
										goto cleanup;
									}
								} else if (pollBuffer[0].status !=
									ERR_REQ_PENDING) {
									pendingList[(k * MAX_TO_POLL) + j +
										i].status = 0;
									pending_count--;
									printf
										("Miss Request %d failed (error code 0x%X)\n",
										pendingList[(k * MAX_TO_POLL) + i +
											j].reqid,
										pollBuffer[0].status);
									printf ("Miss Success Count = %d\n",
										count);
									printf
										("Miss cleanup pending count = %d\n",
										pending_count);
									goto cleanup;
								}

							}
						}
					}

				}				//max pending loop
			}					//k
		}						//while 1 loop



#endif
		goto cleanup;
	}							//End of Operation flag

	else if (hs_flag) {

		ClientFinishMessageOutput clnt_fin_msg_out;
		ServerFinishMessageOutput srvr_fin_msg_out;
		clnt_fin_msg_out = RETURN_CFM_UNENCRYPTED;
		srvr_fin_msg_out = RETURN_SFM_UNENCRYPTED;
		Uint16 client_pad_length;
		Uint16 server_pad_length;
		DesType des_type;

		des_type = DES3_192;
#ifndef CAVIUM_MULTICARD_API
		Uint64 key_handle;
#else
		Uint64 key_handle[4];
		int device_id;
#endif
		Rc4Type rc4_type = RC4_128;
		MasterSecretReturn master_secret_ret = NOT_RETURNED;
		Uint8 enc_premaster_secret[PKP_CTL_REQ__DAT_MAX_MODEXP] = { 0 };
		Uint8 enc_master_secret[48] = { 0 };	//ReturnMasterSecret
		Uint8 temp[PKP_CTL_REQ__DAT_MAX_MODEXP];
		Uint8 preMasterSecret[PKP_CTL_REQ__DAT_MAX_MODEXP];

		RSA *key_p;
		int data_length;
		Uint8 *handshake = NULL;

		if (isversion == SSL3_VERSION) {
			ssl_version = VER3_0;
		} else if (isversion == TLS1_VERSION) {
			ssl_version = VER_TLS;
		} else {
			ssl_version = VER_TLS;
		}

		if (which_digest == SHA_DIGEST) {
			hash_type = SHA1_TYPE;
		} else {
			hash_type = MD5_TYPE;
		}

		ssl_party = SSL_SERVER;
		message_type = APP_DATA;
		if (modlength < 64 || modlength > 128) {
			printf ("modulus size should be in 64 and 128\n");
			exit (0);
		}

		modlength = ROUNDUP8 (modlength);
		modlength &= ~1;		// make even for CRT, since modlenmin was RAISED to an even number we can't fall below min.
		rsa_key_t = malloc (sizeof (Key_t));

		if (rsa_key_t == NULL) {
			printf
				("SSL Rsaserver Processing: error allocating rsa_key_t memory\n");
		}
#ifdef CAVIUM_MULTICARD_API
		for (device_id = 0; device_id < device_count; device_id++) {
#endif
			if (Csp1AllocKeyMem (HOST_MEM,
#ifndef CAVIUM_MULTICARD_API
					&key_handle
#else
					&key_handle[device_id]
#endif
#ifdef CAVIUM_MULTICARD_API
					, device_id
#endif
				)) {
				printf
					("SSL Rsaserver Processing: error allocating key handle memory\n");
				exit (-1);
			}
#ifdef CAVIUM_MULTICARD_API
		}
#endif
		key_p = RSA_generate_key (modlength * 8 /*bits/byte */ ,
			65537 /*public exponent */ , NULL /*callback */ , NULL);

		if (key_p == NULL) {
			printf ("Error at key_p\n");
			return 0;
		}

		/* generate plain-text pre-master secret */
		data_length = 48;		// pre-master secret is 48 bytes long
		assert (data_length <= (RSA_size (key_p) - 11));

		// should be the same
		assert (modlength == RSA_size (key_p));

		for (i = 0; i < data_length; ++i)
			preMasterSecret[i] = (0x80 + i) /*pkp_rand() */ &0xFF;

		/* encrypt pre-master secret w/block type 2 pkcs */
		RSA_public_encrypt (data_length, preMasterSecret, temp, key_p,
			RSA_PKCS1_PADDING);

		/* convert to integer format?!?! */
		memcpy (enc_premaster_secret, temp, modlength);

		{
			int bnsize;
			unsigned char buffer[512];

			bnsize = BN_bn2bin (key_p->n, buffer);
			memset (rsa_key_t->full.modulus, 0, modlength - bnsize);
			memcpy (rsa_key_t->full.modulus + modlength - bnsize, buffer,
				bnsize);

			bnsize = BN_bn2bin (key_p->d, buffer);
			memset (rsa_key_t->full.exponent, 0, modlength - bnsize);
			memcpy (rsa_key_t->full.exponent + modlength - bnsize, buffer,
				bnsize);

		}

		RSA_free (key_p);
#ifndef CAVIUM_MULTICARD_API
		if (!rsa_store_pkey (rsa_key_t, &key_handle, modlength))
#else
		if (!rsa_store_pkey (rsa_key_t, key_handle, modlength, device_id))
#endif
		{
			printf ("Rsa key store error\n");
		}

		getrandom (clientRandom, PKP_CTL_REQ__DAT_RANDOM);
		getrandom (serverRandom, PKP_CTL_REQ__DAT_RANDOM);

		handshake = malloc (MAX_HANDSHAKE_SIZE + HANDSHAKE_HEADER_LENGTH);
		if (handshake == NULL) {
			printf
				("SSL Rsaserver Processing: error allocating handshake memory\n");
				exit (-1);
		}
		/* generate handshake data */
		getrandom (handshake, data);

		if (handshake == NULL) {
			printf
				("SSL Rsaserver Processing: error allocating handshake memory\n");
		}


		t1 = apiTimeMS ();

#ifndef CAVIUM_MULTICARD_API

		for (i = 0; i < MAX_PENDING; i++) {
			pendingList[i].outlen = 0;
			pendingList[i].status = 0xff;

			if (which_cipher == RC4_CIPHER) {
				retVal = Csp1RsaServerFullRc4 (CAVIUM_NON_BLOCKING,
					ctxHandle,
					&key_handle,
					hash_type,
					ssl_version,
					rc4_type,
					master_secret_ret,
					(Uint16) modlength,
					enc_premaster_secret,
					clientRandom,
					serverRandom,
					(short int) data,
					handshake,
					client_finished,
					server_finished,
					enc_master_secret, &pendingList[i].reqid);
			} else if (which_cipher == AES_CIPHER) {
				retVal = Csp1RsaServerFullAes (CAVIUM_NON_BLOCKING,
					ctxHandle,
					&key_handle,
					hash_type,
					ssl_version,
					aes_type,
					master_secret_ret,
					clnt_fin_msg_out,
					srvr_fin_msg_out,
					client_pad_length,
					server_pad_length,
					modlength,
					enc_premaster_secret,
					clientRandom,
					serverRandom,
					(short int) data,
					handshake,
					client_finished,
					server_finished,
					enc_master_secret, &pendingList[i].reqid);
			} else if (which_cipher == DES3_CIPHER) {
				retVal = Csp1RsaServerFull3Des (CAVIUM_NON_BLOCKING,
					ctxHandle,
					&key_handle,
					hash_type,
					ssl_version,
					des_type,
					master_secret_ret,
					clnt_fin_msg_out,
					srvr_fin_msg_out,
					client_pad_length,
					server_pad_length,
					modlength,
					enc_premaster_secret,
					clientRandom,
					serverRandom,
					(short int) data,
					handshake,
					client_finished,
					server_finished,
					enc_master_secret, &pendingList[i].reqid);
			} else {
				printf ("No support for this cipher\n");
				exit (0);
			}
			if (retVal == ERR_OPERATION_NOT_SUPPORTED) {
				printf ("Error: Operation not supported\n");
				exit (-1);
			}

			if (retVal != EAGAIN) {
				printf
					("[%d] Csp1Encrypt : error sending encrypt request (error 0x%x).\n",
					i, retVal);

				/* now cleanup all the pending rrequests */
				count = 0;
				while (moretogo) {
					sleep (1);
					moretogo = 0;
					for (j = 0; j < i; j++) {
						pendingList[j].status =
							Csp1CheckForCompletion (pendingList[j].reqid);
						if (pendingList[j].status != 0x0)
							moretogo = 1;
					}

					if (count > 20)
						break;
				}
				return (-1);
			}

			pendingList[i].status = 1;
		}

		pending_count = MAX_PENDING;
		hit_count = miss_count = 0;


		int times = 0;
		while (1) {
			if ((times / 500)) {
				times -= 500;
				t2 = apiTimeMS ();
				if ((t2 - t1) >= testTime * 1000) {
					goto cleanup;
				}
			}

			for (i = 0; i < MAX_PENDING; i = i + MAX_TO_POLL) {
				hit = 1;
				for (j = 0; j < MAX_TO_POLL; j++) {
					if (pendingList[j + i].status == 0) {
						hit = 0;
						break;
					}
				}
				if (hit) {
					hit_count++;
					for (j = 0; j < MAX_TO_POLL; j++) {
						pollBuffer[j].request_id =
							pendingList[j + i].reqid;
						pollBuffer[j].status = 1;
					}

					ret = Csp1GetAllResults (pollBuffer,
						MAX_TO_POLL * sizeof (Csp1RequestStatusBuffer),
						&resCount);

					for (j = 0; j < MAX_TO_POLL; j++) {
						if (pollBuffer[j].status == 0) {
							count++;
							times++;
							/* send the request again */
							if (which_cipher == RC4_CIPHER) {
								retVal =
									Csp1RsaServerFullRc4
									(CAVIUM_NON_BLOCKING, ctxHandle,
									&key_handle, hash_type, ssl_version,
									rc4_type, master_secret_ret,
									(Uint16) modlength,
									enc_premaster_secret, clientRandom,
									serverRandom, (short int) data,
									handshake, client_finished,
									server_finished, enc_master_secret,
									&pendingList[j + i].reqid);
							} else if (which_cipher == AES_CIPHER) {
								retVal =
									Csp1RsaServerFullAes
									(CAVIUM_NON_BLOCKING, ctxHandle,
									&key_handle, hash_type, ssl_version,
									aes_type, master_secret_ret,
									clnt_fin_msg_out, srvr_fin_msg_out,
									client_pad_length, server_pad_length,
									modlength, enc_premaster_secret,
									clientRandom, serverRandom,
									(short int) data, handshake,
									client_finished, server_finished,
									enc_master_secret,
									&pendingList[j + i].reqid);
							} else if (which_cipher == DES3_CIPHER) {
								retVal =
									Csp1RsaServerFull3Des
									(CAVIUM_NON_BLOCKING, ctxHandle,
									&key_handle, hash_type, ssl_version,
									des_type, master_secret_ret,
									clnt_fin_msg_out, srvr_fin_msg_out,
									client_pad_length, server_pad_length,
									modlength, enc_premaster_secret,
									clientRandom, serverRandom,
									(short int) data, handshake,
									client_finished, server_finished,
									enc_master_secret,
									&pendingList[j + i].reqid);
							} else {
								printf ("No support for this cipher\n");
								exit (0);
							}

							if (retVal != EAGAIN) {
								printf
									("Csp1Encrypt : error sending request.\n");
								pendingList[j + i].status = 0;
								pending_count--;
								goto cleanup;
							}

							pendingList[j + i].status = 1;
						}

						else if (pollBuffer[j].status != ERR_REQ_PENDING) {
							pendingList[j + i].status = 0;
							pending_count--;
							printf
								("Request %d failed (error code 0x%X)\n",
								pendingList[j + i].reqid,
								pollBuffer[j].status);
							printf ("Success Count = %d\n", count);
							printf ("pending count = %d\n", pending_count);
							goto cleanup;
						}
					}			/* for j */
				} /* if all pending */
				else {
					miss_count++;
					for (j = 0; j < MAX_TO_POLL; j++) {
						if (pendingList[j + i].status) {
							pollBuffer[0].request_id =
								pendingList[j + i].reqid;
							pollBuffer[0].status = 1;
							ret = Csp1GetAllResults (pollBuffer,
								sizeof (Csp1RequestStatusBuffer),
								&resCount);
							if (pollBuffer[0].status == 0) {
								count++;
								if (which_cipher == RC4_CIPHER) {
									retVal =
										Csp1RsaServerFullRc4
										(CAVIUM_NON_BLOCKING, ctxHandle,
										&key_handle, hash_type,
										ssl_version, rc4_type,
										master_secret_ret,
										(Uint16) modlength,
										enc_premaster_secret, clientRandom,
										serverRandom, (short int) data,
										handshake, client_finished,
										server_finished, enc_master_secret,
										&pendingList[j + i].reqid);
								} else if (which_cipher == AES_CIPHER) {
									retVal =
										Csp1RsaServerFullAes
										(CAVIUM_NON_BLOCKING, ctxHandle,
										&key_handle, hash_type,
										ssl_version, aes_type,
										master_secret_ret,
										clnt_fin_msg_out, srvr_fin_msg_out,
										client_pad_length,
										server_pad_length, modlength,
										enc_premaster_secret, clientRandom,
										serverRandom, (short int) data,
										handshake, client_finished,
										server_finished, enc_master_secret,
										&pendingList[j + i].reqid);
								} else if (which_cipher == DES3_CIPHER) {
									retVal =
										Csp1RsaServerFull3Des
										(CAVIUM_NON_BLOCKING, ctxHandle,
										&key_handle, hash_type,
										ssl_version, des_type,
										master_secret_ret,
										clnt_fin_msg_out, srvr_fin_msg_out,
										client_pad_length,
										server_pad_length, modlength,
										enc_premaster_secret, clientRandom,
										serverRandom, (short int) data,
										handshake, client_finished,
										server_finished, enc_master_secret,
										&pendingList[j + i].reqid);
								} else {
									printf
										("No support for this cipher\n");
									exit (0);
								}

								if (retVal != EAGAIN) {
									printf
										("Csp1Encrypt : error sending request.\n");
									pendingList[j + i].status = 0;
									pending_count--;
									goto cleanup;
								}
							} else if (pollBuffer[0].status !=
								ERR_REQ_PENDING) {
								pendingList[j + i].status = 0;
								pending_count--;
								printf
									("Request %d failed (error code 0x%X)\n",
									pendingList[j + i].reqid,
									pollBuffer[0].status);
								printf ("Success Count = %d\n", count);
								printf ("pending count = %d\n",
									pending_count);
								goto cleanup;
							}
						}
					}
				}
			}
		}

#else

		for (k = 0; k < device_count; k++) {
			for (i = 0; i < MAX_PENDING; i++) {
				pendingList[(k * MAX_PENDING) + i].outlen = 0;
				pendingList[(k * MAX_PENDING) + i].status = 0xff;
				if (which_cipher == RC4_CIPHER) {
					retVal = Csp1RsaServerFullRc4 (CAVIUM_NON_BLOCKING,
						ctxHandle[k],
						&key_handle[k],
						hash_type,
						ssl_version,
						rc4_type,
						master_secret_ret,
						(Uint16) modlength,
						enc_premaster_secret,
						clientRandom,
						serverRandom,
						(short int) data,
						handshake,
						client_finished,
						server_finished,
						enc_master_secret,
						&pendingList[(k * MAX_PENDING) + i].reqid, k);
				} else if (which_cipher == AES_CIPHER) {
					retVal = Csp1RsaServerFullAes (CAVIUM_NON_BLOCKING,
						ctxHandle[k],
						&key_handle[k],
						hash_type,
						ssl_version,
						aes_type,
						master_secret_ret,
						clnt_fin_msg_out,
						srvr_fin_msg_out,
						client_pad_length,
						server_pad_length,
						modlength,
						enc_premaster_secret,
						clientRandom,
						serverRandom,
						(short int) data,
						handshake,
						client_finished,
						server_finished,
						enc_master_secret,
						&pendingList[(k * MAX_PENDING) + i].reqid, k);
				} else if (which_cipher == DES3_CIPHER) {
					retVal = Csp1RsaServerFull3Des (CAVIUM_NON_BLOCKING,
						ctxHandle[k],
						&key_handle[k],
						hash_type,
						ssl_version,
						des_type,
						master_secret_ret,
						clnt_fin_msg_out,
						srvr_fin_msg_out,
						client_pad_length,
						server_pad_length,
						modlength,
						enc_premaster_secret,
						clientRandom,
						serverRandom,
						(short int) data,
						handshake,
						client_finished,
						server_finished,
						enc_master_secret,
						&pendingList[(k * MAX_PENDING) + i].reqid, k);
				} else {
					printf ("No support for this cipher\n");
					exit (0);
				}


				if (retVal != EAGAIN) {
					printf
						("[%d] Csp1Encrypt : error sending encrypt request (error 0x%x).\n",
						i, retVal);
					/* now cleanup all the pending rrequests */
					count = 0;
					while (moretogo) {
						moretogo = 0;
						for (j = 0; j < i; j++) {
							pendingList[k * MAX_PENDING + j].status =
								Csp1CheckForCompletion (pendingList[k *
									MAX_PENDING + j].reqid, k);
							if (pendingList[k * MAX_PENDING + j].status !=
								0x0)
								moretogo = 1;
						}

						if (count > 20)
							break;
					}
					return (-1);
				}

				pendingList[k * MAX_PENDING + i].status = 1;

			}					//end of i

		}						//end  for k
		pending_count = MAX_PENDING * device_count;
		hit_count = miss_count = 0;

		int times = 0;
		while (1) {
			if ((times / 500)) {
				times -= 500;
				t2 = apiTimeMS ();
				if ((t2 - t1) >= testTime * 1000) {
					goto cleanup;
				}
			}
			//here needs a for loop for k=devicecount
			for (k = 0; k < device_count; k++) {
				for (j = 0; j < MAX_PENDING; j += MAX_TO_POLL) {

					for (i = 0; i < MAX_TO_POLL; i++) {
						hit = 1;
						if (pendingList[(k * MAX_PENDING) + j +
								i].status == 0) {
							hit = 0;
							break;
						}
					}
					if (hit) {
						hit_count++;
						for (i = 0; i < MAX_TO_POLL; i++) {
							pollBuffer[i].request_id =
								pendingList[(k * MAX_PENDING) + i +
								j].reqid;
							pollBuffer[i].status = 1;
						}
						ret = Csp1GetAllResults (pollBuffer,
							MAX_TO_POLL * sizeof (Csp1RequestStatusBuffer),
							&resCount, k);
						if (ret) {
							printf ("BAD ERROR j=%d---i=%d\n", i, j);
						}



						for (i = 0; i < MAX_TO_POLL; i++) {
							if (pollBuffer[i].status == 0) {
								count++;
								times++;
								if (which_cipher == RC4_CIPHER) {
									retVal =
										Csp1RsaServerFullRc4
										(CAVIUM_NON_BLOCKING, ctxHandle[k],
										&key_handle[k], hash_type,
										ssl_version, rc4_type,
										master_secret_ret,
										(Uint16) modlength,
										enc_premaster_secret, clientRandom,
										serverRandom, (short int) data,
										handshake, client_finished,
										server_finished, enc_master_secret,
										&pendingList[(k * MAX_PENDING) +
											i + j].reqid, k);
								} else if (which_cipher == AES_CIPHER) {
									retVal =
										Csp1RsaServerFullAes
										(CAVIUM_NON_BLOCKING, ctxHandle[k],
										&key_handle[k], hash_type,
										ssl_version, aes_type,
										master_secret_ret,
										clnt_fin_msg_out, srvr_fin_msg_out,
										client_pad_length,
										server_pad_length, modlength,
										enc_premaster_secret, clientRandom,
										serverRandom, (short int) data,
										handshake, client_finished,
										server_finished, enc_master_secret,
										&pendingList[(k * MAX_PENDING) +
											i + j].reqid, k);
								} else if (which_cipher == DES3_CIPHER) {
									retVal =
										Csp1RsaServerFull3Des
										(CAVIUM_NON_BLOCKING, ctxHandle[k],
										&key_handle[k], hash_type,
										ssl_version, des_type,
										master_secret_ret,
										clnt_fin_msg_out, srvr_fin_msg_out,
										client_pad_length,
										server_pad_length, modlength,
										enc_premaster_secret, clientRandom,
										serverRandom, (short int) data,
										handshake, client_finished,
										server_finished, enc_master_secret,
										&pendingList[(k * MAX_PENDING) +
											i + j].reqid, k);
								} else {
									printf
										("No support for this cipher\n");
									exit (0);
								}



								if (retVal != EAGAIN) {
									printf
										("Hit Csp1Encrypt : error sending request.\n");
									pendingList[(k * MAX_PENDING) + i +
										j].status = 0;
									pending_count--;
									goto cleanup;
								}

								pendingList[(k * MAX_PENDING) + i +
									j].status = 1;
							}

							else if (((pollBuffer[(k * MAX_TO_POLL) +
											j].status) =
									!ERR_REQ_PENDING)) {
								pendingList[(k * MAX_TO_POLL) + i +
									j].status = 0;
								pending_count--;
								printf
									("hit Request %d failed (error code 0x%X) at j=%d\n",
									pendingList[(k * MAX_TO_POLL) + i +
										j].reqid,
									pollBuffer[(k * MAX_TO_POLL) +
										i].status, j);
								printf ("hit Success Count = %d\n", count);
								printf ("hit pending count = %d\n",
									pending_count);
								goto cleanup;
							}
						}		/* for j */
					} else {
						miss_count++;
						printf ("/n Miss\n");
						for (j = 0; j < MAX_TO_POLL; j++) {
							if (pendingList[(k * MAX_TO_POLL) + i +
									j].status) {
								pollBuffer[0].request_id =
									pendingList[(k * MAX_TO_POLL) + j +
									i].reqid;
								ret =
									Csp1GetAllResults (pollBuffer,
									sizeof (Csp1RequestStatusBuffer),
									&resCount, k);
								if (pollBuffer[j].status == 0) {
									count++;
									if (which_cipher == RC4_CIPHER) {
										retVal =
											Csp1RsaServerFullRc4
											(CAVIUM_NON_BLOCKING,
											ctxHandle[k], &key_handle[k],
											hash_type, ssl_version,
											rc4_type, master_secret_ret,
											(Uint16) modlength,
											enc_premaster_secret,
											clientRandom, serverRandom,
											(short int) data, handshake,
											client_finished,
											server_finished,
											enc_master_secret,
											&pendingList[(k *
													MAX_PENDING) + i +
												j].reqid, k);
									} else if (which_cipher == AES_CIPHER) {
										retVal =
											Csp1RsaServerFullAes
											(CAVIUM_NON_BLOCKING,
											ctxHandle[k], &key_handle[k],
											hash_type, ssl_version,
											aes_type, master_secret_ret,
											clnt_fin_msg_out,
											srvr_fin_msg_out,
											client_pad_length,
											server_pad_length, modlength,
											enc_premaster_secret,
											clientRandom, serverRandom,
											(short int) data, handshake,
											client_finished,
											server_finished,
											enc_master_secret,
											&pendingList[(k *
													MAX_PENDING) + i +
												j].reqid, k);
									} else if (which_cipher == DES3_CIPHER) {
										retVal =
											Csp1RsaServerFull3Des
											(CAVIUM_NON_BLOCKING,
											ctxHandle[k], &key_handle[k],
											hash_type, ssl_version,
											des_type, master_secret_ret,
											clnt_fin_msg_out,
											srvr_fin_msg_out,
											client_pad_length,
											server_pad_length, modlength,
											enc_premaster_secret,
											clientRandom, serverRandom,
											(short int) data, handshake,
											client_finished,
											server_finished,
											enc_master_secret,
											&pendingList[(k *
													MAX_PENDING) + i +
												j].reqid, k);
									} else {
										printf
											("No support for this cipher\n");
										exit (0);
									}



									if (retVal != EAGAIN) {
										printf
											("Miss Csp1Encrypt : error sending request.\n");
										pendingList[(k * MAX_TO_POLL) + j +
											i].status = 0;
										pending_count--;
										goto cleanup;
									}
								} else if (pollBuffer[0].status !=
									ERR_REQ_PENDING) {
									pendingList[(k * MAX_TO_POLL) + j +
										i].status = 0;
									pending_count--;
									printf
										("Miss Request %d failed (error code 0x%X)\n",
										pendingList[(k * MAX_TO_POLL) + i +
											j].reqid,
										pollBuffer[0].status);
									printf ("Miss Success Count = %d\n",
										count);
									printf
										("Miss cleanup pending count = %d\n",
										pending_count);
									goto cleanup;
								}

							}
						}
					}

				}				//max pending loop
			}					//k
		}						//while 1 loop




#endif
		goto cleanup;

	}							//Handshake flage ends here

  cleanup:
	t2 = apiTimeMS ();
	while (pending_count) {
#ifndef CAVIUM_MULTICARD_API
		for (i = 0; i < MAX_PENDING; i++) {
			if (pendingList[i].status) {
				pollBuffer[0].request_id = pendingList[i].reqid;
				pollBuffer[0].status = 1;
				ret = Csp1GetAllResults (pollBuffer,
					sizeof (Csp1RequestStatusBuffer), &resCount);
				if (pollBuffer[0].status == 0) {
					pending_count--;
					pendingList[i].status = 0;
				} else if (pollBuffer[0].status != ERR_REQ_PENDING) {
					printf (" Request %d failed (error code 0x%X)\n",
						pendingList[i].reqid, pollBuffer[0].status);
					printf ("Success Count = %d\n", count);
					printf ("pending count = %d\n", pending_count);
					break;
				}
			}
		}
#else
		for (k = 0; k < device_count; k++) {
			for (i = 0; i < MAX_PENDING; i++) {
				ret = 0;
				if (pendingList[(k * MAX_PENDING) + i].status) {
					ret = Csp1CheckForCompletion (pendingList[k *
							MAX_PENDING + i].reqid, k);
					if (!ret) {
						pending_count--;
						pendingList[(k * MAX_PENDING) + i].status = 0;
					}
					if (ret > 0) {
						if (ret != 11)
							printf ("ERROR or PENDING %x\n", ret);
					}
			}
		}
	}


#endif
}
time_elapsed = t2 - t1;
	/* Check if the test has run for atleast 1 sec */
if (time_elapsed >= 100) {
	//operations = (int)(count) / ((int) ((int)(time_elapsed) / (int)1000));
	operations = (int) (count * 1000) / ((int) (time_elapsed));
	if (bufferLen < 16000)
		throughput = ((operations * bufferLen * 8) / 1000000);
	else {
		throughput = ((operations * 8 * 1024 * 8) / 1000000);
		throughput *= 2;
	}

	if (crypto_flag || record_flag) {
		printf ("%-25d %-10d", bufflen, operations);
	} else if (operation_flag || hs_flag) {
		printf ("%-30d %-10d\n", modlength, operations);
	}

	return throughput;
} else 
	return (0);


return (0);

}								//end of nbperf function

void
show_options (char *command_name)
{
	printf ("Usage : %s [options]\n"
		"Options:\n"
		"  -h, --help\t  :<Show usage options message>\n"
		"  -c, --cipher\t  :<Name of the cipher to run>(AES,DES3,RC4)\n"
		"  -l, --dlen\t  :<Date length in bytes> Default date length=1024\n"
		"  -d, --digest\t  :<Digest to be used>(MD5,SHA1)\n"
		"  -s, --version\t  :<Version to be used>(tls1,ssl3),Default version=tls1\n"
		"  -p, --operations:<RSA operations>(rsa_crt,rsa_nocrt,modexp)\n"
		"  -n, --handshake :<RSA Handshake operations>(rsaserverfullrc4)\n"
		"  -t, --time :<time to be given>(default time is of 10 sec)\n",
		command_name);

	return;
}


void
getrandom (Uint8 * buf, int len)
{
	int i;
	for (i = 0; i < len; i++)
		buf[i] = i;
}

Uint32
RandRange (Uint32 min, Uint32 max)
{
	Uint32 result;
	result = random ();			//get uniform RV
	result = result % (max - min + 1);	//normalize essentially
	result = min + result;		//add to min
	return (result);
}

int
#ifndef CAVIUM_MULTICARD_API
rsa_store_pkey (Key_t * pkey, Uint64 * key_handle, int modlength)
#else
rsa_store_pkey (Key_t * pkey, Uint64 * key_handle, int modlength,
	int device_id)
#endif
{
	int sizem, sizep, ret = 1;
	unsigned char *mb, *pb, *temp;
	BIGNUM *m, *p;
	BN_CTX *ctx;

	ctx = BN_CTX_new ();
	m = BN_new ();
	p = BN_new ();

	m = BN_bin2bn (pkey->full.modulus, modlength, m);
	p = BN_bin2bn (pkey->full.exponent, modlength, p);

	sizem = BN_num_bytes (m);
	if ((sizem < 8) || (sizem > 4096))
		return 0;
	sizem = ((sizem + 7) / 8) * 8;
	sizep = BN_num_bytes (p);

	mb = alloca (sizem);
	if (mb == NULL)
		return 0;
	memset (mb, 0, sizem);

	pb = alloca (sizem);
	if (pb == NULL)
		return 0;
	memset (pb, 0, sizem);

	temp = alloca (sizem * 2);
	if (temp == NULL)
		return 0;
	memset (temp, 0, sizem * 2);

	BN_bn2bin (m, mb);

	BN_bn2bin (p, pb);

	if (sizep < sizem) {
		leftfill (pb, sizep, temp, sizem);
		memcpy (pb, temp, sizem);
		memset (temp, 0, sizem);
	}
#ifdef MC2
	memcpy (temp, mb, sizem);
	memcpy (temp + sizem, pb, sizem);
#endif
#ifndef CAVIUM_MULTICARD_API
	if (Csp1StoreKey (key_handle, (unsigned short) (sizem * 2), temp, 0))
#else
	for (device_id = 0; device_id < device_count; device_id++)
		if (Csp1StoreKey (&key_handle[device_id],
				(unsigned short) (sizem * 2), temp, 0, device_id))
#endif
		{
			ret = 0;
		}

	memset (temp, 0, sizem * 2);
	BN_CTX_free (ctx);
	BN_free (m);
	BN_free (p);
	return (ret);

}

void
leftfill (unsigned char input[], int length, unsigned char output[],
	int finallength)
{
	int i;
	int j;
	memset (output, 0, finallength);
	j = finallength - 1;
	for (i = length - 1; i >= 0; i--) {
		output[j] = input[i];
		j = j - 1;
	}
}

unsigned long
apiTimeMS (void)
{
	struct timeval m_real1;
	unsigned long temp;

	gettimeofday (&m_real1, 0);
	temp = (m_real1.tv_sec * 1000) + ((m_real1.tv_usec + 999) / 1000);
	return temp;
}
