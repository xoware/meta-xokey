/*! file  n1_op.c */

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
 ponsibility to obtain licenses to export, re-export or import the
 * Software.
 *
 * TO THE MAXIMUM EXTENT PERMITTED BY LAW, THE SOFTWARE IS PROVIDED "AS IS" AND
 * WITH ALL FAULTS AND CAVIUM MAKES NO PROMISES, REPRESENTATIONS OR WARRANTIES,
 * EITHER EXPRESS,IMPLIED, STATUTORY,OR OTHERWISE, WITH RESPECT TO THE SOFTWARE, * INCLUDING ITS CONDITION,ITS CONFORMITY TO ANY REPRESENTATION OR DESCRIPTION,
 * OR THE EXISTENCE OF ANY LATENT OR PATENT DEFECTS, AND CAVIUM SPECIFICALLY
 * DISCLAIMS ALL IMPLIED (IF ANY) WARRANTIES OF TITLE, MERCHANTABILITY,
 * NONINFRINGEMENT, FITNESS FOR A PARTICULAR PURPOSE,LACK OF VIRUSES,ACCURACY OR * COMPLETENESS, QUIET ENJOYMENT, QUIET POSSESSION OR CORRESPONDENCE TO
 * DESCRIPTION. THE ENTIRE RISK ARISING OUT OF USE OR PERFORMANCE OF THE
 * SOFTWARE LIES WITH YOU.
 **/




/* Sample program which takes Input Data and Key in arrays
 * and gets the output from N1/NLite/NPX */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "cavium_sysdep.h"
#include "cavium_common.h"
#include "cavium_ioctl.h"

/* This holds the key and data arrays */
/* They are in Input[] and Key[] */
#include "n1op_data.h"

#define  OP_TYPE       CAVIUM_BLOCKING
#define  CONTEXT_TYPE  CONTEXT_SSL


#define  KEY_SIZE      0x140

#define  OPCODE        0x6005
#define  SIZE          0x80
#define  OP_PARAM      0x1ae
#define  DLEN          0x4f7 
#define  RLEN          0x98 
#define  IN_SIZE       DLEN
#define  OUT_SIZE      RLEN
#define  IN_OFFSET     0x0 
#define  OUT_OFFSET    0x0

Uint32 
n1op_do_operation( Uint64  context_handle,
				Uint8   *Input,
				Uint8   *Output);

void
print_data(Uint8 *data, Uint32 size)
{
	int i;

	printf("--Printing %d bytes of data\n" , size);
	for(i = 0; i < size; i++) {
		printf(" %02x, ", data[i]);
		if(!((i+1)%8))
			printf("\n");
	}
	printf("\n");
}


int main(void)
{
	int i;
	Uint8  *Inbuf, *Outbuf, *ptr;
	Uint64 context_handle, KeyHandle;
	Uint32 device = 0;


	/* Open the device. */
    if(OpenNitroxDevice(CAVIUM_DIRECT,0)) {
        printf("SIMOP: Cannot open device file\n");
        return -ENODEV;
    }

	if (Csp1GetDevType(&device)) {
		printf("Unable to retrieve Device Type\n");
		exit(0);
	}
	if (device == NPX_DEVICE)
		printf("Starting Operation with for NitroxPX\n"); 
	else
		printf("Starting Operation with for N1/NLite\n"); 

	printf("Parameters:\n\tOpcode: 0x%x\n\tParam: 0x%x\n\t InputSize: 0x%x\n",
	       OPCODE, OP_PARAM, DLEN);
	printf("\tOutputSize: 0x%x\n", RLEN);

	/* Allocate context memory */
#ifdef CAVIUM_MULTICARD_API
	Csp1AllocContext(CONTEXT_TYPE, &context_handle,0);
#else
	Csp1AllocContext(CONTEXT_TYPE, &context_handle);
#endif

	/* Create a Input buffer. */
	Inbuf = malloc(DLEN);

	/* Create a output buffer. */
	Outbuf = malloc(RLEN);

	/* Alloc Key Memory in Host */
#ifdef CAVIUM_MULTICARD_API
	Csp1AllocKeyMem(HOST_MEM, &KeyHandle,0);
#else
	Csp1AllocKeyMem(HOST_MEM, &KeyHandle);
#endif

	/* Store the key we have in our Key buffer to the Key Memory */
#ifdef CAVIUM_MULTICARD_API
	Csp1StoreKey(&KeyHandle, KEY_SIZE, Key, KEY_MODE,0);
#else
	Csp1StoreKey(&KeyHandle, KEY_SIZE, Key, KEY_MODE);
#endif


	printf("Key Handle is 0x%016lx\n", KeyHandle);
	/* First 8 bytes must be the keyhandle */
	ptr = (Uint8 *)&KeyHandle;
	for(i = 0; i < 8; i++)
		Inbuf[i] = ptr[i];

	for(i = 8; i < DLEN; i++)
		Inbuf[i] = Input[i];

	memset(Outbuf, 0, RLEN);

#if 0
	printf("Inbuf Data Dump:\n");
	print_data(Inbuf, DLEN);
	printf("------------------\n");
#endif

	/* Perform the operation now. */
	n1op_do_operation(context_handle, Inbuf, Outbuf);



#if 0
	printf("Outbuf Data Dump:\n");
	print_data(Outbuf, RLEN);
	printf("------------------\n");
#endif

	free(Outbuf);
	free(Inbuf);

	/* Free the Key Memory. */
#ifdef CAVIUM_MULTICARD_API
	Csp1FreeKeyMem(KeyHandle,0);
#else
	Csp1FreeKeyMem(KeyHandle);
#endif

	/* Free the context. */
#ifdef CAVIUM_MULTICARD_API
	Csp1FreeContext(CONTEXT_SSL, context_handle,0);
#else
	Csp1FreeContext(CONTEXT_SSL, context_handle);
#endif

	/* Close the device. */
#ifdef CAVIUM_MULTICARD_API
	Csp1Shutdown(0);
#else
	Csp1Shutdown();
#endif
	return 0;
}




Uint32 
n1op_do_operation( Uint64  context_handle,
				Uint8   *Input,
				Uint8   *Output)
{
	Csp1OperationBuffer  buffer;
	Uint32               cond_code, ret_val;
	Uint32               request_id; 


	memset(&buffer, 0, sizeof(Csp1OperationBuffer));

	buffer.opcode = OPCODE;
	buffer.size   = SIZE;
    buffer.param  = OP_PARAM;
	buffer.dlen   = DLEN; 
	buffer.rlen   = RLEN;

	buffer.ctx_ptr = context_handle;

	buffer.incnt  = 1;
	buffer.outcnt = 1;

	buffer.inptr[0]     = CAST_TO_X_PTR(Input);
	buffer.insize[0]    = IN_SIZE;
	buffer.inoffset[0]  = IN_OFFSET;
	buffer.inunit[0]    = UNIT_8_BIT;

	buffer.outptr[0]    = CAST_TO_X_PTR(Output);
	buffer.outsize[0]   = OUT_SIZE;
	buffer.outoffset[0] = OUT_OFFSET;
	buffer.outunit[0]   = UNIT_8_BIT;

	buffer.req_type     = OP_TYPE;
	buffer.req_queue    = 0;

	buffer.res_order    = CAVIUM_RESPONSE_ORDERED;
	buffer.dma_mode     = CAVIUM_DIRECT;
	buffer.status       = 0;

#ifdef CAVIUM_MULTICARD_API
	cond_code = ioctl (gpkpdev_hdlr[0], IOCTL_N1_OPERATION_CODE, (ptrlong) & buffer);
#else
	cond_code = ioctl (CSP1_driver_handle, IOCTL_N1_OPERATION_CODE, (ptrlong) & buffer);
#endif

	/* Wonder what to do with this. */
	request_id = buffer.request_id;

	if(cond_code) {
		printf("cond_code: 0x%x\n", cond_code);
		ret_val = cond_code;
	} else {
		printf("buffer.status: 0x%x\n", buffer.status);
		ret_val = buffer.status;/*return OPERATION STATUS: SUCCESS('0')/EAGAIN */
	}
	return ret_val;
}
