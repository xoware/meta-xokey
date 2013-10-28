/*! file n1test_3des.c*/
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
 * EITHER EXPRESS,IMPLIED, STATUTORY,OR OTHERWISE, WITH RESPECT TO THE SOFTWARE, * INCLUDING ITS CONDITION,ITS CONFORMITY TO ANY REPRESENTATION OR DESCRIPTION,
 * OR THE EXISTENCE OF ANY LATENT OR PATENT DEFECTS, AND CAVIUM SPECIFICALLY
 * DISCLAIMS ALL IMPLIED (IF ANY) WARRANTIES OF TITLE, MERCHANTABILITY,
 * NONINFRINGEMENT, FITNESS FOR A PARTICULAR PURPOSE,LACK OF VIRUSES,ACCURACY OR * COMPLETENESS, QUIET ENJOYMENT, QUIET POSSESSION OR CORRESPONDENCE TO
 * DESCRIPTION. THE ENTIRE RISK ARISING OUT OF USE OR PERFORMANCE OF THE
 * SOFTWARE LIES WITH YOU.
 *
 */





#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "cavium_sysdep.h"
#include "cavium_common.h"

#define INPUT_SIZE   1512
	
int main(void)
{
	unsigned char *Input, *Output, *DecryptedOutput, key[24], iv[24];
	unsigned int ret;
	Uint64 context_handle;
	Uint32 request_id;
	int i;
        Uint32 dev_count = 0;
	Uint8  dev_mask=0;
	Uint8  test_set=0; 

#ifdef CAVIUM_MULTICARD_API
	if(OpenNitroxDevice(CAVIUM_DIRECT,CAVIUM_DEV_ID))
#else
	if(OpenNitroxDevice(CAVIUM_DIRECT))
#endif
	 {
		printf("3DES_TEST: Failed to open device file\n");
		return -ENODEV;
	}
        if(Csp1GetDevCnt(&dev_count,&dev_mask))
        {
           printf("Unable to retrieve dev_count \n");
#ifdef CAVIUM_MULTICARD_API
	   Csp1Shutdown(0);
#else
	   Csp1Shutdown();
#endif
	   return 1;
        }

#ifdef CAVIUM_MULTICARD_API
	Csp1Shutdown(0);
#else
	Csp1Shutdown();
#endif

        printf("3DES_TEST: devices detected %d \n",dev_count);
        if(dev_count == 0)
        {
	   return 1;
        }
    
      while(dev_count--)
      {
	
	if(!(dev_mask&(1<<dev_count)))
		continue;

	printf("3DES_TEST: Starting..  \n");
	if(OpenNitroxDevice(CAVIUM_DIRECT,dev_count)) {
		printf("3DES_TEST: Failed to open device file\n");
		return -ENODEV;
	}

#ifdef CAVIUM_MULTICARD_API
	Csp1AllocContext(CONTEXT_SSL, &context_handle,dev_count);
#else
	Csp1AllocContext(CONTEXT_SSL, &context_handle);
#endif

	Input = malloc(0xFFFF);
	Output = malloc(0xFFFF);
	DecryptedOutput = malloc(0xFFFF);

	memset(Input, 0, 0xFFFF);
	memset(Output, 0, 0xFFFF);
	memset(DecryptedOutput, 0, 0xFFFF);

	for(i=0;i<24;i++) {
		key[i]=i;
		iv[i] = i+64;
	}

	for(i=0;i<INPUT_SIZE;i++)
		Input[i]=i;

	printf("3DES_TEST: Encrypting data\n");
	ret = Csp1Encrypt3Des(CAVIUM_BLOCKING,
            			context_handle, 
            			CAVIUM_NO_UPDATE, 
            			INPUT_SIZE, 
            			Input, 
            			Output,
#ifdef MC2
            			&iv[0],
            			key,
#endif
#ifdef CAVIUM_MULTICARD_API
            			&request_id,dev_count
#else
            			&request_id
#endif
                              );
	if(ret) {
		printf("3DES_TEST: Encrypt Failed, Error Code: 0x%x\n", ret);
		goto test_error;
	}


	printf("3DES_TEST: Decrypting data\n");
	ret = Csp1Decrypt3Des(CAVIUM_BLOCKING,
            			context_handle, 
            			CAVIUM_NO_UPDATE, 
            			INPUT_SIZE, 
            			Output, 
            			DecryptedOutput,
#ifdef MC2
            			iv,
            			key,
#endif
#ifdef CAVIUM_MULTICARD_API
            			&request_id,dev_count
#else
            			&request_id
#endif
                              );
	if(ret) {
		printf("3DES_TEST: Decrypt Failed, Error Code: 0x%x\n", ret);
		goto test_error;
	}
			
	printf("3DES_TEST: Comparing decrypted data with original\n");
	ret = memcmp(Input, DecryptedOutput, INPUT_SIZE);
	if(ret) {
		printf("3DES_TEST: Comparison Failed\n");
		goto test_error;
	}

test_error:
	if(!ret)
		printf("3DES_TEST: Success\n");

	free(Input);
	free(Output);
	free(DecryptedOutput);		

#ifdef CAVIUM_MULTICARD_API
	Csp1FreeContext(CONTEXT_SSL, context_handle,dev_count);
	Csp1Shutdown(dev_count);
#else
	Csp1FreeContext(CONTEXT_SSL, context_handle);
	Csp1Shutdown();
#endif
      }
	return 1;
}



