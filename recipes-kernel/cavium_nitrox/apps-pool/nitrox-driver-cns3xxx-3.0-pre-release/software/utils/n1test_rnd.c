/*! file n1test_rnd.c*/
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


	
int main(void)
{
	unsigned char *Output;
	Uint32 request_id;
	int ret;

        Uint32 dev_count = 0;
	Uint8 dev_mask=0;

#ifdef CAVIUM_MULTICARD_API
	if(OpenNitroxDevice(CAVIUM_DIRECT,CAVIUM_DEV_ID)) 
#else
	if(OpenNitroxDevice(CAVIUM_DIRECT))
#endif
 	{
		printf("RND_TEST: Failed to open device file\n");
		return -ENODEV;
	}
        if(Csp1GetDevCnt(&dev_count,&dev_mask))
        {
           printf("Unable to retrieve dev_count \n");
#ifdef CAVIUM_MULTICARD_API
	   Csp1Shutdown(CAVIUM_DEV_ID);
#else
	   Csp1Shutdown();
#endif
	   return 1;
        }
#ifdef CAVIUM_MULTICARD_API
	Csp1Shutdown(CAVIUM_DEV_ID);
#else
	Csp1Shutdown();
#endif

        printf("RND_TEST: devices detected %d \n",dev_count);
        if(dev_count == 0)
        {
	   return 1;
        }

      while(dev_count --)
      {
		
	if(!(dev_mask&(1<<dev_count)))
		continue;

	if(OpenNitroxDevice(CAVIUM_DIRECT,dev_count)) {
		printf("RND_TEST: Failed to open device file\n");
		return -ENODEV;
	}

	printf("starting Random number testi\n");

	Output = malloc(0xFFFF);
	memset(Output, 0, 0xFFFF);
	
#ifdef CAVIUM_MULTICARD_API
	ret = Csp1Random(CAVIUM_BLOCKING, 16000, Output, &request_id,dev_count); 
#else
	ret = Csp1Random(CAVIUM_BLOCKING, 16000, Output, &request_id); 
#endif
	if(ret)
		printf("Failed to get Random Data\n");
	else 
		printf("RND_TEST: Success\n");

	free(Output);
#ifdef CAVIUM_MULTICARD_API
  	Csp1Shutdown(dev_count);
#else
  	Csp1Shutdown();
#endif
      }
  	return 1;
}



