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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "openssl/bn.h"
#include "openssl/rand.h"
#include "openssl/x509.h"
#include "openssl/err.h"

#include "cavium_sysdep.h"
#include "cavium_common.h"
#include "pots.h"
//#include "defs.h"

extern uint8_t ssl;

extern int pots_modex_devid;

const int num0 = 100; /* number of tests */
const int num1 = 50;  /* additional tests for some functions */
const int num2 = 5;   /* number of tests for slow functions */

int test_mod_exp();
static int results=0;

extern unsigned int AdminCore, EnabledCore, AutoMode;

static const char rnd_seed[] = "string to make the random number generator think it has entropy";

void swap_word_openssl(unsigned char *d, unsigned char *s, int len)
{
  int i,j;
  Uint64  *ps;
  Uint64  *pd;

  j=0;

  ps = (Uint64 *)s;
  pd = (Uint64 *)d;

  for(i=(len>>3)-1; i>=0; i--)
   {
     pd[j] = ps[i];
     j++;      
   }

}

void pkp_leftfill(unsigned char input[], int length, unsigned char output[], int finallength )
{
  int i;
  int j;
  memset(output,0,finallength);
  j = finallength-1;
  for (i=length-1; i>=0; i--) 
  {
    output[j] = input[i];
    j = j-1;
  }
}

int cav_mod_exp(BIGNUM *r, BIGNUM *a, BIGNUM *p, BIGNUM *m)
{
  unsigned char *ab, *pb, *mb, *rb, *temp;
  int sizep,sizea;
  int sizem,osizem;
  Uint32 rid;
  osizem = BN_num_bytes(m);
  int err=0;
  //if( (osizem < 24) || (osizem>256) ) return 0; 
  // MODIFIED MANOJ 01/29/07
  if( (osizem < 24) || (osizem>512) ) goto fail;

  sizem = ((osizem+7)/8)*8;
  sizea = BN_num_bytes(a);
  sizep = BN_num_bytes(p);

  if(sizea < sizem) goto fail;

  mb = alloca(sizem);
  if(mb==NULL)
    goto fail;
  memset(mb,0,sizem);

  ab = alloca(sizem);
  if(ab==NULL)
    goto fail;
  memset(ab,0,sizem);

  pb = alloca(sizem);
  if(pb==NULL)
    goto fail;
  memset(pb,0,sizem);   

  temp = alloca(sizem); 
  if(temp==NULL)
    goto fail;
  memset(temp,0,sizem);

  rb = alloca(sizem); 
  if(rb==NULL)
    goto fail;
  memset(rb,0,sizem);

  BN_bn2bin(a,ab); 

  BN_bn2bin(p,pb); 

  if(sizep < sizem)
   {
    pkp_leftfill(pb,sizep,temp,sizem);
    memcpy(pb,temp,sizem);
    memset(temp,0,sizem); 
   }
  if(sizea < sizem)
   {
    pkp_leftfill(ab,sizea,temp,sizem);
    memcpy(ab,temp,sizem);
    memset(temp,0,sizem); 
   }

  BN_bn2bin(m,mb); 

  if(sizem < osizem)
   {
    pkp_leftfill(mb,osizem,temp,sizem);
    memcpy(mb,temp,sizem);
    memset(temp,0,sizem); 
   }

//#ifndef MC2 && defined (SSL)
//#if defined (SSL) && !defined (MC2)
#ifndef MC2
  if (ssl) {
  swap_word_openssl(temp, ab, sizem);
  memcpy(ab,temp,sizem);
  memset(temp,0,sizem);

  swap_word_openssl(temp, pb, sizem);
  memcpy(pb,temp,sizem);
  memset(temp,0,sizem);

  swap_word_openssl(temp, mb, sizem);
  memcpy(mb,temp,sizem);
  memset(temp,0,sizem);
  }
#endif

#ifdef CAVIUM_MULTICARD_API
   Csp1Initialize(CAVIUM_DIRECT,pots_modex_devid);
#else
   Csp1Initialize(CAVIUM_DIRECT);
#endif


#ifdef MC2

#ifdef CAVIUM_MULTICARD_API
   if (Csp1Me(CAVIUM_BLOCKING,  sizem, sizem, sizem, (Uint8 *)mb, (Uint8 *)pb, (Uint8 *)ab, rb, &rid,pots_modex_devid))
#else
   if (Csp1Me(CAVIUM_BLOCKING,  sizem, sizem, sizem, (Uint8 *)mb, (Uint8 *)pb, (Uint8 *)ab, rb, &rid))
#endif

#else

#ifdef CAVIUM_MULTICARD_API
   if(Csp1Me(CAVIUM_BLOCKING, RESULT_PTR, (Uint64)NULL, sizem, ab, mb, pb, rb, &rid,pots_modex_devid)) 
#else
   if(Csp1Me(CAVIUM_BLOCKING, RESULT_PTR, (Uint64)NULL, sizem, ab, mb, pb, rb, &rid)) 
#endif

#endif
      goto fail;
else
      err=1;
fail:
#ifdef CAVIUM_MULTICARD_API
  Csp1Shutdown(pots_modex_devid);
#else
  Csp1Shutdown();
#endif
  BN_bin2bn(rb,sizem,r); 
  return err;
}

#if 0
int enable_2048_exec_unit(int nExecUnit)
{
   int ret, ExecUnit2;
   PkpConfig dw;


   /* 
    * if the first core is an odd numbered core, 2048 bit
    * operations won't work
    */
   if(nExecUnit % 2)
      return 0;

   ExecUnit2 = nExecUnit + 1;
   if( (nUnits & (1 << ExecUnit2)) == 0)
      return 0;

   dw.RegVal = 0;
   dw.RegOffset = UNIT_ENABLE + bar0base;

   ret = 1 << nExecUnit | 1 << ExecUnit2;
   dw.RegVal = ret | 0x10000000;
   ret = ioctl(file_desc,IOCTL_CSP1_DEBUG_WRITE_CODE, &dw);
   return 1;

}
#endif



/*
 * $Id: mod_ex_utils.c,v 1.9 2009/09/09 15:01:46 aravikumar Exp $
 * $Log: mod_ex_utils.c,v $
 * Revision 1.9  2009/09/09 15:01:46  aravikumar
 * NPLUS macro dependency removed and made it dynamic
 *
 * Revision 1.8  2008/11/26 05:48:47  ysandeep
 * Fixed Bugs
 *
 * Revision 1.7  2008/11/05 06:45:57  ysandeep
 * Added NPLUS support for N1/NLite
 *
 * Revision 1.6  2008/10/31 10:51:29  ysandeep
 * MULTICARD support added for ipsec.
 * nplus_handle removed (NPLUS).
 *
 * Revision 1.5  2008/10/24 08:43:51  ysandeep
 * NPLUS support added
 *
 * Revision 1.4  2008/03/10 10:22:58  kkiran
 *  - Cavium Copyright added.
 *
 * Revision 1.3  2007/09/11 14:09:02  kchunduri
 * --provide option to run POTS on each PX device.
 *
 * Revision 1.2  2007/09/10 10:16:59  kchunduri
 * --Support added to use new multi-card API.
 *
 * Revision 1.1  2007/02/20 23:43:29  panicker
 * * Utilities checked in
 *
 * Revision 1.2  2005/05/21 05:17:31  rkumar
 * Merge with India CVS Head
 *
 * Revision 1.1  2004/04/15 22:40:51  bimran
 * Checkin of the code from India with some cleanups.
 *
 */

