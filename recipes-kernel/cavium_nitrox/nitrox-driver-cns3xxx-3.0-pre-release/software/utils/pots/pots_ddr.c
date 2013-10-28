/*
 * pots_ddr.c:
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


#include "cavium_sysdep.h"
#include "cavium_common.h"
#include "cavium_ioctl.h"
#include "pots.h"

extern uint8_t ssl;

int write_and_check_ddr(pots_sts *pots_stp,Uint64 shim_ctxt, Uint16 len, Uint8 *wbufp);

int pots_ddr(pots_sts *pots_stp)
{

   int i;
   int rc;
   Uint64 shim_ctxt;
   int ret=0;
   int err =-1;

#ifdef CAVIUM_MULTICARD_API
   rc = Csp1Initialize(CAVIUM_DIRECT,pots_stp->dev_id);
   rc = Csp1AllocContext(CONTEXT_SSL, &shim_ctxt,pots_stp->dev_id);
#else 
   rc = Csp1Initialize(CAVIUM_DIRECT);
   rc = Csp1AllocContext(CONTEXT_SSL, &shim_ctxt);
#endif 
   if ( rc ) {
      pots_log(PT_LOG_ERROR, "pots_ddr(): Csp1AllocContext() failed\n");
      goto fail;
   }

#ifdef CAVIUM_MULTICARD_API
   ret=ioctl(pots_stp->pt_dd_fd,IOCTL_N1_GET_STATUS_DDR,pots_stp->dev_id);
#else
   ret=ioctl(pots_stp->pt_dd_fd,IOCTL_N1_GET_STATUS_DDR,0);
#endif
   if(ret==-1){
      printf("DDR is not present in this N1 card\n");
      err = 0;
      goto fail;
   }

   pots_stp->pt_ddr_size = 1024*1024;
   /* test 64 write, then reads */
   rc = write_ddr_64(pots_stp, shim_ctxt);
   if ( rc ) {
      if (ssl) {
#ifdef CAVIUM_MULTICARD_API
         Csp1FreeContext(CONTEXT_SSL, shim_ctxt,pots_stp->dev_id);
#else
         Csp1FreeContext(CONTEXT_SSL, shim_ctxt);
#endif
	  }
      else {
#ifdef CAVIUM_MULTICARD_API
         Csp1FreeContext(CONTEXT_IPSEC, shim_ctxt,pots_stp->dev_id);
#else
         Csp1FreeContext(CONTEXT_IPSEC, shim_ctxt);
#endif
	  }
      pots_log(PT_LOG_ERROR, "pots_ddr(): write_ddr_64() failed\n");
      goto fail;
   }
   pots_log(PT_LOG_ERROR, "pots_ddr(): write_ddr_64() worked\n");

   /* test writting addr's and then reading 'em back */
   rc = write_ddr_addrs(pots_stp, shim_ctxt); 
   if ( rc ) {
      if (ssl) {
#ifdef CAVIUM_MULTICARD_API
         Csp1FreeContext(CONTEXT_SSL, shim_ctxt,pots_stp->dev_id);
#else
         Csp1FreeContext(CONTEXT_SSL, shim_ctxt);
#endif
	  }
      else {
#ifdef CAVIUM_MULTICARD_API
         Csp1FreeContext(CONTEXT_IPSEC, shim_ctxt,pots_stp->dev_id);
#else
         Csp1FreeContext(CONTEXT_IPSEC, shim_ctxt);
#endif
	  }
      pots_log(PT_LOG_ERROR, "pots_ddr(): write_ddr_addrs() failed\n");
      goto fail;
   }
   pots_log(PT_LOG_ERROR, "pots_ddr(): write_ddr_addrs() worked\n");

   /* test writting random addr's and then reading 'em back */
   rc = write_ddr_random(pots_stp, shim_ctxt); 
   if ( rc ) {
      if (ssl) {
#ifdef CAVIUM_MULTICARD_API
         Csp1FreeContext(CONTEXT_SSL, shim_ctxt,pots_stp->dev_id);
#else
         Csp1FreeContext(CONTEXT_SSL, shim_ctxt);
#endif
	  }
      else {
#ifdef CAVIUM_MULTICARD_API
         Csp1FreeContext(CONTEXT_IPSEC, shim_ctxt,pots_stp->dev_id);
#else
         Csp1FreeContext(CONTEXT_IPSEC, shim_ctxt);
#endif
	  }
      pots_log(PT_LOG_ERROR, "pots_ddr(): write_ddr_random() failed\n");
      goto fail;
   }
   pots_log(PT_LOG_ERROR, "pots_ddr(): write_ddr_random() worked\n");
   err = 0;

   // FOR NOW
   // See if can generate an interrupt from
   // sending a bad opcode
   //call_bad_opcode(shim_ctxt);
      if (ssl) {
#ifdef CAVIUM_MULTICARD_API
         Csp1FreeContext(CONTEXT_SSL, shim_ctxt,pots_stp->dev_id);
#else
         Csp1FreeContext(CONTEXT_SSL, shim_ctxt);
#endif
	  }
      else {
#ifdef CAVIUM_MULTICARD_API
         Csp1FreeContext(CONTEXT_IPSEC, shim_ctxt,pots_stp->dev_id);
#else
         Csp1FreeContext(CONTEXT_IPSEC, shim_ctxt);
#endif
	  }
fail:
#ifdef CAVIUM_MULTICARD_API
   Csp1Shutdown(pots_stp->dev_id);
#else
   Csp1Shutdown();
#endif
   return err;

} // end pots_ddr()


int write_ddr_64(pots_sts *pots_stp, Uint64 shim_ctxt)
{

   int i;
   int rc = 0;
   Uint16 len;
   Uint64 *wptr;
   Uint8 wbuf[MAX_MEM];

   memset(wbuf,'\0', MAX_MEM);

   i = 0;
   len = 0;
   wptr = (Uint64 *)&wbuf[0];
   for (i = 0; i < 64; i++) {
      *wptr = 1 << i;

      if ( *wptr > pots_stp->pt_ddr_size ) {
         pots_log(PT_LOG_DEBUG, 
            "write_ddr_64(): %d) we have reached the end of ddr\n", i);
         break;
      }
      pots_log(PT_LOG_DEBUG, 
            "write_ddr_64(): %d) wptr = 0x%0x, *wptr = 0x%0x\n", 
            i, wptr, *wptr);
      wptr++;
      len += 8;
   }

   rc = write_and_check_ddr(pots_stp,shim_ctxt, len, &wbuf[0]);
   if ( rc == -1 ) {
      pots_log(PT_LOG_ERROR, 
            "write_ddr_64(): write_and_check_ddr() failed\n");
      return(-1);
   }
   
   return(0);

} // end write_ddr_64()


int write_ddr_addrs(pots_sts *pots_stp, Uint64 shim_ctxt)
{

   int i;
   int rc;
   Uint16 len;
   Uint64 *wptr;
   Uint64 *rptr;
   Uint64 addr0;
   Uint64 addr1;
   Uint64 addr2;
   Uint8 wbuf[24];
   Uint8 rbuf[24];
   unsigned int dummy=0;

   len = 24;   // in bytes
   wptr = (Uint64 *)&wbuf[0];
   
   // start from addr 8
   for (i = 4; i < 32; i++) {

      addr0 = 1 << i;
      addr1 = addr0 + 8;
      addr2 = addr1 + 8;

      if ( addr0 > pots_stp->pt_ddr_size ) {
         pots_log(PT_LOG_DEBUG, 
               "write_ddr_addr(): we have reached the end of ddr\n");
         break;
      }

      pots_log(PT_LOG_DEBUG, "write_ddr_addrs(): %d) addr = 0x%x\n",
            i, addr0);
      pots_log(PT_LOG_DEBUG, "write_ddr_addrs(): %d) addr = 0x%x\n",
            i, addr1);
      pots_log(PT_LOG_DEBUG, "write_ddr_addrs(): %d) addr = 0x%x\n",
            i, addr2);
            
      *wptr = addr0;
      *(wptr+1) = addr1;
      *(wptr+2) = addr2;

      /* write wbuf to ddr memory */

#ifdef CAVIUM_MULTICARD_API
      rc = Csp1WriteContext(CAVIUM_BLOCKING,shim_ctxt + addr0, len, wbuf,&dummy,pots_stp->dev_id);
#else
      rc = Csp1WriteContext(CAVIUM_BLOCKING,shim_ctxt + addr0, len, wbuf,&dummy);
#endif
      if ( rc ) {
         pots_log(PT_LOG_DEBUG, 
               "write_ddr_addrs(): Csp1WriteContext() failed with rc %x\n", rc);
         return(-1);
      }

      /* read rbuf to ddr memory */
      memset(rbuf, '\0', 24);
#ifdef CAVIUM_MULTICARD_API
      rc = Csp1ReadContext(CAVIUM_BLOCKING, shim_ctxt + addr0, len, rbuf,&dummy,pots_stp->dev_id);
#else
      rc = Csp1ReadContext(CAVIUM_BLOCKING, shim_ctxt + addr0, len, rbuf,&dummy);
#endif
      if ( rc ) {
         pots_log(PT_LOG_ERROR, 
               "write_ddr_addrs(): Csp1ReadContext() failed\n");
         return(-1);
      }

      rptr = (Uint64 *)&rbuf[0];
      if ( memcmp(&rbuf[0], &wbuf[0], 24) != 0 ) {
         pots_log(PT_LOG_ERROR, 
            "write_ddr_addrs(): %d) rbuf 0x%0x and addr2 0x%0x do not match\n",
            i, *rptr, addr2);
         return(-1);
      }
   }

   return(0);

} // end write_ddr_addrs()


int write_ddr_random(pots_sts *pots_stp, Uint64 shim_ctxt)
{

   int i;
   int rc;
   Uint16 len;
   Uint64 *wptr;
   Uint64 *rptr;
   Uint64 addr0;
   Uint8 wbuf[8];
   Uint8 rbuf[8];
   unsigned int dummy=0;

   len = 8;   // in bytes

   // run teste 3 times with random data
   for (i = 0; i < 3; i++) {
      getrandom(wbuf, 8);
      wptr = (Uint64 *)(unsigned long)wbuf;

      addr0 = *wptr % CONTEXT_SIZE;

      pots_log(PT_LOG_DEBUG, "write_ddr_random(): %d) addr = 0x%x\n",
            i, addr0);
            
      if (addr0 % 16) 
         addr0 = (addr0/16)*16;

      *wptr = addr0;

      /* write wbuf to ddr memory */
#ifdef CAVIUM_MULTICARD_API
      rc = Csp1WriteContext(CAVIUM_BLOCKING,shim_ctxt + addr0, len, wbuf,&dummy,pots_stp->dev_id);
#else
      rc = Csp1WriteContext(CAVIUM_BLOCKING,shim_ctxt + addr0, len, wbuf,&dummy);
#endif
      if ( rc ) {
         pots_log(PT_LOG_DEBUG, 
               "write_ddr_random(): Csp1WriteContext() failed\n");
         return(-1);
      }

      /* read rbuf to ddr memory */
      memset(rbuf, '\0', 8);
#ifdef CAVIUM_MULTICARD_API
      rc = Csp1ReadContext(CAVIUM_BLOCKING,shim_ctxt + addr0, len, rbuf,&dummy,pots_stp->dev_id);
#else
      rc = Csp1ReadContext(CAVIUM_BLOCKING,shim_ctxt + addr0, len, rbuf,&dummy);
#endif
      if ( rc ) {
         pots_log(PT_LOG_ERROR, 
               "write_ddr_random(): Csp1ReadContext() failed\n");
         return(-1);
      }

      rptr = (Uint64 *)&rbuf[0];
      if ( memcmp(&rbuf[0], &wbuf[0], 8) != 0 ) {
         pots_log(PT_LOG_ERROR, 
            "write_ddr_random(): %d) rptr 0x%0x and wptr 0x%0x do not match\n",
            i, *rptr, *wptr);
         return(-1);
      }

   } // end for

   return(0);

} // end write_ddr_random()


int write_and_check_ddr(pots_sts *pots_stp, Uint64 shim_ctxt, Uint16 len, Uint8 *wbufp)
{
   int rc = 0;
   int index;
   int ko;
   Uint16 dataleft;
   Uint16 curlen;
   Uint8 rbuf[MAX_MEM];
   unsigned int dummy=0;

   pots_log(PT_LOG_ERROR, 
         "write_and_check_ddr(): will write %d bytes to key mem\n", 
         len);

   memset(rbuf,'\0', MAX_MEM);

   /* do not read/write more than 1k ddr at a time */
   index = 0;
   dataleft = len;
   ko = 0;   
   while ( dataleft > 0 ) {

      if ( dataleft > MAX_ATOMIC_MEM_RW )
         curlen = MAX_ATOMIC_MEM_RW;
      else
         curlen = dataleft;

      pots_log(PT_LOG_ERROR, 
            "write_and_check_ddr(): index = %d, ko = %d (0x%0x)\n",
            index, ko, ko);

      /* write wbuf to key memory */

#ifdef CAVIUM_MULTICARD_API
      rc = Csp1WriteContext(CAVIUM_BLOCKING,shim_ctxt + index, curlen, wbufp + index,&dummy,pots_stp->dev_id);
#else
      rc = Csp1WriteContext(CAVIUM_BLOCKING,shim_ctxt + index, curlen, wbufp + index,&dummy);
#endif
      if ( rc ) {
         pots_log(PT_LOG_ERROR, 
               "write_and_check_ddr(): Csp1WriteContext() failed with error:%x\n",rc);
         return(-1);
      }
      
      /* now read this back */
#ifdef CAVIUM_MULTICARD_API
      rc = Csp1ReadContext(CAVIUM_BLOCKING,shim_ctxt + index, curlen, &rbuf[index] ,&dummy,pots_stp->dev_id);
#else
      rc = Csp1ReadContext(CAVIUM_BLOCKING,shim_ctxt + index, curlen, &rbuf[index] ,&dummy);
#endif
      if ( rc ) {
         pots_log(PT_LOG_ERROR, 
               "write_and_check_ddr(): Csp1ReadContext() failed with error:%x\n",rc);
         return(-1);
      }

      // FOR NOW
      if ( memcmp(wbufp+index, &rbuf[index], curlen) != 0 ) {
         pots_log(PT_LOG_ERROR, 
               "write_and_check_ddr(): rbuf and wbuf do not match for index %d\n",
               index);
         return(-1);
      }
      else {
         pots_log(PT_LOG_ERROR, 
               "write_and_check_ddr(): rbuf and wbuf match for index = %d\n", 
               index);
      }

      index += curlen;
      ko = index/8;
      dataleft -= curlen;


   } // end while 

   /* now compare */
   if ( memcmp(wbufp, &rbuf[0], len) != 0 ) {
      pots_log(PT_LOG_ERROR, 
            "write_and_check_ddr(): rbuf and wbuf do not match\n");
      return(-1);
   }

   return(0);

} // end write_and_check_ddr()


#if 0
int call_bad_opcode(Uint64 shim_ctxt)
{
   int rc;
   Uint8 len;
   Uint8 rbuf[64];

   len = 8;

   /* write wbuf to key memory */
#ifdef CAVIUM_MULTICARD_API
   rc = Csp1ReadContextBAD(shim_ctxt, len, rbuf,pots_stp->dev_id);
#else
   rc = Csp1ReadContextBAD(shim_ctxt, len, rbuf);
#endif
   if ( rc ) {
      pots_log(PT_LOG_ERROR, "call_bad_opcode(): Csp1ReadContextBAD() failed\n");
      return(-1);
   }

   return(0);
}
#endif

/*
 * $Id: pots_ddr.c,v 1.14 2009/09/09 15:01:46 aravikumar Exp $
 * $Log: pots_ddr.c,v $
 * Revision 1.14  2009/09/09 15:01:46  aravikumar
 * NPLUS macro dependency removed and made it dynamic
 *
 * Revision 1.13  2008/12/16 12:04:42  jsrikanth
 * Added Common driver and Multi-Card Changes for FreeBSD
 *
 * Revision 1.12  2008/11/26 10:22:23  ysandeep
 * fixed bug for NPLUS
 *
 * Revision 1.11  2008/11/26 05:48:47  ysandeep
 * Fixed Bugs
 *
 * Revision 1.10  2008/11/21 06:04:34  ysandeep
 * fixed bug for nplus
 *
 * Revision 1.9  2008/11/05 06:45:57  ysandeep
 * Added NPLUS support for N1/NLite
 *
 * Revision 1.8  2008/10/31 10:51:29  ysandeep
 * MULTICARD support added for ipsec.
 * nplus_handle removed (NPLUS).
 *
 * Revision 1.7  2008/10/24 08:43:51  ysandeep
 * NPLUS support added
 *
 * Revision 1.6  2008/07/30 10:43:03  aramesh
 * handled properly for DDR presence in N1.
 *
 * Revision 1.5  2008/07/29 14:55:38  aramesh
 * used IOCTL_N1_GET_DDR_STATUS .
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
 * Revision 1.7  2005/12/07 04:54:35  kanantha
 * updated for 32i and 64 bit compatiability
 *
 * Revision 1.6  2005/11/21 06:03:18  kanantha
 * Modifed wptr initialization with wbuf directly, Initialization with getrandom call gives some wierd behaviour
 *
 * Revision 1.4  2005/05/21 05:17:31  rkumar
 * Merge with India CVS Head
 *
 * Revision 1.3  2004/04/23 21:57:25  bimran
 * Modified Csp1Initialize() call to take care NPLUS mode initiliaztion.
 *
 * Revision 1.2  2004/04/17 01:31:26  bimran
 * Things were not coded correctly to work with MC1 and MC2.
 *
 * Revision 1.1  2004/04/15 22:40:51  bimran
 * Checkin of the code from India with some cleanups.
 *
 */

