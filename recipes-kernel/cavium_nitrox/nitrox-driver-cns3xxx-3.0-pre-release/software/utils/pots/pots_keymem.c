/*
 * pots_keymem.c:
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
#include "pots.h"


int write_and_check_keymem(Uint64 *key_hdlp, Uint16 len, Uint8 *wbufp);
static int dev_id =0;

int pots_keymem(pots_sts *pots_stp)
{

   int i;
   int rc;
   Uint64 key_hdl;
   int err = -1;

   // open dd 
#ifdef CAVIUM_MULTICARD_API
         dev_id = pots_stp->dev_id;
#endif

#ifdef CAVIUM_MULTICARD_API
   rc = Csp1Initialize(CAVIUM_DIRECT,dev_id);
#else
   rc = Csp1Initialize(CAVIUM_DIRECT);
#endif


   if ( rc ) {
      pots_log(PT_LOG_ERROR, "pots_keymem(): Csp1Initialize() failed\n");
      goto fail;
   }
   
   //rc = Csp1AllocKeyMem(OP_MEM_ALLOC_KEY_SRAM_MEM, &key_hdl);
#ifdef CAVIUM_MULTICARD_API
   rc = Csp1AllocKeyMem(INTERNAL_SRAM,&key_hdl,dev_id);
#else
   rc = Csp1AllocKeyMem(INTERNAL_SRAM,&key_hdl);
#endif
   if ( rc == ERR_OPERATION_NOT_SUPPORTED) {
      pots_log(PT_LOG_ERROR, "pots_keymem(): Csp1AllocKeyMem() operation not supported\n");
#ifdef CAVIUM_MULTICARD_API
       Csp1Shutdown(pots_stp->dev_id);
#else
       Csp1Shutdown();
#endif
       return rc;
   }
   else if ( rc ) {
      pots_log(PT_LOG_ERROR, "pots_keymem(): Csp1AllocKeyMem() failed\n");
      goto fail;
   }
   pots_log(PT_LOG_ERROR, "pots_keymem(): key_hdl = %d\n", key_hdl);

   /* test 64 write, then reads */
   rc = write_keymem_64(&key_hdl);
   if ( rc ) {
#ifdef CAVIUM_MULTICARD_API
      Csp1FreeKeyMem(key_hdl,dev_id);
#else
      Csp1FreeKeyMem(key_hdl);
#endif
      pots_log(PT_LOG_ERROR, "pots_keymem(): write_keymem_64() failed\n");
      goto fail; 
   }
   pots_log(PT_LOG_INFO, "pots_keymem(): write_keymem_64() worked\n");

   /* test writing all 0xf's and test */
   rc = write_keymem_all_ones(&key_hdl);
   if ( rc ) {
#ifdef CAVIUM_MULTICARD_API
      Csp1FreeKeyMem(key_hdl,dev_id);
#else
      Csp1FreeKeyMem(key_hdl);
#endif
      pots_log(PT_LOG_ERROR, 
            "pots_keymem(): write_keymem_all_ones() failed\n");
      goto fail; 
   }
   pots_log(PT_LOG_INFO, "pots_keymem(): write_keymem_all_ones() worked\n");

   /* test writing all 0x00 and test */
   rc = write_keymem_all_zeros(&key_hdl);
   if ( rc ) {
#ifdef CAVIUM_MULTICARD_API
      Csp1FreeKeyMem(key_hdl,dev_id);
#else
      Csp1FreeKeyMem(key_hdl);
#endif
      pots_log(PT_LOG_ERROR, 
            "pots_keymem(): write_keymem_all_zeros() failed\n");
      goto fail;      
   }
   pots_log(PT_LOG_INFO, "pots_keymem(): write_keymem_all_zeros() worked\n");
   err = 0;
#ifdef CAVIUM_MULTICARD_API
   Csp1FreeKeyMem(key_hdl,dev_id);
#else
   Csp1FreeKeyMem(key_hdl);
#endif
fail:
#ifdef CAVIUM_MULTICARD_API
   Csp1Shutdown(pots_stp->dev_id);
#else
   Csp1Shutdown();
#endif
   return err;

} // end pots_keymem()


int write_keymem_64(Uint64 *key_hdlp)
{

   int i;
   int rc;
   Uint16 len;
   Uint64 *wptr;
   Uint64 dummy;
   //Uint8 wbuf[MAX_KEYMEM];
   Uint64 wbuf[MAX_KEYMEM/8];
   Uint8 *datap = (Uint8 *)wbuf;
   

   //memset(wbuf,'\0', 8196);

   pots_log(PT_LOG_ERROR, 
         "write_keymem_64(): sizeof(wbuf) = %d\n", sizeof(wbuf));

   pots_log(PT_LOG_ERROR, 
         "write_keymem_64(): sizeof(Uint64) = %d\n", sizeof(Uint64));

   i = 0;
   len = 0;
   wptr = (Uint64 *)&wbuf[0];

   for (i = 0; i < 64; i++) {
      *wptr = 1 << i;
      if ( *wptr > MAX_MEM ) {
         pots_log(PT_LOG_DEBUG, 
            "write_keymem_64(): %d) we have reached the end of keymem\n", i);
         break;
      }
      pots_log(PT_LOG_DEBUG, 
            "write_keymem_64(): %d) wptr = 0x%0x, *wptr = 0x%0x\n", 
            i, wptr, *wptr);
      wptr++;
      len += 8;
   }

   //len = wptr - &wbuf[0];
   //rc = write_and_check_keymem(key_hdlp, len, &wbuf[0]);
   rc = write_and_check_keymem(key_hdlp, len, datap);
   if ( rc == -1 ) {
      pots_log(PT_LOG_ERROR, 
            "write_keymem_64(): write_and_check_keymem() failed\n");
      return(-1);
   }
   
   return(0);

} // end write_keymem_64()


int write_keymem_all_ones(Uint64 *key_hdlp)
{

   int rc;
   Uint16 len;
   Uint8 wbuf[MAX_KEYMEM];
   

   memset(wbuf,0xFF, MAX_KEYMEM);

   len = MAX_KEYMEM;
   rc = write_and_check_keymem(key_hdlp, len, &wbuf[0]);
   if ( rc == -1 ) {
      pots_log(PT_LOG_ERROR, 
            "write_keymem_all_ones(): write_and_check_keymem() failed\n");
      return(-1);
   }
   
   return(0);

} // end write_keymem_all_ones()


int write_keymem_all_zeros(Uint64 *key_hdlp)
{

   int rc;
   Uint16 len;
   Uint8 wbuf[MAX_KEYMEM];
   

   memset(wbuf,0x00, MAX_KEYMEM);

   len = MAX_KEYMEM;
   rc = write_and_check_keymem(key_hdlp, len, &wbuf[0]);
   if ( rc == -1 ) {
      pots_log(PT_LOG_ERROR, 
            "write_keymem_all_zeros(): write_and_check_keymem() failed\n");
      return(-1);
   }
   
   return(0);

} // end write_keymem_all_zeros()



int write_and_check_keymem(Uint64 *key_hdlp, Uint16 len, Uint8 *wbufp)
{
   int rc;
   int index;
   int ko;
   Uint16 dataleft;
   Uint16 curlen;
   Uint8 rbuf[MAX_KEYMEM];
   Uint64 temp_key_hdl;
   Uint64 start_key_hdl;
   Uint32 dummy = 0;



   pots_log(PT_LOG_DEBUG, 
         "write_and_check_keymem(): *key_hdlp = %lx\n", *key_hdlp);

   if ( len <= 0 ) {
      pots_log(PT_LOG_ERROR, 
            "write_and_check_keymem(): len = %d, *key_hdlp = %lx\n",
            len, *key_hdlp);
      pots_log(PT_LOG_ERROR, 
            "write_and_check_keymem(): unable to test key memory\n");
      return(-1);
   }

   pots_log(PT_LOG_DEBUG, 
         "write_and_check_keymem(): will write %d bytes to key mem\n", 
         len);

   start_key_hdl = 0;
   temp_key_hdl = start_key_hdl;

   pots_log(PT_LOG_DEBUG, 
         "write_and_check_keymem(): start_key_hdl = %lx\n", 
         start_key_hdl);

   memset(rbuf,'\0', MAX_KEYMEM);

   /* cannot read/write more than 1k keymem at a time */

   index = 0;
   dataleft = len;
   ko = 0;   
   while ( dataleft > 0 ) {

      if ( dataleft > MAX_ATOMIC_KEYMEM_RW )
         curlen = MAX_ATOMIC_KEYMEM_RW;
      else
         curlen = dataleft;

      pots_log(PT_LOG_DEBUG, 
            "write_and_check_keymem(): index = %d, ko = %d (0x%0x)\n",
            index, ko, ko);

      pots_log(PT_LOG_DEBUG, 
            "write_and_check_keymem(): temp_key_hdl = %lx\n",
            temp_key_hdl);

      /* write wbuf to key memory */
#ifdef CAVIUM_MULTICARD_API
      rc = Csp1WriteEpci(CAVIUM_BLOCKING,&temp_key_hdl, curlen, wbufp + index, &dummy,dev_id);
#else
      rc = Csp1WriteEpci(CAVIUM_BLOCKING,&temp_key_hdl, curlen, wbufp + index, &dummy);
#endif
      if ( rc ) {
         pots_log(PT_LOG_ERROR, 
               "write_and_check_keymem(): Csp1WriteEpci() failed\n");
         return(-1);
      }
      
      /* now read this back */
#ifdef CAVIUM_MULTICARD_API
      rc = Csp1ReadEpci(CAVIUM_BLOCKING,&temp_key_hdl, curlen, &rbuf[index],&dummy,dev_id);
#else
      rc = Csp1ReadEpci(CAVIUM_BLOCKING,&temp_key_hdl, curlen, &rbuf[index],&dummy);
#endif
      if ( rc ) {
         pots_log(PT_LOG_ERROR, 
               "write_and_check_keymem(): Csp1ReadEpci() failed\n");
         return(-1);
      }

      // FOR NOW
      if ( memcmp(wbufp+index, &rbuf[index], curlen) != 0 ) {
         pots_log(PT_LOG_ERROR, 
               "write_and_check_keymem(): rbuf and wbuf do not match for index %d\n",
               index);
         return(-1);
      }
      else {
         pots_log(PT_LOG_ERROR, 
               "write_and_check_keymem(): rbuf and wbuf match for index = %d\n", 
               index);
      }

      index += curlen;
      ko = index/8;
      dataleft -= curlen;
      temp_key_hdl = start_key_hdl + ko;


   } // end while 

   /* now compare */
   if ( memcmp(wbufp, &rbuf[0], len) != 0 ) {
      pots_log(PT_LOG_ERROR, 
            "write_and_check_keymem(): rbuf and wbuf do not match\n");
      return(-1);
   }

   return(0);

} // end write_and_check_keymem()


/*
 * $Id: pots_keymem.c,v 1.11 2009/09/22 09:57:08 aravikumar Exp $
 * $Log: pots_keymem.c,v $
 * Revision 1.11  2009/09/22 09:57:08  aravikumar
 * made list of test options to constant for both plus and non-nplus
 *
 * Revision 1.10  2009/09/09 15:01:46  aravikumar
 * NPLUS macro dependency removed and made it dynamic
 *
 * Revision 1.9  2008/12/16 12:04:42  jsrikanth
 * Added Common driver and Multi-Card Changes for FreeBSD
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
 * Revision 1.5  2005/11/17 13:31:09  kanantha
 * Updating with the 64 bit modifications, with proper matching of data types
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

