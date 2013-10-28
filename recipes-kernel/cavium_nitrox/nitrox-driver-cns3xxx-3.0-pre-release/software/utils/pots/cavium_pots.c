/*
 * cavium_pots:
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

#include <stdio.h>
#include <stdlib.h>

#include "pots.h"

#include "cavium_sysdep.h"
#include "cavium_common.h"

#include "pots_dd.h"
extern Uint32 device;
extern uint8_t nplus;
extern Uint32 ssl_core_mask;
extern Uint32 ipsec_core_mask;

/*
 * Csp1TestSoftReset:
 *       This does a soft reset on the chip.
 *       This function assumes that all 3 microcodes
 *       (boot, admin and main) were loaded. 
 *       It then calls the soft reset ioctl entry
 *       point in the driver.
 *      - Returns 0 on success and -1 on error.
 *
 */
Uint32 Csp1TestSoftReset(pots_sts *pots_stp)
{

   Uint32 rc;

   pots_log(PT_LOG_INFO, "Csp1TestSoftReset(): PT_SOFT_RESET\n");
   rc = soft_reset_test(pots_stp);
   if ( rc == -1 ) {
      pots_log(PT_LOG_INFO, "Csp1TestSoftReset(): soft_reset_test() failed\n");
      fprintf(pots_stp->pt_rfp, "Soft Reset Test Result: FAILED\n");
      printf("Soft Reset Test Result: FAILED\n");
   }
   else {
      pots_log(PT_LOG_INFO, "Csp1TestSoftReset(): soft_reset_test() worked\n");
      fprintf(pots_stp->pt_rfp, "Soft Reset Test Result: PASSED\n");
      printf("Soft Reset Test Result: PASSED\n");
   }

   return(rc);

} // end Csp1TestSoftReset()

/*
 * Csp1TestInboundPacketProcess :
*/
   
Uint32 Csp1TestInboundPacketProcess(pots_sts *pots_stp)
{
   n1_scatter_buffer inv, outv;
   Uint32 output_data1[512] ;
   Uint32 *out_buffer_ip ;
   Uint32 *in_buffer_ip;
   Uint16 input_pkt_len ;
   Uint64 ctxt;
   Uint32 rc;
   int rlen ;
   Uint8 e_key[] = {0x11,0x11,0xaa,0xaa,0x22,0x22,0xbb,0xbb,0x33,0x33,0xcc,0xcc,0x44,0x44,0xdd,0xdd,0x55,0x55,0xee,0xee,0x66,0x66,0xff,0xff};
   Uint8 a_key[] ={0x11,0x11,0xaa,0xaa,0x22,0x22,0xbb,0xbb,0x33,0x33,0xcc,0xcc,0x44,0x44,0xdd,0xdd} ; 
   Uint8 input_data1[] = { 
      0x45,0x00,0x00,0x78,0x00,0x00,0x40,0x00,
      0x40,0x32,0xb6,0x3a,0xc0,0xa8,0x01,0x64,
      0xc0,0xa8,0x01,0x65,0x00,0x02,0x00,0x00,
      0x00,0x00,0x00,0x01,0x79,0x75,0x78,0xf2,
      0xcb,0x45,0x22,0x22,0x82,0x15,0xcf,0x2e,
      0x55,0x1e,0x8d,0x6a,0xa5,0x30,0xdc,0xa8,
      0xc2,0x96,0xe6,0x91,0xae,0xa8,0xd5,0xf2,
      0xf0,0x20,0x8c,0xfd,0xed,0x7e,0x96,0xf9,
      0x80,0xb9,0x7e,0x2e,0xcf,0xd6,0x74,0xd1,
      0xab,0xdd,0x2f,0x83,0x83,0xba,0x4a,0x7e,
      0xf9,0x4d,0x85,0x9e,0xdd,0xd6,0x01,0x8b,
      0xfe,0xf3,0xd6,0xc8,0x18,0x86,0x43,0x45,
      0xf5,0x5c,0xc3,0xe8,0x62,0x07,0x23,0xbe,
      0xf8,0x9e,0x29,0x5a,0x50,0x9b,0x1a,0x8a,
      0x2a,0x07,0x81,0x67,0x1d,0x50,0xf9,0x44
   };

   in_buffer_ip = (Uint32 *)malloc (512*sizeof(Uint8));
   out_buffer_ip = (Uint32 *)malloc (8*(sizeof(Uint8)));

   if (!in_buffer_ip || !out_buffer_ip)
      printf("Csp1TestInboundPacket: Null buffers passed\n");

#ifdef CAVIUM_MULTICARD_API
   rc = Csp1Initialize(CAVIUM_DIRECT, pots_stp->dev_id);
#else 
   rc = Csp1Initialize(CAVIUM_DIRECT);
#endif 

#ifdef CAVIUM_MULTICARD_API
   rc = Csp1AllocContext(CONTEXT_IPSEC, (Uint64*)&ctxt,pots_stp->dev_id);
#else
   rc = Csp1AllocContext(CONTEXT_IPSEC, (Uint64*)&ctxt);
#endif

   if (rc == 0) { 
#ifndef MC2
#ifdef CAVIUM_MULTICARD_API
       rc = n1_write_ipsec_sa(1,0,0,0,1, &e_key, 1, &a_key ,NULL, 0x200, 1,0,(Uint64)ctxt,in_buffer_ip,out_buffer_ip,0,0,pots_stp->dev_id);
#else
      rc = n1_write_ipsec_sa(1,0,0,0,1, &e_key, 1, &a_key ,NULL, 0x200, 1,0,(Uint64)ctxt,in_buffer_ip,out_buffer_ip,0,0);          
#endif
#else
#ifdef CAVIUM_MULTICARD_API
      rc = n1_write_ipsec_sa(1,0,0,0,2, &e_key, 1, &a_key ,NULL, 0x200, 1,0,(Uint64)ctxt,(Uint64)0, in_buffer_ip,out_buffer_ip,0,0,pots_stp->dev_id);
#else
      rc = n1_write_ipsec_sa(1,0,0,0,2, &e_key, 1, &a_key ,NULL, 0x200, 1,0,(Uint64)ctxt,(Uint64)0, in_buffer_ip,out_buffer_ip,0,0);          
#endif
#endif
      if (rc != 0) {
        if (rc == ERR_OPERATION_NOT_SUPPORTED) {
           pots_log(PT_LOG_INFO, "Csp1TestInboundPacketProcess: n1_write_ipsec_sa operation not supported\n");
           fprintf(pots_stp->pt_rfp, "n1_write_ipsec_sa Result: operation not supported\n");
           printf("InboundPacketProcess operation not supported \n");
#ifdef CAVIUM_MULTICARD_API
           Csp1Shutdown(pots_stp->dev_id);
#else
           Csp1Shutdown();
#endif
           return 0;
        }
        else {
           pots_log(PT_LOG_INFO, "Csp1TestInboundPacketProcess: n1_write_ipsec_sa failed\n");
           fprintf(pots_stp->pt_rfp, "n1_write_ipsec_sa Result: FAILED\n");
           printf("WriteIpsecsa for InboundPacketProcess transport mode Failed \n");
        }
        goto fail;
      }
   }
   else {
      pots_log(PT_LOG_INFO, "Csp1TestInboundPacketProcess: Csp1AllocContext failed\n");
      fprintf(pots_stp->pt_rfp, "Csp1AllocContext Result: FAILED\n");
      printf("AllocContext for InboundPacketProcess transport mode Failed \n");
      goto fail;

   }


#ifndef MC2
   input_pkt_len = 15;
   rlen = 13;
#else
   input_pkt_len = 120;
   rlen = 100; /* Find according to input data */   
#endif
   inv.bufcnt = 1;
    outv.bufcnt = 1;
#ifndef MC2
   inv.bufsize[0] = input_pkt_len*8;
   inv.bufptr[0] = (Uint32 *)input_data1;
   outv.bufsize[0] = rlen*8;
#else
   inv.bufsize[0] = input_pkt_len;
   inv.bufptr[0] = (Uint32 *)input_data1;
   outv.bufsize[0] = rlen;
#endif
   outv.bufptr[0] = output_data1;

#ifdef MC2
#ifdef CAVIUM_MULTICARD_API
   rc = n1_process_inbound_packet (0,0,input_pkt_len,&inv,&outv,rlen,(Uint64)ctxt,0,0,pots_stp->dev_id);
#else
   rc = n1_process_inbound_packet (0,0,input_pkt_len,&inv,&outv,rlen,(Uint64)ctxt,0,0);
#endif
#else
#ifdef CAVIUM_MULTICARD_API
   rc = n1_process_inbound_packet (input_pkt_len*8,0,input_pkt_len,&inv,&outv,rlen,(Uint64)ctxt,0,0,pots_stp->dev_id);
#else
   rc = n1_process_inbound_packet (input_pkt_len*8,0,input_pkt_len,&inv,&outv,rlen,(Uint64)ctxt,0,0);
#endif
#endif

   if (rc == 0 )  {
      pots_log(PT_LOG_INFO, "Csp1TestInboundPacketProcess():  passed\n");
      fprintf(pots_stp->pt_rfp, "n1_process_inbound_packet Result: PASSED\n");
      printf("InboundPacketProcess Test Result: PASSED \n");
   }
   else {
      pots_log(PT_LOG_INFO, "Csp1TestInboundPacketProcess(): failed\n");
      fprintf(pots_stp->pt_rfp, "n1_process_inbound_packet Result: FAILED\n");
      printf("InboundPacketProcess Test Result: FAILED\n");
   }

#ifdef CAVIUM_MULTICARD_API
   Csp1FreeContext(CONTEXT_IPSEC, (Uint64)ctxt,pots_stp->dev_id);
#else
   Csp1FreeContext(CONTEXT_IPSEC, (Uint64)ctxt);
#endif
fail:
#ifdef CAVIUM_MULTICARD_API
   Csp1Shutdown(pots_stp->dev_id);
#else
   Csp1Shutdown();
#endif
   return(rc);

} // end Csp1TestInboundPacketProcess()

Uint32 Csp1TestOutboundPacketProcess(pots_sts *pots_stp)
{
   n1_scatter_buffer inv, outv;
   Uint32 output_data[512] ;
   Uint32 *out_buffer_ip ;
   Uint32 *in_buffer_ip;
   Uint16 input_pkt_len ;
   Uint64 ctxt;
   Uint32 rc;
   int rlen ;

   Uint8 e_key[] = {0x11,0x11,0xaa,0xaa,0x22,0x22,0xbb,0xbb,0x33,0x33,0xcc,0xcc,0x44,0x44,0xdd,0xdd,0x55,0x55,0xee,0xee,0x66,0x66,0xff,0xff};
   Uint8 a_key[] ={0x11,0x11,0xaa,0xaa,0x22,0x22,0xbb,0xbb,0x33,0x33,0xcc,0xcc,0x44,0x44,0xdd,0xdd} ; 

   Uint8 temp_data [ ] = { 0x00,0x00,0x00,0x01,0x00,0x00,0x00,0x01,
      0x45,0x00,0x00,0x54,0x00,0x00,0x40,0x00, 
      0x40,0x01,0xb6,0x8f,0xc0,0xa8,0x01,0x64,
      0xc0,0xa8,0x01,0x65,0x08,0x00,0x67,0x41,
      0x1e,0x09,0x00,0x01,0x9a,0xe6,0xc7,0x41,
      0x1f,0x89,0x06,0x00,0x08,0x09,0x0a,0x0b, 
      0x0c,0x0d,0x0e,0x0f,0x10,0x11,0x12,0x13,
      0x14,0x15,0x16,0x17,0x18,0x19,0x1a,0x1b,
      0x1c,0x1d,0x1e,0x1f,0x20,0x21,0x22,0x23,
      0x24,0x25,0x26,0x27,0x28,0x29,0x2a,0x2b,
      0x2c,0x2d,0x2e,0x2f,0x30,0x31,0x32,0x33,
      0x34,0x35,0x36,0x37};

   in_buffer_ip = (Uint32 *)malloc (512*sizeof(Uint8));
   out_buffer_ip = (Uint32 *)malloc (8*sizeof(Uint8));

#ifdef CAVIUM_MULTICARD_API
   rc = Csp1Initialize(CAVIUM_DIRECT, pots_stp->dev_id);
#else 
   rc = Csp1Initialize(CAVIUM_DIRECT);
#endif

#ifdef CAVIUM_MULTICARD_API
   rc = Csp1AllocContext(CONTEXT_IPSEC,(Uint64*)&ctxt,pots_stp->dev_id);
#else
   rc = Csp1AllocContext(CONTEXT_IPSEC,(Uint64*)&ctxt);
#endif
   if (rc == 0 ) {
#ifndef MC2
#ifdef CAVIUM_MULTICARD_API
      rc = n1_write_ipsec_sa(1,0,0,1,1, e_key, 1, a_key ,NULL, 0x200, 1,0,(Uint64)ctxt, in_buffer_ip,out_buffer_ip,0,0,pots_stp->dev_id);
#else
      rc = n1_write_ipsec_sa(1,0,0,1,1, e_key, 1, a_key ,NULL, 0x200, 1,0,(Uint64)ctxt, in_buffer_ip,out_buffer_ip,0,0);          
#endif
#else 
#ifdef CAVIUM_MULTICARD_API
      rc = n1_write_ipsec_sa(1,0,0,1,2, e_key, 1, a_key ,NULL, 0x200, 1,0,(Uint64)ctxt,(Uint64)0, in_buffer_ip,out_buffer_ip,0,0,pots_stp->dev_id);
#else
      rc = n1_write_ipsec_sa(1,0,0,1,2, e_key, 1, a_key ,NULL, 0x200, 1,0,(Uint64)ctxt,(Uint64)0, in_buffer_ip,out_buffer_ip,0,0);          
#endif
#endif
      
      if (rc != 0) { 

        if ( rc == ERR_OPERATION_NOT_SUPPORTED) {
           pots_log(PT_LOG_INFO, "Csp1TestOutboundPacketProcess(): n1_write_ipsec_sa()  opeation not supported\n");
           fprintf(pots_stp->pt_rfp, "write ipsec sa Result: Not Supported\n");
           printf("OutboundPacketProcess not Supported \n");
#ifdef CAVIUM_MULTICARD_API
           Csp1Shutdown(pots_stp->dev_id);
#else
           Csp1Shutdown();
#endif
           return rc;
        }
        else {
           pots_log(PT_LOG_INFO, "Csp1TestOutboundPacketProcess(): n1_write_ipsec_sa()  failed\n");
           fprintf(pots_stp->pt_rfp, "write ipsec sa Result: FAILED\n");
           printf("WriteIpsecsa for OutboundPacketProcess transport mode Failed \n");
        }
      }
   }
   else {
         pots_log(PT_LOG_INFO, "Csp1TestOutboundPacketProcess():Csp1AllocConext () failed\n");
         fprintf(pots_stp->pt_rfp, "Alloc Context Result: FAILED\n");
         printf("AllocContext for OutboundPacketProcess transport mode Failed \n");
         goto fail;
      }

#ifdef MC2
   input_pkt_len = 92 ;
   rlen = 120; /* Find according to input data */   
   inv.bufsize[0] = input_pkt_len;
   outv.bufsize[0] = rlen;
#else
   input_pkt_len = 12 ;
   rlen = 16; /* Find according to input data */   
   inv.bufsize[0] = input_pkt_len*8;
   outv.bufsize[0] = rlen*8;
#endif
   inv.bufcnt = 1;
   outv.bufcnt = 1;
   inv.bufptr[0] = (Uint32 *)temp_data;
   outv.bufptr[0] = output_data;
#ifdef CAVIUM_MULTICARD_API
   rc = n1_process_outbound_packet (0,0,input_pkt_len,&inv,&outv,rlen,(Uint64)ctxt,0,0,pots_stp->dev_id);
#else
   rc = n1_process_outbound_packet (0,0,input_pkt_len,&inv,&outv,rlen,(Uint64)ctxt,0,0);
#endif
   if (rc == 0 ) {
      pots_log(PT_LOG_INFO, "Csp1TestOutboundPacketProcess(): n1_process_outbound_packet() passed\n");
      fprintf(pots_stp->pt_rfp, "Outbound Packet Process Test Result: PASSED\n");
      printf("OutboundPacketProcess Test Result: PASSED\n");
   }
   else {
      pots_log(PT_LOG_INFO, "Csp1TestOutboundPacketProcess(): n1_process_outbound_packet() failed \n");
      fprintf(pots_stp->pt_rfp, "Outbound Packet Process Test Result: FAILED\n");
      printf("OutboundPacketProcess Test Result: FAILED\n");
   }

#ifdef CAVIUM_MULTICARD_API
   Csp1FreeContext(CONTEXT_IPSEC, (Uint64)ctxt,pots_stp->dev_id);
#else
   Csp1FreeContext(CONTEXT_IPSEC, (Uint64)ctxt);
#endif
fail:
#ifdef CAVIUM_MULTICARD_API
   Csp1Shutdown(pots_stp->dev_id);
#else
   Csp1Shutdown();
#endif
   return(rc);

} // end Csp1TestOutBoundPacketProcess()

/*
 * Csp1TestReadWriteRegs:
 *       - Tests reading and writing on IQM3 Base Address High reg.
 *      - Returns 0 on success and -1 on error.
 *
 */
Uint32 Csp1TestReadWriteRegs(pots_sts *pots_stp)
{
   Uint32 rc;


   pots_log(PT_LOG_INFO, "Csp1TestReadWriteRegs(): PT_READ_WRITE_REGS\n");
   rc = read_write_reg(pots_stp);
   if ( rc == -1 ) {
      pots_log(PT_LOG_INFO,
         "Csp1TestReadWriteRegs(): read_write_reg() failed\n");
      fprintf(pots_stp->pt_rfp, "Register Read/Write Test Result: FAILED\n");
      printf("Register Read/Write Test Result: FAILED\n");
   }
   else {
      pots_log(PT_LOG_INFO,
         "Csp1TestReadWriteRegs(): read_write_reg() worked\n");
      fprintf(pots_stp->pt_rfp, "Register Read/Write Test Result: PASSED\n");
      printf("Register Read/Write Test Result: PASSED\n");
   }

   return(rc);

} // end Csp1TestReadWriteRegs()



/*
 * Csp1TestReadEeprom:
 *
 */
Uint32 Csp1TestReadEeprom(pots_sts *pots_stp)
{
   pots_log(PT_LOG_INFO, "Csp1TestReadEeprom(): PT_PCI_EEPROM\n");

   pots_log(PT_LOG_INFO,
      "pp1TestReadEepromrocess_test(): Read EEPROM Test: Not Implemented\n");

   fprintf(pots_stp->pt_rfp, "Read EEPROM Test Result: Not Implemented\n");
   printf("Read EEPROM Test Result: Not Implemented\n");
   
   return(0);

} // end Csp1TestReadEeprom()


/*
 * Csp1TestTWSI:
 *
 */
Uint32 Csp1TestTWSI(pots_sts *pots_stp)
{

   pots_log(PT_LOG_INFO, "Csp1TestTWSI(): TWSI test not yet implemented\n");

   pots_log(PT_LOG_INFO, "Csp1TestTWSI(): %s %s %s\n",
      "TWSI test not needed, since checking ddr context memory ",
      "is done thru the TWSI interface, so it is implicitly ",
      "tested during the ddr test.");

   fprintf(pots_stp->pt_rfp, "TWSI Test Result: Not Implemented\n");
   printf("TWSI Test Result: Not Implemented\n");

   return(0);

} // end Csp1TestTWSI()



/*
 * Csp1TestUcodeLoad:
 *
 */
Uint32 Csp1TestUcodeLoad(pots_sts *pots_stp)
{
   Uint32 rc;

   pots_log(PT_LOG_INFO, "Csp1TestUcodeLoad(): PT_LOAD_MICROCODE\n");
   rc = load_microcode(pots_stp);
   if ( rc == -1 ) {
      pots_log(PT_LOG_INFO,
         "Csp1TestUcodeLoad(): load_microcode() failed\n");
      fprintf(pots_stp->pt_rfp, "Microcode Load Test Result: FAILED\n");
      printf("Microcode Load Test Result: FAILED\n");
   }
   else {
      pots_log(PT_LOG_INFO,
         "Csp1TestUcodeLoad(): load_microcode() worked\n");
      fprintf(pots_stp->pt_rfp, "Microcode Load Test Result: PASSED\n");
      printf("Microcode Load Test Result: PASSED\n");
   }

   return(rc);

} // end Csp1TestUcodeLoad()
   

/*
 * Csp1TestQueues:
 *
 */
Uint32 Csp1TestQueues(pots_sts *pots_stp)
{
   pots_log(PT_LOG_INFO, "Cps1TestQueues(): PT_QUEUE\n");

   pots_log(PT_LOG_INFO, "Cps1TestQueues(): QUEUE test not yet implemented\n");

   fprintf(pots_stp->pt_rfp, "Queues Test Result: Not Implemented\n");
   printf("Queues Test Result: Not Implemented\n");

   return(0);

} // end Csp1TestQueues()


/*
 * Csp1TestArbiter:
 *
 */
Uint32 Csp1TestArbiter(pots_sts *pots_stp)
{

   pots_log(PT_LOG_INFO, "Cps1TestArbiter(): PT_ARBITER\n");

   pots_log(PT_LOG_INFO, "NO DRIVER SUPPORT AVAILABLE ARBITER\n");
        fprintf(pots_stp->pt_rfp, "ARBITER TEST RESULT: NO DRIVER SUPPORT\n");

   return(0);

} // end Csp1TestArbiter()


Uint32 Csp1EndianTest(pots_sts *pots_stp)
{

   pots_log(PT_LOG_INFO, "NO DRIVER SUPPORT AVAILABLE FOR ENDIAN\n");
        fprintf(pots_stp->pt_rfp, "ENDIAN TEST: NO DRIVER SUPPORT\n");
   return(0);
} // end Csp1EndianTest()


/*
 * Cps1TestKeyMemAndDMA:
 *
 */
Uint32 Csp1TestKeyMemAndDMA(pots_sts *pots_stp)
{
   Uint32 rc;

   pots_log(PT_LOG_INFO, "Cps1TestKeyMemAndDMA(): PT_KEY_MEMORY\n");

   rc = pots_keymem(pots_stp);
   if ( rc == -1 ) {
      pots_log(PT_LOG_INFO, "Cps1TestKeyMemAndDMA(): pots_keymem() failed\n");
      fprintf(pots_stp->pt_rfp, "Key Memory and DMA Test Result: FAILED\n");
      printf("Key Memory and DMA Test Result: FAILED\n");
   }
   else if (rc==ERR_OPERATION_NOT_SUPPORTED){
      pots_log(PT_LOG_INFO, "Cps1TestKeyMemAndDMA(): pots_keymem() operation not suppoted\n");
      fprintf(pots_stp->pt_rfp, "Key Memory and DMA Test Result: PASSED\n");
      printf("Key Memory and DMA Test Result: Opeartion not supported\n");
      pots_log(PT_LOG_INFO, "Cps1TestKeyMemAndDMA(): pots_keymem() not supported\n");
      return 0;
   }
   else {
      fprintf(pots_stp->pt_rfp, "Key Memory and DMA Test Result: PASSED\n");
      printf("Key Memory and DMA Test Result: PASSED\n");
   }

   return(rc);
   
} // end Cps1TestKeyMemAndDMA()


/*
 * Csp1TestRandomNumbers:
 *
 */
Uint32 Csp1TestRandomNumbers(pots_sts *pots_stp)
{
   Uint32 rc;

   rc = pots_random_test(pots_stp);
   if ( rc == -1 ) {
      pots_log(PT_LOG_INFO,
         "Csp1TestRandomNumbers(): pots_random_test() failed\n");
      fprintf(pots_stp->pt_rfp, "Random Numbers Test Result: FAILED\n");
      printf("Random Numbers Test Result: FAILED\n");
   }
   else {
      pots_log(PT_LOG_INFO,
         "Csp1TestRandomNumbers(): pots_random_test() worked\n");
      fprintf(pots_stp->pt_rfp, "Random Numbers Test Result: PASSED\n");
      printf("Random Numbers Test Result: PASSED\n");
   }

   return(rc);

} // end Csp1TestRandomNumbers


/*
 * Cps1TestLocalMem: (dd test)
 *
 */
Uint32 Csp1TestLocalMem(pots_sts *pots_stp)
{

   Uint32 rc;
//#ifndef N1
   if(device!=N1_DEVICE){
      pots_log(PT_LOG_INFO, "NO DDR MEMORY ON Nitrox-Px\n");
      fprintf(pots_stp->pt_rfp, "Csp1TestLocalMem %s", "No DDR Memory on Nitrox-Px\n");
      printf("NO DDR MEMORY present on the chip\n");
      return 0;
   }
//#endif

   rc = pots_ddr(pots_stp);

   switch (rc) {
   
   default:
   case -1:
      pots_log(PT_LOG_INFO, "Csp1TestLocalMem(): pots_ddr() failed\n");
      fprintf(pots_stp->pt_rfp, "Local Memory (DDR) Test Result: FAILED\n");
      printf("Local Memory (DDR) Test Result: FAILED\n");
      break;
   
   case 0:
      pots_log(PT_LOG_INFO, "Csp1TestLocalMem(): pots_ddr() worked\n");
      fprintf(pots_stp->pt_rfp, "Local Memory (DDR) Test Result: PASSED\n");
      printf("Local Memory (DDR) Test Result: PASSED\n");
      break;

   case 1:
      pots_log(PT_LOG_INFO, "Csp1TestLocalMem(): there is no ddr memory to test\n");
      fprintf(pots_stp->pt_rfp, 
            "Local Memory (DDR) Test Result: There is no DDR Memory.\n");
      printf("Local Memory (DDR) Test Result: There is no DDR Memory.\n");
      break;

   } // end switch 

   return(rc);

} // end Csp1TestLocalMem


/*
 * Csp1TestRC4:
 */
Uint32 Csp1TestRC4(pots_sts *pots_stp)
{
   Uint32 rc;
   
   rc = pots_rc4(pots_stp);
   if ( rc == -1 ) {
      pots_log(PT_LOG_INFO, "Csp1TestRC4(): pots_rc4() failed\n");
      fprintf(pots_stp->pt_rfp, "RC4 Crypto Test Result: FAILED\n");
      printf("RC4 Crypto Test Result: FAILED\n");
   }
   else if ( rc == ERR_OPERATION_NOT_SUPPORTED ) {
      pots_log(PT_LOG_INFO, "Csp1TestRC4(): pots_rc4() operation not supported\n");
      fprintf(pots_stp->pt_rfp, "RC4 Crypto Test Result: Operation not supported\n");
      printf("RC4 Crypto Test Result: Operation not supported\n");
      return 0;
   }
   else {
      pots_log(PT_LOG_INFO, "Csp1TestRC4(): pots_rc4() worked\n");
      fprintf(pots_stp->pt_rfp, "RC4 Crypto Test Result: PASSED\n");
      printf("RC4 Crypto Test Result: PASSED\n");
   }

   return(rc);

} // end Csp1TestRc4


/*
 * Csp1TestHMAC:
 */
Uint32 Csp1TestHMAC(pots_sts *pots_stp)
{
   Uint32 rc;
   
   rc = pots_hmac(pots_stp);
   if ( rc == -1 ) {
      pots_log(PT_LOG_INFO, "Csp1TestHMAC(): pots_hmac() failed\n");
      fprintf(pots_stp->pt_rfp, "HMAC Crypto Test Result: FAILED\n");
      printf("HMAC Crypto Test Result: FAILED\n");
   }
   else if (rc == ERR_OPERATION_NOT_SUPPORTED) {
      pots_log(PT_LOG_INFO, "Csp1TestHMAC(): pots_hmac() operation not supported\n");
      fprintf(pots_stp->pt_rfp, "HMAC Crypto Test Result: PASSED\n");
      printf("HMAC Crypto Test Result: Operation not supported\n");
      return 0;
   }
   else {
      pots_log(PT_LOG_INFO, "Csp1TestHMAC(): pots_hmac() worked\n");
      fprintf(pots_stp->pt_rfp, "HMAC Crypto Test Result: PASSED\n");
      printf("HMAC Crypto Test Result: PASSED\n");
   }

   return(rc);

} // end Csp1TestHMAC


/*
 * Csp1Test3DES:
 */
Uint32 Csp1Test3DES(pots_sts *pots_stp)
{
   Uint32 rc;
   
   rc = pots_3des(pots_stp);
   if ( rc == -1 ) {
      pots_log(PT_LOG_INFO, "Csp1Test3DES(): pots_3des() failed\n");
      fprintf(pots_stp->pt_rfp, "3DES Crypto Test Result: FAILED\n");
      printf("3DES Crypto Test Result: FAILED\n");
   }
   if ( rc ==  ERR_OPERATION_NOT_SUPPORTED) {
      pots_log(PT_LOG_INFO, "Csp1Test3DES(): pots_3des() Operation not supported\n");
      fprintf(pots_stp->pt_rfp, "3DES Crypto Test Result: Operation not supported\n");
      printf("3DES Crypto Test Result: Operation not supported\n");
      return 0;
   }
   else {
      pots_log(PT_LOG_INFO, "Csp1Test3DES(): pots_3des() worked\n");
      fprintf(pots_stp->pt_rfp, "3DES Crypto Test Result: PASSED\n");
      printf("3DES Crypto Test Result: PASSED\n");
   }

   return(rc);

} // end Csp1Test3DES


/*
 * Csp1TestAES:
 */
Uint32 Csp1TestAES(pots_sts *pots_stp)
{

   int rc;

   rc = pots_aes(pots_stp);
   if ( rc == -1 ) {
      pots_log(PT_LOG_INFO, "Csp1TestAES(): pots_aes() failed\n");
      fprintf(pots_stp->pt_rfp, "AES Crypto Test Result: FAILED\n");
      printf("AES Crypto Test Result: FAILED\n");
   }
   else if ( rc == ERR_OPERATION_NOT_SUPPORTED ) {
      pots_log(PT_LOG_INFO, "Csp1TestAES(): pots_aes() Operation not supported\n");
      fprintf(pots_stp->pt_rfp, "AES Crypto Test Result: Operation not supported\n");
      printf("AES Crypto Test Result: Operation not supported\n");
      return 0;
   }
   else {
      pots_log(PT_LOG_INFO, "Csp1TestAES(): pots_aes() worked\n");
      fprintf(pots_stp->pt_rfp, "AES Crypto Test Result: PASSED\n");
      printf("AES Crypto Test Result: PASSED\n");
   }

   return(rc);

} // end Csp1TestAES


/*
 * Csp1TestModEx:
 */
Uint32 Csp1TestModEx(pots_sts *pots_stp)
{
   int rc;
   
   rc = pots_mod_ex(pots_stp);
   if ( rc == -1 ) {
      pots_log(PT_LOG_INFO, "Csp1TestModEx(): pots_mod_ex() failed\n");
      fprintf(pots_stp->pt_rfp, "Mod Ex Crypto Test Result: FAILED\n");
      printf("Mod Ex Crypto Test Result: FAILED\n");
   }
   else {
      pots_log(PT_LOG_INFO, "Csp1TestModE(): pots_mod_ex() worked\n");
      fprintf(pots_stp->pt_rfp, "Mod Ex Crypto Test Result: PASSED\n");
      printf("Mod Ex Crypto Test Result: PASSED\n");
   }

   return(rc);

} // end Csp1TestModEx


/*
 * Csp1Test3DES:
 */
Uint32 Csp1TestInterrupts(pots_sts *pots_stp)
{
   pots_log(PT_LOG_INFO, "NO DRIVER SUPPORT AVAILABLE INTERRUPTS\n");
        fprintf(pots_stp->pt_rfp, "Interrupt Test Result: NO DRIVER SUPPORT\n");

} // end Csp1TestInterrupts

/*
 * Csp1TestVirtualReset:
 */
Uint32 Csp1TestVirtualReset(pots_sts *pots_stp)
{
   
   pots_log(PT_LOG_INFO,
      "Csp1TestVirtualReset(): Virtual Reset Test: Not Implemented\n");

   fprintf(pots_stp->pt_rfp, "Virtual Reset Test Result: Not Implemented\n");
   printf("Virtual Reset Test Result: Not Implemented\n");

   return(0);

} // end Csp1TestVirtualReset


/*
 * Csp1GetUcodeVerions:
 */
Uint32 Csp1GetUcodeVersions(pots_sts *pots_stp)
{
   Uint32 rc;
   
   rc = print_ucode_loaded(pots_stp);

   switch (rc) {

   case -1:
   default:
      pots_log(PT_LOG_INFO, 
            "Csp1GetUcodeVersions(): print_ucode_loaded() failed\n");
      fprintf(pots_stp->pt_rfp, "Microcode Verions Print: ERROR\n");
      printf("Microcode Verions Print: ERROR\n");
      break;

   case 0:
      pots_log(PT_LOG_INFO, 
            "Csp1GetUcodeVersions(): print_ucode_loaded() worked\n");
      fprintf(pots_stp->pt_rfp, "Microcode Not Loaded Yet!\n");
      printf("Microcode Not Loaded Yet!\n");
      break;

   case 1:
      pots_log(PT_LOG_INFO, 
            "Csp1GetUcodeVersions(): print_ucode_loaded() worked\n");
      fprintf(pots_stp->pt_rfp, "\tMicrocode Verions Printed\n");
      printf("Microcode Verions Printed\n");
      break;
   }

   return(rc);

} // end Csp1GetUcodeVersions


/*
 * Csp1GetBISTRegVal:
 *
 */
Uint32 Csp1GetBISTRegVal(pots_sts *pots_stp, Uint32 *outp)
{
   Uint32 rc;

   pots_log(PT_LOG_INFO, "Csp1GetBISTRegVal(): PT_CHECK_BIST_REG\n");

   rc = check_bist_reg(pots_stp, outp);
   if ( rc == -1 ) {
      pots_log(PT_LOG_INFO,
         "Csp1GetBISTRegVal(): check_bist_reg() failed\n");
      fprintf(pots_stp->pt_rfp, "Get BIST Reg Val Test Result: FAILED\n");
      printf("Get BIST Reg Val Test Result: FAILED\n");
   }
   else {
      pots_log(PT_LOG_INFO,
         "Csp1GetBISTRegVal(): check_bist_reg() worked\n");
      fprintf(pots_stp->pt_rfp, "Get BIST Reg Val Test Result: PASSED\n");
      printf("Get BIST Reg Val Test Result: PASSED\n");
      fprintf(pots_stp->pt_rfp, "\tBIST Reg Val = 0x%0x\n", *outp);
      printf("\tBIST Reg Val = 0x%0x\n", *outp);
   }

   return(rc);

} // end Csp1GETBISTRegVal()


/*
 * Csp1GetUnitEnableRegVal:
 *
 */
Uint32 Csp1GetUnitEnableRegVal(pots_sts *pots_stp, Uint32 *outp)
{
   Uint32 rc;

   pots_log(PT_LOG_INFO, "Csp1GetUnitEnableRegVal(): PT_CHECK_UNIT_ENABLE_REG\n");

   rc = check_unit_enable_reg(pots_stp, outp);
   if ( rc == -1 ) {
      pots_log(PT_LOG_INFO,
         "Csp1GetUnitEnableRegVal(): check_bist_reg() failed\n");
      fprintf(pots_stp->pt_rfp, "Get Unit Enable Reg Val Test Result: FAILED\n");
      printf("Get Unit Enable Reg Val Test Result: FAILED\n");
   }
   else {
      pots_log(PT_LOG_INFO,
         "Csp1GetUnitEnableRegVal(): check_bist_reg() worked\n");
      fprintf(pots_stp->pt_rfp, "Get Unit Enable Reg Val Test Result: PASSED\n");
      printf("Get Unit Enable Reg Val Test Result: PASSED\n");
      fprintf(pots_stp->pt_rfp, "\tUnit Enable Reg Val = 0x%0x\n", *outp);
      printf("\tUnit Enable Reg Val = 0x%0x\n", *outp);
   }
   
   return(rc);

} // end Csp1GetUnitEnableRegVal()


/*
 * Csp1GetExecUnitsAvailable
 *       - Returns a bitmask of available exec units (i.e cores)
 *
 */
Uint32 Csp1GetExecUnitsAvailable(pots_sts *pots_stp, Uint32 *outp)
{
   Uint32 rc =0 ;
   int nr;         // for # of exec units

   pots_log(PT_LOG_INFO, "Csp1GetExecUnitsAvailable(): PT_CHECK_UNIT_ENABLE_REG\n");
//#ifdef NPLUS   
   if(nplus && device != NPX_DEVICE)
      *outp = ssl_core_mask + ipsec_core_mask;
   else
//#endif
      rc = get_exec_units(pots_stp, outp);
   if ( rc == -1 ) {
      pots_log(PT_LOG_INFO,
         "Csp1GetExecUnitsAvailable(): get_exec_units() failed\n");
      fprintf(pots_stp->pt_rfp, "Get Exec Units Avail Test Result: FAILED\n");
      printf("Get Exec Units Avail Test Result: FAILED\n");
   }
   else {
      pots_log(PT_LOG_INFO,
         "Csp1GetExecUnitsAvailable(): get_exec_units() worked\n");
      nr = count_bits_set(*outp, 28);
      fprintf(pots_stp->pt_rfp, "Get Exec Units Avail Test Result: PASSED\n");
      printf("Get Exec Units Avail Test Result: PASSED\n");
      fprintf(pots_stp->pt_rfp, 
            "\tNumber of exec units found = %d, mask = 0x%0x\n", nr, *outp);
      printf("\tNumber of exec units found = %d, mask = 0x%0x\n", nr, *outp);
   }
   
   return(rc);

} // end Csp1GetExecUnitsAvailable


/*
 * Csp1DoRequestUnitOperation
 *       - Returns a bitmask of available exec units (i.e cores)
 *
 */
Uint32 Csp1DoRequestUnitOperation(pots_sts *pots_stp, int action, Uint32 mask)
{
   Uint32 rc;

   pots_log(PT_LOG_INFO, "Csp1DoRequestUnitOperation(): PT_CHECK_UNIT_ENABLE_REG\n");

   rc = request_unit_operation(pots_stp, action, mask);
   if ( rc == -1 ) {
      pots_log(PT_LOG_INFO,
         "Csp1DoRequestUnitOperation(): request_unit_operation() failed\n");
      fprintf(pots_stp->pt_rfp, "Request Unit Test (%d) Result: FAILED\n",
            action);
      printf("Request Unit Test (%d) Result: FAILED\n", action);
   }
   else {
      pots_log(PT_LOG_INFO,
         "Csp1DoRequestUnitOperation(): request_unit_operation() worked\n");
      fprintf(pots_stp->pt_rfp, "Request Unit Test (%d) Result: PASSED\n",
            action);
      printf("Request Unit Test (%d) Result: PASSED\n", action);
   }

   return(rc);

} // end Csp1DoRequestUnitOperation


/*
 * Csp1PotsSpecificUcodeLoad:
 *
 */
Uint32 Csp1PotsSpecificUcodeLoad(pots_sts *pots_stp)
{

   pots_log(PT_LOG_INFO, "NO DRIVER SUPPORT AVAILABLE POTS SPEC MC\n");
        fprintf(pots_stp->pt_rfp, "POTS Specific Microcode Load Test Result: NO DRIVER SUPPORT\n");

   return(0);
} // end Csp1PotsSpecificUcodeLoad


Uint32 Csp1PotsSpecificSoftReset(pots_sts *pots_stp)
{

   pots_log(PT_LOG_INFO, "NO DRIVER SUPPORT AVAILABLE POTS SPEC MC\n");
        fprintf(pots_stp->pt_rfp, "POTS Specific Microcode Soft Reset Test Result: NO DRIVER SUPPORT\n");
   return (0);
} // end Csp1PotsSpecificSoftReset()


Uint32 Csp1TestAllCoresForSelfIDIns(pots_sts *pots_stp)
{
   pots_log(PT_LOG_INFO, "NO DRIVER SUPPORT AVAILABLE POTS SPEC MC\n");
   fprintf(pots_stp->pt_rfp, "Run Self ID Ins on all cores Test Result %s",
                             "NO DRIVER SUPPORT\n");
   return (0);
} // end Csp1TestAllCoresForSelfIDIns()

#if 0
/*
 * Csp1GetDDRSize:
 *
 */
Uint32 Csp1GetDDRSize(pots_sts *pots_stp, Uint32 *outp)
{
   Uint32 rc;
#ifndef N1
   pots_log(PT_LOG_INFO, "NO DDR MEMORY ON Nitrox-Px\n");
   fprintf(pots_stp->pt_rfp, "GetDDRSize %s", "No DDR Memory on Nitrox-Px\n");
   printf("NO DDR MEMORY ON Nitrox-Px\n");
   return 0;
#endif

   rc = get_ddr_size(pots_stp);
   if ( rc == -1 ) {
      pots_log(PT_LOG_INFO,
         "Csp1GetUnitEnableRegVal(): call_pots_test_ioctl() failed\n");
      fprintf(pots_stp->pt_rfp, "Get DDR Size Test Result: FAILED\n");
      printf("Get DDR Size Test Result: FAILED\n");
   }
   else {
      pots_log(PT_LOG_INFO,
         "Csp1GetUnitEnableRegVal(): call_pots_test_ioctl() worked\n");
      fprintf(pots_stp->pt_rfp, "Get DDR Size Test Result: PASSED\n");
      printf("Get DDR Size Test Result: PASSED\n");
      fprintf(pots_stp->pt_rfp, "\tSize of DDR = %d (0x%0x) bytes\n",
            pots_stp->pt_ddr_size, pots_stp->pt_ddr_size);
      printf("\tSize of DDR = %d (0x%0x) bytes\n",
            pots_stp->pt_ddr_size, pots_stp->pt_ddr_size);
   }

   *outp = pots_stp->pt_ddr_size;
   
   return(0);

} // end Csp1GetDDRSize()
#endif

/*
 * Csp1GetChipCSR:
 *       - Returns a bitmask that represents teh chip's csr
 *
 */
Uint32 Csp1GetChipCSR(pots_sts *pots_stp, Uint32 *outp)
{
   Uint32 rc;
   int nr;         // for # of exec units


   rc = get_chip_csr(pots_stp, outp);
   if ( rc == -1 ) {
      pots_log(PT_LOG_INFO,
         "Csp1GetChipCSR(): get_chip_csr() failed\n");
      fprintf(pots_stp->pt_rfp, "Get Chip CSR: FAILED\n");
      printf("Get Chip CSR: FAILED\n");
   }
   else {
      pots_log(PT_LOG_INFO,
         "Csp1GetChipCSR(): get_chip_csr() worked\n");
      fprintf(pots_stp->pt_rfp, "Get Chip CSR: PASSED\n");
      printf("Get Chip CSR: PASSED\n");
      fprintf(pots_stp->pt_rfp, 
            "\tChip CSR bit-mask = 0x%0x\n", *outp);
      printf("\tChip CSR bit-mask = 0x%0x\n", *outp);

   }

   return(0);

} // end Csp1GetChipCSR()


/*
 * Csp1GetPciCSR:
 *       - Returns a bitmask that represents the PCI CSR
 *
 */
Uint32 Csp1GetPciCSR(pots_sts *pots_stp, Uint32 *outp)
{
   Uint32 rc;
   int nr;         // for # of exec units

   rc = get_pci_csr(pots_stp, outp);
   if ( rc == -1 ) {
      pots_log(PT_LOG_INFO,
         "Csp1GetPciCSR(): get_pci_csr() failed\n");
      fprintf(pots_stp->pt_rfp, "Get PCI CSR: PASSED\n");
      printf("Get PCI CSR: PASSED\n");
   }
   else {
      pots_log(PT_LOG_INFO,
         "Csp1GetPciCSR(): get_pci_csr() worked\n");
      fprintf(pots_stp->pt_rfp, "Get PCI CSR: PASSED\n");
      printf("Get PCI CSR: PASSED\n");
      fprintf(pots_stp->pt_rfp, 
            "\tPCI CSR bit-mask = 0x%0x\n", *outp);
      printf("\tPCI CSR bit-mask = 0x%0x\n", *outp);

   }

   return(0);

} // end Csp1GetPciCSR()


/*
 * Csp1GetPciConfigReg:
 *       - Returns a bitmask that represents the PCI Config Reg
 *
 */
Uint32 Csp1GetPciConfigReg(pots_sts *pots_stp, Uint32 *outp)
{
   Uint32 rc;
   int nr;         // for # of exec units

   rc = get_pci_config_reg(pots_stp, outp);
   if ( rc == -1 ) {
      pots_log(PT_LOG_INFO,
         "Csp1GetPciConfigReg(): get_pci_config_reg() failed\n");
      fprintf(pots_stp->pt_rfp, "Get PCI Config Reg: PASSED\n");
      printf("Get PCI Config Reg: PASSED\n");
   }
   else {
      pots_log(PT_LOG_INFO,
         "Csp1GetPciConfigReg(): get_pci_config_reg() worked\n");
      fprintf(pots_stp->pt_rfp, "Get PCI Config Reg: PASSED\n");
      printf("Get PCI Config Reg: PASSED\n");
      fprintf(pots_stp->pt_rfp, "\tPCI Config Reg bit-mask = 0x%0x\n", *outp);
      printf("\tPCI Config Reg bit-mask = 0x%0x\n", *outp);
      fprintf(pots_stp->pt_rfp, "\tVendor ID = 0x%0x, Device ID = 0x%0x\n",
            (*outp & 0x0000ffff), (*outp & 0xffff0000));
      printf("Vendor ID = 0x%0x, Device ID = 0x%0x\n",
            (*outp & 0x0000ffff), (*outp & 0xffff0000));

   }

   return(0);

} // end Csp1GetPciConfigReg()


/*
 * $Id: cavium_pots.c,v 1.16 2009/09/22 09:57:08 aravikumar Exp $
 * $Log: cavium_pots.c,v $
 * Revision 1.16  2009/09/22 09:57:08  aravikumar
 * made list of test options to constant for both plus and non-nplus
 *
 * Revision 1.15  2009/09/09 15:01:46  aravikumar
 * NPLUS macro dependency removed and made it dynamic
 *
 * Revision 1.14  2008/12/16 12:04:42  jsrikanth
 * Added Common driver and Multi-Card Changes for FreeBSD
 *
 * Revision 1.13  2008/11/27 13:37:45  ysandeep
 * Fixed Bug for NPLUS
 *
 * Revision 1.12  2008/11/26 05:48:47  ysandeep
 * Fixed Bugs
 *
 * Revision 1.11  2008/11/05 06:45:57  ysandeep
 * Added NPLUS support for N1/NLite
 *
 * Revision 1.10  2008/10/31 10:51:29  ysandeep
 * MULTICARD support added for ipsec.
 * nplus_handle removed (NPLUS).
 *
 * Revision 1.9  2008/10/24 08:43:51  ysandeep
 * NPLUS support added
 *
 * Revision 1.8  2008/07/30 13:28:50  aramesh
 * added printf for NO DDR presence for PX/LITE.
 *
 * Revision 1.7  2008/07/14 10:46:48  aramesh
 * corrected N1 related errors.
 *
 * Revision 1.6  2008/07/11 08:29:18  aramesh
 * device type  is used for determining N1.
 *
 * Revision 1.5  2008/03/10 10:22:58  kkiran
 *  - Cavium Copyright added.
 *
 * Revision 1.4  2007/09/11 14:09:02  kchunduri
 * --provide option to run POTS on each PX device.
 *
 * Revision 1.3  2007/09/10 10:16:59  kchunduri
 * --Support added to use new multi-card API.
 *
 * Revision 1.2  2007/07/13 13:51:47  tghoriparti
 * N1-Lite changed to Nitrox-Px in log messages
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

