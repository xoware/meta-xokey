/*
 * pots_main:
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
#include <ctype.h>
#include "pots.h"
#include <signal.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include "cavium_sysdep.h"
#include "cavium_common.h"
#include "cavium_ioctl.h"

pots_sts pots_st;
Uint32 device=0;
uint8_t drv_st, ssl=0, ipsec=0, nplus=0, drv_dfl=0;

int microcode_type;
int ssl_mlm;
int is_modex_ok = 0;
Uint32 ssl_core_mask;
Uint32 ipsec_core_mask;
#ifdef CAVIUM_MULTICARD_API
extern int gpkpdev_hdlr[];
#else
extern int CSP1_driver_handle;
#endif

int base_b_offset=0x000;
int px_flag=0;

#ifdef CAVIUM_MULTICARD_API
static void print_dev_option()
{
   Csp1Initialize(CAVIUM_DIRECT, CAVIUM_DEV_ID);
   Csp1GetDevCnt(&pots_st.dev_cnt,&pots_st.dev_mask);
   pots_st.dev_id = CAVIUM_DEV_ID;
   Csp1Shutdown(0);

   printf("\t\t\n");

   printf("\t\tPOTS Test Program\n");
   printf("\t\t=================\n");

   printf("\t\tDetected %d Nitrox parts\n",pots_st.dev_cnt);

   printf("\t\t\n");
   printf("\t\tEnter the chip id : run(0-%d) (or) 'q' to quit: ",(pots_st.dev_cnt-1));
   return;

} /* end print_dev_option() */
#endif

static void print_menu()
{

   printf("\t\t\n");

   printf("\t\tPOTS Test Program\n");
   printf("\t\t=================\n");

//   if (drv_dfl) {
      printf("\t\t  1) Test Soft Reset on the Chip\n");
      printf("\t\t  2) Test loading of microcode only\n");
      printf("\t\t  3) Print version of microcode loaded\n");
//   }
   printf("\t\t  4) Test Read/Write of Chip Registers\n");
   printf("\t\t  5) Check BIST Register Value\n");
   printf("\t\t  6) Test Read/Write of DDR\n");
   printf("\t\t  7) Test Random Number Generation\n");
   printf("\t\t  8) SSL Test Crypto RC4 \n");
   printf("\t\t  9) SSL Test Crypto HMAC\n");
   printf("\t\t 10) SSL Test Crypto 3DES\n");
   printf("\t\t 11) SSL Test Crypto AES\n");
   printf("\t\t 12) Test Crypto MOD_EX\n");
   printf("\t\t 13) SSL Test Key Memory\n");
   printf("\t\t 14) Check UNIT_ENABLE Register Value\n");
   printf("\t\t 15) Check number of exec units\n");
   printf("\t\t 16) Disable Request Unit\n");
   printf("\t\t 17) Enable Request Unit\n");
   printf("\t\t 18) Disable All Exec Units\n");
   printf("\t\t 19) Enable All Exec Units\n");
   printf("\t\t 20) Get Chip CSR Value\n");
   printf("\t\t 21) Get PCI CSR Value\n");
   printf("\t\t 22) Get PCI Config Reg Value\n");
   printf("\t\t 23) IPSec Test Inbound Packet Process\n");
   printf("\t\t 24) IPSec Test Outbound Packet Process\n");

   printf("\t\tall) To Run all of the above tests (in sequence)\n");
   printf("\t\t  q) To Quit\n");

   printf("\t\t\n");

   printf("\t\t\n");
   printf("\t\tEnter the test number to run: ");

   return;

} /* end print_menu() */


/*
 * print_help():
 *    - Prints the help menu for the pots program.
 */
static void print_help()
{
   printf("\tThe POTS Test Suite allows testing of the NITROX Chip.\n");
   printf("\tThe program creates a results.log file which contains\n");
   printf("\ta summary of the test results. In addition a more \n");
   printf("\tdetailed log file, pots.log is created.\n");
}


/*
 * print_test_details():
 *    - Prints the detailed description of what each test 
 *      does/accomplishes.
 */
static void print_test_details(int nr)
{

}


/*
 * get_user_input:
 *       - Gets users input
 *       - Returns 0 on success and -1 on error
 */
static int get_user_input(int *input)
{
   char tempbuf[1024];
   int test_nr;
   
   scanf("%s",tempbuf);

   if (tempbuf == NULL ) {
      pots_log(PT_LOG_ERROR, "get_user_input(): gets() failed\n");
      return(-1);
   }

   /* check if user wants to quit */
   if ( tempbuf[0] == 'q' || tempbuf[0] == 'Q' ) {
     if (drv_dfl) { 
         /* do soft reset before exit */
#ifndef CNS3000
         if ( soft_reset_test(&pots_st) == -1 ) {
            pots_log(PT_LOG_INFO, "get_user_input: \
                     soft_reset_test() failed\n");
         } else {
            pots_log(PT_LOG_INFO, "get_user_input: \
                     soft_reset_test() failed\n");
         }
#endif
      }
#ifdef CAVIUM_MULTICARD_API
      *input = 'Q';
      return -1; 
#else
      exit(0);
#endif
   }
   
   /* check if user wants to run all tests */
   if ( strncasecmp(tempbuf, "all", 3) == 0 ) {
      /* user wants to run all test */
      *input = 0xFFFF;   /* to run all tests */
      return(0);
   }


   if ( ! isdigit(tempbuf[0]) ) {
      pots_log(PT_LOG_WARNING, "get_user_input(): invalid char %c\n", 
            tempbuf[0]);
      printf("ERROR: Invalid user input %s\n", tempbuf);
      printf("-----------------------------------\n\n");
      return(-1);
   }

   test_nr = atoi(tempbuf);

   if ( test_nr < 1 || test_nr >= PT_MAX_TEST ) {

      /* back-door form enable/disbale eu from mask: */
         pots_log(PT_LOG_WARNING, "get_user_input(): \
                    invalid test nr %d\n",
                    test_nr);
         printf("ERROR: Invalid user input %s\n", tempbuf);
         printf("----------------------------------\n\n");
         return(-1);
      }

   pots_log(PT_LOG_DEBUG, "get_user_input(): test to run = %d\n", test_nr);

   *input = test_nr;

   return(0);

} /* end get_user_input() */

#ifdef CAVIUM_MULTICARD_API
static int get_dev_input(int *input)
{
   char tempbuf[1024];
   int test_nr;
   
   scanf("%s",tempbuf);

   if (tempbuf == NULL ) {
      pots_log(PT_LOG_ERROR, "get_dev_input(): gets() failed\n");
      return(-1);
   }
   if ( tempbuf[0] == 'q' || tempbuf[0] == 'Q' ) {
             exit(0);
        }

   if ( ! isdigit(tempbuf[0]) ) {
      pots_log(PT_LOG_WARNING, "get_dev_input(): invalid char %c\n", 
            tempbuf[0]);
      printf("ERROR: Invalid dev input %s\n", tempbuf);
      printf("-----------------------------------\n\n");
      return(-1);
   }

   test_nr = atoi(tempbuf);

   if ( test_nr < 0 || test_nr >= pots_st.dev_cnt ) {

      printf("ERROR: Invalid dev input %s\n", tempbuf);
      printf("----------------------------------\n\n");
      return(-1);
   }

   pots_log(PT_LOG_DEBUG, "get_dev_input(): test to run = %d\n", test_nr);

   *input = test_nr;
   pots_st.dev_id=test_nr;
   pots_init2(&pots_st);

   return(0);

} /* end get_dev_input() */
#endif


/*
 * get_mask_from_user: (for disable/enable eu from mask test)
 *       - Gets users input
 *       - Returns 0 on success and -1 on error
 *       
 */
static int get_mask_from_user(unsigned int *input)
{
   char tempbuf[1024];
   int mask;

   printf("Enter mask in decimal: " );

   scanf("%s",tempbuf); 
   if (tempbuf == NULL ) {
      pots_log(PT_LOG_ERROR, "get_mask_from_user(): gets() failed\n");
      return(-1);
   }

   /* check if user wants to quit */
   if ( tempbuf[0] == 'q' || tempbuf[0] == 'Q' )
         exit(0);
   
   if ( ! isdigit(tempbuf[0]) ) {
      pots_log(PT_LOG_WARNING, "get_mask_from_user(): \
                  invalid char %c\n", tempbuf[0]);
      printf("ERROR: Invalid user input %s\n", tempbuf);
      printf("-----------------------------------\n\n");
      return(-1);
   }

   mask = atoi(tempbuf);

   pots_log(PT_LOG_DEBUG, "get_mask_from_user(): mask = %d, 0x%0x\n",
            mask, mask);

   *input = mask;

   return(0);

} /* end get_mask_from_user() */





/*
 * process_args:
 *       - process arguments passed on the cmd line.
 *       - returns -1 on error
 *       - returns  0 is regular processing 
 *       - returns  1 is all pocessing is done
 */
static int process_args(int argc, char **argv)
{
   char *ptr;
   int len;

   if ( argc > 1 ) {
      ptr = *(argv + 1);
      printf("ptr = %s\n", ptr);
      if ((len = strlen(ptr)) < 2 ) {
         /* cannot be "-h", etc. */
         return(0);
      }
      if ( strncasecmp(ptr, "help", len) == 0 ||
           strncasecmp(ptr, "-help", len) == 0)  {
         print_help();
         return(-1);
      }
      return(0);
   }
   return(0);      /* FOR NOW */

} /* end process_args() */


/*
 * process_test:
 *       - Based upon test_nr passed, calls the appropriate test function
 *       - Returns 0 on success and -1 on error.
 */
static int process_test(int test_nr)
{

   int rc = 0;
   int i;
   unsigned int outval;
   unsigned int mask;
   char maskbuf[100];
   int chk_next=1;

   if (test_nr == PT_NONE) 
      pots_log(PT_LOG_INFO, "process_test(): PT_NONE\n");
   else if(test_nr==PT_ALL) 
   {
      pots_log(PT_LOG_INFO, "process_test(): PT_ALL\n");

      /* run all the tests in sequence from the first to last */
//      for ( i = (drv_dfl)?1:4; i < PT_MAX_TEST; i++) { 
      for ( i = 1; i < PT_MAX_TEST; i++) { 

         if (((rc = process_test(i)) == -1 )){
            /* should we keep going or stop ? */
            pots_log(PT_LOG_ERROR, "process_test(%d) failed\n", i);
            /*
             * based upon input from Randy,
             * stop upon first failure 
             */
            return(rc);
         }
      } 
   }      
   else {
      switch (test_nr) {
         case   PT_INBOUND_TEST:
            rc = Csp1TestInboundPacketProcess(&pots_st);
            break;
         case   PT_OUTBOUND_TEST:
            rc = Csp1TestOutboundPacketProcess(&pots_st);
            break;
         case   PT_SOFT_RESET:
            if (!drv_dfl) 
               printf ("Soft reset not Supported\n");
            else
               rc = Csp1TestSoftReset(&pots_st);
            break;
         case    PT_LOAD_MICROCODE:
         if (!drv_dfl) 
            printf ("Load microcode on specified cores not added\n");
         else 
            rc = Csp1TestUcodeLoad(&pots_st);
            break;
         case    PT_ARBITER:
            rc = Csp1TestArbiter(&pots_st);
            break;

         case    PT_ENDIAN_TEST:
            rc = Csp1EndianTest(&pots_st);
            break;
         case    PT_RANDOM_NR_GEN:
            if (!drv_dfl) 
               printf ("Random Number Test Not Supported\n");
            else 
               rc = Csp1TestRandomNumbers(&pots_st);
            break;
         case    PT_INTERRUPT:
            rc = Csp1TestInterrupts(&pots_st);
            break;
         case    PT_UCODE_LOADED:
            if (!drv_dfl) 
               printf ("Microcode not loaded from the pots\n");
            else 
               rc = Csp1GetUcodeVersions(&pots_st);
            break;
         case PT_POTS_SP_INIT_CODE:
            rc = Csp1PotsSpecificUcodeLoad(&pots_st);
            break;
         case PT_TEST_CORES_FOR_SELF_ID_INS:
            rc = Csp1TestAllCoresForSelfIDIns(&pots_st);
            break;
         case   PT_KEY_MEMORY:
            rc = Csp1TestKeyMemAndDMA(&pots_st);
            break;
         case   PT_READ_WRITE_DDR:
            rc = Csp1TestLocalMem(&pots_st);
            break;
         case   PT_CRYPTO_RC4:
            /* test RC4 */
            rc = Csp1TestRC4(&pots_st);
            break;
         case   PT_CRYPTO_HMAC:
            /* test hmac */
            rc = Csp1TestHMAC(&pots_st);
            break;
         case   PT_CRYPTO_3DES:
            /* test 3DES */
            rc = Csp1Test3DES(&pots_st);
            break;
         case   PT_CRYPTO_AES:
            if(device==N1_DEVICE)
            {
               #if defined(MC2)&& !defined(RAW_AES)                
               printf("\n AES on N1 is not supported for MC2 \n");
               rc=0;
               #else
               rc = Csp1TestAES(&pots_st);
               #endif                     
            }
            else{
               rc = Csp1TestAES(&pots_st);
            }
            break;
         case    PT_CHECK_UNIT_ENABLE_REG:
            rc = Csp1GetUnitEnableRegVal(&pots_st, &outval);
            break;
         case    PT_CHECK_NR_EXEC_UNITS:
            rc = Csp1GetExecUnitsAvailable(&pots_st, &outval);
            break;
         case PT_ENABLE_EU_FROM_MASK:
         case PT_DISABLE_EU_FROM_MASK:
                 /* mask set to what ? */
            get_mask_from_user(&mask);
         case PT_DISABLE_RU:
         case PT_ENABLE_RU:
         case PT_DISABLE_ALL_EU:
         case PT_ENABLE_ALL_EU:
            rc = Csp1DoRequestUnitOperation(&pots_st, test_nr, mask);
           break;
/*       case PT_GET_DDR_SIZE:
            rc = Csp1GetDDRSize(&pots_st, &outval);
            break;*/
         case PT_GET_CHIP_CSR:
            rc = Csp1GetChipCSR(&pots_st, &outval);
            break;
         case PT_GET_PCI_CSR:
            rc = Csp1GetPciCSR(&pots_st, &outval);
            break;
         case PT_GET_PCI_CONFIG_REG:
            rc = Csp1GetPciConfigReg(&pots_st, &outval);
            break;
       case   PT_CHECK_BIST_REG:
           if (px_flag == 1)  {
              printf ("BIST Register Check not supported for Nitrox_Px\n");
              break;
           }
           if (!drv_dfl) 
              printf ("BIST Register check not supported\n");
            else {
               reg_r_w_flg = 0 ;
               rc = Csp1GetBISTRegVal(&pots_st, &outval);
            }
            break;
         case PT_CRYPTO_MOD_EX:
            if (device == N1_DEVICE)
               printf ("This operation not supported in N1 device...\n");
/*            else if(!drv_dfl && ssl_core_mask < 2)
            printf("\n MODEx operation requires atleast 2 SSL cores:\n"); */
            else
            rc = Csp1TestModEx(&pots_st);
            break;
         case PT_POTS_SOFT_RESET:
            rc = Csp1PotsSpecificSoftReset(&pots_st);
            break;
         case PT_READ_WRITE_REGS:
            reg_r_w_flg = 1 ;
            rc = Csp1TestReadWriteRegs(&pots_st);
            reg_r_w_flg = 0 ;
            break;
         case   PT_MAX_TEST:
            pots_log(PT_LOG_INFO, "process_test(): \
                     PT_MAX_TEST, invalid test nr %d\n",
                     test_nr);
            break;
         case PT_NO_OP:
            break;
         default:
            pots_log(PT_LOG_INFO, "process_test(): \
                     default, invalid test nr %d\n", 
                     test_nr);
            return(-1);

      } /* end switch */
   }
   return(rc);

} /* end process_test() */

main(int argc, char **argv)
{

   int rc;
   int done;
   int test_nr;

   Csp1CoreAssignment core_assign;
   
#ifdef CAVIUM_MULTICARD_API
   if(Csp1Initialize(CAVIUM_DIRECT, CAVIUM_DEV_ID))
#else
   if(Csp1Initialize(CAVIUM_DIRECT))
#endif
      return 0;
   if(Csp1GetDevType(&device))
      return 0;
   if(device==NPX_DEVICE){
      base_b_offset=0x0100;
      px_flag=1;
   }
   else{
      base_b_offset=0x0000;
   }

#ifdef CAVIUM_MULTICARD_API
   if(ioctl(gpkpdev_hdlr[CAVIUM_DEV_ID], IOCTL_N1_GET_DRIVER_STATE, (uint8_t *)&drv_st)!= 0)
#else
   if(ioctl(CSP1_driver_handle, IOCTL_N1_GET_DRIVER_STATE, (uint8_t *)&drv_st)!= 0)
#endif
   {
      printf ("CSP1 failed to get driver state\n");
      exit (0);
   }
   if (drv_st == DRV_ST_UNKNOWN) {
      printf ("Driver state unknown\n");
      exit (0);
   }
   switch (drv_st)
   {
      case DRV_ST_SSL_CORES:
      case DRV_ST_IPSEC_CORES:
      case DRV_ST_SSL_IPSEC:

#ifdef CAVIUM_MULTICARD_API
      if(ioctl(gpkpdev_hdlr[CAVIUM_DEV_ID], IOCTL_CSP1_GET_CORE_ASSIGNMENT, (Uint32 *)&core_assign)!= 0)
#else
      if(ioctl(CSP1_driver_handle, IOCTL_CSP1_GET_CORE_ASSIGNMENT, (Uint32 *)&core_assign)!= 0)
#endif
      {
          printf("CSP1 failed to get core assignments\n");
          exit(0);
      }
      if (drv_st == DRV_ST_SSL_IPSEC) {
         ssl_core_mask = core_assign.core_mask[UCODE_IDX];
         ipsec_core_mask = core_assign.core_mask[UCODE_IDX+1];
         nplus=1;
      }
      else if (drv_st == DRV_ST_SSL_CORES) {
         ssl=1;
         ssl_core_mask = core_assign.core_mask[UCODE_IDX];
      }
      else {
         ipsec=1;
         ipsec_core_mask = core_assign.core_mask[UCODE_IDX];
      }
      break;
      default: 
         drv_dfl = 1;
         ssl = (drv_st == DRV_ST_SSL_DFL) ? 1:0;
         ipsec = (drv_st == DRV_ST_IPSEC_DFL) ? 1:0;

   }

   if (nplus) {
      system ("ln -sf ../../bin/main_ssl.out ./main_ssl.out");
      system ("ln -sf ../../bin/main_ipsec.out ./main_ipsec.out");
   }
   else if (ssl)
      system ("ln -sf ../../bin/main_ssl.out ./main_ssl.out");
   else 
      system ("ln -sf ../../bin/main_ipsec.out ./main_ipsec.out");
   /* process args passed on cmd line */
   if ( (rc =  process_args(argc, argv)) != 0 )
      exit(0);
   printf("POTS: process args done\n");

   /* initialize the pots env. */
   if ( (rc = pots_init(&pots_st)) == -1 ) {
      printf("main(): pots_init() failed\n");
      exit(0);
   }
   printf("POTS: pots init done\n");

   pots_log(PT_LOG_ALWAYS, "main(): pots_init() done\n");
#ifdef CAVIUM_MULTICARD_API
   Csp1Shutdown(CAVIUM_DEV_ID);
#else
   Csp1Shutdown();
#endif
   done = 0;
   while ( ! done ) {

#ifdef CAVIUM_MULTICARD_API
      print_dev_option();
      if ( get_dev_input(&test_nr) == -1 ) {
         pots_log(PT_LOG_WARNING, "main(): \
                     get_dev_input() failed\n");
         continue;
      }
#endif

GET_USER_INPUT:

      print_menu();
      
      if ( get_user_input(&test_nr) == -1 ) {
         pots_log(PT_LOG_WARNING, "main(): \
                     get_user_input() failed\n");
#ifdef CAVIUM_MULTICARD_API
            if(test_nr == 'Q')
               continue;
            else
               goto GET_USER_INPUT;
#else
         continue;
#endif
      }
      

      if ( process_test(test_nr) == -1 ) {
         pots_log(PT_LOG_ERROR, "main(): \
                   process_test() failed\n");
         ;   /* keep going!!! */
      }
#ifdef CAVIUM_MULTICARD_API
      goto GET_USER_INPUT;
#endif
      

   } /* end while */

} /* end main() */


/*
 * $Id: pots_main.c,v 1.25 2009/10/19 09:24:56 aravikumar Exp $
 * $Log: pots_main.c,v $
 * Revision 1.25  2009/10/19 09:24:56  aravikumar
 * SSL and IPSec words added in print_menu
 *
 * Revision 1.24  2009/09/24 13:34:57  aravikumar
 * Check added for BIST Test and made print_menu list constant.
 *
 * Revision 1.23  2009/09/22 09:57:08  aravikumar
 * made list of test options to constant for both plus and non-nplus
 *
 * Revision 1.22  2009/09/15 05:39:55  aravikumar
 * MOD_EX support added for ipsec also and indentation
 *
 * Revision 1.21  2009/09/09 15:01:46  aravikumar
 * NPLUS macro dependency removed and made it dynamic
 *
 * Revision 1.20  2008/12/02 04:59:08  ysandeep
 * removed error messages for RC4 and MODEx for N1_DEVICE
 *
 * Revision 1.19  2008/11/27 13:37:26  ysandeep
 * Fixed bug for NPLUS
 *
 * Revision 1.18  2008/11/26 13:07:05  ysandeep
 * fixed bugs for N1_DEVICE
 *
 * Revision 1.17  2008/11/21 06:32:26  ysandeep
 * ModEx is performed if more than 1 ssl core is available (NPLUS)
 *
 * Revision 1.16  2008/11/11 06:31:55  ysandeep
 * fixed bug for N1/NLite multicard NPLUS mode
 *
 * Revision 1.15  2008/11/05 06:45:57  ysandeep
 * Added NPLUS support for N1/NLite
 *
 * Revision 1.14  2008/10/31 10:51:29  ysandeep
 * MULTICARD support added for ipsec.
 * nplus_handle removed (NPLUS).
 *
 * Revision 1.13  2008/10/24 08:43:51  ysandeep
 * NPLUS support added
 *
 * Revision 1.12  2008/08/14 05:23:04  aramesh
 * delted printfs.
 *
 * Revision 1.11  2008/07/14 10:46:06  aramesh
 * removed N1 printfs.
 *
 * Revision 1.10  2008/07/11 08:29:57  aramesh
 * device type isused for determining N1 device.
 *
 * Revision 1.9  2008/07/07 12:40:14  aramesh
 * dev_mask is used.
 *
 * Revision 1.8  2008/07/03 12:08:10  aramesh
 * Used Csp1GetDevType API.
 *
 * Revision 1.7  2008/07/03 05:22:58  aramesh
 * deleted NITROX_PX flag.
 *
 * Revision 1.6  2008/03/10 10:22:58  kkiran
 *  - Cavium Copyright added.
 *
 * Revision 1.5  2008/01/18 07:58:39  tghoriparti
 * IPSEC random test number changed to 5 and option "all" to run all the tests
 *
 * Revision 1.4  2007/09/20 09:52:30  kchunduri
 * --Fix to open correct device in multi-card environment.
 *
 * Revision 1.3  2007/09/11 14:09:02  kchunduri
 * --provide option to run POTS on each PX device.
 *
 * Revision 1.2  2007/07/31 11:14:56  tghoriparti
 * all will run all the tests
 *
 * Revision 1.1  2007/02/20 23:43:29  panicker
 * * Utilities checked in
 *
 * Revision 1.11  2006/11/02 10:42:22  kanantha
 * resetting the r_w_flag after the TestReadWriteRegs, or else few testcases fails with random test order
 *
 * Revision 1.10  2006/09/01 15:25:12  kchunduri
 * support for SSLb version micro-code which has RAW_AES mode.
 *
 * Revision 1.9  2005/11/17 13:31:09  kanantha
 * Updating with the 64 bit modifications, with proper matching of data types
 *
 * Revision 1.8  2005/10/04 07:32:06  sgadam
 * - Key memory test and BIST tests swapped
 *
 * Revision 1.7  2005/09/29 13:50:17  sgadam
 * RC4 pots test has been removed for MC2
 *
 * Revision 1.6  2005/09/27 07:21:52  sgadam
 * AES pots test has been removed for N1 with MC2
 *
 * Revision 1.5  2005/09/27 05:22:11  sgadam
 * Warning fixed
 *
 * Revision 1.4  2005/08/31 17:21:40  bimran
 * Fixed a lot of warnings.
 *
 * Revision 1.3  2005/05/21 05:17:31  rkumar
 * Merge with India CVS Head
 *
 * Revision 1.2  2004/04/16 00:05:41  bimran
 * Fixed compilation issues/warnings.
 *
 * Revision 1.1  2004/04/15 22:40:51  bimran
 * Checkin of the code from India with some cleanups.
 *
 */

