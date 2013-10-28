/*
 * pots_init.c:
 *      - Does initiliation for pots program.
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
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>


#include "cavium_sysdep.h"
#include "cavium_common.h"

#include "pots.h"
#include "pots_proto.h"

extern uint8_t nplus, ssl;
/*
 * pots_init:
 *       - Initializes various configuration parameters for the
 *         pots program.
 */
int pots_init(pots_sts *pots_stp)
{

   int rc;
   unsigned long outval;

   /* open log file */
   if ( (pots_stp->pt_lfp = pots_open_file(PT_LOG_FNAME)) == NULL ) {
      printf("main(): pots_open_log() failed\n");
      return(-1);
   }

   pots_stp->pt_prog_loglvl = PT_LOG_ALWAYS;
   /***
   pots_stp->pt_prog_loglvl =    PT_LOG_FATAL | 
                        PT_LOG_SEVERE |
                                PT_LOG_ERROR |
                           PT_LOG_WARNING |
                           PT_LOG_INFO;
   ***/
   pots_log(PT_LOG_ALWAYS, "Log file opened\n");
   pots_log(PT_LOG_INFO, "Log file opened %s, %d, %s\n", "s1", 5, "s2");

   /* setup default values for the crypto tests */
   if ( pots_crypto_def_vals(pots_stp) == -1 ) {
      printf("pots_init(): pots_config() failed\n");
      return(-1);
   }

   /* open and read the pots configuration */
   if ( pots_config(pots_stp) == -1 ) {
      printf("pots_init(): pots_config() failed\n");
      ;   // keep going, we'll use the default values 
   }

   /* open the results file */
   if ( (pots_stp->pt_rfp = pots_open_file(PT_RESULTS_FNAME)) == NULL ) {
      printf("main(): pots_open_rf() failed\n");
      return(-1);
   }


   /* Get names of boot, admin and main microcode files */
   // FOR NOW!!!
   strcpy(pots_stp->pt_boot_ucode_fname, PT_BOOT_FNAME);
//#ifndef MC2
//   strcpy(pots_stp->pt_admin_ucode_fname, PT_ADMIN_FNAME);
//#endif
//   if (nplus)
//      strcpy(pots_stp->pt_main_ucode_fname, PT_MAIN_FNAME);
//   else {
      if (ssl)
         strcpy(pots_stp->pt_main_ucode_fname, PT_MAIN_SSL_FNAME);
      else
         strcpy(pots_stp->pt_main_ucode_fname, PT_MAIN_IPSEC_FNAME);
//   }
   strcpy(pots_stp->pt_pots_ucode_fname, PT_POTS_UCODE_FNAME);

   /*
    * open the device driver
    */
   if ( (pots_stp->pt_dd_fd = open(DD_FILENAME, O_RDWR)) == -1 ) {
      printf("pots_init(): open(%s) failed %s <%d>\n",
            DD_FILENAME, strerror(errno), errno);
      pots_close_log(pots_stp->pt_lfp);
      return(-1);
   }

#ifndef CNS3000
   /* get and save bar0 and bar2 value */
   rc = pots_get_bar_value(pots_stp->pt_dd_fd, 
                     "bar0", 
                     &pots_stp->pt_bar0);
   if ( rc == -1 ) {
      pots_log(PT_LOG_FATAL, 
            "pots_init(): pots_get_bar_value(bar0) failed\n");
      close(pots_stp->pt_dd_fd);
      pots_close_log(pots_stp->pt_lfp);
      return(-1);
   }
   printf("POTS: Bar0 @ 0x%lx\n", pots_stp->pt_bar0);

   rc = pots_get_bar_value(pots_stp->pt_dd_fd, 
                     "bar2", 
                     &pots_stp->pt_bar2);
   if ( rc == -1 ) {
      pots_log(PT_LOG_FATAL,
            "pots_init(): pots_get_bar_value(bar2) failed\n");
      close(pots_stp->pt_dd_fd);
      pots_close_log(pots_stp->pt_lfp);
      return(-1);
   }
   printf("POTS: Bar2 @ 0x%lx\n", pots_stp->pt_bar2);
#endif
   /* 
    * Should the 3 microcodes (boot.out, admin.out and
    * main.out be automatically loaded when program starts ?
    * Note: Read this from conf file. 
    */
   pots_stp->pt_load_ucode_on_startup = 0;   // FOR NOW
   //pots_stp->pt_load_ucode_on_startup = 0;   // FOR NOW
   

   /*
    * Load ucode(s) if specified.
    */
   if ( pots_stp->pt_load_ucode_on_startup ) {
      
      pots_log(PT_LOG_INFO, "pots_init: loading ucode on startup\n");

      if ( (rc = load_microcode(pots_stp)) == -1 ) {
         pots_log(PT_LOG_FATAL,
            "pots_init(): load_microcode() failed\n");
         close(pots_stp->pt_dd_fd);
         pots_close_log(pots_stp->pt_lfp);
         return(-1);
      }

      // ucode loaded
      pots_log(PT_LOG_INFO, "process_test(): load_microcode() worked\n");
      
      /*
       * now check bist reg, unit enable reg and # of exec units
       * and save these values.
       */
      if ( (rc = check_bist_reg(pots_stp, &outval)) == -1 ) {
         pots_log(PT_LOG_ERROR,
            "pots_init(): check_bist_reg() failed\n");

         /* 
          * Note:
          *       We get here, if only boot ucode is loaded,
          *       the last time pots_main program exited.
          *       We just loaded the 3 ucodes (above);
          *       Now try to restore BIST sanity, by
          *       doing a "regular" soft reset.
          *
          */
         if ( (rc = soft_reset_test(pots_stp)) == -1 ) {
            pots_log(PT_LOG_FATAL, 
                  "pots_init(): soft_reset_test() failed\n");
            close(pots_stp->pt_dd_fd);
            pots_close_log(pots_stp->pt_lfp);
            return(-1);
         }
         else {
            pots_log(PT_LOG_INFO, 
                  "pots_init(): soft_reset_test() worked\n");
         }
      }

      /* save the bist reg value */
      pots_stp->pt_bist_regval = outval;

      if ( (rc = check_unit_enable_reg(pots_stp, &outval)) == -1 ) {
         pots_log(PT_LOG_ERROR,
            "pots_init(): check_unit_enable_reg() failed\n");
         close(pots_stp->pt_dd_fd);
         pots_close_log(pots_stp->pt_lfp);
         return(-1);
      }
      /* save the unit enable reg value */
      pots_stp->pt_cores_enabled = outval;

      if ( (rc = get_exec_units(pots_stp, &outval)) == -1 ) {
         pots_log(PT_LOG_ERROR,
            "pots_init(): get_exec_units() failed\n");
         close(pots_stp->pt_dd_fd);
         pots_close_log(pots_stp->pt_lfp);
         return(-1);
      }
      /* save the mask for the exec units that exist */
      pots_stp->pt_cores_present = outval;
      
   } // end if load microcode on startup
   else {
      /*
       * Get and save cores enabled and present 
        */
#ifndef CNS3000
      if ( (rc = check_and_save_ue_cp(pots_stp)) == -1 ) {
         pots_log(PT_LOG_ERROR,
            "pots_init(): check_and_save_ue_cp() failed\n");
         // keep going
      }
#endif
   if (CSP1_driver_handle < 0)
   {
      CSP1_driver_handle = open(DD_FILENAME, O_RDWR);
      if (CSP1_driver_handle < 0) {
         pots_log(PT_LOG_FATAL, 
               "pots_load_microcode: open(%s) failed %s <%d>\n",
               DD_FILENAME, strerror(errno), errno);
         return(-1);
      }
   }
   }

   pots_log(PT_LOG_INFO, "pots_init(): initialization successful\n");

   return(0);

} // end pots_init()

/*This function is invoked only in multi-card environment.*/
#ifdef CAVIUM_MULTICARD_API
int pots_init2(pots_sts *pots_stp)
{

   int rc;
   unsigned long outval;
        char dev_name[32];
        static int prev_dev_id=0;
   /*
    * open the device driver
    */
        if(pots_stp->dev_id == prev_dev_id)
        {
           return 0;
        }
        prev_dev_id = pots_stp->dev_id;

        if(pots_stp->pt_dd_fd > 0)
           close(pots_stp->pt_dd_fd);

        if(pots_stp->dev_id)
           sprintf(dev_name,"%s%d",DD_FILENAME,pots_stp->dev_id);
        else
           sprintf(dev_name,"%s",DD_FILENAME);

   if ( (pots_stp->pt_dd_fd = open(dev_name, O_RDWR)) == -1 ) 
        {
      printf("pots_init2(): open(%s) failed %s <%d>\n",
            dev_name, strerror(errno), errno);
      pots_close_log(pots_stp->pt_lfp);
      return(-1);
   }

   /* get and save bar0 and bar2 value */
   rc = pots_get_bar_value(pots_stp->pt_dd_fd, 
                     "bar0", 
                     &pots_stp->pt_bar0);
   if ( rc == -1 ) {
      pots_log(PT_LOG_FATAL, 
            "pots_init2(): pots_get_bar_value(bar0) failed\n");
      close(pots_stp->pt_dd_fd);
      pots_close_log(pots_stp->pt_lfp);
      return(-1);
   }
   printf("POTS: Bar0 @ 0x%lx\n", pots_stp->pt_bar0);

   rc = pots_get_bar_value(pots_stp->pt_dd_fd, 
                     "bar2", 
                     &pots_stp->pt_bar2);
   if ( rc == -1 ) {
      pots_log(PT_LOG_FATAL,
            "pots_init2(): pots_get_bar_value(bar2) failed\n");
      close(pots_stp->pt_dd_fd);
      pots_close_log(pots_stp->pt_lfp);
      return(-1);
   }
   printf("POTS: Bar2 @ 0x%lx\n", pots_stp->pt_bar2);

   /*
    * Load ucode(s) if specified.
    */
   if ( pots_stp->pt_load_ucode_on_startup ) {
      
      pots_log(PT_LOG_INFO, "pots_init2: loading ucode on startup\n");

      if ( (rc = load_microcode(pots_stp)) == -1 ) {
         pots_log(PT_LOG_FATAL,
            "pots_init2(): load_microcode() failed\n");
         close(pots_stp->pt_dd_fd);
         pots_close_log(pots_stp->pt_lfp);
         return(-1);
      }

      // ucode loaded
      pots_log(PT_LOG_INFO, "process_test(): load_microcode() worked\n");
      
      /*
       * now check bist reg, unit enable reg and # of exec units
       * and save these values.
       */
      if ( (rc = check_bist_reg(pots_stp, &outval)) == -1 ) {
         pots_log(PT_LOG_ERROR,
            "pots_init2(): check_bist_reg() failed\n");

         /* 
          * Note:
          *       We get here, if only boot ucode is loaded,
          *       the last time pots_main program exited.
          *       We just loaded the 3 ucodes (above);
          *       Now try to restore BIST sanity, by
          *       doing a "regular" soft reset.
          *
          */
         if ( (rc = soft_reset_test(pots_stp)) == -1 ) {
            pots_log(PT_LOG_FATAL, 
                  "pots_init2(): soft_reset_test() failed\n");
            close(pots_stp->pt_dd_fd);
            pots_close_log(pots_stp->pt_lfp);
            return(-1);
         }
         else {
            pots_log(PT_LOG_INFO, 
                  "pots_init2(): soft_reset_test() worked\n");
         }
      }

      /* save the bist reg value */
      pots_stp->pt_bist_regval = outval;

      if ( (rc = check_unit_enable_reg(pots_stp, &outval)) == -1 ) {
         pots_log(PT_LOG_ERROR,
            "pots_init2(): check_unit_enable_reg() failed\n");
         close(pots_stp->pt_dd_fd);
         pots_close_log(pots_stp->pt_lfp);
         return(-1);
      }
      /* save the unit enable reg value */
      pots_stp->pt_cores_enabled = outval;

      if ( (rc = get_exec_units(pots_stp, &outval)) == -1 ) {
         pots_log(PT_LOG_ERROR,
            "pots_init2(): get_exec_units() failed\n");
         close(pots_stp->pt_dd_fd);
         pots_close_log(pots_stp->pt_lfp);
         return(-1);
      }
      /* save the mask for the exec units that exist */
      pots_stp->pt_cores_present = outval;
      
   } // end if load microcode on startup
   else {
      /*
       * Get and save cores enabled and present 
        */
      if ( (rc = check_and_save_ue_cp(pots_stp)) == -1 ) {
         pots_log(PT_LOG_ERROR,
            "pots_init2(): check_and_save_ue_cp() failed\n");
         // keep going
      }
      
   }

   pots_log(PT_LOG_INFO, "pots_init2(): initialization successful\n");

   return(0);

} // end pots_init2()
#endif

/*
 * $Id: pots_init.c,v 1.5 2009/09/09 15:01:46 aravikumar Exp $
 * $Log: pots_init.c,v $
 * Revision 1.5  2009/09/09 15:01:46  aravikumar
 * NPLUS macro dependency removed and made it dynamic
 *
 * Revision 1.4  2008/10/24 08:43:51  ysandeep
 * NPLUS support added
 *
 * Revision 1.3  2008/03/10 10:22:58  kkiran
 *  - Cavium Copyright added.
 *
 * Revision 1.2  2007/09/20 09:52:30  kchunduri
 * --Fix to open correct device in multi-card environment.
 *
 * Revision 1.1  2007/02/20 23:43:29  panicker
 * * Utilities checked in
 *
 * Revision 1.3  2005/08/31 17:21:40  bimran
 * Fixed a lot of warnings.
 *
 * Revision 1.2  2005/05/21 05:17:31  rkumar
 * Merge with India CVS Head
 *
 * Revision 1.1  2004/04/15 22:40:51  bimran
 * Checkin of the code from India with some cleanups.
 *
 */

