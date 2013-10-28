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
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include "cavium_sysdep.h"
#include "cavium_common.h"
#include "cavium_ioctl.h"

#include "pots.h"
#include "pots_dd.h"


#define VERSION_LEN    32
#define SRAM_ADDRESS_LEN    8
Csp1InitBuffer init;

Uint8 map_eu_mask_to_6bits(int eu_mask);
/* 
 * load_microcode:
 *       - loads the 3 microcodes.
 
*/
int load_microcode(pots_sts *pots_stp)
{
   int rc;
   char *fname[4];         // names of microcode files */

   fname[0] = "load_microcode";
   fname[1] = pots_stp->pt_boot_ucode_fname;
#if 1
   fname[2] = pots_stp->pt_main_ucode_fname;
#else
   fname[2] = pots_stp->pt_admin_ucode_fname;
   fname[3] = pots_stp->pt_main_ucode_fname;
#endif

#if 1
   if ( (rc = pots_load_microcode(pots_stp,-1, 3, fname)) == -1 ) {
#else
   if ( (rc = pots_load_microcode(pots_stp,-1, 4, fname)) == -1 ) {
#endif
      pots_log(PT_LOG_FATAL, 
            "load_microcode: pots_load_microcode() failed\n");
      return(-1);
   }

   pots_stp->pt_ucode_loaded = 1;

#if 0 /* BIST disabled */
   /*
    * now check bist reg, unit enable reg and # of exec units
    * and save these values.
    */
   if ( (rc = check_and_save_ue_cp(pots_stp)) == -1 ) {
      pots_log(PT_LOG_INFO,
         "load_microcode(): check_and_save_ue_cp() failed\n");
      return(-1);
   }
#endif
   return(rc);

}

/*
 * pots_specific_init_code:
 *       - Loads just the boot microcode and does pots
 *         only initialization on the device driver.
 *       - Returns 0 on success and -1 on error.
 */
int pots_specific_init_code(pots_sts *pots_stp, int eu_mask)
{
   int rc;
   char *fname[2];         // names of microcode files */

   fname[0] = "load_microcode";
   fname[1] = pots_stp->pt_pots_ucode_fname;

   if ( (rc = pots_load_microcode(pots_stp,eu_mask, 2, fname)) == -1 ) {
      pots_log(PT_LOG_FATAL, 
            "pots_specific_init_code: pots_load_microcode() failed\n");
      return(-1);
   }

   pots_stp->pt_pots_sp_ucode_loaded = 1;

#if 0
   /*
    * now check bist reg, unit enable reg and # of exec units
    * and save these values.
    */
   if ( (rc = check_and_save_ue_cp(pots_stp)) == -1 ) {
      pots_log(PT_LOG_INFO,
         "pots_specific_init_code(): check_and_save_ue_cp() failed\n");
      return(-1);
   }
#endif

   return(rc);

}

/*
 * pots_load_microcode:
 *       - Loads microcode files passed as args.
 *       - eu_nr is the nr of the EU to which the code will be loaded.
 *         if -1, then it's not used (i.e. all eu's get the microcode).
 */
int pots_load_microcode(pots_sts *pots_stp,int eu_nr, int argc, char *argv[])
{
   int rc = 0;
   int CSP1_driver_handle = -1;
   int size, cnt;
   int fd;
   int i;
   char version[VERSION_LEN+1];
   char sram_address[SRAM_ADDRESS_LEN+1];
   int ioctl_call;
   Uint8 saved_init_size;
      
#ifdef CAVIUM_MULTICARD_API
        char dev_name[32];
        int dev_hdlr = -1;

        if(pots_stp->dev_id)
           sprintf(dev_name,"%s%d",DD_FILENAME,pots_stp->dev_id);
        else
           sprintf(dev_name,"%s",DD_FILENAME);

   if ( (dev_hdlr = open(dev_name, O_RDWR)) == -1 ) 
        {
      pots_log(PT_LOG_FATAL, "pots_load_microcode: open(%s) failed %s <%d>\n",
               dev_name, strerror(errno), errno);
      return(-1);
        }
#else
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
#endif
   memset(&init,0,sizeof(init));   

#if 0
   if ( argc == 2 ) {
      ioctl_call = IOCTL_CSP1_POTS_INIT_CODE;
   }
   else 
#endif
   {
      ioctl_call = IOCTL_N1_INIT_CODE;
   }


   for (i=1; i<argc; i++)
   {
      fd = open(argv[i],O_RDONLY,0);
      if (fd < 0)
      {
         pots_log(PT_LOG_FATAL, 
            "pots_load_microcode: open of ucode file %s failed %s <%d>\n",
            argv[i], strerror(errno), errno);
         rc = -1;
         goto init_error;
         }

      /* version */
      cnt = read(fd,init.version_info[init.size],VERSION_LEN);
      if (cnt != VERSION_LEN) {
         pots_log(PT_LOG_FATAL, 
         "pots_load_microcode: could not read version from file %s\n",
            argv[i]);
         close(fd);

         rc = -1;
         goto init_error;
      }
      version[VERSION_LEN] = 0;
      memcpy(version,init.version_info[init.size],VERSION_LEN);
      pots_log(PT_LOG_DEBUG, "File %s; Version = %32s\n",
            argv[i],version);

      /* code length */
      cnt = read(fd,&init.code_length[init.size],4);
      if (cnt != 4)
      {
         close(fd);
         pots_log(PT_LOG_FATAL, 
               "File %s; Could not read code length\n",argv[i]);
         rc = -1;
         goto init_error;
      }

      /* keep size consistent in byte lengths */
      init.code_length[init.size] = ntohl(init.code_length[init.size])*4;
      size = init.code_length[init.size];
      pots_log(PT_LOG_DEBUG, "File %s; Code length = %d\n",argv[i],size);
   
      /* data length */
           cnt = read(fd,&init.data_length[init.size],4);
      if (cnt != 4)
      {
         pots_log(PT_LOG_FATAL, 
               "File %s; Could not read data length\n",argv[i]);
         close(fd);

         rc = -1;
         goto init_error;
      }

      init.data_length[init.size] = ntohl(init.data_length[init.size]);
      size = init.data_length[init.size];
      pots_log(PT_LOG_DEBUG, 
            "File %s; Data length = %d\n",argv[i],size);
   
      /* sram address */
      cnt = read(fd,init.sram_address[init.size],SRAM_ADDRESS_LEN);
      if (cnt != SRAM_ADDRESS_LEN)
      {
         pots_log(PT_LOG_FATAL, 
               "File %s; Could not read sram address\n",argv[i]);
         close(fd);

         rc = -1;
         goto init_error;
      }
      sram_address[SRAM_ADDRESS_LEN] = 0;
      memcpy(sram_address,init.sram_address[init.size],SRAM_ADDRESS_LEN);
      pots_log(PT_LOG_DEBUG, 
            "File %s; SRAM address = %8s\n",argv[i],sram_address);
      
      /* code */
      size = ROUNDUP16(init.code_length[init.size]);
      init.code[init.size] = CAST_TO_X_PTR(malloc(size));
      cnt = read(fd,CAST_FRM_X_PTR(init.code[init.size]),size); 
      if (cnt != size)
      {
         pots_log(PT_LOG_FATAL, "File %s; Could not read code\n",argv[i]);
         close(fd);

         rc = -1;
         goto init_error;
      }


      /* data */
      size = ROUNDUP16(init.data_length[init.size]);
           init.data[init.size] =CAST_TO_X_PTR(malloc(size));
           cnt = read(fd,CAST_FRM_X_PTR(init.data[init.size]),size);
      if (cnt != size)
      {
         pots_log(PT_LOG_FATAL, "File %s; Could not read data\n",argv[i]);
         close(fd);
         rc = -1;
         goto init_error;
      }

      /* signature */
      cnt = read(fd,init.signature[init.size],256);
      if (cnt != 256)
      {
         pots_log(PT_LOG_FATAL, "File %s; Could not read signature\n",argv[i]);
         close(fd);
         rc = -1;
         goto init_error;
      }

      init.size++;   
      
      close(fd);
   }
    
   /*
    * For the pots specific ioctl, overload the init.size integer
    * to contain not just the number of microcodes being loaded,
    * but also to contain the eu_nr of the EU which should
    * be enabled after the pots specific microcode is loaded.
    * NOTE: init.size is 8 bits. The first 2 bits are used
    *         to specifiy how many microcodes are being loaded.
    *         So, we use the rest of the 6 bits in this way:
    *         bit 0 = for # of microcode being loaded
    *         bit 1 = for # of microcode being loaded
    *         bit 2 = set to 1 if we area specifying some specific eu_nr
    *         bit 3-7 = the nr by which we should shift bit 2 to get
    *                   the eu's mask nr. Note that first bit 2 should
    *                   be shiftted >> 2. Then << shift_by, where
    *                   shift_by is the nr value represented by 
    *                   bits 3-7.
    *    So the driver level call should extract the eu_nr accordingly.
    *       
    */
   saved_init_size = init.size;

   if ( argc == 2 ) {
      if ( eu_nr != -1 )
         //init.size = init.size | (eu_nr <<4);
         saved_init_size = init.size;
         init.size = init.size | (map_eu_mask_to_6bits(eu_nr) << 2);
         pots_log(PT_LOG_DEBUG, 
               "pots_load_microcode(): init.size = %d, 0x%0x\n",
               init.size, init.size);
         pots_log(PT_LOG_DEBUG, "pots eu_nr %ld \n", eu_nr);
   }
   
//   if(ioctl(CSP1_driver_handle,IOCTL_N1_INIT_CODE,(Uint32*)&init) != 0)
#ifdef CAVIUM_MULTICARD_API
   if(ioctl(dev_hdlr,ioctl_call,(Uint32*)&init) != 0)
#else
   if(ioctl(CSP1_driver_handle,ioctl_call,(Uint32*)&init) != 0)
#endif
   {
      pots_log(PT_LOG_FATAL, "CSP1 init failed\n");
      rc = -1;
   }

init_error:

   init.size = saved_init_size;

   for (i=0; i<init.size; i++)
   {
      if (init.code[i])
         free(CAST_FRM_X_PTR(init.code[i]));

      if (init.data[i])
         free(CAST_FRM_X_PTR(init.data[i]));   
   }
 
#ifdef CAVIUM_MULTICARD_API
   if(dev_hdlr != -1)
      close(dev_hdlr);
#else
   if(CSP1_driver_handle != -1)
      close(CSP1_driver_handle);
#endif
   
   return(rc);
}



/*
 * print_ucode_loaded:
 *       - Prints the version of microcode(s) loaded.
 */
int print_ucode_loaded(pots_sts *pots_stp)
{
   int i;
   int s;
   int b;

   if ( ! pots_stp->pt_ucode_loaded ) {
      printf("microcode not loaded\n");
      pots_log(PT_LOG_ALWAYS, "microcode not loaded\n");
      return(0);
   }
   for (i = 0; i < 2; i++) {

      printf("Microcode # %d info:\n", i);
      fprintf(pots_stp->pt_rfp, "\tMicrocode # %d info:\n", i);

      if ( i == 0 ) {
         printf("Ucode file = %s\n", pots_stp->pt_boot_ucode_fname);
         fprintf(pots_stp->pt_rfp, 
               "\tUcode file = %s\n", pots_stp->pt_boot_ucode_fname);
      }
      else if ( i == 1 ) {
         fprintf(pots_stp->pt_rfp, 
            "\tUcode file = %s\n", pots_stp->pt_admin_ucode_fname);
      }
      else if ( i == 2 ) {
         fprintf(pots_stp->pt_rfp, 
            "\tUcode file = %s\n", pots_stp->pt_main_ucode_fname);
      }

      printf("version = %s\n", init.version_info[i]);
      fprintf(pots_stp->pt_rfp, "\tversion = %s\n", init.version_info[i]);

      printf("code length = %d\n", init.code_length[i]);
      fprintf(pots_stp->pt_rfp, "\tcode length = %d\n", init.code_length[i]);

      printf("data length = %d\n", init.data_length[i]);
      fprintf(pots_stp->pt_rfp, "\tdata length = %d\n", init.data_length[i]);

   //   printf("sram address = %8s\n", init.sram_address[i]);

#if 0
      printf("signature = ");
      b = 0;
      for ( s = 0; s < 256; s++) {
         printf("0x%0x ", init.signature[i][s]);
         b++;
         if ( b == 10 ) {
            b = 0;
            printf("\n");
         }
      }
      printf("\n");
#endif

      pots_log(PT_LOG_ALWAYS, "Microcode # %d info:\n", i);

      if ( i == 0 )
         pots_log(PT_LOG_ALWAYS, 
               "Ucode file = %s\n", pots_stp->pt_boot_ucode_fname);
      else if ( i == 1 ) 
         pots_log(PT_LOG_ALWAYS, 
               "Ucode file = %s\n", pots_stp->pt_admin_ucode_fname);
      else if ( i == 2 ) 
         pots_log(PT_LOG_ALWAYS, 
               "Ucode file = %s\n", pots_stp->pt_main_ucode_fname);

      pots_log(PT_LOG_ALWAYS, "version = %s\n", init.version_info[i]);
      pots_log(PT_LOG_ALWAYS, "code length = %d\n", init.code_length[i]);
      pots_log(PT_LOG_ALWAYS, "data length = %d\n", init.data_length[i]);
//      pots_log(PT_LOG_ALWAYS, "sram address = %s\n", init.sram_address[i]);
#if 0
      pots_log(PT_LOG_ALWAYS, "signature = \n\t");
      b = 0;
      for ( s = 0; s < 256; s++) {
         pots_log0(PT_LOG_ALWAYS, "0x%0x ", init.signature[i][s]);
         b++;
         if ( b == 10 ) {
            b = 0;
            pots_log0(PT_LOG_ALWAYS, "\n\t");
         }
      }
      pots_log0(PT_LOG_ALWAYS, "\n");
#endif

   }
   return(1);

} // end print_ucode_loaded()


Uint8 map_eu_mask_to_6bits(int eu_mask)
{
   int i;
   int tempval;
   Uint8 bit6val;

   if ( eu_mask == 0 )
      return(0);

   if ( eu_mask == 1 )
      return(1);

   bit6val = 1;
   for (i = 2; i < 32; i++) {
      tempval = 0x1 << (i-1);
      bit6val = bit6val + 2;
      if ( eu_mask == tempval ) {
         pots_log(PT_LOG_DEBUG, 
      "map_eu_mask_to_6bits(): for eu_mask = 0x%0x, bit6val = 0x%0x\n", 
               eu_mask, bit6val);
         return(bit6val);
      }
   }

   return(0);
}




/*
 * $Id: pots_ucode.c,v 1.8 2009/10/19 09:26:50 aravikumar Exp $
 * $Log: pots_ucode.c,v $
 * Revision 1.8  2009/10/19 09:26:50  aravikumar
 * define SSL removed
 *
 * Revision 1.7  2009/09/09 15:01:46  aravikumar
 * NPLUS macro dependency removed and made it dynamic
 *
 * Revision 1.6  2008/12/22 10:19:31  jrana
 * - BIST disabled
 *
 * Revision 1.5  2008/10/24 08:43:51  ysandeep
 * NPLUS support added
 *
 * Revision 1.4  2008/03/10 10:22:58  kkiran
 *  - Cavium Copyright added.
 *
 * Revision 1.3  2007/09/20 09:52:30  kchunduri
 * --Fix to open correct device in multi-card environment.
 *
 * Revision 1.2  2007/07/14 10:53:09  tghoriparti
 * printing of microcode-3(admin) disabled
 *
 * Revision 1.1  2007/02/20 23:43:29  panicker
 * * Utilities checked in
 *
 * Revision 1.5  2006/05/16 10:19:50  kchunduri
 * --changes to support re-aligned API structures.
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
 * Revision 1.1  2004/04/15 22:40:52  bimran
 * Checkin of the code from India with some cleanups.
 *
 */

