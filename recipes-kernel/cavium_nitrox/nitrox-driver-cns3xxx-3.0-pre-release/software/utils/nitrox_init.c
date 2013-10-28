/* nplus_init.c */
/*
 * Copyright (c) 2003-2005 Cavium Networks (support@cavium.com). All rights 
 * reserved.
 * 
 * Redistribution and use in source and binary forms, with or without 
 * modification, are permitted provided that the following conditions are met:
 * 
 * 1. Redistributions of source code must retain the above copyright notice, 
 * this list of conditions and the following disclaimer.
 * 
 * 2. Redistributions in binary form must reproduce the above copyright notice, 
 *    this list of conditions and the following disclaimer in the documentation 
 *    and/or other materials provided with the distribution.
 * 
 * 3. All advertising materials mentioning features or use of this software 
 *    must display the following acknowledgement:
 * 
 *   This product includes software developed by Cavium Networks
 * 
 * 4. Cavium Networks' name may not be used to endorse or promote products 
 *    derived from this software without specific prior written permission.
 * 
 * 5. User agrees to enable and utilize only the features and performance 
 *    purchased on the target hardware.
 * 
 * This Software,including technical data,may be subject to U.S. export control 
 * laws, including the U.S. Export Administration Act and its associated 
 * regulations, and may be subject to export or import regulations in other 
 * countries.You warrant that You will comply strictly in all respects with all 
 * such regulations and acknowledge that you have the responsibility to obtain 
 * licenses to export, re-export or import the Software.

 * TO THE MAXIMUM EXTENT PERMITTED BY LAW, THE SOFTWARE IS PROVIDED "AS IS" AND 
 * WITH ALL FAULTS AND CAVIUM MAKES NO PROMISES, REPRESENTATIONS OR WARRANTIES, 
 * EITHER EXPRESS,IMPLIED,STATUTORY, OR OTHERWISE, WITH RESPECT TO THE SOFTWARE,
 * INCLUDING ITS CONDITION,ITS CONFORMITY TO ANY REPRESENTATION OR DESCRIPTION, 
 * OR THE EXISTENCE OF ANY LATENT OR PATENT DEFECTS, AND CAVIUM SPECIFICALLY 
 * DISCLAIMS ALL IMPLIED (IF ANY) WARRANTIES OF TITLE, MERCHANTABILITY, 
 * NONINFRINGEMENT,FITNESS FOR A PARTICULAR PURPOSE,LACK OF VIRUSES, ACCURACY OR
 * COMPLETENESS, QUIET ENJOYMENT, QUIET POSSESSION OR CORRESPONDENCE TO 
 * DESCRIPTION. THE ENTIRE RISK ARISING OUT OF USE OR PERFORMANCE OF THE 
 * SOFTWARE LIES WITH YOU.
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/fcntl.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include "cavium_sysdep.h"
#include "cavium_common.h"
#include "cavium_ioctl.h"

/*
 *   cavium_init stuff
 */

#define MAX_LEN 50
#define COMMON_PATH "../microcode/"
#define MAIN_SSL     "main_ssl2"
#define PLUS_SSL     "plus_ssl2"
#define MAIN_IPSEC   "main_ipsec2"
#define PLUS_IPSEC   "plus_ipsec2"
#define BOOT_FILE    "boot_mc2"
#define MAX_CORES_NITROX   24

/* Ucode structure */
char ucode_list[MICROCODE_MAX][MAX_LEN];

struct ucode {
    char *path;
    int ucode_idx;
    Uint32 cores;
};

Uint32 device = 0;

#define VERSION_LEN    32
#define SRAM_ADDRESS_LEN    8

#ifdef CAVIUM_DEBUG
#define   DEBUG_PRINT(x)      printf x
#else
#define   DEBUG_PRINT(x)
#endif

int Csp1_handle = -1;

int ssl_cores =-1;
int ipsec_cores =-1;
char part_num[10];
short ssl=-1, nplus=0,cores=0;

void usage (char *s)
{
   printf ("\nError: Wrong argument list, Usage as follows...\n");
   printf ("\nFor Nplus: \n\t%s[Nitrox Part Number] ssl=<No_of_cores> ipsec=<no_of_cores>\n", s);
   printf ("For Non-Nplus: \n\t%s[Nitrox Part Number] ssl/ipsec=<no_of_cores>\n", s);
   printf ("\t  If no_of_cores not mentioned with protocol it uses all available cores\n");
   printf ("'<No_of_cores>' should not be a negative number\n\n");
}   

/* parse_args: check for nplus or non-nplus patterns along with part_number
 * if it is nplus pattern like: 
 *      ./command [Nitrox Part Number] ssl=<no_of_cores> ipsec=<no_of_cores> 
 * if it is non-nplus pattern like: 
 *      ./command [Nitrox Part Number] ssl/ipsec=<no_of_cores>
 */

int parse_args (int argc, char *argv[])
{
   char *str_indx=0, *str_indx1=0, *argv_ptr;
   int str_len, str_len1, num=-1;
   int cmd_indx=0;

   if (argc > 1) {
      if (!strncmp (argv[1], "CN", 2)) 
      {
         strcpy(part_num,argv[1]);
         if (argc > 2) 
            cmd_indx=2;
      }
      else 
         cmd_indx=1;
   }
   else {
      return -1;
   }
   if (argc == cmd_indx+1) {
      argv_ptr = argv[cmd_indx];
      str_len = strlen(argv_ptr);
/*
      if ((!strncmp(argv_ptr, "ipsec=", 6))||(!strncmp(argv_ptr, "IPSEC=", 6))) 
         ipsec_cores=0;
      else if ((!strncmp(argv_ptr, "ssl=",4))||(!strncmp(argv_ptr, "SSL=",4))) 
         ssl_cores=0;*/
/*      else */ if((str_indx = strchr(argv_ptr, '=')) && 
               (++str_indx < argv_ptr+str_len))
      {   
         if ((!strncmp(argv_ptr,"ssl",3)) || (!strncmp(argv_ptr,"SSL",3))) {
/*            num=atoi(str_indx);
            if (num == 0) return -1;*/
            ssl_cores=atoi(str_indx);
         }
         else if ((!strncmp(argv_ptr,"ipsec",5))||(!strncmp(argv_ptr,"IPSEC",5))) {
/*            num=atoi(str_indx);
            if (num == 0) return -1;*/
            ipsec_cores=atoi(str_indx);
         }
      }
      else 
         return -1;
   }
   else if (argc > cmd_indx+1) {
      str_len = strlen (argv[cmd_indx]);
      str_len1 = strlen (argv[cmd_indx+1]);
      
      if ((!strncmp(argv[cmd_indx], "SSL=", 4) &&
          !strncmp(argv[cmd_indx+1], "IPSEC=", 6)) ||
          (!strncmp(argv[cmd_indx], "ssl=", 4) &&
          !strncmp(argv[cmd_indx+1], "ipsec=", 6)))
      {
         if ((str_indx = strchr(argv[cmd_indx], '=')) &&
             (++str_indx < argv[cmd_indx]+str_len) &&
             (str_indx1 = strchr(argv[cmd_indx+1], '=')) &&
             (++str_indx1 < argv[cmd_indx+1]+str_len1)) 
         {
            num=atoi(str_indx);
            if (num < 1) return -1;
            ssl_cores=num;
            num=atoi(str_indx1);
            if (num < 1) return -1;
            ipsec_cores=num;
            nplus=1;
         }
         else 
            return -1;
      }
      else if ((!strncmp(argv[cmd_indx], "IPSEC=", 6) &&
          !strncmp(argv[cmd_indx+1], "SSL=", 4)) ||
          (!strncmp(argv[cmd_indx], "ipsec=", 6) &&
          !strncmp(argv[cmd_indx+1], "ssl=", 4)))
      {
         if ((str_indx = strchr(argv[cmd_indx], '=')) &&
             (++str_indx < argv[cmd_indx]+str_len) &&
             (str_indx1 = strchr(argv[cmd_indx+1], '=')) &&
             (++str_indx1 < argv[cmd_indx+1]+str_len1))
         {
            num=atoi(str_indx);
            if (num < 0) return -1;
            ipsec_cores=num;
            num=atoi(str_indx1);
            if (num < 0) return -1;
            ssl_cores=num;
            nplus=1;
         }
         else 
            return -1;
      }
      else 
         return -1;
   }
   else 
      return -1;
   return 0;
}

int set_ucode_links ()
{
   uint8_t ulist_indx=0, i;
#ifdef CAVIUM_MULTICARD_API
   Uint32 dev_cnt;
   Uint8 dev_mask;
#endif
   system("rm -f /dev/pkp_dev");   
   system("mknod /dev/pkp_dev c 125 0");

//#if NPLUS
#ifdef CAVIUM_MULTICARD_API
   if(Csp1Initialize(CAVIUM_DIRECT, CAVIUM_DEV_ID))   
#else
   if(Csp1Initialize(CAVIUM_DIRECT))
#endif
/*#else 
#ifdef CAVIUM_MULTICARD_API
   if(Csp1Initialize(CAVIUM_DIRECT, CAVIUM_DEV_ID))   
#else
   if(Csp1Initialize(CAVIUM_DIRECT))
#endif
#endif*/
   {   
      printf("failed Initializing device");
      return -1;
   }
#ifdef CAVIUM_MULTICARD_API
   Csp1GetDevCnt(&dev_cnt,&dev_mask);
   switch(dev_cnt)
   {
      case 4:
         system("rm -f /dev/pkp_dev3");   
         system("mknod /dev/pkp_dev3  c 125 3");
      case 3:
         system("rm -f /dev/pkp_dev2");
         system("mknod /dev/pkp_dev2  c 125 2");
      case 2:
         system("rm -f /dev/pkp_dev1");
         system("mknod /dev/pkp_dev1  c 125 1");
      case 1: break;
   }
#endif    

   if(Csp1GetDevType(&device))
   {
      printf("Unable to retrieve Dev type");
      exit(0);
   }

   for (i = 0; i < MICROCODE_MAX-!nplus; i++) {
//   for (i = 0; i < MICROCODE_MAX; i++) {
      strcpy (ucode_list[i], COMMON_PATH);
   }
#ifdef MC2
   if(device == NPX_DEVICE){
      system("ln -sf ../microcode/boot_mc2_px.out boot.out");
      strcat (ucode_list[ulist_indx], BOOT_FILE);
      strcat (ucode_list[ulist_indx], "_px.out");
      if (nplus) {
         system("ln -sf ../microcode/main_ssl2_px.out main_ssl.out");
         strcat (ucode_list[++ulist_indx], MAIN_SSL);
         strcat (ucode_list[ulist_indx], "_px.out");
         system("ln -sf ../microcode/main_ipsec2_px.out main_ipsec.out");
         strcat (ucode_list[++ulist_indx], MAIN_IPSEC);
         strcat (ucode_list[ulist_indx], "_px.out");
      }
      else if(ssl_cores>-1) {
         system("ln -sf ../microcode/main_ssl2_px.out main_ssl.out");
         strcat (ucode_list[++ulist_indx], MAIN_SSL);
         strcat (ucode_list[ulist_indx], "_px.out");
      }
      else if(ipsec_cores>-1) {
         system("ln -sf ../microcode/main_ipsec2_px.out main_ipsec.out");
         strcat (ucode_list[++ulist_indx], MAIN_IPSEC);
         strcat (ucode_list[ulist_indx], "_px.out");
      }
      else 
         printf ("No-Protocol defined for Nitorx-Px Device\n");
   }else if(device == N1_DEVICE){
      system("ln -sf ../microcode/boot_mc2.out boot.out");
      strcat (ucode_list[ulist_indx], BOOT_FILE);
      strcat (ucode_list[ulist_indx], ".out");
      if (nplus) {
         system("ln -sf ../microcode/plus_ssl2_n1.out plus_ssl.out");
         strcat (ucode_list[++ulist_indx], PLUS_SSL);
         strcat (ucode_list[ulist_indx], "_n1.out");
         system("ln -sf ../microcode/main_ipsec2_n1.out main_ipsec.out");
         strcat (ucode_list[++ulist_indx], MAIN_IPSEC);
         strcat (ucode_list[ulist_indx], "_n1.out");
      }
      else if(ssl_cores>-1) {
         system("ln -sf ../microcode/main_ssl2_n1.out main_ssl.out");
         strcat (ucode_list[++ulist_indx], MAIN_SSL);
         strcat (ucode_list[ulist_indx], "_n1.out");
      }
      else if(ipsec_cores>-1) {
         system("ln -sf ../microcode/main_ipsec2_n1.out main_ipsec.out");
         strcat (ucode_list[++ulist_indx], MAIN_IPSEC);
         strcat (ucode_list[ulist_indx], "_n1.out");
      }
      else 
         printf ("No-Protocol defined for N1 Device\n");

  }else if(device == N1_LITE_DEVICE){
      system("ln -sf ../microcode/boot_mc2.out boot.out");
      strcat (ucode_list[ulist_indx], BOOT_FILE);
      strcat (ucode_list[ulist_indx], ".out");
      if (nplus) {
         system("ln -sf ../microcode/plus_ssl2.out plus_ssl.out");
         strcat (ucode_list[++ulist_indx], PLUS_SSL);
         strcat (ucode_list[ulist_indx], ".out");
         system("ln -sf ../microcode/main_ipsec2.out main_ipsec.out");
         strcat (ucode_list[++ulist_indx], MAIN_IPSEC);
         strcat (ucode_list[ulist_indx], ".out");
      }
      else if(ssl_cores>-1) {
         system("ln -sf ../microcode/main_ssl2.out main_ssl.out");
         strcat (ucode_list[++ulist_indx], MAIN_SSL);
         strcat (ucode_list[ulist_indx], ".out");
      }
      else if(ipsec_cores>-1) {
         system("ln -sf ../microcode/main_ipsec2.out main_ipsec.out");
         strcat (ucode_list[++ulist_indx], MAIN_IPSEC);
         strcat (ucode_list[ulist_indx], ".out");
      }
      else 
         printf ("No-Protocol defined for N-Lite Device\n");
 
   }
   else {
      printf("\n unable to create links for device %d \n",device);
      return -1;
   }
#else 
   printf ("It supports only MC2 microcode\n");
   return -1;
#endif
#if 1
#ifdef CAVIUM_MULTICARD_API
   Csp1Shutdown(CAVIUM_DEV_ID);
#else
   Csp1Shutdown();
#endif
#endif
   return 0;
}

int ucode_dload (int Csp1_handle)
{
   Csp1InitBuffer init;
   int size, cnt;
   int fd;
   int i;
   char version[VERSION_LEN+1];
   char sram_address[SRAM_ADDRESS_LEN+1];
   int ret = 0;
      
   memset(&init,0,sizeof(init));   
   for (i=0; i < MICROCODE_MAX - !nplus; i++)
   {
      fd = open(ucode_list[i], O_RDONLY,0);
      if (fd < 0)
      {
         printf("File %s; Could not open\n",ucode_list[i]);
         perror("error");
         goto init_error;
      }

      /* version */
      cnt = read(fd,init.version_info[init.size],VERSION_LEN);
      if (cnt != VERSION_LEN)
      {
         printf("File %s; Could not read version\n",ucode_list[i]);
         close(fd);

         goto init_error;
      }
      version[VERSION_LEN] = 0;
      memcpy(version,init.version_info[init.size],VERSION_LEN);
      printf("File: %s\n\tVersion = %s\n",ucode_list[i],version);

      /* code length */
      cnt = read(fd,&init.code_length[init.size],4);
      if (cnt != 4)
      {
         close(fd);
         printf("File %s; Could not read code length\n",ucode_list[i]);
         goto init_error;
      }
      /* keep size consistent in byte lengths */
      init.code_length[init.size] = ntohl(init.code_length[init.size])*4;
      size = init.code_length[init.size];
      printf("\tCode length = %d\t",size);
   
      /* data length */
           cnt = read(fd,&init.data_length[init.size],4);
      if (cnt != 4)
      {
         printf("\nFile %s; Could not read data length\n",ucode_list[i]);
         close(fd);

         goto init_error;
      }

      init.data_length[init.size] = ntohl(init.data_length[init.size]);
      size = init.data_length[init.size];
      printf("Data length = %d\n",size);
   
      /* sram address */
      cnt = read(fd,init.sram_address[init.size],SRAM_ADDRESS_LEN);
      if (cnt != SRAM_ADDRESS_LEN)
      {
         printf("File %s; Could not read sram address\n",ucode_list[i]);
         close(fd);

         goto init_error;
      }
      sram_address[SRAM_ADDRESS_LEN] = 0;
      memcpy(sram_address,init.sram_address[init.size],SRAM_ADDRESS_LEN);
      
      /* code */
      size = ROUNDUP16(init.code_length[init.size]);
      init.code[init.size] = CAST_TO_X_PTR(malloc(size));
      cnt = read(fd,CAST_FRM_X_PTR(init.code[init.size]),size); 
      if (cnt != size)
      {
         printf("File %s; Could not read code\n",ucode_list[i]);
         close(fd);

         goto init_error;
      }


      /* data */
      size = ROUNDUP16(init.data_length[init.size]);
           init.data[init.size] = CAST_TO_X_PTR(malloc(size));
           cnt = read(fd,CAST_FRM_X_PTR(init.data[init.size]),size);
      if (cnt != size)
      {
         printf("File %s; Could not read data\n",ucode_list[i]);
         close(fd);
         goto init_error;
      }

      /* signature */
      cnt = read(fd,init.signature[init.size],256);
      if (cnt != 256)
      {
         printf("File %s; Could not read signature\n",ucode_list[i]);
         close(fd);
    ret = -2;
         goto init_error;
      }
//#ifdef NPLUS
      /* ucode_idx */
      init.ucode_idx[init.size] = i; //ucode_array[init.size].ucode_idx;
//#endif
      printf("%d: name=%s, index=%d, core=%d\n", i, ucode_list[i], i, cores); 
      init.size++;   

      close(fd);
   }
   if(ioctl(Csp1_handle,IOCTL_N1_INIT_CODE,(Uint32*)&init)==0) {
      printf ("Microcode Load Succeed\n");
   }else 
      printf ("Microcode Load Failed\n");

init_error:

   for (i=0; i<init.size; i++)
   {
      if (init.code[i])
         free(CAST_FRM_X_PTR(init.code[i]));

      if (init.data[i])
         free(CAST_FRM_X_PTR(init.data[i]));   
   }
   return ret;
}

int check_cores(void)
{
   int s_cores, ip_cores;

   s_cores = (ssl_cores == -1) ? 0: ssl_cores;
   ip_cores = (ipsec_cores == -1) ? 0 : ipsec_cores;

   switch(device)
   {
      case NPX_DEVICE:
         if((s_cores+ip_cores)>8)
         {
            printf("\n THE MAX NUMBER OF CORES SUPPORTED ARE : 8 \n");
            return 0;
         }
         break;
      case N1_DEVICE:
         if( ((!strcmp("CN1220",part_num))||(!strcmp("CN1320",part_num))||(!strcmp("CN1120",part_num) )) && (s_cores+ip_cores)>8)
         {
               printf("\n THE MAX NUMBER OF CORES SUPPORTED ARE : 8 \n");
               return 0;
         }
         else if((s_cores+ip_cores)>16)
         {
                printf("\n THE MAX NUMBER OF CORES SUPPORTED ARE : 16 \n");
                return 0;
         }
         break;   
      case N1_LITE_DEVICE:
         if(( (!strcmp("CN501",part_num)) || (!strcmp("CN1001",part_num)) )  && (s_cores+ip_cores)>1)
         {
            printf("\n THE MAX NUMBER OF CORES SUPPORTED ARE : 1 \n");
            return 0;
         }
         if(( (!strcmp("CN505",part_num)) || (!strcmp("CN1005",part_num)) )  && (s_cores+ip_cores)>2)
         {
            printf("\n THE MAX NUMBER OF CORES SUPPORTED ARE : 2 \n");
            return 0;
         }
         else if((s_cores+ip_cores)>4)
         {
            printf("\n THE MAX NUMBER OF CORES SUPPORTED ARE : 4 \n");
            return 0;
         }
		 break;
      default:
         printf ("Unknown Device: %x\n", device);
         return 0;
   }
   return 1;
}
         
int init_csp1()
{
   int i, j, bit;
   uint8_t cores;

   if(!check_cores())
   {
	  printf ("ERROR: Cores out of range, Unable to load microcode\n");
      return -1;
   }
   if(ucode_dload(Csp1_handle) != 0)
   {
      printf("ucode_dlaodCSP1 failed to initialize\n");
      return(-1);
   }
/****** set cores for nplus mode *******/   
   if (nplus || ssl_cores>0 || ipsec_cores>0) {
      Csp1CoreAssignment core_assign;
      /* Now check, what cores are available */
      if(ioctl(Csp1_handle, IOCTL_CSP1_GET_CORE_ASSIGNMENT,(Uint32 *)&core_assign) != 0) {
         printf("CSP1 failed to get core assignments\n");
         return(-2);
      }
      /* Assign cores to microcodes */
      bit = 0;
   /* It is assumed that ucode_list contains ssl code followed by ipsec code */
      cores = (nplus || ssl_cores > 0) ?ssl_cores : ipsec_cores;
      for(i=1;i<MICROCODE_MAX-!nplus;i++)
      {

         for(j=0;j<cores && bit<MAX_CORES_NITROX;j++) 
         {
            do 
            {
               if((1<<bit) & core_assign.core_mask[BOOT_IDX])
               {
                  core_assign.core_mask[BOOT_IDX] &= ~(1<<bit);
                  core_assign.core_mask[i] |= (1<<bit);
                  break;
               }
               bit++;
            } while(bit<MAX_CORES_NITROX);
            if(bit>= MAX_CORES_NITROX)
            {
                printf("Error: Insufficient cores for allocation\n");
                exit(2);
            }
         }
         cores=ipsec_cores; // ipsec ucode always at end
      }

      if(ioctl(Csp1_handle, IOCTL_CSP1_SET_CORE_ASSIGNMENT, (Uint32 *)&core_assign) != 0)
      {
         printf("CSP1 failed to set core assignments\n");
         return(-3);
      }
   
      if(ioctl(Csp1_handle, IOCTL_CSP1_GET_CORE_ASSIGNMENT, (Uint32 *)&core_assign) != 0)
      {
          printf("CSP1 failed to get core assignments\n");
          return(-4);
      }
   
      printf("CSP1 core assignments\n");
      for(i=0;i<MICROCODE_MAX-!nplus;i++)
         if(core_assign.mc_present[i])
       printf("%10s : 0x%06x\n",ucode_list[i],core_assign.core_mask[i]);

   } /* end nplus */
   return(0);
}

int main(int argc, char *argv[])
{
   Csp1DevMask buf;
   int dev_count = 0;
   int i, ret=0;
   char name[30];

   if ((parse_args (argc, argv) < 0) || (ssl_cores < 0 && ipsec_cores < 0)) {
      usage (argv[0]);
      return -1;
   }

   if (set_ucode_links() < 0) {
      printf ("Error: Unable to set microcode error\n");
      return -1;
   }

   Csp1_handle = open("/dev/pkp_dev", 0);
   if(Csp1_handle < 0)
   {
      printf("\n the error is %s\n",strerror(errno));
      printf("Error: Unable to open Cavium device file\n");
      printf("Retry after unloading and reloading the driver\n");
      exit(-1);
   }
   if(ioctl(Csp1_handle,IOCTL_N1_GET_DEV_TYPE,&device))
   {
      printf("failed in determining device");
      return -1;
   }

   if(init_csp1()) {
       printf("\nInit Failed\n");
	   ret = -1;
	   goto error;
   }

#ifdef CAVIUM_MULTICARD_API
   if(ioctl(Csp1_handle,IOCTL_N1_GET_DEV_CNT,&buf) == 0)
   {
#if CAVIUM_DEBUG_LEVEL>0
      printf("CSP1: Detected devices dev_count %d\n",buf.dev_cnt);
#endif
   }
   else
   {
      printf("CSP1: No devices detected \n");
      exit(-1);
   }
   dev_count=buf.dev_cnt;
   printf ("Number of Devices: %d\n", dev_count);
   dev_count--;   
   for(i=1 ; i<=dev_count; i++)
   {
      sprintf(name,"%s%d","/dev/pkp_dev",i);
      Csp1_handle = open(name, 0, O_RDWR);
      if(Csp1_handle < 0)
      {
         printf("Error: Unable to open Cavium device file\n");
         printf("Retry after unloading and reloading the driver\n");
         exit(-1);
      }

      if(init_csp1())
         printf("init failed for device %d \n",i); 
   
   if(Csp1_handle >= 0)
   {
      close(Csp1_handle);
   }
   }
#endif   
error:
   if (ret == -1) 
      system ("rmmod pkp_drv.ko");
   exit(0);
}

