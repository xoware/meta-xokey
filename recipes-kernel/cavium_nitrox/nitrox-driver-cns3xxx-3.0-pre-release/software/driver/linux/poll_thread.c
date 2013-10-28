/* poll_thread.c */ 
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
 * 3. All manuals,brochures,user guides mentioning features or use of this software 
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
/*------------------------------------------------------------------------------
 * 
 *      Linux Driver file -- Implementaion of polling thread for checking
 *      completion of requests.
 *
 *----------------------------------------------------------------------------*/

#include "cavium_sysdep.h"
#include "cavium_common.h"
#include "linux_main.h"
#include "cavium_list.h"
#include "cavium.h"
#include "pending_list.h"
#include "command_que.h"
#include "soft_req_queue.h"

static pid_t thread_pid = -1;

static cavium_semaphore thread_sema;
volatile static int thread_exit;

wait_queue_head_t cavium_poll = { CAVIUM_SPIN_LOCK_UNLOCKED, {NULL, NULL}};
extern int dev_count;
extern short nplus;
extern cavium_device cavium_dev[];

static int poll_thread(void* arg);

/*
 * Create poll thread
 */
int init_poll_thread(void)
{
   MPRINTFLOW();

   cavium_sema_init(&thread_sema,0);
   thread_exit=0;
   init_waitqueue_head(&cavium_poll);
   thread_pid = kernel_thread(poll_thread,NULL,0);
   if (thread_pid < 0)
      return 1;
   return 0;
}

/*
 * free poll thread
 */
void free_poll_thread(void)
{
   int ret=0;
   if (thread_pid >= 0) 
   {
      cavium_wakeup(&cavium_poll);
      thread_exit=1;
      ret = cavium_sema_down_interruptible(&thread_sema);
   }
}


/*
 * Poll thread. Calls check_for_completion_callback when woken up.
 */
static int poll_thread(void *pdev)
{
   int i,queue;
   int ucode;

#if LINUX_VERSION_CODE < KERNEL_VERSION (2,6,0)
   daemonize();
#else
   char name[]="Cavium Poll Thread\n";
   daemonize((char*)name);
#endif

   sigfillset(&current->blocked);

   strcpy(current->comm,"cavium");

   mb();

   cavium_print("Starting poll_thread\n");
   cavium_print("device count = %d\n", dev_count);
   while (1) 
   {
#if LINUX_VERSION_CODE >= KERNEL_VERSION (2,6,2)
   lock_kernel ();
#endif
      cavium_wait_interruptible_timeout(cavium_poll,0,1);
#if LINUX_VERSION_CODE >= KERNEL_VERSION (2,6,2)
   unlock_kernel ();
#endif

      for (i=0; i <dev_count; i++)
      {
         /*Doorbell coalescing */
         if(nplus && cavium_dev[i].device_id != NPX_DEVICE)
         {
            for (ucode=0; ucode < MICROCODE_MAX;ucode++)
            {
               if((cavium_dev[i].microcode[ucode].code_type == CODE_TYPE_SPECIAL)
                 && likely((cavium_dev[i].microcode[ucode].core_id != (Uint8)(-1)))) {
               move_srq_entries(&cavium_dev[i], ucode, 0);
            	}
         	}
         }	
         check_for_completion_callback(&cavium_dev[i]);

         for(queue=0;queue<MAX_N1_QUEUES;queue++)
         {
            lock_command_queue(&cavium_dev[i], queue);
            if(cavium_dev[i].door_bell_count[queue])
            {
          cavium_dbgprint("poll:hitting doorbell %d\n", cavium_dev[i].door_bell_count[queue]);
               ring_door_bell(&cavium_dev[i], queue, cavium_dev[i].door_bell_count[queue]);
               cavium_dev[i].door_bell_count[queue]=0;
            }
            unlock_command_queue(&cavium_dev[i], queue);
         }
    
       }/* for all devices */

       if (thread_exit)
       break;
   }
   
   cavium_dbgprint("Ending poll_thread\n");
   thread_pid = -1; 

   cavium_sema_up(&thread_sema);
   
   return 0;
}/*poll_thread*/

/*
 * $Id: poll_thread.c,v 1.7 2009/09/09 11:19:04 aravikumar Exp $
 * $Log: poll_thread.c,v $
 * Revision 1.7  2009/09/09 11:19:04  aravikumar
 * NPLUS macro dependency removed and made it dynamic
 *
 * Revision 1.6  2009/04/28 11:22:38  pnalla
 * Supressed the warning by catching the return value of "cavium_sema_down_interruptible" into a variable.
 *
 * Revision 1.5  2008/11/06 09:07:18  ysandeep
 * Removed PX_PLUS
 *
 * Revision 1.4  2008/09/30 13:18:18  jsrikanth
 *         PX-4X [Multicard] support for IPsec :
 *                 -    Round-robin scheduling for selecting a device
 *                      implemented within IPSec APIs.
 *                 -    All Lists [Pending/Direct/SG/CompletionDMA]
 *                      moved to device structure.
 *                 -    A single buffer pool manager for all devices.
 *         Interrupt handler now checks for PCI Error register as well.
 *         Proc Entry bug fixes when dumping more than a single page.
 *         DUMP_FAILING_REQUESTS pre-processor define added to dump
 *         out all failing requests.
 *         Minor modification of changing all tabs to spaces.
 *
 * Revision 1.3  2007/03/08 20:38:28  panicker
 * * NPLUS mode changes. pre-release
 * * NitroxPX now supports N1-style NPLUS operation.
 * * Native PX mode PLUS operations are enabled only if PX_PLUS flag is enabled
 *
 * Revision 1.2  2007/01/11 02:18:28  panicker
 * - No NPLUS mode needs to be used in PX.
 *
 * Revision 1.1  2007/01/06 02:47:40  panicker
 * * first cut - NITROX PX driver
 *
 * Revision 1.15  2006/08/01 07:56:15  kchunduri
 * replace deprecated interruptible_sleep_on_timeout
 *
 * Revision 1.14  2005/11/17 13:31:09  kanantha
 * Updating with the 64 bit modifications, with proper matching of data types
 *
 * Revision 1.13  2005/06/13 06:35:42  rkumar
 * Changed copyright
 *
 * Revision 1.12  2005/05/20 14:34:05  rkumar
 * Merging CVS head from india
 *
 * Revision 1.11  2005/02/01 04:07:12  bimran
 * copyright fix
 *
 * Revision 1.10  2005/01/06 18:43:32  mvarga
 * Added realtime support
 *
 * Revision 1.9  2004/08/03 20:44:10  tahuja
 * support for Mips Linux & HT.
 *
 * Revision 1.8  2004/06/03 21:18:31  bimran
 * included cavium_list.h
 *
 * Revision 1.7  2004/05/08 03:58:22  bimran
 * Fixed INTERRUPT_ON_COMP
 *
 * Revision 1.6  2004/05/02 19:43:58  bimran
 * Added Copyright notice.
 *
 * Revision 1.5  2004/04/29 21:56:46  tsingh
 * Moved check_for_completion_callback() up before hitting doorbell.(bimran)
 *
 * Revision 1.4  2004/04/17 01:32:41  bimran
 * Fixed a print.
 *
 * Revision 1.3  2004/04/16 23:58:43  bimran
 * Added more debug prints.
 * Fixed sleep timeout value and made it independent of changing HZ value of different kernels.
 *
 * Revision 1.2  2004/04/16 03:15:16  bimran
 * Added doorbell coalescing support.
 *
 * Revision 1.1  2004/04/15 22:40:48  bimran
 * Checkin of the code from India with some cleanups.
 *
 */

