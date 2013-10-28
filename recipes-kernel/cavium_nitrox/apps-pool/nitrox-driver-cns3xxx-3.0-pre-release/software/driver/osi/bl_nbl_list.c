/* bl_nbl_list.c */
/*
 * Copyright (c) 2003-2006 Cavium Networks (support@cavium.com). All rights 
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

#include "cavium_sysdep.h"
#include "cavium_common.h"
#include "cavium_endian.h"
#include "cavium_list.h"
#include "cavium.h"
#include "pending_free_list.h"
#include "init_cfg.h"
#include "buffer_pool.h"
#include "cavium_endian.h"
#include "pending_list.h"
#include "bl_nbl_list.h"

/* Blocking list*/
cavium_spinlock_t blocking_list_lock = CAVIUM_SPIN_LOCK_UNLOCKED;
struct cavium_list_head blocking_list_head = { NULL, NULL }; 

/* Non-blocking list */
cavium_spinlock_t non_blocking_list_lock = CAVIUM_SPIN_LOCK_UNLOCKED;
struct cavium_list_head non_blocking_list_head = { NULL, NULL };

static void
remove_from_non_blocking(n1_user_info_buffer *entry);
static void
remove_from_blocking(n1_user_info_buffer *entry);
static void 
push_non_blocking(n1_user_info_buffer *entry);
static void 
push_blocking(n1_user_info_buffer *entry);

/*
 * Lists/locks initialization.
 */
void
init_blocking_non_blocking_lists(void)
{
   MPRINTFLOW();
   CAVIUM_INIT_LIST_HEAD(&blocking_list_head);
   CAVIUM_INIT_LIST_HEAD(&non_blocking_list_head);

   cavium_spin_lock_init(&blocking_list_lock);
   cavium_spin_lock_init(&non_blocking_list_lock);
}

void
cleanup_blocking_non_blocking_lists(void)
{
   cavium_spin_lock_destroy(&blocking_list_lock);
   cavium_spin_lock_destroy(&non_blocking_list_lock);
}


/*
 * Push to Blocking list 
 */
static void 
push_blocking(n1_user_info_buffer *entry)
{
   MPRINTFLOW();
   cavium_spin_lock_softirqsave(&blocking_list_lock);
   cavium_list_add_tail(&entry->list, &blocking_list_head);
   cavium_spin_unlock_softirqrestore(&blocking_list_lock);
}


/*
 * Push to Non-blocking-list
 */
static void 
push_non_blocking(n1_user_info_buffer *entry)
{
   MPRINTFLOW();
   cavium_spin_lock_softirqsave(&non_blocking_list_lock);
   cavium_list_add_tail(&entry->list, &non_blocking_list_head);
   cavium_spin_unlock_softirqrestore(&non_blocking_list_lock);
}

/*
 * Push pending structure to the corresponding queue 
 */
void push_user_info(n1_user_info_buffer *entry)
{
   MPRINTFLOW();
   if(entry->req_type == CAVIUM_BLOCKING)
      push_blocking(entry);
   else
      push_non_blocking(entry);
}


/*
 */
static void
remove_from_blocking(n1_user_info_buffer *entry)
{
   MPRINTFLOW();
   cavium_list_del(&entry->list);
   
}


static void
remove_from_non_blocking(n1_user_info_buffer *entry)
{
   MPRINTFLOW();
   cavium_list_del(&entry->list);
}

/*
 * Remove from list
 */
void
del_user_info_from_list(n1_user_info_buffer *entry)
{
   MPRINTFLOW();
   if (entry->req_type == CAVIUM_BLOCKING)
   {
      cavium_spin_lock_softirqsave(&blocking_list_lock);
      remove_from_blocking(entry);   
      cavium_spin_unlock_softirqrestore(&blocking_list_lock);
   }
   else
   {
      cavium_spin_lock_softirqsave(&non_blocking_list_lock);
      remove_from_non_blocking(entry);
      cavium_spin_unlock_softirqrestore(&non_blocking_list_lock);
   }
}

Uint32
check_nb_command_pid(cavium_pid_t pid)
{
   struct cavium_list_head *tmp;
   Uint32 ret=ERR_REQ_PENDING;

   MPRINTFLOW();
   cavium_spin_lock_softirqsave(&non_blocking_list_lock);

   cavium_list_for_each(tmp, &non_blocking_list_head)
   {
      n1_user_info_buffer *entry = cavium_list_entry(tmp, n1_user_info_buffer, list);
      if (entry->pid == pid)
      {
         if (entry->status != 0xff)
         {
            ret=entry->status;
            goto cleanup;
         }
      }
   }
cleanup:
   cavium_spin_unlock_softirqrestore(&non_blocking_list_lock);
   return ret;
}

/*check for the status of pending requests*/
Uint32
check_all_nb_command(cavium_device *pdev,Csp1StatusOperationBuffer *csp1_status_operation)
{
   Uint32 cnt = 0;
   Uint32 res_cnt = 0;
   Uint32 ret=0;
   /*number of request ids to be checked for*/
   Uint32 req_cnt = csp1_status_operation->cnt;

   Csp1RequestStatusBuffer *req_stat_buf = (void *)(ptrlong) (csp1_status_operation->req_stat_buf);

   Csp1RequestStatusBuffer *resp_stat_buf = NULL;

   MPRINTFLOW();
   resp_stat_buf =
        (Csp1RequestStatusBuffer *) get_buffer_from_pool(pdev,
                                      req_cnt * sizeof (Csp1RequestStatusBuffer));
   if (resp_stat_buf == NULL)
      return ERR_MEMORY_ALLOC_FAILURE;

   while(cnt < req_cnt)
   {
       ret = check_nb_command_id(req_stat_buf[cnt].request_id);
  /*res_stat_buf is updated only for completed and pending(ERR_REQ_PENDING)
   *requests*/ 
       if(ret != ERR_INVALID_REQ_ID)
       {
          resp_stat_buf[res_cnt].request_id =req_stat_buf[cnt].request_id;
          resp_stat_buf[res_cnt].status = ret;
          res_cnt++;
       }
       cnt++;
   }
   
   if(cavium_copy_out((void *)(ptrlong) (csp1_status_operation->req_stat_buf), 
                  resp_stat_buf,
                  res_cnt * sizeof(Csp1RequestStatusBuffer)))
   {
      return EFAULT;
   }
   csp1_status_operation->res_count = res_cnt;             

   put_buffer_in_pool(pdev, (Uint8 *) resp_stat_buf);

   return 0;
}

Uint32
check_nb_command_id(Uint32 id)
{
   struct cavium_list_head *tmp;
   Uint32 ret=ERR_INVALID_REQ_ID;
   n1_user_info_buffer user_info_entry;

   MPRINTFLOW();
   cavium_spin_lock_softirqsave(&non_blocking_list_lock);
   cavium_list_for_each(tmp, &non_blocking_list_head) 
   {
      n1_user_info_buffer *entry 
         = cavium_list_entry(tmp, n1_user_info_buffer, list);
      if ((entry->req->request_id) == id) 
      {
        if (entry->status != 0xff)
        {
           ret=entry->status;

           cavium_dbgprint("check_nb_cmd_id:request(0x%x) status(0x%x)\n",
                            id,ret); 

            /* make a copy */
           cavium_memcpy((Uint8 *)&user_info_entry, 
                           (Uint8 *)entry, 
                            sizeof(n1_user_info_buffer));

           cavium_dbgprint("check_nb_cmd: deallocating entry->req %p\n",
                              entry->req);
           if (entry->req)
              put_buffer_in_pool(entry->n1_dev, (Uint8 *)entry->req);
      
           cavium_dbgprint("check_nb_cmd:calling remove_from_non_blocking \n");
           remove_from_non_blocking(entry);
           cavium_dbgprint("check_nb_cmd: deallocating entry %p\n",entry);
           put_buffer_in_pool(entry->n1_dev, (Uint8 *)entry);
           cavium_dbgprint("check_nb_cmd: releasing lock\n");
           cavium_spin_unlock_softirqrestore(&non_blocking_list_lock);
           goto copy_result;
        } /* status changed */
        else
        {
              cavium_spin_unlock_softirqrestore(&non_blocking_list_lock);
            ret = ERR_REQ_PENDING;
            return ret;
        }
      } /* id match */
   } /* list for each */
   cavium_spin_unlock_softirqrestore(&non_blocking_list_lock);

/* It will reach here only if status was changed from 0xff or request ID was
 * not found in the list */
copy_result:
   if( ret != ERR_INVALID_REQ_ID)
   {
      cavium_dbgprint("check_nb_cmd: result for id 0x%x\n", id);

      /* copy user mode result*/
      if (!user_info_entry.mmaped) 
      {
         cavium_dbgprint("check_nb_cmd: not mmapped\n");
         if (user_info_entry.out_size) 
         {
            int total_offset;
             unsigned int i;
             Uint64 *p;
       
       if (cavium_debug_level > 2)
           cavium_dump("Response Pkt:", 
            (Uint8 *)user_info_entry.out_buffer, 
            user_info_entry.out_size);
            
       total_offset = 0;
       cavium_dbgprint("check_nb_cmd: copying result\n");
          
       for (i = 0; i < user_info_entry.outcnt; i++) 
       {
          if (user_info_entry.outunit[i] == UNIT_64_BIT) 
          {
             p = (Uint64 *)&user_info_entry.out_buffer[total_offset];
             *p = betoh64(*p);
          }
          if(cavium_copy_out(user_info_entry.outptr[i], 
            &user_info_entry.out_buffer[total_offset], 
            user_info_entry.outsize[i]))
          {
             cavium_error("Failed to copy %d bytes to user_buffer 0x%lx\n",
                           user_info_entry.outsize[i],
                           (ptrlong)user_info_entry.outptr[i]);   
          }
          
          total_offset += user_info_entry.outoffset[i];
       }
         }
         cavium_dbgprint("check_nb_cmd: freeing outbuffer\n");
         if(user_info_entry.out_buffer)
            put_buffer_in_pool(user_info_entry.n1_dev, 
                               (Uint8 *)user_info_entry.out_buffer);
         
         cavium_dbgprint("check_nb_cmd: freeing inbuffer\n");
         if(user_info_entry.in_buffer)
            put_buffer_in_pool(user_info_entry.n1_dev, 
                               (Uint8 *)user_info_entry.in_buffer);
      }
   }
   else
      cavium_error("check_nb_command_id: request_id 0x%x not found\n",id);
   return ret;
}

Uint32
cleanup_nb_command_id(Uint32 id)
{
   struct cavium_list_head *tmp, *tmp1;

   MPRINTFLOW();
again:
  cavium_spin_lock_softirqsave(&non_blocking_list_lock);
  cavium_list_for_each_safe(tmp, tmp1, &non_blocking_list_head)
  {
      n1_user_info_buffer *entry = cavium_list_entry(tmp, n1_user_info_buffer, list);
      if ((entry->req->request_id) == id)
      {
         if (entry->status == 0xff) {
            void *n1dev = (void *) entry->n1_dev;
            cavium_spin_unlock_softirqrestore (&non_blocking_list_lock);
            check_for_completion_callback (n1dev);
            goto again;
         }
         cavium_dbgprint("Cleaning up request id %d\n", entry->req->request_id);
         if (!entry->mmaped)
         {
            if(entry->out_buffer)
               put_buffer_in_pool(entry->n1_dev, (Uint8 *)entry->out_buffer);
            if(entry->in_buffer)
               put_buffer_in_pool(entry->n1_dev, (Uint8 *)entry->in_buffer);
         }
         if (entry->req) 
            put_buffer_in_pool(entry->n1_dev, (Uint8*)entry->req);
         remove_from_non_blocking(entry);
         put_buffer_in_pool(entry->n1_dev, (Uint8 *)entry);
         cavium_spin_unlock_softirqrestore(&non_blocking_list_lock);
                  return 1;
      }
   }
   cavium_spin_unlock_softirqrestore(&non_blocking_list_lock);
   return 0;
}

Uint32
cleanup_nb_command_pid(cavium_pid_t pid)
{
   struct cavium_list_head *tmp, *tmp1;

   MPRINTFLOW();
again:
  cavium_spin_lock_softirqsave(&non_blocking_list_lock);

   cavium_list_for_each_safe(tmp, tmp1, &non_blocking_list_head)
   {
      n1_user_info_buffer *entry = cavium_list_entry(tmp, n1_user_info_buffer, list);
      if (entry->pid == pid)
      {
         if (entry->status == 0xff) {
            void *n1dev = (void *) entry->n1_dev;
            cavium_spin_unlock_softirqrestore (&non_blocking_list_lock);
            check_for_completion_callback (n1dev);
            goto again;
         }
         cavium_dbgprint("Cleaning up request for pid %d\n",(Uint32)(ptrlong)pid);
         if (!entry->mmaped) 
         {
            if(entry->out_buffer)
               put_buffer_in_pool(entry->n1_dev, (Uint8 *)entry->out_buffer);
            if(entry->in_buffer)
               put_buffer_in_pool(entry->n1_dev, (Uint8 *)entry->in_buffer);
         }
         if (entry->req) 
            put_buffer_in_pool(entry->n1_dev, (Uint8*)entry->req);
         remove_from_non_blocking(entry);
         put_buffer_in_pool(entry->n1_dev, (Uint8 *)entry);
      }
   }
   cavium_spin_unlock_softirqrestore(&non_blocking_list_lock);
   return 0;
}

/*
 * $Id: bl_nbl_list.c,v 1.6 2008/09/30 13:15:17 jsrikanth Exp $
 * $Log: bl_nbl_list.c,v $
 * Revision 1.6  2008/09/30 13:15:17  jsrikanth
 * PX-4X [Multicard] support for IPsec :
 *      -  Round-robin scheduling for selecting a device
 *         implemented within IPSec APIs.
 *      -  All Lists [Pending/Direct/SG/CompletionDMA]
 *         moved to device structure.
 *      -  A single buffer pool manager for all devices.
 *         Interrupt handler now checks for PCI Error register as well.
 *         Proc Entry bug fixes when dumping more than a single page.
 *         DUMP_FAILING_REQUESTS pre-processor define added to dump
 *         out all failing requests.
 * Minor modifications of removing all tabs to spaces.
 *
 * Revision 1.5  2008/03/14 09:40:17  rkumar
 * Wrong pointer[req_stat_buf instead of resp_stat_buf] check for memory allocation failure corrected.
 *
 * Revision 1.4  2008/01/08 05:58:22  rkumar
 * Get all requests issue of not using req_cnt for memory allocation.
 *
 * Revision 1.3  2007/12/05 14:29:54  lpathy
 * bug fix in request flush
 *
 * Revision 1.2  2007/11/19 11:11:55  lpathy
 * ported to 64 bit windows.
 *
 * Revision 1.1  2007/01/06 02:47:40  panicker
 * * first cut - NITROX PX driver
 *
 * Revision 1.28  2006/05/16 09:30:12  kchunduri
 * --support for Dynamic DMA mapping instead of virt_to_phys
 *
 * Revision 1.27  2006/04/17 04:16:53  kchunduri
 * --def of check_all_nb_command() to support IOCTL_N1_GET_ALL_REQUEST_STATUS
 *
 * Revision 1.26  2006/01/12 13:14:20  ksadasivuni
 * - Changed copyright notice
 *
 * Revision 1.25  2006/01/10 10:54:55  ksadasivuni
 * - In the case of Wrong request id passed by application non_blocking_list is not being locked.
 *   It was changed to unlock if request id is not found in the list.
 *
 * Revision 1.24  2005/11/17 13:31:09  kanantha
 * Updating with the 64 bit modifications, with proper matching of data types
 *
 * Revision 1.23  2005/10/13 09:17:58  ksnaren
 * fixed compile warnings
 *
 * Revision 1.22  2005/09/28 15:50:26  ksadasivuni
 * - Merging FreeBSD 6.0 AMD64 Release with CVS Head
 * - Now context pointer given to user space applications is physical pointer.
 *   So there is no need to do cavium_vtophys() of context pointer.
 *
 * Revision 1.21  2005/09/21 06:54:49  lpathy
 * Merging windows server 2003 release with CVS head
 *
 * Revision 1.20  2005/09/06 14:38:57  ksadasivuni
 * - Some cleanup error fixing and spin_lock_destroy functionality added to osi.
 *   spin_lock_destroy was necessary because of FreeBSD 6.0.
 *
 * Revision 1.19  2005/08/31 02:30:20  bimran
 * Fixed code to check for copy_in/out return values.
 *
 * Revision 1.18  2005/06/13 06:35:42  rkumar
 * Changed copyright
 *
 * Revision 1.17  2005/06/07 05:03:16  rkumar
 * changed cavium_list_for_each to cavium_list_for_each_safe
 *
 * Revision 1.16  2005/06/06 08:18:04  rkumar
 * SMP crash in SSL, with non-blocking code fixed. The lock usage has been cleaned up
 *
 * Revision 1.15  2005/06/03 08:07:55  rkumar
 * Moved cavium_prints to cavium_dbgprint
 *
 * Revision 1.14  2005/02/01 04:11:07  bimran
 * copyright fix
 *
 * Revision 1.13  2005/01/06 18:43:32  mvarga
 * Added realtime support
 *
 * Revision 1.12  2004/08/03 20:44:11  tahuja
 * support for Mips Linux & HT.
 *
 * Revision 1.11  2004/06/28 20:37:42  tahuja
 * Fixed compiler warnings on NetBSD. changed mdelay in check_completion from 1ms to 2ms.
 *
 * Revision 1.10  2004/06/23 19:16:47  bimran
 * Fixed compiler warnings on NetBSD.
 * changed list_for_each to cavium_list_for_each.
 *
 * Revision 1.9  2004/06/03 21:26:04  bimran
 * fixed list* calls to use cavium_list
 *
 * Revision 1.8  2004/06/03 21:21:36  bimran
 * included cavium_list.h
 * fixed list* calls to use cavium_list
 *
 * Revision 1.7  2004/06/02 19:04:20  tsingh
 * Fixed non-blocking SMP hang bug.
 * Added some more debug prints. (bimran)
 *
 * Revision 1.6  2004/06/02 02:09:49  tsingh
 * Fixes for SMP issues.
 * Never do a copyout after holding a softirq lock as the call might sleep.
 * (bimran)
 *
 * Revision 1.5  2004/05/05 21:19:19  bimran
 * Fixed freeing up in/out buffers.
 *
 * Revision 1.4  2004/05/02 19:44:29  bimran
 * Added Copyright notice.
 *
 * Revision 1.3  2004/05/01 07:14:37  bimran
 * Fixed non-blocking operation from user mode.
 *
 * Revision 1.2  2004/04/30 00:08:50  bimran
 * changed spin_lock/unlock to spin_lock/unlock_softirq*
 *
 * Revision 1.1  2004/04/15 22:40:48  bimran
 * Checkin of the code from India with some cleanups.
 *
 */

