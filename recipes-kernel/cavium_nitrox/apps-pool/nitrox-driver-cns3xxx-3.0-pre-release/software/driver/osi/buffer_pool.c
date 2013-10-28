/* buffer_pool.c */
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
#include "cavium_sysdep.h"
#include "cavium_common.h"
#include "cavium_list.h"
#include "cavium.h"
#include "init_cfg.h"
#include "buffer_pool.h"

static cavium_buffer_t buffer[BUF_POOLS];
static cavium_frag_buf_t fragments[MAX_BUFFER_CHUNKS];
static Uint16 fragment_free_list[MAX_BUFFER_CHUNKS];
static Uint16 fragment_free_list_index;
static cavium_spinlock_t fragment_lock;

static int malloc_buffer(pool,int,int);
static void free_buffer(pool);
static void put_buffer(cavium_buffer_t *,int);
static Uint8 *get_buffer(cavium_buffer_t *);

struct cavium_list_head allocated_list_head = {NULL, NULL};
/* Initial Buffer count */
Uint32 buffer_stats[BUF_POOLS];
/* Allocated buffers */
Uint32 alloc_buffer_stats[BUF_POOLS];
/* Buffers in fragmented pool */
Uint32 fragment_buf_stats[BUF_POOLS];
/* Buffers given for fragmentation */
Uint32 other_pools[BUF_POOLS];

/******************************************************** 
 * Function : init_buffer_pool
 *
 * Arguments    : cavium_general_config *
 * Return Value : Returns the status 0 (success) or
 *                1 (failure)
 * 
 * This function is used to intialize the buffer pool of 
 * the driver.The individual buffer pools are of size
 * 1k,2k,4k,8k,16k and 32k
 *
 ********************************************************/

Uint32
init_buffer_pool(cavium_general_config *gconfig)
{
   Uint16 i;
   cavium_dbgprint( "CAVIUM init_buffer_pool: called\n");
   
   MPRINTFLOW();
   /* FreeBSD Lock Initialization and Cleanup changes*/ 
   
   cavium_spin_lock_init(&fragment_lock);
#ifdef CAVIUM_HUGE_MEMORY
   cavium_spin_lock_init(&(buffer[huge_pool].buffer_lock));
   cavium_spin_lock_init(&(buffer[large].buffer_lock));
   cavium_spin_lock_init(&(buffer[medium].buffer_lock));
   cavium_spin_lock_init(&(buffer[small].buffer_lock));
   cavium_spin_lock_init(&(buffer[tiny].buffer_lock));
#endif
   cavium_spin_lock_init(&(buffer[ex_tiny].buffer_lock));
   
#ifdef CAVIUM_HUGE_MEMORY
   /* 32 kB buffers */
   if (malloc_buffer(huge_pool, gconfig->huge_buffer_max,
           HUGE_BUFFER_CHUNK_SIZE))
   {
      cavium_print( "PKP init_buffer_pool: failed to alloc huge\n");
      goto failed;
   }
   buffer_stats[huge_pool] = gconfig->huge_buffer_max;

   /* 16 kB buffers */
   if (malloc_buffer(large, gconfig->large_buffer_max,
           LARGE_BUFFER_CHUNK_SIZE))
   {
      cavium_print( "PKP init_buffer_pool: failed to alloc large\n");
      goto failed;
   }
   buffer_stats[large] = gconfig->large_buffer_max;

   /* 8 kB buffers */
   if (malloc_buffer(medium, gconfig->medium_buffer_max,
           MEDIUM_BUFFER_CHUNK_SIZE))
   {
      cavium_print( "PKP init_buffer_pool: failed to alloc medium\n");
      goto failed;
   }
   buffer_stats[medium] = gconfig->medium_buffer_max;

   /* 4 kB buffers */
   if (malloc_buffer(small, gconfig->small_buffer_max,
           SMALL_BUFFER_CHUNK_SIZE))
   {
      cavium_print( "PKP init_buffer_pool: failed to alloc small\n");
      goto failed;
   }
   buffer_stats[small] = gconfig->small_buffer_max;
   
   /*  2 kB buffers */
   if (malloc_buffer(tiny, gconfig->tiny_buffer_max,
           TINY_BUFFER_CHUNK_SIZE))
   {
      cavium_print( "PKP init_buffer_pool: failed to alloc tiny\n");
      goto failed;
   }
   buffer_stats[tiny] = gconfig->tiny_buffer_max;
#endif

   /* 1kB buffers */
   if (malloc_buffer(ex_tiny, gconfig->ex_tiny_buffer_max,
           EX_TINY_BUFFER_CHUNK_SIZE))
   {
      cavium_print( "PKP init_buffer_pool: failed to alloc ex_tiny\n");
      goto failed;
   }
   buffer_stats[ex_tiny] = gconfig->ex_tiny_buffer_max;
   
   /* List of fragmented buffers in use by applications */
   CAVIUM_INIT_LIST_HEAD(&allocated_list_head);
   for ( i = 0; i < MAX_BUFFER_CHUNKS; i++)
   {
      fragment_free_list[i] = i;
      fragments[i].index = i;
   }
   fragment_free_list_index = 0;
   /* cavium_spin_lock_init(&fragment_lock); */
   cavium_dbgprint("Returning from init_buffer_pool\n");
   return 0;
 
failed:
   free_buffer_pool();
   
   return 1;
}

/*************************************************** 
 * Function : free_buffer_pool
 *
 * Arguments       : void
 * Return Value    : Returns void 
 *
 * This function free the individual buffer pools 
 * of different sizes.
 *
 ***************************************************/
void 
free_buffer_pool(void)
{
#ifdef CAVIUM_HUGE_MEMORY
   cavium_spin_lock_destroy(&(buffer[huge_pool].buffer_lock));
   cavium_spin_lock_destroy(&(buffer[large].buffer_lock));
   cavium_spin_lock_destroy(&(buffer[medium].buffer_lock));
   cavium_spin_lock_destroy(&(buffer[small].buffer_lock));
   cavium_spin_lock_destroy(&(buffer[tiny].buffer_lock));
#endif
   cavium_spin_lock_destroy(&(buffer[ex_tiny].buffer_lock));
#ifdef CAVIUM_HUGE_MEMORY
   free_buffer(huge_pool);
   buffer_stats[huge_pool] = 0;
   free_buffer(large);
   buffer_stats[large] = 0;
   free_buffer(medium);
   buffer_stats[medium] = 0;
   free_buffer(small);
   buffer_stats[small] = 0;
   free_buffer(tiny);
   buffer_stats[tiny] = 0;
#endif
   free_buffer(ex_tiny);
   buffer_stats[ex_tiny] = 0;
   cavium_spin_lock_destroy(&fragment_lock);
}

/**************************************************** 
 * Function  : malloc_buffer
 * 
 * Arguments :  pool,int, int
 * Return Value : Type - int 
 *                Returns the error value 0 (success)
 *                and 1 (failure).
 * 
 * This function does the actual allocation of 
 * memory to a particular buffer pool
 *
 ****************************************************/

static int 
malloc_buffer(pool p, int count, int size)
{
   Uint16 i; 
   cavium_buffer_t *buf = &buffer[p];

   MPRINTFLOW();
   /* cavium_memset(buf,0,sizeof(buf)); */

   /* cavium_spin_lock_init(&buf->buffer_lock); */
   buf->chunks = count;
   buf->chunk_size = size;
   buf->real_size = size + sizeof(buffer_tag);
   buf->free_list_index = 0;
   /* List of Fragmented buffers obtained */
   CAVIUM_INIT_LIST_HEAD(&buf->frags_list);
    
   for (i = 0; i < buf->chunks; i++) 
   {
      buf->address[i] = (Uint8 *)cavium_malloc_dma(buf->real_size + ALIGNMENT, NULL);
      if (!buf->address[i]) 
      {
         cavium_error("PKP malloc_buffer: failed for chunk=%d\n",i);
         goto failed;
      }

      buf->address_trans[i] = (Uint8 *)(((ptrlong)(buf->address[i]) + 
                        sizeof(buffer_tag) + ALIGNMENT) & ALIGNMENT_MASK);
      buf->free_list[i] = i; 
      ((buffer_tag *)(((ptrlong)buf->address[i] + ALIGNMENT) & ALIGNMENT_MASK))->pool = p;
      ((buffer_tag *)(((ptrlong)buf->address[i] + ALIGNMENT) & ALIGNMENT_MASK))->index = i;
   }

   return 0;

failed:
    return 1;
}

/*************************************************** 
 * Function : free_buffer
 *
 * Arguments : pool
 * Return Value : Returns void 
 *
 * This function does the actual freeing of the 
 * DMA buffer which has been allocted by the driver
 *
 ***************************************************/
void 
free_buffer(pool p)
{
   int i;
   cavium_buffer_t *buf = &buffer[p];

   MPRINTFLOW();
   for (i = 0; i < buf->chunks; i++) 
   {
      if (buf->address[i])
         cavium_free_dma(buf->address[i]);
   }

   cavium_memset(buf, 0, sizeof(cavium_buffer_t));
   return;
}

/***************************************************** 
 * Function       : get_free_fragment 
 *
 * Arguments      : cavium_device *
 * Return Value   : Returns a free fragment of the 
 *                  type cavium_frag_buf_t *
 *
 * This function gets a free buffer fragment from the 
 * free fragment list
 *
 *****************************************************/
static cavium_frag_buf_t *
get_free_fragment(cavium_device *RESERVED)
{
   cavium_frag_buf_t *frag;
   int index =fragment_free_list[fragment_free_list_index++];
   MPRINTFLOW();
   frag = &fragments[index];
   return frag;
}

/*************************************************
 * Function : put_fragment
 *
 * Argument      : cavium_device *,cavium_frag_buf_t 
 * Return Value  : Returns void 
 *
 * This function puts back the fragment into the 
 * free pool of fragment list.
 *
 *************************************************/

static void
put_fragment(cavium_device *RESERVED, cavium_frag_buf_t frag)
{
   MPRINTFLOW();
   fragment_free_list_index --;
   fragment_free_list[fragment_free_list_index] = (Uint16) frag.index;
}
/********************************************************* 
 * Function  : put_buffer
 *
 * Arguments : cavium_buffer_t *, int
 * Returns   : void
 *
 * This function puts back the buffer into the 
 * free buffer pool
 *********************************************************/

static void 
put_buffer(cavium_buffer_t * b,int index)
{
   buffer_tag* t = NULL;
   MPRINTFLOW();
   cavium_spin_lock_softirqsave(&b->buffer_lock);
   b->free_list_index --;
   b->free_list[b->free_list_index] = (Uint16) index;
   t = (buffer_tag*)((ptrlong)b->address_trans[index] - sizeof(buffer_tag));
   alloc_buffer_stats[t->pool]--;
   cavium_spin_unlock_softirqrestore(&b->buffer_lock);
}
 
/********************************************************* 
 * Function  : get_buffer_from_init_pool
 *
 * Arguments : void *, cavium_buffer_t *
 * Returns   : Returns the address of the buffer 
 *             of type Uint8 *  or NULL
 *
 * This function gets buffer (which has been requested)
 * from the preallocated free pool 
 *
 *********************************************************/
static Uint8 * 
get_buffer_from_init_pool(void *RESERVED, cavium_buffer_t * b)
{
   int index;
   Uint8 *ret = NULL;

   buffer_tag* t = NULL;

   MPRINTFLOW();
   cavium_spin_lock_softirqsave(&b->buffer_lock);
   if (b->free_list_index < b->chunks) {
      /* Allocating from the free pool */
      index = b->free_list[b->free_list_index++];
      ret = b->address_trans[index];
      t = (buffer_tag*)((ptrlong)b->address_trans[index] - sizeof(buffer_tag));
      alloc_buffer_stats[t->pool]++;
   }
   cavium_spin_unlock_softirqrestore(&b->buffer_lock);
   return ret;
}
/********************************************************* 
 * Function  : get_buffer
 *
 * Arguments : cavium_buffer_t *
 * Returns   : Returns the address of the buffer 
 *             of type Uint8 *  or NULL
 *
 * This function gets buffer (which has been requested)
 * from the preallocated free pool or from the fragmented
 * list of buffers obtained from higher pools
 *
 *********************************************************/
static Uint8 * 
get_buffer(cavium_buffer_t * b)
{
   int index;
   Uint8 *ret = NULL;
   struct cavium_list_head *tmp;
   int pool = 0;

   MPRINTFLOW();

   ret = get_buffer_from_init_pool(NULL, b);
   if (ret)
      return ret;

   /* Allocating from the fragmented list of buffers 
    * obtained from higher pools*/
   cavium_spin_lock_softirqsave(&fragment_lock);
   cavium_list_for_each(tmp, &b->frags_list) {
      cavium_frag_buf_t *entry = cavium_list_entry(tmp, cavium_frag_buf_t, list);
      if (entry->free_list_index < entry->frags_count) {
         index = entry->free_list[entry->free_list_index++];
         ret = entry->address[index];
         if (entry->not_allocated == 1) {
            entry->not_allocated = 0;
            cavium_list_add_tail(&entry->alloc_list, &allocated_list_head);
         }
         pool = entry->p;
         other_pools[pool]++;
         break;
      }
   }
   cavium_spin_unlock_softirqrestore(&fragment_lock);

   return ret;
}

/************************************************************* 
 * Function  : fragment_buffer
 *
 * Arguments : cavium_device *,  pool , Uint8 *
 * Returns   : void 
 *
 * This function fragments the buffer pointed to by "buf"
 * into sizes of b->chunk_size(of Pool p) and places the same 
 * into b->frag_list (of Pool p)
 * 
 *************************************************************/
static void
fragment_buffer(cavium_device *RESERVED, pool p, Uint8 *buf)
{
   buffer_tag* t = (buffer_tag*)((ptrlong)buf - sizeof(buffer_tag));
   cavium_frag_buf_t *fragment;
   Uint16 i;
   cavium_buffer_t *b = &(buffer[p]);

   fragment = get_free_fragment(NULL);

   fragment->big_buf = buf;

   switch (t->pool) 
   {
      case ex_tiny:
         cavium_error("Cavium buffer pools fragmenting from a tiny buffer\n");
         put_fragment(NULL, *fragment);
         return;
      case tiny:
         fragment->frags_count = (TINY_BUFFER_CHUNK_SIZE/b->chunk_size);
         break;
      case small:
         fragment->frags_count = (SMALL_BUFFER_CHUNK_SIZE/b->chunk_size);
         break;
      case medium:
         fragment->frags_count = (MEDIUM_BUFFER_CHUNK_SIZE/b->chunk_size);
         break;
      case large:
         fragment->frags_count = (LARGE_BUFFER_CHUNK_SIZE/b->chunk_size);
         break;
      case huge_pool:
         fragment->frags_count = (HUGE_BUFFER_CHUNK_SIZE/b->chunk_size);
         break;
      default:
         /* bad, very bad! this should never happen. */
         cavium_error("Unsupported buffer pool %d\n", 
            t->pool);
         put_fragment(NULL, *fragment);
         return;
   }

   fragment->p = p;
   fragment_buf_stats[p] += fragment->frags_count;

   for (i = 0; i < fragment->frags_count; i++) 
   {
      fragment->free_list[i] = i;
      fragment->address[i] = buf + i*b->chunk_size;
   }
   fragment->free_list_index = 0;
   fragment->not_allocated = 1;
   cavium_list_add_tail(&fragment->list, &b->frags_list);
}

/******************************************************
 * 
 * Function  : grow_buffers 
 *
 * Arguments : cavium_device *, pool 
 * Returns   : Uint32 
 *
 * This function grows buffers in Pool p by allocating 
 * from higher pool and fragmenting the higher pool buffer
 *
 ******************************************************/
static Uint32
grow_buffers(cavium_device *RESERVED, pool p)
{
   Uint8 *buf = NULL;

   MPRINTFLOW();
   switch (p) 
   {
      case ex_tiny:
         buf = get_buffer_from_init_pool(NULL, &buffer[tiny]);
         if (buf) 
         {
            break;
         }
      case tiny:
         buf = get_buffer_from_init_pool(NULL, &buffer[small]);
         if (buf) 
         {
            break;
         }
      case small:
         buf = get_buffer_from_init_pool(NULL, &buffer[medium]);
         if (buf) 
         {
            break;
         }
      case medium:
         buf = get_buffer_from_init_pool(NULL, &buffer[large]);
         if (buf) 
         {
            break;
         }
      case large:
         buf = get_buffer_from_init_pool(NULL, &buffer[huge_pool]);
         if (buf) 
         {
            break;
         }
      case huge_pool:
      case os:
         return 1;
   }

   if (buf) 
   {
      int ret = 0;
      cavium_spin_lock_softirqsave(&fragment_lock);
      if (fragment_free_list_index == MAX_BUFFER_CHUNKS) {
         ret = 1;
      } else {
          fragment_buffer(NULL, p, buf);
      }
      cavium_spin_unlock_softirqrestore(&fragment_lock);
      if (ret) 
      {
         put_buffer_in_pool(NULL, buf);
         return 1;
      }
   }

   return 0;
}

#if 0
/* Defragment the buffers from cavium_buffer_t into pool p back */
static Uint32
defragment_buffers(cavium_device *RESERVED, cavium_buffer_t *b, pool p)
{
   cavium_list_head *tmp, *tmp1;
   Uint32 ret = 1;

   cavium_list_for_each_safe(tmp, tmp1, &b->frags_list) {
      cavium_frag_buf_t *frag = list_entry(tmp, cavium_frag_buf_t, list);
      buffer_tag * t = (buffer_tag*)((Uint32)(frag->big_buf) - sizeof(buffer_tag));
      if (frag->not_allocated) {
         if (t->pool != p) { 
            continue;
         } else {
            cavium_list_del(&frag->list);
            put_fragment(NULL, *frag);
            put_buffer(b, t->index);
            ret = 0;
         }
      }
   }
   return ret;
}

/* Trying to reclaim back all the possible buffers into pool p */

/*********************************************** 
 * Function  : reclaim_buffers_in_pool
 *
 * Arguments : cavium_device *, pool
 * Returns   : static Uint32 
 *
 * This function tries to reclaim back all the 
 * possible buffers into pool p
 *
 ***********************************************/
static Uint32
reclaim_buffers_in_pool(cavium_device * RESERVED, pool p)
{
   Uint32 ret = 1;

   switch (p) {
      case huge_pool:
         if (!defragment_buffers(NULL, &buffer[large], p)) {
            ret = 0;
         }
      case large:
         if (!defragment_buffers(NULL, &buffer[medium], p)) {
            ret = 0;
         }
      case medium:
         if (!defragment_buffers(NULL, &buffer[small], p)) {
            ret = 0;
         }
      case small:
         if (!defragment_buffers(NULL, &buffer[tiny], p)) {
            ret = 0;
         }
      case tiny:
         if (!defragment_buffers(NULL, &buffer[ex_tiny], p)) {
            ret = 0;
         }
         break;
      case ex_tiny:
         cavium_error("Trying to reclaim for buffers of Ex_tiny size\n");
         break;
   }
   return ret;
}
#endif

/************************************************************
 * Function  : get_buffer_from_pool
 *
 * Arguments : void * , int 
 * Returns   : Uint8 *
 *
 * This function tries to get the requested buffer 
 * from the preallocated pool of buffers.If the preallocated
 * pool has exhausted, then it tries to grow the buffers 
 * from the next higher pool 
 * 
 *************************************************************/

Uint8 *
get_buffer_from_pool(void *RESERVED,int size)
{
   Uint8 * buf;
   pool p;

   MPRINTFLOW();

get_buf:
   if (size <= EX_TINY_BUFFER_CHUNK_SIZE) 
   {
       buf = get_buffer(&buffer[ex_tiny]);
       p = ex_tiny;
   }
#ifdef CAVIUM_HUGE_MEMORY
   else if (size <= TINY_BUFFER_CHUNK_SIZE) 
   {
      buf = get_buffer(&buffer[tiny]);
      p = tiny;
   } else if (size <= SMALL_BUFFER_CHUNK_SIZE) 
   {
      buf = get_buffer(&buffer[small]);
      p = small;
   } else if (size <= MEDIUM_BUFFER_CHUNK_SIZE) 
   {
      buf = get_buffer(&buffer[medium]);
      p = medium;
   } else if (size <= LARGE_BUFFER_CHUNK_SIZE) 
   {
      buf = get_buffer(&buffer[large]);
      p = large;
   } else if (size <= HUGE_BUFFER_CHUNK_SIZE) 
   {
      buf = get_buffer(&buffer[huge_pool]);
      p = huge_pool;
   }
#endif
 else 
   {
#ifdef CAVIUM_OS
      buf = cavium_malloc_dma(size + sizeof(buffer_tag), NULL);
      if (buf) 
      {
         ((buffer_tag *)buf)->pool = os;
         return (buf + sizeof(buffer_tag));
      }
      else
#endif
      {
         cavium_print("Out of memory %d\n",size);
                return NULL;   
      }
   }
   
   /* No Free buffers available */

   if (buf == NULL) 
   {
      /* Try growing buffers */
      if (grow_buffers(NULL, p)) 
      {
         /* Unable to grow */
#if 0
         if (reclaim_buffers_in_pool(NULL, p)) 
            /* no buffers, allocate from OS */
#endif
#ifdef CAVIUM_OS
         buf = cavium_malloc_dma(size + sizeof(buffer_tag), NULL);
         if (buf) 
         {
            ((buffer_tag *)buf)->pool = os;
            return (buf + sizeof(buffer_tag));
         } else 
#endif
         {
            cavium_error("Unable to allocate buffer\n");
            return buf;
         }
      }
      goto get_buf;
   }
   return buf;
}

/*************************************************
 * Function : check_in_fragmented_pool
 *
 * Arguments    : cavium_device *, Uint8 *
 * Return Value : Uint32 
 *
 * This function checks if a buffer is from a 
 * fragmented pool, and if so places the buffer 
 * on the free list
 *
 *************************************************/

static Uint32
check_in_fragmented_pool(cavium_device *RESERVED, Uint8 *b)
{
   struct cavium_list_head *tmp, *tmp1;

   MPRINTFLOW();
   cavium_spin_lock_softirqsave(&fragment_lock);

   cavium_list_for_each_safe(tmp, tmp1, &allocated_list_head) 
   {
      cavium_frag_buf_t *frag = cavium_list_entry(tmp, cavium_frag_buf_t, alloc_list);
      Uint16 i;
      buffer_tag * t = (buffer_tag*)((ptrlong)(frag->big_buf) - sizeof(buffer_tag));

      for (i = 0; i < frag->frags_count; i++) 
      {
         if (frag->address[i] == b) 
         {
            int big_buf_to_be_freed = 0;
            frag->free_list_index--;
            frag->free_list[frag->free_list_index] = i;
            other_pools[frag->p]--;

            if (frag->free_list_index == 0) 
            {
               frag->not_allocated = 1;
               cavium_list_del_init(&frag->alloc_list);
               /* Put back the big buffer */
               cavium_list_del_init(&frag->list);
               fragment_buf_stats[frag->p] -= frag->frags_count;
               put_fragment(NULL, *frag);
               big_buf_to_be_freed = 1;
            }
            cavium_spin_unlock_softirqrestore(&fragment_lock);
            if (big_buf_to_be_freed) 
            {
               put_buffer(&buffer[t->pool], t->index);
            }
            return 0;
         }
      }
   }
   cavium_spin_unlock_softirqrestore(&fragment_lock);
   return 1;
}

/******************************************************** 
 *
 * Function : put_buffer_in_pool
 * 
 * Arguments     : void * , Uint8 * 
 * Return Value  : Returns void
 *
 * This function releases the buffer to the buffer pool
 * manager. 
 *
 ********************************************************/

void 
put_buffer_in_pool(void *RESERVED, Uint8 *b)
{
   buffer_tag* t = NULL;

   MPRINTFLOW();
   if (!check_in_fragmented_pool(NULL, b)) 
   {
      return;
   }
   
   t = (buffer_tag*)(b - sizeof(buffer_tag));

   switch (t->pool) 
   {
      case ex_tiny:
         put_buffer(&buffer[ex_tiny], t->index);
         break;
   
      case tiny:
         put_buffer(&buffer[tiny], t->index);
         break;

      case small:
         put_buffer(&buffer[small], t->index);
         break;

      case medium:
         put_buffer(&buffer[medium], t->index);
         break;

      case large:
         put_buffer(&buffer[large], t->index);
         break;

      case huge_pool:
         put_buffer(&buffer[huge_pool], t->index);
         break;
#ifdef CAVIUM_OS
      case os:
         cavium_free_dma((Uint8 *)t);
         return;
#endif
      default:
         /* bad, very bad! this should never happen. */
         cavium_error( 
            "Unsupported pool type (%d) in put_buffer_in_pool\n", 
            t->pool);
         return;
   }
}

/*
 * $Id: buffer_pool.c,v 1.5 2008/09/30 13:15:17 jsrikanth Exp $
 * $Log: buffer_pool.c,v $
 * Revision 1.5  2008/09/30 13:15:17  jsrikanth
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
 * Revision 1.4  2008/02/22 10:18:52  aramesh
 * N1_SANITY is set always.
 *
 * Revision 1.3  2007/12/05 14:31:12  lpathy
 * bug fix in fragmentation
 *
 * Revision 1.2  2007/06/06 08:47:29  rkumar
 * CAVIUM_HUGE_MEMORY define missing
 *
 * Revision 1.1  2007/01/06 02:47:40  panicker
 * * first cut - NITROX PX driver
 *
 * Revision 1.21  2006/11/15 06:42:44  kchunduri
 * In 'put_buffer_in_pool' check in fragment buffer list should precede all pool checks.
 *
 * Revision 1.20  2006/11/10 09:22:38  apappu
 * 'alloc_buffer_stats' are locked while updating. Else you may see wrong statistics on SMP platform.
 *
 * Revision 1.19  2006/09/28 08:57:06  kchunduri
 * --encapsulate all dynamic allocations under CAVIUM_OS
 *
 * Revision 1.18  2005/11/17 13:31:09  kanantha
 * Updating with the 64 bit modifications, with proper matching of data types
 *
 * Revision 1.17  2005/10/13 09:18:42  ksnaren
 * fixed compile errors for windows xp
 *
 * Revision 1.16  2005/09/28 15:50:26  ksadasivuni
 * - Merging FreeBSD 6.0 AMD64 Release with CVS Head
 * - Now context pointer given to user space applications is physical pointer.
 *   So there is no need to do cavium_vtophys() of context pointer.
 *
 * Revision 1.15  2005/09/21 06:54:49  lpathy
 * Merging windows server 2003 release with CVS head
 *
 * Revision 1.14  2005/09/06 14:38:57  ksadasivuni
 * - Some cleanup error fixing and spin_lock_destroy functionality added to osi.
 *   spin_lock_destroy was necessary because of FreeBSD 6.0.
 *
 * Revision 1.13  2005/09/06 07:08:22  ksadasivuni
 * - Merging FreeBSD 4.11 Release with CVS Head
 *
 * Revision 1.12  2005/08/13 06:48:03  sgadam
 * SSL-FIPS merged code
 *
 * Revision 1.11  2005/06/29 19:41:26  rkumar
 * 8-byte alignment problem fixed with N1_SANITY define.
 *
 * Revision 1.10  2005/06/13 06:35:42  rkumar
 * Changed copyright
 *
 * Revision 1.9  2005/05/20 14:34:05  rkumar
 * Merging CVS head from india
 *
 * Revision 1.8  2005/02/01 04:11:07  bimran
 * copyright fix
 *
 * Revision 1.7  2004/08/03 20:44:11  tahuja
 * support for Mips Linux & HT.
 *
 * Revision 1.6  2004/06/28 20:37:42  tahuja
 * Fixed compiler warnings on NetBSD. changed mdelay in check_completion from 1ms to 2ms.
 *
 * Revision 1.5  2004/06/03 21:21:58  bimran
 * included cavium_list.h
 * fixed list* calls to use cavium_list
 *
 * Revision 1.4  2004/05/28 17:56:09  bimran
 * added some missing locks.
 *
 * Revision 1.3  2004/05/02 19:44:29  bimran
 * Added Copyright notice.
 *
 * Revision 1.2  2004/04/30 00:28:25  bimran
 * changed spin_locks to softirq save modes.
 *
 * Revision 1.1  2004/04/15 22:40:48  bimran
 * Checkin of the code from India with some cleanups.
 *
 */

