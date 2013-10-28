/* linux_sysdep.h */
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
#ifndef _LINUX_SYSDEP_H
#define _LINUX_SYSDEP_H

/*Define PORT_TO_64BIT for 64bit aligned API data structure.*/
#define PORT_TO_64BIT

#ifndef CAVIUM_NO_MMAP
#define CAVIUM_NO_MMAP
#endif

#ifndef CTX_MEM_IS_HOST_MEM
#define CTX_MEM_IS_HOST_MEM
#endif

#ifndef DMA_DYN_MAP
#define DMA_DYN_MAP
#endif

#ifdef __KERNEL__
#include <linux/types.h>
#include <linux/sched.h>
#ifdef DMA_DYN_MAP
#include <linux/pci.h>
#endif
#else
#include <sys/types.h>
#endif
typedef  u_int8_t          Uint8;
typedef  u_int16_t         Uint16;
typedef  u_int32_t         Uint32;
typedef  u_int64_t 	   Uint64;

typedef unsigned long ptrlong;

#ifndef OP_BUF_ALIGN
#define OP_BUF_ALIGN	0
#endif

#ifndef KEY_BUF_ALIGN
#define KEY_BUF_ALIGN	6
#endif

#ifdef __KERNEL__
#define CSP1_KERNEL
#endif

#ifndef CAVIUM_IPSEC

#ifdef __KERNEL__

#include <linux/version.h>
#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,6,18))  
#include <linux/config.h>
#endif

#if (LINUX_VERSION_CODE > KERNEL_VERSION(2,6,0))  
#include <linux/highmem.h>
#endif

#ifdef CNS3000
typedef struct {
	uint32_t unused;
	unsigned long config_addr;
} cns3000_dev_t;
#endif

#
#if 0
#undef __NO_VERSION__ /* don't define kernel_verion in module.h */
#if defined(CONFIG_MODVERSIONS) && !defined(MODVERSIONS)
#  define MODVERSIONS
#endif /*CONFIG_MODVERSIONS*/

#ifdef MODVERSIONS
#  include <linux/modversions.h>
#endif /*MODVERSIONS*/
#endif

#include <linux/module.h>
#include <linux/kernel.h> 
#include <linux/slab.h> 
#include <linux/types.h>  
#include <linux/delay.h>
#include <linux/interrupt.h>
#include <linux/pci.h>
#include <asm/byteorder.h>
#include <linux/vmalloc.h>
#include <asm/uaccess.h>
#if LINUX_VERSION_CODE > KERNEL_VERSION(2,6,0)
#include <linux/smp_lock.h>
#endif


#if 0
#define MPRINTFLOW()   \
        printk("--> %s:%s\n", __FILE__, __FUNCTION__)
#else
#define MPRINTFLOW()  do{}while(0) 
#endif

#ifndef __CAVIUM_LITTLE_ENDIAN
#define __CAVIUM_LITTLE_ENDIAN 4321
#endif

#ifndef __CAVIUM_BIG_ENDIAN
#define __CAVIUM_BIG_ENDIAN 1234
#endif


#ifdef __LITTLE_ENDIAN_BITFIELD
#define __CAVIUM_BYTE_ORDER __CAVIUM_LITTLE_ENDIAN 
#else /* presumably Big Endian :-) */
#define __CAVIUM_BYTE_ORDER __CAVIUM_BIG_ENDIAN 
#endif

#if BITS_PER_LONG == 32
#define CAST64(v) ((unsigned long long)(v))
#elif BITS_PER_LONG == 64
#define CAST64(v) ((unsigned long long)(unsigned long)(v))
#else
#error "Unknown system architecture"
#endif

#define CAVIUM_PCI_DMA_TODEVICE       PCI_DMA_TODEVICE
#define CAVIUM_PCI_DMA_FROMDEVICE     PCI_DMA_FROMDEVICE
#define CAVIUM_PCI_DMA_BIDIRECTIONAL  PCI_DMA_BIDIRECTIONAL

#define CAVIUM_HZ		      HZ
#if LINUX_VERSION_CODE > KERNEL_VERSION(2,6,0)
#define INTERRUPT_RETURN
#else
typedef void irqreturn_t;
#endif

/*
 * cavium_print
 *
 * Prints message (x) to stdout
 */
typedef dma_addr_t cavium_dmaaddr;

extern int cavium_debug_level;
#define cavium_print(format,...)	if(cavium_debug_level) \
						printk(format,## __VA_ARGS__)
#define cavium_error(format,...)	printk(format,## __VA_ARGS__)

#define cavium_dbgprint(format,...)	if(cavium_debug_level > 1) \
						printk(format,## __VA_ARGS__)


typedef void (*CallBackFn)(int, void *);
/*
 * cavium_spinlock_t
 */
typedef spinlock_t  cavium_spinlock_t;		
#define CAVIUM_SPIN_LOCK_UNLOCKED SPIN_LOCK_UNLOCKED

/* 
 * cavium_semaphore
 */
typedef struct semaphore  cavium_semaphore; 


/*
 * cavium_spin_lock_init
 *
 * initializes spinlock
 */
#define cavium_spin_lock_init(lock)		spin_lock_init((lock))


/*
 * cavium_spin_lock
 *
 * acquire lock
 */
#define cavium_spin_lock(lock)			spin_lock((lock))	



/*
 * cavium_spin_unlock
 *
 * release lock
 */
#define cavium_spin_unlock(lock)		spin_unlock((lock))	

/* Added for compatibility with BSD series */
#define cavium_spin_lock_destroy(lock)		
/*
 * cavium_spin_lock_irq
 *
 * acquire lock
 */
#define cavium_spin_lock_irq(lock)			spin_lock_irq((lock))	



/*
 * cavium_spin_unlock_irq
 *
 * release lock
 */
#define cavium_spin_unlock_irq(lock)		spin_unlock_irq((lock))	

/*
 * cavium_spin_lock_irqsave
 *
 * acquire lock, disable interrupt and store interrupt status in flags
 */
#define cavium_spin_lock_irqsave(lock, flags)			spin_lock_irqsave((lock), (flags))	



/*
 * cavium_spin_unlock_irqrestore
 *
 * release lock and restore interrupts
 */
#define cavium_spin_unlock_irqrestore(lock, flags)		spin_unlock_irqrestore((lock), (flags))


/*
 * cavium_spinlock_softirqsave
 * acquire lock in softirq save mode
 */

#define cavium_spin_lock_softirqsave(lock) spin_lock_bh((lock))


/*
 * cavium_spin_unlock_softirqrestore
 * releases lock in softirq save mode
 */
#define cavium_spin_unlock_softirqrestore(lock) spin_unlock_bh((lock))

static inline void cavium_softirq_disable(int _flags)
{	
	local_bh_disable();
}
static inline void cavium_softirq_enable(int _flags)
{
	local_bh_enable(); 
}

#if 0
/*
 * cavium_spinlock_softirqsave
 * acquire lock in softirq save mode
 */
#define cavium_spin_lock_softirqsave(lock)	spin_lock_bh(lock)


/*
 * cavium_spin_unlock_softirqrestore
 * releases lock in softirq save mode
 */
#define cavium_spin_unlock_softirqrestore(lock)		spin_unlock_bh(lock)

#endif

/*
 * cavium_sema_init
 *
 * Initializes semaphore
 */

#define cavium_sema_init(sema, count)	sema_init((sema),(count))

/*
 * cavium_sema_down
 *
 */
#define cavium_sema_down(sema)	down_trylock((sema)) 
#define cavium_sema_down_interruptible(sema)	down_interruptible((sema)) 



/*
 * cavium_sema_up
 *
 */
#define cavium_sema_up(sema)	up((sema))


/*
 * write_PKP_register(pdev, addr, val) 
 */
#ifdef CNS3000
#define write_PKP_register(pdev,addr,value) \
{ \
	*(Uint32 *)addr = value; \
}
#else
#define write_PKP_register(pdev,addr,value) \
{ \
        if((pdev)->device_id == NPX_DEVICE) { \
                writel((value),(addr)); \
        } \
        else { \
                outl((value),(ptrlong)(addr)); \
        }; \
}
#endif

/*
 * read_PKP_register(pdev, addr, pvalue)
 */
#ifdef CNS3000
#define read_PKP_register(pdev, addr, pvalue) \
{ \
   *(pvalue) = *(Uint32 *)addr; \
}	
#else
#define read_PKP_register(pdev,addr,pvalue) \
{ \
        if((pdev)->device_id == NPX_DEVICE) { \
                *(pvalue)=readl(addr); \
        } \
        else { \
                *(pvalue)=inl((ptrlong)(addr)); \
        }; \
}
#endif

/*
 * write_PCI_register(pdev, offset, value)
 */
#ifndef CNS3000
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,0)
#define write_PCI_register(pdev,offset,value)	((struct pci_dev *)((cavium_device_ptr)(pdev))->dev)->bus->ops->write_dword((struct pci_dev *)((cavium_device_ptr)(pdev))->dev,(offset),(value))
#else
#define write_PCI_register(pdev, offset,value)	((struct pci_dev *)((cavium_device_ptr)(pdev))->dev)->bus->ops->write( (struct pci_bus*)(((struct pci_dev *)pdev->dev)->bus),((struct pci_dev*)pdev->dev)->devfn,(offset), 4,(value))
#endif
#else
//#define write_PCI_register(pdev, offset,value)	 *(uint32_t *)(((cns3000_dev_t *)((cavium_device_ptr)(pdev))->dev)->config_addr + offset) = (value);
#define write_PCI_register(pdev, offset,value)	 ;
#endif

/*
 * read_PCI_register(pdev, offset, pvalue)
 */
#ifndef CNS3000
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,0)
#define read_PCI_register(pdev, offset,pvalue)	((struct pci_dev *)((cavium_device_ptr)(pdev))->dev)->bus->ops->read_dword((struct pci_dev *)((cavium_device_ptr)(pdev))->dev,(offset),(unsigned int *)pvalue);
#else
/* Kernel > 2.6.0 */
#define read_PCI_register(pdev, offset,pvalue)	((struct pci_dev *)((cavium_device_ptr)(pdev))->dev)->bus->ops->read( (struct pci_bus*)(((struct pci_dev *)pdev->dev)->bus),((struct pci_dev*)pdev->dev)->devfn,(offset), 4,(unsigned int *)(pvalue))
#endif
#else
// #define read_PCI_register(pdev, offset,pvalue)	 *(uint32_t *)pvalue = *(uint32_t *)(((cns3000_dev_t *)((cavium_device_ptr)(pdev))->dev)->config_addr + offset);
#define read_PCI_register(pdev, offset,pvalue)	 ;
#endif

/*
 * cavium_udelay(value)	
 *	
 * delays execution by value micro-seconds
 */
#define cavium_udelay(value)		udelay((value))


/*
 * cavium_mdelay(value)	
 *	
 * delays execution by value milli-seconds
 */
#define cavium_mdelay(value)		mdelay((value))



/*
 * cavium_jiffies
 *
 * system ticks to keep track of elapsed time
 */

#define   cavium_jiffies	jiffies

/*
 * when comapring jiffies use these safe macros which take care 
 * of rollover problems
 */
#define	cavium_time_before(a,b) time_before(a,b)
#define cavium_time_after(a,b) time_after(a,b)

/*wmb() support*/
#define cavium_wmb() wmb()

/*
 * cavium_malloc_dma( size, flags)
 *
 * allocates a contiguous non_paged kernel  memory chunk.
 *
 */
#define cavium_malloc_dma(size, flags)	kmalloc((size),GFP_ATOMIC)
#define cavium_malloc(size, flags)      kmalloc((size),GFP_ATOMIC)



/*
 * cavium_free_dma
 *
 * frees a buffer previously allocated by cavium_malloc_dma
 *
 */
#define cavium_free_dma(pbuffer)	kfree((pbuffer))	
#define cavium_free(pbuffer)        kfree((pbuffer))


/*
 * cavium_malloc_nc_dma(size, flags)
 *
 * allocates a contiguous non_cached, non_paged kernel x memory chunk.
 *
 */
#ifdef DMA_DYN_MAP
#ifdef CNS3000
#define cavium_malloc_nc_dma(pdev,size,pbus_addr) \
        ({ \
               ptrlong vaddr; \
               vaddr = (ptrlong)pci_alloc_consistent(NULL,size,pbus_addr);\
               vaddr; \
         })
#else
#define cavium_malloc_nc_dma(pdev,size,pbus_addr) \
        ({ \
               ptrlong vaddr; \
               vaddr = (ptrlong)pci_alloc_consistent(pdev->dev,size,pbus_addr);\
               vaddr; \
         })
#endif
#else

#define cavium_malloc_nc_dma(pdev,size,pbus_addr) \
	({ \
		ptrlong vaddr; \
		vaddr = (ptrlong)kmalloc ((size), GFP_ATOMIC | GFP_KERNEL); \
		*(pbus_addr) = (unsigned long)__virt_to_phys((void *)vaddr); \
		vaddr; \
	})
#endif

/*
 * cavium_free_nc_dma(size, flags)
 *
 * frees the buffer previously allocated by cavium_malloc_nc_dma.
 *
 */
#ifdef DMA_DYN_MAP
#ifdef CNS3000
#define cavium_free_nc_dma(pdev,size,pcpu_addr,bus_addr) \
                pci_free_consistent(NULL,size,pcpu_addr,bus_addr)
#else
#define cavium_free_nc_dma(pdev,size,pcpu_addr,bus_addr) \
                pci_free_consistent(pdev->dev,size,pcpu_addr,bus_addr)
#endif
#else
#define cavium_free_nc_dma(pdev,size,pcpu_addr,bus_addr) \
	kfree((pcpu_addr))
#endif


/*
 *  cavium_map_kernel_buffer(pdev,pbuffer,size,flags)
 *   
 *  maps buffer to DMAable location wgich was previously allocated by
 *  cavium_malloc_dma.
 *  
 *
 */
#ifdef DMA_DYN_MAP
#ifdef CNS3000
#define cavium_map_kernel_buffer(pdev,pbuffer,size,flags) ({ \
                     unsigned int ret;\
                     ret=pci_map_single(NULL,(void *)(pbuffer),(size),flags);\
                     ret;\
})
#else
#define cavium_map_kernel_buffer(pdev,pbuffer,size,flags) \
                     pci_map_single((pdev)->dev,(void *)(pbuffer),(size),flags)
#endif
#else
#define cavium_map_kernel_buffer(pdev,pbuffer,size,flags) \
                     cavium_vtophys((pbuffer))
#endif


/*
 *  cavium_unmap_kernel_buffer(pdev,bus_addr,size,flags)
 *   
 *  unmaps buffer which was previuosly mapped by cavium_map_kernel_buffer.
 *  
 *
 */
#ifdef DMA_DYN_MAP
#ifdef CNS3000
#define cavium_unmap_kernel_buffer(pdev,bus_addr,size,flags) \
                     pci_unmap_single(NULL,(bus_addr),(size),flags)
#else
#define cavium_unmap_kernel_buffer(pdev,bus_addr,size,flags) \
                     pci_unmap_single((pdev)->dev,(bus_addr),(size),flags)
#endif
#else
#define cavium_unmap_kernel_buffer(pdev,bus_addr,size,flags) 
#endif


/* 
 * cavium_sync_kernel_buffer(pdev,buas_addr,size,flags)
 *
 * flushes the content of the buffer to physical memory.
 *
 */
#ifdef CNS3000
#define cavium_flush_cache(pdev,size,v_addr,bus_addr,flags) \
	pci_dma_sync_single_for_device(NULL, virt_to_phys((Uint8 *)v_addr), size, PCI_DMA_TODEVICE);
#else
#define cavium_flush_cache(pdev,size,v_addr,bus_addr,flags) 
#endif

/*
 * invalidate cache
 */
#ifdef CNS3000
#define cavium_invalidate_cache(pdev,size,v_addr,bus_addr,flags) \
	pci_dma_sync_single_for_device(NULL, virt_to_phys((Uint8 *)v_addr), size, PCI_DMA_FROMDEVICE);
#else
#define cavium_invalidate_cache(pdev,size,v_addr,bus_addr,flags) 
#endif

/*
 * cavium_malloc_virt(size)
 *
 * allocates virtual memory to necessary contiguous and mapped to physical memory.
 *
 */
#define cavium_malloc_virt(size) vmalloc((size))


/*
 * cavium_free_virt(size)
 *
 * frees virtual memory.
 *
 */
#define cavium_free_virt(pbuffer) vfree((pbuffer))


/* 
 * cavium_vtophys
 *
 * Returns bus/physical (DMAable) address
 */
#define cavium_vtophys(vaddr)	(unsigned long)__virt_to_phys((Uint8 *)vaddr)
//#define cavium_vtophys(vaddr)	virt_to_bus((Uint8 *)vaddr)



/* 
 * cavium_phystov
 *
 * Returns kernel address 
 */
#define cavium_phystov(paddr)	(void *)__phys_to_virt((paddr))
//#define cavium_phystov(paddr)	bus_to_virt((paddr))



/*
 * cavium_copy_in
 *
 * Copy size bytes from src to dest buffer.
 * For OS with user and system/kernel level partitioning, 
 * it copies  bytes from user to kernel layer.
 * For others, it could be just memcpy.
 *
 */
#define cavium_copy_in(dest, src, size)		copy_from_user((dest), (src), (size))	

/*
 * cavium_copy_out
 *
 * Copy size bytes from src to dest buffer.
 * For OS with user and system/kernel level partitioning, 
 * it copies  bytes from kernel to user layer.
 * For others, it could be just memcpy.
 *
 */
#define cavium_copy_out(dest, src, size)	copy_to_user((dest), (src), (size))	

/*
 * cavium_memcpy(dest, src, size)
 *
 * copies size bytes from src to dest.
 *
 */
#define cavium_memcpy(dest, src, size)		memcpy((dest), (src), (size))



/*
 * cavium_memset(buf, val, size)
 *
 * sets size bytes pointed to by buf to val.
 *
 */
#define cavium_memset(buf, val, size)		memset((buf), (val), (size))


/*
 * wait channel 
 */
typedef wait_queue_head_t cavium_wait_channel;

typedef pid_t cavium_pid_t;

/*
 * init_wait_channel
 */

#define init_wait_channel(wc)		init_waitqueue_head(wc)
#define cavium_get_channel(wc)		init_wait_channel(wc)

/*
 * sleep
 */
#define cavium_yield(wc,to)	schedule() 

#define cavium_sleep_timeout(wc,to)	interruptible_sleep_on_timeout(wc,to)

#define cavium_sleep(wc) interruptible_sleep_on(wc)

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,0)
#define cavium_wait_interruptible_timeout(wc,cond,to) \
		cavium_sleep_timeout(&wc,to)
#else
#define cavium_wait_interruptible_timeout(wc,cond,to) \
		wait_event_interruptible_timeout(wc,cond,to)
#endif

/*
 * wakeup
 */

#define cavium_wakeup(wc)	wake_up_interruptible(wc)

#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,6,27))
#define cavium_send_signal(pid, signo) kill_proc(pid, signo, 1)
#else
#define cavium_send_signal(pid, signo) kill_pid(task_pid(current), signo, 1)
#endif


/*
 *  Tasklets
 */

typedef struct tasklet_struct cavium_tasklet_t;

#define cavium_tasklet_init(taskp, func, data)  tasklet_init(taskp, func, (ptrlong) data)

#define cavium_tasklet_kill(taskp)              tasklet_kill(taskp)

#define cavium_tasklet_schedule(taskp)          tasklet_schedule(taskp)

#ifndef CAVIUM_NO_MMAP

/*
 * Get kernel address
 */

static inline unsigned long uvirt_to_kva(pgd_t *pgd, unsigned long adr)
{
        unsigned long ret = 0UL;
	pmd_t *pmd;
	pte_t *ptep, pte;

#if (LINUX_VERSION_CODE > KERNEL_VERSION(2,4,20))  
        pud_t *pud; 
#endif
	if (!pgd_none(*pgd)) {
#if (LINUX_VERSION_CODE > KERNEL_VERSION(2,4,20))  
		pud = pud_offset(pgd,adr);
                pmd = pmd_offset(pud, adr);
#else
                pmd = pmd_offset(pgd, adr);
#endif
                if (!pmd_none(*pmd)) {
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,4,20) 
			ptep = pte_offset(pmd, adr);
#elif (LINUX_VERSION_CODE >= KERNEL_VERSION(2,4,20))  
                        ptep = pte_offset_map(pmd, adr);
#endif
                        pte = *ptep;
#if (LINUX_VERSION_CODE > KERNEL_VERSION(2,4,20))  
			pte_unmap(ptep);
#endif
                        if(pte_present(pte)) {
				ret  = (unsigned long) page_address(pte_page(pte));
				ret |= (adr & (PAGE_SIZE - 1));
			}
                }
        }
        cavium_dbgprint("uv2kva(%lx-->%lx)\n", adr, ret);
	return ret;
}

/* 
 * It is must to have these statically defined, they can be made extern, but it
 * does not follow gcc semantics
 * And, BTW this will not work with -fno-inline option, so inlining has to be 
 * enabled
 */ 

static inline unsigned char * cavium_get_kernel_address(unsigned char *addr)
{
	unsigned char * out;
	
	down_write(&current->mm->mmap_sem);
	spin_lock(&current->mm->page_table_lock);
	out = (unsigned char *)uvirt_to_kva(pgd_offset(current->mm, (unsigned long)addr), 
					    (unsigned long)addr);
	spin_unlock(&current->mm->page_table_lock);
	up_write(&current->mm->mmap_sem);

	return out;
}	
#else
static inline unsigned char * cavium_get_kernel_address(unsigned char *addr)
{
	return NULL;
}
#endif

static inline pid_t cavium_get_pid(void)
{
	return current->pid;
}


#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,0) 
#define CAVIUM_MOD_INC_USE_COUNT MOD_INC_USE_COUNT
#define CAVIUM_MOD_DEC_USE_COUNT MOD_DEC_USE_COUNT
#else
#define CAVIUM_MOD_INC_USE_COUNT try_module_get(THIS_MODULE);
#define CAVIUM_MOD_DEC_USE_COUNT module_put(THIS_MODULE);
#endif

#define CAVIUM_SIGNAL_NUM	SIGUSR1


#ifdef N1_TIMER_ROLLOVER
#define  cavium_check_timeout(time_to_check, system_time) \
				cavium_time_before((time_to_check), (system_time))
#else
#define  cavium_check_timeout(time_to_check, system_time) \
				((time_to_check) < (cavium_jiffies))
#endif

#if defined(__i386__)

static inline Uint64 cavium_rdtsc(void)
{
     Uint64 x;
     __asm__ volatile (".byte 0x0f, 0x31" : "=A" (x));
     return x;
}
#elif defined(__x86_64__)

static inline Uint64 cavium_rdtsc(void)
{
  unsigned hi, lo;
  __asm__ __volatile__ ("rdtsc" : "=a"(lo), "=d"(hi));
  return ( (Uint64)lo)|( ((Uint64)hi)<<32 );
}

#elif defined(__powerpc__)

static inline Uint64 cavium_rdtsc(void)
{
  Uint64 result=0;
  Uint32 upper, lower,tmp;
  __asm__ volatile(
                "0:                  \n"
                "\tmftbu   %0           \n"
                "\tmftb    %1           \n"
                "\tmftbu   %2           \n"
                "\tcmpw    %2,%0        \n"
                "\tbne     0b         \n"
                : "=r"(upper),"=r"(lower),"=r"(tmp)
                );
  result = upper;
  result = result<<32;
  result = result|lower;
  return(result);
}

#else

#ifdef CNS3000
#define BIT_CONT(x) (1 << x)
static inline void cavium_rdtsc_init(void)
{
	uint32_t result_pm = 0;
	uint32_t write_pm = 0;
	/* disable pmc */
	write_pm = 0;
	asm volatile ("mcr p15, 0, %0, c15, c12, 0" : : "r" (write_pm));
	asm volatile ("mrc p15, 0, %0, c15, c12, 0" : "=r" (result_pm));
	/* enable pmc */
	write_pm = BIT_CONT(0) | BIT_CONT(2);
	asm volatile ("mcr p15, 0, %0, c15, c12, 0" : : "r" (write_pm));
	asm volatile ("mrc p15, 0, %0, c15, c12, 0" : "=r" (result_pm));
//	printk (KERN_CRIT "rdtsc_pm in cns3xxx is %u\n", result_pm);
}

static inline Uint64 cavium_rdtsc(void)
{
	uint32_t result = 0;
	asm volatile ("mrc p15, 0, %0, c15, c12, 1" : "=r" (result));
    return result;
}

#else
static inline Uint64 cavium_rdtsc(void)
{
	return cavium_jiffies;
}

#endif
#endif

static inline Uint32 cavium_speed_unit(void)
{
#if defined(__i386__) || defined(__x86_64__) || defined(__powerpc__)
	return cpu_khz;
#else
#ifdef CNS3000
#define CNS3000_CORE_CLK_KHZ 600000
	return CNS3000_CORE_CLK_KHZ;
#else
	return CAVIUM_HZ;
#endif
#endif
}



#else /* __KERNEL__ */
#include <fcntl.h>
#include <stdio.h>
#include <endian.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <netinet/in.h>

#if __BYTE_ORDER == __LITTLE_ENDIAN
#define __CAVIUM_BYTE_ORDER __CAVIUM_LITTLE_ENDIAN
#endif

#if __BYTE_ORDER == __BIG_ENDIAN
#define __CAVIUM_BYTE_ORDER __CAVIUM_BIG_ENDIAN
#endif

#endif /* __KERNEL__ */

#endif /* CAVIUM_IPSEC */
	 
#endif /* _LINUX_SYSDEP_H */

/*
 * $Id: linux_sysdep.h,v 1.21 2009/05/15 10:19:20 kmonendra Exp $
 * $Log: linux_sysdep.h,v $
 * Revision 1.21  2009/05/15 10:19:20  kmonendra
 * Added cavium_rdtsc() which return the current clock cycle of processor.
 *
 * Revision 1.20  2009/04/28 10:33:48  pnalla
 * Changed "cavium_send_signal" to use proper function depending on the kernel version under use.
 *
 * Revision 1.19  2009/03/14 10:05:53  jsrikanth
 * Operation and key buf align constats added
 *
 * Revision 1.18  2008/12/18 15:16:54  jsrikanth
 * pci BAR addr related changes and device count ioctl changes
 *
 * Revision 1.17  2008/12/16 12:04:42  jsrikanth
 * Added Common driver and Multi-Card Changes for FreeBSD
 *
 * Revision 1.16  2008/09/30 13:19:09  jsrikanth
 * Changed printk formatting
 *
 * Revision 1.15  2008/07/02 12:22:37  aramesh
 * deleted config_part and corresponding flags.
 *
 * Revision 1.14  2008/03/14 06:22:02  aramesh
 * CTX_MEM_IS_HOST_MEM is defined always.
 *
 * Revision 1.13  2008/02/22 09:10:09  aramesh
 * driver cleanup done.
 *
 * Revision 1.12  2008/02/15 09:23:13  dvenkata
 * config.h is not included in 2.6.18 kernel
 *
 * Revision 1.11  2007/10/22 08:44:29  aramesh
 * register addr is typecasted to ptrlong instead of Uint64 in read/write_PKP_register for compatability of 32bit and 64 bit machines.
 *
 * Revision 1.10  2007/10/18 09:19:18  lpathy
 * moved cavium_pcie_print to sysdep files
 *
 * Revision 1.9  2007/10/16 06:30:28  aramesh
 * --Changes to support NLite/N1 family.
 *
 * Revision 1.8  2007/07/16 12:33:33  tghoriparti
 * typecasting to volatile of reg addr is removed as it is not updating the proper registers
 *
 * Revision 1.7  2007/05/04 10:47:23  rsruthi
 * fix comipler warning.
 *
 * Revision 1.6  2007/05/01 05:41:01  kchunduri
 * * definition for cavium_wmb()
 *
 * Revision 1.5  2007/04/04 21:54:13  panicker
 * * Added support for CN1600
 * * correction for 2.6.19 and above.
 *
 * Revision 1.4  2007/02/21 23:29:14  panicker
 * * CAST64() macro fixed
 *
 * Revision 1.3  2007/02/20 23:16:00  panicker
 * * CAST64() macro modified
 *
 * Revision 1.2  2007/02/02 02:38:23  panicker
 * * _ENDIAN definition is now in linux_sysdep.h
 * * CAST64 - macro to typecast to 64 bits
 * * cavium_check_timeout() - macro to check timeout
 * * read/write_PKP_register - modified for PX
 *
 * Revision 1.1  2007/01/06 02:47:40  panicker
 * * first cut - NITROX PX driver
 *
 * Revision 1.39  2006/08/08 13:20:32  kchunduri
 * moved ptrlong definition from cavium_sysdep.h
 *
 * Revision 1.38  2006/08/01 08:03:38  kchunduri
 * cavium_wait_interruptible_timeout defined to replace deprecated interruptible_sleep_on_timeout
 *
 * Revision 1.37  2006/05/16 09:36:22  kchunduri
 * --support for Dynamic DMA mapping instead of virt_to_phys
 *
 * Revision 1.36  2006/01/19 09:51:10  sgadam
 * -IPsec 2.6.11 changes
 *
 * Revision 1.35  2006/01/19 06:56:42  pyelgar
 *    - Changed the cavium_softirq_en/disable macro to accept a flag as input.
 *      (It is required for freebsd).
 *
 * Revision 1.34  2005/12/14 09:23:06  kkiran
 * - Fixed compile error under Linux 2.4.20.
 *
 * Revision 1.33  2005/12/07 04:52:19  kanantha
 * Mapped the typedefs to system definitions:wq
 *
 * Revision 1.32  2005/11/21 06:00:23  kanantha
 * Removed warnings for MMAP mode on FC4 64 bit
 *
 * Revision 1.30  2005/10/19 09:25:55  sgadam
 * - fixed dependencies
 *
 * Revision 1.29  2005/10/11 12:00:11  sgadam
 * - moved pgtable.h inside define
 *
 * Revision 1.28  2005/09/28 12:40:01  pyelgar
 *    - Fixed the delay in driver polling mode for RHEL3.
 *
 * Revision 1.27  2005/09/27 11:48:18  sgadam
 * mmap issue fixed
 *
 * Revision 1.26  2005/09/27 09:28:23  sgadam
 * FC4 Warnings fixed
 *
 * Revision 1.25  2005/09/27 06:24:59  sgadam
 * Warning fixed
 *
 * Revision 1.24  2005/09/12 18:20:11  bimran
 * Fixed for FC4 SMP.
 *
 * Revision 1.23  2005/09/06 12:44:29  ksadasivuni
 * - Added cavium_spin_lock_destroy() for compatibility with BSD operating systems.
 *
 * Revision 1.22  2005/08/31 02:39:18  bimran
 * removed functions that we don't need for no mmap.
 *
 * Revision 1.21  2005/06/10 09:10:58  rkumar
 * pte_offset in 7.3 was not being used..
 *
 * Revision 1.20  2005/06/03 07:32:43  rkumar
 * *** empty log message ***
 *
 * Revision 1.19  2005/05/21 05:04:41  rkumar
 * Merge with India CVS head
 *
 * Revision 1.18  2005/02/03 19:21:14  tsingh
 * fixed kernel version dependency
 *
 * Revision 1.17  2005/02/01 04:12:05  bimran
 * copyright fix
 *
 * Revision 1.16  2005/01/28 18:31:46  mvarga
 * Fixed kernel version dependency (bimran)
 *
 * Revision 1.15  2005/01/26 20:33:20  bimran
 * Fixed dependency on RH distribution. Made it kernel version dependent.
 *
 * Revision 1.14  2005/01/18 01:30:58  tsingh
 * Fixed SMP lock issue on 2.4.27 kernel. It was the matter of just extra brackets on the macro. On other kernel unmodified code works just fine. May be just a kernel issue.(bimran)
 *
 * Revision 1.13  2005/01/06 18:57:05  mvarga
 * Put back to original.
 *
 * Revision 1.12  2005/01/06 18:43:32  mvarga
 * Added realtime support
 *
 * Revision 1.11  2004/08/13 18:22:16  tsingh
 * fixed pte_offset definition based on RedHat version.
 *
 * Revision 1.10  2004/07/06 21:31:24  tsingh
 * moved CallBackFn definition from linux_main.h to linux_sysdep.h
 *
 * Revision 1.9  2004/06/26 01:14:51  bimran
 * defined linux specific mod counts.
 *
 * Revision 1.8  2004/06/03 21:16:20  bimran
 * added invalidate cache
 *
 * Revision 1.7  2004/06/01 22:07:33  tsingh
 * typo fixed
 *
 * Revision 1.6  2004/05/28 17:54:50  bimran
 * cavium_malloc_dma and cavium_malloc now uses __GFP_ATOMIC flag.
 *
 * Revision 1.5  2004/05/11 19:41:27  bimran
 * Added code for lock debug
 *
 * Revision 1.4  2004/05/02 19:45:59  bimran
 * Added Copyright notice.
 *
 * Revision 1.3  2004/04/23 21:50:14  bimran
 * Added header files for user mode programs.
 *
 * Revision 1.2  2004/04/22 02:03:33  bimran
 * changed one cavium_print to debug print.
 *
 * Revision 1.1  2004/04/15 22:40:50  bimran
 * Checkin of the code from India with some cleanups.
 *
 */

