/* linux_main.c */
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
 * 3. All manuals,brochures,user guides mentioning features or use of this
 *    software must display the following acknowledgement:
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
 *      Linux Driver main file -- this file contains the driver code.
 *
 *----------------------------------------------------------------------------*/

#include <cavium_sysdep.h>
#include <cavium_common.h>
#include <cavium_ioctl.h>
#include <cavium_endian.h>
#include <linux/poll.h>
#if LINUX_VERSION_CODE < KERNEL_VERSION (2,6,0)
#include <linux/wrapper.h>
#else
#include <linux/page-flags.h>
#endif
#include <linux/kdev_t.h>
#include <linux/pci.h>
#include "cavium_list.h"
#include "cavium.h"
#include "init_cfg.h"
#include "linux_main.h"
#include "poll_thread.h"
#include "cavium_proc.h"
#include "request_manager.h"
#include "context_memory.h"
#include "microcode.h"
#include "bl_nbl_list.h"
#include "buffer_pool.h"
#include "hw_lib.h"
#include "key_memory.h"
#include "cavium_random.h"
#include "command_que.h"
//#if defined(NPLUS) 
#include "soft_req_queue.h" 
//#endif
#include "completion_dma_free_list.h"
#include "direct_free_list.h"
#include "pending_free_list.h"
#include "pending_list.h"
#include<linux/stat.h>

#ifdef CNS3000
#include <mach/board.h>
#include <mach/pm.h>
#endif

MODULE_AUTHOR("Cavium Networks <www.cavium.com>");
MODULE_DESCRIPTION("Nitrox-Lite driver");
MODULE_LICENSE("CAVIUM");

char *config_part;
short ssl=-1, ipsec=-1, nplus=0;
module_param(ssl,short,S_IRUGO);
MODULE_PARM_DESC(ssl, "runs on specified cores, if cores=0, uses all cores");
module_param(ipsec,short,S_IRUGO);
MODULE_PARM_DESC(ipsec, "runs on specified cores, if cores=0, uses all cores");
module_param(config_part,charp,S_IRUGO);
MODULE_PARM_DESC(config_part, "Driver will detect except these Nitrox parts: CN1120, CN1220, CN1320, CN1001, CN1005, CN505, CN501");
#ifdef CNS3000
u32 crypto_clk=2;
//defualt=2
// 0: 200MHz
// 1: 300MHz
// 2: 400MHz
module_param(crypto_clk,uint,0444);
#endif

/*
 * Device driver entry points
 */
int    initmodule (void);
static int __init cavium_driver_init(void);
static void __exit cavium_driver_exit(void);
void   cleanupmodule (void);
void   cleanup (struct pci_dev *dev);
#ifdef CNS3000
int cavium_init_one(cns3000_dev_t *dev);
#else
int cavium_init_one(struct pci_dev *dev);
#endif
#if LINUX_VERSION_CODE >= KERNEL_VERSION (2,6,11)
long    n1_unlocked_ioctl (struct file *, unsigned int, ptrlong);
#endif
int    n1_ioctl (struct inode *, struct file *, unsigned int, ptrlong);

long    n1_ioctl32 (struct file *, unsigned int, ptrlong);

#if LINUX_VERSION_CODE < KERNEL_VERSION (2,6,11)
int    n1_simulated_unlocked_ioctl (struct inode *, struct file *, unsigned int, ptrlong);
#endif
int    n1_open (struct inode *, struct file *);
int    n1_release (struct inode *, struct file *);
#ifndef CAVIUM_NO_MMAP
int   n1_mmap(struct file *, struct vm_area_struct *);
#endif
unsigned int n1_poll(struct file *, poll_table *);

struct N1_Dev *device_list = NULL;

extern cavium_device cavium_dev[];
extern int dev_count;
extern Uint8 cavium_version[3];
static int driver_removal = 0;
int ssl_cores, ipsec_cores;

#ifdef CONFIG_PCI_MSI
int msi_enabled = 0;
#endif


#ifdef EXPORT_SYMTAB
EXPORT_SYMBOL(n1_ioctl);

EXPORT_SYMBOL(n1_ioctl32);

#if LINUX_VERSION_CODE >= KERNEL_VERSION (2,6,11)
EXPORT_SYMBOL(n1_unlocked_ioctl);
#endif
#if LINUX_VERSION_CODE < KERNEL_VERSION (2,6,11)
EXPORT_SYMBOL(n1_simulated_unlocked_ioctl);
#endif
EXPORT_SYMBOL(n1_open);
EXPORT_SYMBOL(n1_release);
#ifndef CAVIUM_NO_MMAP
EXPORT_SYMBOL(n1_mmap);
#endif
EXPORT_SYMBOL(n1_poll);
EXPORT_SYMBOL(init_blocking_non_blocking_lists);
EXPORT_SYMBOL(push_user_info);
EXPORT_SYMBOL(del_user_info_from_list);
EXPORT_SYMBOL(check_nb_command_pid);
EXPORT_SYMBOL(check_nb_command_id);
EXPORT_SYMBOL(check_all_nb_command);
EXPORT_SYMBOL(cleanup_nb_command_id);
EXPORT_SYMBOL(cleanup_nb_command_pid);
EXPORT_SYMBOL(init_buffer_pool);
EXPORT_SYMBOL(free_buffer_pool);
EXPORT_SYMBOL(get_buffer_from_pool);
EXPORT_SYMBOL(put_buffer_in_pool);
EXPORT_SYMBOL(pkp_setup_direct_operation);
EXPORT_SYMBOL(pkp_setup_sg_operation);
EXPORT_SYMBOL(check_endian_swap);
EXPORT_SYMBOL(pkp_unmap_user_buffers);
EXPORT_SYMBOL(pkp_flush_input_buffers);
EXPORT_SYMBOL(pkp_invalidate_output_buffers);
EXPORT_SYMBOL(check_completion);
EXPORT_SYMBOL(init_rnd_buffer);
EXPORT_SYMBOL(cleanup_rnd_buffer);
EXPORT_SYMBOL(fill_rnd_buffer);
EXPORT_SYMBOL(get_rnd);
EXPORT_SYMBOL(reset_command_queue);
EXPORT_SYMBOL(inc_front_command_queue);
EXPORT_SYMBOL(cleanup_command_queue);
EXPORT_SYMBOL(init_command_queue);
EXPORT_SYMBOL(init_completion_dma_free_list);
EXPORT_SYMBOL(get_completion_dma);
EXPORT_SYMBOL(put_completion_dma);
EXPORT_SYMBOL(get_completion_dma_bus_addr);
EXPORT_SYMBOL(cleanup_completion_dma_free_list);
#ifdef CAVIUM_RESOURCE_CHECK
EXPORT_SYMBOL(insert_ctx_entry);
#endif
EXPORT_SYMBOL(init_context); 
EXPORT_SYMBOL(cleanup_context);
EXPORT_SYMBOL(alloc_context);
EXPORT_SYMBOL(dealloc_context);
EXPORT_SYMBOL(alloc_context_id);
EXPORT_SYMBOL(dealloc_context_id);
EXPORT_SYMBOL(init_direct_free_list);
EXPORT_SYMBOL(get_direct_entry);
EXPORT_SYMBOL(put_direct_entry);
EXPORT_SYMBOL(cleanup_direct_free_list);
EXPORT_SYMBOL(enable_request_unit);
EXPORT_SYMBOL(disable_request_unit);
EXPORT_SYMBOL(enable_exec_units);
EXPORT_SYMBOL(disable_all_exec_units);
EXPORT_SYMBOL(enable_data_swap);
EXPORT_SYMBOL(set_PCIX_split_transactions);
EXPORT_SYMBOL(set_PCI_cache_line);
EXPORT_SYMBOL(get_exec_units);
EXPORT_SYMBOL(set_soft_reset);
EXPORT_SYMBOL(do_soft_reset);
EXPORT_SYMBOL(count_set_bits);
EXPORT_SYMBOL(cavium_pow);
EXPORT_SYMBOL(get_exec_units_part);
EXPORT_SYMBOL(check_core_mask);
EXPORT_SYMBOL(enable_local_ddr);
EXPORT_SYMBOL(check_dram);
EXPORT_SYMBOL(enable_rnd_entropy);
EXPORT_SYMBOL(get_first_available_core);
EXPORT_SYMBOL(get_unit_id);
EXPORT_SYMBOL(enable_exec_units_from_mask);
EXPORT_SYMBOL(disable_exec_units_from_mask);
EXPORT_SYMBOL(setup_request_queues);
EXPORT_SYMBOL(init_twsi);
EXPORT_SYMBOL(get_enabled_units);
EXPORT_SYMBOL(cycle_exec_units_from_mask);
#ifdef CAVIUM_RESOURCE_CHECK
EXPORT_SYMBOL(insert_key_entry);
#endif
EXPORT_SYMBOL(init_key_memory);
EXPORT_SYMBOL(cleanup_key_memory);
EXPORT_SYMBOL(store_key_mem);
EXPORT_SYMBOL(alloc_key_memory);
EXPORT_SYMBOL(dealloc_key_memory);
EXPORT_SYMBOL(flush_key_memory);
EXPORT_SYMBOL(init_pending_free_list);
EXPORT_SYMBOL(get_pending_entry);
EXPORT_SYMBOL(put_pending_entry);
EXPORT_SYMBOL(cleanup_pending_free_list);
EXPORT_SYMBOL(push_pending);
EXPORT_SYMBOL(push_pending_ordered);
EXPORT_SYMBOL(push_pending_unordered);
EXPORT_SYMBOL(poll_pending_ordered);
EXPORT_SYMBOL(poll_pending_unordered);
EXPORT_SYMBOL(finalize_request);
EXPORT_SYMBOL(get_queue_head_ordered);
EXPORT_SYMBOL(get_queue_head_unordered);
EXPORT_SYMBOL(check_for_completion_callback);
EXPORT_SYMBOL(send_command);
EXPORT_SYMBOL(do_operation);
EXPORT_SYMBOL(do_speed);
EXPORT_SYMBOL(do_request);
EXPORT_SYMBOL(user_scatter);
#endif


/*
 * Global variables
 */

static struct file_operations n1_fops =
{
open:      n1_open,
     release:   n1_release,
     read:      NULL,
     write:     NULL,
#if LINUX_VERSION_CODE >= KERNEL_VERSION (2,6,11)
     unlocked_ioctl: n1_unlocked_ioctl,
#endif
#if LINUX_VERSION_CODE >= KERNEL_VERSION (2,6,11)
     ioctl:     n1_ioctl,
#else
     ioctl:     n1_simulated_unlocked_ioctl,
#endif
#if LINUX_VERSION_CODE <= KERNEL_VERSION (2,4,20)
     /* no compact_ioct */
#else
     compat_ioctl:  n1_ioctl32,
#endif
#ifndef CAVIUM_NO_MMAP
     mmap:      n1_mmap,
#else
     mmap:      NULL,
#endif
     poll:      n1_poll,
};


struct __NITROX_DEVICES {
  Uint16   id;
  char     name[80];
};



#define MAX_NITROX_DEVLIST   3
#define __CVM_DRIVER_TYPE__  "Nitrox"
#define CVM_DRV_NAME        "pkp" 
struct __NITROX_DEVICES  nitrox_devices[MAX_NITROX_DEVLIST] =
{ { N1_DEVICE, "Nitrox-1"},
  { N1_LITE_DEVICE, "Nitrox-Lite"}, 
  { NPX_DEVICE, "Nitrox-PX"}};



/*
 * General
 */
int setup_interrupt(cavium_device *pdev);
void free_interrupt(cavium_device *pdev);
#ifdef INTERRUPT_RETURN
extern int
#else
extern void
#endif
cavium_interrupt_handler(void *);

Uint32  csrbase_b_offset=0x0000;
#ifndef CNS3000
static int __devinit cavium_probe(struct pci_dev *dev, const struct pci_device_id *ent)
{
  int ret_val=0, i;
  // struct pci_dev *dev = NULL;
  // cavium_general_config cavium_g_cfg;
  int device_id;   

#if defined(CAVIUM_DEBUG_LEVEL)
  cavium_debug_level = CAVIUM_DEBUG_LEVEL;
#else
  cavium_debug_level = 0;
#endif
  if (!dev) {
    ret_val = -1;
    goto error;
  } 
  device_id= dev->device;      
  /* Try to find a device listed in nitrox_devices */
  for(i = 0; i < MAX_NITROX_DEVLIST; i++) {

    if(device_id == nitrox_devices[i].id) {
#if CAVIUM_DEBUG_LEVEL>0
      printk("%s found at Bus %d Slot %d\n", nitrox_devices[i].name,
          dev->bus->number, PCI_SLOT(dev->devfn));
#endif

      break;
    }

  }
  if(i == MAX_NITROX_DEVLIST) {
    printk("CAVIUM Card found: But this driver is for %s\n",
        __CVM_DRIVER_TYPE__);
    ret_val = -1;
    goto error;
  }
  if (!cavium_init_one(dev)) {
    dev_count++;
    cavium_print("Finished Initializing this device\n");
    if (dev_count > MAX_DEV) {
      cavium_error("MAX %d %s Devices supported\n", dev_count,
          __CVM_DRIVER_TYPE__);
      cavium_error("Ignoring other devices\n");
      ret_val = -1;
      goto error;
    }
  } else {
    cavium_error(" Cavium Init failed for device \n");
    ret_val = -ENOMEM;
    goto error;
  }
  if (dev_count == 0) {
    cavium_error("%s not found \n", __CVM_DRIVER_TYPE__);
    ret_val = -ENODEV;
    goto error;
  } else {
    cavium_print("Total Number of %s Devices: %d\n",
        __CVM_DRIVER_TYPE__, dev_count);
  }
error:
  return ret_val;
}
struct pci_device_id cavium_pci_table[] __devinitdata =
{
  {  VENDOR_ID,
    PCI_ANY_ID,    
    PCI_ANY_ID,            
    PCI_ANY_ID,            
    0, 0, 0    },
  {0},
};

struct pci_driver cavium_pci_driver = {
  .name     = "pkp",                     
  .probe    = cavium_probe,              
  .remove   = __devexit_p(cleanup),
  .id_table = cavium_pci_table,         
};
#endif

#ifdef CNS3000
int
cavium_init_one(cns3000_dev_t *dev)
{
   cavium_config cavium_cfg;
	#define CNS3000_PX_BAR     CNS3XXX_CRYPTO_BASE   
   unsigned long bar_px_hw=CNS3000_PX_BAR;
   void  *bar_px = NULL;
	#define CNS3000_PX_CONFIG_ADDR     0
	unsigned long config_addr_hw = CNS3000_PX_CONFIG_ADDR;

	dev->config_addr = config_addr_hw;

   cavium_cfg.px_flag=CN16XX;

	bar_px = ioremap(bar_px_hw, 0x400);
	if(bar_px == NULL) {
		printk(KERN_CRIT "ioremap for bar memory failed\n");
		return -1;
	}
   /* do soft reset of chip */
   write_PKP_register(ptr, bar_px, 0x20);
   udelay (100);
   /* enable data swap in command status register */
   write_PKP_register(ptr, bar_px, 0x5);
	csrbase_b_offset = 0x0100;
	cavium_cfg.bar_px_hw = CNS3000_PX_BAR;
	cavium_cfg.bar_px = bar_px;
   /* nr. of 32 byte contiguous structures */
   cavium_cfg.command_queue_max = CAVIUM_COMMAND_QUEUE_SIZE; 
    	   
   /* context memory to be pre-allocated,
    * if DDR memory is not found.
    * Otherwise actual size is used. */ 
   cavium_cfg.context_max = CAVIUM_CONTEXT_MAX; 
   cavium_cfg.device_id = NPX_DEVICE;
   cavium_dev[dev_count].dev = dev;


   /* allocate command queue, initialize chip */
   if (cavium_init(&cavium_cfg)) {
	   cavium_error("cavium_init failed\n");
      return -ENOMEM;
	}
	return 0;
}
#else
  int
cavium_init_one(struct pci_dev *dev)
{
  cavium_config cavium_cfg;
  unsigned long bar_px_hw=0;
  void  *bar_px = NULL;
  Uint32 bar_0=0, bar_2=0;
  Uint32 NPX_BAR=0;   

  int ret_val=0;

  MPRINTFLOW();

  if(dev->device==NPX_DEVICE)
  {
    if(pci_find_capability(dev, PCI_CAP_ID_EXP))
    {       
      NPX_BAR= 0 ;
      cavium_cfg.px_flag=CN16XX;
    }
    else
    {
      cavium_cfg.px_flag=CN15XX;
      NPX_BAR = 4;
    }   

  }else
    cavium_cfg.px_flag=0;      

  /* Enable PCI Device */
  if(pci_enable_device(dev))
  {
    cavium_error("pci_enable_device failed\n");
    return -1;
  }

  /* We should be able to access 64-bit mem space. */
  ret_val = pci_set_dma_mask(dev, 0xffffffffffffffffULL);
#if LINUX_VERSION_CODE  > KERNEL_VERSION (2,6,0)
  ret_val = pci_set_consistent_dma_mask(dev, 0xffffffffffffffffULL);
#endif

  if(dev->device==NPX_DEVICE)
  {

    csrbase_b_offset = 0x0100;

#if CAVIUM_DEBUG_LEVEL>0
    printk(KERN_CRIT "Using memory-mapped bar for device 0x%X:0x%X\n",
        VENDOR_ID, dev->device); 
#endif
    bar_px_hw = pci_resource_start(dev, NPX_BAR);
#if CAVIUM_DEBUG_LEVEL>0
    printk(KERN_CRIT "bar %d: %lx\n", NPX_BAR, bar_px_hw);
#endif

    /* get hold of memory-mapped region */
    bar_px = request_mem_region(bar_px_hw, 0x400, (const Uint8 *)CVM_DRV_NAME); 
    if(bar_px == NULL) {
      printk(KERN_CRIT " requested mem region for bar %d cannot be allocated\n", NPX_BAR);
      return -1;
    }

    bar_px = ioremap(bar_px_hw, 0x400);
    if(bar_px == NULL) {
      printk(KERN_CRIT "ioremap for bar %d memory failed\n", NPX_BAR);
      release_mem_region(bar_px_hw, 0x400);
      return -1;
    }

  }
  else {
    /* Read BAR 0 and BAR 2 */
    bar_0 = pci_resource_start(dev, 0);
    bar_2 = pci_resource_start(dev, 2);

    cavium_print( "bar 0: %x\n",bar_0);
    cavium_print( "bar 2: %x\n",bar_2);


#if LINUX_VERSION_CODE  > KERNEL_VERSION (2,6,0)
    if (!request_region(bar_0, 0xff,(const Uint8 *)CVM_DRV_NAME)) {
      cavium_error("region checking for bar 0 io ports failed\n");
      return -1;
    }   

    if (!request_region(bar_2, 0xff,(const Uint8 *)CVM_DRV_NAME)) {
      cavium_error("region checking for bar 2 io ports failed\n");
      release_region(bar_0, 0xff);
      return -1;
    }
#else
    ret_val = check_region(bar_0, 0xff);
    if(ret_val < 0) {
      cavium_error("region checking for bar 0 io ports failed\n");
      return ret_val;
    }
    request_region(bar_0, 0xff,(const Uint8 *)CVM_DRV_NAME);

    ret_val = check_region(bar_2,0xff);
    if(ret_val < 0) {
      cavium_error("region checking for bar 2 io ports failed\n");
      release_region(bar_0, 0xff);
      return ret_val;
    }
    request_region(bar_2, 0xff,(const Uint8 *)CVM_DRV_NAME);
#endif
    cavium_memset(&cavium_dev[dev_count], 0, sizeof(cavium_device));

  }

  cavium_cfg.dev= dev;
  cavium_cfg.bus_number = dev->bus->number; 
  cavium_cfg.dev_number = PCI_SLOT(dev->devfn);
  cavium_cfg.func_number = PCI_FUNC(dev->devfn);

  if(dev->device==NPX_DEVICE){   
    cavium_cfg.bar_px_hw = bar_px_hw;
    cavium_cfg.bar_px = bar_px;
  }   
  else{
    cavium_cfg.bar_0 = bar_0;
    cavium_cfg.bar_2 = bar_2;
  }

  /* nr. of 32 byte contiguous structures */
  cavium_cfg.command_queue_max = CAVIUM_COMMAND_QUEUE_SIZE; 

  /* context memory to be pre-allocated,
   * if DDR memory is not found.
   * Otherwise actual size is used. */ 
  cavium_cfg.context_max = CAVIUM_CONTEXT_MAX; 
  cavium_cfg.device_id =dev->device;
  cavium_dev[dev_count].dev = dev;


  /* allocate command queue, initialize chip */
  if (cavium_init(&cavium_cfg)) {
    cavium_error("cavium_init failed.\n");
    if(dev->device==NPX_DEVICE){
      if(bar_px)
        iounmap(bar_px);   
      release_mem_region(bar_px_hw, 0x400);
    }
    else{
      release_region(bar_2, 0xff);
      release_region(bar_0, 0xff);
    }
    return -ENOMEM;
  }

  return 0;
}
#endif

void cavium_cleanup_one(cavium_device *pkp_dev)
{
  cavium_cleanup(pkp_dev);

  if(pkp_dev->device_id==NPX_DEVICE){

    if(pkp_dev->bar_px)
      iounmap(pkp_dev->bar_px);
    if(pkp_dev->bar_px_hw)
      release_mem_region(pkp_dev->bar_px_hw, 0x400);
  }
  else{
    release_region(pkp_dev->bar_1, 0xff);
    release_region(pkp_dev->bar_0, 0xff);
  }
  return;
}
void cleanup(struct pci_dev *dev)
{
  int i;
  int device_id;
  device_id = dev->device;
  for(i = 0; i < dev_count; i++) {
    if((cavium_dev[i].bus_number == dev->bus->number) &&
        (cavium_dev[i].device_id == device_id) &&
        (cavium_dev[i].dev_number == PCI_SLOT(dev->devfn)) &&
        (cavium_dev[i].func_number == PCI_FUNC(dev->devfn)))
    {
      break;
    }

  }
  if(i<dev_count)
    cavium_cleanup_one(&cavium_dev[i]);
  pci_disable_device(dev);
}

/*
 *  Standard module initialization function.
 *  This function scans the PCI bus looking for the right board 
 *   and allocates resources.
 */

int initmodule ()
{
  int ret_val=0, i;
  cavium_general_config cavium_g_cfg;

#ifdef CNS3000
  {
     cns3000_dev_t *dev;
#if 1
				cavium_rdtsc_init();
#endif

//		printk("the original crypto_clk_sel=%d(0:200, 1:300, 2:400MHz)\n",((PM_CLK_CTRL_REG & 0x3000)>>12));
		PM_CLK_CTRL_REG = ((PM_CLK_CTRL_REG & (~0x3000)) | ((crypto_clk&0x3)<<12));
		printk("the current crypto_clk_sel=%d(0:200, 1:300, 2:400MHz)\n",((PM_CLK_CTRL_REG & 0x3000)>>12));
		
		cns3xxx_pwr_power_up(1<<PM_PLL_HM_PD_CTRL_REG_OFFSET_PLL_USB);
		cns3xxx_pwr_clk_en(1<<PM_CLK_GATE_REG_OFFSET_CRYPTO);
		cns3xxx_pwr_soft_rst(1<<PM_SOFT_RST_REG_OFFST_CRYPTO);

     dev = cavium_malloc(sizeof(cns3000_dev_t), GFP_ATOMIC);
     if (!dev) {
        cavium_error("unable to allocate memory for cns3000 dev\n");
        return -ENOMEM;
     }
     if (!cavium_init_one(dev)) {
        dev_count++;
        cavium_print("Finished Initializing this device\n");
     } else {
        cavium_error(" Cavium Init failed for device \n");
        goto init_error;
     }
  }
#endif

  cavium_g_cfg.pending_max = CAVIUM_PENDING_MAX; 
  /* number of pending response structures to be pre-allocated. */
  cavium_g_cfg.direct_max = CAVIUM_DIRECT_MAX;   
  /* number of DIRECT operation structures to be pre-allocated. */
  cavium_g_cfg.sg_max = CAVIUM_SG_MAX;      
  /* number of SG operation structures to be pre-allocated. */
  cavium_g_cfg.sg_dma_list_max = CAVIUM_SG_DMA_MAX; 
  /* number of scatter/gather lists to be pre-allocated. */

  cavium_g_cfg.huge_buffer_max = HUGE_BUFFER_CHUNKS;
  cavium_g_cfg.large_buffer_max = LARGE_BUFFER_CHUNKS;
  cavium_g_cfg.medium_buffer_max = MEDIUM_BUFFER_CHUNKS;
  cavium_g_cfg.small_buffer_max = SMALL_BUFFER_CHUNKS;
  cavium_g_cfg.tiny_buffer_max = TINY_BUFFER_CHUNKS;
  cavium_g_cfg.ex_tiny_buffer_max = EX_TINY_BUFFER_CHUNKS;

  if(cavium_general_init(&cavium_g_cfg)) {
    cavium_error("cavium_general_init failed.\n");
    ret_val = -ENOMEM;
    goto init_error;
  }

  /* create poll thread */
  if(init_poll_thread()) {
    cavium_print("init_poll_thread failed.\n");
    ret_val = -ENOMEM;
    goto init_error;
  }

  /* now setup interrupt handler */
  for (i = 0; i < dev_count; i++) {
    if(setup_interrupt(&cavium_dev[i])) {
      int j;
      ret_val = -ENXIO;
      for (j = 0; j <i; j++) {
        free_interrupt(&cavium_dev[j]);
      }
      cavium_print("Error setting up interrupt.\n");
      goto init_error;
    }
  }

  /* initialize kernel mode stuff */
  init_kernel_mode();

  /* register driver */
  ret_val = register_chrdev(DEVICE_MAJOR,DEVICE_NAME,&n1_fops);
  if(ret_val <0)
  {
    for (i = 0; i <dev_count; i++) {
      free_interrupt(&cavium_dev[i]);
    }
    printk("%s failed with %d\n", "Sorry, registering n1 device failed", ret_val);
    goto init_error;
  }

#ifdef NPLUS
#if CAVIUM_DEBUG_LEVEL>0
  printk("%s The major device number is %d\n", "Registration is a success", DEVICE_MAJOR);
  printk("To talk to the device driver, please use device appropriate device node.\n");
  printk("Device's minor number corresponds to the microcode to be used.\n");
  printk("Please read the README file for further instructions\n\n");
#endif

#else 
#if CAVIUM_DEBUG_LEVEL>0
  printk("%s The major device number is %d\n", "Registration is a success", DEVICE_MAJOR);
  printk("if you want to talk to the device driver,\n");
  printk("I suggest you use:\n");
  printk(" mknod %s c %d 0\n", DEVICE_NAME,DEVICE_MAJOR);
#endif
#endif

  if (cavium_init_proc()) {
    printk(" Support for proc filesystem failed\n");
    printk(" Still continuing ....\n");
  }

#if CAVIUM_DEBUG_LEVEL>0
  printk("Loaded Cavium Driver --- %01d.%02d-%c\n",cavium_version[0],cavium_version[1],cavium_version[2]);
#endif

  return 0;

init_error:
  free_poll_thread();
  cavium_general_cleanup();
  return ret_val;
}/*initmodule*/

/*
 *  Standard module release function.
 */
void cleanupmodule (void)
{
  int i;
#if LINUX_VERSION_CODE <= KERNEL_VERSION (2,6,22)
  int ret;
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION (2,6,0)
  if(MOD_IN_USE) {    
    cavium_error("Nitrox device driver is in use\n"); 
    return;
  }
#endif
  driver_removal = 1;
  cavium_print("Unregistering char device\n");
#if LINUX_VERSION_CODE > KERNEL_VERSION (2,6,22)
  unregister_chrdev(DEVICE_MAJOR,DEVICE_NAME);
#else
  ret = unregister_chrdev(DEVICE_MAJOR,DEVICE_NAME);

  if(ret < 0) {
    cavium_error("Error in unregistering Nitrox device\n");
  } else {
    cavium_print("Nitrox Device successfully unregistered\n");
  }
#endif
  cavium_print("Freeing kernel mode\n");
  free_kernel_mode();

  cavium_print("Freeing interrupt\n");
  for (i=0; i < dev_count; i++)
    free_interrupt(&cavium_dev[i]);

  cavium_print("Freeing poll thread\n");
  free_poll_thread();

  cavium_print("dev_count %d \n", dev_count);

}

/*
 *  Standard open() entry point.
 *  It simply increments the module usage count.
 */
int n1_open (struct inode *inode, struct file *file)
{
  Uint32 dev_id =0;
  struct MICROCODE *microcode = NULL;

#ifdef CAVIUM_RESOURCE_CHECK
  struct CAV_RESOURCES *resource;
#endif
  MPRINTFLOW();
  if(driver_removal) {
    cavium_print("open: returning error :%d\n", ENOMEM);
    return ENOMEM;
  }
#ifdef CAVIUM_MULTICARD_API
  dev_id = MINOR(inode->i_rdev);
#endif
  microcode = &(cavium_dev[dev_id].microcode[BOOT_IDX]);
  cavium_dbgprint("Microcode code_type = %d idx: %d,dev_id = %d\n",
      microcode->code_type, BOOT_IDX, dev_id); 

  CAVIUM_MOD_INC_USE_COUNT;

  cavium_dbgprint("n1_open(): Device minor number %d.%d\n", 
      inode->i_rdev >>8, inode->i_rdev & 0xff);

#ifdef CAVIUM_RESOURCE_CHECK
  resource = cavium_malloc(sizeof(struct CAV_RESOURCES), NULL);
  if (resource == NULL) {
    cavium_error("Unable to allocate memory for Cavium resource\n");
    return -ERESTARTSYS;
  }

  cavium_spin_lock_init(&resource->resource_check_lock);
  CAVIUM_INIT_LIST_HEAD(&resource->ctx_head);
  CAVIUM_INIT_LIST_HEAD(&resource->key_head);
  file->private_data = resource;
#endif

  microcode->use_count++;

  cavium_dbgprint("Microcode[%d] use_count: %d\n",
      BOOT_IDX, microcode->use_count);
  return (0);
}


/*
 *  Standard release() entry point.
 *  This function is called by the close() system call.
 */
int n1_release (struct inode *inode, struct file *file)
{

  int ret=driver_removal;
  struct MICROCODE *microcode = NULL;
  MPRINTFLOW();
  if(ret)
  {
    cavium_print("n1: close returning error %d\n", ENXIO);
    return ENXIO;
  }
  else
  {
#ifdef CAVIUM_RESOURCE_CHECK
    Uint32 dev_id=0;
    cavium_device *pdev;
    struct CAV_RESOURCES *resource = NULL;
    struct cavium_list_head *tmp, *tmp1;
    dev_id = MINOR(inode->i_rdev);
    if (dev_id > (dev_count - 1)) {
      cavium_print("\n no No N1 device associated with this minor device no. %d\n", dev_id);
      return -ENODEV;
    }
    pdev = &cavium_dev[dev_id];
    cleanup_nb_command_pid(cavium_get_pid());
    resource = file->private_data;
    if (resource == NULL) {
      cavium_error("Resource not found while deallocating\n");
      return -1;
    }
    cavium_spin_lock(&resource->resource_check_lock);

    cavium_list_for_each_safe(tmp, tmp1, &resource->ctx_head) {
      struct CTX_ENTRY *entry = list_entry(tmp, struct CTX_ENTRY, list);
      dealloc_context(entry->pkp_dev, entry->ctx_type, entry->ctx);
      cavium_list_del(&entry->list);
      cavium_free((Uint8 *)entry);
    }

    cavium_list_for_each_safe(tmp, tmp1, &resource->key_head) {
      struct KEY_ENTRY *entry = list_entry(tmp, struct KEY_ENTRY, list);
      dealloc_key_memory(entry->pkp_dev, entry->key_handle);
      cavium_list_del(&entry->list);
      cavium_free((Uint8 *)entry);
    }
    cavium_spin_unlock(&resource->resource_check_lock);
    cavium_free(resource);
#endif
    CAVIUM_MOD_DEC_USE_COUNT;
    cavium_dbgprint("n1: close pid %d \n",cavium_get_pid());
    {
      Uint32 dev_id=0;    
#ifdef CAVIUM_MULTICARD_API
      dev_id = MINOR(inode->i_rdev);
#endif
      microcode = &(cavium_dev[dev_id].microcode[BOOT_IDX]);
      microcode->use_count--;
      cavium_dbgprint("Microcode[%d] use_count: %d\n",BOOT_IDX, microcode->use_count);
    }
    return(0);
  }
}


int acquire_core(cavium_device *pdev, int ucode_idx, int core_id)
{
  Cmd strcmd;
  int ret = 0, insize = 8, outsize = 16;
  Uint8 *out_buffer=NULL;
  Uint8 *in_buffer=NULL;
  Request request;
  Uint64 *completion_address;
  Uint64 disabled_core;
  Uint32 disabled_mask = 0;
  Uint64 dataptr = 0;
  Uint64 recvptr = 0;

  cavium_dbgprint("Attempt to acquire core %d\n", core_id);
  MPRINTFLOW();


  in_buffer = (Uint8 *)get_buffer_from_pool(pdev, (insize + 8));
  if(in_buffer == NULL)
  {
    cavium_print("acquire_core: unable to allocate in_buffer.\n");
    ret = -1;
    goto ca_err;
  }

  out_buffer = (Uint8 *)get_buffer_from_pool(pdev, (outsize + 8));
  if(out_buffer == NULL)
  {
    cavium_print("acquire_core: unable to allocate out_buffer.\n");
    ret = -2;
    goto ca_err;
  }

  dataptr = (Uint64)cavium_map_kernel_buffer(pdev,
      in_buffer, insize+8, CAVIUM_PCI_DMA_BIDIRECTIONAL);
  recvptr = (Uint64)cavium_map_kernel_buffer(pdev,
      out_buffer, outsize+8, CAVIUM_PCI_DMA_BIDIRECTIONAL);

  do
  {
    strcmd.opcode= (0x7f<<8) | MAJOR_OP_ACQUIRE_CORE;;
    strcmd.size  = 0;
    strcmd.param = 0;
    strcmd.dlen  = insize>>3;

    strcmd.opcode  = htobe16(strcmd.opcode);
    strcmd.size    = htobe16(strcmd.size);
    strcmd.param   = htobe16(strcmd.param);
    strcmd.dlen    = htobe16(strcmd.dlen);

    cavium_memcpy((unsigned char *)&request, (unsigned char *)&strcmd, 8);

    request.cptr = 0;

    request.dptr = htobe64(dataptr);
    request.rptr = htobe64(recvptr);
    request.cptr = htobe64(request.cptr);

    completion_address = (Uint64 *)(out_buffer + outsize);
    *completion_address = COMPLETION_CODE_INIT;

    if(send_command(pdev, &request, 0, ucode_idx, completion_address) < 0) {
      cavium_print("Error sending core acquire request.\n");
      goto ca_err;
    }

    ret = check_completion(pdev, completion_address, 100, ucode_idx, -1);
    if(ret) {
      cavium_print("Error: %x on acquire core request.\n", ret);
      goto ca_err;
    }
    disabled_core = betoh64(*(Uint64 *)(out_buffer+8));

    cavium_dbgprint("Acquired core %d\n", (Uint32)(disabled_core));

    if(disabled_core == core_id)
    {
      break;
    }
    else
    {
      disabled_mask |= (1<<disabled_core);
      cavium_dbgprint("Acquired mask 0x%x\n", disabled_mask);
    }
  } while(1);

ca_err:

  if(disabled_mask)
  {
    cycle_exec_units_from_mask(pdev, disabled_mask);
    cavium_dbgprint("Cycled cores 0x%x\n", disabled_mask);
  }


  if(in_buffer)
  {
    /*unmap the dma buffers*/
    cavium_unmap_kernel_buffer(pdev, dataptr, insize+8,
        CAVIUM_PCI_DMA_BIDIRECTIONAL);
    put_buffer_in_pool(pdev,(Uint8 *)in_buffer);
  }
  if(out_buffer)
  {
    /*unmap the dma buffers*/
    cavium_unmap_kernel_buffer(pdev, recvptr, outsize+8,
        CAVIUM_PCI_DMA_BIDIRECTIONAL);
    put_buffer_in_pool(pdev,(Uint8 *)out_buffer);
  }
  return(ret);

}

  int 
nplus_init(cavium_device *pdev, int ucode_idx, unsigned long arg)
{
  int i, ret=0;
  int offset=40;
  Uint8 code_idx;
  Csp1InitBuffer *init_buffer;
  struct MICROCODE *microcode;

  init_buffer = (Csp1InitBuffer *)arg;

  MPRINTFLOW();
  cavium_dbgprint("got csp1_init code\n");
  cavium_dbgprint("size = %d\n", init_buffer->size);

  /* We only allow this IOCTL on "/dev/pkp_admin" */

  if(ucode_idx != BOOT_IDX )
  {
    cavium_print("Inappropriate IOCTL for device %d",ucode_idx);
    ret = ERR_INIT_FAILURE;
    goto cleanup_init;
  }

  /* Was this driver initialized earlier ? */
  if(pdev->initialized)
  {
    if(pdev->initialized == 1)
      cavium_error("Device already initialized\n");
    else
      cavium_error("Device incorrectly initialized\n");

    cavium_print("To reinitialize device, please unload & reload driver\n");
    ret = ERR_INIT_FAILURE;
    goto cleanup_init;
  }

  /* get all the information from init buffer */
  for(i=0;i<init_buffer->size;i++)
  {
    code_idx = init_buffer->ucode_idx[i];
    microcode = &(pdev->microcode[code_idx]);

    /* Make sure it isnt previously initialized */
    if(microcode->code != NULL)
    {
      cavium_print("Code Index %d found more than once\n", code_idx);
      ret = ERR_INIT_FAILURE;
      goto cleanup_init;
    }

    /* code */
    microcode->code_type = init_buffer->version_info[i][0] & 0x7f;

    /*** Paired cores is not supported in NitroxPX */
    if(pdev->device_id!=NPX_DEVICE)
      microcode->paired_cores
        = (init_buffer->version_info[i][0] & 0x80 ? 1:0);
    microcode->code_size = init_buffer->code_length[i];
    microcode->code = 
      (Uint8 *)get_buffer_from_pool(pdev,microcode->code_size);

    if (microcode->code == NULL)
    {
      cavium_print("Failed to allocate %d bytes microcode buffer type %d\n", 
          microcode->code_size, microcode->code_type);
      ret = ERR_MEMORY_ALLOC_FAILURE;
      goto cleanup_init;
    }            

    if(cavium_copy_in(microcode->code, CAST_FRM_X_PTR(init_buffer->code[i]),
          microcode->code_size))
    {
      cavium_error("Failed to copy in microcode->code\n");
      ret = ERR_INIT_FAILURE;
      goto cleanup_init;
    }

    /* data */
    microcode->data_size = init_buffer->data_length[i];
    if(microcode->data_size)
    {

      microcode->data =  (Uint8 *)cavium_malloc_nc_dma(pdev,
          microcode->data_size+offset,
          &microcode->data_dma_addr);

      if (microcode->data == NULL)
      {
        cavium_print("Failed to allocate %d bytes admin cst buffer type %d\n",
            microcode->data_size+offset,microcode->code_type);
        ret = ERR_MEMORY_ALLOC_FAILURE;
        goto cleanup_init;
      } 

      cavium_memset(microcode->data,0,microcode->data_size+offset);
      if(cavium_copy_in(microcode->data+offset, 
            CAST_FRM_X_PTR(init_buffer->data[i]),
            microcode->data_size))
      {
        cavium_error("Failed to copy in microcode->data\n");
        ret = ERR_INIT_FAILURE;
        goto cleanup_init;
      }
    }

    /* sram address */
    if(cavium_copy_in(microcode->sram_address,
          init_buffer->sram_address[i], SRAM_ADDRESS_LEN))
    {
      cavium_error("Failed to copy in sram_address\n");
      ret = ERR_INIT_FAILURE;
      goto cleanup_init;
    }
    if(pdev->device_id != NPX_DEVICE)
    {
      int j;
      /* Initialize the SRQ */
      microcode->srq.head = microcode->srq.tail = 0;
      microcode->srq.qsize = 0;
      cavium_spin_lock_init(&microcode->srq.lock);
      for(j=0;j<MAX_SRQ_SIZE;j++)
      {
        microcode->srq.state[j] = SR_FREE;
      }
    }
    cavium_dbgprint("Code type = %02x, code size = %x, data size = %x\n",
        microcode->code_type, microcode->code_size,microcode->data_size);
  }

  /* check for any missing piece */
  if(pdev->microcode[BOOT_IDX].code == NULL)
  {
    cavium_print("Boot code not sent to driver.\n");
    cavium_print("Please check version information\n");
    ret = ERR_INIT_FAILURE;
    goto cleanup_init;
  }

  /* We have gathered all the required information from init_buffer
   * Now it is time for some action. Lets do it! 
   */
  cavium_dbgprint("nplus_init: calling do_init\n");
  ret = do_init(pdev);   

cleanup_init:
  if(ret != 0)
  {

    for(i=0;i<init_buffer->size;i++)
    {
      code_idx = init_buffer->ucode_idx[i];
      microcode = &(pdev->microcode[code_idx]);
      if(microcode->code)
      {
        put_buffer_in_pool(pdev, microcode->code);
        microcode->code = NULL;
      }
      if(microcode->data)
      {
        cavium_free_nc_dma(pdev,
            microcode->data_size+offset,
            microcode->data,
            microcode->data_dma_addr);
        microcode->data_size = 0;
        microcode->data_dma_addr = 0;
        microcode->data = NULL;
      }
    }
    pdev->initialized = -1;
  }
  else
    pdev->initialized = 1;

  return ret;
}/*nplus_init*/

#if LINUX_VERSION_CODE >= KERNEL_VERSION (2,6,11)
/* High performance ioctl */
long    n1_unlocked_ioctl (struct file *file, unsigned int cmd, ptrlong arg)
{
  cavium_dbgprint("inside n1_unlocked_ioctl\n");
  return (long)n1_ioctl(file->f_dentry->d_inode,file,cmd,arg);   
}
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,11)
int n1_simulated_unlocked_ioctl(struct inode *inode, struct file*file,unsigned int cmd,unsigned long arg)
{
  int ret;
#if LINUX_VERSION_CODE >= KERNEL_VERSION (2,6,2)
  unlock_kernel();
#endif
  ret = n1_ioctl(inode,file,cmd,arg);
#if LINUX_VERSION_CODE >= KERNEL_VERSION (2,6,2)
  lock_kernel();
#endif
  return ret;
}
#endif

long n1_ioctl32 (struct file *file,
    unsigned int cmd,unsigned long arg)
{
  struct inode  *inode = file->f_dentry->d_inode;
  MPRINTFLOW();
  return (long) n1_ioctl(inode, file, cmd, arg);

}
/*
 *  Standard ioctl() entry point.
 */
int n1_ioctl (struct inode *inode, struct file *file, 
    unsigned int cmd,unsigned long arg)
{
  int ret=0;
  Uint32  data32 = 0;

  Uint32 rval=0;

  DebugRWReg *dw;
  cavium_device *pdev=NULL;
//  int ucode_idx;  
  Uint32 dev_id=0;
//struct MICROCODE *microcode = NULL;
  Csp1InitBuffer *init_buffer;
#ifdef CAVIUM_MULTICARD_API
  dev_id = MINOR(inode->i_rdev);
#endif
//  ucode_idx = BOOT_IDX;
//  microcode = &(cavium_dev[dev_id].microcode[ucode_idx]);
  if (dev_id > (dev_count - 1)) {
    cavium_print("No N1 device associated with this minor device no. %d\n", dev_id);
    return -ENODEV;
  }

  MPRINTFLOW();
  pdev = &cavium_dev[dev_id];
  cavium_dbgprint("Ioctl Cmd 0x%x called with arg 0x%lx\n",cmd, arg);
  cavium_dbgprint("\n Cmd: %x, device id = %d, init = %d\n",cmd,dev_id,pdev->enable);

  switch (cmd) {
    /* write PKP register */
    case IOCTL_N1_DEBUG_WRITE_CODE:
      dw =  (DebugRWReg *)arg;
      data32 = dw->data & 0xffffffff;

      if(pdev->device_id==NPX_DEVICE)
        read_PKP_register(pdev, (Uint8 *)dw->addr, &rval);

      cavium_dbgprint("pkp_drv: writing 0x%x at 0x%llx\n", 
          data32, CAST64(dw->addr));
      write_PKP_register(pdev, (Uint8 *)dw->addr, data32);

      if(pdev->device_id==NPX_DEVICE){   
        if(( (Uint8 *)dw->addr == pdev->CSRBASE_A + UNIT_ENABLE) && !(rval & 0x10000000) && (data32 & 0x10000000))
        {
          int i;
          for(i=0; i<MAX_N1_QUEUES; i++)
            reset_command_queue(pdev, i);
        }
      }

      ret = 0;
      break;

      /* Read PKP register */
    case IOCTL_N1_DEBUG_READ_CODE:
      dw = (DebugRWReg *)arg;
      cavium_dbgprint( "Kernel: reading 0x%llx \n", CAST64(dw->addr));
      read_PKP_register(pdev, (Uint8 *)dw->addr, &dw->data);
      cavium_dbgprint("Kernel read 0x%llx from 0x%llx\n",
          CAST64(dw->data), CAST64(dw->addr));
      ret = 0;
      break;

      /* Write PCI config space */
    case IOCTL_PCI_DEBUG_WRITE_CODE:
      dw =  (DebugRWReg *)arg;
      data32 = dw->data & 0xffffffff;
      cavium_dbgprint("pkp_drv: writing 0x%x at PCI config 0x%llx\n", 
          data32, CAST64(dw->addr));
#ifdef CNS3000
      write_PCI_register(pdev, dw->addr, data32);
#else
      pci_write_config_dword((struct pci_dev *)(pdev->dev), dw->addr,
          data32);
#endif					 
      ret = 0;
      break;

      /* Read PCI config space */
    case IOCTL_PCI_DEBUG_READ_CODE:
      dw = (DebugRWReg *)arg;
      dw->data = 0;
      cavium_dbgprint("pkp_drv: reading PCI config 0x%llx\n",
          CAST64(dw->addr));
#ifdef CNS3000
      write_PCI_register(pdev, dw->addr, data32);
#else
      pci_read_config_dword((struct pci_dev *)(pdev->dev), dw->addr,
          (u32 *)&data32);
#endif				
      dw->data = (unsigned long)data32;

      if(pdev->device_id==NPX_DEVICE){
        if(dw->addr == 0x10)
          dw->data = (unsigned long)pdev->bar_px + BASE_A_OFFSET;
        if(dw->addr == 0x18)
          dw->data = (unsigned long)pdev->bar_px + BASE_B_OFFSET;
      }

      ret = 0;
      break;

      /* run some basic test */
    case IOCTL_N1_API_TEST_CODE:
#if defined API_TEST
      ret = api_test(pdev);
#else
      ret = -1;
#endif /* API_TEST */
      break;

    case IOCTL_N1_DO_OPERATION:
      {
        n1_operation_buffer *buf;

        buf = (n1_operation_buffer *)arg;
        cavium_dbgprint("ioctl N1 do operation called with opcode 0x%x\n", 
            buf->opcode);
        buf->dma_mode = CAVIUM_DIRECT;
        if (buf->group==CAVIUM_IPSEC_GRP && (!nplus && ipsec == -1))
        {
          cavium_dbgprint("Driver not running for IPSec\n");
          return ERR_OPERATION_NOT_SUPPORTED;
        }
        if (buf->group==CAVIUM_SSL_GRP && (!nplus && ssl == -1))
        {
          cavium_dbgprint("Driver not running for SSL\n");
          return ERR_OPERATION_NOT_SUPPORTED;
        }
        if (buf->group != CAVIUM_GP_GRP && buf->group != CAVIUM_SSL_GRP && 
            buf->group != CAVIUM_IPSEC_GRP )
        {
          cavium_error ("Unknown Group operation\n");
          return ERR_OPERATION_NOT_SUPPORTED;
        }

        buf->ucode_idx = (buf->group==CAVIUM_IPSEC_GRP)?UCODE_IDX+nplus:UCODE_IDX;
        cavium_dbgprint("IOCTL_DO_OP:ucodeidx=%d, group: %d, nplus: %d\n", buf->ucode_idx, buf->group, nplus);
        if(buf->req_type == CAVIUM_SPEED) 
          ret = do_speed(pdev, buf);
        else
          ret = do_operation(pdev, buf);
        if(ret == ERR_REQ_PENDING)
        {
          buf->status= EAGAIN;
          ret= 0;
        }
      }
      cavium_dbgprint("ioctl N1 do operation returning.\n");
      break;
    case IOCTL_N1_DO_SG_OPERATION:
      {
        n1_operation_buffer *buf;

        buf = (n1_operation_buffer *)arg;
        cavium_dbgprint("ioctl N1 do operation called with opcode 0x%x\n", 
            buf->opcode);
        if (buf->group==CAVIUM_IPSEC_GRP && (!nplus || ipsec == -1))
        {
          cavium_dbgprint("Driver not running for IPSec\n");
          return ERR_OPERATION_NOT_SUPPORTED;
        }
        if (buf->group==CAVIUM_SSL_GRP && (!nplus || ssl == -1))
        {
          cavium_dbgprint("Driver not running for SSL\n");
          return ERR_OPERATION_NOT_SUPPORTED;
        }
        if (buf->group != CAVIUM_GP_GRP && buf->group != CAVIUM_SSL_GRP && 
            buf->group != CAVIUM_IPSEC_GRP )
        {
          cavium_error ("Unknown Group operation\n");
          return ERR_OPERATION_NOT_SUPPORTED;
        }
        buf->dma_mode = CAVIUM_SCATTER_GATHER;
        buf->ucode_idx = (buf->group==CAVIUM_IPSEC_GRP)?UCODE_IDX+nplus:UCODE_IDX;
        buf->opcode = buf->opcode & (~0x80);
        ret = do_operation(pdev, buf);
      }
      break;
    case IOCTL_N1_GET_REQUEST_STATUS:
      {
        Csp1RequestStatusBuffer *pReqStatus;
        cavium_dbgprint("Ioctl get request status called\n");
        if(nplus && pdev->device_id != NPX_DEVICE && pdev->microcode[UCODE_IDX].code_type == CODE_TYPE_SPECIAL)
        {
          move_srq_entries(pdev, UCODE_IDX, 0);
        }
        pReqStatus = (Csp1RequestStatusBuffer *)arg; 
        ret = check_nb_command_id(pReqStatus->request_id);
        if(ret == ERR_REQ_PENDING)
        {
          pReqStatus->status = EAGAIN;
          ret = 0;
        }
        cavium_dbgprint("get_request_status: 0x%x\n", pReqStatus->status);
      }
      break;
    case IOCTL_N1_GET_ALL_REQUEST_STATUS:
      {
        cavium_dbgprint("Ioctl getall request status called\n");
        /*check for completion of a series of pending requests*/
        ret = check_all_nb_command(pdev,(Csp1StatusOperationBuffer *)arg);
        cavium_dbgprint("getall request status ret:0x%x\n",ret);
      }
      break;
    case IOCTL_N1_FLUSH_ALL_CODE:
      {
        cavium_dbgprint("Ioctl flush all code called\n");
        cleanup_nb_command_pid(current->pid);
      }
      break;
    case IOCTL_N1_FLUSH_CODE:
      {
        cavium_dbgprint("Ioctl N1 Flush code called\n");
        cleanup_nb_command_id((Uint32)arg);
      }
      break;
    case IOCTL_N1_ALLOC_CONTEXT:
      {
        n1_context_buf c;
        cavium_dbgprint("ioctl N1 alloc context called\n");
        c = (*(n1_context_buf *)arg);
        c.ctx_ptr = alloc_context(pdev,(c.type));
        if (c.ctx_ptr == (Uint64)0) {
          cavium_print("ALLOC_CTX: failed \n");
          ret = -ENOMEM;   
        } else {
          ret = 0;
#ifdef CAVIUM_RESOURCE_CHECK
          {
            struct CAV_RESOURCES *resource = file->private_data;
            cavium_spin_lock(&resource->resource_check_lock);
            ret = insert_ctx_entry(pdev,&resource->ctx_head, c.type,
                    c.ctx_ptr);
            cavium_spin_unlock(&resource->resource_check_lock);
          }
#endif
          if(cavium_copy_out((caddr_t)arg, &c, sizeof(n1_context_buf)))
          {
            cavium_error("Failed to copy out context\n");
            ret = -EFAULT;
          }
        }
      }
      cavium_dbgprint("ioctl N1 alloc context returning\n");
      break;

    case IOCTL_N1_FREE_CONTEXT:
      {
        n1_context_buf c;
        cavium_dbgprint("ioctl N1 free context called\n");
        c = (*(n1_context_buf *)arg);
        dealloc_context(pdev, c.type, c.ctx_ptr);
        ret = 0;
#ifdef CAVIUM_RESOURCE_CHECK
        {
          struct CAV_RESOURCES *resource = file->private_data;
          struct cavium_list_head *tmp, *tmp1;
          cavium_spin_lock(&resource->resource_check_lock);
          cavium_list_for_each_safe(tmp, tmp1, &resource->ctx_head) {
            struct CTX_ENTRY *entry = list_entry(tmp, struct CTX_ENTRY, list);
            if (entry->ctx == c.ctx_ptr) 
            {
                cavium_list_del(&entry->list);
                cavium_free((Uint8 *)entry);
            }
          }
          cavium_spin_unlock(&resource->resource_check_lock);
        }
#endif
      }
      cavium_dbgprint("ioctl N1 free context returning\n");
      break;
    case IOCTL_N1_SOFT_RESET_CODE:
      {
        Uint32 dev_id;         
        dev_id=(Uint32)arg;
        do_soft_reset(&cavium_dev[dev_id]);
        ret = 0;
      }
      break;

    case IOCTL_N1_GET_STATUS_DDR:
      {
        Uint32 dev_id;
        dev_id=(Uint32)arg;

        if(cavium_dev[dev_id].dram_present)
          return 0;
        else
          return -1;
      }
      break;

    case IOCTL_N1_ALLOC_KEYMEM:
      {
        Uint64 key_handle;
        if (ssl == -1) {
          cavium_error ("Alloc Key Memory support only for SSL\n");
          return ERR_OPERATION_NOT_SUPPORTED;
        }
        cavium_dbgprint("ioctl N1 alloc keymem called\n");
        key_handle = alloc_key_memory(pdev);
        if (!key_handle) {
          cavium_error("Allocation of Key Memory failed\n");
          return -1;
        }
#ifdef CAVIUM_RESOURCE_CHECK
        {
          struct CAV_RESOURCES *resource = file->private_data;
          cavium_spin_lock_softirqsave(&resource->resource_check_lock);
          ret = insert_key_entry(pdev,&resource->key_head, 
                key_handle);
          cavium_spin_unlock_softirqrestore(&resource->resource_check_lock);
        }
#endif
        if(cavium_copy_out((caddr_t)arg, &key_handle, sizeof(Uint64)))
          cavium_error("Failed to copy out key_handle\n");
      }
      cavium_dbgprint("ioctl N1 alloc keymem returning.\n");
      break;
    case IOCTL_N1_FREE_KEYMEM:
      {
        n1_write_key_buf key_buf;
        if (ssl == -1) {
          cavium_error ("Key Memory support only for SSL\n");
          return ERR_OPERATION_NOT_SUPPORTED;
        }
        cavium_dbgprint("ioctl N1 free keymem called\n");
        key_buf = (*(n1_write_key_buf *)arg);
        dealloc_key_memory(pdev, key_buf.key_handle);
#ifdef CAVIUM_RESOURCE_CHECK
        {
          struct CAV_RESOURCES *resource = file->private_data;
          struct cavium_list_head *tmp, *tmp1;
          cavium_spin_lock_softirqsave(&resource->resource_check_lock);
          cavium_list_for_each_safe(tmp, tmp1, &resource->key_head) {
            struct KEY_ENTRY *entry = list_entry(tmp, struct KEY_ENTRY, list);
            if (entry->key_handle == key_buf.key_handle) 
            {
                cavium_list_del(&entry->list);
                cavium_free((Uint8 *)entry);
            }
          }
          cavium_spin_unlock_softirqrestore(&resource->resource_check_lock);
        }
#endif
      }
      cavium_dbgprint("ioctl N1 free keymem returning.\n");
      break;
    case IOCTL_N1_WRITE_KEYMEM:
      {
        n1_write_key_buf key_buf;
        Uint8 *key;
        if (ssl == -1) {
          cavium_error ("Key Memory support only for SSL\n");
          return ERR_OPERATION_NOT_SUPPORTED;
        }
        key_buf = (*(n1_write_key_buf *)arg);
        key = (Uint8*)get_buffer_from_pool(pdev,key_buf.length);
        if (key == NULL) {
          cavium_error("Unable to allocate memory for key\n");
          return -1;
        }
        if(cavium_copy_in(key, CAST_FRM_X_PTR(key_buf.key), key_buf.length))
        {
          cavium_error("Unable to copy in key\n");
          return -1;
        }
        key_buf.key = CAST_TO_X_PTR(key);
        if (store_key_mem(pdev, key_buf, UCODE_IDX) < 0) 
        {
          cavium_error("n1_ioctl: store_key_mem failed\n");
          put_buffer_in_pool(pdev,key);
          return -1;
        }
        put_buffer_in_pool(pdev,key);
        ret = 0;
      }
      break;

    case IOCTL_N1_GET_DEV_TYPE:
      {
        *((Uint32 *)arg) = pdev->device_id; 

      }
      break;

    case IOCTL_N1_GET_RANDOM_CODE:
      {
         n1_operation_buffer *buf;
         /* It works when microcode uses all cores */
         if (ssl && ipsec) { 
            cavium_dbgprint("Get Random not supported on some cores\n");
            ret = ERR_OPERATION_NOT_SUPPORTED;
         }
        if(!pdev->enable)
        {
          ret = ERR_DRIVER_NOT_READY;
          break;
        }
        buf = (n1_operation_buffer *)arg;
        ret = get_rnd(pdev, CAST_FRM_X_PTR(buf->outptr[0]), buf->outsize[0] , UCODE_IDX);
      }
      break;
    case IOCTL_N1_INIT_CODE:
      {
        if (nplus || ssl > 0 || ipsec > 0) 
        {
          cavium_dbgprint("calling nplus_init\n");
          ret = nplus_init(pdev, BOOT_IDX, arg);
        }
        else {
          int boot_info = 0;
          int offset = 0;
          int mainline_info = 0;
          Uint8 code_type;
          int i;
          struct MICROCODE *microcode;

          init_buffer = (Csp1InitBuffer *)arg;

          microcode = pdev->microcode;

          boot_info = 0;
          mainline_info = 0;

          /* get all the information from init buffer */
          for(i=0;i<init_buffer->size;i++)
          {
            code_type = init_buffer->version_info[i][0];

            if(code_type == CODE_TYPE_BOOT)
            {
                if(boot_info)
                {
                    cavium_print( "Code type boot found more than once\n");
                    ret = ERR_INIT_FAILURE;
                    break;
                }
                else
                {
                    cavium_print( "got boot microcode\n");
                    boot_info=1;
                }
            }
            else if (code_type == CODE_TYPE_MAINLINE)
            {
                if(mainline_info)
                {
                    cavium_print( "Code type mainline found more than once\n");
                    ret = ERR_INIT_FAILURE;
                    break;
                }
                else
                {
                    cavium_print( "got mainline microcode\n");
                    mainline_info=1;
                }
            }
            else
            {
                cavium_print( "unknown microcode type\n");
                ret = ERR_INIT_FAILURE;
                break;
            }

            /* code */

            microcode[i].code_type = code_type;
            microcode[i].code_size = init_buffer->code_length[i];
            microcode[i].code = 
                (Uint8 *)get_buffer_from_pool(pdev, microcode[i].code_size);

            if (microcode[i].code == NULL)
            {
                cavium_print( "Failed to allocate %d bytes microcode buffer type %d\n", 
                    microcode[i].code_size, code_type);
                ret = ERR_MEMORY_ALLOC_FAILURE;
                break;
            }            

            if(cavium_copy_in(microcode[i].code,
                    CAST_FRM_X_PTR(init_buffer->code[i]),
                    microcode[i].code_size))
            {
                cavium_error("Failed to copy microcode->code for microcode %d\n", i);
                ret = ERR_INIT_FAILURE;
                break;
            }

            /* data */
            microcode[i].data_size = init_buffer->data_length[i];
            if(microcode[i].data_size)
            {
#ifdef MC2
                offset = 40;
#else
                offset = 0;
#endif
                microcode[i].data =  (Uint8 *)cavium_malloc_nc_dma(pdev,
                    microcode[i].data_size+offset,
                    &microcode[i].data_dma_addr);

                if (microcode[i].data == NULL)
                {
                    cavium_print( "Failed to allocate %d bytes cst buffer type %d\n", 
                        microcode[i].data_size,code_type);

                    ret = ERR_MEMORY_ALLOC_FAILURE;
                    break;
                } 
                cavium_memset(microcode[i].data, 0x0,
                    microcode[i].data_size + offset);


                if(cavium_copy_in( microcode[i].data + offset,
                        CAST_FRM_X_PTR(init_buffer->data[i]),
                        microcode[i].data_size))
                {
                    cavium_error("Failed to copy in microcode->data for microcode %d\n", i);
                    cavium_free_nc_dma(pdev,
                        microcode[i].data_size+offset,
                        microcode[i].data,
                        microcode[i].data_dma_addr);
                    microcode[i].data_size = 0;
                    microcode[i].data = NULL;
                    microcode[i].data_dma_addr = 0;

                    ret = ERR_INIT_FAILURE;
                    break;
                }
            }

            /* sram address */
            if(cavium_copy_in(microcode[i].sram_address, 
                    init_buffer->sram_address[i],
                    SRAM_ADDRESS_LEN))
            {
                cavium_error("Failed to copy in sram_address for microcode %d\n", i);
                cavium_free_nc_dma(pdev, microcode[i].data_size+offset,
                    microcode[i].data,
                    microcode[i].data_dma_addr);
                microcode[i].data_size = 0;
                microcode[i].data = NULL;
                microcode[i].data_dma_addr = 0;

                ret = ERR_INIT_FAILURE;
                break;
            }


            cavium_print("Code type = %02x, code size = %x, data size = %x\n",
                    microcode[i].code_type,
                    microcode[i].code_size,
                    microcode[i].data_size);


          }/* for */

          /* check for any missing piece */
          if( !mainline_info || !boot_info ) {
            cavium_print( "Not all of the information was sent to device driver.\n");
            cavium_print( "Please check version information\n");
            ret = ERR_INIT_FAILURE;
            break;
          }

          /* Now we have gathered all the required information from init_buffer*/
          /* Now it is time for some action. */

          ret = do_init(pdev);
        } /* nplus */
        break;
      }
    case IOCTL_N1_GET_DEV_CNT:
      {
        n1_dev_mask *buf;
        Uint8 i=0;
        Uint8 mask=0;   
        buf=(n1_dev_mask*)arg;   
        cavium_dbgprint("Ioctl GET device count called\n");
        /*retun the devices detected*/
        buf->dev_cnt=dev_count;   

        for(i=0;i<dev_count;i++)
        {   
          if(cavium_dev[i].enable)
            mask |=   1<<i;    
        }

        buf->dev_mask=mask;
        //  *((Uint32 *)arg) = dev_count;
        break;
      }

      /* To driver state */
    case IOCTL_N1_GET_DRIVER_STATE:
      {
        uint8_t *driver_type = (uint8_t *)arg;
        cavium_dbgprint("ioctl get driver type\n");

        if (nplus) /* if ssl & ipsec are running */
          *driver_type = DRV_ST_SSL_IPSEC;
        else if (ssl>0) /* if ssl running on some cores */ 
          *driver_type = DRV_ST_SSL_CORES;
        else if (ssl==0) /* if ssl running on default cores */
          *driver_type = DRV_ST_SSL_DFL;
        else if (ipsec>0) /* if ipsec running on some cores */
          *driver_type = DRV_ST_IPSEC_CORES;
        else if (ipsec==0) /* if ipsec running on default cores */
          *driver_type = DRV_ST_IPSEC_DFL;
        else /* Unknown state */
          *driver_type = DRV_ST_UNKNOWN;
      }
      break;

    case IOCTL_CSP1_GET_CORE_ASSIGNMENT:
      if (nplus || ssl>0 || ipsec>0)
      {
        int i;
        Csp1CoreAssignment *core_assign = (Csp1CoreAssignment *)arg;

        cavium_dbgprint("ioctl Get core assignment \n");
        cavium_spin_lock_softirqsave(&pdev->mc_core_lock);

        for(i=0;i<MICROCODE_MAX-!nplus;i++)
        {
          core_assign->core_mask[i] = get_core_mask(pdev,i); 
          core_assign->mc_present[i] = (pdev->microcode[i].code==NULL)? 0:1;
        }
        cavium_spin_unlock_softirqrestore(&pdev->mc_core_lock);
      }
      break;

    case IOCTL_CSP1_SET_CORE_ASSIGNMENT:
      if (nplus || ipsec>0 || ssl>0)
      {
        int i;
        Uint8 id;
        Uint32 changed_mask_0_1 = 0, changed_mask_1_0 = 0;
        Uint32 core_mask, core_mask_1_0, core_mask_0_1;
        Csp1CoreAssignment *core_assign = (Csp1CoreAssignment *)arg;
        Uint8   core_grp=0;
        Uint32  new_core_grp_mask=0, reg_exec_grp_mask=0;
        cavium_dbgprint("ioctl set core assignment \n");

        if(pdev->initialized != 1)
        {
          ret = ERR_DRIVER_NOT_READY;
          break;
        }

        cavium_dbgprint("Assign Cores(%ld): { ", jiffies);
        for(i=0;i<MICROCODE_MAX - !nplus; i++) {
          cavium_dbgprint("%x ", core_assign->core_mask[i]);
          if (i==1) {
             if(ssl > 0) ssl_cores=core_assign->core_mask[i];
             else ipsec_cores = core_assign->core_mask[i];
          }
          else
             if(i==2) ipsec_cores = core_assign->core_mask[i];
        }

        cavium_dbgprint("}\n");

        cavium_spin_lock_softirqsave(&pdev->mc_core_lock);
        /* This loop checks if the new assignments will be valid */
        for(i=0;i<MICROCODE_MAX - !nplus && ret==0;i++)
        {
          /*** Paired cores is not supported in NitroxPX */
          /* Does this ucode require paired cores for 2048 bit ops ? */
          if(pdev->device_id!=NPX_DEVICE) {

            if(pdev->microcode[i].paired_cores)
            {
                core_mask = core_assign->core_mask[i];
                /* We will check if the new assignment will result in an
                 * unpaired core
                 */
                while(core_mask != 0)
                {
                    if((core_mask & 0x1) != ((core_mask>>1) & 0x1))
                    {
                      ret = ERR_ILLEGAL_ASSIGNMENT;
                      goto cleanup_set_cores;
                    }
                    core_mask = (core_mask >> 2);
                }
            }
          }    
          /*  Check the 0->1 transitions in the mask */
          core_mask = get_core_mask(pdev,i);
          core_mask_0_1 = (~core_mask & core_assign->core_mask[i]);
          if(core_mask_0_1)
          {
            if(changed_mask_0_1 & core_mask_0_1)
            {
                ret = ERR_ILLEGAL_ASSIGNMENT;
                goto cleanup_set_cores;
            }
            changed_mask_0_1 |= core_mask_0_1;
          }

          core_mask_1_0 = (core_mask & ~core_assign->core_mask[i]);
          if(core_mask_1_0)
          {
            /*  Check the 1->0 transitions in the mask */
            if(changed_mask_1_0 & core_mask_1_0)
            {
                ret = ERR_ILLEGAL_ASSIGNMENT;
                goto cleanup_set_cores;
            }
            changed_mask_1_0 |= core_mask_1_0;
            /* If we are reducing the cores to 0 for any microcode, there
             * should not be any open handles for that microcode */
            /*               if((core_assign->core_mask[i] == 0)
                     && pdev->microcode[i].use_count)
                     {
                     ret = ERR_ILLEGAL_ASSIGNMENT;
                     goto cleanup_set_cores;
                     } */
          }
        }
        /* Make sure the transitions match */
        if(changed_mask_1_0 != changed_mask_0_1)
        {
          ret = ERR_ILLEGAL_ASSIGNMENT;
          goto cleanup_set_cores;
        }

        /* We will first free cores */
        for(i=FREE_IDX+1; i<MICROCODE_MAX-!nplus; i++)
        {
          Uint8 prev_id = (Uint8)-1;
          if(!(changed_mask_1_0 & get_core_mask(pdev, i)))
            continue;

          id = pdev->microcode[i].core_id;
          while(id != (Uint8)-1)
          {
            /* Is this core to be free'd ? */
            if(changed_mask_1_0 & (1<<id))
            {
                /* First get the core to a "loop forever state" */
                if(pdev->microcode[i].code_type == CODE_TYPE_MAINLINE)
                {
                    if(acquire_core(pdev, i, id))
                    {
                    /* TODO: Need to consider error handling. */
                    cavium_print("Failed core %d acquisition!!\n", id);
                    }
                }
                else if(pdev->device_id != NPX_DEVICE)
                {
                    /* First we will try to see if the core is ready */
                    wait_cores_idle(pdev, id);
                    /* Cleanup the core structure */
                    pdev->cores[id].ready = 0;
                    pdev->cores[id].pend2048 = 0;
                    pdev->cores[id].lrsrq_idx = -1;
                    pdev->cores[id].ctp_ptr = NULL;
                    pdev->cores[id].lrcc_ptr = NULL;
                }

                /* Delink from current list */
                if(prev_id == (Uint8)-1)
                    pdev->microcode[i].core_id = pdev->cores[id].next_id;
                else
                    pdev->cores[prev_id].next_id = pdev->cores[id].next_id;

                /* Add to free list */
                pdev->cores[id].next_id=pdev->microcode[FREE_IDX].core_id;
                pdev->microcode[FREE_IDX].core_id = id; 
                pdev->cores[id].ucode_idx = FREE_IDX;

                if(prev_id == (Uint8) -1)
                    id = pdev->microcode[i].core_id;
                else
                    id = pdev->cores[prev_id].next_id;
            }
            else
            {
                prev_id = id; id = pdev->cores[prev_id].next_id;
            }
          }
          /* Initially all microcode have core grp as NITROX_PX_MAX_GROUPS.
             We need to free the group only if the microcode was previously
             loaded but is being unloaded now. */
          if(pdev->device_id  == NPX_DEVICE && pdev->microcode[i].core_grp < NITROX_PX_MAX_GROUPS) {
            free_npx_group(pdev->microcode[i].core_grp);
          }
        }

        /* TODO: We need to be sure they are done */
        /* Disable the cores */
        cavium_udelay(10);

        cavium_print("Disabling units: mask 0x%x\n", changed_mask_1_0);

        disable_exec_units_from_mask(pdev, changed_mask_1_0);

        /* Now go ahead and add the cores to the new microcodes */
        for(i=FREE_IDX+1; i<MICROCODE_MAX-!nplus; i++)
        {

          Uint8 prev_id = (Uint8)-1;
          Uint32 mask = 0;

          if(!(changed_mask_0_1 & core_assign->core_mask[i]))
            continue;

          cavium_print("Loading ucode %d\n", i);

          /* Load the microcode, except for FREE_IDX */
          if(load_microcode(pdev, i))
          {
            cavium_print("Error loading microcode %d\n", i);
            ret = ERR_UCODE_LOAD_FAILURE;
            goto cleanup_set_cores;
          }
          if(pdev->device_id == NPX_DEVICE)
          {
            core_grp = (Uint8)get_next_npx_group();
            if(core_grp >= NITROX_PX_MAX_GROUPS) {
                cavium_error("N1_IOCTL : No more core groups available\n");
                return ERR_ILLEGAL_ASSIGNMENT;
            }
            pdev->microcode[i].core_grp = core_grp;
          }

          id = pdev->microcode[FREE_IDX].core_id;
          while(id != (Uint8)-1)
          {
            /* Is this core to be allocated ? */
            if(changed_mask_0_1 & core_assign->core_mask[i] & (1<<id))
            {
                /* Delink from free list */
                if(prev_id == (Uint8)-1)
                    pdev->microcode[FREE_IDX].core_id
                    = pdev->cores[id].next_id;
                else
                    pdev->cores[prev_id].next_id
                    = pdev->cores[id].next_id;

                /* Add to microcode list */
                pdev->cores[id].next_id=pdev->microcode[i].core_id;
                pdev->microcode[i].core_id = id; 
                pdev->cores[id].ucode_idx = i;
                if(pdev->device_id != NPX_DEVICE && pdev->microcode[i].code_type == CODE_TYPE_SPECIAL)
                {
                    pdev->cores[id].ctp_ptr = pdev->ctp_base
                    + (id*CTP_COMMAND_BLOCK_SIZE*CTP_QUEUE_SIZE);
                    /* Zero the CTP for the core */
                    cavium_memset(pdev->cores[id].ctp_ptr, 0 ,
                        CTP_COMMAND_BLOCK_SIZE*CTP_QUEUE_SIZE);

                    pdev->cores[id].ctp_idx = 0;
                    pdev->cores[id].ready = 1;
                    pdev->cores[id].lrsrq_idx = -1;
                    pdev->cores[id].lrcc_ptr = NULL;
                    pdev->cores[id].doorbell = 0;
                }
                else if(pdev->device_id == NPX_DEVICE)
                    new_core_grp_mask |= ( (1 << core_grp) << (id * 4));

                mask |= (1<<id);

                if(prev_id == (Uint8) -1)
                {
                    id = pdev->microcode[FREE_IDX].core_id;
                }
                else
                {
                    id = pdev->cores[prev_id].next_id;
                }
            }
            else
            {
                prev_id = id; id = pdev->cores[prev_id].next_id;
            }
          }

          cavium_dbgprint("Cycling cores: 0x%x\n", mask);

          cavium_udelay(100);
          enable_exec_units_from_mask(pdev, mask);

        }
        cavium_udelay(100);


        cavium_dbgprint("Enabled cores: 0x%x\n", get_enabled_units(pdev));
        if(pdev->device_id == NPX_DEVICE)
        {
          read_PKP_register(pdev, (pdev->CSRBASE_A + REG_EXEC_GROUP), &reg_exec_grp_mask);
          reg_exec_grp_mask |= new_core_grp_mask;
          write_PKP_register(pdev, (pdev->CSRBASE_A + REG_EXEC_GROUP), reg_exec_grp_mask);
        }

cleanup_set_cores:
        cavium_spin_unlock_softirqrestore(&pdev->mc_core_lock);
        if(ret != 0) break;

        if(pdev->enable == 0)
        {
          int idx;

          /* TODO: Assuming that MLM code is running (may not be true)
           * We will first search for the MLM code type. */
          for(idx=0;idx<MICROCODE_MAX-!nplus;idx++)
          {
            if(pdev->microcode[idx].code_type == CODE_TYPE_MAINLINE)
                break;
          }
          if(idx>=MICROCODE_MAX)
          {
            /* We did not find any mainline microcode, so we give up */
            ret = ERR_INIT_FAILURE;
            break;
          }

          //#ifdef SSL
          /* Now initialize encrypted master secret key and iv in the first 48
           * bytes of FSK */
          if(ssl>=0 && core_assign->core_mask[UCODE_IDX] && 
                   pdev->microcode[UCODE_IDX].code_type == CODE_TYPE_SPECIAL)
          {    
            if(init_ms_key(pdev, UCODE_IDX))
            {
                cavium_print("Couldnot initialize encrypted master secret key and IV.\n");
                ret = ERR_INIT_FAILURE;
                break;
            }

            /* Fill random buffer */
            if(fill_rnd_buffer(pdev, UCODE_IDX))
            {
                cavium_print("Couldnot fill random buffer.\n");
                ret = ERR_INIT_FAILURE;
                break;
            }

          }   
          //#endif /*SSL*/
          pdev->rnd_index=0;
          pdev->enable=1;

          pdev->rnd_index=0;
          pdev->enable=1;

          /* disable master latency timer */ /* QUES: What for?? */
          write_PCI_register(pdev, 0x40, 0x00000001);
        }
        ret=0;
      }
      break;


      /* Oops, sorry */
    default:
      cavium_print("cavium: Invalid request 0x%x\n", cmd);
      ret = -EINVAL;
      break;

  } /* switch cmd*/
  return (ret);

}/*n1_ioctl*/





/*
 * Poll for completion
 */
  unsigned int
n1_poll(struct file *fp, poll_table *wait)
{
  Uint32 mask = 0, is_ready;
  cavium_pid_t pid = current->pid;

  is_ready = check_nb_command_pid(pid);

  if (is_ready) {
    mask |= POLLIN | POLLRDNORM;
  }

  return mask;
}


#ifndef CAVIUM_NO_MMAP
/* 
 *  VMA Operation called when an munmap of the entire VM segment is done
 */

  void 
n1_vma_close(struct vm_area_struct *vma)
{
  Uint32 size;
  ptrlong virt_addr;
  Uint8 *kmalloc_ptr, *kmalloc_area;
  Uint32 minor=0;
  if (!nplus)
    minor = MINOR(vma->vm_file->f_dentry->d_inode->i_rdev);

  kmalloc_ptr = vma->vm_private_data;
  size = vma->vm_end - vma->vm_start;

  /* align it to page boundary */
  kmalloc_area = (Uint8 *)(((ptrlong)kmalloc_ptr + PAGE_SIZE -1) & PAGE_MASK);

  /* Unreserve all pages */
  for(virt_addr = (ptrlong)kmalloc_area; 
      virt_addr < (ptrlong)kmalloc_area + size; virt_addr +=PAGE_SIZE) {
#if LINUX_VERSION_CODE <= KERNEL_VERSION(2,6,0) 
    mem_map_unreserve(virt_to_page(virt_addr));
#else
    ClearPageReserved(virt_to_page(virt_addr));
#endif
  }

  put_buffer_in_pool(&cavium_dev[minor], kmalloc_ptr);

  cavium_dbgprint( "pkp_drv: UNmap returning successfully(pid=%d)\n",
      current->pid);
  CAVIUM_MOD_DEC_USE_COUNT;
  return;

}

static struct vm_operations_struct n1_vma_ops = 
{
  NULL,
  n1_vma_close,
  NULL,
};


/*
 * mmap entry point
 */
  int 
n1_mmap(struct file *file, struct vm_area_struct *vma)
{
  Uint32 size;
  Uint8 *kmalloc_ptr,*kmalloc_area;
  ptrlong virt_addr;
  Uint32 offset;
  Uint32 minor=0;
  if (ssl==0 || ipsec==0)
    minor = MINOR(file->f_dentry->d_inode->i_rdev);
  MPRINTFLOW();

  size = vma->vm_end - vma->vm_start;

  if(size % PAGE_SIZE) {
    cavium_error("n1_mmap: size (%d) not multiple of PAGE_SIZE.\n", size);
    return -ENXIO;
  }

  offset = vma->vm_pgoff << PAGE_SHIFT;
  if(offset & ~PAGE_MASK) {
    cavium_error("n1_mmap: offset (%d) not aligned.\n", offset);
    return -ENXIO;
  }

  kmalloc_ptr = (Uint8 *)get_buffer_from_pool(&cavium_dev[minor], size);
  if(kmalloc_ptr == NULL) {
    cavium_error("n1_mmap: not enough memory.\n");
    return -ENOMEM;
  }

  /* align it to page boundary */
  kmalloc_area = (Uint8 *)(((ptrlong)kmalloc_ptr + PAGE_SIZE -1) & PAGE_MASK);

  /* reserve all pages */
  for (virt_addr = (ptrlong)kmalloc_area; 
      virt_addr < (ptrlong)kmalloc_area + size; virt_addr +=PAGE_SIZE) {
#if LINUX_VERSION_CODE <= KERNEL_VERSION(2,6,0) 
    mem_map_reserve(virt_to_page(virt_addr));
#else
    SetPageReserved(virt_to_page(virt_addr));
#endif
    /*  get_page not required *
        get_page(virt_to_page(virt_addr)); */
  }

  /* Mark the vm-area Reserved*/
  vma->vm_flags |=VM_RESERVED;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,11)
  if(remap_pfn_range(vma,vma->vm_start,
        (virt_to_phys((void *)(ptrlong)kmalloc_area))>>PAGE_SHIFT,
        size, vma->vm_page_prot))

#elif LINUX_VERSION_CODE <= KERNEL_VERSION(2,4,18) 
    if(remap_page_range(vma->vm_start,
          virt_to_phys((void *)(ptrlong)kmalloc_area),
          size, vma->vm_page_prot))
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(2,4,20) 
      if(remap_page_range(vma,vma->vm_start,
            virt_to_phys((void *)(ptrlong)kmalloc_area),
            size, vma->vm_page_prot))
#endif
      {

        cavium_error("n1_mmap: remap page range failed.\n");
        return -ENXIO;
      }

  vma->vm_ops = &n1_vma_ops;
  vma->vm_private_data = kmalloc_ptr;
  vma->vm_file = file;

  CAVIUM_MOD_INC_USE_COUNT;
  cavium_dbgprint( "n1_mmap: mmap returning successfully(pid=%d)\n",current->pid);
  return 0;
}

#endif


/*
 * Linux layer Intrerrupt Service Routine
 */
#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,6,19))
irqreturn_t linux_layer_isr(int irq, void *dev_id, struct pt_regs *regs)
#else
irqreturn_t linux_layer_isr(int irq, void *dev_id)
#endif
{
#ifdef INTERRUPT_RETURN
  int ret;
  ret = cavium_interrupt_handler(dev_id);
  if(ret == 0) {
    return IRQ_HANDLED;
  }else {
    return IRQ_NONE;
  }
#else
  cavium_interrupt_handler(dev_id);
#endif
}

/* 
 * Hook the interrupt handler
 */
int setup_interrupt(cavium_device *pdev)
{
  int result;
  int interrupt_pin;

  MPRINTFLOW();
#ifndef CNS3000
#ifdef CONFIG_PCI_MSI
  if(pdev->device_id==NPX_DEVICE){   
    if(pci_find_capability((struct pci_dev *)(pdev->dev), PCI_CAP_ID_MSI)) {
      if(!pci_enable_msi((struct pci_dev *)(pdev->dev))) {
        msi_enabled = 1;
      }
    } 
  }   

#endif
  interrupt_pin = ((struct pci_dev *)(pdev->dev))->irq;
#else
	#define CNS3000_CRYPTO_IRQ IRQ_CNS3XXX_CRYPTO
   interrupt_pin = CNS3000_CRYPTO_IRQ;
#endif

#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,6,22))
  result = request_irq(interrupt_pin, linux_layer_isr,SA_SHIRQ,DEVICE_NAME,pdev);
#else
  result = request_irq(interrupt_pin, linux_layer_isr,IRQF_SHARED,DEVICE_NAME,pdev);
#endif

  if(result)
  {
    cavium_print ("pkp_drv: can't get assigned irq : %x\n", interrupt_pin);
    return 1;
  }
  return 0;
}/* setup interrupt */


/* Let go the interrupt */
void free_interrupt(cavium_device *pdev)
{
  int interrupt_pin;

	#ifdef CNS3000
	interrupt_pin = CNS3000_CRYPTO_IRQ;
	#else
  interrupt_pin = ((struct pci_dev *)(pdev->dev))->irq;
  free_irq(interrupt_pin, pdev);
#ifdef CONFIG_PCI_MSI

  if(pdev->device_id==NPX_DEVICE){
    if(msi_enabled)
      pci_disable_msi((struct pci_dev *)(pdev->dev));
  }   

#endif
#endif
}

/* 
 * initialize kernel mode.
 * Calls user interface specific functions.
 */
  int
init_kernel_mode ()
{
  struct N1_Dev *device_node = NULL, *prev = NULL;
  int i;

  MPRINTFLOW();
  for (i = 0; i < dev_count; i++) {
    device_node = cavium_malloc((sizeof(struct N1_Dev)), NULL);
    device_node->next = NULL;
    device_node->id = i;
    device_node->bus = cavium_dev[i].bus_number;
    device_node->dev = cavium_dev[i].dev_number;
    device_node->func = cavium_dev[i].func_number;
    device_node->data = (void *)(&cavium_dev[i]);
    if(device_list == NULL)
      device_list = device_node;
    else
      prev->next = device_node;
    prev = device_node;
  }
#if LINUX_VERSION_CODE < KERNEL_VERSION (2,6,10)
  //   if (nplus || ipsec>=0) 
  {
    inter_module_register(N1ConfigDeviceName, THIS_MODULE, 
        n1_config_device);
    inter_module_register(N1UnconfigDeviceName, THIS_MODULE, 
        n1_unconfig_device); 
    inter_module_register(N1AllocContextName, THIS_MODULE, 
        n1_alloc_context);
    inter_module_register(N1FreeContextName, THIS_MODULE, 
        n1_free_context);
    inter_module_register(N1ProcessInboundPacketName, THIS_MODULE,
        n1_process_inbound_packet);
    inter_module_register(N1ProcessOutboundPacketName, THIS_MODULE,
        n1_process_outbound_packet);
    inter_module_register(N1WriteIpSecSaName, THIS_MODULE,
        n1_write_ipsec_sa);
  }
#endif

  return 0;
}/* init_kernel_mode */

/*
 * free kernel mode.
 * Calls user interface specific functions
 */
  int
free_kernel_mode (void)
{
  struct N1_Dev *node = device_list;
  /* 
   * */
  while (node != NULL) {
    struct N1_Dev *tmp;
    tmp = node->next;
    cavium_free(node);
    node = tmp;
  }

#if LINUX_VERSION_CODE < KERNEL_VERSION (2,6,10)
  if (nplus || ipsec>=0)
  {
    inter_module_unregister(N1ConfigDeviceName);
    inter_module_unregister(N1UnconfigDeviceName);
    inter_module_unregister(N1AllocContextName);
    inter_module_unregister(N1FreeContextName);
    inter_module_unregister(N1ProcessInboundPacketName);
    inter_module_unregister(N1ProcessOutboundPacketName);
    inter_module_unregister(N1WriteIpSecSaName);
  }
#endif

  return 0;
}
static int __init cavium_driver_init(void)
{
  int ret_val = 0;

#if defined(CAVIUM_DEBUG_LEVEL)
   cavium_debug_level = CAVIUM_DEBUG_LEVEL;
#else
   cavium_debug_level = 0;
#endif

/* nplus check */
   if (ssl > 0 && ipsec > 0) {
      cavium_dbgprint("***** PLUS Driver selected *****\n");
      nplus=1;
   }
   else if ((ssl < 0 && ipsec < 0) || (ssl==0 && ipsec==0))
   {
      printk ("Wrong args: It requires ssl=<cores> and/or ipsec=<cores> as arguments\n");
      printk ("    If you want use all available cores for a protocol, say ssl/ipsec=0\n");
      return -ERANGE;
   }
   if (!nplus) {
      cavium_dbgprint("***** NON-PLUS Driver selected *****\n");
   }
/* nplus check done */
#ifndef CNS3000
  if ((ret_val = pci_register_driver(&cavium_pci_driver))) {
     cavium_error ("Unable to register the cavium driver\n");
     return ret_val;
  }
#else
#endif

  ret_val = initmodule();    
  return 0;
}
static void __exit cavium_driver_exit(void)
{
  cleanupmodule();
#ifndef CNS3000
  pci_unregister_driver(&cavium_pci_driver);
#endif
  cavium_print("General cleanup \n");
  cavium_general_cleanup();

  cavium_print("Freeing proc resources \n");
  cavium_free_proc();

#if CAVIUM_DEBUG_LEVEL
  printk("UnLoaded Cavium Nitrox Driver --- %01d.%02d-%c\n",
      cavium_version[0],cavium_version[1],cavium_version[2]);
#endif
}/* free_kernel_mode */
#if LINUX_VERSION_CODE > KERNEL_VERSION (2,6,10)
EXPORT_SYMBOL(n1_config_device);
EXPORT_SYMBOL(n1_unconfig_device); 
EXPORT_SYMBOL(n1_alloc_context);
EXPORT_SYMBOL(n1_free_context);
EXPORT_SYMBOL(n1_process_inbound_packet);
EXPORT_SYMBOL(n1_process_outbound_packet);
EXPORT_SYMBOL(n1_write_ipsec_sa);
#ifdef MC2
EXPORT_SYMBOL(n1_invalidate_ipsec_sa);
EXPORT_SYMBOL(n1_flush_packet_queue);
#endif
//#endif
#endif

module_init (cavium_driver_init);
module_exit (cavium_driver_exit);
/*
 * $Id: linux_main.c,v 1.50 2009/10/01 05:27:46 aravikumar Exp $
 * $Log: linux_main.c,v $
 * Revision 1.50  2009/10/01 05:27:46  aravikumar
 * Added Check for pci_register_driver
 *
 * Revision 1.49  2009/09/29 11:24:46  aravikumar
 * Added cavium_driver_init and cavium_driver_exit, cleanup and cavium_probe to remove manual cavium pci device detection process by Vipin and ucode_idx has changed to UCODE_IDX for SSL calls
 *
 * Revision 1.48  2009/09/22 09:51:24  aravikumar
 * fill_rnd_buffer call moved before init_ms_key
 *
 * Revision 1.47  2009/09/16 11:53:15  aravikumar
 * Error handle Added
 *
 * Revision 1.46  2009/09/15 06:01:42  aravikumar
 * removed ucode_idx variable in n1_open and n1_close and changed to BOOT_IDX
 *
 * Revision 1.45  2009/09/11 09:51:43  aravikumar
 * fixed group check
 *
 * Revision 1.44  2009/09/10 14:27:32  aravikumar
 * Added check before do_operation call
 *
 * Revision 1.43  2009/09/09 11:18:29  aravikumar
 * NPLUS macro dependency removed and made it dynamic
 *
 * Revision 1.42  2009/06/23 12:55:04  kkiran
 * - if(dev_count >= MAX_DEV) changed to if(dev_count>MAX_DEV).
 *
 * Revision 1.41  2009/06/11 07:53:57  aravikumar
 * Changes made for FC-10
 *
 * Revision 1.40  2009/04/07 05:36:14  kmonendra
 * Check reqeuest type, if it is CAVIUM_SPEED then call do_speed for speedtest.
 *
 * Revision 1.39  2008/11/20 07:10:14  ysandeep
 * fixed bug in nplus_init
 *
 * Revision 1.38  2008/11/06 09:06:29  ysandeep
 * Removed PX_PLUS
 *
 * Revision 1.37  2008/10/20 08:44:35  ysandeep
 * fixed driver load failure when ssl cores = 0 and ipsec cores = 8 for
 * NITROX_PX
 *
 * Revision 1.36  2008/10/15 09:58:19  ysandeep
 * Fixed compilation errors and warnings
 *
 * Revision 1.35  2008/10/15 08:03:39  ysandeep
 * Multicard support for NPLUS added.
 *
 * Revision 1.33  2008/09/30 13:18:18  jsrikanth
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
 * Revision 1.32  2008/08/25 10:04:13  aramesh
 * deleted unnecessary printfs.
 *
 * Revision 1.31  2008/07/29 14:53:21  aramesh
 * IOCTL_N1_GET_DDR_STATUS is added.
 *
 * Revision 1.30  2008/07/29 11:10:45  aramesh
 * SET_SOFT_RESET ioctl has added dev_id argumnet.
 *
 * Revision 1.29  2008/07/29 04:20:01  aramesh
 * done proper indendation.
 *
* Revision 1.28  2008/07/18 05:52:41  aramesh
* px_flag is set to CN15XX/CN16XX based on px device.
*
* Revision 1.27  2008/07/07 12:30:11  aramesh
* dev_mask is added fo DEV_CNT ioctl.
*
* Revision 1.26  2008/07/02 12:27:41  aramesh
* deleted config part and corresponding flags.
*
* Revision 1.25  2008/02/22 08:36:55  aramesh
* driver cleanup done.
*
* Revision 1.24  2008/02/14 05:40:15  kchunduri
* -- remove CN1600 dependency.
*
* Revision 1.23  2007/12/06 13:38:10  jsrikanth
* dev_cnt is Uint32 type.
*
* Revision 1.22  2007/11/26 11:29:08  tghoriparti
* request_mem_region failed case handled
*
* Revision 1.21  2007/11/21 07:07:33  ksadasivuni
* all driver load messages now will be printed at CAVIUM_DEBUG_LEVEL>0
*
* Revision 1.20  2007/11/05 08:52:02  tghoriparti
* MSI support added for CN1600
*
* Revision 1.19  2007/11/01 15:28:00  tghoriparti
* Revoking the changes done to Read/Write Debug registers
*
* Revision 1.18  2007/10/31 07:02:49  aramesh
* Read/Write Debug code ioctl changed to expect only the register offset
*
* Revision 1.17  2007/10/16 06:27:57  aramesh
* --Changes for support of NLite/N1 family.
*
* Revision 1.16  2007/10/04 11:22:47  tghoriparti
* changed ioctl of read/write debug rg to expect complete addr instead of offset
*
* Revision 1.15  2007/09/20 05:24:09  kchunduri
* --Associate Resources to Device.
*
* Revision 1.14  2007/07/24 12:57:04  kchunduri
* --update return parameter in IOCTL_N1_DEV_CNT;
*
* Revision 1.13  2007/07/16 12:39:33  tghoriparti
* command queues are reset after enabling the request unit
*
* Revision 1.12  2007/07/04 04:45:08  kchunduri
* --New IOCTL to return number of devices detected.
*
* Revision 1.11  2007/06/07 15:00:59  tghoriparti
* fixed misplaced cavium_cleanup in cavium_cleanup_one.
*
* Revision 1.10  2007/04/04 21:49:15  panicker
* * Added support for CN1600
* * correction in isr declaration for 2.6.19 and above
*
* Revision 1.9  2007/03/08 20:38:28  panicker
* * NPLUS mode changes. pre-release
* * NitroxPX now supports N1-style NPLUS operation.
* * Native PX mode PLUS operations are enabled only if PX_PLUS flag is enabled
*
* Revision 1.8  2007/03/06 02:38:27  panicker
* * PX will use the same core id lookup mechanism as N1. So now IOCTL_CSP1_SET_CORE_ASSIGNMENT uses most of the same code as N1 for PX. core group maintenance routines are in cavium.c. core groups are set/unset as
* microcode is loaded/unloaded for NPLUS on PX (PX-PLUS in the future).
* * npx_ioctl_set_core() routine removed.
* * store_key_mem() and get_rnd() use the same prototype as N1 for PX.
*
* Revision 1.7  2007/02/21 23:31:25  panicker
* * print fixed
*
* Revision 1.6  2007/02/20 22:29:08  panicker
* * New chip version resolves config space issues. So device id 0x0 is no longer required.
* * memory region calls corrected.
*
* Revision 1.5  2007/02/02 02:23:13  panicker
* * Prints modified
*
* Revision 1.4  2007/02/01 23:26:38  panicker
* * Temporary changes during bringup. Device Id 0x0. Driver names unique for PX and N1.
*
* Revision 1.3  2007/01/13 03:11:48  panicker
* * compilation warnings fixed.
* * fill_rnd_buffer() and init_ms_key() use non-NPLUS mode call for PX.
*
* Revision 1.2  2007/01/13 01:51:11  panicker
* NPLUS changes for PX
* - do not include soft_req_queue.h in PX
* - use_count is used in NPLUS (for all). It is incremented in n1_open() and
*   decremented in n1_release(). It is checked in IOCTL_N1_SET_CORE.
* - send_command() & check_completion() uses non-NPLUS mode calling method.
* - paired_cores, srq and ctp are not used in PX for NPLUS.
  *
* -- n1_ioctl()
  *    - N1_GET_REQUEST - move srq is not required for PX
  *    - get_rnd(), store_key_mem() uses non-NPLUS mode for PX
  *    - IOCTL_SET_CORE - for NPLUS mode in PX a new function is defined
  *           npx_ioctl_set_core().
  *
  * Revision 1.1  2007/01/06 02:47:40  panicker
  * * first cut - NITROX PX driver
  *
  * Revision 1.61  2006/11/02 10:47:41  kanantha
  * Removed the warning for kernel <2.6.2
  *
  * Revision 1.60  2006/09/25 10:09:56  ksnaren
  * fixed compile error for linux 2.4.18
  *
  * Revision 1.59  2006/08/16 14:26:07  kchunduri
  * --1)set the status of N1 Operation in 'status'(EAGAIN/'0') field of n1_operation_buffer instead of passing it in return value.
  * --2)The request_id parameter for IOCTL_N1_GET_REQUEST_STATUS is passed in 'Csp1RequestStatusBuffer'. The status of request is set in 'status' field of 'Csp1RequestStatusBuffer'.
  *
  * Revision 1.58  2006/08/01 07:55:03  kchunduri
  * Fix warning messages due to change in DebugRWReg structure
  *
  * Revision 1.57  2006/07/10 07:07:34  kchunduri
  * --io_remap_page_range not supported on some kernels. So changed to remap_pfn_range
  *
  * Revision 1.56  2006/05/16 15:33:45  kchunduri
* --changed argument type of function nplus_init()
  *
  * Revision 1.55  2006/05/16 09:25:57  kchunduri
* --support for Dynamic DMA mapping instead of virt_to_phys()
  *
  * Revision 1.54  2006/04/17 04:21:31  kchunduri
  * --new IOCTL case 'IOCTL_N1_GET_ALL_REQUEST_STATUS'
  *
  * Revision 1.53  2006/04/05 11:58:04  ksadasivuni
  * - Added n1_simulated_unlocked_ioctl for kernels older than 2.6.11.
  *   If it is not desired in Makefile.Linux define NO_SIMULATED_UNLOCKED_IOTCL.
  *
  * Revision 1.52  2006/03/28 06:33:32  ksadasivuni
  * - v1.50 being moved to 1.52.
  *   v.1.51 is a intermediate checkin required for nplus.
  *
  * Revision 1.50  2006/03/27 05:51:53  ksadasivuni
  * - Merged 1.48 changes with added n1_unlocked_ioctl stuff
  *
  * Revision 1.48  2006/02/27 07:09:14  sgadam
  * - checking for NULL in alloc_context
  *
  * Revision 1.47  2006/02/10 05:19:12  sgadam
  * - Ipsec MC1 invalidate_ipsec_sa removed
  *
  * Revision 1.46  2006/02/06 05:23:43  sgadam
  *  - invalidate_ipsec_sa api added
  *
  * Revision 1.45  2006/01/19 09:43:49  sgadam
  * - IPsec 2.6.11 changes
  *
  * Revision 1.44  2005/12/21 06:36:17  ksadasivuni
  * - 8 byte alignment issue fixed.
  *
  * Revision 1.43  2005/12/14 09:22:04  kkiran
  * - Fixed compile errors.
  *
  * Revision 1.42  2005/12/14 09:00:26  kkiran
  * - Fixed NPLUS related module unregister calls.
  * - Removed MODVERSIONS from Makefile.
  *
  * Revision 1.41  2005/12/13 10:13:54  sgadam
  * - made ipsec related changes for 2.6.11
  *
  * Revision 1.40  2005/12/13 09:43:49  pravin
  * - Fixed Nplus related compilation issues on Linux 2.4 kernels.
  *
  * Revision 1.39  2005/12/12 06:41:52  sgadam
  * - made ipsec related changes for 2.6.11
  *
  * Revision 1.38  2005/12/09 06:08:27  kanantha
  * Modified the Uint64 to ptrlong to support in both 32 and 64 bit versoions for MMAP
  *
  * Revision 1.37  2005/12/07 04:48:47  kanantha
  * modified for both 32 and 64 bit supoort
  *
  * Revision 1.36  2005/11/21 05:58:28  kanantha
  * Removed compilation warnings for MMAP mode on FC4 64bit
  *
  * Revision 1.34  2005/08/31 18:11:45  bimran
  * Added CAVIUM_NO_MMAP macro.
  *
  * Revision 1.33  2005/08/31 02:25:18  bimran
  * Fixed code to check for copy_in/out return values and for some other functions too.
  * Fixed for 2.6.11 kernel.
  *
  * Revision 1.32  2005/06/29 19:41:26  rkumar
  * 8-byte alignment problem fixed with N1_SANITY define.
  *
  * Revision 1.31  2005/06/13 06:35:42  rkumar
  * Changed copyright
  *
  * Revision 1.30  2005/06/10 09:12:07  rkumar
  * 7.3 compilation error fixed
  *
  * Revision 1.29  2005/06/03 08:20:27  rkumar
  * Preventing opening of devices when driver removal is being done
  *
  * Revision 1.28  2005/05/20 14:34:05  rkumar
  * Merging CVS head from india
  *
  * Revision 1.27  2005/02/03 19:21:30  tsingh
  * fixed kernel version dependency
  *
  * Revision 1.26  2005/02/01 04:07:12  bimran
  * copyright fix
  *
  * Revision 1.25  2005/01/28 18:32:15  mvarga
* Fixed kernel version dependenmcy (bimran)
  *
  * Revision 1.24  2005/01/26 20:34:04  bimran
  * Fixed dependency on RH distribution. Made it kernel version dependent.
  *
  * Revision 1.23  2004/08/03 20:44:10  tahuja
  * support for Mips Linux & HT.
  *
  * Revision 1.22  2004/07/07 17:59:31  tsingh
  * some compilation issues
  *
  * Revision 1.21  2004/06/23 02:20:20  mikev
  * Added api test.
  *
  * Revision 1.20  2004/06/09 01:57:27  bimran
  * Fixed a bug in NPLUS mode where microcode reference was taken from NULL pointer.
  *
  * Revision 1.19  2004/06/08 18:06:39  tsingh
  * fixed compile time issue
  *
  * Revision 1.18  2004/06/03 21:19:41  bimran
  * included cavium_list.h
  * fixed list* calls to use cavium_list
  *
  * Revision 1.17  2004/06/02 19:02:53  tsingh
* added one more debug print. (bimran)
  *
  * Revision 1.16  2004/06/02 02:08:23  tsingh
  * removed get_id() (bimran).
  *
  * Revision 1.15  2004/06/01 17:42:06  bimran
  * Made some locks softirq safe,
  *
  * Revision 1.14  2004/05/11 20:50:31  tsingh
  * Changed some arguments passed through a function
  *
  * Revision 1.13  2004/05/05 06:43:23  bimran
  * Fixed non blocking return code.
  *
  * Revision 1.12  2004/05/04 20:48:08  bimran
  * Fixed RESOURCE_CHECK.
  *
  * Revision 1.11  2004/05/02 19:43:58  bimran
  * Added Copyright notice.
  *
  * Revision 1.10  2004/05/01 07:13:37  bimran
  * Fixed return code get request status function.
  *
  * Revision 1.9  2004/05/01 00:48:10  tsingh
  * Fixed for NPLus (bimran).
  *
  * Revision 1.8  2004/04/24 04:01:26  bimran
  * Fixed NPLUS related bugs.
  * Added some more debug prints.
  *
  * Revision 1.7  2004/04/22 01:10:35  bimran
  * Added NPLUS registeration message.
  *
  * Revision 1.6  2004/04/21 19:15:18  bimran
  * Added Random pool support.
  * Added NPLUS specific initialization functions and core acquire functions.
  * Added NPLUS related ioctls.
  *
  * Revision 1.5  2004/04/20 17:40:27  bimran
  * changed all microcode references from cavium_device structure instead of global mirocode structure.
  *
  * Revision 1.4  2004/04/20 02:18:37  bimran
  * Removed an unreachabe code segment where ddr_present flag was checked before the driver checked for DDR memory presence.
  *
  * Revision 1.3  2004/04/19 18:36:32  bimran
  * Removed admin microcode requirement.
  *
  * Revision 1.2  2004/04/16 23:57:47  bimran
  * Added more debug prints.
  *
  * Revision 1.1  2004/04/15 22:40:47  bimran
  * Checkin of the code from India with some cleanups.
  *
  */

