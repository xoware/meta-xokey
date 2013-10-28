ifeq ($(strip $(LINUX_VERSION)),2.4)
DRIVER_DEFINES += -D__KERNEL__ -DMODULE -DEXPORT_SYMTAB 
INCLUDE = -I$(KERNEL_PATH)/include
else
DRIVER_DEFINES += -DCAVIUM_NEW_API -DEXPORT_SYMTAB 
endif

$(shell ln -sf $(CAV_TOPDIR)/api/cavium_crypto.c $(CAV_TOPDIR)/driver/linux/cavium_crypto.c)
KERN_API_O      = cavium_crypto.o

#ifeq ($(strip $(MLM_PROTOCOL)),SSL) 
$(shell ln -sf $(CAV_TOPDIR)/api/cavium_speed.c $(CAV_TOPDIR)/driver/linux/cavium_speed.c)
SPEED_O      = cavium_speed.o
#endif

ifeq ($(MICROCODE),MC2)
$(shell ln -sf $(CAV_TOPDIR)/api/ipsec_mc2.c $(CAV_TOPDIR)/driver/linux/ipsec_mc2.c)
IPSEC_O      = ipsec_mc2.o
else
ifeq ($(MICROCODE),MC1)
$(shell ln -sf $(CAV_TOPDIR)/api/ipsec_mc1.c $(CAV_TOPDIR)/driver/linux/ipsec_mc1.c)
IPSEC_O      = ipsec_mc1.o
#MC1
endif
#MC2
endif


$(shell ln -sf $(CAV_TOPDIR)/api/cavium_speed.c $(CAV_TOPDIR)/driver/linux/cavium_speed.c)
SPEED_O      = cavium_speed.o
$(shell ln -sf $(CAV_TOPDIR)/api/ipsec_mc2.c $(CAV_TOPDIR)/driver/linux/ipsec_mc2.c)
IPSEC_O = ipsec_mc2.o  


#ifneq (PX_PLUS,$(findstring PX_PLUS,$(DRIVER_DEFINES)))
NPLUS_O = ../osi/soft_req_queue.o
#endif

#endif
## END NPLUS ##




CONFIG_API_TEST = n
ifeq ($(CONFIG_API_TEST), y)
DRIVER_DEFINES += -DAPI_TEST
NPLUS_O += api_test.o
endif 

DRIVER_DEFINES += -DN1_TIMER_ROLLOVER

INCLUDE     += -I$(CAV_TOPDIR)/driver/linux -I$(CAV_TOPDIR)/driver/osi -I$(CAV_TOPDIR)/include  
INCLUDE     += -I/usr/local/Cavium_Networks/CN3XXX-SDK/target/include
EXTRA_CFLAGS  = $(DRIVER_DEFINES) $(INCLUDE) $(INC_BUILD)
OPT_FLAGS   = -O2
WARN_FLAGS  = -Wall -Werror
DEBUG_FLAGS = -DCAVIUM_DEBUG_LEVEL=$(CAVIUM_DEBUG_LEVEL)
EXTRA_CFLAGS      += $(OPT_FLAGS) $(WARN_FLAGS) $(DEBUG_FLAGS)

DRVOBJ = pkp_drv

obj-m := $(DRVOBJ).o

$(DRVOBJ)-objs := ../osi/command_que.o \
				../osi/context_memory.o \
				../osi/error_handler.o \
				../osi/hw_lib.o    \
				../osi/pending_free_list.o \
				../osi/pending_list.o \
				../osi/direct_free_list.o \
				../osi/cavium.o \
				../osi/init_cfg.o \
				../osi/interrupt.o \
				../osi/cavium_random.o \
				../osi/request_manager.o \
				../osi/bl_nbl_list.o \
				../osi/buffer_pool.o \
				../osi/sg_free_list.o  \
				../osi/completion_dma_free_list.o \
				../osi/sg_dma_free_list.o \
				../osi/key_memory.o \
				linux_main.o poll_thread.o cavium_proc.o $(IPSEC_O) $(NPLUS_O) $(SPEED_O) $(KERN_API_O)


all:
	@$(MAKE) -C .. all

install:
	@$(MAKE) -C .. install
	
clean:
	@$(MAKE) -C .. clean

all-linux: 
	@if [ $(LINUX_VERSION) = 2.6 ]; then \
		$(MAKE) -C $(KERNEL_PATH) SUBDIRS=`pwd` modules; \
		ln -sf ./$(DRVOBJ).ko ./$(DRVOBJ).o; \
	else \
		$(MAKE) $(DRVOBJ).o; \
	fi


#pkp_drv.o: $(pkp_drv-objs)
$(DRVOBJ).o: $($(DRVOBJ)-objs)
	@$(LD) -r $^ -o $@



../osi/%.o : %.c 
	$(CC) $(EXTRA_CFLAGS) -c $< -o $@

clean-linux:
	@rm -f *.o *.ko *~ core *.symvers *.mod.c ipsec_mc2.c cavium_speed.c .*.cmd
	@rm -rf .tmp_versions
	@rm -f ../osi/*.o ../osi/*.ko ../osi/*~ ../osi/core ../osi/.*.cmd

#
# $Id: Makefile,v 1.23 2009/09/15 05:58:44 aravikumar Exp $
# $Log: Makefile,v $
# Revision 1.23  2009/09/15 05:58:44  aravikumar
# MLM_PROTOCOL and CAVIUM_MICROCODE dependency removed
#
# Revision 1.22  2009/09/09 11:19:04  aravikumar
# NPLUS macro dependency removed and made it dynamic
#
# Revision 1.21  2009/06/25 06:39:04  ysandeep
# fixed compilation error
#
# Revision 1.20  2009/06/25 06:34:04  ysandeep
# cavium_kernel.c changed to cavium_crypto.c
#
# Revision 1.19  2009/06/24 11:12:23  ysandeep
# OCF support added
#
# Revision 1.18  2009/04/28 11:19:51  pnalla
# Used EXTRA_CFLAGS instead of CFLAGS
#
# Revision 1.17  2008/12/19 10:00:11  ysandeep
# added *.symvers to clean
#
# Revision 1.16  2008/11/26 13:45:59  ysandeep
# added *.mod.c to "make clean"
#
# Revision 1.15  2008/11/05 06:55:34  ysandeep
# Fixed compilation error
#
# Revision 1.14  2008/11/05 06:17:00  ysandeep
# Added cavium_speed.c to clean
#
# Revision 1.13  2008/11/04 08:31:43  ysandeep
# Fixed compilation error for NPLUS with IPSEC as MLM
#
# Revision 1.12  2008/10/24 08:38:35  ysandeep
# NPLUS support added for cavium_speed.c
#
# Revision 1.11  2008/10/13 09:51:37  ysandeep
#   Fixed compilation errors for NPLUS mode with SSL as MLM protocol
#
# Revision 1.10  2008/07/02 12:27:41  aramesh
# deleted config part and corresponding flags.
#
# Revision 1.9  2008/05/02 10:03:23  kkiran
#  - cavium_speed.c should compile only for SSL.
#
# Revision 1.8  2008/05/01 12:54:43  tghoriparti
# cavium_speed.c is compiled
#
# Revision 1.7  2008/02/22 07:16:12  aramesh
# driver cleanup done.
#
# Revision 1.6  2007/10/16 06:27:57  aramesh
# --Changes for support of NLite/N1 family.
#
# Revision 1.5  2007/03/08 20:38:28  panicker
# * NPLUS mode changes. pre-release
# * NitroxPX now supports N1-style NPLUS operation.
# * Native PX mode PLUS operations are enabled only if PX_PLUS flag is enabled
#
# Revision 1.4  2007/02/02 02:20:46  panicker
# * Make for Octeon. NLE and N1 driver have different names currently
#
# Revision 1.3  2007/01/16 00:06:46  panicker
# * ipsec_mc2.c file fixed for NPLUS mode with NITROX PX
# * removed comments from temporarily commented lines
#
# Revision 1.2  2007/01/13 03:06:19  panicker
# * soft_req_queue is compiled only for non-NITROX_PX
# * Temporarily disabled compilation of ipsec_mc2.c
#
# Revision 1.1  2007/01/06 02:47:40  panicker
# * first cut - NITROX PX driver
#
# Revision 1.24  2005/12/14 09:00:26  kkiran
# - Fixed NPLUS related module unregister calls.
# - Removed MODVERSIONS from Makefile.
#
# Revision 1.23  2005/12/13 09:43:49  pravin
# - Fixed Nplus related compilation issues on Linux 2.4 kernels.
#
# Revision 1.22  2005/12/12 06:40:09  sgadam
# - Corrected path for link
#
# Revision 1.21  2005/08/31 18:11:09  bimran
# Fixed for FC4.
#
# Revision 1.20  2005/06/03 08:25:37  rkumar
# CONFIG_MICROCODE changed to CAVIUM_MICROCODE
#
# Revision 1.19  2005/05/20 14:34:05  rkumar
# Merging CVS head from india
#
# Revision 1.18  2005/01/19 22:54:52  tsingh
# parameter changes for quicksec on CN1005
#
# Revision 1.17  2005/01/19 02:50:48  mvarga
# Removed modversions
#
# Revision 1.16  2004/08/03 20:44:10  tahuja
# support for Mips Linux & HT.
#
# Revision 1.15  2004/07/12 21:56:50  tsingh
# *** empty log message ***
#
# Revision 1.14  2004/07/07 20:07:16  tsingh
# *** empty log message ***
#
# Revision 1.13  2004/07/07 19:58:19  tsingh
# not doing export of Makefile options
#
# Revision 1.12  2004/06/23 02:19:33  mikev
# Added api test.
#
# Revision 1.11  2004/05/03 18:02:39  bimran
# Fixed KERNEL SOURCE.
#
# Revision 1.10  2004/05/01 00:48:10  tsingh
# Fixed for NPLus (bimran).
#
# Revision 1.9  2004/04/28 18:40:48  tsingh
# modified kernel source to be /usr/src/linux
#
# Revision 1.8  2004/04/26 20:39:00  tsingh
# added api compile rule
#
# Revision 1.7  2004/04/24 03:43:15  bimran
# Fixed SMP flag definition.
#
# Revision 1.6  2004/04/22 03:47:35  bimran
# Removed un-necessary portions .
#
# Revision 1.5  2004/04/22 02:47:26  bimran
# Removed un-necessary sections.
#
# Revision 1.4  2004/04/21 21:18:40  bimran
# Added Cavium default debug level
#
# Revision 1.3  2004/04/21 19:13:58  bimran
# Added support for NPLUS.
#
# Revision 1.2  2004/04/19 18:35:58  bimran
# Removed admin microcode requirement.
#
# Revision 1.1  2004/04/15 22:40:47  bimran
# Checkin of the code from India with some cleanups.
#
#/

