
BASEDIR = .
include $(BASEDIR)/platform
include Makefile.$(OS)

SUBDIRS= driver  utils

INCLUDEDIR = $(TOPDIR)/include

all: check_defines sub_all bin_install  

check_defines:
#check for consistency of defines
	@if test $(OS) = Linux ; then \
		if test $(LINUX_VERSION) != $(LINUX_SRC_VERSION) ; then \
			echo "Linux Kernel Path $(KERNEL_PATH) points to $(LINUX_SRC_VERSION) does not match Running kernel $(LINUX_VERSION) "; \
			exit 1; \
		fi \
	fi
	@if test $(OS) = Linux ; then \
		if [ -d $(KERNEL_PATH) ] ; then \
			echo ""; \
		else \
			echo "Linux Kernel directory not found/specified"; \
			exit 1; \
		fi \
	fi

	@if test -f include/app_defines.h ; then \
		echo " " ;\
	else \
		for i in $(APP_DEFINES); \
			do \
				echo "#ifndef $$i" >> include/app_defines.h; \
				echo "#define $$i" >> include/app_defines.h; \
				echo "#endif" >> include/app_defines.h; \
			done;	\
	fi

	  
sub_all:
	@for i in $(SUBDIRS); \
	do \
	if [ -d "$$i" ]; then \
		(cd $$i && \
		$(MAKE) all-$$i) || exit 1; \
	fi; \
	done;

linux:
	@ln -sf $(TOPDIR)/include/cavium_common.h $(KERNEL_PATH)/net/ipv4/cavium_common.h
	@ln -sf $(TOPDIR)/include/linux_sysdep.h $(KERNEL_PATH)/net/ipv4/cavium_sysdep.h

linux_patch:
	@ln -sf $(TOPDIR)/include/cavium_common.h $(KERNEL_PATH)/net/ipv4/cavium_common.h
	@ln -sf $(TOPDIR)/include/linux_sysdep.h $(KERNEL_PATH)/net/ipv4/cavium_sysdep.h
	@(cd $(KERNEL_PATH); patch -p1 < $(TOPDIR)/apps/linux-2.6.2.patch)

bin_install:
	@mkdir -p bin
	@ln -sf $(TOPDIR)/driver/$(PLATFORM)/$(DRIVER_OBJ) $(TOPDIR)/bin/$(DRIVER_OBJ)
	@ln -sf $(TOPDIR)/utils/$(INIT_NITROX) $(TOPDIR)/bin/init_nitrox
	@ln -sf $(TOPDIR)/utils/csp1_init $(TOPDIR)/bin/csp1_init; 
	@ln -sf $(TOPDIR)/utils/pots/pots_main $(TOPDIR)/bin/;
	@ln -sf $(TOPDIR)/utils/pots/pots.cnf $(TOPDIR)/bin/;
	@ln -sf $(TOPDIR)/utils/pots/aes.txt $(TOPDIR)/bin/;
	@ln -sf $(TOPDIR)/utils/speed-ipsec/speedtest $(TOPDIR)/bin/;
	@ln -sf $(TOPDIR)/utils/speed-ipsec/ipsec_run $(TOPDIR)/bin/;
	@ln -sf $(TOPDIR)/utils/speed-ipsec/speedtest_nb $(TOPDIR)/bin/;
	@ln -sf $(TOPDIR)/utils/speed-ssl/speed_ssl $(TOPDIR)/bin/;
	@ln -sf $(TOPDIR)/utils/speed-ssl/nbaperf $(TOPDIR)/bin/;
	@ln -sf $(TOPDIR)/utils/speed-ssl/ssl_run $(TOPDIR)/bin/;
	@ln -sf $(TOPDIR)/utils/test_3des $(TOPDIR)/bin/;
	@ln -sf $(TOPDIR)/utils/test_rc4 $(TOPDIR)/bin/;
	@ln -sf $(TOPDIR)/utils/test_rnd $(TOPDIR)/bin/;
	@ln -sf $(TOPDIR)/utils/simop $(TOPDIR)/bin/;
	@ln -sf $(TOPDIR)/utils/n1debug $(TOPDIR)/bin/;
	@ln -sf $(TOPDIR)/utils/init_nitrox $(TOPDIR)/bin/;
	@ln -sf $(TOPDIR)/utils/get_package_list $(TOPDIR)/bin/;



install: all

clean:
	
	@rm -f include/app_defines.h 1>/dev/null 2>/dev/null;
	@rm -f $(TOPDIR)/bin/$(DRIVER_OBJ)
	@rm -f $(TOPDIR)/bin/boot.out
	@rm -f $(TOPDIR)/bin/main_ssl.out
	@rm -f $(TOPDIR)/bin/plus_ssl.out
	@rm -f $(TOPDIR)/bin/main_ipsec.out
	@rm -f $(TOPDIR)/bin/plus_ipsec.out
	@rm -f $(TOPDIR)/bin/init_nitrox
	@rm -f $(TOPDIR)/bin/pots
	@rm -f $(TOPDIR)/bin/pkp_debug
	@rm -f $(TOPDIR)/bin/csp1_init
	@for i in $(SUBDIRS) ; \
	do \
	if [ -d "$$i" ]; then \
		(cd $$i && \
		 $(MAKE) clean-$$i ) || exit 1; \
	fi; \
	done;

dev:    
	@if test $(OS) = Linux ; then \
		mknod /dev/$(DEV_PREFIX)_dev c $(DEV_MAJOR) 0; \
	fi

#
# $Id: Makefile,v 1.20 2009/09/09 15:09:58 aravikumar Exp $
# $Log: Makefile,v $
# Revision 1.20  2009/09/09 15:09:58  aravikumar
# NPLUS macro dependency removed and made it dynamic
#
# Revision 1.19  2008/11/26 07:11:05  ysandeep
# Fixed compilation error
#
# Revision 1.18  2008/11/26 07:06:16  ysandeep
# moved init_nitrox_plus under NPLUS
#
# Revision 1.17  2008/11/05 06:43:16  ysandeep
# Removed creation of devices for multicard
#
# Revision 1.16  2008/10/24 07:16:55  ysandeep
# removed cavium_npx.conf
#
# Revision 1.15  2008/10/15 10:26:42  ysandeep
# Made init_nitrox_plus executable
#
# Revision 1.14  2008/10/15 08:36:35  ysandeep
# fixed errors
#
# Revision 1.12  2008/07/02 12:21:07  aramesh
# deleted config part and corresponding flags.
#
# Revision 1.11  2008/03/14 06:19:17  aramesh
# links created properly.
#
# Revision 1.10  2008/02/22 07:13:34  aramesh
# driver cleanup done.
#
# Revision 1.9  2007/10/24 11:29:21  aramesh
# linking errors fixed
#
# Revision 1.8  2007/07/31 10:11:08  tghoriparti
# N1 related changes done
#
# Revision 1.7  2007/06/18 11:30:59  rsruthi
# -- Nitrox-PX PLUS related changes
#
# Revision 1.6  2007/05/01 05:57:51  kchunduri
# * moved definition of few flags to Makefile.$(OS)
#
# Revision 1.5  2007/04/05 03:04:48  panicker
# * Makefile corrections before CN1600 pre-release
#
# Revision 1.4  2007/03/08 23:52:42  panicker
# * rules to build all device files for N1 and NPX.
#
# Revision 1.3  2007/02/21 04:20:50  panicker
# Modified make rules for pre-release
#
# Revision 1.2  2007/02/02 02:20:22  panicker
# * Make for Octeon. NLE and N1 driver have different names currently
#
# Revision 1.1  2007/01/13 03:03:40  panicker
# Makefiles
#
