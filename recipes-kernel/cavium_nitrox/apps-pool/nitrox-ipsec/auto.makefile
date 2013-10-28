#make -f star_auto.makefile KERNEL=$(KERNEL) TARGET_ROOTFS_DIR=$(TARGET_ROOTFS_DIR) CROSS_COMPILE=${CROSS_COMPILE}
#
# Initial parameters (don't change)
#
PWD=$(shell pwd)
MYPATH=$(shell dirname ${PWD})
MYNAME=$(shell basename ${PWD})


# 
# Received Parameter (don't change)
#  

#TARGET_ROOTFS_DIR is the installation target directory,
#ROOTFS_DIR_FOR_LIB is the places to collect all cumulative rootfs, includes libs
#Usually TARGET_ROOTFS_DIR and ROOTFS_DIR_FOR_LIB are the same, but there are situations that they are not.
#
TARGET_ROOTFS_DIR?=$(shell pwd)/target

KERNEL?=$(shell pwd)/../../kernels/linux
CROSS_COMPILE?=arm-linux-

#
# Application specific application, change as needed
#
CC=${CROSS_COMPILE}gcc
PARAM= KERNELDIR=${KERNEL} INSTALL_MOD_PATH=${TARGET_ROOTFS_DIR} 


#
# build: configure, then build
#
build: info
	@echo action=$@
	cd ipsec-tools-0.6.5;./configure --host=arm-linux --with-openssl=${ROOTFS_DIR_FOR_LIB}/usr/local/ssl --prefix=${TARGET_ROOTFS_DIR} --with-kernel-headers=${KERNEL}/include --enable-ipv6 ||exit 1;\
	if [ ! -e mkinstalldir ] ; then ln -s /usr/share/automake-1.7/mkinstalldirs;fi;\
	patch -i config.h.patch config.h ;\
	make ;
	
	make -C linux/ipsec_module ${PARAM}
clean: info
	@echo action=$@
	if [ -e ipsec-tools-0.6.5/Makefile ] ; then make -C ipsec-tools-0.6.5 $@ || exit 0;fi
	make -C linux/ipsec_module ${PARAM} $@
	#if [ -e Makefile ] ; then make distclean ${PARAM}||exit 1; fi

install: info
	@echo action=$@
	make -C ipsec-tools-0.6.5 $@
	make -C linux/ipsec_module ${PARAM} $@

info:
	@echo ==================
	@echo MYPATH=${MYPATH}
	@echo MYNAME=${MYNAME}
	@echo PWD=${PWD}
	@echo TARGET_ROOTFS_DIR=${TARGET_ROOTFS_DIR}
	@echo KERNEL=${KERNEL}
	@echo ==================


