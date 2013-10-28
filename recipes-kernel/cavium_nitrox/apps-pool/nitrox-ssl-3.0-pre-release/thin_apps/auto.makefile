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

#toolchain bin directory =    ${TOOLCHAIN_INSTALL_PATH}/${TOOLCHAIN_BIN}
#toolchain lib directory =    ${TOOLCHAIN_INSTALL_PATH}/${TOOLCHAIN_LIB}
#toolchain header directory = ${TOOLCHAIN_INSTALL_PATH}/${TOOLCHAIN_H}
#
#
# Application specific application, change as needed
#
CC=${CROSS_COMPILE}gcc
PARAM= CC=${CC} DESTDIR=${TARGET_ROOTFS_DIR} CROSS_COMPILE=${CROSS_COMPILE} CAVIUMDIR=${CAVIUM_INCLUDEDIR} \
OPENSSLDIR=${ROOTFS_DIR_FOR_LIB}/usr/local/ssl \
OPENSSLDIR_INCLUDE=${ROOTFS_DIR_FOR_LIB}/usr/local/ssl/include \
OPENSSLDIR_LIB=${ROOTFS_DIR_FOR_LIB}/usr/local/ssl/lib 

#
# build: configure, then build
#
build: info
	@echo action=$@
	make ${PARAM}

clean: info
	@echo action=$@
	make ${PARAM} $@
	#if [ -e Makefile ] ; then make distclean ${PARAM}||exit 1; fi

install: info
	@echo action=$@
	mkdir ${TARGET_ROOTFS_DIR}/bin -p
	cp thin_server thin_client ${TARGET_ROOTFS_DIR}/bin/ -avf

info:
	@echo ==================
	@echo MYPATH=${MYPATH}
	@echo MYNAME=${MYNAME}
	@echo PWD=${PWD}
	@echo TARGET_ROOTFS_DIR=${TARGET_ROOTFS_DIR}
	@echo KERNEL=${KERNEL}
	@echo ==================


