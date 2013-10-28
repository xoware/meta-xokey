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
#
TARGET_ROOTFS_DIR?=$(shell pwd)/target
KERNEL?=$(shell pwd)/../../kernels/linux
CROSS_COMPILE?=arm-linux-

#
# Application specific application, change as needed
#
CC=${CROSS_COMPILE}gcc
PARAM= CC=${CC} DESTDIR=${TARGET_ROOTFS_DIR} CROSS_COMPILE=${CROSS_COMPILE}

#
# build: configure, then build
#
build: info
	@echo action=$@
	./configure --host=arm-linux --prefix=/ --with-ssl-headers=${ROOTFS_DIR_FOR_LIB}/usr/local/ssl/include --with-ssl-lib=${ROOTFS_DIR_FOR_LIB}/usr/local/ssl/lib
	make ${PARAM}

clean: info
	@echo action=$@
	if [ -e Makefile ] ; then make ${PARAM} $@ ||exit 1; fi

install: info
	@echo action=$@
	mkdir ${TARGET_ROOTFS_DIR} -p
	make ${PARAM} $@
	#cp _install/* ${TARGET_ROOTFS_DIR} -af

info:
	@echo ==================
	@echo MYPATH=${MYPATH}
	@echo MYNAME=${MYNAME}
	@echo PWD=${PWD}
	@echo TARGET_ROOTFS_DIR=${TARGET_ROOTFS_DIR}
	@echo KERNEL=${KERNEL}
	@echo ==================


