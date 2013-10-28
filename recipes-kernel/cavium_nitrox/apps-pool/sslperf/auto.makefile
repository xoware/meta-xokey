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
PARAM= CC=${CC} DESTDIR=${TARGET_ROOTFS_DIR} CROSS_COMPILE=${CROSS_COMPILE} SSL_PATH=${ROOTFS_DIR_FOR_LIB}/usr/local/ssl 

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
	mkdir ${TARGET_ROOTFS_DIR}/root/sslperf -p
	cp sslperf ${TARGET_ROOTFS_DIR}/bin -v
	cp client.* server.* ${TARGET_ROOTFS_DIR}/root/sslperf -v

info:
	@echo ==================
	@echo MYPATH=${MYPATH}
	@echo MYNAME=${MYNAME}
	@echo PWD=${PWD}
	@echo TARGET_ROOTFS_DIR=${TARGET_ROOTFS_DIR}
	@echo KERNEL=${KERNEL}
	@echo ==================


