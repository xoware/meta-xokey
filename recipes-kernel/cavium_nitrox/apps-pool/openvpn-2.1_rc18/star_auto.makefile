#make -f star_auto.makefile TARGET_ROOT=$(TARGET_ROOT) KERNELDIR=$(KERNELDIR) INSTALL_PATH=$(TARGET_ROOT) CC=${CC}
#make -f star_auto.makefile  TARGET_ROOT=`pwd`/install CC=arm-linux-gcc
# 
# Required Parameter
#
INSTALL_PATH?=$(shell pwd)/target
KERNELDIR?=../linux

CC?=arm-linux-gcc
PARAM?= CC=${CC} DESTDIR=${INSTALL_PATH}

#
# Only Used for debug currently
#
PWD=$(shell pwd)
MYPATH=$(shell dirname ${PWD})
MYNAME=$(shell basename ${PWD})
build: info
	@echo action=$@
	#./configure --prefix=$TMP_INSTALL
	#./configure --host=arm-linux CC=arm-linux-gcc CXX=arm-linux-uclibc-g++ --prefix=${INSTALL_PATH} 
	#./configure --host=arm-linux CC=arm-linux-gcc CXX=arm-linux-uclibc-g++ --prefix=${INSTALL_PATH} CPPFLAGS="-DEMBEDDED -I${INSTALL_PATH}/include/" CFLAGS="-DEMBEDDED -I${INSTALL_PATH}/include/" LDFLAGS=-L${INSTALL_PATH}/lib 
	#./configure --host=arm-linux CC=arm-linux-gcc CXX=arm-linux-uclibc-g++ --prefix=${INSTALL_PATH} CPPFLAGS=" -I${INSTALL_PATH}/include/" CFLAGS=" -I${INSTALL_PATH}/include/" LDFLAGS="-L${INSTALL_PATH}/lib" 
	#./configure --host=arm-linux CC=arm-linux-gcc CXX=arm-linux-uclibc-g++ CPPFLAGS=" -I${INSTALL_PATH}/include/" CFLAGS=" -I${INSTALL_PATH}/include/" LDFLAGS="-L${INSTALL_PATH}/lib" --prefix=/
	./configure --host=arm-linux --prefix=/ --with-ssl-headers=${INSTALL_PATH}/usr/local/ssl/include --with-ssl-lib=${INSTALL_PATH}/usr/local/ssl/lib
	make ${PARAM}

clean: info
	@echo action=$@
	#make clean ${PARAM}
	if [ -e Makefile ] ; then make distclean ${PARAM}||exit 1; fi

install: info
	@echo action=$@
	make install ${PARAM}

info:
	@echo ==================
	@echo MYPATH=${MYPATH}
	@echo MYNAME=${MYNAME}
	@echo PWD=${PWD}
	@echo INSTALL_PATH=${INSTALL_PATH}
	@echo KERNELDIR=${KERNELDIR}
	@echo ==================


