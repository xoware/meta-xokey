EXTRA_CFLAGS += -DMC2
EXTRA_CFLAGS += -I$(CAVIUM_INCLUDEDIR)

obj-m += cavm_ipsec.o
cavm_ipsec-objs := cavium_ipsec.o cavium_ah4.o cavium_esp4.o cavium_ah6.o cavium_esp6.o ipsec_engine.o cavium_kernel.o
all:
	make -C $(KERNELDIR) M=`pwd` modules
clean:
	make -C $(KERNELDIR) M=`pwd` clean

install:
	echo pwd=`pwd`
	make -C $(KERNELDIR) INSTALL_MOD_PATH=${INSTALL_MOD_PATH} M=`pwd` modules modules_install
