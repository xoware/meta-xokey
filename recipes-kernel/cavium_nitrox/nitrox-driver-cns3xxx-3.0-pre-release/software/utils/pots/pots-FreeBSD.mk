
BASEDIR= ../..
include $(BASEDIR)/platform
include $(BASEDIR)/Makefile.$(OS)
#CFLAGS += -c -g -I$(BASEDIR)/include -I$(ARCH_INCLUDEDIR) -mabi=64
CFLAGS += -c -g -I$(BASEDIR)/include -I$(ARCH_INCLUDEDIR) 

# This is the path on 30xx system
CFLAGS += -I/usr/local/ssl/include

# This is the path on my Intel Build system
CFLAGS += -I/usr/local/octeon-openssl/include

######## Enable for 32bit compilation on 64bit kernel #########
CFLAGS_LOCAL32 =  #-B /usr/lib32 -m32

CFLAGS += -I/usr/include
CFLAGS += -D$(MLM_PROTOCOL)
CFLAGS += $(ARCH_APPFLAGS)

CFLAGS += $(CFLAGS_LOCAL32)
#CC=mips64-octeon-linux-gnu-gcc
#LD=mips64-octeon-linux-gnu-ld

.if $(CONFIG_NPLUS) != y
BOOT_MC=../../bin/boot.out
MAIN_MC=../../bin/main.out
.endif

######### Enable for 32bit compilation on 64bit kernel ##########
LDFLAGS_LOCAL32 = #-B /usr/lib32 -m32 -L/usr/lib32

LDFLAGS = $(LDFLAGS_LOCAL32)
LDFLAGS += -o

DEFINES = -DPOTS 
#Need to be defined for MC2 SSL-b version microcode
#DEFINES += -DRAW_AES 
DEFINES += -DAES_OSSL
#DEFINES += $(APP_DEFINES)

SRCS = 	cavium_common.c		\
	cavium_pots.c		\
	pots_main.c 		\
	pots_init.c 		\
	pots_config.c 		\
	pots_crypto_def_vals.c	\
	pots_utils.c 		\
	pots_log.c		\
	pots_results.c		\
	pots_soft_reset.c 	\
	pots_reg_utils.c 	\
	pots_bist.c 		\
	pots_rc4.c 		\
	pots_hmac.c		\
	pots_read_write_reg.c	\
	pots_keymem.c		\
	pots_ddr.c		\
	pots_random.c		\
	randtest.c		\
	pots_ucode.c		\
	pots_openssl.c		\
	pots_3des.c		\
	pots_aes.c		\
	pots_mod_ex.c		\
	pots_ipsec.c		\
	mod_ex_utils.c			


OBJS = 	cavium_common.o			\
		cavium_pots.o		\
		pots_main.o 		\
		pots_init.o 		\
		pots_config.o 		\
		pots_crypto_def_vals.o	\
		pots_utils.o 		\
		pots_log.o		\
		pots_results.o		\
		pots_soft_reset.o 	\
		pots_bist.o 		\
		pots_reg_utils.o	\
		pots_rc4.o 		\
		pots_hmac.o		\
		pots_read_write_reg.o	\
		pots_keymem.o		\
		pots_ddr.o		\
		pots_random.o		\
		randtest.o		\
		pots_ucode.o		\
		pots_openssl.o		\
		pots_3des.o		\
		pots_aes.o		\
		pots_mod_ex.o		\
		pots_ipsec.o		\
		mod_ex_utils.o			

all-pots-FreeBSD: make_links pots_main 

all: make_links
	@$(MAKE) -C .. all

install:
	@$(MAKE) -C .. install


pots_main: $(OBJS)
	$(CC) $(LDFLAGS)  pots_main $(OBJS) -L. -lcrypto #-ldl

cavium_common.o: ../../api/cavium_common.c
	$(CC) $(CFLAGS) $(DEFINES) ../../api/cavium_common.c

pots_openssl.o: pots_openssl.c
	$(CC) $(CFLAGS) $(DEFINES) -I$(X) -c -o pots_openssl.o pots_openssl.c

%.o : %.c
	$(CC) $(CFLAGS) $(DEFINES) -c $^ -o $@
.c.o:
	$(CC) $(CFLAGS) $(DEFINES) -c ${.IMPSRC}

make_links:
.if $(CONFIG_NPLUS) != y
	@ln -sf $(BOOT_MC) ./boot.out
	@ln -sf $(MAIN_MC) ./main.out
.endif
	@mkdir -p logs

clean: clean-pots-FreeBSD

clean-pots-FreeBSD:
	@rm -f *.o pots_main boot.out main.out logs/*.log 
	@rm -rf logs
