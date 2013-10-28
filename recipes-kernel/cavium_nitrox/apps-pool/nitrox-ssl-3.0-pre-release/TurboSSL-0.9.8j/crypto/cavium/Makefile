#
# SSLeay/crypto/cast/Makefile
#

DIR=	cavium
APIDIR = ../../../../api
TOP=	../..
CC=	cc
CPP=	$(CC) -E
INCLUDES= -I$(APIDIR)
CFLAG=-g
INSTALL_PREFIX=
OPENSSLDIR=     /usr/local/ssl
INSTALLTOP=/usr/local/ssl
MAKE=		make -f Makefile.ssl
MAKEDEPEND=	$(TOP)/util/domd $(TOP)
MAKEFILE=	Makefile.ssl
AR=		ar r

CFLAGS= $(INCLUDES) $(CFLAG)

GENERAL=Makefile
APPS=


LIB=$(TOP)/libcrypto.a

ifeq ($(findstring CAVIUM_FIPS,$(CFLAG)),CAVIUM_FIPS) 
LIBSRC=luna_ssl.c luna_common.c cav_crypto_engine.c luna_private.c luna_api.c  
LIBOBJ=luna_ssl.o luna_common.o cav_crypto_engine.o luna_private.o luna_api.o $(CAVEO_ENC)
else
LIBSRC=cavium_ssl.c cavium_common.c cav_crypto_engine.c 
LIBOBJ=cavium_ssl.o cavium_common.o cav_crypto_engine.o $(CAVEO_ENC)
endif

SRC= $(LIBSRC)

EXHEADER= 

HEADER= $(EXHEADER)

ALL=    $(GENERAL) $(SRC) $(HEADER)

top:
	(cd ../..; $(MAKE) DIRS=crypto SDIRS=$(DIR) sub_all)

all:	lib

lib:	$(LIBOBJ)
	$(AR) $(LIB) $(LIBOBJ)
	$(RANLIB) $(LIB)
	@touch lib

files:
	$(PERL) $(TOP)/util/files.pl Makefile.ssl >> $(TOP)/MINFO

links:
	#@$(TOP)/util/point.sh Makefile.ssl Makefile
	@if test -f $(APIDIR)/luna_common.c; then \
	ln -fs  $(APIDIR)/luna_common.c luna_common.c ; \
	ln -fs  $(APIDIR)/luna_api.c luna_api.c ;\
	ln -fs  $(APIDIR)/luna_private.c luna_private.c; \
	ln -fs  $(APIDIR)/luna_ssl.c luna_ssl.c; \
	fi
	@if test -f $(APIDIR)/cavium_common.c; then \
	ln -fs  $(APIDIR)/cavium_common.c cavium_common.c ; \
	ln -fs  $(APIDIR)/cavium_ssl.c cavium_ssl.c;\
	fi
	@if test -f $(APIDIR)/cavium_ecc.c; then \
        ln -fs  $(APIDIR)/cavium_ecc.c cavium_ecc.c ; \
	fi
	@$(PERL) $(TOP)/util/mklink.pl ../../include/openssl $(EXHEADER)
	@$(PERL) $(TOP)/util/mklink.pl ../../test $(TEST)
	@$(PERL) $(TOP)/util/mklink.pl ../../apps $(APPS)

install:
	@for i in $(EXHEADER) ; \
	do  \
	(cp $$i $(INSTALL_PREFIX)$(INSTALLTOP)/include/openssl/$$i; \
	chmod 644 $(INSTALL_PREFIX)$(INSTALLTOP)/include/openssl/$$i ); \
	done;

tags:
	ctags $(SRC)

tests:

lint:
	lint -DLINT $(INCLUDES) $(SRC)>fluff

depend:
	$(MAKEDEPEND) $(INCLUDES) $(DEPFLAG) $(PROGS) $(LIBSRC)

dclean:
	$(PERL) -pe 'if (/^# DO NOT DELETE THIS LINE/) {print; exit(0);}' $(MAKEFILE) >Makefile.new
	mv -f Makefile.new $(MAKEFILE)

clean:
	rm -f asm/cx86unix.cpp *.o asm/*.o *.obj lib tags core .pure .nfs* *.old *.bak fluff

# DO NOT DELETE THIS LINE -- make depend depends on it.
