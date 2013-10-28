BASEDIR= ..


include $(BASEDIR)/platform
include $(BASEDIR)/Makefile.$(OS)

# Using octeon SDK currently
#CC=mips64-octeon-linux-gnu-gcc

#KEYMODE=NORMAL_MOD_EX
KEYMODE=CRT_MOD_EX

BINARIES=$(CSP1_BIN) $(DBG_BIN) $(RND_BIN) $(N1OP_BIN)  

BINARIES += $(RC4_BIN)  $(DES_BIN)  #$(ECC_BIN) $(TEST_ECC_BIN)  $(ECC_NB_BIN)

# Do 'make utils' for all utilities.
utils: $(BINARIES) 

all-utils-Linux: utils 
 
clean-utils-Linux: 
	rm -f $(BINARIES) *~


$(CSP1_BIN): nitrox_init.c 
		$(CC) -g -Wall $(DRIVER_DEFINES) $(ARCH_APPFLAGS) -I$(ARCH_INCLUDEDIR) -I$(BASEDIR)/include \
		-O nitrox_init.c ../api/cavium_common.c -o $(CSP1_BIN) 

$(RC4_BIN): n1test_rc4.c 
	$(CC)  $(ARCH_APPFLAGS) -I$(ARCH_INCLUDEDIR) -I$(BASEDIR)/include \
		-O n1test_rc4.c n1test_common.c ../api/cavium_common.c -o $(RC4_BIN)

$(DES_BIN): n1test_3des.c
	    $(CC)  $(ARCH_APPFLAGS) -I$(ARCH_INCLUDEDIR) -I$(BASEDIR)/include \
		-O n1test_3des.c n1test_common.c ../api/cavium_common.c -o $(DES_BIN)

$(RND_BIN): n1test_rnd.c
	    $(CC)  $(ARCH_APPFLAGS) -I$(ARCH_INCLUDEDIR) -I$(BASEDIR)/include \
		-O n1test_rnd.c n1test_common.c ../api/cavium_common.c -o $(RND_BIN)

$(DBG_BIN): pkpdbg.c
		$(CC) $(ARCH_APPFLAGS) -I$(ARCH_INCLUDEDIR) -I$(BASEDIR)/include \
		-O pkpdbg.c -o $(DBG_BIN)

$(N1OP_BIN): n1op.c n1op_data.h
	    $(CC) $(ARCH_APPFLAGS) -I$(ARCH_INCLUDEDIR) -I$(BASEDIR)/include \
		-O n1op.c n1test_common.c ../api/cavium_common.c -o $(N1OP_BIN) -DKEY_MODE=$(KEYMODE) -g

$(ECC_BIN): n1test_ecc.c ../api/cavium_ecc.c ../api/cavium_ecrng.c 
	    $(CC)  $(ARCH_APPFLAGS) -I$(ARCH_INCLUDEDIR) -I$(BASEDIR)/include \
		-O n1test_ecc.c n1test_common.c ../api/cavium_ecc.c ../api/cavium_ecrng.c ../api/cavium_common.c -o $(ECC_BIN) -lssl

$(ECC_NB_BIN): n1test_ecc_nb.c ../api/cavium_ecc.c ../api/cavium_ecrng.c
	$(CC)  $(ARCH_APPFLAGS) -I$(ARCH_INCLUDEDIR) -I$(BASEDIR)/include \
	-O n1test_ecc_nb.c n1test_common.c ../api/cavium_ecc.c ../api/cavium_ecrng.c ../api/cavium_common.c -o $(ECC_NB_BIN) -lssl

$(TEST_ECC_BIN): testecc.c ../api/cavium_ecc.c ../api/cavium_ecrng.c 
	    $(CC)  $(ARCH_APPFLAGS) -I$(ARCH_INCLUDEDIR) -I$(BASEDIR)/include \
		-O testecc.c n1test_common.c ../api/cavium_ecc.c ../api/cavium_ecrng.c ../api/cavium_common.c -o $(TEST_ECC_BIN) -lssl


#
# $Id: utils-Linux.mk,v 1.4 2009/09/18 07:16:33 aravikumar Exp $
# $Log: utils-Linux.mk,v $
# Revision 1.4  2009/09/18 07:16:33  aravikumar
# commented ECC files
#
# Revision 1.3  2009/09/09 14:54:40  aravikumar
# NPLUS macro dependency removed and made it dynamic
#
# Revision 1.2  2009/07/22 11:36:32  pnalla
# building test_rc4 and test_3des in ssl and plus modes only.
#
# Revision 1.1  2008/12/16 12:09:31  jsrikanth
# Makefile for Linux
#
# Revision 1.18  2008/11/26 07:35:48  ysandeep
# n1test_ecc.c n1test_ecc_nb.c testecc.c made to compile if mlm is ssl or in NPLUS
#
# Revision 1.17  2008/11/26 07:12:35  ysandeep
# made nplus_init.c to compile in NPLUS mode only
#
# Revision 1.16  2008/07/03 10:19:35  aramesh
# compiled mcode_liks.c  with proper dependents.
#
# Revision 1.14  2008/02/22 10:48:08  aramesh
# APP_DEFINES flags is deleted.
#
# Revision 1.13  2008/01/21 09:40:54  aramesh
# Added changes related to non-blocking support for ECC-API
#
# Revision 1.12  2007/12/03 06:19:24  ksadasivuni
# - ecrng random int inital checkin
#
# Revision 1.11  2007/11/21 07:07:33  ksadasivuni
# all driver load messages now will be printed at CAVIUM_DEBUG_LEVEL>0
#
# Revision 1.10  2007/07/31 10:11:08  tghoriparti
# N1 related changes done
#
# Revision 1.9  2007/07/11 08:26:40  tghoriparti
# clean is updated to clean pots
#
# Revision 1.8  2007/07/06 13:05:36  tghoriparti
# compilation for pots added
#
# Revision 1.7  2007/06/11 14:30:41  tghoriparti
# APP_DEFINES added to gcc flags
#
# Revision 1.6  2007/05/01 05:59:06  kchunduri
# * moved definition of few flags to Makefile.$(OS).
#
# Revision 1.5  2007/04/05 03:11:06  panicker
# * Makefile corrections before CN1600 pre-release - NPLUS needs to be compiled only if NPLUS is defined.
#
# Revision 1.4  2007/03/08 20:44:19  panicker
# * NPLUS mode changes. pre-release
# * NitroxPX now supports N1-style NPLUS operation.
#
# Revision 1.3  2007/03/06 19:46:05  panicker
# * cleanup
# * n1test_common.c required for some utilities
#
# Revision 1.2  2007/02/21 04:21:20  panicker
# Modified makefile for pre-release
#
# Revision 1.1  2007/02/20 23:43:29  panicker
# * Utilities checked in
#
# Revision 1.8  2005/01/18 01:42:48  tsingh
# Removed dependency of readline and termcap (bimran)
#
# Revision 1.7  2004/08/03 20:45:05  tahuja
# support for Mips Linux.
#
# Revision 1.6  2004/07/07 18:02:24  tsingh
# compilation issues
#
# Revision 1.5  2004/06/28 21:27:15  tahuja
# OSI Makefiles.
#
# Revision 1.4  2004/04/23 21:56:40  bimran
# POts is now built only for non-PLUS parts.
#
# Revision 1.3  2004/04/22 02:50:33  bimran
# changed program name from nplus_init to init_nplus.
#
# Revision 1.2  2004/04/22 01:07:11  bimran
# Added support for NPLUS utilities.
#
# Revision 1.1  2004/04/15 22:40:51  bimran
# Checkin of the code from India with some cleanups.
#
#

