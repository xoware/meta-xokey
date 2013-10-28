BASEDIR= ../..
include $(BASEDIR)/platform
include $(BASEDIR)/Makefile.$(OS)
CFLAGS += -c -g -I$(BASEDIR)/include -I$(ARCH_INCLUDEDIR) -Wall

CFLAGS += $(ARCH_APPFLAGS) -DCNS3000

##### IPSec Editable Parameters
PKT_SIZES     = 64 128 256 512 768 1024 1400 1450 
IPSEC_PROCESS = OUTBOUND    # Or INBOUND
IPSEC_PROTO   = ESP         # Or AH
IPSEC_ALGO    = AES128      # Or AES192, AES256, DESCBC, DES3CBC
IPSEC_AUTH    = SHA1        # Or MD5 
IPSEC_MODE    = TUNNEL      # Or TRANSPORT
NB_TEST_DURATION = 2 

LDFLAGS = -o  

SRCS = 	cavium_common.c	\
		speed_ipsec.c	

OBJS = 	cavium_common.o	\
		speed_ipsec.o	

all:all-speed-ipsec

all-speed-ipsec: speedtest speedtest_nb 

cavium_common.o: ../../api/cavium_common.c
	$(CC) $(CFLAGS) ../../api/cavium_common.c

speedtest: $(OBJS) ../../api/cavium_common.o
	$(CC) $(LDFLAGS) speedtest speed_ipsec.o cavium_common.o

speedtest_nb: speed_ipsecnb.o ../../api/cavium_common.o
	$(CC) $(LDFLAGS) speedtest_nb speed_ipsecnb.o cavium_common.o

%.o : %.c
	$(CC) $(CFLAGS) $(DEFINES) -c $^ -o $@
.c.o:
	$(CC) $(CFLAGS) $(DEFINES) -c ${.IMPSRC}

clean: clean-speed-ipsec

clean-speed-ipsec:
	@rm -f *.o speedtest speedtest_nb

.PHONY: run run_nb
run: 
	if  [ ${IPSEC_PROCESS} == INBOUND ]; then \
		echo "Error!! Presently INBOUND IPSec Processing is not supported"; \
		exit -1; \
	fi
	@echo "Final IPSec Speed Test Results";
	@echo "-------------------------------------------";
	@echo "IPSec Protocol : ${IPSEC_PROTO}";
	@echo "-------------------------------------------";
	@echo "Packet size     Throughput in Mbps";
	@echo "-------------------------------------------";
	for pktsize in ${PKT_SIZES}; do \
		if [ ${IPSEC_PROTO} == ESP ]; then \
			./speedtest -l $$pktsize -i ${IPSEC_PROCESS} -t ${IPSEC_MODE} -p ${IPSEC_PROTO} -e ${IPSEC_ALGO} -a ${IPSEC_AUTH}; \
		elif [ ${IPSEC_PROTO} == AH ]; then \
			./speedtest -l $$pktsize -i ${IPSEC_PROCESS} -t ${IPSEC_MODE} -p ${IPSEC_PROTO} -a ${IPSEC_AUTH}; \
		fi \
	done
	@echo "-------------------------------------------";
	@echo "";

run_nb: 
	if  [ ${IPSEC_PROCESS} == INBOUND ]; then \
		echo "Error!! Presently INBOUND IPSec Processing is not supported"; \
		exit -1; \
	fi
	@echo "Final IPSec NonBlock Speed Test Results";
	@echo "-------------------------------------------";
	@echo "IPSec Protocol : ${IPSEC_PROTO}";
	@echo "-------------------------------------------";
	@echo "Packet size     Throughput in Mbps";
	@echo "-------------------------------------------";
	for pktsize in ${PKT_SIZES}; do \
		if [ ${IPSEC_PROTO} == ESP ]; then \
			./speedtest_nb -l $$pktsize -i ${IPSEC_PROCESS} -m ${IPSEC_MODE} -p ${IPSEC_PROTO} -e ${IPSEC_ALGO} -a ${IPSEC_AUTH} -t ${NB_TEST_DURATION}; \
		elif [ ${IPSEC_PROTO} == AH ]; then \
			./speedtest_nb -l $$pktsize -i ${IPSEC_PROCESS} -m ${IPSEC_MODE} -p ${IPSEC_PROTO} -a ${IPSEC_AUTH} -t ${NB_TEST_DURATION}; \
		fi \
	done
	@echo "-------------------------------------------";
	@echo "";
