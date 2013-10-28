MC_TYPE = MC2
CIPHER = RC4   #AES or DES3 or RC4
DIGEST = MD5  #SHA1 or MD5
NB_TEST_DURATION = 2 
PKT_SIZES = 32 64 128 256 512 1024 1500 2048 4096 8192 16384 
RSA = RSA_CRT RSA_NOCRT MODEXP
MOD_LEN = 64 128 256
HANDSHAKE = RSASERVERFULL
OPENSSL?=../../apps/openssl-0.9.8i-bin/usr/local/ssl/
CFLAGS = -I../../include -I../../api/ -I${OPENSSL}/include -Wall -DSSL
LDFLAGS= -lcrypto -L${OPENSSL}/lib

CC=arm-linux-gcc

ifeq ($(strip $(MC_TYPE)),MC2)
CFLAGS += -DMC2
else
CFLAGS += -DMC1
endif
 
OBJS +=  speed_ssl.o
OBJS_NB += nb_app_perf.o

all:speed_ssl nbaperf

api.o: ../../api/cavium_common.c   
	$(CC) $(CFLAGS)  -c $^ -o $@
api_ssl.o: ../../api/cavium_ssl.c
	$(CC) $(CFLAGS)  -c $^ -o $@
speed_ssl: api.o	api_ssl.o	$(OBJS)
	$(CC) -o $@ $^ ${LDFLAGS}
nbaperf: api.o	api_ssl.o	$(OBJS_NB)
	$(CC) -o $@ $^ ${LDFLAGS}

run_record:
	@echo "Final SSL Record processing Speed Test Results ";
	@echo "Cipher: ${CIPHER}  Digest: ${DIGEST}";
	echo "===============================================================";
	echo "Pkt Size(in Bytes)     Operations/Sec      Throughput(in Mbps)";
	echo "===============================================================";
	for pktsize in ${PKT_SIZES}; do \
	./speed_ssl -l $$pktsize -c ${CIPHER} -d ${DIGEST}; \
	done
	echo "===============================================================";

run_crypto:
	@echo "Final SSL Crypto Processing Speed Test Results ";
	@echo "Algorithm: ${CIPHER}"; 
	echo "===============================================================";
	echo "Pkt Size(in Bytes)     Operations/Sec      Throughput(in Mbps)";
	echo "===============================================================";
	for pktsize in ${PKT_SIZES}; do \
	./speed_ssl -l $$pktsize -c ${CIPHER};\
	done
	echo "===============================================================";

run_rsa:
	@echo "Final RSA Operations Speed Test Results ";
	for rsatype in ${RSA}; do \
	echo ""; \
	echo "Algorithm: $$rsatype";  \
	echo "=========================================="; \
	echo "Modulus Size (in Bytes)     Operations/Sec"; \
	echo "=========================================="; \
	for modlen in ${MOD_LEN}; do \
	./speed_ssl -l 32 -p $$rsatype -m $$modlen;\
	done \
	done
	echo "===========================================";  

run_handshake:
	@echo "Final SSL RSA Handshake Operations Speed Test Results ";
	@echo "Algorithm: ${CIPHER}  Digest: ${DIGEST}"; 
	echo "=======================================";
	echo "Modulus Size(in Bytes)     Operations/Sec";
	echo "=======================================";
	for modlen in ${MOD_LEN}; do \
	./speed_ssl -l -c ${CIPHER} -d ${DIGEST} -n ${HANDSHAKE} -m $$modlen;\
	done
	echo "=======================================";

run_all: run_record run_crypto run_rsa run_handshake

run_nb_record:
	@echo "Final SSL Record processing Speed Test Results ";
	@echo "Cipher: ${CIPHER}  Digest: ${DIGEST}";
	echo "===============================================================";
	echo "Pkt Size(in Bytes)     Operations/Sec      Throughput(in Mbps)";
	echo "===============================================================";
	for pktsize in ${PKT_SIZES}; do \
	./nbaperf -l $$pktsize -c ${CIPHER} -d ${DIGEST} -t ${NB_TEST_DURATION};\
	done
	echo "===============================================================";

run_nb_crypto:
	@echo "Final SSL Crypto Processing Speed Test Results ";
	@echo "Algorithm: ${CIPHER}"; 
	echo "===============================================================";
	echo "Pkt Size(in Bytes)     Operations/Sec      Throughput(in Mbps)";
	echo "===============================================================";
	for pktsize in ${PKT_SIZES}; do \
	./nbaperf -l $$pktsize -c ${CIPHER} -t ${NB_TEST_DURATION};\
	done
	echo "===============================================================";

run_nb_rsa:
	@echo "Final RSA Operations Speed Test Results ";
	for rsatype in ${RSA}; do \
	echo ""; \
	echo "Algorithm: $$rsatype";  \
	echo "=========================================="; \
	echo "Modulus Size (in Bytes)     Operations/Sec"; \
	echo "=========================================="; \
	for modlen in ${MOD_LEN}; do \
	./nbaperf -l 32 -p $$rsatype -m $$modlen -t ${NB_TEST_DURATION};\
	done \
	done
	echo "===========================================";  

run_nb_handshake:
	@echo "Final SSL RSA Handshake Operations Speed Test Results ";
	@echo "Algorithm: ${CIPHER}  Digest: ${DIGEST}"; 
	echo "=======================================";
	echo "Modulus Size(in Bytes)     Operations/Sec";
	echo "=======================================";
	for modlen in ${MOD_LEN}; do \
	./nbaperf -m $$modlen -c ${CIPHER} -d ${DIGEST} -n ${HANDSHAKE} -t ${NB_TEST_DURATION};\
	done
	echo "=======================================";

run_nb_all: run_nb_record run_nb_crypto run_nb_rsa run_nb_handshake

all:all-speed-ssl

all-speed-ssl: nbaperf speed_ssl

clean: clean-speed-ssl

clean-speed-ssl:
	rm -f *.o *~ speed_ssl nbaperf
