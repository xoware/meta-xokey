PROG=sslperf
#CROSS_COMPILE?=arm-linux-
CC=${CROSS_COMPILE}gcc

##### Path to OpenSSL ######
SSL_PATH?=/usr/local/ssl

CFLAGS = -Wall -O3
CFLAGS += -DMC2
CFLAGS += -DCAVIUM_SSL

###### Engine support #######
ifneq ($(strip $(USE_CAVIUM_ENGINE)), )
CFLAGS += -DUSE_CAVIUM_ENGINE
endif

CFLAGS += -I$(SSL_PATH)/include
CFLAGS += -I../../include
LIBS = $(SSL_PATH)/lib/libssl.a
LIBS += $(SSL_PATH)/lib/libcrypto.a

OBJS = sslperf.o

$(PROG): $(OBJS)
	$(CC) -o $@ $(CFLAGS) $(OBJS) $(LIBS) 

.PHONY: clean
clean:
	rm -f $(OBJS) $(PROG)
