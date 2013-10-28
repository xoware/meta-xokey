
OS := $(shell uname)
CC = cc
LDFLAG=
# For non-blocking 
OPENSSLDIR=../TurboSSL-0.9.8j
OPENSSLDIR_INCLUDE=${OPENSSLDIR}/include
OPENSSLDIR_LIB=${OPENSSLDIR}
CAVIUMDIR=../../include
CFLAGS=-g -I$(OPENSSLDIR_INCLUDE) -I$(CAVIUMDIR) -DCAVIUM_SSL  
#CFLAGS+= -DCAVIUM_MULTICARD_API 
#CFLAGS+= -DMC2
LD=-L$(OPENSSLDIR_LIB) -lssl -lcrypto


all: thin_server thin_client 

ifneq  ($(OS),FreeBSD)
LDFLAG += -ldl
endif


thin_server: thin_server.o 
	$(CC) $(CFLAGS) thin_server.o -o thin_server \
	$(OPENSSLDIR_LIB)/libssl.a \
	$(OPENSSLDIR_LIB)/libcrypto.a \
	$(LDFLAG)

thin_client: thin_client.o
	$(CC) $(CFLAGS) thin_client.o -o thin_client \
	$(OPENSSLDIR_LIB)/libssl.a \
	$(OPENSSLDIR_LIB)/libcrypto.a \
	$(LDFLAG)

clean:
	rm -rf *.o thin_server 
	rm -rf *.o thin_client 

