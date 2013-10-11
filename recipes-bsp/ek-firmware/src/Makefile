
CC ?= gcc

CFLAGS ?= -Wall -g -pipe

objs = md5.o

xomkimage: $(objs) xomkimage.c
	$(CC) $(CFLAGS) -o $@ $^

.c.o:
	$(CC) $(CFLAGS) -c $<

.PHONY: clean
clean:
	rm -f $(objs) mkimage
	
