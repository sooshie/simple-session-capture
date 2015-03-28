CC=gcc
LD=gcc

#CFLAGS= -g -Wall -DDEBUG -D_GNU_SOURCE=1
CFLAGS= -Wall -D_GNU_SOURCE=1 -DUSE_AIO_

LDFLAGS=-lpthread -lpcap -lrt -lm
OBJS=hash.o ring_buffer.o filehashmap.o

all:  capture

*.c.*.o:
	$(CC) -c $(CFLAGS) $<

hash: $(OBJS) hash.o
	$(LD) -o $@ $(LDFLAGS) $^

capture: $(OBJS) capture.o
	$(LD) -o $@ $^ $(LDFLAGS)

filehashmap: $(OBJS) filehashmap.o
	$(LD) -o $@ $^ $(LDFLAGS)
clean:
	rm *.o capture



