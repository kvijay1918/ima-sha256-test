# Make the IMA LTP testsuite as standalone programs
#
CC = gcc
CFLAGS = -g -O2 -DDEBUG 
LIBS = -lcrypto -lssl
DESTDIR = /usr/local/vijay-sha256/

SRCS = ima_boot_aggregate.c ima_measure.c ima_mmap.c 

MEASURE_OBJECTS = ima_measure.c pkeys.c ima_sigv2.c rsa_oid.c
PROGS = $(patsubst %.c,%,$(SRCS))

all: $(PROGS) ima_measure

%: %.c
	$(CC) $(CFLAGS)  -o $@ $< $(LIBS) ltp-tst-replacement.c 

ima_measure: $(MEASURE_OBJECTS)
	$(CC) $(CFLAGS) -o $@ $(MEASURE_OBJECTS) $(LIBS) ltp-tst-replacement.c
	
install: 
	cp -t $(DESTDIR) $(PROGS)

clean:
	rm $(PROGS)
