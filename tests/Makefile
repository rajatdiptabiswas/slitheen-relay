CC=gcc
CFLAGS=-g -ggdb -Wall -std=gnu99

TARGETS=check_tagged

all: $(TARGETS)

check_tagged: check_tagged.c ../flow.c ../crypto.o ../relay.o ../cryptothread.o ../ptwist168.o ../packet.o ../util.o ../flow.h ../crypto.h ../relay.h ../cryptothread.h ../ptwist.h ../packet.h ../util.h
	gcc -g -ggdb -o $@ $^ -L/usr/local/lib -I/usr/local/include -lssl -lcrypto -ldl -lpthread -lpcap -lcheck_pic -lrt -lm -lsubunit

clean:
	-rm $(TARGETS)

