CC=gcc
CFLAGS=-g -ggdb -Wall -std=gnu99

TARGETS=check_tagged check_handshake test_webm test_partial_aes

all: $(TARGETS)

test_util.o: test_util.h

check_tagged: check_tagged.c test_util.o ../flow.c ../crypto.o ../relay.o ../cryptothread.o ../ptwist168.o ../packet.o ../util.o ../flow.h ../crypto.h ../relay.h ../cryptothread.h ../ptwist.h ../packet.h ../util.h
	gcc -g -ggdb -o $@ $^ -L/usr/local/lib -I/usr/local/include -lssl -lcrypto -ldl -lpthread -lpcap -lcheck_pic -lrt -lm -lsubunit

check_handshake: check_handshake.c test_util.o ../flow.c ../crypto.o ../relay.o ../cryptothread.o ../ptwist168.o ../packet.o ../util.o ../flow.h ../crypto.h ../relay.h ../cryptothread.h ../ptwist.h ../packet.h ../util.h
	gcc -g -ggdb -o $@ $^ -L/usr/local/lib -I/usr/local/include -lssl -lcrypto -ldl -lpthread -lpcap -lcheck_pic -lrt -lm -lsubunit

test_partial_aes: test_partial_aes.c test_util.o ../flow.c ../crypto.o ../relay.o ../cryptothread.o ../ptwist168.o ../packet.o ../util.o ../flow.h ../crypto.h ../relay.h ../cryptothread.h ../ptwist.h ../packet.h ../util.h
	gcc -g -ggdb -o $@ $^ -L/usr/local/lib -I/usr/local/include -lssl -lcrypto -ldl -lpthread -lpcap -lcheck_pic -lrt -lm -lsubunit

test_webm: test_webm.c test_util.o ../flow.o ../crypto.o ../relay.o ../cryptothread.o ../ptwist168.o ../packet.o ../util.o ../flow.h ../crypto.h ../relay.h ../cryptothread.h ../ptwist.h ../packet.h ../util.h
	gcc -g -ggdb -o $@ $^ -L/usr/local/lib -I/usr/local/include -lssl -lcrypto -ldl -lpthread -lpcap -lcheck_pic -lrt -lm -lsubunit

clean:
	-rm $(TARGETS)

