CC=gcc
CFLAGS=-g -ggdb -Wall -std=gnu99

TARGETS=check_tagged check_handshake test_webm test_tls test_http

INCLUDES=../flow.h ../crypto.h ../relay.h ../cryptothread.h ../ptwist.h ../packet.h ../util.h ../webm.h ../http.h

LINKS=-lssl -lcrypto -ldl -lpthread -lpcap -lcheck_pic -lrt -lm -lsubunit

all: $(TARGETS)

test_util.o: test_util.h

check_tagged: check_tagged.c test_util.o ../flow.c ../crypto.o ../relay.o ../cryptothread.o ../ptwist168.o ../packet.o ../util.o ../webm.o ../http.o $(INCLUDES)
	gcc -g -ggdb -o $@ $^ -L/usr/local/lib -I/usr/local/include $(LINKS)

check_handshake: check_handshake.c test_util.o ../flow.c ../crypto.o ../relay.o ../cryptothread.o ../ptwist168.o ../packet.o ../util.o ../webm.o ../http.o $(INCLUDES)
	gcc -g -ggdb -o $@ $^ -L/usr/local/lib -I/usr/local/include $(LINKS)

test_tls: test_tls.c test_util.o ../flow.c ../crypto.o ../relay.o ../cryptothread.o ../ptwist168.o ../packet.o ../util.o ../webm.o ../http.o $(INCLUDES)
	gcc -g -ggdb -o $@ $^ -L/usr/local/lib -I/usr/local/include $(LINKS)

test_webm: test_webm.c test_util.o ../flow.o ../crypto.o ../relay.o ../cryptothread.o ../ptwist168.o ../packet.o ../util.o ../http.o $(INCLUDES)
	gcc -g -ggdb -o $@ $^ -L/usr/local/lib -I/usr/local/include $(LINKS)

test_http: test_http.c test_util.o ../flow.o ../crypto.o ../relay.o ../cryptothread.o ../ptwist168.o ../packet.o ../util.o ../http.o $(INCLUDES)
	gcc -g -ggdb -o $@ $^ -L/usr/local/lib -I/usr/local/include $(LINKS)

clean:
	-rm $(TARGETS)

