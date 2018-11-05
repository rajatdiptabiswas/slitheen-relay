CFLAGS=-g -ggdb -Wall -std=gnu99

TARGETS=slitheen

all: $(TARGETS)

http.o webm.o packet.o flow.o ptwist168.o crypto.o relay.o cryptothread.o util.o:: ptwist.h flow.h packet.h crypto.h relay.h cryptothread.h util.h webm.h http.h

slitheen: slitheen.c packet.o flow.o ptwist168.o crypto.o relay.o cryptothread.o util.o webm.o http.o http.h webm.h relay.h crypto.h ptwist.h flow.h packet.h cryptothread.h util.h
	gcc -g -ggdb -o $@ $^ -L/usr/local/lib -I/usr/local/include -lssl -lcrypto -lpcap -lpthread -ldl

clean:
	-rm *.o

veryclean: clean
	-rm $(TARGETS)

