CFLAGS=-g -ggdb -Wall -std=gnu99 -DDEBUG_DOWN -DDEBUG_PROXY -DRESOURCE_DEBUG

TARGETS=slitheen-proxy

all: $(TARGETS)

slitheen-proxy.o flow.o ptwist168.o crypto.o relay.o cryptothread.o util.o:: ptwist.h flow.h slitheen.h crypto.h relay.h cryptothread.h util.h

slitheen-proxy: slitheen-proxy.o flow.o ptwist168.o crypto.o relay.o cryptothread.o util.o relay.h crypto.h ptwist.h flow.h slitheen.h cryptothread.h util.h
	gcc -g -ggdb -o $@ $^ -L/usr/local/lib -I/usr/local/include -lssl -lcrypto -lpcap -lpthread -ldl

clean:
	-rm *.o

veryclean: clean
	-rm $(TARGETS)

