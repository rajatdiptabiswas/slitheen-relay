CFLAGS=-g -ggdb -Wall -std=gnu99

TARGETS=slitheen-proxy

all: $(TARGETS)

slitheen-proxy.o flow.o rserv.o ptwist168.o crypto.o relay.o cryptothread.o util.o:: ptwist.h rserv.h flow.h slitheen.h crypto.h relay.h cryptothread.h util.h

rserv: rserv.o ptwist168.o
	gcc -g -ggdb -o $@ $^ -lssl -lcrypto

slitheen-proxy: slitheen-proxy.o flow.o rserv.o ptwist168.o crypto.o relay.o cryptothread.o util.o relay.h crypto.h ptwist.h rserv.h flow.h slitheen.h cryptothread.h
	gcc -g -ggdb -o $@ $^ -I/home/slitheen/Documents/include/openssl libssl.a libcrypto.a -lpcap -lpthread -ldl

clean:
	-rm *.o

veryclean: clean
	-rm $(TARGETS)

#DEPS=ptwist.h rserv.h flow.h slitheen.h 
#
#%.o: %.c $(DEPS)
#	gcc -g -Wall -std=c99 -c -o $@ $<

