CFLAGS=-g -O3 -Wall

TARGETS=genkeys

all: $(TARGETS)

genkeys.o ptwist168.o:: ptwist.h

genkeys: genkeys.o ptwist168.o
	gcc -g -o $@ $^ -lssl -lcrypto

clean:
	-rm *.o

veryclean: clean
	-rm $(TARGETS)
	-rm privkey pubkey
