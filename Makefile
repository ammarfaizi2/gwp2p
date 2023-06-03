
CC ?= cc
CFLAGS ?= -Wall -Wextra -ggdb3 -O2
LDFLAGS = -lpthread

all: gwp2p

gwp2p.o: gwp2p.c
	$(CC) $(CFLAGS) -c -o $@ $<

gwp2p: gwp2p.o
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

clean:
	rm -f gwp2p gwp2p.o

.PHONY: all clean
