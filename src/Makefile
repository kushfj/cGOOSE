CC = gcc

SRC = $(wildcard *.c)

OBJ = $(SRC:.c=.o)

LDFLAGS = -lpcap -lpthread 

pi-debug:	CC = arm-linux-gnueabi-gcc
pi-debug:	DIR = ../bin/raspberry-pi_debug
pi-debug:	LDFLAGS = -lpcap -lpthread -L/home/nkush/development/libpcap-1.8.1
pi-debug:	CFLAGS += -DNDEBUG -Wall -O3 -I../include -o $(DIR)/
pi-debug:	all

pi-release:	CC = arm-linux-gnueabi-gcc
pi-release:	DIR = ../bin/raspberry-pi_release
pi-release:	LDFLAGS = -lpcap -lpthread -L/home/nkush/development/libpcap-1.8.1
pi-release:	CFLAGS += -DNDEBUG -Wall -g3 -I../include -o $(DIR)/
pi-release:	all

debug:	DIR = ../bin/debug
debug:	CFLAGS += -DDEBUG -v -Wall -g3 -I../include -o $(DIR)/
debug:	all

release:	DIR = ../bin/release
release:	CFLAGS += -DNDEBUG -Wall -O3 -I../include -o $(DIR)/
release:	all

all: goose_ping

goose_ping: goose_ping.c goose.o publisher.o subscriber.o utils.o
	$(CC) $(CFLAGS)goose_ping goose_ping.c $(DIR)/goose.o $(DIR)/publisher.o $(DIR)/subscriber.o $(DIR)/utils.o $(LDFLAGS)

%.o: %.c
	$(CC) $(CFLAGS)$@ -c $< 

.PHONY: clean
clean:
	rm -f *.o
