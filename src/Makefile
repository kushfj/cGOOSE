all: goose_ping

goose_ping: goose_ping.c goose.o publisher.o subscriber.o
	gcc -Wall -g -O2 -I../include -o ../bin/goose_ping goose_ping.c goose.o utils.o publisher.o subscriber.o -lpcap -lpthread

goose.o: goose.c utils.o
	gcc -Wall -g -O2 -c goose.c -I../include -o goose.o 

publisher.o: publisher.c goose.o utils.o
	gcc -Wall -g -O2 -c publisher.c -I../include -o publisher.o

subscriber.o: subscriber.c goose.o 
	gcc -Wall -g -O2 -c subscriber.c -I../include -o subscriber.o

utils.o: utils.c
	gcc -Wall -g -O2 -c utils.c -I../include -o utils.o

clean:
	rm -f ../bin/goose_ping
	rm -f *.o
