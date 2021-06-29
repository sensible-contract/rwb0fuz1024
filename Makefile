targets: rwtest

rabin.o: rabin.c api.h
	gcc -Wall -c rabin.c -std=c99 -O2

rwtest: rabin.o rwtest.c devurandom.c api.h
	gcc -o rwtest -Wall -L/usr/local/opt/openssl/lib/ -O2 rwtest.c devurandom.c rabin.o -lgmp -lcrypto
