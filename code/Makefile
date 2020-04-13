# Makefile for RSASecurID Implementation (Simplified)

CC = gcc
CFLAGS = -Wall -g -c
DEPS = securid.h

.PHONY: all
all: token authenticate

token: token.o securid.o
	$(CC) -Wall -g token.o securid.o -o token

authenticate: authenticate.o securid.o
	$(CC) -Wall -g authenticate.o securid.o -o authenticate

token.o: $(DEPS)
	gcc $(CFLAGS) token.c

authenticate.o: $(DEPS)
	gcc $(CFLAGS) authenticate.c

securid.o: $(DEPS)
	gcc $(CFLAGS) securid.c

.PHONY: clean
clean :
	rm -f token.o authenticate.o securid.o token authenticate