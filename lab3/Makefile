TARGET := libgotoku.so

CC := gcc
CFLAGS := -std=gnu99 -Wall -Wextra -g -fpic
LDFLAGS := -pie -z now
LDLIBS := -lunwind -lunwind-$(shell uname -m)

all: libgotoku.so libsolver.so gotoku

libgotoku.so: libgotoku_dummy.c
	gcc -o libgotoku.so -shared -fPIC libgotoku_dummy.c -ldl

libsolver.so: libsolver.c
	gcc -o libsolver.so -shared -fPIC libsolver.c -ldl
	LD_LIBRARY_PATH=$(shell pwd)

gotoku: gops.c libsolver.so gotoku.c
	gcc -o gotoku -Wall -g libsolver.c gotoku.c

clean:
	rm -f libgotoku.so libsolver.so

