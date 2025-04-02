TARGET := libgotoku.so

CC := gcc
CFLAGS := -std=gnu99 -Wall -Wextra -g -fpic
LDFLAGS := -pie -z now
LDLIBS := -lunwind -lunwind-$(shell uname -m)

all: libgotoku.so libsolver.so libsolver_local.so gotoku.local

libgotoku.so: libgotoku_dummy.c
	gcc -o libgotoku.so -shared -fPIC libgotoku_dummy.c -ldl

libsolver.so: libsolver.c
	gcc -o libsolver.so -shared -fPIC libsolver.c -ldl

libsolver_local.so: libsolver.c
	gcc -DUSE_SERVER -o libsolver_local.so -shared -fPIC libsolver.c -ldl

gotoku.local: gotoku.c gops.c
	LD_LIBRARY_PATH=$(shell pwd)
	gcc -o gotoku.local gotoku.c -L. -lgotoku -ldl

run: gotoku.local
	LD_LIBRARY_PATH=. LD_PRELOAD=./libsolver_local.so ./gotoku.local

clean:
	rm -f libgotoku.so libsolver.so libsolver_local.so gotoku.local

# LD_LIBRARY_PATH=. LD_PRELOAD=./libsolver.so ./gotoku.local

