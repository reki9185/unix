CFLAGS := -pipe -g -Werror -Wall -Wextra -shared -fPIC

all: libzpoline.so.1 libzpoline.so.2 libex3hook.so libzpoline.so logger.so

libzpoline.so.1: main1.c
	gcc -o libzpoline.so.1 -g -shared -fPIC main1.c -ldl

libzpoline.so.2: main2.c
	gcc -o libzpoline.so.2 -g -shared -fPIC main2.c -ldl -lcapstone

libex3hook.so: libex3hook.c
	gcc -shared -march=x86-64 -fPIC -o libex3hook.so libex3hook.c

libzpoline.so: main3.c
	gcc -o libzpoline.so -g -march=x86-64 -shared -fPIC main3.c -ldl -lcapstone

logger.so: logger.c
	gcc -o logger.so -g -shared -fPIC logger.c -ldl -lcapstone

logger.so:

run:
	sudo sh -c "echo 0 > /proc/sys/vm/mmap_min_addr"
	LD_PRELOAD=./libzpoline.so.1 ./ex1
	LD_PRELOAD=./libzpoline.so.2 /usr/bin/echo 'uphw{7h15_15_4_51mpl3_fl46_fr0m_200l4b}'
	LD_PRELOAD=./libzpoline.so LIBZPHOOK=./libex3hook.so ./ex3
	LD_PRELOAD=./libzpoline.so LIBZPHOOK=./logger.so touch main.c
	LD_PRELOAD=./libzpoline.so LIBZPHOOK=./logger.so cat /etc/hosts
	LD_PRELOAD=./libzpoline.so LIBZPHOOK=./logger.so wget http://www.google.com -q -t 1
	LD_PRELOAD=./libzpoline.so LIBZPHOOK=./logger.so python3 -c 'import os; os.system("wget http://www.google.com -q -t 1")'

	LD_PRELOAD=./libzpoline.so LIBZPHOOK=./logger.so cp ex3 '[vsyscall]'
	LD_PRELOAD=./libzpoline.so LIBZPHOOK=./logger.so ./'[vsyscall]'
	LD_PRELOAD=./libzpoline.so LIBZPHOOK=./logger.so nc -lkU /tmp/hidden3.sock
	LD_PRELOAD=./libzpoline.so LIBZPHOOK=./logger.so nc -U /tmp/hidden3.sock
	LD_PRELOAD=./libzpoline.so LIBZPHOOK=./logger.so bash -c 'curl -s file:///etc/hosts'
	LD_PRELOAD=./libzpoline.so LIBZPHOOK=./logger.so python3 -c 'import os; os.system("python3 -c '\''import os; os.system(\"id\")'\''")'	

debug:
	gdb /lib64/ld-linux-x86-64.so.2
	(gdb) set environment ZDEBUG=1
	(gdb) r --preload ./libzpoline.so.2 /usr/bin/echo 'uphw{7h15_15_4_51mpl3_fl46_fr0m_200l4b}'
	(gdb) set environment LIBZPHOOK=./libex3hook.so
	(gdb) r --preload ./libzpoline.so ./ex3
	(gdb) p (char*)$rdi

clean:
	rm -f libzpoline.so.1
	rm -f libzpoline.so.2
	rm -f libzpoline.so
	rm -f libex3hook.so
	rm -f logger.so
