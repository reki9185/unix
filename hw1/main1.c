#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>
#include <stdint.h>

// fill the first 512 bytes with nop instructions
#define TRAMPOLINE_SIZE 512

void hello() {
    printf("Hello from trampoline!\n");
}

void setup_trampoline() {
    // allocate memory at virtual address 0
    void* mem = mmap((void *)0x0, 0x1000, PROT_READ | PROT_WRITE | PROT_EXEC,
        MAP_ANONYMOUS | MAP_PRIVATE | MAP_FIXED, -1, 0);
    
    if (mem == MAP_FAILED) {
        fprintf(stderr, "map failed\n");
		fprintf(stderr, "NOTE: /proc/sys/vm/mmap_min_addr should be set 0\n");
		exit(1);
    }

    for (int i = 0; i < TRAMPOLINE_SIZE; i++) {
        ((uint8_t *) mem)[i] = 0x90;
    }

    unsigned char *trampoline = (unsigned char*) mem + TRAMPOLINE_SIZE;
    uintptr_t func_addr = (uintptr_t)hello;

    printf("Setting up trampoline to call function at: %p\n", (void *)func_addr);

    // mov rax, func_addr
    trampoline[0] = 0x48;
    trampoline[1] = 0xB8;
    memcpy(&trampoline[2], &func_addr, sizeof(uintptr_t));

    // call rax
    trampoline[10] = 0xFF;
    trampoline[11] = 0xD0;

    // ret
    trampoline[12] = 0xC3;

}

__attribute__((constructor))
void init() {
    if (getenv("ZDEBUG")) {
        asm("int3");
    }
    setup_trampoline();
}