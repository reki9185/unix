#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>
#include <stdint.h>
#include <dlfcn.h>
#include <assert.h>
#include <capstone/capstone.h>

// fill the first 512 bytes with nop instructions
#define TRAMPOLINE_SIZE 512

typedef struct {
    char opr[32];
    char opnd[64];
    uint8_t bytes[16];
    size_t size;
} instruction;

void decode(char *buf) {
    int len = strlen(buf);
    for (int i = 0; i < len; i++) {
        switch(buf[i]) {
            case '0': 
                buf[i] = 'o'; break;
            case '1': 
                buf[i] = 'i'; break;
            case '2': 
                buf[i] = 'z'; break;
            case '3': 
                buf[i] = 'e'; break;
            case '4': 
                buf[i] = 'a'; break;
            case '5': 
                buf[i] = 's'; break;
            case '6': 
                buf[i] = 'g'; break;
            case '7': 
                buf[i] = 't'; break;
            default:
                break;
        }
    }
}

void trampoline_func() {
    asm volatile(
        "mov %r10, %rcx \n\t"
        "push %rax \n\t"
        "call handler \n\t"
        "add $8, %rsp \n\t"
        // "ret \n\t"
    );
}

extern void syscall_addr(void);
extern int64_t trigger_syscall(int64_t, int64_t, int64_t, int64_t, int64_t, int64_t, int64_t);
void __raw_asm() {
    asm volatile(
        "trigger_syscall: \t\n"
        "mov %rcx, %r10 \n\t"
        "mov 0x10(%rbp), %rax \n\t"
        ".globl syscall_addr \n\t"
	    "syscall_addr: \n\t"
        "syscall \n\t"
        "ret \n\t"
    );
}

int rewrite(char* from, size_t size, uintptr_t address) {

    size_t pagesize = sysconf(_SC_PAGESIZE);
    uintptr_t page_start = (uintptr_t)from & ~(pagesize - 1);
    size_t offset = (uintptr_t)from - page_start;
    size_t total_size = ((offset + size + pagesize - 1) / pagesize) * pagesize;

    mprotect((void *)page_start, total_size, PROT_READ | PROT_WRITE | PROT_EXEC);

    static csh cshandle = 0;
    if (cs_open(CS_ARCH_X86, CS_MODE_64, &cshandle) != CS_ERR_OK) return -1;

    cs_option(cshandle, CS_OPT_SKIPDATA, CS_OPT_ON);

    cs_insn *insn;
    int count = cs_disasm(cshandle, (uint8_t*) from, size, address, 0, &insn);

    if (count <= 0) {
        printf("count error: %d\n", count);
        return -1;
    }

    // printf("Disassembled %d instructions at 0x%lx\n", count, address);

    for (int i = 0; i < count; i++) {
        instruction in;
        in.size = insn[i].size;
        strncpy(in.opr, insn[i].mnemonic, sizeof(in.opr));
        strncpy(in.opnd, insn[i].op_str, sizeof(in.opnd));
        memcpy(in.bytes, insn[i].bytes, insn[i].size);

        uint8_t patch[] = {  0xFF, 0xD0 }; 

        // check if syscall
        if (in.size == 2 && in.bytes[0] == 0x0F && in.bytes[1] == 0x05 && (strcmp(insn[i].mnemonic, "syscall") == 0)) {

            if ((uintptr_t) insn[i].address == (uintptr_t)syscall_addr) {
                // printf("Real system call: %s %s\n", in.opr, in.opnd);
                continue;
            }

            // replace to call %rax
            memcpy((void *)insn[i].address, patch, 2);
        }
    }

    cs_free(insn, count);
    cs_close(&cshandle);
}

void find() {
    FILE *fp;
	assert((fp = fopen("/proc/self/maps", "r")) != NULL);
    char buf[4096];
    while (fgets(buf, sizeof(buf), fp) != NULL) {
        // do not touch stack and vsyscall memory
        if (((strstr(buf, "[stack]\n") == NULL) && (strstr(buf, "[vsyscall]\n") == NULL))) {
            int i = 0;
            char addr[65] = { 0 };
            char *c = strtok(buf, " ");
            while (c != NULL) {
                switch (i) {
                case 0:
                    strncpy(addr, c, sizeof(addr) - 1);
                    break;
                case 1:
                    int mem_prot = 0;
                    size_t j;
                    for (j = 0; j < strlen(c); j++) {
                        if (c[j] == 'r')
                            mem_prot |= PROT_READ;
                        if (c[j] == 'w')
                            mem_prot |= PROT_WRITE;
                        if (c[j] == 'x')
                            mem_prot |= PROT_EXEC;
                    }
                    /* rewrite code if the memory is executable */
                    if (mem_prot & PROT_EXEC) {
                        size_t k;
                        for (k = 0; k < strlen(addr); k++) {
                            if (addr[k] == '-') {
                                addr[k] = '\0';
                                break;
                            }
                        }

                        int64_t from, to;
                        from = strtol(&addr[0], NULL, 16);
                        if (from == 0) {
                            /*
                                * this is trampoline code.
                                * so skip it.
                                */
                            break;
                        }
                        to = strtol(&addr[k + 1], NULL, 16);
                        rewrite((char *) from, (size_t) to - from, (uint64_t)from);
                    }
                break;
                }
                if (i == 1) break;
                c = strtok(NULL, " ");
                i++;
            }
        }
    }
	fclose(fp);
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
    uintptr_t func_addr = (uintptr_t)&trampoline_func;

    printf("Setting up trampoline to call function at: %p\n", (void *)func_addr);

    // mov r11, func_addr
    trampoline[0] = 0x49;
    trampoline[1] = 0xBB; // b *0x200 si
    memcpy(&trampoline[2], &func_addr, 8);

    // call r11
    trampoline[10] = 0x41;
    trampoline[11] = 0xFF;
    trampoline[12] = 0xD3;

    // ret
    trampoline[13] = 0xC3;

    find();
}

int64_t handler(int64_t rdi, int64_t rsi, int64_t rdx, int64_t rcx, int64_t r8, int64_t r9, int64_t rax) {
    if (rdi == 1 && rax == 1) {
        decode((char*)rsi);
    }
    return trigger_syscall(rdi, rsi, rdx, rcx, r8, r9, rax);
}

__attribute__((constructor))
void init() {
    if (getenv("ZDEBUG")) {
        asm("int3");
    }
    setup_trampoline();
    // find();
}