# NYCU 2024 Spring Advanced Programming in the UNIX Environment
[113-2] 高等Unix程式設計 (黃俊穎)
### Lab1: docker & pwntools
Write a game solver to interact with the challenge server and decode/display the messages received from the server.

challenge server: `nc up.zoolab.org 10155`

### Lab2: Encrypt and Decrypt Data Using a Kernel Module
Implement a kernel module that performs encryption and decryption operations using the Linux Kernel API.
1. The kernel module performs AES encryption and only supports the ECB mode, allowing each block to be processed independently.
The encryption and decryption operations can be configured using the ioctl interface:
- Encryption mode: The user program writes plaintext to the device as input and reads the corresponding ciphertext as output.
- Decryption mode: The user program writes ciphertext to the device as input and reads the corresponding plaintext as output.

2. The **write** interface allows the device to receive user input and process it based on CM_IOC_SETUP.
3. The **read** operation allows users to retrieve data processed by the module.
4. The I/O behavior depends on the ioctl configuration, with two available modes:
- I/O Mode BASIC: All output data is buffered within the kernel module and cannot be accessed through read until CM_IOC_FINALIZE is called.
- I/O Mode ADV: Data is encrypted or decrypted incrementally. A full block of processed data becomes available for read only after enough input has been received to complete a block.

5. The ioctl interface:
- CM_IOC_SETUP
- CM_IOC_FINALIZE
- CM_IOC_CLEANUP
- CM_IOC_CNT_RST

### Lab3: GOTOKU Challenge
This lab aims to play with LD_PRELOAD and GOT table and ask the challenge server to solve the sudoku puzzle.

challenge server: `nc up.zoolab.org 58164`

### Lab4: Assembly Language Practice
Implement the required functions:
- time
- srand, grand, rand
- sigemptyset, sigfillset, sigaddset, sigdelset, sigismember
- sigprocmask
- sigsetjmp, siglongjmp

### Lab5: Let’s Race Together
This lab aims to investigate possible race or reentrant errors from multithreaded programs.
- Challenge 1: unixfortune.c
- Challenge 2: flagsrv.cpp
- Challenge 3: insecureweb.c

### Hw1: System Call Hook and Logging
The system call hooking mechanism is inspired by [zpoline](<https://github.com/yasukata/zpoline>), which won the Best Paper award at USENIX ATC 2023.

`libzpoline.so` is a shared library that hooks Linux system calls by rewriting `syscall` instructions in user space. 
It redirects execution through a trampoline placed at memory address `0x0`, allowing custom logic (e.g., logging, filtering, modifying behavior) to be executed before invoking the real system call.

**Features**

- Replaces `syscall` instructions with `call *%rax`.
- Trampoline at `0x0` redirects execution to a C `handler()` function.
- Compatible with dynamically linked binaries.
- Supports loading external hook logic via `LIBZPHOOK`.

**Usage**

`LD_PRELOAD=./libzpoline.so LIBZPHOOK=./logger.so command [arg1 arg2 ...]`

### Hw2: Simple Instruction Level Debugger
In this homework, you have to implement a simple instruction-level debugger that allows a user to debug a program interactively at the assembly instruction level.

**Features**

- Load Program
  
  `load [path to a program]`
  ```
  (sdb) load ./hello
  ** program './hello' loaded. entry point: 0x401620.
        401620: f3 0f 1e fa                      endbr64
        401624: 31 ed                            xor       ebp, ebp
        401626: 49 89 d1                         mov       r9, rdx
        401629: 5e                               pop       rsi
        40162a: 48 89 e2                         mov       rdx, rsp
  ```
- Disassemble: When returning from execution, the debugger should disassemble 5 instructions starting from the current program counter (instruction pointer). 
- Step Instruction
  
  `si`
  ```
  (sdb) si
      401040: 0f 05                             syscall
  ** the address is out of the range of the text section.
  (sdb) si
  ** the target program terminated.
  ```
- Continue
  
  `cont`
  ```
  (sdb) break 0x40100d
  ** set a breakpoint at 0x40100d.
  (sdb) cont
  ** hit a breakpoint at 0x40100d.
        40100d: 48 8d 05 ec 0f 00 00              lea       rax, [rip + 0xfec]
        401014: 48 89 c6                          mov       rsi, rax
        401017: bf 01 00 00 00                    mov       edi, 1
        40101c: e8 0a 00 00 00                    call      0x40102b
        401021: bf 00 00 00 00                    mov       edi, 0
  (sdb) cont
  hello world!
  ** the target program terminated.
  ```
- Info Registers
  
  `info reg`
  ```
  (sdb) info reg
  $rax 0x0000000000000001    $rbx 0x0000000000000000    $rcx 0x0000000000000000
  $rdx 0x000000000000000e    $rsi 0x0000000000402000    $rdi 0x0000000000000001
  $rbp 0x00007ffdc479ab68    $rsp 0x00007ffdc479ab60    $r8  0x0000000000000000
  $r9  0x0000000000000000    $r10 0x0000000000000000    $r11 0x0000000000000000
  $r12 0x0000000000000000    $r13 0x0000000000000000    $r14 0x0000000000000000
  $r15 0x0000000000000000    $rip 0x0000000000401030    $eflags 0x0000000000000202
  ```
- Breakpoint
  
  `break [hex address] | b [hexaddress]`
  ```
  (sdb) break 0x401005
  ** set a breakpoint at 0x401005.
  ```
- Break at Offset of Target Binary
  
  `breakrva [hex offset]`
  ```
  (sdb) breakrva 11C3
  ** set a breakpoint at 0x60e3bc9321c3.
  ```
- Info Breakpoints
  
  `info break`
  ```
  (sdb) info break
  Num     Address
  0       0x4000ba
  1       0x4000bf
  ```
- Delete Breakpoints
  
  `delete [id]`
  ```
  (sdb) delete 0
  ** delete breakpoint 0.
  ```
- Patch Memory
  
  `patch [hex address] [hex string]`
- System Call
  
  `syscall`
  ```
  (sdb) syscall
  ** enter a syscall(1) at 0x401030.
        401030: 0f 05                           	syscall   
        401032: c3                              	ret       
        401033: b8 00 00 00 00                  	mov       eax, 0
        401038: 0f 05                           	syscall   
        40103a: c3                              	ret       
  (sdb) syscall
  hello world!
  ** leave a syscall(1) = 14 at 0x401030.
        401030: 0f 05                           	syscall   
        401032: c3                              	ret       
        401033: b8 00 00 00 00                  	mov       eax, 0
        401038: 0f 05                           	syscall   
        40103a: c3                              	ret 
  ```
- Exit
  
  `exit`
  
**Usage**

```
./sdb
./sdb [program]
```
