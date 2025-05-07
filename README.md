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

