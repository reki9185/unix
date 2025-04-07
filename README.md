# NYCU 2024 Spring Advanced Programming in the UNIX Environment
[113-1] 高等Unix程式設計 (黃俊穎)
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
