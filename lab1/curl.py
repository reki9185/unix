from pwn import *
r = remote('ipinfo.io', 80)
request = (
    "GET /ip HTTP/1.1\r\n"
    "Host: ipinfo.io\r\n"
    "User-Agent: pwntools\r\n"
    "Accept: */*\r\n"
    "Connection: close\r\n"
    "\r\n"
)

r.send(request.encode())
response = r.recvall().decode()
print(response)

r.close()