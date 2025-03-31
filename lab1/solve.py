import sys
import itertools
import base64
import zlib
from pwn import *
from solpow import solve_pow

if len(sys.argv) > 1:
    ## for remote access
    r = remote('up.zoolab.org', 10155)
    solve_pow(r)
else:
    ## for local testing
    r = process('./guess.dist.py', shell=False)

def decode_msg(data):
    decoded = base64.b64decode(data) 
    mlen = int.from_bytes(decoded[:4], 'big')
    compressed_data = decoded[4:]
    return zlib.decompress(compressed_data).decode('utf-8')

def send_msg(r, number):
    compressed_number = zlib.compress(number.encode())
    mlen = len(compressed_number)
    request = base64.b64encode(mlen.to_bytes(4, 'little') + compressed_number).decode('utf-8')
    
    r.sendline(request.encode())

def guess_number(r):

    numbers = generate_numbers()
    
    for _ in range(10):
        guess = numbers[0]
        print(f"Guessing {guess}")
        send_msg(r, guess)

        response = r.recvline().strip()
        result = decode_msg(response)
        # print(result)

        msg = r.recvline().strip()
        msg = decode_msg(msg)
        print(msg)

        a_count, b_count = extract_A_B(result)
        # print(a_count, b_count)

        if a_count == 4:
            break

        msg = r.recvline().strip()
        msg = decode_msg(msg)
        print(msg)

        numbers = [num for num in numbers if check_feedback(num, guess, a_count, b_count)]

def check_feedback(candidate, guess, a_count, b_count):
    a = sum(1 for i in range(4) if candidate[i] == guess[i])
    b = sum(1 for i in range(4) if candidate[i] in guess) - a
    return (a, b) == (a_count, b_count)
    
def generate_numbers():
    return [''.join(p) for p in itertools.permutations('0123456789', 4)]

def extract_A_B(data):
    if isinstance(data, str):
        data = data.encode()

    parts = data.split(b'A')
    a_count = int.from_bytes(parts[0][-4:], 'big')

    parts = parts[1].split(b'B') 
    b_count = int.from_bytes(parts[0][-4:], 'big')
    
    return a_count, b_count

response = r.recvline().strip()
ans = decode_msg(response)
print(ans)
response = r.recvline().strip()
ans = decode_msg(response)
print(ans)

guess_number(r)
r.close()