; 26 = 2^4 + 2^3 + 2^1
mov eax, [0x7f2000]
shl eax, 4

mov ebx, [0x7f2000]
shl ebx, 3
add eax, ebx

mov ebx, [0x7f2000]
shl ebx, 1
add eax, ebx

mov [0x7f2004], eax

done: