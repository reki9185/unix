mov esi, 0
sub esi, 5
imul esi, [0x6d7000]

mov eax, 0
sub eax, [0x6d7004]
mov ebx, [0x6d7008]
cdq
idiv ebx

mov eax, esi
mov edi, edx
cdq
idiv edi

mov [0x6d700c], eax
done: