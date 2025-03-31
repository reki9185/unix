add eax, 0x695000
mov edi, 0

loop1:
cmp edi, 10
jge end
mov esi, 0

loop2:
cmp esi, edi
jge next

mov ecx, edi
imul ecx, 4
mov ecx, [eax + ecx]

mov edx, esi
imul edx, 4
mov edx, [eax + edx]

cmp ecx, edx
jle swap
inc esi
jmp loop2

swap:
mov ebx, ecx
mov ecx, edi
imul ecx, 4
mov [eax + ecx], edx
mov edx, esi
imul edx, 4
mov [eax + edx], ebx
inc esi
jmp loop2

next:
inc edi
jmp loop1

end:
done: