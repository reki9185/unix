mov eax, 0x730000
mov ebx, 0x730010
mov edi, 0

loop:
cmp edi, 15
jge end

mov cl, [eax + edi]
mov dl, 97
cmp cl, dl
jge next
add cl, 32

next:
mov [ebx + edi], cl
inc edi
jmp loop

end:
done: