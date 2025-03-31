mov ebx, 0x7e3000
mov esi, 2
mov edi, 0x0f
mov cx, ax

loop:
cmp edi, 0
jl end

; expand eax to edx for division
cdq
idiv esi

cmp edx, 0
je set_zero
jmp set_one

set_zero:
mov cl, 0x30
mov [ebx + edi], cl
dec edi
jmp loop

set_one:
mov cl, 0x31
mov [ebx + edi], cl
dec edi
jmp loop

end:
done: