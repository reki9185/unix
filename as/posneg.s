mov esi, 1
mov edi, -1

a:
cmp eax, 0
jge a_pos
jmp a_neg

a_pos:
mov [0x6d2000], esi
jmp b

a_neg:
mov [0x6d2000], edi

b:
cmp ebx, 0
jge b_pos
jmp b_neg

b_pos:
mov [0x6d2004], esi
jmp c

b_neg:
mov [0x6d2004], edi

c:
cmp ecx, 0
jge c_pos
jmp c_neg

c_pos:
mov [0x6d2008], esi
jmp d

c_neg:
mov [0x6d2008], edi

d:
cmp edx, 0
jge d_pos
jmp d_neg

d_pos:
mov [0x6d200c], esi
jmp end

d_neg:
mov [0x6d200c], edi

end:
done: