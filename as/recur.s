mov rdi, 27
call r
jmp exit

r:
cmp rdi, 0
jle zero

cmp rdi, 1
je one

push rdi
dec rdi
call r

pop rdi
push rax

sub rdi, 2
call r
pop rbx

imul rbx, 2
imul rax, 3
add rax, rbx

ret

zero:
mov rax, 0
ret

one:
mov rax, 1
ret

exit:
done: