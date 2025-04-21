; time function
global time
time:
    mov rax, 201
    syscall
    ret

; rand function
section .data
    seed dq 0

section .text
    global srand
    global grand
    global rand

srand:
    mov eax, edi
    sub rax, 1
    mov [rel seed], rax
    ret

grand:
    mov     rax, [rel seed]
    mov     eax, eax
    ret

rand:
    mov rax, [rel seed]
    mov rcx, 6364136223846793005
    mul rcx
    add rax, 1
    mov [rel seed], rax
    shr     rax, 33
    mov     eax, eax
    ret

; signal function
section .text
    global sigemptyset
    global sigfillset
    global sigaddset
    global sigdelset
    global sigismember
    global sigprocmask

sigemptyset:
    mov qword [rdi], 0
    ret

sigfillset:
    mov qword [rdi], 0xFFFFFFFFFFFFFFFF
    ret

sigaddset:
    ; ecx = signum - 1
    mov ecx, esi
    sub ecx, 1

    mov rax, 1
    shl rax, cl 
    or [rdi], rax

    xor eax, eax 
    ret

sigdelset:
    mov ecx, esi
    sub ecx, 1

    mov rax, 1
    shl rax, cl 
    not rax

    and [rdi], rax

    xor eax, eax 
    ret

sigismember:
    mov ecx, esi
    sub ecx, 1
    mov rax, [rdi]
    bt rax, rcx
    jc .sigismember_set
    mov eax, 0
    ret
.sigismember_set:
    mov eax, 1
    ret

sigprocmask:
    mov r10, 8
    mov eax, 14
    syscall
    ret

; jump function
section .text
    global setjmp
    global longjmp

setjmp:

    mov [rdi + 0], rbx
    mov [rdi + 8], rbp
    mov rax, rsp
    mov [rdi + 16], rax
    mov [rdi + 24], r12
    mov [rdi + 32], r13
    mov [rdi + 40], r14
    mov [rdi + 48], r15

    mov rax, [rsp]
    mov [rdi + 56], rax

    lea rdx, [rdi + 64]
    mov rdi, 0
    mov rsi, 0
    mov r10, 8
    call sigprocmask

    xor eax, eax
    ret

longjmp:
    push rsi
    push rdi
    lea rsi, [rdi + 64]
    mov rdi, 2
    xor rdx, rdx
    mov r10, 8
    call sigprocmask
    pop rdi
    pop rsi

    mov rbx, [rdi]
    mov rbp, [rdi + 8]
    mov rsp, [rdi + 16]
    mov r12, [rdi + 24]
    mov r13, [rdi + 32]
    mov r14, [rdi + 40]
    mov r15, [rdi + 48]

    ; check return value
    mov rax, rsi
    test rax, rax
    jne .ret
    mov rax, 1

.ret:
    jmp [rdi + 56]