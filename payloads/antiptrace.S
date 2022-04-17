
; Source code from hex raw of 'srcs/build_decryptor.c'

mov rax, 157
mov rdi, 4
mov rsi, 0
mov rdx, 0
mov rcx, 0
mov r8, 0
syscall

mov rax, 101
mov rdi, 0
mov rsi, 0
mov rdx, 1
mov rcx, 0
syscall

cmp rax, -1
jne not_traced

mov rax, 60
mov rdi, 0
syscall

not_traced:
