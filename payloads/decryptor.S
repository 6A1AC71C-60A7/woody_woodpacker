
; Source code from hex raw of 'srcs/build_decryptor.c'

pop rax

mov r9, 2
push rax
imul rax, r9
lea rdi, [rsp + rax * 8]
add rdi, 8
pop rax

xor r10, r10

decrypt_chunk:

pop r11
pop rsi

push rdi
push rsi
push rdx
push rax
push rcx
push r11
pushfq
mov rdi, rsi
mov rsi, r11
mov edx, 7
mov rax, 10
syscall
popfq
pop r11
pop rcx
pop rax
pop rdx
pop rsi
pop rdi

decrypt_term_msg:

push r10

xor r8, r8

decrypt_byte:

mov rdx, r8
and rdx, 7

mov r9b, BYTE PTR [rdi + rdx]

sub BYTE PTR [rsi + r8], r9b

push r9
push r11

mov cl, dl
mov r9b, BYTE PTR [rsi + r8]
shr r9b, cl

mov r12b, 8
sub r12b, dl
mov cl, r12b

mov r12b, BYTE PTR [rsi + r8]
shl r12b, cl

or r12b, r9b

pop r11
pop r9

mov BYTE PTR [rsi + r8], r12b

not BYTE PTR [rsi + r8]

xor BYTE PTR [rsi + r8], r9b

inc r8

cmp r8, r11
jb decrypt_byte

pop r10
inc r10

cmp r10, rax
jb decrypt_chunk

cmp r10, rax
jne end
inc r10
push r10
mov r10, 1
lea rsi, [rdi + r10 * 8]
pop r10
mov r11, 24
jmp decrypt_term_msg

end:
mov rax, 1
mov rdi, 1
mov rdx, 24
syscall

add rsp, 32
