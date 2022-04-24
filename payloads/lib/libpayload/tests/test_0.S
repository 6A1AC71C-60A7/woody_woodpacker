%include "libpayload.S"

section .data
filepath: db "/proc/self/maps", 0

section .text

extern next_line
extern htoi
extern putnbr
extern ptoi
extern itop

global _start

_start:
	push r12

    mov rax, SYS_OPEN
    mov rdi, filepath
    mov rsi, 0
    syscall

	mov r12d, eax

	sub rsp, BUFFER_SIZE

	xor rcx, rcx
	mov rdx, rsp
	mov rdi, rdx
	mov esi, r12d
	call next_line

	push rdi
	push rcx
	mov rax, SYS_WRITE
	mov rsi, rdi
	mov edi, STDOUT_FILENO
	mov rdx, rcx
	syscall
	pop rcx
	pop rdi

	mov sil, '-'
	call htoi

	push rdi
	push rcx
	mov edi, STDOUT_FILENO
	mov rsi, rax
	mov dl, '-'
	call putnbr
	pop rcx
	pop rdi

	mov sil, ' '
	call htoi

	push rdi
	push rcx
	mov edi, STDOUT_FILENO
	mov rsi, rax
	mov dl, ' '
	call putnbr
	pop rcx
	pop rdi

	call ptoi


	push rdi
	push rcx
	mov edi, STDOUT_FILENO
	mov rsi, rax
	mov dl, ' '
	call putnbr
	pop rcx
	pop rdi

	push rdi
	push rcx
	sub rsp, 4
	mov rdi, rsp
	call itop

	mov rax, SYS_WRITE
	mov rdi, STDOUT_FILENO
	mov rsi, rsp
	mov rdx, 4
	syscall

	add rsp, 4
	pop rdi
	pop rcx

	add rsp, BUFFER_SIZE

	mov edi, r12d
	mov rax, SYS_CLOSE
	syscall

	pop r12

    mov edi, eax
    mov rax, SYS_EXIT
    syscall
