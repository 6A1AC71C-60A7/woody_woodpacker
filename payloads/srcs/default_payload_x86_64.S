%include "libpayload.S"

section .text

global main:weak

main:
	push rdi
	push rsi
	push rdx
	push r8

	mov r8, `payload\n`
	push r8

	mov edi, STDOUT_FILENO
	mov rsi, rsp
	mov rdx, 8
	mov rax, SYS_WRITE
	syscall

	pop r8

	pop r8
	pop rdx
	pop rsi
	pop rdi

	ret
