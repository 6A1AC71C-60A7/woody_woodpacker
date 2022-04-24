%include "libpayload.S"

section .data
filepath: db "/proc/self/maps", 0

section .text

extern next_line
extern htoi
extern putnbr
extern ptoi
extern itop
extern minfo
extern putminfo

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

;	push rdi
;	push rcx
;	mov rax, SYS_WRITE
;	mov rsi, rdi
;	mov edi, STDOUT_FILENO
;	mov rdx, rcx
;	syscall
;	pop rcx
;	pop rdi

	push rdi
	sub rsp, sminfo_size

	mov rsi, rsp
	call minfo

	mov edi, STDOUT_FILENO
	mov rsi, rsp
	call putminfo

	add rsp, sminfo_size
	pop rdi

	mov rdx, rsp
	mov esi, r12d
	call next_line

;	push rdi
;	push rcx
;	mov rax, SYS_WRITE
;	mov rsi, rdi
;	mov edi, STDOUT_FILENO
;	mov rdx, rcx
;	syscall
;	pop rcx
;	pop rdi

	push rdi
	sub rsp, sminfo_size

	mov rsi, rsp
	call minfo

	mov edi, STDOUT_FILENO
	mov rsi, rsp
	call putminfo

	add rsp, sminfo_size
	pop rdi

	add rsp, BUFFER_SIZE

	mov edi, r12d
	mov rax, SYS_CLOSE
	syscall

	pop r12

    mov edi, eax
    mov rax, SYS_EXIT
    syscall
