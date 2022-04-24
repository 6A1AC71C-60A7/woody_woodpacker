%include "syscall.S"

section .text
global _start

_start:
	mov rax, SYS_PRCTL
	mov rdi, 4
	mov rsi, 0
	mov rdx, 0
	mov rcx, 0
	mov r8, 0
	syscall

	mov rax, SYS_PTRACE
	mov rdi, 0
	mov rsi, 0
	mov rdx, 1
	mov rcx, 0
	syscall

	cmp rax, -1
	jne not_traced

	mov rax, SYS_EXIT
	mov rdi, 0
	syscall

	not_traced:
