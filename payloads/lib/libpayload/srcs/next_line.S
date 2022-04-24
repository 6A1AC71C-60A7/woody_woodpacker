%include "libpayload.S"
%include "syscall.S"

%define rline r12
%define rfd r13
%define rbuffer r14
%define ris_empty r15b

section .text

global next_line

; line: rdi, rfd: esi, buffer: rdx, length: rcx -> rax ! rdx
next_line:
	push rline
	push rfd
	push rbuffer
	push r15					; Preserve callee-saved registers

	mov rline, rdi				; rline = rdi
	mov rfd, rsi				; rfd = esi
	mov rbuffer, rdx			; rbuffer = rdx

.next:
	mov al, `\n`				; c: al = '\n'

	test rcx, rcx
	setz ris_empty				; ris_empty = length == 0
	jz .read					; read if ris_empty

	repne scasb					; Search for newline
	je .found

	mov rsi, rline
	sub rsi, rbuffer
	neg rsi						; offset: rsi = -(line_end - buffer)

	mov rdx, SEEK_CURR
	mov rdi, rfd
	mov rax, SYS_LSEEK
	syscall						; lseek(rfd, offset, SEEK_CURR)

.read:
	mov rax, SYS_READ
	mov rdi, rfd
	mov rsi, rbuffer			; overwrite the previous read
	mov rdx, BUFFER_SIZE
	syscall						; length: rcx = read(rfd, rline, size)
	mov rcx, rax
	mov rline, rbuffer
	mov rdi, rline

	test ris_empty, ris_empty
	jz .next					; Search for newline if is_empty == 0

.found:
	mov rax, rcx

	pop r15
	pop rbuffer
	pop rfd
	pop rline					; Restore callee-saved registers
	ret
