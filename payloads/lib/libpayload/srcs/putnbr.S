%include "libpayload.S"

%define rfd r12
%define rlength r13

section .text

extern itoh

global putnbr

; fd: edi, number: rsi, delim: dl
putnbr:
	push rfd
	push rlength

	mov rfd, rdi

	mov rlength, 1					; rlength = 1
	mov r8, rsi						; tmp_number: r8 = number
	.numlen:
		inc rlength					; rlength += 1
		shr r8, 4					; tmp_number: r8 /= 16
		test r8, r8
	jnz .numlen						; loop while tmp_number != 0

	sub rsp, rlength				; buffer: rsp[rlength]

	mov rcx, rlength
	mov rdi, rsp
	call itoh						; itoh(buffer, number, delim, rlength)

	mov rdx, rlength
	mov rsi, rsp
	mov rdi, rfd
	mov rax, SYS_WRITE
	syscall							; write(rfd, buffer, rlength)

	add rsp, rlength

	pop rlength
	pop rfd

	ret
