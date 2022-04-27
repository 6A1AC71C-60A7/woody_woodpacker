%include "libpayload.S"

%define rfd r12
%define rsminfo r13

section .text

extern putnbr

global putminfo

; fd: edi, sminfo: rsi
putminfo:
	push rcx						; Preserve rcx
	push rfd						; Preserve rfd
	push rsminfo					; Preserve rsminfo

	mov rfd, rdi					; rfd = fd
	mov rsminfo, rsi				; rsminfo = sminfo

	mov rsi, [rsminfo + sminfo.start]
	mov dl, '-'
	call putnbr						; putnbr(rsminfo.start, '-')

	mov rsi, [rsminfo + sminfo.end]
	mov dl, ' '
	call putnbr						; putnbr(rsminfo.end, ' ')

	mov rsi, [rsminfo + sminfo.vaddr]
	mov dl, ' '
	call putnbr						; putnbr(rsminfo.vaddr, ' ')

	xor rsi, rsi
	mov sil, [rsminfo + sminfo.prot]
	mov dl, `\n`
	call putnbr						; putnbr(rsminfo.vaddr, ' ')

	pop rsminfo						; Restore rsminfo
	pop rfd							; Restore rfd
	pop rcx							; Restore rcx

	ret
