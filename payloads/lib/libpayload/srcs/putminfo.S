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

	mov rsi, [rsminfo + map_start]
	mov dl, '-'
	call putnbr						; putnbr(rsminfo.map_start, '-')

	mov rsi, [rsminfo + map_end]
	mov dl, ' '
	call putnbr						; putnbr(rsminfo.map_end, ' ')

	mov rsi, [rsminfo + vaddr]
	mov dl, ' '
	call putnbr						; putnbr(rsminfo.vaddr, ' ')

	xor rsi, rsi
	mov sil, [rsminfo + protection]
	mov dl, `\n`
	call putnbr						; putnbr(rsminfo.vaddr, ' ')

	pop rsminfo						; Restore rsminfo
	pop rfd							; Restore rfd
	pop rcx							; Restore rcx

	ret
