%include "libpayload.S"

%define rminfo r12
%define rvaddr r13
%define rfilter r14

section .text

extern next_line
extern minfo

extern putnbr
extern putminfo

global mfind

; line: rdi, fd: esi, buffer: rdx, length: rcx, sminfo: r8, vaddr: r9, prot_filter: r10b
mfind:
	push rminfo
	push rvaddr
	push rfilter

	mov rminfo, r8
	mov rvaddr, r9
	mov r14b, r10b

	cmp rvaddr, 0x400000
	jl .next
	sub rvaddr, 0x400000

.next:
; registers to preserve: line: rdi, fd: esi, buffer: rdx, length: rcx
;	push rdi
;	push rsi
;	push rdx
;	push rcx
;
;	mov rdi, STDOUT_FILENO
;	mov rsi, rvaddr
;	mov dl, `\n`
;	call putnbr
;
;	pop rcx
;	pop rdx
;	pop rsi
;	pop rdi
	call next_line						; next_line(line: rdi, fd: esi, buffer: rdx, length: rcx)

	push rdi							; Preserve line
	push rsi							; Preserve fd
	push rdx							; Preserve buffer
	push rcx							; Preserve length

	mov rsi, rminfo
	call minfo

;	mov rsi, rminfo
;	mov rdi, STDOUT_FILENO
;	call putminfo

	pop rcx								; Restore length
	pop rdx								; Restore buffer
	pop rsi								; Restore fd
	pop rdi								; Restore line

	test r14b, r14b
	jz .skip_prot						; if filter == 0
	test r14b, [rminfo + sminfo.prot]
	jz .next							; if filter & prot == 0

.skip_prot:
	cmp rvaddr, [rminfo + sminfo.vaddr]
	jl .next							; skip if rvaddr < segment_vaddr

	mov rax, [rminfo + sminfo.end]
	sub rax, [rminfo + sminfo.start]
	add rax, [rminfo + sminfo.vaddr]	; segment_end: rax = end - start + vaddr
	cmp rvaddr, rax						; skip if rvaddr >= segment_end
	jge .next

	mov rax, rvaddr
	sub rax, [rminfo + sminfo.vaddr]
	add rax, [rminfo + sminfo.start]	; translate address

	pop rfilter
	pop rvaddr
	pop rminfo

	ret
