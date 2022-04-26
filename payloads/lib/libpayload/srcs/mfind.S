%include "libpayload.S"

%define rminfo r12
%define rvaddr r13
%define rfilter r14

section .text

extern next_line
extern minfo

global mfind

; line: rdi, fd: esi, buffer: rdx, length: rcx, sminfo: r8, vaddr: r9, prot_filter: r10b
mfind:
	push rminfo
	push rvaddr
	push rfilter

	mov rminfo, r8
	mov rvaddr, r9
	mov r14b, r10b

.next:
	call next_line						; next_line(line: rdi, fd: esi, buffer: rdx, length: rcx)

	push rdi							; Preserve line
	push rsi							; Preserve fd
	push rdx							; Preserve buffer
	push rcx							; Preserve length

	mov rsi, rminfo
	call minfo

	pop rcx								; Restore length
	pop rdx								; Restore buffer
	pop rsi								; Restore fd
	pop rdi								; Restore line

	test r14b, r14b
	jz .skip_prot						; if filter == 0
	test r14b, [rminfo + sminfo.prot]
	jz .next							; if filter & prot == 0

.skip_prot:
	mov rax, rvaddr
	cmp rax, [rminfo + sminfo.vaddr]
	jl .next							; skip if rvaddr < segment_vaddr

	mov rax, [rminfo + sminfo.end]
	sub rax, [rminfo + sminfo.start]
	add rax, [rminfo + sminfo.vaddr]	; segment_end: rax = end - start + vaddr
	cmp rvaddr, rax						; skip if rvaddr >= segment_end
	jge .next

	pop rfilter
	pop rvaddr
	pop rminfo

	ret
