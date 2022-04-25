%include "libpayload.S"

%define rsminfo r12
%define rvaddr r13

section .text

extern next_line
extern minfo

global mfind

; line: rdi, fd: esi, buffer: rdx, length: rcx, sminfo: r8, vaddr: r9, prot_filter: r10b
mfind:
	push rsminfo
	push rvaddr

	mov rsminfo, r8
	mov rvaddr, r9

.next:
	call next_line						; next_line(line: rdi, fd: esi, buffer: rdx, length: rcx)

	push rdi							; Preserve line
	push rsi							; Preserve fd
	push rdx							; Preserve buffer
	push rcx							; Preserve length

	mov rsi, rsminfo
	call minfo

	pop rcx								; Restore length
	pop rdx								; Restore buffer
	pop rsi								; Restore fd
	pop rdi								; Restore line

	test r10b, r10b
	jz .skip_prot						; if filter == 0
	test r10b, [rsminfo + sminfo.prot]
	jz .next							; if filter & prot == 0

.skip_prot:
	mov rax, rvaddr
	cmp rax, [rsminfo + sminfo.vaddr]
	jl .next							; skip if rvaddr < segment_vaddr

	mov rax, [rsminfo + sminfo.end]
	sub rax, [rsminfo + sminfo.start]
	add rax, [rsminfo + sminfo.vaddr]	; segment_end: rax = end - start + vaddr
	cmp rvaddr, rax						; skip if rvaddr >= segment_end
	jge .next

	pop rvaddr
	pop rsminfo

	ret
