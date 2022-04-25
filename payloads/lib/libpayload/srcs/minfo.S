%include "libpayload.S"

%define rline r12
%define rminfo r13

section .text

extern htoi
extern ptoi

global minfo

; rdi: map line, rsi: sminfo
minfo:
	push rline						; Preserve rline
	push rminfo						; Preserve rminfo

	mov rline, rdi					; rline = line
	mov rminfo, rsi					; rminfo = sminfo

	mov sil, '-'
	call htoi
	mov [rminfo + sminfo.start], rax; Parse map_start

	mov sil, ' '
	call htoi
	mov [rminfo + sminfo.end], rax	; Parse map_end

	call ptoi
	mov [rminfo + sminfo.prot], al	; Parse protection

	mov sil, ' '
	call htoi
	mov [rminfo + sminfo.vaddr], rax; Parse vaddr

	pop rminfo						; Restore rminfo
	pop rline						; Restore rline

	ret
