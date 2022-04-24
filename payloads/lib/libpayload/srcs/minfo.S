%include "libpayload.S"

%define rline r12
%define rsminfo r13

section .text

extern htoi
extern ptoi

global minfo

; rdi: map line, rsi: sminfo
minfo:
	push rline						; Preserve rline
	push rsminfo					; Preserve rsminfo

	mov rline, rdi					; rline = line
	mov rsminfo, rsi				; rsminfo = sminfo

	mov sil, '-'
	call htoi
	mov [rsminfo + map_start], rax	; Parse map_start

	mov sil, ' '
	call htoi
	mov [rsminfo + map_end], rax	; Parse map_end

	call ptoi
	mov [rsminfo + protection], al	; Parse protection

	mov sil, ' '
	call htoi
	mov [rsminfo + vaddr], rax		; Parse vaddr

	pop rsminfo						; Restore rsminfo
	pop rline						; Restore rline

	ret
