section .text

global htoi

; line: rdi, delim: sil -> rax ! rdi, rdx, rcx
htoi:
	push rbx					; Preserve rbx

	xor rax, rax				; value: rax = 0
	xor rbx, rbx				; digit: rbx = 0

.loop:
	mov bl, [rdi]				; c: bl = *line

	cmp bl, sil
	je .break					; break if c == delim

	shl rax, 4					; value: rax *= 16

	cmp bl, '9'
	setle dl
	dec dl
	and dl, 'a' - '0' - 10
	add dl, '0'					; base_value: dl = bl <= '9' ? '0' : 'a' - 10

	sub bl, dl					; digit: bl -= base_value
	add rax, rbx				; value: rax += digit

	inc rdi						; line: rdi += 1
	dec rcx
	jmp .loop

.break:
	inc rdi
	dec rcx

	pop rbx						; Restore rbx
	ret
