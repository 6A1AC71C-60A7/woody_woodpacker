section .text

global ptoi

; field: rdi -> al ! rdi, rcx
ptoi:
	push rbx				; Preserve rbx
	push rcx				; Preserve rcx

	xor rax, rax			; value: rax = 0
	mov rcx, 3				; i: rcx = 3

	.convert:
		dec rcx				; i: rcx -= 1
		mov bl, [rdi + rcx]	; c: bl = field[i]
		cmp bl, '-'
		setne bl			; bit: bl = c != '-'
		je .continue		; if c != '-'
			shl bl, cl		; bit: bl <<= i
			or al, bl		; value: al |= bit
		.continue:
		test rcx, rcx
	jnz .convert			; while --i

	pop rcx					; Restore rcx
	pop rbx					; Restore rbx

	sub rcx, 5				; length: rcx -= 5
	add rdi, 5				; field: rdi += 5

	ret
