section .text

global itop

; dest: rdi[4], value: sil
itop:
	xor rcx, rcx				; i: rcx = 8
	push "rwx"

	mov BYTE [rdi], `\0`		; *dest: [rdi] = `\0`

	.convert:
		mov al, 1
		and al, sil				; bit: al = value & 1
		test al, al
		jnz .unset
			mov al, [rsp + rcx]
			mov [rdi + rcx], al

	.unset:
		inc rcx					; i: rcx += 1
		shr sil, 1				; value: sil >>= 1
		test sil, sil
	jnz .convert				; while value != 0

	add rsp, 8

	ret
