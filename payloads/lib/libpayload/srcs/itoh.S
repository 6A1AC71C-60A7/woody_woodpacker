section .text

global itoh

; rdi: dest, number: rsi, delim: dl, rcx: buffer_len
itoh:
	dec rcx
	mov [rdi + rcx], dl

	.convert:
		dec rcx

		mov r8b, sil
		and r8b, 0x10 - 1			; digit: r8b = number % 0x10

		cmp r8b, 9
		setle r10b
		dec r10b
		and r10b, 'a' - '0' - 10
		add r10b, '0'				; base_value: r10b = digit <= 9 ? '0' : 'A' - 10

		add r8b, r10b				; digit: sil += base_value
		mov [rdi + rcx], r8b		; rdi[i] = digit

		shr rsi, 4					; number: rsi /= 0x10
		test rcx, rcx
	jnz .convert					; loop while i != 0

	ret
