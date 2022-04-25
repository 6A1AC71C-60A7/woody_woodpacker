section .text

global next_field

; line: rdi, delim: sil -> rdi ! rax
next_field:
	mov al, sil		; Search for delim

	repne scasb		; Skip until delim
	repe scasb		; Skip delim

	dec rdi
	inc rcx

	ret
