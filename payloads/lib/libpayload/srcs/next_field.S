section .text

global next_field

next_field:							; line: rdi, delim: sil -> rdi ! rax
	mov al, sil						; Search for delim

	repne scasb						; Skip until delim
	repe scasb						; Skip delim

	dec rdi
	inc rcx

	ret
