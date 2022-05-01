%include "libpayload.S"

section .text

global kdecrypt

%define ri r8
%define rkey_c r9b
%define rcipher_c r10b

; cipher_text: rdi, length: rsi, key: rdx
kdecrypt:
	xor ri, ri						; data_offset: ri = 0

.byte:
	mov	rcipher_c, BYTE [rdi + ri]	; rcipher_c =  cipher_text[data_offset]

	mov rcx, ri
	and rcx, 7						; key_offset: rcx = count_iterator % 8

	mov rkey_c, BYTE [rdx + rcx]	; rkey_c = key_str[key_offset]

	sub rcipher_c, rkey_c			; rcipher_c: rcipher_c -= rkey_c

	rol BYTE rcipher_c, cl			; ROTL(rcipher_c, rot_offset)

	not rcipher_c					; rcipher_char = ~rcipher_char

	xor BYTE rcipher_c, 2			; rcipher_char ^= rkey_c

	mov BYTE [rdi + ri], rcipher_c	; rcipher_c =  cipher_text[data_offset]

	inc ri							; data_offset: ri += 1

	cmp ri, rsi
	jb .byte						; if data_offset >= chunk_size

	ret
