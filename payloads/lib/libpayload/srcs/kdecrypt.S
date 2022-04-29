%include "libpayload.S"

section .text

global kdecrypt

%define ri r8
%define rkey_c r9b
%define rcipher_c r10b

; cipher_text: rdi, length: rsi, key: rdx
kdecrypt:
	xor ri, ri						; data_iterator: ri = 0
	xor rax, rax					; count_iterator: rax = 0

.byte:
	mov	rcipher_c, BYTE [rdi + ri]		; rcipher_c =  cipher_text[data_iterator]

;	test rcipher_c, rcipher_c					; if rcipher_c == '\0'
;	jz .skip_byte

	mov rcx, rax
	and rcx, 7						; key_offset: rcx = count_iterator % 8


	mov rkey_c, BYTE [rdx + rcx]	; rkey_c = key_str[key_offset]

	; sub rcipher_c, rkey_c					; rcipher_c: rcipher_c -= rkey_c

	; mov cl, dl						; rot_offset: cl = key_offset
	; rol rcipher_c, cl						; ROTL(rcipher_c, rot_offset)

	not rcipher_c						; rcipher_char = ~rcipher_char

	; xor BYTE rcipher_c, 2				; rcipher_char ^= rkey_c

	mov	 BYTE [rdi + ri], rcipher_c	; rcipher_c: rcipher_c =  cipher_text[data_iterator]

	inc rax							; count_iterator: rax += 1

.skip_byte:
	inc ri							; data_iterator: ri += 1

	cmp rax, rsi
	jb .byte						; if data_iterator >= chunk_size

	ret
