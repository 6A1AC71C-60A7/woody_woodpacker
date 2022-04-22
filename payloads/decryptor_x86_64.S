section .text
global _start

_start:
	pop rax						; n: rax = N

	push rax

	mov r9, 2					; key_str: rdi = &key
	imul rax, r9				
	lea rdi, [rsp + rax * 8]
	add rdi, 8

	pop rax

	xor r10, r10				; iterator: r10 = 0

decrypt_chunk:
	pop r11							; chunk_size: r11
	pop rsi							; chunk_vaddr: rsi

	push rdi
	push rsi
	push rax
	push r8
	push r9
	push r10
	push rcx
	push rbx

	mov r8, "lf/maps"
	push r8
	mov r8, "/proc/se"
	push r8

	mov r8, rsi						; chunk_vaddr: r8 = rsi

	mov rax, 2						; fd: edi = open("/proc/self/maps", O_RDONLY)
	mov rdi, rsp
	mov rsi, 0
	syscall
	mov r9d, eax

	sub rsp, 1024

	xor rcx, rcx
	call next_line
	push rdi
	push rcx

	push rsi ; DEBUG
	push rax
	push rcx
	push rdi
	mov rsi, rdi
	mov rdi, 1
	mov rdx, rcx
	mov rax, 1
	syscall
	pop rdi
	pop rcx
	pop rax
	pop rsi ; END DEBUG

	line:
		mov sil, ' '				; delim: sil = ' '
		call next_field				; Skip address field
		call next_field				; Skip protections field

;		push rdi
;		mov rdx, 8
;		mov rsi, rdi
;;		mov rdi, 1
;		mov rax, 1
;;		syscall
;		pop rdi
;
		call convert_hex			; addr: rax = convert_hex(field)

		mov edi, eax
		mov rax, 60
		syscall
		
		mov sil, ' '

		cmp rax, r8					; if addr == chunk_vaddr
		je line_break				; break

		pop rcx
		pop rdi
		call next_line
		push rdi
		push rcx

		jmp line

	line_break:
		pop rcx
		pop rdi

		mov sil, '-'
		call convert_hex

		push rax

		inc rdi
		dec rcx

		mov sil, ' '
		call convert_hex

		push rax

		call next_field				; Skip address field

		xor al, al					; prots: al = 0
		mov rcx, 3					; i: rcx = 3
		convert_prot:				; while i != 0
			mov bl, [rdi + rcx]		; c: bl = line[i]
			cmp bl, '-'

				mov rdx, 1		; len
				mov rsi, rdi	; str
				mov edi, 1		; fd
				mov rax, 1		; write
				syscall
				
			je convert_prot_next	; if c != '-'
				mov bl, 1			; bit: bl = 1
				dec cl
				shl bl, cl			; bit: bl <<= i
				or al, bl			; prots: al |= bit
				inc cl
			convert_prot_next:
		loop convert_prot			; i: rcx -= 1

	mov edi, eax
	mov rax, 60
	syscall

	add rsp, 1024

	pop rbx
	pop rcx
	pop r10
	pop r9
	pop r8
	pop rax
	pop rsi
	pop rdi

	push rdi						; mprotect(chunk_address, chunk_size, PROT_RWX)
	push rsi
	push rdx
	push rax
	push rcx
	push r11
	pushfq
	mov rdi, rsi; align to page size
	mov rsi, r11; len
	mov edx, 7      ; prot
	mov rax, 10
	syscall

	neg rax
	mov rdi, rax
	mov rax, 60
	syscall
	popfq
	pop r11
	pop rcx
	pop rax
	pop rdx
	pop rsi
	pop rdi

decrypt_term_msg:
	push r10
	xor r8, r8

decrypt_byte:
	mov rdx, r8
	and rdx, 7

	mov r9b, BYTE [rdi + rdx]

	sub BYTE [rsi + r8], r9b

	push r9
	push r11

	mov cl, dl
	mov r9b, BYTE [rsi + r8]
	shr r9b, cl

	mov r12b, 8
	sub r12b, dl
	mov cl, r12b

	mov r12b, BYTE [rsi + r8]
	shl r12b, cl

	or r12b, r9b

	pop r11
	pop r9

	mov BYTE [rsi + r8], r12b

	not BYTE [rsi + r8]

	xor BYTE [rsi + r8], r9b

	inc r8

	cmp r8, r11
	jb decrypt_byte					; if r8 >= r11

		pop r10
		inc r10

		cmp r10, rax
		jb decrypt_chunk				; if r10 <= rax

			cmp r10, rax
			jne end							; if r10 == rax
				inc r10
				push r10
				mov r10, 1
				lea rsi, [rdi + r10 * 8]
				pop r10
				mov r11, 24
				jmp decrypt_term_msg

end:
	mov rax, 1
	mov rdi, 1
	mov rdx, 24
	syscall

	add rsp, 32

	mov rdi, 0
	mov rax, 60
	syscall							; temporary exit(0)

next_field:							; line: rdi, delim: sil -> rdi ! rax
	mov al, sil						; Search for delim

	repne scasb						; Skip until delim
	repe scasb						; Skip delim

	dec rdi
	dec rcx

	ret

convert_hex:						; line: rdi, delim: sil -> rax ! rbx, rdx, rcx
	xor rax, rax					; value: rax = 0
	xor rbx, rbx					; digit: rbx = 0
	convert_hex_loop:
		shl rax, 4					; value: rax *= 16
		mov bl, [rdi]				; c: bl = *line

		cmp bl, sil
		je convert_hex_break		; break if c == delim

		cmp bl, '9'
		jg convert_hex_alpha		; if c <= '9'
			mov dl, '0'				; Get digit value
			jmp convert_hex_done
		convert_hex_alpha:			; else
			mov dl, 'A'				; Get hex digit value
		convert_hex_done:

		sub bl, dl

		add rax, rbx				; value: rax += digit

		inc rdi						; line: rdi += 1
		dec rcx
		jmp convert_hex_loop
	convert_hex_break:
		ret

next_line:              ; rdi: buffer, r9d: fd, buffer_length: rcx ! rdx
    add rsp, 8

next_line_next:
    xor rax, rax
    mov al, `\n`        ; c: al = '\n'

    cld                 ; Go forward

	mov r10, rcx

	test r10, r10
	jz next_line_read

    repne scasb         ; Search for newline
    je next_line_found

    mov rsi, rdi
    sub rsi, rsp        ; offset: rsi = line_end - buffer

    mov rax, 8
    neg rsi
    mov edi, r9d
    mov rdx, 1
    syscall             ; lseek(fd, -current_line_offset, SEEK_CURR)

next_line_read:
    mov rax, 0
    mov edi, r9d
    mov rsi, rsp        ; overwrite the previous read
    mov rdx, 1024
    syscall             ; i: rcx = read(fd, buffer, size)
    mov rcx, rax
    mov rdi, rsp

	test r10, r10
    jnz next_line_next

next_line_found:
    sub rsp, 8
    ret
