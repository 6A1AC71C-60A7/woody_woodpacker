%include "libpayload.S"
%include "payloads.S"

section .text

extern htoi
extern next_field
extern next_line
extern minfo
extern putminfo
extern mfind
extern putnbr

global _start

; registers to preserve: rbx, rsp, rbp, r12-r15
; cld should be set to forward (0) before entry and upon exit of a function

_start:
	pop rn							; rn = N

	mov rchunk, rsp					; rchunk = chunks

	sub rsp, BUFFER_SIZE
	mov rbuffer, rsp				; rbuffer = rsp[BUFFER_SIZE]

	sub rsp, sminfo_size
	mov rsminfo, rsp				; rsminfo = rsp[sminfo_size]

	mov r8, maps_filepath_8_16
	push r8
	mov r8, maps_filepath_0_8
	push r8							; filepath: rsp[16] = maps_filepath

	mov rax, SYS_OPEN
	mov rdi, rsp
	mov rsi, O_RDONLY
	syscall
	mov rmaps_fd, rax				; rmaps_fd = open(filpath, O_RDONLY)

	add rsp, 16						; Release filepath: rsp[16]

	mov rax, rn
	shl rax, 4						; key_offset: rax = n * 16

	lea rkey_str, [rchunk + rax]	; key_str = chunks[key_offset]

	xor rcx, rcx					; length: rcx = 0
	mov rdi, rbuffer				; line: rdi = rbuffer

decrypt_chunk:
	mov rdx, rbuffer				; buffer: rdx = rbuffer
	mov rsi, rmaps_fd				; fd: rsi = rmaps_fd
	mov r8, rsminfo
	mov r9, [rchunk + schunk.vaddr]
	mov r10b, 0						; no filter
	call mfind						; mfind(line, fd, buffer, sminfo, vaddr, filter)

	mov rax, [rchunk + schunk.vaddr]
	sub rax, [rsminfo + sminfo.vaddr]
	add rax, [rsminfo + sminfo.start]
	mov [rchunk + schunk.vaddr], rax

	push rdx
	push rcx
	push rdi
	mov rdi, [rsminfo + sminfo.start]
	mov rsi, [rsminfo + sminfo.end]
	sub rsi, rdi
	mov edx, 7							; prot TODO: Restore old protection
	mov rax, SYS_MPROTECT				; mprotect(map_start, map_end - map_start, PROT_RWX)
	syscall
	pop rdi
	pop rcx
	pop rdx

decrypt_term_msg:
	xor r8, r8							; data_iterator: r8 = 0

decrypt_byte:
	mov rdx, r8
	and rdx, 7							; key_offset: rdx = data_iterator % 8

	mov r9b, BYTE [rkey_str + rdx]		; key_c: r9b = key_str[key_offset]

	mov r11, [rchunk + schunk.vaddr]
	sub BYTE [r11 + r8], r9b			; cipher_text[data_iterator] -= key_c

	push rcx
	mov cl, dl
	rol BYTE [r11 + r8], cl			; ROTL(cipher_text[data_iterator], key_offset)
	pop rcx

	not BYTE [r11 + r8]					; cipher_text[data_iterator] = ~cipher_text[data_iterator]

	xor BYTE [r11 + r8], r9b			; cipher_text[data_iterator] ^= key_c

	inc r8								; data_iterator: r8 += 1

	cmp r8, [rchunk + schunk.size]
	jb decrypt_byte						; if data_iterator >= chunk_size
		add rchunk, schunk_size			; rchunk += schunk_size

		add rcx, rdi
		sub rcx, rbuffer				; length: rcx = line_end - buffer_data
		mov rdi, rbuffer				; line: rdi = buffer

		dec rn
		js end							; if rn >= 0
			test rn, rn
			jnz decrypt_chunk			; if chunk_iterator == 0
				lea rax, [rchunk + 8]
				sub rchunk, 16			;
				mov [rchunk + schunk.vaddr], rax
				mov QWORD [rchunk + schunk.size], TERM_MSG_SIZE

				jmp decrypt_term_msg	; Decrypt woody string

end:
	mov r9, [rchunk + 8 + TERM_MSG_SIZE + 18 * 8]	; Load real entrypoint pointer

	push rdi
	push rsi
	push rcx

	mov edi, STDOUT_FILENO
	mov rsi, r9
	mov dl, `\n`
	call putnbr

	pop rcx
	pop rsi
	pop rdi

	push r9							; Preserve entrypoint

	mov rdx, rbuffer				; buffer: rdx = rbuffer
	mov rsi, rmaps_fd				; fd: rsi = rmaps_fd
	mov r8, rsminfo
	mov r10b, PROT_EXEC
	call mfind

	mov edi, STDOUT_FILENO
	mov rsi, rsminfo
	call putminfo

	pop r9							; Restore entrypoint

	sub r9, [rsminfo + sminfo.vaddr]
	add r9, [rsminfo + sminfo.start]	; Translate entrypoint address

	mov [rchunk + 8 + TERM_MSG_SIZE + 18 * 8], r9	; Overwrite entrypoint

	mov edi, STDOUT_FILENO
	mov rsi, r9
	mov dl, `\n`
	call putnbr

	mov rsp, rchunk

	mov rax, SYS_WRITE
	mov rdi, STDOUT_FILENO
	lea rsi, [rchunk + 8]
	mov rdx, TERM_MSG_SIZE
	syscall								; write(STDOUT_FILENO, chunk_vaddr, chunk_size)

	add rsp, 8 + TERM_MSG_SIZE
