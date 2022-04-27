%include "libpayload.S"

%include "payloads.S"

%define rchunk rbp
%define rminfo rbx
%define rbuffer r12
%define rmaps_fd r13
%define rn r14
%define rkey_str r15

section .text.startup

;extern putminfo
;extern putnbr
extern mfind

extern main

global _start

; registers to preserve: rbx, rsp, rbp, r12-r15
; cld should be set to forward (0) before entry and upon exit of a function

_start:
	pop rn							; rn = N

	mov rchunk, rsp					; rchunk = chunks

	sub rsp, BUFFER_SIZE
	mov rbuffer, rsp				; rbuffer = rsp[BUFFER_SIZE]

	sub rsp, sminfo_size
	mov rminfo, rsp					; rminfo = rsp[sminfo_size]

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

; Registers to preserve: line: rdi, length: rcx
decrypt_chunk:
;	push rcx
;	push rdi
;	mov edi, STDOUT_FILENO
;	mov rsi, rn
;	mov dl, `\n`
;	call putnbr
;	pop rdi
;	pop rcx

	add rcx, rdi
	sub rcx, rbuffer				; length: rcx = line_end - buffer_data
	mov rdi, rbuffer				; line: rdi = buffer
	mov rsi, rmaps_fd				; fd: rsi = rmaps_fd
	mov rdx, rbuffer				; buffer: rdx = rbuffer
	mov r8, rminfo					; sminfo: r8 = rminfo
	mov r9, [rchunk + schunk.vaddr]	; vaddr: r9 = rchunk.vaddr
	mov r10b, PROT_NONE				; filter: r10b = 0
	call mfind						; mfind(line, fd, buffer, sminfo, vaddr, filter)
	mov [rchunk + schunk.vaddr], rax; rchunk.vaddr = rchunk.vaddr - rminfo.vaddr + rminfo.start

;	push rdi
; 	push rcx
; 	mov dl, `\n`
; 	mov rsi, rax
; 	mov edi, STDOUT_FILENO
; 	call putnbr
; 	pop rcx
; 	pop rdi

	push rdi						; Preserve line
	push rcx						; Preserve length

	mov rdi, [rminfo + sminfo.start]
	mov rsi, [rminfo + sminfo.end]
	sub rsi, rdi
	mov edx, PROT_RWX				; TODO: Restore old protection
	mov rax, SYS_MPROTECT
	syscall							; mprotect(map_start, map_end - map_start, PROT_RWX)

	pop rcx							; Restore length
	pop rdi							; Restore line

.term_msg:
	xor r8, r8						; data_iterator: r8 = 0

.byte:
	push rcx

	mov rdx, r8
	and rdx, 7						; key_offset: rdx = data_iterator % 8

	mov r9b, BYTE [rkey_str + rdx]	; key_c: r9b = key_str[key_offset]

	mov r11, [rchunk + schunk.vaddr]
	sub BYTE [r11 + r8], r9b		; cipher_text[data_iterator] -= key_c

	mov cl, dl
	rol BYTE [r11 + r8], cl			; ROTL(cipher_text[data_iterator], key_offset)

	not BYTE [r11 + r8]				; cipher_text[data_iterator] = ~cipher_text[data_iterator]

	xor BYTE [r11 + r8], r9b		; cipher_text[data_iterator] ^= key_c

	inc r8							; data_iterator: r8 += 1

	pop rcx

	cmp r8, [rchunk + schunk.size]
	jb .byte						; if data_iterator >= chunk_size
	add rchunk, schunk_size			; rchunk += schunk_size

	dec rn
	js end							; if rn >= 0
	test rn, rn
	jnz decrypt_chunk				; if chunk_iterator == 0
	lea rax, [rchunk + 8]

	sub rchunk, schunk_size			; rchunk -= schunk_size

	mov [rchunk + schunk.vaddr], rax
	mov QWORD [rchunk + schunk.size], TERM_MSG_SIZE

	jmp .term_msg					; Decrypt woody string

end:
	add rcx, rdi
	sub rcx, rbuffer				; length: rcx = line_end - buffer_data
	mov rdi, rbuffer				; line: rdi = buffer
	mov rsi, rmaps_fd				; fd: rsi = rmaps_fd
	mov rdx, rbuffer				; buffer: rdx = rbuffer
	mov r8, rminfo						; sminfo: r8 = rsminfo
	mov r9, [rchunk + EP_OFFSET]	; Load real entrypoint pointer
	mov r10b, PROT_EXEC					; filter: r10b = PROT_EXEC
	call mfind							; mfind(line, fd, buffer, length, sminfo, filter)

;	mov edi, STDOUT_FILENO
;	mov rsi, rminfo
;	call putminfo

	mov [rchunk + EP_OFFSET], rax		; Overwrite entrypoint

;	mov edi, STDOUT_FILENO
;	mov rsi, rax
;	mov dl, `\n`
;	call putnbr

	mov rsp, rchunk

	mov rax, SYS_WRITE
	mov rdi, STDOUT_FILENO
	lea rsi, [rchunk + 8]
	mov rdx, TERM_MSG_SIZE
	syscall								; write(STDOUT_FILENO, chunk_vaddr, chunk_size)

	add rsp, 8 + TERM_MSG_SIZE

	call main

	; Restore original register state
	popfq
	pop r15
	pop r14
	pop r13
	pop r12
	pop r11
	pop r10
	pop r9
	pop r8
	pop rdi
	pop rsi
	pop rbp
	pop rbx
	pop rdx
	pop rcx
	pop rax

	ret
