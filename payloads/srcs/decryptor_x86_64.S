%include "libpayload.S"

%include "payloads.S"

%define rchunk rbp
%define rminfo rbx
%define rbuffer r12
%define rmaps_fd r13
%define rn r14
%define rkey r15

section .text.startup

extern putminfo
extern putnbr
extern mdump
extern mfind
extern kdecrypt

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

	lea rkey, [rchunk + rax]		; key = chunks[key_offset]

	xor rcx, rcx					; length: rcx = 0
	mov rdi, rbuffer				; line: rdi = rbuffer

; Registers to preserve: line: rdi, length: rcx
decrypt_chunk:
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


	push rdi
 	push rcx

 	mov dl, `\n`
 	mov rsi, rn
 	mov edi, STDOUT_FILENO
 	call putnbr

	mov edi, STDOUT_FILENO
	mov rsi, rminfo
	call putminfo

 	mov dl, `\n`
 	mov rsi, [rchunk + schunk.size]
 	mov edi, STDOUT_FILENO
 	call putnbr

 	pop rcx
 	pop rdi


	push rdi						; Preserve line
	push rcx						; Preserve length

;	mov edi, STDOUT_FILENO
;	mov rsi, rn
;	mov dl, `\n`
;	call putnbr

	mov rdi, [rminfo + sminfo.start]
	mov rsi, [rminfo + sminfo.end]
	sub rsi, rdi
	mov edx, PROT_RWX				; TODO: Restore old protection
	mov rax, SYS_MPROTECT
	syscall							; mprotect(map_start, map_end - map_start, PROT_RWX)

	mov rdi, rchunk
	mov rsi, "cipher0"
	mov rdx, rn
	call dump_chunk

	mov rdi, [rchunk + schunk.vaddr]
	mov rsi, [rchunk + schunk.size]
	mov rdx, rkey
	call kdecrypt

	mov rdi, rchunk
	mov rsi, "plaint0"
	mov rdx, rn
	call dump_chunk

 	mov dl, `\n`
	mov edi, STDOUT_FILENO
	mov rsi, [rchunk + schunk.vaddr]
	call putnbr

	add rchunk, schunk_size			; rchunk += schunk_size

	pop rcx							; Restore length
	pop rdi							; Restore line

	dec rn

	test rn, rn
	jnz decrypt_chunk				; while chunk_iterator != 0


	push rdi
	push rcx

	lea rdi, [rchunk + 8]			; woody_str: rax = last_chunk + 8
	mov rsi, TERM_MSG_SIZE
	mov rdx, rkey
	call kdecrypt					; kdecrypt(woody_str, TERM_MSG_SIZE, key)

	pop rcx
	pop rdi
end:
	add rcx, rdi
	sub rcx, rbuffer				; length: rcx = line_end - buffer_data
	mov rdi, rbuffer				; line: rdi = buffer
	mov rsi, rmaps_fd				; fd: rsi = rmaps_fd
	mov rdx, rbuffer				; buffer: rdx = rbuffer
	mov r8, rminfo					; sminfo: r8 = rsminfo
	mov r9, [rchunk + EP_OFFSET]	; vaddr: r9 = entrypoint
	mov r10b, PROT_EXEC				; filter: r10b = PROT_EXEC
	call mfind						; mfind(line, fd, buffer, length, sminfo, filter)

	mov [rchunk + EP_OFFSET], rax	; Overwrite entrypoint

	mov edi, STDOUT_FILENO
	mov rsi, rax
	mov dl, `\n`
	call putnbr

	mov rdi, rmaps_fd
	mov rax, SYS_CLOSE
	syscall							; close(maps_fd)

	lea rsp, [rchunk + 8]			; rsp = msg = last_chunk + 8

	mov rax, SYS_WRITE
	mov rdi, STDOUT_FILENO
	mov rsi, rsp
	mov rdx, TERM_MSG_SIZE
	syscall							; write(STDOUT_FILENO, chunk_vaddr, chunk_size)

	add rsp, TERM_MSG_SIZE			; rsp += TERM_MSG_SIZE

;	call main

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

; chunk: rdi, prefix: rsi, chunk_no: dl
dump_chunk:
	sub dl, 1
	push rsi
	add BYTE [rsp + 6], dl

	mov r8, rdi

	mov rdi, rsp
	mov rsi, O_WRONLY | O_CREAT | O_TRUNC
	mov rdx, S_IRUSR | S_IWUSR
	mov rax, SYS_OPEN
	syscall

	mov rsi, [r8 + schunk.vaddr]
	mov rdx, [r8 + schunk.size]

	pop r8

	push rax

	mov edi, eax
	mov rax, SYS_WRITE
	syscall

	pop rax

	mov rdi, rax
	mov rax, SYS_CLOSE
	syscall

	ret
