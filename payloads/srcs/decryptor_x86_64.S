%include "libpayload.S"

%define PAGE_SIZE 0x1000
%define TERM_MSG_SIZE 24

; filepath string size must be multiples of 8, including the NUL terminator.
%define maps_filepath "/proc/self/maps"
%substr maps_filepath_0_8 maps_filepath 1,8
%substr maps_filepath_0_16 maps_filepath 9,8

%define rmaps_fd r12
%define rchunk_size r13
%define rchunk_vaddr r14
%define rkey_str r15

section .text

extern htoi
extern next_field
extern next_line
extern putnbr
extern minfo
extern putminfo

global _start

; registers to preserve: rbx, rsp, rbp, r12-r15
; cld should be set to forward (0) before entry and upon exit of a function

; rchunk_vaddr: rsi
_start:
	mov rchunk_vaddr, rsi			; rchunk_vaddr = rsi

	mov r8, maps_filepath_0_16
	push r8
	mov r8, maps_filepath_0_8
	push r8							; filepath: rsp[16] = maps_filepath

	mov rax, SYS_OPEN				; rmaps_fd = open(filpath, O_RDONLY)
	mov rdi, rsp
	mov rsi, O_RDONLY
	syscall
	mov rmaps_fd, rax

	add rsp, 16						; Release filepath: rsp[16]

	pop rax							; n: rax = N
	push rax						; Preserve n: rax

	mov r9, 2						; rkey_str = &key
	imul rax, r9
	lea rkey_str, [rsp + rax * 8]
	add rkey_str, 8

decrypt_chunk:
	pop rchunk_size					; Load rchunk_size
	pop rchunk_vaddr				; Load rchunk_vaddr

	push rbx						; Preserve rbx

	sub rsp, BUFFER_SIZE			; buffer_data: rsp[BUFFER_SIZE]
	mov rdx, rsp					; buffer: rdx = buffer_data
	mov rdi, rdx					; line: rdi = buffer
	xor rcx, rcx					; length: rcx = 0

	sub rsp, sminfo_size
	mov rbx, rsp
	.mfind:
		mov rsi, rmaps_fd			; fd: esi = rmaps_fd
		call next_line				; next_line(line: rdi, fd: esi, buffer: rdx, length: rcx)
		push rdi					; Preserve line
		push rdx					; Preserve buffer
		push rcx					; Preserve length

		mov rsi, rbx
		call minfo

		mov edi, STDOUT_FILENO
		mov rsi, rbx
		call putminfo

		pop rcx						; Restore length
		pop rdx						; Restore buffer
		pop rdi						; Restore line

		mov al, PROT_EXEC			; bit: al = PROT_EXEC
		and al, [rbx + protection]
		test al, al
		jz .mfind					; skip if not executable

		cmp rchunk_vaddr, [rbx + vaddr]
		jl .mfind					; skip if rchunk_vaddr < segment_vaddr

		mov rax, [rbx + map_end]
		sub rax, [rbx + map_start]
		add rax, [rbx + vaddr]		; segment_end: rax = map_end - map_start + vaddr
		cmp rchunk_vaddr, rax		; skip if rchunk_vaddr >= segment_end
		jge .mfind

	add rsp, sminfo_size

	mov edi, eax
	mov rax, SYS_EXIT
	syscall

	add rsp, BUFFER_SIZE

	pop rbx

	push rdx
;	push rcx
	pushfq
	mov rdi, rchunk_vaddr		; TODO: Obtain segment virtual address
;	and rdi, PAGE_SIZE - 1		; align to page size
	mov rsi, rchunk_size		; len TODO: Make the whole segment writable
	mov edx, 7					; prot TODO: Restore old protection
	mov rax, SYS_MPROTECT
	syscall

;	neg rax		; get errno
;	mov rdi, rax
;	mov rax, SYS_EXIT
;	syscall

	popfq
;	pop rcx
	pop rdx

	pop rax						; n: rax = N
	push rax					; Preserve N

	xor r10, r10				; chunk_iterator: r10 = 0
decrypt_term_msg:
	push r10
	xor r8, r8					; data_iterator: r8 = 0

decrypt_byte:
	mov rdx, r8
	and rdx, 7							; key_offset: rdx = data_iterator % 8

	mov r9b, BYTE [rkey_str + rdx]		; key_c: r9b = key_str[key_offset]

	sub BYTE [rchunk_vaddr + r8], r9b	; cipher_text[data_iterator] -= key_c

;	push rchunk_size					; Preserve chunk_size

	mov cl, dl
	rol BYTE [rchunk_vaddr + r8], cl			; ROTL(cipher_text[data_iterator], key_offset)

;	pop rchunk_size

	not BYTE [rchunk_vaddr + r8]		; cipher_text[data_iterator] = ~cipher_text[data_iterator]

	xor BYTE [rchunk_vaddr + r8], r9b	; cipher_text[data_iterator] ^= key_c

	inc r8								; data_iterator: r8 += 1

	cmp r8, rchunk_size
	jb decrypt_byte						; if data_iterator >= rchunk_size

		pop r10							; Load chunk_iterator: r10
		inc r10							; chunk_iterator: r10 += 1

		cmp r10, rax
		jb decrypt_chunk				; if chunk_iterator <= N

			cmp r10, rax
			jne end							; if chunk_iterator == N
				inc r10						; chunk_iterator: r10 += 1
				push r10					; Preserve chunk_iterator
				lea rchunk_vaddr, [rchunk_vaddr + 8]	; Load woody string
				pop r10									; Restore chunk_iterator
				mov rchunk_size, TERM_MSG_SIZE			; Load woody string len
				jmp decrypt_term_msg					; Decrypt woody string

end:
	mov rax, SYS_WRITE
	mov rdi, 1
	mov rdx, rchunk_size
	syscall

	add rsp, TERM_MSG_SIZE + 1 * 8

	mov rdi, 0
	mov rax, SYS_EXIT
	syscall							; TODO: Remove temporary exit(0)
