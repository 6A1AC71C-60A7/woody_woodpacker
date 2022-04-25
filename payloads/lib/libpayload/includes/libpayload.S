%ifndef LIBPAYLOAD_S
	%define LIBPAYLOAD_S

	%include "syscall.S"

	%define BUFFER_SIZE 0x400

	struc	sminfo
		.start:	resq	1
		.end:	resq	1
		.vaddr:	resq	1
		.prot:	resb	1
	endstruc

%endif
