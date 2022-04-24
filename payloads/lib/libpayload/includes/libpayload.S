%ifndef LIBPAYLOAD_S
	%define LIBPAYLOAD_S

	%include "syscall.S"

	%define BUFFER_SIZE 0x400

	struc	sminfo
		map_start:	resq	1
		map_end:	resq	1
		vaddr:		resq	1
		protection:	resb	1
	endstruc

%endif
