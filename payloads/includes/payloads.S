%ifndef PAYLOADS_S
	%define PAYLOADS_S

	%define PAGE_SIZE 0x1000
	%define TERM_MSG_SIZE 24

	%define EP_OFFSET 8 + TERM_MSG_SIZE + 16 * 8

	; string size must be multiples of 8, including the NUL terminator.
	%define maps_filepath "/proc/self/maps"
	%substr maps_filepath_0_8 maps_filepath 1,8
	%substr maps_filepath_8_16 maps_filepath 9,8

	struc	schunk
		.size:		resq	1
		.vaddr:		resq	1
	endstruc
%endif
