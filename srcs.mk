SRCDIR	=	srcs

SRCS	=\
$(addprefix srcs/,\
	build_decryptor.c\
	$(addprefix crypt/,\
		kcrypt.c\
		kdecrypt.c\
	)\
	encrypt_chunks.c\
	$(addprefix ftlibc/,\
		memcpy.c\
		memmove.c\
		strcmp.c\
		strlen.c\
		strncmp.c\
	)\
	genkey.c\
	inject_decryptor.c\
	lookup_sections.c\
	main.c\
	map_elf.c\
	parse_opts.c\
	test.c\
)
