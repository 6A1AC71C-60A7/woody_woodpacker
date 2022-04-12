INCDIR	=	includes
SRCDIR	=	srcs

HDRS	=\
$(addprefix includes/,\
	ftlibc.h\
	wd_crypt.h\
	wd_error.h\
	wd_parse.h\
	wd_types.h\
	wd_utils.h\
	woody_woodpacker.h\
)
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
