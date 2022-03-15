INCDIR	=	includes
SRCDIR	=	srcs

HDRS	=\
$(addprefix includes/,\
	wd_crypt.h\
	wd_types.h\
)
SRCS	=\
$(addprefix srcs/,\
	$(addprefix crypt/,\
		kcrypt.c\
		kdecrypt.c\
	)\
	main.c\
)
