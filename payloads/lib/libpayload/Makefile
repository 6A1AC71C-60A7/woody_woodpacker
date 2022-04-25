NAME	=	libpayload.a

# Directories
SRCDIR	=	srcs
INCDIR	=	includes
OBJDIR	=	objs

# Assembler and Archiver
AS		=	nasm
AR		=	ar

# Flags
ASFLAGS	=	-g -felf64 -I$(INCDIR)
ARFLAGS	=	rcs

# Compiling commands
COMPILE.S = $(AS) $(ASFLAGS)

SRCS	=	$(addprefix $(SRCDIR)/, $(addsuffix .S, \
	htoi \
	itoh \
	itop \
	mfind \
	minfo \
	next_field \
	next_line \
	ptoi \
	putminfo \
	putnbr \
))
OBJS	=	$(patsubst $(SRCDIR)/%.S, $(OBJDIR)/%.o, $(SRCS))

# Default target
all:			$(NAME)

$(OBJDIR):
	@printf "%-3s $@\n" MK
	@mkdir -p $(OBJDIR)

$(OBJDIR)/%.o:	$(SRCDIR)/%.S | $(OBJDIR)
	@mkdir -p '$(@D)'
	@printf '%-3s %s\n' AS "$<"
	$(COMPILE.S) $< -o $@

$(NAME):		$(OBJS)
	@printf '%-3s %s %s\n' AR "$@" "$(OBJS)"
	@$(AR) $(ARFLAGS) $@ $(OBJS)

clean:
	@printf "%-3s $(OBJDIR)\n" RM
	rm -r "$(OBJDIR)" 2>/dev/null && echo "RM $(OBJDIR)" || :

fclean:			clean
	rm $(NAME) 2>/dev/null && echo "RM $(NAME)" || :

re:				fclean all

.PHONY: clean fclean re
