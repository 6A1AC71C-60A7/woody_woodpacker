NAME		=		woody_woodpacker
OBJDIR		=		relocs
PAYLOADDIR	=		payloads
CC			=		/usr/bin/gcc
RM			=		/bin/rm

include				srcs.mk

CFLAGS		=		-Wall -Wextra -g3 #-fsanitize=address
IFLAGS		=		-I$(INCDIR) -I$(PAYLOADDIR)

ifeq ($(shell uname -s), Darwin)
    IFLAGS += -Ilib/gnu/elf/include
	CFLAGS += -Wno-deprecated-declarations
endif

OBJS		=		$(patsubst $(SRCDIR)/%.c, $(OBJDIR)/%.o, $(SRCS))

all: $(NAME)
	@:

$(PAYLOADDIR)/wd_payloads.h:
	@$(MAKE) -C payloads NAME=$(@F) $(@F)
	@echo "MK $@"

$(NAME) : $(OBJDIR) $(OBJS) $(HDRS) $(PAYLOADDIR)/wd_payloads.h
	@$(CC) -o $(NAME) $(CFLAGS) $(OBJS)
	@echo LINK $@

$(OBJDIR):
	@mkdir -p $@
	@echo MKDIR $@

$(OBJDIR)/%.o : $(SRCDIR)/%.c 
	@mkdir -p $(shell dirname $@)
	@$(CC) -c -o $@ $(CFLAGS) $(IFLAGS) $<
	@echo CC $<

clean:
	@$(RM) -rf $(OBJDIR)
	@echo RM $(OBJDIR)

fclean: clean
	@$(RM) -rf $(NAME)
	@echo RM $(NAME)

re: fclean all
