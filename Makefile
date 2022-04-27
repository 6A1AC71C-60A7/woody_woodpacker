NAME		=		woody_woodpacker
OBJDIR		=		relocs
PAYLOADDIR	=		payloads

# Compiler and linker
CC			=		clang
LD			=		clang

# Sources
include				srcs.mk
INCDIR		=		includes


OBJS		=		$(SRCS:$(SRCDIR)/%.c=$(OBJDIR)/%.o)
DEPS		=		$(OBJS:.o=.d)


# Flags
DBGFLAGS	=		-g3 -fsanitize=address
IFLAGS		=		-I$(INCDIR) -I$(PAYLOADDIR)
CFLAGS		=		-Wall -Wextra $(IFLAGS)# $(DBGFLAGS)
DFLAGS		=		-MT $@ -MMD -MP -MF $(OBJDIR)/$*.d
LDFLAGS		=		$(LIBDIRS:%=-L%)# $(DBGFLAGS)
#LDLIBS		=		$(LIBARS:lib%.a=-l%)

UNAME		=		$(shell uname -s)

ifeq ($(UNAME), Darwin)
    IFLAGS += -Ilib/gnu/elf/include
	CFLAGS += -Wno-deprecated-declarations
endif

# Compiling commands
COMPILE.c = $(CC) $(DFLAGS) $(CFLAGS) -c
COMPILE.o = $(LD) $(LDFLAGS)

all: $(NAME)

# Directories
$(OBJDIR):
	@echo "MK $@"
	@mkdir -p $@

# Payloads
$(PAYLOADDIR)/wd_payloads.h: FORCE
	@echo "MK $@"
	@$(MAKE) --quiet -C payloads NAME=$(@F) $(@F)

# Objects
$(OBJS): $(OBJDIR)/%.o: $(SRCDIR)/%.c $(OBJDIR)/%.d $(PAYLOADDIR)/wd_payloads.h | $(OBJDIR)
	@mkdir -p '$(@D)'
	@echo "CC $<"
	@$(COMPILE.c) $< -o $@

# Dependencies
$(DEPS): $(OBJDIR)/%.d:
include $(wildcard $(DEPS))

# Binaries
$(NAME) : $(OBJS)
	@echo "LD $@"
	@$(COMPILE.o) $^ -o $@ $(LDFLAGS)

clean:
	echo "MK -C $(PAYLOADDIR) $@" && $(MAKE) -C $(PAYLOADDIR) $@
	rm $(PAYLOADS_x86_64) $(PAYLOADS_x86) 2>/dev/null && echo "RM $(PAYLOADS)" || :
	@echo RM $(OBJDIR)
	@$(RM) -rf $(OBJDIR)

fclean: clean
	echo "MK -C $(PAYLOADDIR) $@" && $(MAKE) -C $(PAYLOADDIR) $@
	@echo RM $(NAME)
	@$(RM) -rf $(NAME)

re: fclean all

FORCE: ;

.PHONY: clean fclean re FORCE


# Assign a value to VERBOSE to enable verbose output
$(VERBOSE).SILENT:
