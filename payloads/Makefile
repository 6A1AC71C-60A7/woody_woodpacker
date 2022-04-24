# C include header name
NAME=wd_payloads.h

# C array data type
TYPE=const ubyte

# Directories
INCDIR=includes
SRCDIR=.
LIBDIR=lib

OBJDIR=relocs
BINDIR=bin

# Library dependencies
LIBS=$(addprefix $(LIBDIR)/, libpayload/libpayload.a)

LIBDIRS=$(dir $(LIBS))
LIBINCS=$(addsuffix $(INCDIR), $(LIBDIRS))
LIBARS=$(notdir $(LIBS))

# Sources
INCS = $(LIBINCS) $(INCDIR)
PAYLOADS=antiptrace decryptor regs_preservation regs_restoration
ARCHS=x86_64 x86

# Payloads to include in the header
TARGET_PAYLOADS=$(PAYLOADS_x86_64)# $(PAYLOADS_x86)

# Payload binaries
PAYLOADS_x86_64=$(addsuffix _x86_64, $(addprefix $(BINDIR)/, $(PAYLOADS)))
PAYLOADS_x86=$(addsuffix _x86, $(addprefix $(BINDIR)/, $(PAYLOADS)))

# Payload sources
SRCS_x86_64=$(addsuffix _x86_64.S, $(addprefix $(SRCDIR)/, $(PAYLOADS)))
SRCS_x86=$(addsuffix _x86.S, $(addprefix $(SRCDIR)/, $(PAYLOADS)))

# Payload relocatable objects
OBJS_x86_64=$(SRCS_x86_64:$(SRCDIR)/%.S=$(OBJDIR)/%.o)
OBJS_x86=$(SRCS_x86:$(SRCDIR)/%.S=$(OBJDIR)/%.o)

# Assembler and Linker
AS=nasm
LD=ld

# Flags
ASFLAGS=$(INCS:%=-I%)
LDFLAGS=$(LIBDIRS:%=-L%)
LDLIBS=$(LIBARS:lib%.a=-l%)

ASFLAGS_x86_64=-f elf64
LDFLAGS_x86_64=-m elf_x86_64

ASFLAGS_x86=-f elf32
LDFLAGS_x86=-m elf_i386

# Compiling commands
COMPILE.S=$(AS) $(ASFLAGS)
COMPILE.o=$(LD) $(LDFLAGS)

# Default target
all: $(NAME)

# Directories
$(OBJDIR) $(BINDIR):
	@echo "MK $@"
	@mkdir -p "$@"

# Libraries
$(LIBS): %.a: FORCE
	@echo "MK $@"
	@$(MAKE) -C $(dir $@) NAME=$(@F)

# Objects
$(OBJS_x86_64): ASFLAGS+=$(ASFLAGS_x86_64)

$(OBJS_x86): ASFLAGS+=$(ASFLAGS_x86)

$(OBJDIR)/%.o: $(SRCDIR)/%.S | $(OBJDIR)
	@mkdir -p '$(@D)'
	@echo "AS $<"
	$(COMPILE.S) $< -o $@

$(BINDIR)/%: $(OBJDIR)/%.o $(LIBS) | $(BINDIR)
	$(COMPILE.o) -o $@ $< $(LDLIBS)

clean:
	$(foreach dir, $(LIBDIRS),\
		echo "MK $(addprefix -C , $(dir)) $@" && make -C $(dir) $@ ; ):
	rm -r "$(OBJDIR)" 2>/dev/null && echo "RM $(OBJDIR)" || :

fclean: clean
	$(foreach dir, $(LIBDIRS),\
		echo "MK $(addprefix -C, $(dir)) $@" && make -C $(dir) $@ ; ):
	rm $(PAYLOADS) 2>/dev/null && echo "RM $(PAYLOADS)" || :
	rm $(NAME) 2>/dev/null && echo "RM $(NAME)" || :

re: fclean all

$(NAME): $(PAYLOADS_x86_64) Makefile
	@echo "OD $< > $@"

	@echo -ne "#pragma once\n\n#include <wd_types.h>\n" > $@

	$(foreach payload, $(TARGET_PAYLOADS), \
		echo -ne "\n$(TYPE) $(notdir $(payload))[] = {\n" >> $@; \
		objdump -d $(payload) \
		|  grep "^ " | cut -f2 | tr -d ' ' \
		| sed 's/.\{2\}/0x&, /g' | tr -d '\n' \
		| fold -s -w 76 | sed -e 's/^/\t/g' >> $@; \
		echo -ne "\n};\n" >> $@;)

FORCE: ;

.PHONY: clean fclean re FORCE

# Assign a value to VERBOSE to enable verbose output
$(VERBOSE).SILENT:
