NAME=wd_payloads.h

SRCDIR=.
OBJDIR=relocs
BINDIR=bin

PAYLOADS=antiptrace decryptor regs_preservation regs_restoration

TARGET_PAYLOADS=$(PAYLOADS_x86_64)# $(PAYLOADS_x86)

PAYLOADS_x86_64=$(addsuffix _x86_64, $(addprefix $(BINDIR)/, $(PAYLOADS)))
PAYLOADS_x86=$(addsuffix _x86, $(addprefix $(BINDIR)/, $(PAYLOADS)))

SRCS_x86_64=$(addsuffix _x86_64.S, $(addprefix $(SRCDIR)/, $(PAYLOADS)))
SRCS_x86=$(addsuffix _x86.S, $(addprefix $(SRCDIR)/, $(PAYLOADS)))

OBJS_x86_64=$(SRCS_x86_64:$(SRCDIR)/%.S=$(OBJDIR)/%.o)
OBJS_x86=$(SRCS_x86:$(SRCDIR)/%.S=$(OBJDIR)/%.o)

ARCHS=x86_64 x86

AS=nasm
LD=ld

TYPE=const ubyte 

ASFLAGS_x86_64=-f elf64
ASFLAGS_x86=-f elf32

LDFLAGS_x86_64=-m elf_x86_64
LDFLAGS_x86=-m elf_i386

COMPILE.S = $(AS) $(ASFLAGS)
COMPILE.o = $(LD) $(LDFLAGS)

all: $(NAME)

$(OBJDIR) $(BINDIR):
	@echo "MK $@"
	@mkdir -p "$@"

$(OBJS_x86_64): ASFLAGS=$(ASFLAGS_x86_64)

$(OBJS_x86): ASFLAGS=$(ASFLAGS_x86)

$(OBJDIR)/%.o: $(SRCDIR)/%.S | $(OBJDIR)
	@mkdir -p '$(@D)'
	@echo "AS $<"
	@$(COMPILE.S) $< -o $@

$(BINDIR)/%: $(OBJDIR)/%.o | $(BINDIR)
	@$(COMPILE.o) -o $@ $<

.PHONY: clean
clean:
	rm -rf $(OBJDIR)

.PHONY: fclean
fclean: clean
	rm -f $(PAYLOADS)
	rm $(NAME)

.PHONY: re
re: fclean all

$(NAME): $(PAYLOADS_x86_64) Makefile
	@echo -ne "#pragma once\n\n#include <wd_types.h>\n" > $@

	@$(foreach payload, $(TARGET_PAYLOADS), \
		echo -ne "\n$(TYPE) $(notdir $(payload))[] = {\n" >> $@; \
		objdump -d $(payload) \
		|  grep "^ " | cut -f2 | tr -d ' ' \
		| sed 's/.\{2\}/0x&, /g' | tr -d '\n' \
		| fold -s -w 76 | sed -e 's/^/\t/g' >> $@; \
		echo -ne "\n};\n" >> $@;)