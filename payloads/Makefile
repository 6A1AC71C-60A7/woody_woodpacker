# C include header name
NAME=wd_payloads.h

# C array data type
TYPE=const ubyte

# Directories
INCDIR=includes
SRCDIR=srcs
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
HDRS = $(addprefix $(INCDIR)/, payloads.S)

DEFAULT_PAYLOAD=default_payload
PAYLOADS=antiptrace decryptor regs_preservation regs_restoration remote_serv_shell
ARCHS=x86_64 x86

# Payloads to include in the header
TARGET_PAYLOADS=$(PAYLOADS_x86_64)# $(PAYLOADS_x86)

# Payload binaries
PAYLOADS_BIN= $(addprefix $(BINDIR)/, $(PAYLOADS))
PAYLOADS_x86_64=$(addsuffix _x86_64, $(PAYLOADS_BIN))
PAYLOADS_x86=$(addsuffix _x86, $(PAYLOADS_BIN))

# Payload sources
SRCS=$(addprefix $(SRCDIR)/, $(PAYLOADS) $(DEFAULT_PAYLOAD))
PAYLOAD_SRC_x86_64=$(SRCDIR)/$(DEFAULT_PAYLOAD)_x86_64.S
PAYLOAD_SRC_x86=$(SRCDIR)/$(DEFAULT_PAYLOAD)_x86.S
SRCS_x86_64=$(addsuffix _x86_64.S, $(SRCS))
SRCS_x86=$(addsuffix _x86.S, $(SRCS))

# Payload relocatable objects
OBJS_x86_64=$(SRCS_x86_64:$(SRCDIR)/%.S=$(OBJDIR)/%.o)
OBJS_x86=$(SRCS_x86:$(SRCDIR)/%.S=$(OBJDIR)/%.o)

# Custom additional payload relocatable object
PAYLOAD_OBJ_x86_64=$(PAYLOAD_SRC_x86_64:$(SRCDIR)/%.S=$(OBJDIR)/%.o)
PAYLOAD_OBJ_x86=$(PAYLOAD_SRC_x86:$(SRCDIR)/%.S=$(OBJDIR)/%.o)

# Assembler and Linker
AS=nasm
LD=ld

# Flags
ASFLAGS=$(INCS:%=-I%)
LDFLAGS=$(LIBDIRS:%=-L%) -static -T link.ld --gc-sections -z nodefaultlib
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
$(OBJS_x86_64) $(PAYLOAD_OBJ_x86_64): ASFLAGS+=$(ASFLAGS_x86_64)
$(OBJS_x86_64) $(PAYLOAD_OBJ_x86_64): LDFLAGS+=$(LDFLAGS_x86_64)

$(OBJS_x86) $(PAYLOAD_OBJ_x86): ASFLAGS+=$(ASFLAGS_x86)
$(OBJS_x86) $(PAYLOAD_OBJ_x86): LDFLAGS+=$(LDFLAGS_x86)

$(OBJDIR)/%.o: $(SRCDIR)/%.S $(HDRS) | $(OBJDIR)
	@mkdir -p '$(@D)'
	@echo "AS $<"
	$(COMPILE.S) $< -o $@


# Binaries
$(PAYLOADS_x86_64): $(BINDIR)/%: $(OBJDIR)/%.o $(PAYLOAD_OBJ_x86_64) $(LIBS) link.ld | $(BINDIR)
	@echo "LD $@"
	$(COMPILE.o) -o $@ $< $(PAYLOAD_OBJ_x86_64) $(LDLIBS)

$(PAYLOADS_x86): $(BINDIR)/%: $(OBJDIR)/%.o $(PAYLOAD_OBJ_x86) $(LIBS) link.ld | $(BINDIR)
	@echo "LD $@"
	$(COMPILE.o) -o $@ $< $(PAYLOAD_OBJ_x86) $(LDLIBS)

# C array header
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


# Cleanup
clean:
	$(foreach dir, $(LIBDIRS),\
		echo "MK $(addprefix -C , $(dir)) $@" && make -C $(dir) $@ ; ):
	rm -r "$(OBJDIR)" 2>/dev/null && echo "RM $(OBJDIR)" || :


# Full cleanup
fclean: clean
	$(foreach dir, $(LIBDIRS),\
		echo "MK $(addprefix -C, $(dir)) $@" && make -C $(dir) $@ ; ):
	rm $(PAYLOADS_x86_64) $(PAYLOADS_x86) 2>/dev/null && echo "RM $(PAYLOADS)" || :
	rm $(NAME) 2>/dev/null && echo "RM $(NAME)" || :


# Build again
re: fclean all


FORCE: ;


.PHONY: clean fclean re FORCE


# Assign a value to VERBOSE to enable verbose output
$(VERBOSE).SILENT:
