
#include "wd_error.h"
#include <wd_utils.h>
#include <wd_parse.h>
#include <wd_types.h>
#include <elf.h>
#include <stdio.h>
#include <woody_woodpacker.h>
#include <ftlibc.h>

#include <unistd.h>

#define P_ISTEXT(ph) ((ph).p_type == PT_LOAD && ((ph).p_flags & (PF_X | PF_R)) == (PF_X | PF_R))

static uqword	find_text_segment(Elf64_Phdr const *const ph, const Elf64_Half num)
{
	uqword	i;

	i = 0;
	while (i < num && !P_ISTEXT(ph[i]))
		i++;

	return (i);
}

err_t	prepare_decryptor_x86_64(const elf_map_t *const map, decryptor_t* const decryptor)
{
	const Elf64_Ehdr*	eh = (Elf64_Ehdr*)map->addr;
	const Elf64_Phdr*	ph = (Elf64_Phdr*)(map->addr + eh->e_phoff);
	const uqword		i = find_text_segment(ph, eh->e_phnum);
	err_t				err;

	dprintf(2, "text segment index: %zu, phnum %hu\n", i, eh->e_phnum);
	err = (i <= eh->e_phnum) ? SUCCESS : EARGUMENT;
	if (err == SUCCESS)
	{
		dprintf(2, "text:          offset: %lx, virt addr: %lx, file size: %lx\n",
			ph[i].p_offset, ph[i].p_vaddr, ph[i].p_filesz);

		// Get text segment offset for relocations
		decryptor->segment_index = i;
		decryptor->segment_offset = ph[i].p_offset;

		// Get decryptor offset
		decryptor->offset = ph[i].p_offset + ph[i].p_filesz;
		decryptor->vaddr = ph[i].p_vaddr + ph[i].p_memsz;
	}

	return (err);
}



/**
 * @brief Append the decryptor at the end of woody and modify the entry point to jump on it.
 *
 * @param map The mapped copy of the elf executable file given by the user.
 * @param decryptor The decryptor previously built.
 * @param decryptor_size The lenght in bytes of the decryptor.
 */
void	inject_decryptor_X86_64(elf_map_t* const map, const decryptor_t* const dec)
{
	Elf64_Ehdr *const	header = (Elf64_Ehdr*)map->addr;
	Elf64_Phdr *const	ph = (Elf64_Phdr*)(map->addr + header->e_phoff);
	Elf64_Shdr *const	sh = (Elf64_Shdr*)(map->addr + header->e_shoff);
	uqword				i;

	// Expand text segment
	i = dec->segment_index;
	ph[i].p_filesz += dec->size;
	ph[i].p_memsz += dec->size;

	dprintf(2, "expanded text: offset: %lx, virt addr: %lx, file size: %lx\n",
		ph[i].p_offset, ph[i].p_vaddr, ph[i].p_filesz);

 	if (header->e_phoff >= dec->offset)
	{
		dprintf(2, "relocating phoff\n");
		header->e_phoff += page_size;
	}
	if (header->e_shoff >= dec->offset)
	{
		dprintf(2, "relocating shoff\n");
		header->e_shoff += page_size;
	}

	// Move segements after decryptor_entry
	i = 0;
	while (i < header->e_phnum)
	{
		if (ph[i].p_offset > dec->offset)
		{
			dprintf(2, "relocating segment %zu\n", i);
			ph[i].p_offset += page_size;
		}
		i++;
	}

	// Move sections after text decryptor_entry
	dprintf(2, "shnum: %hu\n", header->e_shnum);
	i = 0;
	while (i < header->e_shnum)
	{
		if (sh[i].sh_offset + sh[i].sh_size == dec->offset)
		{
			dprintf(2, "expanding section %zu %s\n", i, (char*)header + sh[header->e_shstrndx].sh_offset + sh[i].sh_offset);
			sh[i].sh_size += dec->size;
		}
		// if the section data comes after the decriptor
		else if (sh[i].sh_offset >= dec->offset)
		{
			dprintf(2, "relocating section %zu\n", i);
			sh[i].sh_offset += page_size;
		}
		else
			dprintf(2, "ignoring section %zu, offset 0x%04zx, end 0x%04zx\n", i, sh[i].sh_offset, sh[i].sh_offset + sh[i].sh_size);
		i++;
	}

	i = 0;
	while (i < ARRLEN(targets_decrypt))
	{
		if ((uqword)targets_decrypt[i].start >= dec->offset)
			targets_decrypt[i].start += page_size;
		i++;
	}

	dprintf(2, "orig entry point:   0x%zx\n", GET_ELF_ENTRY_POINT_X86_64(header));
	dprintf(2, "relative offset:    -0x%zx\n", dec->vaddr - GET_ELF_ENTRY_POINT_X86_64(header));

	// Set entry to decryptor
	dprintf(2, "setting entry point to 0x%zx\n", dec->vaddr);
	header->e_entry = dec->vaddr;

	ft_memmove((void*)header + dec->offset + page_size, (void*)header + dec->offset, map->size - dec->offset);

	dprintf(2, "injecting payload at 0x%zx, size: %zx\n",  dec->offset, dec->size);
	ft_memcpy((void*)header + dec->offset, dec->data, dec->size);

	map->size += page_size;
}

void	inject_decryptor_X86_64_rev(elf_map_t* const map, ubyte* decryptor, uqword decryptor_size)
{
	Elf64_Ehdr *const	header = (Elf64_Ehdr*)map->addr;
	Elf64_Phdr *const	ph = (Elf64_Phdr*)(map->addr + header->e_phoff);
	Elf64_Shdr *const	sh = (Elf64_Shdr*)(map->addr + header->e_shoff);
	const uqword		rounded_size = PAGE_ROUND(decryptor_size);
	uqword				segment_i = 0;
	uqword				section_i;
	uqword				orig_text_vaddr;
	uqword				text_offset;

	// Find text segment
	while (segment_i < header->e_phnum && !P_ISTEXT(ph[segment_i]))
		segment_i++;

	// TODO: Handle text section not found
	if (segment_i >= header->e_phnum)
		return;

	dprintf(2, "text:          offset: %lx, virt addr: %lx, file size: %lx\n",
		ph[segment_i].p_offset, ph[segment_i].p_vaddr, ph[segment_i].p_filesz);

	orig_text_vaddr = ph[segment_i].p_vaddr;

	// Expand text segment backwards
	ph[segment_i].p_vaddr -= rounded_size;
	ph[segment_i].p_paddr -= rounded_size;
	ph[segment_i].p_filesz += rounded_size;
	ph[segment_i].p_memsz += rounded_size;
	ph[segment_i].p_offset = 0;

	dprintf(2, "expanded text: offset: %lx, virt addr: %lx, file size: %lx\n",
		ph[segment_i].p_offset, ph[segment_i].p_vaddr, ph[segment_i].p_filesz);

	// Get text segment file offset
	text_offset = ph[segment_i].p_offset;

	segment_i = 0;
	// Move offsets after text segment
	while (segment_i < header->e_phnum)
	{
		if (ph[segment_i].p_offset > text_offset)
		{
			dprintf(2, "relocating segment %zu\n", segment_i);
			ph[segment_i].p_offset += rounded_size;
		}
		segment_i++;
	}

	section_i = 0;
	// Move sections after text segment
	while (section_i < header->e_shnum)
	{
		if (sh[section_i].sh_offset > text_offset)
		{
			dprintf(2, "relocating section %zu\n", section_i);
			sh[section_i].sh_offset += rounded_size;
		}
		section_i++;
	}

	GET_ELF_ENTRY_POINT_X86_64(header) = orig_text_vaddr - rounded_size + sizeof(*header);
	dprintf(2, "entry point:        0x%zx\n", header->e_entry);
	dprintf(2, "rounded size:       %zx\n", rounded_size);
	dprintf(2, "original file size: %zx\n",  map->size);
	dprintf(2, "moving from %p to %p (+%zx), size: %zx\n", header + 1, (void*)(header + 1) + rounded_size, rounded_size, map->size - sizeof(*header));
	ft_memmove((void*)(header) + rounded_size, (void*)(header) + text_offset, map->size - sizeof(*header));
	ft_memcpy((void*)(header + 1), decryptor, decryptor_size);


	if (header->e_phoff > text_offset)
	{
		dprintf(2, "relocating phoff\n");
		header->e_phoff += rounded_size;
	}
	if (header->e_shoff > text_offset)
	{
		dprintf(2, "relocating shoff\n");
		header->e_shoff += rounded_size;
	}
	dprintf(2, "shoff: %zu\n", header->e_shoff);
	dprintf(2, "phoff: %zu\n", header->e_phoff);

	map->size += rounded_size;
	dprintf(2, "new size: %zx\n", map->size);
	dprintf(2, "%hhx\n", map->addr[map->size - 1]);
}
