
#include "wd_types.h"
#include <elf.h>
#include <stdio.h>
#include <woody_woodpacker.h>
#include <ftlibc.h>

#include <unistd.h>

#define P_ISTEXT(ph) ((ph).p_type == PT_LOAD && ((ph).p_flags & (PF_X | PF_R)) == (PF_X | PF_R))


/**
 * @brief Append the decryptor at the end of woody and modify the entry point to jump on it.
 * 
 * @param map The mapped copy of the elf executable file given by the user.
 * @param decryptor The decryptor previously built.
 * @param decryptor_size The lenght in bytes of the decryptor.
 */
void	inject_decryptor_X86_64(elf_map_t* const map, ubyte* decryptor, uqword decryptor_size)
{
	Elf64_Ehdr *const	header = (Elf64_Ehdr*)map->addr;
	Elf64_Phdr *const	ph = (Elf64_Phdr*)(map->addr + header->e_phoff);
	Elf64_Shdr *const	sh = (Elf64_Shdr*)(map->addr + header->e_shoff);
	const uqword		rounded_size = PAGE_ROUND(decryptor_size); 
	uqword				segment_i = 0;
	uqword				section_i;
	uqword				text_vaddr;
	uqword				text_offset;

	// Find text segment
	while (segment_i < header->e_phnum && !P_ISTEXT(ph[segment_i]))
		segment_i++;

	// TODO: Handle text section not found
	if (segment_i >= header->e_phnum)
		return;

	dprintf(2, "text:          offset: %lx, virt addr: %lx, file size: %lx\n",
		ph[segment_i].p_offset, ph[segment_i].p_vaddr, ph[segment_i].p_filesz);

	// Expand text segment backwards
	ph[segment_i].p_vaddr -= rounded_size;
	ph[segment_i].p_paddr -= rounded_size;
	ph[segment_i].p_filesz += rounded_size;
	ph[segment_i].p_memsz += rounded_size;
	//ph[segment_i].p_offset = sizeof(*header);

	dprintf(2, "expanded text: offset: %lx, virt addr: %lx, file size: %lx\n",
		ph[segment_i].p_offset, ph[segment_i].p_vaddr, ph[segment_i].p_filesz);

	// Get new text segment virtual address
	text_vaddr = ph[segment_i].p_vaddr;
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

	GET_ELF_ENTRY_POINT_X86_64(header) = text_vaddr;
	dprintf(2, "entry point:        0x%zx\n", header->e_entry);
	dprintf(2, "rounded size:       %zx\n", rounded_size);
	dprintf(2, "original file size: %zx\n",  map->size);
	//dprintf(2, "moving from 0x%zx to 0x%zx (+%zx), size: %zx\n", text_offset, text_offset + rounded_size, rounded_size, map->size - text_offset);
//	ft_memmove((void*)(header + 1) + rounded_size, (void*)(header) + text_offset, map->size - text_offset);
	ft_memmove((void*)map->addr + text_offset + rounded_size, (void*)map->addr + text_offset, map->size - text_offset);
	//dprintf(2, "injecting payload at 0x%zx, size: %zx\n",  text_offset, decryptor_size);
//	ft_memcpy((void*)(header) + text_offset, decryptor, decryptor_size);
	ft_memcpy((void*)map->addr + text_offset, decryptor, decryptor_size);


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
