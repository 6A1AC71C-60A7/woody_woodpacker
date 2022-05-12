#include "wd_error.h"
#include <wd_utils.h>
#include <wd_parse.h>
#include <wd_types.h>
#include <elf.h>
#include <stdio.h>
#include <woody_woodpacker.h>
#include <ftlibc.h>

#include <unistd.h>

uqword	find_segment(Elf64_Phdr const *const ph, const Elf64_Half num,
	const Elf64_Word type)
{
	uqword	i;

	for (i = 0; i < num && ph[i].p_type != type; i++);

	return (i);
}

uqword	find_text_segment(Elf64_Phdr const *const ph, const Elf64_Half num)
{
	uqword	i;

	for (i = 0; i < num && !P_ISTEXT(ph[i]); i++);

	return (i);
}

inline static void	relocate_segments(Elf64_Ehdr* const eh, const uqword offset,
	const uqword size)
{
	Elf64_Phdr *const	ph = (void*)eh + eh->e_phoff;

	for (uqword i = 0; i < eh->e_phnum; i++)
	{
		if (ph[i].p_offset > offset)
		{
			dprintf(2, "relocating segment %zu offset %zu -> %zu\n",
				i, ph[i].p_offset, ph[i].p_offset + size);
			ph[i].p_offset += size;
		}
	}
}

inline static void	relocate_sections(Elf64_Ehdr* const eh, const uqword offset,
	const uqword size)
{
	Elf64_Shdr *const	sh = (void*)eh + eh->e_shoff;
	const char*			sh_name = (char*)eh + sh[eh->e_shstrndx].sh_offset;
	const char*			name;

	for (uqword i = 0; i < eh->e_shnum; i++)
	{
		name = sh_name + sh[i].sh_name;
		if (sh[i].sh_offset + sh[i].sh_size == offset)
		{
			dprintf(2, "expanding section %zu %s, size 0x%04zx -> 0x%04zx\n", i, name, sh[i].sh_size, sh[i].sh_size + size);
			sh[i].sh_size += size;
		}
		// if the section data comes after the decriptor
		else if (sh[i].sh_offset >= offset)
		{
			dprintf(2, "relocating section %zu %s, offset 0x%04zx -> 0x%04zx\n", i, name, sh[i].sh_offset, sh[i].sh_offset + size);
			sh[i].sh_offset += size;
		}
		else
			dprintf(2, "ignoring section %zu, offset 0x%04zx, end 0x%04zx\n", i, sh[i].sh_offset, sh[i].sh_offset + sh[i].sh_size);
	}
}

inline static void	relocate_headers(Elf64_Ehdr* const eh, const uqword offset,
	const uqword size)
{
 	if (eh->e_phoff >= offset)
	{
		dprintf(2, "relocating phoff\n");
		eh->e_phoff += size;
	}
	if (eh->e_shoff >= offset)
	{
		dprintf(2, "relocating shoff\n");
		eh->e_shoff += size;
	}
}

inline static void	expand_segment(Elf64_Ehdr* const eh, uqword *const filesize,
	const uqword i, const uqword size)
{
	Elf64_Phdr *const	seg = (Elf64_Phdr*)((void*)eh + eh->e_phoff) + i;
	const uqword		offset = seg->p_offset + seg->p_filesz;

	// Increase segment data size
	seg->p_filesz += size;
	seg->p_memsz += size;

	dprintf(2, "expanding segment of size %zu\n", size);
	dprintf(2, "expanded segment %zu: offset: %lx, virt addr: %lx, file size: %lx\n",
		i, seg->p_offset, seg->p_vaddr, seg->p_filesz);

	// Fix segment and section pointers
	relocate_segments(eh, offset, size);
	relocate_sections(eh, offset, size);

	// Fix elf header pointers
	relocate_headers(eh, offset, size);

	// Move memory following expanded segment
	ft_memmove((void*)eh + offset + size, (void*)eh + offset, *filesize - offset);

	// Update filesize
	*filesize += size;
}

/**
 * @brief Append the decryptor at the end of woody and modify the entry point to jump on it.
 *
 * @param map				Mapped copy of the elf executable file.
 * @param decryptor			Previously built decryptor.
 * @param decryptor_size	Decryptor size in bytes.
 */
void	inject_decryptor_X86_64(elf_map_t* const map, const decryptor_t* const dec)
{
	Elf64_Ehdr *const	eh = (Elf64_Ehdr*)map->addr;

	expand_segment(eh, &map->size, dec->segment_index, page_size);

	dprintf(2, "injecting payload at 0x%zx, size: %zx\n",  dec->offset, dec->size);
	ft_memcpy((void*)eh + dec->offset, dec->data, dec->size);

	dprintf(2, "orig entry point:   0x%zx\n", eh->e_entry);
	dprintf(2, "relative offset:    -0x%zx\n", dec->vaddr - eh->e_entry);

	// Set entry to decryptor
	dprintf(2, "setting entry point to 0x%zx\n", dec->vaddr);
	eh->e_entry = dec->vaddr;
}

