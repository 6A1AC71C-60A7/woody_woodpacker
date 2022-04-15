
#include "wd_types.h"
#include <elf.h>
#include <woody_woodpacker.h>
#include <ftlibc.h>

#include <unistd.h>

#define P_ISTEXT(ph) ((ph).p_type != PT_LOAD && ((ph).p_flags & (PF_X | PF_R)) == (PF_X | PF_R))


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
	const uqword		rounded_size = PAGE_ROUND(decryptor_size); 
	uqword				i = 0;
	uqword				text_vaddr;
	uqword				text_offset;

	while (i < header->e_phnum && !P_ISTEXT(ph[i]))
		i++;

	ph[i].p_vaddr -= rounded_size;
	ph[i].p_paddr -= rounded_size;
	ph[i].p_filesz += rounded_size;
	ph[i].p_memsz += rounded_size;

	text_vaddr = ph[i].p_vaddr + sizeof(Elf64_Ehdr);
	text_offset = ph[i].p_offset;

	i = 0;
	while (i < header->e_phnum)
	{
		if (ph[i].p_offset > text_offset)
			ph[i].p_offset += rounded_size;
		i++;
	}

	GET_ELF_ENTRY_POINT_X86_64(header) = text_vaddr;
	header->e_phoff += rounded_size;
	ft_memmove(header + 1 + rounded_size, header + 1, map->size - sizeof(*header));
	ft_memcpy(header + 1, decryptor, decryptor_size);

	header->e_phoff += rounded_size;
	header->e_shoff += rounded_size;
}
