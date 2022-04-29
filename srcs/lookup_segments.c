
#include <elf.h>
#include <wd_types.h>
#include <stdio.h>
#include <woody_woodpacker.h>
#include <ftlibc.h>
#include <wd_utils.h>

#include <stdbool.h>

inline static Elf64_Shdr	*find_section(const elf_map_t* map, uqword offset, uqword size, const char *name)
{
	const Elf64_Shdr* const shdr = (void*)(map->addr) + ((Elf64_Ehdr*)map->addr)->e_shoff;
	const char*	shstrtab = (void*)(map->addr) + shdr[((Elf64_Ehdr*)map->addr)->e_shstrndx].sh_offset;

	const uqword count =  ((Elf64_Ehdr*)map->addr)->e_shnum;

	for (uqword i = 0; i < count; i++)
	{
		if (shdr[i].sh_offset >= offset && shdr[i].sh_offset < offset + size)
		{
			if (name == NULL || (shdr[i].sh_name && !ft_strcmp(name, shstrtab + shdr[i].sh_name)))
			{
				dprintf(2, "Found section %s at offset 0x%zx\n", shdr[i].sh_name ? shstrtab + shdr[i].sh_name : NULL, shdr[i].sh_offset);
				return ((void*)(map->addr) + shdr[i].sh_offset);
			}
		}
	}
	return (NULL);
}

/**
 * @brief Fill @p target_crypt and @p target_decrypt arrays
 * with the start address and sizes of the segments to infect.
 *
 * @param in Struct holding data provided by the user.
 * @param map Struct mapping an elf file.
 * @param target_crypt Array of structs that will be filled on return.
 * It takes the mapped address.
 * @param target_decrypt Array of structs that will be filled on return.
 * It takes the executable's section's address.
 */
err_t lookup_segments_X86_64(const parse_t* const in, const elf_map_t* map,
		crypt_pair_t* const target_crypt, crypt_pair_t* const target_decrypt)
{
	/**
	 * NOTE: Compilers can be configured to build PIE (Position Independent Executable)
	 * by default. Which have the type ET_DYN (Shared Object File) instead of ET_EXEC.
	 * This is why both ELF types are valid.
	*/
	if (GET_ELF_TYPE_X86_64(map->addr) != ET_EXEC
	&& GET_ELF_TYPE_X86_64(map->addr) != ET_DYN)
	{
		ERROR(EFORMAT_EXECONLY);
		return EARGUMENT;
	}

	const Elf64_Ehdr* const ehdr = (Elf64_Ehdr*)map->addr;

	///TODO: Read man: If more than 0xff00 indexes something happens
	if (ehdr->e_shstrndx == SHN_UNDEF)
	{
		ERROR(EFORMAT_SECSSTRIPPED);
		return EARGUMENT;
	}

	const Elf64_Phdr* const phdr = (Elf64_Phdr*)&map->addr[ehdr->e_phoff];

	uqword amount = 0;

	for (uqword ph_i = 0 ; ph_i < ehdr->e_phnum ; ph_i++)
	{

		//if (in->opts & O_SELECTSEC && !(in->sections & (1 << y)))
		//	continue;

		if (phdr[ph_i].p_type == PT_LOAD)
		{
			dprintf(2, "Checking flags in segment %zu\n", ph_i);

			if ((phdr[ph_i].p_flags & PF_R) == PF_R
			&& !find_section(map, phdr[ph_i].p_offset, phdr[ph_i].p_filesz, ".interp")
			&& !find_section(map,  phdr[ph_i].p_offset, phdr[ph_i].p_filesz, ".dynamic"))
			{
				dprintf(2, "Found target %zu -> segment %zu at 0x%lx\n",amount,ph_i, phdr[ph_i].p_offset);
				target_crypt[amount].nbytes = target_decrypt[amount].nbytes = phdr[ph_i].p_filesz;
				target_crypt[amount].start = map->addr + phdr[ph_i].p_offset;
				target_decrypt[amount].start = (void*)phdr[ph_i].p_vaddr;
				amount++;
			}
		}
	}
	return SUCCESS;
}
