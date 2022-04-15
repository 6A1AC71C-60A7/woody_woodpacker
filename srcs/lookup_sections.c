
#include <stdio.h>
#include <woody_woodpacker.h>
#include <ftlibc.h>
#include <wd_utils.h>

#include <stdbool.h>

/**
 * @brief Fill @p target_crypt and @p target_decrypt arrays
 * with the start address and sizes of the sections to infect.
 * 
 * @param in Struct holding data provided by the user.
 * @param map Struct mapping an elf file.
 * @param target_crypt Array of structs that will be filled on return.
 * It takes the mapped address.
 * @param target_decrypt Array of structs that will be filled on return.
 * It takes the executable's section's address.
 */
err_t lookup_sections_X86_64(const parse_t* const in, const elf_map_t* map,
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

	const Elf64_Shdr* const shdr = (Elf64_Shdr*)&map->addr[ehdr->e_shoff];
	dprintf(2, "map->addr: %p, shdr: %p, ehdr: %p size: %lu\n", map->addr, shdr, ehdr, shdr[ehdr->e_shstrndx].sh_offset);
	const ubyte* const section_names = &map->addr[shdr[ehdr->e_shstrndx].sh_offset];

	uqword amount = 0;

	for (uqword i = 1 ; i < ehdr->e_shnum ; i++)
	{
		static const char* const tofind[] = {
			".rodata",
			".data",
			".text"
		};

		for (uqword y = 0 ; y < ARRLEN(tofind) ; y++)
		{
			if (ft_strcmp(tofind[y], (const char*)&section_names[shdr[i].sh_name]) == 0)
			{
				if (in->opts & O_SELECTSEC && !(in->sections & (1 << y)))
					continue;

				target_crypt[amount].nbytes = target_decrypt[amount].nbytes = shdr[i].sh_size;
				target_crypt[amount].start = map->addr + shdr[i].sh_offset;
				target_decrypt[amount].start = (void*)shdr[i].sh_addr;
				amount++;
			}
		}

	}
	return SUCCESS;
}
