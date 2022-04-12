
#include <woody_woodpacker.h>
#include <ftlibc.h>

/**
 * @brief Append the decryptor at the end of woody and modify the entry point to jump on it.
 * 
 * @param map The mapped copy of the elf executable file given by the user.
 * @param decryptor The decryptor previously built.
 * @param decryptor_size The lenght in bytes of the decryptor.
 */
void	inject_decryptor_X86_64(elf_map_t* const map, ubyte* decryptor, uqword decryptor_size)
{
	ft_memcpy(map->addr + map->size, decryptor, decryptor_size);

	///TODO: Calculate the address (offset) of the end of the file (where the decryptor will be located)
	GET_ELF_ENTRY_POINT_X86_64(map->addr) = 0x42424242;
}
