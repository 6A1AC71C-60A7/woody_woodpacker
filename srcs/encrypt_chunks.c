
#include "wd_parse.h"
#include <stdio.h>
#include <wd_crypt.h>
#include <woody_woodpacker.h>

/**
 * @brief Encrypt all the chunks using key.
 *
 * @param chunks An array of structs holding addresses and sizes to encrypt.
 * @param key The 64 bit encryptation key.
 * @param kcrypt A function pointer used to encrypt which used @p chunks and @p key data.
 */
void	encrypt_chunks(const crypt_pair_t* const chunks, uqword key, kcrypt_t kcrypt)
{
	for (uqword i = 0 ; chunks[i].start ; i++)
	{
		dprintf(2, "Encrypting chunk %zu at %p of length 0x%lx\n", i, chunks[i].start, chunks[i].nbytes);
		targets_decrypt[i].nbytes = kcrypt(chunks[i].start, chunks[i].nbytes, key);
	}
}
