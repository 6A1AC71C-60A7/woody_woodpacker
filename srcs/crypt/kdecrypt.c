
#include <wd_crypt.h>

///NOTE: Just for testing, i need the opcodes raw not the code in C
void	kdecrypt(ubyte* const plaintext, uqword plaintext_len, uqword key)
{
	const ubyte* const bkey = (ubyte*)&key;

	for (uqword offset = 0 ; offset < plaintext_len ; offset++)
	{
		plaintext[offset] -= bkey[offset % sizeof(key)];
		plaintext[offset] = ROTL(plaintext[offset], offset % sizeof(key));
		plaintext[offset] = ~plaintext[offset];
		plaintext[offset] ^= bkey[offset % sizeof(key)];
	}
}
