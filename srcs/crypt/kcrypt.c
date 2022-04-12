
#include <wd_crypt.h>

/**
 * @brief A cipher algorithm.
 * 
 * @param plaintext A pointer to the data to be encrypted.
 * @param plaintext_len The lenght in bytes of the data to be encrypted.
 * @param key 64 bit key used for encryption/decryption.
 */
void	kcrypt_X86_64(ubyte* const plaintext, uqword plaintext_len, uqword key)
{
#ifndef KCRYPT_OPIMIZE

	const ubyte* const bkey = (ubyte*)&key;

	for (uqword offset = 0 ; offset < plaintext_len ; offset++)
	{
		plaintext[offset] ^= bkey[offset % sizeof(key)];
		plaintext[offset] = ~plaintext[offset];
		plaintext[offset] = ROTR(plaintext[offset], offset % sizeof(key));
		plaintext[offset] += bkey[offset % sizeof(key)];
	}

#else

	__asm__ volatile (

		/* %r8 is the plaintext's offset */
		"xor %%r8, %%r8\n"

		/* %rdi = plaintext ; %rsi = &key */
		"mov %0, %%rdi\n"
		"lea %2, %%rsi\n"

		"encrypt_byte%=:\n"

		/* %rdx = offset % 8 (offset & 7 is faster) */
		"mov %%r8, %%rdx\n"
		"and $7, %%rdx\n"

		/* %r11b = ((*ubyte)&key)[offset % 8] */
		"movb (%%rsi,%%rdx,1), %%r11b\n"

		/* plaintext[offset] ^= ((*ubyte)&key)[offset % 8] */
		"xorb %%r11b, (%%rdi,%%r8,1)\n"

		/* plaintext[offset] = ~plaintext[offset] */
		"notb (%%rdi,%%r8,1)\n"

		/* #define ROTR(x, n) ( ((x) << (n)) | ((x) >> (8 - (n))) ) */
		/* %r9 = x << n */
		"movb %%dl, %%cl\n"
		"movb (%%rdi,%%r8,1), %%r9b\n"
		"shlb %%cl, %%r9b\n"
		/* %rcx = 8 - n */
		"movb $8, %%r10b\n"
		"subb %%dl, %%r10b\n"
		"movb %%r10b, %%cl\n"
		/* %r10 = x >> (8 - n) */
		"movb (%%rdi,%%r8,1), %%r10b\n"
		"shrb %%cl, %%r10b\n"
		/* %r10 |= %r9 */
		"orb %%r9b, %%r10b\n"

		/* plaintext[offset] = %r10 */
		"movb %%r10b, (%%rdi,%%r8,1)\n"	

		/* plaintext[offset] += ((*ubyte)&key)[offset % 8] */
		"addb %%r11b, (%%rdi,%%r8,1)\n"

		/* offset++ */
		"inc %%r8\n"

		/* if (offset < plaintext_len) goto encrypt_byte */
		"cmp %1, %%r8\n"
		"jb encrypt_byte%=\n"

		:
		: "g" (plaintext), "g" (plaintext_len), "g" (key)
		: "rdi", "rsi", "rcx", "rdx", "r8", "r9", "r10", "r11", "cc"
	);

#endif
}
