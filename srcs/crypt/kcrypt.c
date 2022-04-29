
#include <stdio.h>
#include <wd_crypt.h>

/**
 * @brief A cipher algorithm.
 *
 * @param plaintext A pointer to the data to be encrypted.
 * @param plaintext_len The lenght in bytes of the data to be encrypted.
 * @param key 64 bit key used for encryption/decryption.
 */
uqword	kcrypt_X86_64(ubyte* const plaintext, uqword plaintext_len, uqword key)
{
#ifndef KCRYPT_OPIMIZE

	const ubyte* const bkey = (ubyte*)&key;

	for (uqword offset = 0 ; offset < plaintext_len ; offset++)
	{
		char key_c = bkey[offset % sizeof(key)];

		plaintext[offset] ^= key_c;
		plaintext[offset] = ~plaintext[offset];
		plaintext[offset] = ROTR(plaintext[offset], offset % sizeof(key));
		plaintext[offset] += key_c;
	}

#else
	uqword	ret;

	__asm__ volatile (

		/* %r8 = data_offset */
		"xor %%r8, %%r8\n"

		/* %rax = count_iterator */
		"xor %[ret], %[ret]\n"

		/* %rdi = plaintext ; %rsi = &key */
		"mov %[plain_text], %%rdi\n"
		"lea %[key], %%rsi\n"

		"encrypt_byte%=:\n"

		/* cipher_char: r10b = plain_text[data_offset]*/
		"movb (%%rdi,%%r8,1), %%r10b\n"

		/* if cipher_char == '\0' goto skip_byte */
//		"testb %%r10b, %%r10b\n"
//		"jz skip_byte%=\n"

		/* %rdx = key_offset = count_offset % 8 */
		"mov %[ret], %%rdx\n"
		"and $7, %%rdx\n"

		/* count_iterator++ */
		"inc %[ret]\n"

		/* key_char: r9b = key_str[key_offset] */
		"movb (%%rsi,%%rdx,1), %%r9b\n"

		// /* cipher_char ^= key_char */
		// "xorb $2, %%r10b\n"

		// /* cipher_char = ~cipher_char */
		"notb %%r10b\n"

		// /* ROTR(cipher_char, key_offset) */
		// "movb %%dl, %%cl\n"
		// "rorb %%cl, %%r10b\n"

		// /* cipher_char += key_char */
		//"addb %%r9b, %%r10b\n"

		// /* plain_text[data_offset] = cipher_char */
		"movb %%r10b, (%%rdi,%%r8,1)\n"

		"skip_byte%=:\n"

		/* data_offset++ */
		"inc %%r8\n"

		/* if (offset < plaintext_len) goto encrypt_byte */
		"cmp %[len], %%r8\n"
		"jb encrypt_byte%=\n"

		: [ret] "=r" (ret)
		: [plain_text] "g" (plaintext), [len] "g" (plaintext_len), [key] "g" (key)
		: "rdi", "rsi", "rcx", "rdx", "r8", "r9", "r10", "r11", "cc"
	);


#endif
	dprintf(2, "kcrypt: in %zu, initialized chars %zu\n", plaintext_len, ret);
	return (ret);
}
