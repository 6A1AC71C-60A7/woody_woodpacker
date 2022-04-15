
#include <wd_crypt.h>

#include <stdbool.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/syscall.h>

/* int test(uqword a, uqword b, uqword c)
{
	#include <stdio.h>
	printf("CALL: %"PRIXq", %"PRIXq", %"PRIXq"\n", a, b, c);
	return 0;
}
 */
/**
 * @brief Decrypts multiple chunks of data. Afterwards decrypts the
 * termination msg and print it on stdout.
 *
 * @param targets An array of chunks (pairs of address:lenght).
 * @param targets_len The total amount of chunks.
 * @param key The decryption key.
 * @param term_msg The encrypted termination msg.
 * @param term_msg_len The lenght of the termination msg.
 */
void	kdecrypt(const crypt_pair_t* const targets, uqword targets_len, uqword key,
			ubyte* const term_msg, uqword term_msg_len)
{
	/** NOTE: This function is never used, is just an abstraction of the decryptor
	 *  that will be injected. Even if this function and its injected version
	 *  shares most of the logic, there some diferences. The injected one doesn't
	 *  have parameters, instead, the data is hardcoded on the stack using 'push'
	 *  instructions.
	 *  The stack looks like this at the beginning of the execution:
	 *
	 *  +-------------------+
	 *  |     term_msg      | <----- Bottom of the stack
	 *  +-------------------+
	 *  |     decrypt key   |
	 *  +-------------------+
	 *  |     nbytes [N-1]  |        - 'term_msg' is the ". . . .WOODY. . . ." string
	 *  +-------------------+        - 'nbytes' is the lenght in bytes of a chunk
	 *  |     address [N-1]	|        - 'address' is the start address of a chunk
	 *  +-------------------+        - 'N' is the number of chunks (targets_len)
	 *  |        ...        |
	 *  +-------------------+
	 *  |     nbytes [0]    |
	 *  +-------------------+
	 *  |     address [0]   |
	 *  +-------------------+
	 *  |         N         | <----- Top of the stack
	 *  +-------------------+
	*/

	const ubyte* const bkey = (ubyte*)&key;
	ubyte*	ciphertext;
	uqword	ciphertext_len;
	uqword n = 0;

	for ( ; n < targets_len ; n++)
	{
		ciphertext = targets[n].start;
		ciphertext_len = targets[n].nbytes;
		mprotect(ciphertext, ciphertext_len, PROT_READ | PROT_WRITE | PROT_EXEC);
decrypt:
		for (uqword offset = 0 ; offset < ciphertext_len ; offset++)
		{
			ciphertext[offset] -= bkey[offset % sizeof(key)];
			ciphertext[offset] = ROTL(ciphertext[offset], offset % sizeof(key));
			ciphertext[offset] = ~ciphertext[offset];
			ciphertext[offset] ^= bkey[offset % sizeof(key)];
		}
	}

	if (n == targets_len)
	{
		n++;
		ciphertext = term_msg;
		ciphertext_len = term_msg_len;
		goto decrypt;
	}

	write(STDOUT_FILENO, term_msg, term_msg_len);
}

/**
 * This function does almost the same than its C equivalent (below). The main diference is that
 * data is truly pushed on the stack in the same way the injected code do (same logic for prepare the stack).
 * NOTE: The term msg must be {'.', ' ', '.', '\\n', 0, 0, 0, 0, 'O', 'O', 'D', 'Y', '.', ' ', '.', ' ', '.', ' ', '.', ' ', '.', ' ', '.', 'W'}
 * to display ". . . .WOODY. . . ." (lenght is 24). This is why is pushed on the stack on reverse order.
 * The term msg must be encrypted with the key.
 * TODO: The injected instructions must be exactly the same but the jumps must be relative (PIC).
*/
void	kdecrypt_asm(const crypt_pair_t* const targets, uqword targets_len, uqword key,
			ubyte* const term_msg, uqword term_msg_len)
{
	__asm__ volatile(

		//////////////////////////////////
		/// *** PREPARE THE  STACK *** ///
		//////////////////////////////////

		/* GCC copy the arguments to the stack, but doesn't increment %rsp, i've to do it */
		"sub $40, %%rsp\n"

		/* %rax = number of qwords of term_msg (term_msg_len / 8) */
		"mov %4, %%rax\n"
		"mov $8, %%r8\n"
		"xor %%rdx, %%rdx\n" 
		"idiv %%r8\n"

		/* push %rax times the term_msg to the stack */
		"mov %3, %%r9\n"
		"xor %%r8, %%r8\n"
		"push_term_msg_byte%=:\n"
		"push (%%r9, %%r8, 8)\n"
		"inc %%r8\n"
		"cmp %%rax, %%r8\n"
		"jb push_term_msg_byte%=\n"

		/* push the 64 bit key to the stack */
		"push %2\n"

		/* %rax = N * 2 (targets_len * 2).
		Each chunk is a struct of 16 bytes, thats why the multiplication by 2 */
		"mov $2, %%r9\n"
		"mov %1, %%rax\n"
		"imul %%r9, %%rax\n"

		/* push %rax times the start address and nbytes */
		"xor %%r8, %%r8\n"
		"mov %0, %%r9\n"
		"push_chunks_data%=:\n"
		"push (%%r9, %%r8, 8)\n"
		"inc %%r8\n"
		"cmp %%rax, %%r8\n"
		"jb push_chunks_data%=\n"

		/* push the number of chunks (N) */
		"push %1\n"

		/////////////////////////////////////
		// *** START OFF INJECTED CODE *** //
		/////////////////////////////////////

		/* %rax = N */
		"pop %%rax\n"

		/* %rdi = &key */
		"mov $2, %%r9\n"
		"push %%rax\n"
		"imul %%r9, %%rax\n"
		"lea (%%rsp, %%rax, 8), %%rdi\n" // %rdi points to the first chunk 'nbytes' field
		"add $8, %%rdi\n" // %rdi points to the key
		"pop %%rax\n"

		/* %r10 is the counter of %rax (N) */
		"xor %%r10, %%r10\n"

		"decrypt_chunk%=:\n"

		/* %r11 = nbytes ; %rsi = start */
		"pop %%r11\n"
		"pop %%rsi\n"

		/* Set RWX protection on the target address' segment */
		"push %%rdi\n"
		"push %%rsi\n"
		"push %%rdx\n"
		"push %%rax\n"
		"push %%rcx\n"
		"push %%r11\n"
		"pushfq\n"
		"mov %%rsi, %%rdi\n"
		"mov %%r11, %%rsi\n"
		"movl $7, %%edx\n"
		"mov $10, %%rax\n"
		"syscall\n"
		"popfq\n"
		"pop %%r11\n"
		"pop %%rcx\n"
		"pop %%rax\n"
		"pop %%rdx\n"
		"pop %%rsi\n"
		"pop %%rdi\n"

		"decrypt_term_msg%=:\n"

		/* Save counter of N */
		"push %%r10\n"

		/* chunk c offset = 0 */
		"xor %%r8, %%r8\n"

		"decrypt_byte%=:\n"

		/* %rdx = offset % 8 (offset & 7 is faster) */
		"mov %%r8, %%rdx\n"
		"and $7, %%rdx\n"

		/* %r9b = ((*ubyte)&key)[offset % 8] */
		"movb (%%rdi,%%rdx,1), %%r9b\n"

		/* ciphertext[offset] -= ((*ubyte)&key)[offset % 8] */
		"subb %%r9b, (%%rsi, %%r8, 1)\n"

		/* #define ROTL(x, n) ( ((x) >> (n)) | ((x) << (8 - (n))) ) */
		/* Save local tmp registers */
		"push %%r9\n"
		"push %%r11\n"
		/* %r9 = x >> n */
		"movb %%dl, %%cl\n"
		"movb (%%rsi, %%r8, 1), %%r9b\n"
		"shrb %%cl, %%r9b\n"
		/* %rcx = 8 - n) */
		"movb $8, %%r12b\n"
		"subb %%dl, %%r12b\n"
		"movb %%r12b, %%cl\n"
		/* %r12 = x << (8 - n) */
		"movb (%%rsi, %%r8, 1), %%r12b\n"
		"shlb %%cl, %%r12b\n"
		/* %r12 |= %r9 */
		"orb %%r9b, %%r12b\n"
		/* Restore local tmp registers */
		"pop %%r11\n"
		"pop %%r9\n"

		/* ciphertext[offset] = %r12 */
		"movb %%r12b, (%%rsi, %%r8, 1)\n"

		/* ciphertext[offset] = ~ciphertext[offset] */
		"notb (%%rsi, %%r8, 1)\n"

		/* ciphertext[offset] ^= ((*ubyte)&key)[offset % 8] */
		"xorb %%r9b, (%%rsi, %%r8, 1)\n"

		/* offset++ */
		"inc %%r8\n"

		/* if (offset < ciphertext_len) goto decrypt_byte */
		"cmp %%r11, %%r8\n"
		"jb decrypt_byte%=\n"

		/* Restore counter of N ; then iterate */
		"pop %%r10\n"
		"inc %%r10\n"

		/* if (counter of N < N) goto decrypt_chunk */
		"cmp %%rax, %%r10\n"
		"jb decrypt_chunk%=\n"

		/* Decrypt termination msg once at the end */
		"cmp %%rax, %%r10\n"
		"jne end%=\n"
		"inc %%r10\n"
		"push %%r10\n"
		"mov $1, %%r10\n"
		"lea (%%rdi, %%r10, 8), %%rsi\n"
		"pop %%r10\n"
		"mov %4, %%r11\n"
		"jmp decrypt_term_msg%=\n"

		/* Write on stdout the termination msg */
		"end%=:\n"
		"mov $1, %%rax\n"
		"mov $1, %%rdi\n"
		"mov %4, %%rdx\n"
		"syscall\n"

		/* Reset the stack: 5 arguments (40bytes) + the key (8 bytes) + term string (24bytes) */
		"add $72, %%rsp\n"

		:
		: "g" (targets), "g" (targets_len), "g" (key), "g" (term_msg), "g" (term_msg_len)
		: "rdi", "rsi", "rcx", "rdx", "rax", "r8", "r9", "r10", "r11", "r12", "cc"
	);
}
