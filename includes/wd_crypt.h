
#pragma once

#include <wd_types.h>

#define KCRYPT_OPIMIZE

#define ROTR(x, n) ( ((x) << (n)) | ((x) >> (8 - (n))) )
#define ROTL(x, n) ( ((x) >> (n)) | ((x) << (8 - (n))) )

uqword	kcrypt_X86_64(ubyte* const plaintext, uqword plaintext_len, uqword key);

void	kdecrypt(const crypt_pair_t* const targets, uqword targets_len, uqword key,
			ubyte* const term_msg, uqword term_msg_len);

void	kdecrypt_asm(const crypt_pair_t* const targets, uqword targets_len, uqword key,
			ubyte* const term_msg, uqword term_msg_len);
