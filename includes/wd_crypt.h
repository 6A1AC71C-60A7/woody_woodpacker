
#pragma once

#include <wd_types.h>

#define KCRYPT_OPIMIZE

#define ROTR(x, n) ( ((x) << (n)) | ((x) >> (8 - (n))) )
#define ROTL(x, n) ( ((x) >> (n)) | ((x) << (8 - (n))) )

void	kcrypt(ubyte* const plaintext, uqword plaintext_len, uqword key);

///NOTE: This function will be injected, prototype may change to
/// be able to decrypt several ciphertexts at diferent locations
void	kdecrypt(ubyte* const ciphertext, uqword cyphertext_len, uqword key);
