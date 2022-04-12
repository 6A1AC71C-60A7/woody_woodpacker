
#pragma once

#include <wd_types.h>
#include <wd_error.h>
#include <elf.h>

#define MAX_PAYLOAD_SIZE 512UL

#define IS_ELF(x) ((x)[EI_MAG0] == 0x7f && (x)[EI_MAG1] == 'E' && (x)[EI_MAG2] == 'L' && (x)[EI_MAG3] == 'F')
#define GET_ELF_ARCH(x) ((x)[EI_CLASS])
#define GET_ELF_ENDIANESS(x) ((x)[EI_DATA])
#define GET_ELF_VERSION(x) ((x)[EI_VERSION])

#define GET_ELF_TYPE_X86_64(x) (((Elf64_Ehdr*)(x))->e_type)
#define GET_ELF_ENTRY_POINT_X86_64(x) (((Elf64_Ehdr*)(x))->e_entry)

#define GET_ELF_TYPE_X86(x) (((Elf32_Ehdr*)(x))->e_type)
#define GET_ELF_ENTRY_POINT_X86(x) (((Elf32_Ehdr*)(x))->e_entry)

typedef struct		elf_map
{
	ubyte*			addr;
	uqword			size;
	uqword			entry_point;
	ubyte			endianess;
	ubyte			arch;
}					elf_map_t;

typedef err_t (*build_decryptor_t)(ubyte** const dest, const parse_t* const in,
		const crypt_pair_t* const targets, uqword* const size);

typedef void (*kcrypt_t)(ubyte* const plaintext, uqword plaintext_len, uqword key);

typedef void (*inject_decryptor_t)(elf_map_t* const map, ubyte* decryptor, uqword decryptor_size);

typedef struct		arch
{
	build_decryptor_t	build_decryptor;
	kcrypt_t			kcrypt;
	inject_decryptor_t	inject_decryptor;
}					arch_t;

uqword	genkey();
err_t	map_elf(const char* filename, elf_map_t* const map);

err_t	lookup_sections_X86_64(const parse_t* const in, const elf_map_t* map,
		crypt_pair_t* const target_crypt, crypt_pair_t* const target_decrypt);
err_t	build_decryptor_x86_64(ubyte** const dest, const parse_t* const in,
		const crypt_pair_t* const targets, uqword* const size);
void	inject_decryptor_X86_64(elf_map_t* const map, ubyte* decryptor, uqword decryptor_size);

void	encrypt_chunks(const crypt_pair_t* const chunks, uqword key, kcrypt_t kcrypt);

void	test_crypt();
void	test_crypt_payload();
