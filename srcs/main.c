
#include "wd_error.h"
#include "wd_types.h"
#include <wd_crypt.h>
#include <wd_parse.h>
#include <ftlibc.h>
#include <woody_woodpacker.h>

#include <stdlib.h> // free
#include <errno.h> // errno
#include <fcntl.h> // open
#include <unistd.h> // write
#include <stdbool.h> // bool
#include <string.h> // strerror
#include <sys/mman.h> // nunmap
#include <sys/syscall.h>

#define DISPLAY_KEY(key) fprintf(stdout, "key_value: %016"PRIXq"\n", key)

///TODO: Endianless must be handled
///TODO: Restore mapping protections after decryption
///ENHANCEMENT: Size check to avoid segfault on corrupted ELF files
///ENHANCEMENT: Error check for stripped ELF files (no symbols)
///NOTE: For the moment i'll treat the EP like an offset
///TODO: Inject the decryptor (after ending the TODO of 'inject_decryptor.c' and 'build_decryptor.c')
///TODO: 32 bits files handling

__attribute__ ((always_inline))
static inline bool user_asks_for_help(const char* s)
{ return ft_strncmp(s, "--help", sizeof("--help")) == 0; }

__attribute__ ((always_inline))
static inline void display_usage()
{ ERROR(MSG_USAGE); }

__attribute__ ((always_inline))
static inline err_t handle_key(parse_t* const parse)
{
	if (!(parse->opts & O_CUSTOMKEY) && (parse->key = genkey()) == 0)
	{
		FERROR(EFORMAT_SYSCALL, "getrandom", errno, strerror(errno));
		return EWRAPPER;
	}
	DISPLAY_KEY(parse->key);
	return SUCCESS;
}

__attribute__ ((always_inline))
static inline err_t parse_elf(const char* filename, parse_t* const parse,
		elf_map_t* const map, arch_t* const arch)
{
	err_t st = map_elf(filename, map);

	if (st != SUCCESS)
		goto end;

	if (map->endianess == ELFDATANONE)
	{
		FERROR(EFORMAT_UNKNEND, filename);
		st = EARGUMENT;
		goto end;
	}

	switch (map->arch)
	{
		case ELFCLASS64:
			map->entry_point = GET_ELF_ENTRY_POINT_X86_64(map->addr);
			if ((st = lookup_sections_X86_64(parse, map, targets_crypt, targets_decrypt)) != SUCCESS)
				goto end;
			arch->kcrypt = &kcrypt_X86_64;
			arch->build_decryptor = &build_decryptor_x86_64;
			arch->inject_decryptor = &inject_decryptor_X86_64;
			break ;
		case ELFCLASS32:
			if (parse->opts & O_32BITADRR)
			{
				map->entry_point = GET_ELF_ENTRY_POINT_X86(map->addr);
				///TODO: lookup_sections_X86
				arch->kcrypt = NULL;
				arch->build_decryptor = NULL;
				arch->inject_decryptor = NULL;
				break ;
			}
			// fall through
		default:
			FERROR(EFORMAT_INVARCH, parse->opts & O_32BITADRR ? "X86 or X86_64" : "X86_64");
			st = EARGUMENT;
			goto end;
	}

end:
	return st;
}

__attribute__ ((always_inline))
static inline err_t	write_woody_file(void* buff, uqword bufflen)
{
	const int fd = open("woody", O_CREAT | O_RDWR, S_IRWXU);

	if (fd < 0)
	{
		FERROR(EFORMAT_WRAPPER, "open", errno, strerror(errno));
		return EWRAPPER;
	}

	const ssize_t nbytes = write(fd, buff, bufflen);

	if (nbytes < (ssize_t)bufflen)
	{
		if (nbytes < 0)
			FERROR(EFORMAT_WRAPPER, "write", errno, strerror(errno));
		else
			ERROR(__progname ": error: partial write to woody ... Try again.\n");
		dprintf(2, "nbytes: %zx\n", nbytes);
		return EWRAPPER;
	}
	return SUCCESS;
}

crypt_pair_t	targets_crypt[PAIRARR_LEN];
crypt_pair_t	targets_decrypt[PAIRARR_LEN];

uqword			page_size = 0;

int main(int ac, const char* av[])
{
	err_t 	st = SUCCESS;
	parse_t	parse = {0};
	elf_map_t map = {0};
	arch_t	arch = {0};

	page_size = (uqword)sysconf(_SC_PAGE_SIZE);
	if ((qword)page_size == -1)
	{
		FERROR(EFORMAT_WRAPPER, "sysconf", errno, strerror(errno));
		return (1);
	}
	ubyte*	decryptor;
	uqword	decryptor_size;

	++av;

	///NOTE: Uncomment for decryption and/or payload testing
	//test_crypt_payload();
	//test_crypt();	
//return 0;

	if (ac == 1 || user_asks_for_help(*av) == true)
	{
		display_usage();
		goto end;
	}

	///TODO: Join these 'if's in a single one if i will never call freeing routines (munmap & free)

	if ((st = parse_opts(&av, &parse)) != SUCCESS)
		goto end;

	if ((st = parse_elf(*av, &parse, &map, &arch)) != SUCCESS)
		goto end;

	if ((st = handle_key(&parse)) != SUCCESS)
		goto end;

	///TODO: Decryptor must start pushing the true value of the EP for be able to return to it at the end
	if ((st = arch.build_decryptor(&decryptor, &parse, targets_decrypt, &decryptor_size, map.entry_point)) != SUCCESS)
		goto end;

	arch.inject_decryptor(&map, decryptor, decryptor_size);

	///TODO: Decryptor isn't right yet, so this makes woody crash ...
	encrypt_chunks(targets_crypt, parse.key, arch.kcrypt);

	write_woody_file(map.addr, map.size);

	///TODO: In this situation freeing is irelevant, but if i'll do it anyways i have to handle all the cases ...
	free(decryptor);
	munmap(map.addr, map.size + MAX_PAYLOAD_SIZE);

end:
	return st;
}
