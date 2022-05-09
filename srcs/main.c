
#include <stdio.h>
#include <wd_error.h>
#include <wd_types.h>
#include <wd_crypt.h>
#include <wd_parse.h>
#include <wd_utils.h>
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
///ENHANCEMENT: 32 bit files management

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
			if ((st = lookup_segments_X86_64(parse, map, targets_crypt, targets_decrypt)) != SUCCESS)
				goto end;
			///TODO: FIND WHY
			// if ((st = lookup_sections_X86_64(parse, map, targets_crypt, targets_decrypt)) != SUCCESS)
			// 	goto end;
			arch->kcrypt = &kcrypt_X86_64;
			arch->prepare_decryptor = &prepare_decryptor_x86_64;
			arch->build_decryptor = &build_decryptor_x86_64;
			arch->inject_decryptor = &inject_decryptor_X86_64;
			break ;
		case ELFCLASS32:
			if (parse->opts & O_32BITADRR)
			{
				map->entry_point = GET_ELF_ENTRY_POINT_X86(map->addr);
				///TODO: lookup_sections_X86
				arch->kcrypt = NULL;
				arch->prepare_decryptor = NULL;
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
static inline err_t	write_woody_file(void* buff, uqword bufflen, udword mode)
{
	const int fd = open("woody", O_CREAT | O_RDWR | O_TRUNC, mode);

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
	err_t 			st = SUCCESS;
	parse_t			parse = {0};
	elf_map_t		map = {0};
	arch_t			arch = {0};
	decryptor_t		decryptor = {0};

	page_size = (uqword)sysconf(_SC_PAGE_SIZE);
	if ((qword)page_size == -1)
	{
		FERROR(EFORMAT_WRAPPER, "sysconf", errno, strerror(errno));
		return (1);
	}
	++av;

	if (ac == 1 || user_asks_for_help(*av) == true)
	{
		display_usage();
		goto end;
	}

	if ((st = parse_opts(&av, &parse)) != SUCCESS
	|| (st = parse_elf(*av, &parse, &map, &arch)) != SUCCESS
	|| (st = handle_key(&parse)) != SUCCESS)
		goto end;

	encrypt_chunks(targets_crypt, parse.key, arch.kcrypt);

	if ((st = arch.prepare_decryptor(&map, &decryptor)) != SUCCESS
	|| (st = arch.build_decryptor(&decryptor, &parse, targets_decrypt, map.entry_point)) != SUCCESS)
		goto end;

	arch.inject_decryptor(&map, &decryptor);

	st = write_woody_file(map.addr, map.size, map.mode);

	// Exit will free all the segments anyway
	free(decryptor.data);
	munmap(map.addr, map.size + MAX_PAYLOAD_SIZE);

end:
	return st;
}
