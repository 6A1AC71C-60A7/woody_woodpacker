
#include <stdio.h>
#include <wd_types.h>
#include <wd_error.h>
#include <woody_woodpacker.h>

#include <stdbool.h>
#include <fcntl.h> // open
#include <errno.h> // errno
#include <string.h> // strerror
#include <sys/mman.h> // mmap
#include <sys/syscall.h> // SYS_fstat
#include <sys/stat.h> // S_ISREG
#include <unistd.h> // syscall

__attribute__ ((always_inline))
static inline err_t	validate_file(const char* filename, int* const fd, uqword* const file_size, udword* const mode)
{
	err_t st = SUCCESS;
	struct stat buff;

	if ((*fd = open(filename, O_RDONLY)) < 0)
	{
		FERROR(EFORMAT_WRAPPER, "open", errno, strerror(errno));
		st = EWRAPPER;
		goto error;
	}

	#ifndef __APPLE__
	if ((errno = syscall(SYS_fstat, *fd, &buff)) < 0)
	#else
	if (fstat(*fd, &buff) != 0)
	#endif
	{
		FERROR(EFORMAT_SYSCALL, "fstat", errno, strerror(errno));
		st = EWRAPPER;
		goto error;
	}

	if (S_ISREG(buff.st_mode) == 0)
	{
		FERROR(EFORMAT_NOTAFILE, filename);
		st = EARGUMENT;
		goto error;
	}

	*file_size = buff.st_size;
	*mode = buff.st_mode;
	debug("file size: %zx\n", buff.st_size);

error:
	return st;
}

__attribute__ ((always_inline))
static inline err_t	validate_format(elf_map_t* map)
{
	if (IS_ELF(map->addr) == false)
	{
		ERROR(EFORMAT_INVFORM);
		goto error;
	}

	if (GET_ELF_VERSION(map->addr) == EV_NONE)
	{
		ERROR(EFORMAT_VERDEP);
		goto error;
	}

	map->arch = GET_ELF_ARCH(map->addr);
	map->endianess = GET_ELF_ENDIANESS(map->addr);

	return SUCCESS;

error:
	return EARGUMENT;
}

err_t	map_elf(const char* filename, elf_map_t* const map)
{
	err_t st = SUCCESS;
	int fd;

	if ((st = validate_file(filename, &fd, &map->size, &map->mode)) != SUCCESS)
		return st;

	if ((map->addr = mmap(NULL, map->size + page_size, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0)) == MAP_FAILED)
	{
		FERROR(EFORMAT_WRAPPER, "mmap", errno, strerror(errno));
		return EWRAPPER;
	}
	if (read(fd, map->addr, map->size) < 0)
	{
		FERROR(EFORMAT_WRAPPER, "read", errno, strerror(errno));
		return EWRAPPER;
	}

	return validate_format(map);
}
