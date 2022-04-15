
#include <wd_types.h>

#include <unistd.h> // syscall
#include <sys/syscall.h> // SYS_getrandom

/**
 * @brief Generate random 64 bits and return them.
 */
uqword	genkey()
{
	uqword vec = 0;

	#ifndef __APPLE__
		if (syscall(SYS_getrandom, &vec, sizeof(vec), 0) != sizeof(vec))
			return 0;
	#else
		vec = 0x4242424242424242;
	#endif

	return vec;
}
