
#include <wd_types.h>

#include <unistd.h> // syscall
#include <sys/syscall.h> // SYS_getrandom

/**
 * @brief Generate random 64 bits and return them.
 */
uqword	genkey()
{
	uqword vec = 0;

	if (syscall(SYS_getrandom, &vec, sizeof(vec), 0) != sizeof(vec))
		return 0;
	return vec;
}
