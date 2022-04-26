#include <sys/syscall.h>
#include <unistd.h>

int main()
{
	static const char	*const args[] = {"sh", "-c", "echo hello world", NULL};

	return syscall(SYS_execve, "/bin/sh", args, NULL);
}
