%ifndef SYSCALL_S
	%define SYSCALL_S

	%define SYS_READ		0
	%define SYS_WRITE		1
	%define SYS_OPEN		2
	%define SYS_CLOSE		3

	%define SYS_LSEEK		8

	%define SYS_MPROTECT	10

	%define SYS_EXIT		60

	%define SYS_PTRACE		101
	%define SYS_PRCTL		157

	%define STDIN_FILENO	0
	%define STDOUT_FILENO	1
	%define STDERR_FILENO	2

	%define O_RDONLY		0

	%define SEEK_CURR		1

	%define PROT_READ		0x1
	%define PROT_WRITE		0x2
	%define PROT_EXEC		0x4
	%define PROT_NONE		0x0
%endif
