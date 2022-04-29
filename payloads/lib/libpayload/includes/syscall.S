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

	%define O_RDONLY		00o
	%define O_WRONLY		01o
	%define O_RDWR			02o

	%define O_CREAT			0100o
	%define O_EXCL			0200o
	%define O_NOCTTY		0400o
	%define O_TRUNC			01000o
	%define O_APPEND		02000o
	%define O_NONBLOCK		04000o
	%define O_NDELAY		O_NONBLOCK
	%define O_SYNC			04010000o
	%define O_FSYNC			O_SYNC
	%define O_ASYNC			020000o

	; Set user ID on execution. */
	%define	S_ISUID			04000o
	; Set group ID on execution. */
	%define	S_ISGID			02000o
	; Save swapped text after use (sticky). */
	%define	S_ISVTX			0100o
	; Read by owner. */0
	%define	S_IREAD			0400o
	; Write by owner. */
	%define	S_IWRITE		0200o
	; Execute by owner. */
	%define	S_IEXEC			0100o

	; Read by owner. */
	%define S_IRUSR			S_IREAD
	; Write by owner. */
	%define S_IWUSR			S_IWRITE
	; Execute by owner. */
	%define S_IXUSR			S_IEXEC
	; Read, write, and execute by owner. */
	%define S_IRWXU			(S_IREAD|S_IWRITE|S_IEXEC)

	; Read by group. */
	%define S_IRGRP			(S_IRUSR >> 3)
	; Write by group. */
	%define S_IWGRP			(S_IWUSR >> 3)
	; Execute by group. */
	%define S_IXGRP			(S_IXUSR >> 3)
	; Read, write, and execute by group. */
	%define S_IRWXG			(S_IRWXU >> 3)

	; Read by others. */
	%define S_IROTH			(S_IRGRP >> 3)
	; Write by others. */
	%define S_IWOTH			(S_IWGRP >> 3)
	; Execute by others. */
	%define S_IXOTH			(S_IXGRP >> 3)
	; Read, write, and execute by others. */
	%define S_IRWXO			(S_IRWXG >> 3)

	%define SEEK_CURR		1

	%define PROT_READ		0x1
	%define PROT_WRITE		0x2
	%define PROT_EXEC		0x4
	%define PROT_NONE		0x0

	%define PROT_R			PROT_READ
	%define PROT_W			PROT_WRITE
	%define PROT_X			PROT_EXEC

	%define PROT_RW			PROT_R | PROT_W
	%define PROT_RX			PROT_R | PROT_X

	%define PROT_WX			PROT_W | PROT_X

	%define PROT_RWX		PROT_R | PROT_W | PROT_X

%endif
