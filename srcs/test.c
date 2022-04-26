
#include <woody_woodpacker.h>
#include <wd_crypt.h>
#include <ftlibc.h>

#include <sys/mman.h> // mmap
#include <fcntl.h> // open
#include <unistd.h> // write

void test_crypt()
{
	const qword key = 0x42424242424242;

	ubyte arr1[] = "abcdefghiklmnopqrstuvwxyz\n";
	ubyte arr2[] = "H2llo Word1Hello Word1Hello Word1\n";
	ubyte arr3[] = "H3llo Word1Hello Word1Hello Word1Hello Word1\n";

	ubyte woody[] = {
		'.', ' ', '.', '\n', 0, 0, 0, 0,
		'O', 'O', 'D', 'Y', '.', ' ', '.', ' ',
		'.', ' ', '.', ' ', '.', ' ', '.', 'W'
	};

	crypt_pair_t targets[] = {
		{
			.start = arr1,
			.nbytes = sizeof(arr1) - 1
		},
		{
			.start = arr2,
			.nbytes = sizeof(arr2) - 1
		},
		{
			.start = arr3,
			.nbytes = sizeof(arr3) - 1
		}
	};

	kcrypt_X86_64(arr1, sizeof(arr1) - 1, key);
	kcrypt_X86_64(arr2, sizeof(arr2) - 1, key);
	kcrypt_X86_64(arr3, sizeof(arr3) - 1, key);

	printf("[MSG1 CIPHERTEXT]: %s\n", arr1);
	printf("[MSG2 CIPHERTEXT]: %s\n", arr2);
	printf("[MSG3 CIPHERTEXT]: %s\n", arr3);

	kcrypt_X86_64(woody, sizeof(woody), key);

	kdecrypt_asm(targets, sizeof(targets) / sizeof(*targets), key, woody, sizeof(woody));

	printf("[MSG1]: %s", arr1);
	printf("[MSG2]: %s", arr2);
	printf("[MSG3]: %s", arr3);

}

// useful if a symbol is needed to put a breakpoint
void exec_payload(ubyte* payload)
{
	((void (*)())payload)();
}

void test_crypt_payload()
{
	const qword key = 0x42424242424242;

	ubyte arr1[] = "abcdefghiklmnopqrstuvwxyz\n";
	ubyte arr2[] = "H2llo Word1Hello Word1Hello Word1\n";
	ubyte arr3[] = "H3llo Word1Hello Word1Hello Word1Hello Word1\n";

	crypt_pair_t targets[] = {
		{
			.start = arr1,
			.nbytes = sizeof(arr1) - 1
		},
		{
			.start = arr2,
			.nbytes = sizeof(arr2) - 1
		},
		{
			.start = arr3,
			.nbytes = sizeof(arr3) - 1
		},
		{
			.start = 0,
			.nbytes = 0
		}
	};

	kcrypt_X86_64(arr1, sizeof(arr1) - 1, key);
	kcrypt_X86_64(arr2, sizeof(arr2) - 1, key);
	kcrypt_X86_64(arr3, sizeof(arr3) - 1, key);

	printf("[MSG1 CIPHERTEXT]: %s --> [addr: %p len: %0"PRIXq"]\n", arr1, arr1, (uqword)sizeof(arr1) - 1);
	printf("[MSG2 CIPHERTEXT]: %s --> [addr: %p len: %0"PRIXq"]\n", arr2, arr2, (uqword)sizeof(arr2) - 1);
	printf("[MSG3 CIPHERTEXT]: %s --> [addr: %p len: %0"PRIXq"]\n", arr3, arr3, (uqword)sizeof(arr3) - 1);

	parse_t in = {0};
	in.key = key;
	//in.opts = O_ANTIPTRCE; works well

	decryptor_t	decryptor;
	build_decryptor_x86_64(&decryptor, &in, targets, 0X1122334455667788);

	ubyte* mem = mmap(0, decryptor.size, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS, 0, 0);
	if (mem == MAP_FAILED)
		perror("mmap");
	ft_memcpy(mem, decryptor.data, decryptor.size);

	printf("[WRITING THE PAYLOAD]: (size: %"PRIuq") on the 'on_test' file\n", decryptor.size);
	int fd = open("on_test", O_CREAT | O_WRONLY, S_IRWXU);
	if (fd < 0)
		perror("open");
	write(fd, mem, decryptor.size);

	//((void (*)())mem)();
	exec_payload(mem);

	printf("[MSG1 PLAINTEXT]: %s", arr1);
	printf("[MSG2 PLAINTEXT]: %s", arr2);
	printf("[MSG3 PLAINTEXT]: %s", arr3);
}
