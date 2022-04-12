
#include <wd_types.h>
#include <wd_error.h>
#include <ftlibc.h>
#include <wd_utils.h>
#include <wd_crypt.h>

#include <stdlib.h> // malloc
#include <errno.h>  // errno
#include <string.h> // strerror

/**
 * Since the stack grows downwards and the 'woody_msg'
 * is pushed on the stack, the ". . . .WOODY. . . ." string
 * has to be reversed in 64 bit chunks (qwords).
 */
static const ubyte woody_msg[] = {
	'.', ' ', '.', '\n', '\0', '\0','\0', '\0',
	'O', 'O', 'D', 'Y', '.', ' ', '.', ' ', 	
	'.', ' ', '.', ' ', '.', ' ', '.', 'W'
};

static const ubyte decryptor_x86_64[] = {
	'\x58', '\x49', '\xC7', '\xC1', '\x02', '\x00', '\x00', '\x00',
	'\x50', '\x49', '\x0F', '\xAF', '\xC1', '\x48', '\x8D', '\x3C',
	'\xC4', '\x48', '\x83', '\xC7', '\x08', '\x58', '\x4D', '\x31',
	'\xD2', '\x41', '\x5B', '\x5E', '\x57', '\x56', '\x52', '\x50',
	'\x51', '\x41', '\x53', '\x9C', '\x48', '\x89', '\xF7', '\x4C',
	'\x89', '\xDE', '\xBA', '\x07', '\x00', '\x00', '\x00', '\x48',
	'\xC7', '\xC0', '\x0A', '\x00', '\x00', '\x00', '\x0F', '\x05',
	'\x9D', '\x41', '\x5B', '\x59', '\x58', '\x5A', '\x5E', '\x5F',
	'\x41', '\x52', '\x4D', '\x31', '\xC0', '\x4C', '\x89', '\xC2',
	'\x48', '\x83', '\xE2', '\x07', '\x44', '\x8A', '\x0C', '\x17',
	'\x46', '\x28', '\x0C', '\x06', '\x41', '\x51', '\x41', '\x53',
	'\x88', '\xD1', '\x46', '\x8A', '\x0C', '\x06', '\x41', '\xD2',
	'\xE9', '\x41', '\xB4', '\x08', '\x41', '\x28', '\xD4', '\x44',
	'\x88', '\xE1', '\x46', '\x8A', '\x24', '\x06', '\x41', '\xD2',
	'\xE4', '\x45', '\x08', '\xCC', '\x41', '\x5B', '\x41', '\x59',
	'\x46', '\x88', '\x24', '\x06', '\x42', '\xF6', '\x14', '\x06',
	'\x46', '\x30', '\x0C', '\x06', '\x49', '\xFF', '\xC0', '\x4D',
	'\x39', '\xD8', '\x72', '\xB9', '\x41', '\x5A', '\x49', '\xFF',
	'\xC2', '\x49', '\x39', '\xC2', '\x72', '\x83', '\x49', '\x39',
	'\xC2', '\x75', '\x1B', '\x49', '\xFF', '\xC2', '\x41', '\x52',
	'\x49', '\xC7', '\xC2', '\x01', '\x00', '\x00', '\x00', '\x4A',
	'\x8D', '\x34', '\xD7', '\x41', '\x5A', '\x49', '\xC7', '\xC3',
	'\x18', '\x00', '\x00', '\x00', '\xEB', '\x8A', '\x48', '\xC7',
	'\xC0', '\x01', '\x00', '\x00', '\x00', '\x48', '\xC7', '\xC7',
	'\x01', '\x00', '\x00', '\x00', '\x48', '\xC7', '\xC2', '\x18',
	'\x00', '\x00', '\x00', '\x0F', '\x05', '\x48', '\x83', '\xC4',
	'\x20'
};

/// if (ptrace(PTRACE_TRACEME, 0, 1, 0) == -1) exit(0);
static const ubyte antiptrace_x86_64[] = {
	'\x48', '\xC7', '\xC7', '\x00', '\x00', '\x00', '\x00', '\x48',
	'\xC7', '\xC6', '\x00', '\x00', '\x00', '\x00', '\x48', '\xC7',
	'\xC2', '\x01', '\x00', '\x00', '\x00', '\x48', '\xC7', '\xC1',
	'\x00', '\x00', '\x00', '\x00', '\x48', '\xC7', '\xC0', '\x65',
	'\x00', '\x00', '\x00', '\x0F', '\x05', '\x48', '\x83', '\xF8',
	'\xFF', '\x75', '\x10', '\x48', '\xC7', '\xC0', '\x3C', '\x00',
	'\x00', '\x00', '\x48', '\xC7', '\xC7', '\x00', '\x00', '\x00',
	'\x00', '\x0F', '\x05'
};

/// push regs + flags
static const ubyte regs_preservation_x86_64[] = {
	'\x50', '\x51', '\x52', '\x53', '\x54', '\x55', '\x56', '\x57',
	'\x41', '\x50', '\x41', '\x51', '\x41', '\x52', '\x41', '\x53',
	'\x41', '\x54', '\x41', '\x55', '\x41', '\x56', '\x41', '\x57',
	'\x9C'
};

/// pop regs + flags
static const ubyte regs_restoration_x86_64[] = {
	'\x9D', '\x41', '\x5F', '\x41', '\x5E', '\x41', '\x5D', '\x41',
	'\x5C', '\x41', '\x5B', '\x41', '\x5A', '\x41', '\x59', '\x41',
	'\x58', '\x5F', '\x5E', '\x5D', '\x5C', '\x5B', '\x5A', '\x59',
	'\x58'
};

#define OP_MOV_IMM_TO_REG '\xb8'
#define OP_MOV_IMM_TO_REG_SIZE 0xa
#define OP_REG_RAX '\x48'
#define OP_PUSH_RAX '\x50'
#define OP_PUSH_RAX_SIZE 0x1
#define OP_RETN '\xC3'
#define OP_RETN_SIZE 0x1

__attribute__ ((always_inline))
static inline uqword get_decryptor_size_x86_64(const parse_t* const in, const crypt_pair_t* const targets)
{
	register qword size = ARRLEN(regs_preservation_x86_64) + ARRLEN(decryptor_x86_64) + ARRLEN(regs_restoration_x86_64);

	/* Woody msg */
	size += (OP_MOV_IMM_TO_REG_SIZE + OP_PUSH_RAX_SIZE) * (ARRLEN(woody_msg) / sizeof(uqword));

	/* Decryption key */
	size += OP_MOV_IMM_TO_REG_SIZE + OP_PUSH_RAX_SIZE;

	/* Chunks' locations and sizes */
	for (uqword i = 0 ; targets[i].start ; i++)
		size += (OP_MOV_IMM_TO_REG_SIZE + OP_PUSH_RAX_SIZE) * (sizeof(*targets) / sizeof(uqword));

	/* Total amount if chunks */
	size += OP_MOV_IMM_TO_REG_SIZE + OP_PUSH_RAX_SIZE;

	/* Return */
	size += OP_RETN_SIZE;

	if (in->opts & O_ANTIPTRCE)
		size += ARRLEN(antiptrace_x86_64);
	
	if (in->opts & O_APPENDDAT)
		size += *(uqword*)in->data;

	return size;
}

__attribute__ ((always_inline))
static inline void memcpy_offset(ubyte* const restrict dest, const ubyte* const restrict src,
		uqword nbytes, uqword* const offset)
{
	ft_memcpy(dest + *offset, src, nbytes);
	*offset += nbytes;
}

__attribute__ ((always_inline))
static inline void build_stack_initializer_x86_64(ubyte* const dest, uqword* const offset,
		const crypt_pair_t* const targets, uqword key)
{
	///NOTE: Depending of the endianess movabs, reg, imm could be \xb8\x48 or \x48\xb8 (99% sure)
	///NEED: movabs rax, imm64
	///NOTE: All this file is tested by writing *dest array into a file F and then do the command: 'cat F | hexdump -v -e '/1 "%02X "' ; echo'
	/// The output is dissasembled in the following page: https://defuse.ca/online-x86-assembler.htm#disassembly
	ubyte op_mov_push[OP_MOV_IMM_TO_REG_SIZE + OP_PUSH_RAX_SIZE] = {
		OP_REG_RAX, OP_MOV_IMM_TO_REG, 0X0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, OP_PUSH_RAX
	};

	///NOTE: Also the order of the imm64 can be reversed by endianess:
	/// Eg: 0x1122334455667788 -> {8877665544332211} OR {1122334455667788}

	register uqword* const imm64 = (uqword*)(op_mov_push + 2);

	ubyte encrypted_woody_msg[ARRLEN(woody_msg)];

	ft_memcpy(encrypted_woody_msg, woody_msg, ARRLEN(encrypted_woody_msg));
	kcrypt_X86_64(encrypted_woody_msg, ARRLEN(encrypted_woody_msg), key);

	/* Push the (encrypted) ". . . .WOODY. . . ." string */
	for (uqword i = 0 ; i < ARRLEN(encrypted_woody_msg) ; i += sizeof(uqword))
	{
		*imm64 = *(uqword*)&encrypted_woody_msg[i];
		memcpy_offset(dest, op_mov_push, ARRLEN(op_mov_push), offset);
	}

	/* Push the decryption key */
	*imm64 = key;
	memcpy_offset(dest, op_mov_push, ARRLEN(op_mov_push), offset);

	uqword amount = -1;

	/* Push the chuks' locations and sizes */
	while (targets[++amount].start)
	{
		*imm64 = (uqword)targets[amount].start;
		memcpy_offset(dest, op_mov_push, ARRLEN(op_mov_push), offset);
		*imm64 = targets[amount].nbytes;
		memcpy_offset(dest, op_mov_push, ARRLEN(op_mov_push), offset);
	}

	/* Push the total of amount of chunks */
	*imm64 = amount;
	memcpy_offset(dest, op_mov_push, ARRLEN(op_mov_push), offset);
}

/**
 * @brief Builds the woody's decryptor using user's input.
 * 
 * @param dest On return, will point to the builded decryptor.
 * @param in A struct holding the input given by the user.
 * @param targets An array of structs holding the location and
 * sizes of the chunks to be decrypted.
 * @param size On return, will point to the size of the decryptor.
 */
err_t build_decryptor_x86_64(ubyte** const dest, const parse_t* const in,
		const crypt_pair_t* const targets, uqword* const size)
{
	uqword offset = 0;

	///TODO: Push EP at the begin return to it at the end
	///TODO: Probally for test RETN is needed but whether the injected decryptor returns to another segment RETF will be necesary
	/// https://stackoverflow.com/questions/1396909/ret-retn-retf-how-to-use-them

	*size = get_decryptor_size_x86_64(in, targets);

	if ((*dest = (ubyte*)malloc(sizeof(ubyte) * *size)) == NULL)
	{
		FERROR(EFORMAT_WRAPPER, "malloc", errno, strerror(errno));
		return EWRAPPER;
	}

	memcpy_offset(*dest, regs_preservation_x86_64, ARRLEN(regs_preservation_x86_64), &offset);

	if (in->opts & O_ANTIPTRCE)
		memcpy_offset(*dest, antiptrace_x86_64, ARRLEN(antiptrace_x86_64), &offset);

	build_stack_initializer_x86_64(*dest, &offset, targets, in->key);

	memcpy_offset(*dest, decryptor_x86_64, ARRLEN(decryptor_x86_64), &offset);

	if (in->opts & O_APPENDDAT)
		ft_memcpy(*dest + offset, in->data + sizeof(uqword), *(uqword*)in->data);

	memcpy_offset(*dest, regs_restoration_x86_64, ARRLEN(regs_restoration_x86_64), &offset);

	memcpy_offset(*dest, (ubyte[]){OP_RETN}, OP_RETN_SIZE, &offset);

	return SUCCESS;
}
