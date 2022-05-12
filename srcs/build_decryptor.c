
#include "wd_parse.h"
#include <stdio.h>
#include <woody_woodpacker.h>
#include <wd_types.h>
#include <wd_error.h>
#include <ftlibc.h>
#include <wd_utils.h>
#include <wd_crypt.h>
#include <wd_payloads.h>

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

#define OP_MOV_IMM_TO_REG '\xb8'
#define OP_MOV_IMM_TO_REG_SIZE 0xa
#define OP_REG_RAX '\x48'
#define OP_PUSH_RAX '\x50'
#define OP_PUSH_RAX_SIZE 0x1
#define OP_MOV_IMM_TO_MEM '\xC7'
#define OP_MOV_IMM_TO_MEM_SIZE 0x7
#define OP_MOV_MEM_RSP '\x04', '\x24'
#define OP_ADD '\x83'
#define OP_ADD_SIZE 0x4
#define OP_ADD_SIZE_OPERAND '\x48'
#define OP_ADD_TO_RSP '\xC4'

#define OP_SUB '\x83'
#define OP_SUB_SIZE 0x4
#define OP_SUB_SIZE_OPERAND '\x48'
#define OP_SUB_TO_RSP '\xEC'

#define OP_RETN '\xC3'
#define OP_RETN_SIZE 0x1
#define OP_RETF '\xCB'
#define OP_RETF_SIZE 0x1

#define OP_JUMPN '\xE9'
#define OP_JUMPN_SIZE 0x4

#define OP_REX_W '\x48'
#define OP_MOV_RDI_IMM '\xBF'
#define OP_MOV_RDI_IMM_SIZE 0xa

uqword get_decryptor_size_x86_64(const parse_t* const in, const crypt_pair_t* const targets)
{
	register qword size = ARRLEN(regs_preservation_x86_64) + ARRLEN(decryptor_x86_64); //+ ARRLEN(regs_restoration_x86_64);

	/* Pushed entry point */
	size += (OP_MOV_IMM_TO_MEM_SIZE * 2) + (OP_ADD_SIZE * 2);

	/* Woody msg */
	size += (OP_MOV_IMM_TO_REG_SIZE + OP_PUSH_RAX_SIZE) * (ARRLEN(woody_msg) / sizeof(uqword));

	/* Decryption key */
	size += OP_MOV_IMM_TO_REG_SIZE + OP_PUSH_RAX_SIZE;

	/* Chunks' locations and sizes */
	for (uqword i = 0 ; targets[i].start ; i++)
		size += (OP_MOV_IMM_TO_REG_SIZE + OP_PUSH_RAX_SIZE) * (sizeof(*targets) / sizeof(uqword));

	/* Total amount if chunks */
	size += OP_MOV_IMM_TO_REG_SIZE + OP_PUSH_RAX_SIZE;

	if (in->opts & O_ANTIPTRCE)
		size += ARRLEN(antiptrace_x86_64);

	// if (in->opts & O_REMOTE_SH)
	// 	size += OP_MOV_RDI_IMM_SIZE + ARRLEN(remote_serv_shell_x86_64);

	return size;
}

err_t	prepare_decryptor_x86_64(const elf_map_t *const map, decryptor_t* const decryptor)
{
	const Elf64_Ehdr*	eh = (Elf64_Ehdr*)map->addr;
	const Elf64_Phdr*	ph = (Elf64_Phdr*)(map->addr + eh->e_phoff);
	const uqword		i = find_text_segment(ph, eh->e_phnum);
	const uqword		j = find_segment(ph + i, eh->e_phnum - i, PT_LOAD);
	uqword				virtual_space;
	err_t				err;

	debug("text segment index: %zu, phnum %hu\n", i, eh->e_phnum);
	err = (i <= eh->e_phnum && decryptor->size <= page_size) ? SUCCESS : EARGUMENT;

	debug("payload size: 0x%lx\n", decryptor->size);

	if (err == SUCCESS)
	{
		debug("text:          offset: 0x%lx, virt addr: 0x%lx, file size: 0x%lx\n",
			ph[i].p_offset, ph[i].p_vaddr, ph[i].p_filesz);

		if (j <= eh->e_phnum)
		{
			virtual_space = ph[j].p_vaddr - ph[i].p_vaddr + ph[i].p_memsz;
			debug("Max expansion size: 0x%lx, page size: 0x%lx\n", virtual_space, page_size);
			err = (virtual_space >= page_size) ? SUCCESS : EARGUMENT;
		}

		// Get text segment offset for relocations
		decryptor->segment_index = i;
		decryptor->segment_offset = ph[i].p_offset;

		// Get decryptor offset
		decryptor->offset = ph[i].p_offset + ph[i].p_filesz;
		decryptor->vaddr = ph[i].p_vaddr + ph[i].p_memsz;
	}

	return (err);
}

__attribute__ ((always_inline))
static inline void memcpy_offset(ubyte* const restrict dest, const ubyte* const restrict src,
		uqword nbytes, uqword* const offset)
{
	ft_memcpy(dest + *offset, src, nbytes);
	*offset += nbytes;
}

__attribute__ ((always_inline))
static inline void push_entry_point(ubyte* const dest, uqword* const offset, uqword entry_point)
{

	const udword* const ep = (const udword*)&entry_point;

	ubyte op_mov_mem_to_rsp[OP_MOV_IMM_TO_MEM_SIZE] = {
		OP_MOV_IMM_TO_MEM, OP_MOV_MEM_RSP, 0x0, 0x0, 0x0, 0x0
	};

	register udword* const imm32 = (udword*)(op_mov_mem_to_rsp + 3);

	const ubyte op_sub_4_to_rsp[OP_SUB_SIZE] = {
		OP_SUB_SIZE_OPERAND, OP_SUB, OP_SUB_TO_RSP, 0x4
	};

	*imm32 = ep[1];
	memcpy_offset(dest, op_sub_4_to_rsp, ARRLEN(op_sub_4_to_rsp), offset);
	memcpy_offset(dest, op_mov_mem_to_rsp, ARRLEN(op_mov_mem_to_rsp), offset);

	*imm32 = ep[0];
	memcpy_offset(dest, op_sub_4_to_rsp, ARRLEN(op_sub_4_to_rsp), offset);
	memcpy_offset(dest, op_mov_mem_to_rsp, ARRLEN(op_mov_mem_to_rsp), offset);
}

__attribute__ ((always_inline))
static inline void build_stack_initializer_x86_64(ubyte* const dest, uqword* const offset,
		const crypt_pair_t* const targets, uqword key)
{
	ubyte op_mov_push[OP_MOV_IMM_TO_REG_SIZE + OP_PUSH_RAX_SIZE] = {
		OP_REG_RAX, OP_MOV_IMM_TO_REG, 0X0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, OP_PUSH_RAX
	};

	register uqword* const imm64 = (uqword*)(op_mov_push + 2);

	ubyte encrypted_woody_msg[ARRLEN(woody_msg)];

	ft_memcpy(encrypted_woody_msg, woody_msg, ARRLEN(encrypted_woody_msg));

	for (uqword i = 0; i < ARRLEN(woody_msg); i++)
		debug("%02hhx%c", encrypted_woody_msg[i], i != ARRLEN(woody_msg) - 1 ? ' ' : '\n');

	kcrypt_X86_64(encrypted_woody_msg, ARRLEN(encrypted_woody_msg), key);

	for (uqword i = 0; i < ARRLEN(woody_msg); i++)
		debug("%02hhx%c", encrypted_woody_msg[i], i != ARRLEN(woody_msg) - 1 ? ' ' : '\n');

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
		debug("pushing chunk_vaddr: %jx\n", (uintmax_t)*imm64);
		memcpy_offset(dest, op_mov_push, ARRLEN(op_mov_push), offset);
		*imm64 = targets[amount].nbytes;
		debug("pushing chunk_size: %jx\n", (uintmax_t)*imm64);
		memcpy_offset(dest, op_mov_push, ARRLEN(op_mov_push), offset);
	}

	/* Push the total of amount of chunks */
	*imm64 = amount;
	memcpy_offset(dest, op_mov_push, ARRLEN(op_mov_push), offset);
}

__attribute__((always_inline))
static inline void	relocate_targets(crypt_pair_t* const targets,
	const decryptor_t* const decryptor)
{
	for (uqword i = 0; i < PAIRARR_LEN; i++)
	{
		/* if the chunk to decrypt starts after or at the decryptor's offset */
		if ((uqword)targets[i].start >= decryptor->vaddr)
		{
			debug("relocating targets %zu\n", i);
			targets[i].start += page_size;
		}
	}
}

/**
 * @brief Builds the woody's decryptor using user's input.
 *
 * @param dest On return, will point to the builded decryptor.
 * @param in A struct holding the input given by the user.
 * @param targets An array of structs holding the location and
 * sizes of the chunks to be decrypted.
 * @param size On return, will point to the size of the decryptor.
 * @param ep The real ELF entrypoint (where control will be transfered after the decryptor).
 */
err_t build_decryptor_x86_64(decryptor_t* const dest, const parse_t* const in,
		crypt_pair_t* const targets, uqword ep)
{
	uqword offset = 0;

	relocate_targets(targets, dest);

	if ((dest->data = (ubyte*)malloc(sizeof(ubyte) * dest->size)) == NULL)
	{
		FERROR(EFORMAT_WRAPPER, "malloc", errno, strerror(errno));
		return EWRAPPER;
	}

	push_entry_point(dest->data, &offset, ep);

	memcpy_offset(dest->data, regs_preservation_x86_64, ARRLEN(regs_preservation_x86_64), &offset);

	if (in->opts & O_ANTIPTRCE)
		memcpy_offset(dest->data, antiptrace_x86_64, ARRLEN(antiptrace_x86_64), &offset);

	// if (in->opts & O_REMOTE_SH)
	// {
	// 	mov_key_to_rdi(dest->data, &offset, in->key);
	// 	memcpy_offset(dest->data, remote_serv_shell_x86_64, ARRLEN(remote_serv_shell_x86_64), &offset);
	// }

	build_stack_initializer_x86_64(dest->data, &offset, targets, in->key);

	memcpy_offset(dest->data, decryptor_x86_64, ARRLEN(decryptor_x86_64), &offset);

	return SUCCESS;
}
