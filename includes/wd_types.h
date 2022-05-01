
#pragma once

#include <stdint.h>
#include <inttypes.h> // format specifiers

typedef int8_t		byte;
typedef int16_t		word;
typedef int32_t		dword;
typedef int64_t		qword;

typedef uint8_t		ubyte;
typedef uint16_t	uword;
typedef uint32_t	udword;
typedef uint64_t	uqword;

# define PRIdb	PRId8
# define PRIdw	PRId16
# define PRIdd	PRId32
# define PRIdq	PRId64

# define PRIub	PRIu8
# define PRIuw	PRIu16
# define PRIud	PRIu32
# define PRIuq	PRIu64

# define PRIxb	PRIx8
# define PRIxw	PRIx16
# define PRIxd	PRIx32
# define PRIxq	PRIx64

# define PRIXb	PRIX8
# define PRIXw	PRIX16
# define PRIXd	PRIX32
# define PRIXq	PRIX64

typedef enum		chunk_e
{
	CH_SEGMENT,
	CH_SECTION,
}					chunk_t;

typedef struct		crypt_pair
{
	void*			start;
	uqword			nbytes;
	chunk_t			type;
}					crypt_pair_t;

typedef enum		section
{
	SEC_RODATA =	(1 << 0),
	SEC_DATA   =	(SEC_RODATA << 1),
	SEC_TEXT   =	(SEC_DATA << 1)
}					section_t;

typedef struct		parse
{
	ubyte			opts;
	uqword			key;
	const ubyte*	data;
	ubyte			sections;
}					parse_t;

typedef enum		opts
{
	O_32BITADRR =	(1 << 0),         	// -32 : Expects a 32 bit executable as argument
	O_ANTIPTRCE	=	(O_32BITADRR << 1),	// -t | --antiptrace : Inject anti-ptrace code on woody
	O_CUSTOMKEY	=	(O_ANTIPTRCE << 1),	// -k | --key <key> : Uses 8 most significant bytes of <key> as (en/de)cryption key
	O_APPENDDAT =	(O_CUSTOMKEY << 1),	// -d | --data <data> : Inject arbitrary data after the decryptor
	O_SELECTSEC =	(O_APPENDDAT << 1)	// -s | --section <section> : Select which sections (en/de)crypt
}					opts_t;
