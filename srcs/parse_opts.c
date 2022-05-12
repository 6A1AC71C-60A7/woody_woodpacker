
#include <wd_types.h>
#include <wd_error.h>
#include <wd_utils.h>
#include <ftlibc.h>

#include <stdbool.h>

#include <string.h>

__attribute__ ((unused))
static bool	handle_section_arg(const char** arg, parse_t* const parse)
{
	static const char* const snames[] = {
		".rodata",
		".data",
		".text"
	};

	static const uqword snames_lenghts[] = {
		sizeof(".rodata") - 1,
		sizeof(".data") - 1,
		sizeof(".text") - 1
	};

	const char* p = *arg;
	byte count = 0;

	for (uqword i = 0 ; i < ARRLEN(snames) ; i++)
	{
		if (ft_strncmp(p, snames[i], snames_lenghts[i] - 1) == 0)
		{
			if ((p[snames_lenghts[i]] != 0 && p[snames_lenghts[i]] != ',')
			|| (p[snames_lenghts[i]] == ',' && p[snames_lenghts[i] + 1] == ','))
				goto error;

			parse->sections |= 1 << i;
			p += snames_lenghts[i] + 1;
			count = 0;
			if (*(p - 1) == 0)
				break ;
			i = -1;
		}
		else
			count++;
	}

	if (parse->sections == 0 || count == 3)
		goto error;

	return true;

error:
	FERROR(EFORMAT_INVARG, *(arg - 1), *arg);
	return false;
}

static bool	handle_key_arg(const char** arg, parse_t* const parse)
{
	const uqword lenght = MAX(ft_strlen(*arg), sizeof(parse->key));
	ft_memcpy((void*)&parse->key, *arg, lenght);
	return true;
}

__attribute__ ((always_inline))
static inline bool	opt_arg_is_present(const char** av)
{
	if (*(av + 1) == NULL)
	{
		FERROR(EFORMAT_EXPARG, *av);
		return false;
	}
	return true;
}

static const struct
{
	char*			s_opt;
	uqword			s_opt_len;
	char*			l_opt;
	uqword			l_opt_len;
	void*			handle;
}					po[] = {
	{
		.s_opt = O_32BITADRR_SSTR,
		.s_opt_len = sizeof(O_32BITADRR_SSTR),
		.l_opt = O_32BITADRR_LSTR,
		.l_opt_len = sizeof(O_32BITADRR_LSTR),
		.handle = NULL
	},
	{
		.s_opt = O_ANTIPTRCE_SSTR,
		.s_opt_len = sizeof(O_ANTIPTRCE_SSTR),
		.l_opt = O_ANTIPTRCE_LSTR,
		.l_opt_len = sizeof(O_ANTIPTRCE_LSTR),
		.handle = NULL
	},
	{
		.s_opt = O_CUSTOMKEY_SSTR,
		.s_opt_len = sizeof(O_CUSTOMKEY_SSTR),
		.l_opt = O_CUSTOMKEY_LSTR,
		.l_opt_len = sizeof(O_CUSTOMKEY_LSTR),
		.handle = &handle_key_arg
	},
	{
		.s_opt = O_REMOTE_SH_SSTR,
		.s_opt_len = sizeof(O_REMOTE_SH_SSTR),
		.l_opt = O_REMOTE_SH_LSTR,
		.l_opt_len = sizeof(O_REMOTE_SH_LSTR),
		.handle = NULL
	},
	// {
	// 	.s_opt = O_SELECTSEC_SSTR,
	// 	.s_opt_len = sizeof(O_SELECTSEC_SSTR),
	// 	.l_opt = O_SELECTSEC_LSTR,
	// 	.l_opt_len = sizeof(O_SELECTSEC_LSTR),
	// 	.handle = NULL//&handle_section_arg
	// },
};

/**
 * @brief Parse user options and makes @p av point to <target>.
 *
 * @param av A pointer to the vector of arguments given by the user.
 * @param parse A struct where the parsed data will be stored.
 */
err_t	parse_opts(const char** av[], parse_t* const parse)
{
	uqword iav = -1;

	while ((*av)[++iav] && *(*av)[iav] == '-')
	{
		bool found = false;
		for (register uqword ipo = 0 ; ipo < ARRLEN(po) ; ipo++)
		{
			if (ft_strncmp((*av)[iav], po[ipo].s_opt, po[ipo].s_opt_len) == 0
			|| ft_strncmp((*av)[iav], po[ipo].l_opt, po[ipo].l_opt_len) == 0)
			{
				if (po[ipo].handle != NULL
				&& (opt_arg_is_present(&(*av)[iav]) == false
				|| ((bool (*)(const char**, parse_t* const))po[ipo].handle)(&(*av)[++iav], parse) == false))
					goto invalid_opt;
				parse->opts |= 1 << ipo;
				found = true;
				break ;
			}
		}
		if (found == false)
		{
			FERROR(EFORMAT_INVOPT, (*av)[iav]);
			goto invalid_opt;
		}
	}

	*av += iav;

	if (**av == NULL)
	{
		ERROR(EFORMAT_EXPFILE);
		goto invalid_opt;
	}
	else if (*(*av + 1))
		ERROR(WFORMAT_INGARGS);

	return SUCCESS;

invalid_opt:
	return EARGUMENT;
}
