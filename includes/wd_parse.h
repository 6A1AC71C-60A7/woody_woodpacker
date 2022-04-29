
#pragma once

#include <wd_types.h>
#include <wd_error.h>

#define PAIRARR_LEN 0x10

extern crypt_pair_t	targets_crypt[PAIRARR_LEN];
extern crypt_pair_t	targets_decrypt[PAIRARR_LEN];

err_t	parse_opts(const char** av[], parse_t* const parse);
