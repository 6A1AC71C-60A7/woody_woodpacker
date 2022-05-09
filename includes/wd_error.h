
#pragma once

#include <stdio.h>

typedef enum	err
{
	SUCCESS,
	EWRAPPER,
	EARGUMENT
}				err_t;

#define ERROR(msg) fprintf(stderr, msg)
#define FERROR(format, args...) fprintf(stderr, format, args)

#ifndef __progname
# define __progname "woody_woodpacker"
#endif

#define EFPREFFIX __progname ": error: "
#define WFPREFFIX __progname ": warnning: "

#define EFORMAT_WRAPPER EFPREFFIX "wrapper %s failed (code: %d: msg: %s)" "\n"
#define EFORMAT_SYSCALL EFPREFFIX "syscall %s failed (code: %d: msg: %s)" "\n"
#define EFORMAT_INVOPT EFPREFFIX  "unknown option `%s'" "\n"
#define EFORMAT_INVARG EFPREFFIX  "option: `%s': invalid argument `%s'" "\n"
#define EFORMAT_EXPARG EFPREFFIX  "option: `%s': expects an argument" "\n"
#define EFORMAT_EXPFILE EFPREFFIX "target file: missing" "\n"
#define EFORMAT_NOTAFILE EFPREFFIX "`%s': is not a regular file" "\n"
#define EFORMAT_INVFORM EFPREFFIX "unknown format: supports only elf files" "\n"
#define EFORMAT_INVARCH EFPREFFIX "invalid architecture: expects %s" "\n"
#define EFORMAT_VERDEP EFPREFFIX "elf file version is deprecated" "\n"
#define EFORMAT_UNKNEND EFPREFFIX "`%s': endianess is neither big nor little" "\n"
#define EFORMAT_EXECONLY EFPREFFIX "invalid elf type: expects only executable files" "\n"
#define EFORMAT_SECSSTRIPPED EFPREFFIX "section's symbols not found: only non-stripped elf executable files" "\n"

#define WFORMAT_INGARGS WFPREFFIX "options should be written BEFORE <target>, otherwise will be ignored." "\n"

#define O_CUSTOMKEY_SSTR "-k"
#define O_32BITADRR_SSTR "-32"
#define O_ANTIPTRCE_SSTR "-t"
#define O_REMOTE_SH_SSTR "-e"
#define O_SELECTSEC_SSTR "-s"

#define O_CUSTOMKEY_LSTR "--key"
#define O_32BITADRR_LSTR "-32"
#define O_ANTIPTRCE_LSTR "--antiptrace"
#define O_REMOTE_SH_LSTR "--remote-shell"
#define O_SELECTSEC_LSTR "--section"

#define MSG_USAGE "usage: " __progname " " \
	"[ " O_CUSTOMKEY_SSTR " | " O_CUSTOMKEY_LSTR " <key> ]" \
	"[ " O_32BITADRR_SSTR " ]" \
	"[ " O_ANTIPTRCE_SSTR " | " O_ANTIPTRCE_LSTR " ]" \
	"[ " O_REMOTE_SH_SSTR " | " O_REMOTE_SH_LSTR " ]" \
	"[ " O_SELECTSEC_SSTR " | " O_SELECTSEC_LSTR " <section> ]" \
	" <target>" "\n" \
	"\n\t<target>: An x86_64 ELF executable used to generate an encrypted copy ('woody').\n" \
	"\t\tWhile executed, the encrypted woody's control flow is modified to firstly\n\t\tdecrypt itself and then perform <target>'s behaviour.\n" \
	"\n\tOPTIONS:\n" \
	"\t* [ " O_CUSTOMKEY_SSTR " | " O_CUSTOMKEY_LSTR " <key> ]: Uses <key> as (en/de)cryption key instead of a automatically genereted one.\n" \
	"\t* [ " O_32BITADRR_SSTR " ]: Accepts x86 ELF executable as <target>.\n" \
	"\t* [ " O_ANTIPTRCE_SSTR " | " O_ANTIPTRCE_LSTR " ]: Inject anti-ptrace code (exit if tracee) before the decryptor.\n" \
	"\t* [ " O_REMOTE_SH_SSTR " | " O_REMOTE_SH_LSTR " ]: Inject a remote shell deamon in woody as payload.\n \
	\t\tThe server code source can be found here: https://github.com/6A1AC71C-60A7/remote_shells/tree/main/remote_shell_serv\n" \
	"\t* [ " O_SELECTSEC_SSTR " | " O_SELECTSEC_LSTR " <section>]: Select which section (en/de)crypt (.rodata, .data, .text). All are by default enabled.\n" \
	"\t\tSelect multiple sections using the following syntax: `" __progname " " O_SELECTSEC_SSTR " .text,.data <target>'.\n"
