# include <sys/types.h>

size_t ft_strlen(const char* s)
{
    const char* ss = (const char*)s;

    while (*ss)
        ss++;
    return ss - s;
}
