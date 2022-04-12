# include <sys/types.h>

void ft_memcpy(void *restrict dest, const void* restrict src, size_t n)
{
    ///TODO: Use long ptr for optimization
    char* d = (char*)dest;
    const char* s = (const char*)src;

    for (size_t i = 0 ; i < n ; i++)
        d[i] = s[i];
}
