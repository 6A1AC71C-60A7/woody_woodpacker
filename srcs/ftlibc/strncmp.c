# include <sys/types.h>

int ft_strncmp(const char* s1, const char* s2, size_t size)
{
    if (s1 && s2)
    {
        size_t n = 0;
        while (*s1 && *s2 && *s1 == *s2 && n < size)
        {
            s1++;
            s2++;
            n++;
        }
        return (*s1 - *s2);
    }
    return 1;
}
