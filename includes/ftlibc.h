
#pragma once

#include <sys/types.h>

int		ft_strcmp(const char* s1, const char* s2);
void	ft_memcpy(void *restrict dest, const void* restrict src, size_t n);
void	*ft_memmove(void *dst, const void *src, size_t len);
int		ft_strncmp(const char* s1, const char* s2, size_t size);
size_t	ft_strlen(const char* s);
