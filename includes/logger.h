#pragma once

#ifdef DEBUG
# define debug(...) fprintf(stderr, __VA_ARGS__)
# define info(...) fprintf(stderr, __VA_ARGS__)
# define error(...) fprintf(stderr, __VA_ARGS__)
#else
# define debug(...) (void)0
# define info(...) fprintf(stderr, __VA_ARGS__)
# define error(...) fprintf(stderr, __VA_ARGS__)
#endif
