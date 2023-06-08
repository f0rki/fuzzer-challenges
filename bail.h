#ifndef BAIL_H
#define BAIL_H

#include <stdio.h>

#define bail(MSG, POS)                                                         \
  do {                                                                         \
    fprintf(stderr, "[%s:%d] %s at %lu\n", __FILE__, __LINE__, (char *)MSG,     \
            (uint64_t)POS);                                                    \
    return 0;                                                                  \
  } while (1);

#endif
