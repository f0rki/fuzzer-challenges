#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <strings.h>
#include <stdlib.h>
#include <stdint.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#define bail(msg, pos)                                         \
  while (1) {                                                  \
                                                               \
    fprintf(stderr, "%s at %u\n", (char *)msg, (uint32_t)pos); \
    return 0;                                                  \
                                                               \
  }

typedef unsigned __int128 uint128_t;

typedef struct {
  uint128_t lo;
  uint128_t hi;
} uint256_t;

static inline int u256_eq(uint256_t* a, uint256_t* b) {
  return (a->hi == b->hi) & (a->lo == b->lo);
}

#ifndef O
#define O (0)
#endif

int LLVMFuzzerTestOneInput(uint8_t *buf, size_t len) {

  uint256_t *p256, v256;
  uint8_t *  p = (uint8_t *)&v256;
  const unsigned N = sizeof(uint256_t);

  if (len < (N * 3)) {
    bail("too short", (N * 3));
  }

  for (size_t i = 0; i < 2; i++) {
    if (len < N + i * N) {
      bail("too short", i * N);
    }
    p256 = (uint256_t *)(buf + i * N);
    memset((char *)&v256, 'A' + i * 5, sizeof(v256));

    if (!u256_eq(p256, &v256)) {
      bail("wrong u256", (i * N));
    }
  }

  for (size_t i = 0; i < sizeof(uint256_t); i++) {
    p[i] = '0' + i * 2;
  }
  p256 = (uint256_t *)(buf + (2 * N + O));
  if (!u256_eq(p256, &v256)) {
    bail("wrong u256", 64);
  }

  abort();

  return 0;

}

#ifdef __AFL_COMPILER
int main(int argc, char **argv) {

  unsigned char buf[128];
  ssize_t       len;
  int           fd = 0;
  if (argc > 1) fd = open(argv[1], O_RDONLY);

  if ((len = read(fd, buf, sizeof(buf))) <= 0) exit(0);

  LLVMFuzzerTestOneInput(buf, len);
  exit(0);

}

#endif

