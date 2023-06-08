#include <fcntl.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "bail.h"

typedef struct {
  uint64_t a;
  uint64_t b;
  uint64_t c;
  uint64_t d;
} uint256_t;

static inline int u256_eq(uint256_t *x, uint256_t *y) {
  return (x->a == y->a) & (x->b == y->b) & (x->c == y->c) & (x->d == y->d);
}

void u256_fprint(uint256_t *u, FILE *fp) {
  fprintf(fp, "0x%lx_%lx_%lx_%lx", u->a, u->b, u->c, u->d);
}

#ifndef OFFSET
#define OFFSET (0)
#endif

#ifndef LOOPS
#define LOOPS (2)
#endif

int LLVMFuzzerTestOneInput(uint8_t *buf, size_t len) {

  uint256_t *p256;
  uint256_t v256;
  uint8_t *p = (uint8_t *)&v256;
  const unsigned N = sizeof(uint256_t);
  const size_t REQUIRED_LEN = ((N * (LOOPS + 1)) + OFFSET);

  if (len < REQUIRED_LEN) {
    bail("too short", REQUIRED_LEN);
  }

  for (size_t i = 0; i < LOOPS; i++) {
    size_t off = i * N;
    if (len < N + off) {
      bail("too short", off);
    }
    p256 = (uint256_t *)(buf + off);
    memset((char *)&v256, 'A' + i * 5, sizeof(v256));

    if (!u256_eq(p256, &v256)) {
      bail("wrong u256", off);
    }
  }

  for (size_t i = 0; i < sizeof(uint256_t); i++) {
    p[i] = '0' + i * 2;
  }
  p256 = (uint256_t *)(buf + (LOOPS * N + OFFSET));
  if (!u256_eq(p256, &v256)) {
    bail("wrong u256", 64);
  }

  abort();

  return 0;
}

#ifdef __NEED_MAIN
int main(int argc, char **argv) {

  unsigned char buf[128];
  ssize_t len;
  int fd = 0;
  if (argc > 1)
    fd = open(argv[1], O_RDONLY);

  if ((len = read(fd, buf, sizeof(buf))) <= 0)
    exit(0);

  LLVMFuzzerTestOneInput(buf, len);
  exit(0);
}

#endif
