#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#define bail(msg, pos)                                                         \
  while (1) {                                                                  \
                                                                               \
    fprintf(stderr, "%s at %u\n", (char *)msg, (uint32_t)pos);                 \
    return 0;                                                                  \
  }

// shamelessly plucked from the ijon project, simply to generate constants that
// cannot be known to the compiler/auto-dictionary
__attribute__((always_inline)) static inline uint64_t
ijon_simple_hash(uint64_t x) {
  x = (x ^ (x >> 30)) * UINT64_C(0xbf58476d1ce4e5b9);
  x = (x ^ (x >> 27)) * UINT64_C(0x94d049bb133111eb);
  x = x ^ (x >> 31);
  return x;
}

int LLVMFuzzerTestOneInput(uint8_t *buf, size_t len) {

  uint32_t *p32 = (uint32_t *)(buf);
  uint64_t hash = ijon_simple_hash((uint64_t)&LLVMFuzzerTestOneInput);
  const size_t N = 256;

  if (len < (N * 4))
    bail("too short", 0);

  for (size_t i = 0; i < N; i++) {
    if (p32[i] != (uint32_t)hash) {
      bail("wrong u32", i * sizeof(uint32_t))
    };
    hash = ijon_simple_hash(hash);
  }

  abort();

  return 0;
}

#ifdef __AFL_COMPILER
int main(int argc, char **argv) {

  unsigned char buf[4096];
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
