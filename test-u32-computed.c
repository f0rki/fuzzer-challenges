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

// shamelessly plucked from the ijon project
__attribute__((always_inline))
static inline uint64_t ijon_simple_hash(uint64_t x) {
    x = (x ^ (x >> 30)) * UINT64_C(0xbf58476d1ce4e5b9);
    x = (x ^ (x >> 27)) * UINT64_C(0x94d049bb133111eb);
    x = x ^ (x >> 31);
    return x;
}

int LLVMFuzzerTestOneInput(uint8_t *buf, size_t len) {

  uint32_t *p32;
  uint64_t hash = ijon_simple_hash((uint64_t)&LLVMFuzzerTestOneInput);

  if (len < 24) bail("too short", 0);

  p32 = (uint32_t *)(buf);
  if (*p32 != (uint32_t)hash) bail("wrong u32", 0);
  hash = ijon_simple_hash(hash);

  p32 = (uint32_t *)(buf + 4);
  if (*p32 != (uint32_t)hash) bail("wrong u32", 4);
  hash = ijon_simple_hash(hash);

  p32 = (uint32_t *)(buf + 8);
  if (*p32 != (uint32_t)hash) bail("wrong u32", 8);
  hash = ijon_simple_hash(hash);

  p32 = (uint32_t *)(buf + 12);
  if (*p32 != (uint32_t)hash) bail("wrong u32", 12);
  hash = ijon_simple_hash(hash); // is this a blockchain?

  p32 = (uint32_t *)(buf + 16);
  if (*p32 != (uint32_t)hash) bail("wrong u32", 16);

  abort();

  return 0;

}

#ifdef __AFL_COMPILER
int main(int argc, char **argv) {

  unsigned char buf[32];
  ssize_t       len;
  int           fd = 0;
  if (argc > 1) fd = open(argv[1], O_RDONLY);

  if ((len = read(fd, buf, sizeof(buf))) <= 0) exit(0);

  LLVMFuzzerTestOneInput(buf, len);
  exit(0);

}

#endif

