#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <strings.h>
#include <stdlib.h>
#include <stdint.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdbool.h>

#define bail(msg, pos)                                         \
  while (1) {                                                  \
                                                               \
    fprintf(stderr, "%s at %u\n", (char *)msg, (uint32_t)pos); \
    return 0;                                                  \
                                                               \
  }

int LLVMFuzzerTestOneInput(uint8_t *buf, size_t len) {

  uint32_t *p32;
  bool chain = true;
  bool r = false;
  size_t off = 0;

  if (len < 20) bail("too short", 0);

  p32 = (uint32_t *)(buf);
  r = (*p32 == 0x11223344);
  off |= r;
  chain &= r;

  p32 = (uint32_t *)(buf + 4);
  r = (*p32 == 0x55667788);
  off |= r << 1;
  chain &= r;

  p32 = (uint32_t *)(buf + 8);
  r = (*p32 == 0xa0a1a2a3);
  off |= r << 2;
  chain &= r;

  p32 = (uint32_t *)(buf + 12);
  r = (*p32 == 0xa4a5a6a7);
  off |= r << 3;
  chain &= r;

  p32 = (uint32_t *)(buf + 16);
  r = (*p32 == 0x1234aabb);
  off |= r << 4;
  chain &= r;

  if (chain) {
    abort();
  }

  fprintf(stderr, "wrong u32 (%zx vs %zx)\n", off, (size_t)31);
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

