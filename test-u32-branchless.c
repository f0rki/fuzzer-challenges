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

int LLVMFuzzerTestOneInput(uint8_t *buf, size_t len) {

  uint32_t *p32 = (uint32_t *)(buf);
  bool chain = true;
  bool r = false;
  size_t off = 0;

  if (len < (5 * sizeof(uint32_t))) {
    bail("too short", 0);
  }

  r = (p32[0] == 0x11223344);
  off |= r;
  chain &= r;

  r = (p32[1] == 0x55667788);
  off |= r << 1;
  chain &= r;

  r = (p32[2] == 0xa0a1a2a3);
  off |= r << 2;
  chain &= r;

  r = (p32[3] == 0xa4a5a6a7);
  off |= r << 3;
  chain &= r;

  r = (p32[4] == 0x1234aabb);
  off |= r << 4;
  chain &= r;

  if (chain) {
    abort();
  }

  bail("wrong u32 off", off);
  return 0;
}

#ifdef __NEED_MAIN
int main(int argc, char **argv) {

  unsigned char buf[32];
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
