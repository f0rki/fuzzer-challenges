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
  uint32_t *p32;
  bool r = true;

  if (len < 24)
    bail("too short", 0);

  p32 = (uint32_t *)(buf);
  r &= (*p32 == 0x11223344);

  p32 = (uint32_t *)(buf + 5);
  r &= (*p32 == 0x55667788);

  p32 = (uint32_t *)(buf + 10);
  r &= (*p32 == 0xa0a1a2a3);

  p32 = (uint32_t *)(buf + 16);
  r &= (*p32 == 0xa4a5a6a7);

  p32 = (uint32_t *)(buf + 20);
  r &= (*p32 == 0x1234aabb);

  if (r) {
    abort();
  } else {
    bail("one int was wrong", 0);
  }

  return 0;
}

#ifdef __AFL_COMPILER
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
