#include <fcntl.h>
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

  if (len < 24)
    bail("too short", 0);

  p32 = (uint32_t *)(buf);
  if (*p32 != 0x11223344)
    bail("wrong u32", 0);

  p32 = (uint32_t *)(buf + 4);
  if (*p32 != 0x55667788)
    bail("wrong u32", 4);

  p32 = (uint32_t *)(buf + 8);
  if (*p32 != 0xa0a1a2a3)
    bail("wrong u32", 8);

  p32 = (uint32_t *)(buf + 12);
  if (*p32 != 0xa4a5a6a7)
    bail("wrong u32", 12);

  p32 = (uint32_t *)(buf + 16);
  if (*p32 != 0x1234aabb)
    bail("wrong u32", 16);

  abort();

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
