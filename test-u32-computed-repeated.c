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
#include "hash.h"

int LLVMFuzzerTestOneInput(uint8_t *buf, size_t len) {

  uint32_t *p32 = (uint32_t *)(buf);
  uint64_t hash = simple_hash(obtain_runtime_seed());
  const size_t N = 256;

  if (len < (N * 4))
    bail("too short", 0);

  for (size_t i = 0; i < N; i++) {
    uint32_t C = i | (((uint32_t)hash) & 0xffffff00);
    if (p32[i] == C) {
      hash = simple_hash(hash);
      // continue
    } else {
      bail("wrong u32", i * sizeof(uint32_t))
    }
  }

  abort();

  return 0;
}

#ifdef __NEED_MAIN
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
