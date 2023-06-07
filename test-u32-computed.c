#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <strings.h>
#include <stdlib.h>
#include <stdint.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "bail.h"
#include "hash.h"


int LLVMFuzzerTestOneInput(uint8_t *buf, size_t len) {

  uint32_t *p32;
  uint64_t hash = ijon_simple_hash(obtain_runtime_seed());

  if (len < 24) {
    bail("too short", 0);
  }

  p32 = (uint32_t *)(buf);
  if (p32[0] != (uint32_t)hash) {
    bail("wrong u32", 0);
  }
  hash = ijon_simple_hash(hash);

  if (p32[1] != (uint32_t)hash) {
    bail("wrong u32", 4);
  }
  hash = ijon_simple_hash(hash);

  if (p32[2] != (uint32_t)hash) {
    bail("wrong u32", 8);
  }
  hash = ijon_simple_hash(hash);

  if (p32[3] != (uint32_t)hash) {
    bail("wrong u32", 12);
  }
  hash = ijon_simple_hash(hash); // is this a blockchain?

  if (p32[4] != (uint32_t)hash) {
    bail("wrong u32", 16);
  }

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
