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

#include "bail.h"
#include "hash.h"

int LLVMFuzzerTestOneInput(uint8_t *buf, size_t len) {

  uint32_t *p32 = (uint32_t *)(buf);
  uint64_t hash = ijon_simple_hash(obtain_runtime_seed());
  bool chain = true;
  bool r = false;
  size_t off = 0;

  if (len < 20) {
    bail("too short", 0);
  }

  r = (p32[0] == (uint32_t)hash);
  hash = ijon_simple_hash(hash);
  off |= r;
  chain &= r;

  r = (p32[1] == (uint32_t)hash);
  hash = ijon_simple_hash(hash);
  off |= r << 1;
  chain &= r;

  r = (p32[2] == (uint32_t)hash);
  hash = ijon_simple_hash(hash);
  off |= r << 2;
  chain &= r;

  r = (p32[3] == (uint32_t)hash);
  hash = ijon_simple_hash(hash); // is this a blockchain?
  off |= r << 3;
  chain &= r;

  r = (p32[4] == (uint32_t)hash);
  off |= r << 4;
  chain &= r;

  if (chain) {
    abort();
  }

  bail("wrong u32 at index", off);
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

