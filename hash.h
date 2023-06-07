#ifndef HASH_H
#define HASH_H

#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <strings.h>
#include <stdlib.h>
#include <stdint.h>
#include <sys/types.h>
#include <sys/stat.h>

// shamelessly plucked from the ijon project
__attribute__((always_inline))
static inline uint64_t ijon_simple_hash(uint64_t x) {
    x = (x ^ (x >> 30)) * UINT64_C(0xbf58476d1ce4e5b9);
    x = (x ^ (x >> 27)) * UINT64_C(0x94d049bb133111eb);
    x = x ^ (x >> 31);
    return x;
}


int LLVMFuzzerTestOneInput(uint8_t *buf, size_t len);
static inline uint64_t obtain_runtime_seed() {
  uint64_t seed = 0;
  seed ^= (uint64_t)&LLVMFuzzerTestOneInput;
  srand(0xe8251849);
  seed ^= rand();
  seed ^= ((uint64_t)rand()) << 32;

  return seed;
}

#endif
