#ifndef HASH_H
#define HASH_H

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

__attribute__((always_inline)) static inline uint64_t simple_hash(uint64_t x) {
  // https://xoshiro.di.unimi.it/splitmix64.c
  x += UINT64_C(0x9e3779b97f4a7c15);
  x = (x ^ (x >> 30)) * UINT64_C(0xbf58476d1ce4e5b9);
  x = (x ^ (x >> 27)) * UINT64_C(0x94d049bb133111eb);
  x = x ^ (x >> 31);
  return x;
}

int LLVMFuzzerTestOneInput(uint8_t *buf, size_t len);

static inline uint64_t obtain_runtime_seed() {
  uint64_t seed = UINT64_C(0xffffffffffffffc5);

  // trick clang's constant folding.
  __asm__("pushq %0;"
          "popq %1;"
          : "=r"(seed)
          : "r"(seed)
          );

  return seed;
}

#endif
