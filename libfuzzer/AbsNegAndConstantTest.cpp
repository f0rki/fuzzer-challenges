#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

// abs(x) < 0 and y == Const puzzle.
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {

  if (Size < 8) return 0;
  int      x;
  unsigned y;
  memcpy(&x, Data, sizeof(x));
  memcpy(&y, Data + sizeof(x), sizeof(y));
  volatile int abs_x = abs(x);
  if (abs_x < 0 && y == 0xbaddcafe) {

    printf("BINGO; Found the target, exiting; x = 0x%x y 0x%x\n", x, y);
    fflush(stdout);
    abort();

  }

  return 0;

}

#ifdef __NEED_MAIN
int main(int argc, char **argv) {

  unsigned char buf[64];
  ssize_t       len;
  int           fd = 0;
  if (argc > 1) fd = open(argv[1], O_RDONLY);

  if ((len = read(0, buf, sizeof(buf))) <= 0) return -1;

  LLVMFuzzerTestOneInput(buf, len);
  return 0;

}

#endif

