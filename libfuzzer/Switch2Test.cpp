#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

// Simple test for a fuzzer. The fuzzer must find the interesting switch value.
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>

int Switch(int a) {

  switch (a) {

    case 100001:
      return 1;
    case 100002:
      return 2;
    case 100003:
      return 4;

  }

  return 0;

}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {

  const int N = 3;
  if (Size < N * sizeof(int)) return 0;
  int Res = 0;
  for (int i = 0; i < N; i++) {

    int X;
    memcpy(&X, Data + i * sizeof(int), sizeof(int));
    Res += Switch(X);

  }

  if (Res == 5 || Res == 3 || Res == 6 || Res == 7) {

    fprintf(stderr, "BINGO; Found the target, exiting; Res=%d\n", Res);
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

