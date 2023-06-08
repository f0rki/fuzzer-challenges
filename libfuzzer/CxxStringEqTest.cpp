#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

// Simple test for a fuzzer. Must find a specific string
// used in std::string operator ==.
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <iostream>
#include <string>

static volatile int Sink;

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {

  std::string Str((const char *)Data, Size);
  bool        Eq = Str == "FooBar";
  Sink = Str == "123456";  // Try to confuse the fuzzer
  if (Eq) {

    std::cout << "BINGO; Found the target, exiting\n";
    std::cout.flush();
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

