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

typedef struct {
  uint64_t a;
  uint64_t b;
  uint64_t c;
  uint64_t d;
} uint256_t;

// we mark this as optnone, s.t., we always get a good signal to the fuzzer
// even if compiler optimizations are enabled (this might be optimized away to
// vector comparison or similar).
__attribute__((optnone)) bool u256_eq(uint256_t *x, uint256_t *y) {
  return (x->a == y->a) && (x->b == y->b) && (x->c == y->c) && (x->d == y->d);
}

void u256_fprint(uint256_t *u, FILE *fp) {
  fprintf(fp, "0x%lx_%lx_%lx_%lx", u->a, u->b, u->c, u->d);
}

void u256_hash_advance(uint256_t *h) {
#define H(x)                                                                   \
  x = (x ^ (x >> 30)) * UINT64_C(0xbf58476d1ce4e5b9);                          \
  x = (x ^ (x >> 27)) * UINT64_C(0x94d049bb133111eb);                          \
  x = x ^ (x >> 31);

  // hash limbs
  H(h->a);
  H(h->b);
  H(h->c);
  H(h->d);

  // swap limbs
  uint64_t tmp = h->a;
  h->a = h->c;
  h->c = tmp;
  tmp = h->d;
  h->d = h->b;
  h->b = tmp;

#undef H
}

#define bail(msg, pos)                                                         \
  while (1) {                                                                  \
                                                                               \
    fprintf(stderr, "%s at %u\n", (char *)msg, (uint32_t)pos);                 \
    return 0;                                                                  \
  }

const unsigned N = sizeof(uint256_t);
const size_t LOOP_MAX = 255;

int LLVMFuzzerTestOneInput(uint8_t *buf, size_t len) {

  // random constant
  uint256_t h = {0xd19b16fe2eaa4b24, 0xa9c631e117332060, 0x620a6e3c1058e850,
                 0x159edea320a9e804};
  // we use this to compute a new constant at every comparison, s.t.
  // dictionaries do not help the fuzzer, and instead one must rely on cmplog
  // or similar.
  u256_hash_advance(&h);

  bool do_print = getenv("TEST_PRINTS") != NULL;

  size_t req_len = 0;
  size_t pos = 0;

  for (size_t i = 0; i < LOOP_MAX; i++) {
    req_len = pos + N;
    if (len <= req_len) {
      if (do_print)
      fprintf(stderr,
              "[REACHED %zd / %zd] not enough data pos %zd, len %zd, required "
              "len %zd\n",
              i + 1, LOOP_MAX, pos, len, req_len);
      return 0;
    }

    uint256_t *i256 = (uint256_t *)(buf + pos);
    if (u256_eq(i256, &h)) {
      pos += N;
      u256_hash_advance(&h);
    } else {
      if (do_print) {
      fprintf(stderr, "[REACHED %zd / %zd] invalid data at %zd ", i + 1,
              LOOP_MAX, pos);
      u256_fprint(i256, stderr);
      fprintf(stderr, " vs ");
      u256_fprint(&h, stderr);
      fprintf(stderr, "\n");
      }
      return 0;
    }
  }

  // now if the loop above makes the hitcount of each branch in the uint256_eq
  // function reach the maximum (i.e., 255), then there is no "signal" to the
  // fuzzer anymore.

  req_len = pos + N;
  if (len < req_len) {
      if (do_print) {
    fprintf(stderr,
            "[LAST CHECK] not enough data pos %zd, len %zd, required len %zd\n",
            pos, len, req_len);
      }
    return 0;
  }

  uint256_t *i256 = (uint256_t *)(buf + pos);
  if (u256_eq(i256, &h)) {
    abort();
  } else {
      if (do_print) {
    fprintf(stderr, "[LAST CHECK] invalid data at %zd ", pos);
    u256_fprint(i256, stderr);
    fprintf(stderr, " vs ");
    u256_fprint(&h, stderr);
    fprintf(stderr, "\n");
      }
    return 0;
  }

  return 0;
}

#ifdef __AFL_COMPILER
int main(int argc, char **argv) {

  const unsigned buf_size = N * (LOOP_MAX + 2);
  unsigned char *buf = malloc(buf_size);
  ssize_t len;
  int fd = 0;
  if (argc > 1)
    fd = open(argv[1], O_RDONLY);

  if ((len = read(fd, buf, buf_size)) <= 0)
    exit(0);

  LLVMFuzzerTestOneInput(buf, len);
  exit(0);
}
#endif
