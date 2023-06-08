TARGETS = test-crc32 \
		  test-u8 test-u16 test-u32 test-u64 test-u128 \
		  test-float test-double test-longdouble \
		  test-u32-cmp \
		  test-memcmp test-strcmp \
		  test-transform \
		  test-extint \
		  test-custom-u256-twolimbed test-custom-u256-fourlimbed \
		  test-u32-branchless test-u32-branchless-unaligned test-u32-computed test-u32-computed-branchless test-u32-computed-repeated \
		  test-custom-u256-long-looped

CC ?= clang
CXX ?= clang++
CFLAGS ?= -D__NEED_MAIN -O0 -fno-inline -fno-builtin

all:
	@echo Use test.sh to perform the test.
	@echo To compile with CC and CFLAGS yourself do \"make compile\", however test.sh will overwrite these.

compile:	$(TARGETS)

%:	%.c
	-$(CC) $(CFLAGS) -o $@ $@.c -lm

clean:
	rm -f $(TARGETS) core* *.plain *~ *.data *.log HONGGFUZZ.REPORT.TXT SIG* afl++.dic
	rm -rf out-* in *.dir mcore_*
