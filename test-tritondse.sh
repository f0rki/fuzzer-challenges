#!/bin/bash

#
# Setup for TritonDSE
#
make clean
make CC=clang CFLAGS="-g -D__AFL_COMPILER=1" compile
ulimit -c unlimited

for i in *.c*; do
  TARGET=${i%%.c*}

  # removed longdouble - takes forever
  if [[ "$TARGET" = "test-longdouble" ]]; then
      continue
  fi

  # Setup individual run
  rm -rf core out
  mkdir out
  echo Running $TARGET ...
  timeout -s KILL 120 python3 tritondsetest.py ./$TARGET > $TARGET.log 2>&1
  cd out
  for i in *; do cat $i | ../$TARGET ; done
  test -e core && echo SUCCESS | tee -a ../$TARGET.log
  cd ..
  rm -rf out
done

echo
echo RESULTS
echo =======
grep -wl SUCCESS test-*.log | sed 's/\.log//'
