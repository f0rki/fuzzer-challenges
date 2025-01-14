#!/usr/bin/env bash
###################
### START OF CONFIG

# default fuzzer setup (e.g. afl++, libfuzzer, honggfuzz, ...)
FUZZER=afl++

# how many seconds to try each testcase, recommended: 10-120
RUNTIME=60

# test a fuzzer in a specific directory? you can put that here
#FUZZER_DIR=~/AFLplusplus/branches/cmplog_variant

### END OF CONFIG
#################

# cmdline processing
test -z "$1" -o "$1" = "-h" && {
  echo "Syntax: $0 [FUZZER [TESTCASE]]"
  echo Fuzzers: afl++, afl++-qemu, afl++-frida, afl++-lto, honggfuzz, libfuzzer, libafl
  echo Testcase: instead of processing all, process just this one
  exit 0
}
test -z "$1" && { echo 'Warning: no target given - assuming afl++ - available: afl++, afl++-lto, afl++-qemu, afl++-frida, honggfuzz, libfuzzer, ...'; echo; }
test -n "$1" && FUZZER=$1
DONE=

export CFLAGS="-O0 -fno-inline -fno-builtin"

FUZZER_RUN="$FUZZER"

function aflpp_driver() {
  DRIVER=/usr/local/lib/afl/libAFLDriver.a
  if [[ -n "$FUZZER_DIR" ]]; then
      DRIVER="$FUZZER_DIR/libAFLDriver.a"
  fi
  export CFLAGS="$CFLAGS $DRIVER"
}

# fuzzer options
test "$FUZZER" = "afl++" && { 
  export CC=afl-clang-fast
  export CXX=afl-clang-fast++
  export AFL_LLVM_CMPLOG=1
  export AFL_LLVM_DICT2FILE=`pwd`/afl++.dic
  export CMPLOG_LVL=3AT
  export FUZZER_OPTIONS="-Z"
  aflpp_driver
  DONE=1
}
test "$FUZZER" == "afl++-lto" || test "$FUZZER" == "afl++-lto"* && {
  export CC=afl-clang-lto
  export CXX=afl-clang-lto++
  OPT="-O3"  # default
  if test "$FUZZER" = "afl++-lto-O3"; then
      OPT="-O3"
  elif test "$FUZZER" = "afl++-lto-O2"; then
      OPT="-O2"
  elif test "$FUZZER" = "afl++-lto-O1"; then
      OPT="-O1"
  elif test "$FUZZER" = "afl++-lto-O0"; then
      OPT="-O0"
  fi
  export CFLAGS="-flto=full $OPT -march=native -fvisibility-inlines-hidden -Wl,--plugin-opt=-lto-embed-bitcode=optimized"
  export AFL_LLVM_CMPLOG=1
  export AFL_LLVM_DICT2FILE=`pwd`/afl++.dic
  export CMPLOG_LVL=3AT
  export FUZZER_OPTIONS="-Z"
  aflpp_driver
  FUZZER_RUN="afl++"
  DONE=1
}
test "$FUZZER" = "afl++gcc" && { 
  export CC=afl-gcc-fast
  export CXX=afl-g++-fast++
  export AFL_LLVM_CMPLOG=1
  export AFL_LLVM_DICT2FILE=`pwd`/afl++.dic
  export CMPLOG_LVL=3AT
  export FUZZER_OPTIONS="-Z"
  aflpp_driver
  FUZZER_RUN="afl++"
  DONE=1
}
test "$FUZZER" = "afl++-qemu" -o "$FUZZER" = "afl++-frida" && { 
  export CC=clang
  export CXX=clang++
  export CFLAGS="$CFLAGS -D__NEED_MAIN=1"
  export CMPLOG_LVL=3AT
  export FUZZER_OPTIONS="-Z"
  DONE=1
}
test "$FUZZER" = "libfuzzer" && { 
  export CC=clang
  export CXX=clang++
  export CFLAGS="-fsanitize=fuzzer"
  export FUZZER_OPTIONS="-use_value_profile=1 -entropic=1 $FUZZER_OPTIONS"
  DONE=1
}
test "$FUZZER" = "libfuzzer-lto" || test "$FUZZER" == "libfuzzer-lto"* && {
  export CC=clang
  export CXX=clang++
  OPT="-O0"  # default
  if test "$FUZZER" = "libfuzzer-lto-O3"; then
      OPT="-O3"
  elif test "$FUZZER" = "libfuzzer-lto-O2"; then
      OPT="-O2"
  elif test "$FUZZER" = "libfuzzer-lto-O1"; then
      OPT="-O1"
  elif test "$FUZZER" = "libfuzzer-lto-O0"; then
      OPT="-O0"
  fi
  export CFLAGS="-fsanitize=fuzzer -fuse-ld=lld -flto=full $OPT -march=native -fvisibility-inlines-hidden -Wl,--plugin-opt=-lto-embed-bitcode=optimized"
  export FUZZER_OPTIONS="-use_value_profile=1 -entropic=1 $FUZZER_OPTIONS"
  FUZZER_RUN="libfuzzer"
  DONE=1
}
test "$FUZZER" = "libafl" && { 
  export CC=libafl_cc
  export CXX=libafl_cxx
  export CFLAGS="--libafl"
  #export FUZZER_OPTIONS="-use_value_profile=1 -entropic=1 $FUZZER_OPTIONS"
  DONE=1
}
test "$FUZZER" = "honggfuzz" && {
  export CC=hfuzz-clang
  export CXX=hfuzz-clang++
  DONE=1
}
test "$FUZZER" = "tritondse" && {
  export CC=clang
  export CXX=clang++
  export CFLAGS="$CFLAGS -D__NEED_MAIN=1"
  DONE=1
}

test -z "$DONE" && { echo 'Error: invalid fuzzer, allowed are only afl++, afl++-qemu, afl++-frida, afl++-lto(-O[0-3])?, libfuzzer, libfuzzer-lto(-O[0-3])?, libafl or honggfuzz'; exit 1; }
echo Fuzzer: $FUZZER
echo Maximum runtime: $RUNTIME
test -n "$FUZZER_DIR" && echo Detected FUZZER_DIR=$FUZZER_DIR, expanding PATH and AFL_PATH
test -n "$FUZZER_DIR" && export PATH=$FUZZER_DIR:$PATH
test -n "$FUZZER_DIR" && export AFL_PATH=$FUZZER_DIR
if [[ -n "$FUZZER_DIR" ]]; then
    export CFLAGS="$CFLAGS -L$FUZZER_DIR"
fi
echo

# prepare environment
echo Preparation:
export CFLAGS="-fno-builtin $CFLAGS"
echo CC=$CC
echo CFLAGS=$CFLAGS
env|grep -E '^AFL_'
export CXXFLAGS="$CFLAGS $CXXFLAGS"
export AFL_QUIET=1
make clean >/dev/null 2>&1
test -z "$2" && { make compile || exit 1; }
test -n "$2" && { make "$2" || exit 1; }
rm -rf in out-* *.log crash* SIG* HONGGFUZZ.REPORT.TXT
if [[ "$FUZZER" != "tritondse" ]]; then
    ulimit -c 0
fi

function standard_seed {
    rm -rf in || true
    mkdir in || exit 1
    echo ZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ > in/in
}
standard_seed
test "$FUZZER" = "afl++" -o "$FUZZER" = "afl++-qemu" -o "$FUZZER" = "afl++-frida" -o "$FUZZER" = "afl++-lto" && {
  OK=
  afl-fuzz -h 2>&1 | grep -q ' -l ' && OK=1
  test -z "$OK" && echo Warning: afl++ is not cmplog_variant
  test -n "$OK" && FUZZER_OPTIONS="-l $CMPLOG_LVL $FUZZER_OPTIONS"
}

# set envs
export AFL_NO_UI=1
export AFL_BENCH_UNTIL_CRASH=1
export AFL_SKIP_CPUFREQ=1
export AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1
export RUNTIME
unset ASAN_FUZZER_OPTIONS
export ASAN_OPTIONS="disable_coredump=0:unmap_shadow_on_exit=1:abort_on_error=1:detect_leaks=0:symbolize=0"
test -n "$FUZZER_DIR" && export PATH=$FUZZER_DIR:$PATH
test -n "$FUZZER_DIR" && export AFL_PATH=$FUZZER_DIR
SUCCESS=0
FAIL=0
echo
echo Starting tests
echo Fuzzer special options: $FUZZER_OPTIONS
# run test cases
for i in *.c*; do

  TARGET=${i%%.c*}
  test -z "$2" -o "$2" = "$TARGET" && {
    test -e "$TARGET.seed" && {
        rm ./in/*
        cp "$TARGET.seed" "./in/$TARGET.seed"
    }

    test -x "$TARGET" && {
      echo Running $TARGET ...

      test -e ${AFL_TMPDIR}/.cur_input && rm ${AFL_TMPDIR}/.cur_input
      test "$FUZZER_RUN" = afl++ && {
        HAVE_DICT=""
        test -f afl++.dic && HAVE_DICT="-x afl++.dic"
        TIME=`{ time afl-fuzz $HAVE_DICT $FUZZER_OPTIONS -V$RUNTIME -i in -o out-$TARGET -c ./$TARGET -- ./$TARGET >/dev/null 2>$TARGET.log ; } 2>&1 |grep -w real|awk '{print$2}'`
        ls out-$TARGET/default/crashes/id* >/dev/null 2>&1 && {
          echo SUCCESS: $TARGET $TIME
          test -z "$NO_DELETE" && rm -rf out-$TARGET $TARGET.log
          SUCCESS=$((SUCCESS + 1))
        } || {
          echo FAIL: $TARGET
          ls out-$TARGET/default/queue
          echo 
          FAIL=$((FAIL + 1))
        }
      }

      test "$FUZZER_RUN" = afl++-qemu && {
        TIME=`{ time afl-fuzz -Q $FUZZER_OPTIONS -V$RUNTIME -i in -o out-$TARGET -c 0 -- ./$TARGET >/dev/null 2>$TARGET.log ; } 2>&1 |grep -w real|awk '{print$2}'`
        ls out-$TARGET/default/crashes/id* >/dev/null 2>&1 && {
          echo SUCCESS: $TARGET $TIME
          test -z "$NO_DELETE" && rm -rf out-$TARGET $TARGET.log
          SUCCESS=$((SUCCESS + 1))
        } || {
          echo FAIL: $TARGET
          ls out-$TARGET/default/queue
          echo 
          FAIL=$((FAIL + 1))
        }
      }

      test "$FUZZER_RUN" = afl++-frida && {
        TIME=`{ time afl-fuzz -O $FUZZER_OPTIONS -V$RUNTIME -i in -o out-$TARGET -c 0 -- ./$TARGET >/dev/null 2>$TARGET.log ; } 2>&1 |grep -w real|awk '{print$2}'`
        ls out-$TARGET/default/crashes/id* >/dev/null 2>&1 && {
          echo SUCCESS: $TARGET $TIME
          test -z "$NO_DELETE" && rm -rf out-$TARGET $TARGET.log
          SUCCESS=$((SUCCESS + 1))
        } || {
          echo FAIL: $TARGET
          ls out-$TARGET/default/queue
          echo 
          FAIL=$((FAIL + 1))
        }
      }

      test "$FUZZER_RUN" = honggfuzz && {
        cp -r in out-$TARGET
        TIME=`{ time honggfuzz $FUZZER_OPTIONS --run_time $RUNTIME -q --exit_upon_crash -i out-$TARGET -s -v -- ./$TARGET >/dev/null 2>$TARGET.log ; } 2>&1 |grep -w real|awk '{print$2}'`
        ls SIG* >/dev/null 2>&1 && {
          echo SUCCESS: $TARGET $TIME
          test -z "$NO_DELETE" && rm -rf out-$TARGET $TARGET.log
          rm -f SIG* HONGGFUZZ.REPORT.TXT
          SUCCESS=$((SUCCESS + 1))
        } || {
          echo FAIL: $TARGET
          ls out-$TARGET/
          echo 
          FAIL=$((FAIL + 1))
        }
      }

      test "$FUZZER_RUN" = libfuzzer && {
        cp -r in out-$TARGET
        # -use_value_profile=1 decreases the performance
        TIME=`{ time ./$TARGET $FUZZER_OPTIONS -timeout=1 -detect_leaks=0 -max_total_time=$RUNTIME -workers=0 >/dev/null 2>$TARGET.log ; } 2>&1 |grep -w real|awk '{print$2}'`
        ls crash* >/dev/null 2>&1 && {
          echo SUCCESS: $TARGET $TIME
          test -z "$NO_DELETE" && rm -rf out-$TARGET $TARGET.log
          rm -f crash*
          SUCCESS=$((SUCCESS + 1))
        } || {
          echo FAIL: $TARGET
          ls out-$TARGET/
          echo 
          FAIL=$((FAIL + 1))
        }
      }

      test "$FUZZER_RUN" = libafl && {
        cp -r in out-$TARGET
        TIME=`{ time timeout -s KILL $RUNTIME ./$TARGET $FUZZER_OPTIONS -i in -o out-$TARGET >/dev/null 2>$TARGET.log ; } 2>&1 |grep -w real|awk '{print$2}'`
        ls out-$TARGET/crashes/* >/dev/null 2>&1 && {
          echo SUCCESS: $TARGET $TIME
          test -z "$NO_DELETE" && rm -rf out-$TARGET $TARGET.log
          rm -f crash*
          SUCCESS=$((SUCCESS + 1))
        } || {
          echo FAIL: $TARGET
          ls out-$TARGET/queue
          echo 
          FAIL=$((FAIL + 1))
        }
      }

      test "$FUZZER_RUN" = tritondse && {
       mkdir -p out || true
       timeout -s KILL $RUNTIME python3 tritondsetest.py ./$TARGET >$TARGET.log 2>&1
       cd out
       for i in *; do 
           cat $i | ../$TARGET >/dev/null 2>&1; 
       done
       cd ..
       if test -e out/core; then 
          echo SUCCESS: $TARGET $TIME | tee -a $TARGET.log
          SUCCESS=$((SUCCESS + 1))
       else
          echo FAIL: $TARGET
          echo 
          FAIL=$((FAIL + 1))
       fi
       mv out out-$TARGET
       test -z "$NO_DELETE" && rm -rf out-$TARGET $TARGET.log
      }

    }
  }

  standard_seed
done

echo "Done! SUCCESS=$SUCCESS FAIL=$FAIL"
