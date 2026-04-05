# NimGuard demo test binary.
# Compile with:   nim c -d:release -o:test_binary create_test_binary.nim
#
# This program calls several functions that NimGuard's import scanner flags
# as dangerous (memcpy, memmove, sprintf) so that the analyze and patch demos
# have something concrete to report. It also contains simple arithmetic so the
# .text section has real instructions worth disassembling.

import strutils

proc c_memcpy(dst, src: pointer, n: csize_t): pointer
  {.importc: "memcpy",  header: "<string.h>".}
proc c_memmove(dst, src: pointer, n: csize_t): pointer
  {.importc: "memmove", header: "<string.h>".}
proc c_sprintf(buf: cstring, fmt: cstring): cint
  {.importc: "sprintf", header: "<stdio.h>", varargs.}

proc copyDemo() =
  var src: array[32, char]
  var dst: array[32, char]
  let msg = "Hello, NimGuard!"
  for i in 0 ..< msg.len:
    src[i] = msg[i]
  discard c_memcpy(addr dst, addr src, csize_t(msg.len))
  var s = ""
  for c in dst:
    if c == '\0': break
    s.add(c)
  echo "memcpy result:  ", s

proc moveDemo() =
  var buf: array[32, char]
  let init = "ABCDEFGHIJ"
  for i in 0 ..< init.len:
    buf[i] = init[i]
  # Shift the first 5 bytes forward by 2 positions (overlapping)
  discard c_memmove(addr buf[2], addr buf[0], csize_t(5))
  var s = ""
  for i in 0 ..< 10:
    if buf[i] == '\0': break
    s.add(buf[i])
  echo "memmove result: ", s

proc sprintfDemo() =
  var outBuf: array[64, char]
  discard c_sprintf(cast[cstring](addr outBuf), "value=%d hex=0x%x", 42.cint, 255.cint)
  echo "sprintf result: ", cast[cstring](addr outBuf)

proc arithmeticDemo() =
  # A few operations to generate non-trivial .text instructions
  var acc = 0
  for i in 1 .. 10:
    acc += i * i
  echo "sum of squares: ", acc   # 385
  let primes = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29]
  var psum = 0
  for p in primes:
    psum += p
  echo "sum of primes:  ", psum  # 129

proc main() =
  echo "--- NimGuard test binary ---"
  copyDemo()
  moveDemo()
  sprintfDemo()
  arithmeticDemo()
  echo "--- done ---"

main()
