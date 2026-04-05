# NimGuard - Unit Tests for ARM32 and AArch64 support.
#
# Tests cover pure byte-generation paths that run on any host architecture:
#   - makeNops()  for ARM32 and AArch64 (assembler.nim)
#   - buildArm32Trampoline() and buildAarch64Trampoline() (runtime.nim)
#   - breakpointInstructionBytes() per architecture (runtime.nim)
#
# No live process attachment is required; all assertions are on byte sequences.
import unittest, assembler, binary, runtime

# ---------------------------------------------------------------------------
# NOP generation (assembler.nim)
# ---------------------------------------------------------------------------

suite "ARM NOP Generation":

  test "makeNops ARM32 generates 4 bytes per NOP":
    let nops = makeNops(1, archARM)
    check nops.len == 4

  test "makeNops ARM32 two NOPs produce 8 bytes":
    let nops = makeNops(2, archARM)
    check nops.len == 8

  test "makeNops ARM32 encodes MOV R0,R0 (E1A00000 little-endian: 00 00 A0 E1)":
    let nops = makeNops(1, archARM)
    check nops[0] == 0x00'u8
    check nops[1] == 0x00'u8
    check nops[2] == 0xA0'u8
    check nops[3] == 0xE1'u8

  test "makeNops ARM32 repeats the same 4-byte pattern":
    let nops = makeNops(2, archARM)
    check nops[0] == nops[4]
    check nops[1] == nops[5]
    check nops[2] == nops[6]
    check nops[3] == nops[7]

  test "makeNops AArch64 generates 4 bytes per NOP":
    let nops = makeNops(1, archARM64)
    check nops.len == 4

  test "makeNops AArch64 two NOPs produce 8 bytes":
    let nops = makeNops(2, archARM64)
    check nops.len == 8

  test "makeNops AArch64 encodes NOP (D503201F as stored by assembler)":
    let nops = makeNops(1, archARM64)
    # assembler.nim stores the 4-byte sequence as D5 03 20 1F
    check nops[0] == 0xD5'u8
    check nops[1] == 0x03'u8
    check nops[2] == 0x20'u8
    check nops[3] == 0x1F'u8

  test "makeNops AArch64 repeats the same 4-byte pattern":
    let nops = makeNops(2, archARM64)
    check nops[0] == nops[4]
    check nops[1] == nops[5]
    check nops[2] == nops[6]
    check nops[3] == nops[7]

  test "makeNops x86 still generates single-byte 0x90 NOPs":
    let nops = makeNops(3, archX64)
    check nops.len == 3
    for b in nops:
      check b == 0x90'u8

  test "makeNops zero count returns empty seq for all architectures":
    check makeNops(0, archARM).len == 0
    check makeNops(0, archARM64).len == 0
    check makeNops(0, archX64).len == 0

# ---------------------------------------------------------------------------
# ARM32 trampoline (runtime.nim)
# ---------------------------------------------------------------------------

suite "ARM32 Trampoline Encoding":

  test "ARM32 trampoline is exactly 8 bytes":
    let tramp = buildArm32Trampoline(0xDEADBEEF'u64)
    check tramp.len == 8

  test "ARM32 trampoline first 4 bytes are LDR PC,[PC,#-4] in little-endian":
    # LDR PC, [PC, #-4] = E51FF004 (big-endian value)
    # stored as 04 F0 1F E5 in little-endian memory
    let tramp = buildArm32Trampoline(0'u64)
    check tramp[0] == 0x04'u8
    check tramp[1] == 0xF0'u8
    check tramp[2] == 0x1F'u8
    check tramp[3] == 0xE5'u8

  test "ARM32 trampoline last 4 bytes are hookAddress in little-endian":
    let target = 0x12345678'u64
    let tramp = buildArm32Trampoline(target)
    check tramp[4] == 0x78'u8
    check tramp[5] == 0x56'u8
    check tramp[6] == 0x34'u8
    check tramp[7] == 0x12'u8

  test "ARM32 trampoline encodes address 0xDEADBEEF correctly":
    let tramp = buildArm32Trampoline(0xDEADBEEF'u64)
    check tramp[4] == 0xEF'u8
    check tramp[5] == 0xBE'u8
    check tramp[6] == 0xAD'u8
    check tramp[7] == 0xDE'u8

  test "ARM32 trampoline with zero address produces zero address bytes":
    let tramp = buildArm32Trampoline(0'u64)
    check tramp[4] == 0x00'u8
    check tramp[5] == 0x00'u8
    check tramp[6] == 0x00'u8
    check tramp[7] == 0x00'u8

# ---------------------------------------------------------------------------
# AArch64 trampoline (runtime.nim)
# ---------------------------------------------------------------------------

suite "AArch64 Trampoline Encoding":

  test "AArch64 trampoline is exactly 16 bytes":
    let tramp = buildAarch64Trampoline(0xDEADBEEFCAFEBABE'u64)
    check tramp.len == 16

  test "AArch64 trampoline first 4 bytes are LDR X16,#8 in little-endian":
    # LDR X16, #8 = 58000050 (big-endian value)
    # stored as 50 00 00 58 in little-endian memory
    let tramp = buildAarch64Trampoline(0'u64)
    check tramp[0] == 0x50'u8
    check tramp[1] == 0x00'u8
    check tramp[2] == 0x00'u8
    check tramp[3] == 0x58'u8

  test "AArch64 trampoline bytes 4-7 are BR X16 in little-endian":
    # BR X16 = D61F0200 (big-endian value)
    # stored as 00 02 1F D6 in little-endian memory
    let tramp = buildAarch64Trampoline(0'u64)
    check tramp[4] == 0x00'u8
    check tramp[5] == 0x02'u8
    check tramp[6] == 0x1F'u8
    check tramp[7] == 0xD6'u8

  test "AArch64 trampoline bytes 8-15 are hookAddress in little-endian":
    let target = 0x0123456789ABCDEF'u64
    let tramp = buildAarch64Trampoline(target)
    check tramp[8]  == 0xEF'u8
    check tramp[9]  == 0xCD'u8
    check tramp[10] == 0xAB'u8
    check tramp[11] == 0x89'u8
    check tramp[12] == 0x67'u8
    check tramp[13] == 0x45'u8
    check tramp[14] == 0x23'u8
    check tramp[15] == 0x01'u8

  test "AArch64 trampoline with zero address has zero address bytes":
    let tramp = buildAarch64Trampoline(0'u64)
    for i in 8 ..< 16:
      check tramp[i] == 0x00'u8

# ---------------------------------------------------------------------------
# Breakpoint instruction bytes (runtime.nim)
# ---------------------------------------------------------------------------

suite "Breakpoint Instruction Bytes":

  test "x86/x64 breakpoint is single INT3 byte 0xCC":
    let bkpt = breakpointInstructionBytes(archX64)
    check bkpt.len == 1
    check bkpt[0] == 0xCC'u8

  test "x86 32-bit breakpoint is also INT3 0xCC":
    let bkpt = breakpointInstructionBytes(archX86)
    check bkpt.len == 1
    check bkpt[0] == 0xCC'u8

  test "ARM32 breakpoint is 4-byte BKPT #0 ARM mode":
    # BKPT #0 = E1200070 (big-endian), stored as 70 00 20 E1 (little-endian)
    let bkpt = breakpointInstructionBytes(archARM)
    check bkpt.len == 4
    check bkpt[0] == 0x70'u8
    check bkpt[1] == 0x00'u8
    check bkpt[2] == 0x20'u8
    check bkpt[3] == 0xE1'u8

  test "AArch64 breakpoint is 4-byte BRK #0":
    # BRK #0 = D4200000 (big-endian), stored as 00 00 20 D4 (little-endian)
    let bkpt = breakpointInstructionBytes(archARM64)
    check bkpt.len == 4
    check bkpt[0] == 0x00'u8
    check bkpt[1] == 0x00'u8
    check bkpt[2] == 0x20'u8
    check bkpt[3] == 0xD4'u8
