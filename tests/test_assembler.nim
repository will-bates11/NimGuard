# NimGuard - Unit Tests for the Assembler Module
import unittest, assembler, binary

suite "Assembler Module Tests":

  test "isKeystoneAvailable returns a boolean without raising":
    let available = isKeystoneAvailable()
    check available == true or available == false

  test "assembleInstruction returns empty seq for empty input":
    let bytes = assembleInstruction("", archX64)
    check bytes.len == 0

  test "assembleBlock returns empty output for empty input":
    let output = assembleBlock("", archX64)
    check output.bytes.len == 0
    check output.statCount == 0

  test "assembleInstruction encodes NOP correctly":
    if not isKeystoneAvailable():
      skip()
    else:
      let bytes = assembleInstruction("nop", archX64)
      check bytes.len == 1
      check bytes[0] == 0x90'u8

  test "assembleInstruction encodes RET correctly":
    if not isKeystoneAvailable():
      skip()
    else:
      let bytes = assembleInstruction("ret", archX64)
      check bytes.len == 1
      check bytes[0] == 0xC3'u8

  test "assembleInstruction returns empty seq for invalid instruction":
    if not isKeystoneAvailable():
      skip()
    else:
      let bytes = assembleInstruction("notavalidinstruction xyz_!!!", archX64)
      check bytes.len == 0

  test "assembleBlock encodes multiple semicolon-separated instructions":
    if not isKeystoneAvailable():
      skip()
    else:
      let output = assembleBlock("nop; nop; ret", archX64)
      check output.bytes.len == 3
      check output.statCount == 3
      check output.bytes[0] == 0x90'u8
      check output.bytes[1] == 0x90'u8
      check output.bytes[2] == 0xC3'u8

  test "assembleBlock returns empty output for invalid instructions":
    if not isKeystoneAvailable():
      skip()
    else:
      let output = assembleBlock("notvalid !!!", archX64)
      check output.bytes.len == 0
      check output.statCount == 0

  test "assembleInstruction handles x86 32-bit mode":
    if not isKeystoneAvailable():
      skip()
    else:
      let bytes = assembleInstruction("nop", archX86)
      check bytes.len == 1
      check bytes[0] == 0x90'u8

  test "makeNops generates the correct number of NOP bytes":
    let nops = makeNops(4)
    check nops.len == 4
    for b in nops:
      check b == 0x90'u8

  test "makeNops with zero count returns empty seq":
    let nops = makeNops(0)
    check nops.len == 0

  test "assembleInstruction does not raise when Keystone is unavailable":
    # Regardless of whether Keystone is installed, the call must not raise.
    # With Keystone present it returns encoded bytes; without it returns empty.
    let bytes = assembleInstruction("nop", archX64)
    check bytes.len >= 0
