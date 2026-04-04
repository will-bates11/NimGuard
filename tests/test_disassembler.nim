# NimGuard - Unit Tests for the Disassembler Module
#
# Tests that require Capstone (disassembleBytes, disassembleSection) call
# isCapstoneAvailable() first and skip gracefully if the library is absent.
# Tests for pure-Nim logic (findDangerousCalls, scanImportStrings) run
# unconditionally.
import unittest, disassembler, binary

# ---------------------------------------------------------------------------
# Helper: skip a test when Capstone is not installed.
# ---------------------------------------------------------------------------
template requireCapstone() =
  if not isCapstoneAvailable():
    skip()

# ---------------------------------------------------------------------------
# Suite: Capstone availability probe
# ---------------------------------------------------------------------------
suite "Capstone Availability":

  test "isCapstoneAvailable returns a bool without crashing":
    # Just verify the call does not raise, regardless of result.
    let available = isCapstoneAvailable()
    check available == true or available == false

# ---------------------------------------------------------------------------
# Suite: disassembleBytes
# ---------------------------------------------------------------------------
suite "disassembleBytes":

  test "Empty byte array returns empty instruction list":
    # Does not require Capstone.
    let result = disassembleBytes(@[], 0'u64, archX64)
    check result.len == 0

  test "NOP byte (0x90) decodes as 'nop' on x64":
    requireCapstone()
    let data: seq[byte] = @[0x90'u8]
    let instrs = disassembleBytes(data, 0x1000'u64, archX64)
    check instrs.len == 1
    check instrs[0].mnemonic == "nop"
    check instrs[0].address  == 0x1000'u64
    check instrs[0].rawBytes == @[0x90'u8]

  test "RET byte (0xC3) decodes as 'ret' on x64":
    requireCapstone()
    let data: seq[byte] = @[0xC3'u8]
    let instrs = disassembleBytes(data, 0x2000'u64, archX64)
    check instrs.len == 1
    check instrs[0].mnemonic == "ret"
    check instrs[0].address  == 0x2000'u64

  test "Function prologue bytes decode to push/mov on x64":
    requireCapstone()
    # 55           push rbp
    # 48 89 E5     mov  rbp, rsp
    let data: seq[byte] = @[0x55'u8, 0x48'u8, 0x89'u8, 0xE5'u8]
    let instrs = disassembleBytes(data, 0x4000'u64, archX64)
    check instrs.len == 2
    check instrs[0].mnemonic == "push"
    check instrs[0].address  == 0x4000'u64
    check instrs[1].mnemonic == "mov"
    check instrs[1].address  == 0x4001'u64

  test "Multiple instructions have sequential addresses":
    requireCapstone()
    # 90 = nop (1 byte), C3 = ret (1 byte)
    let data: seq[byte] = @[0x90'u8, 0xC3'u8]
    let instrs = disassembleBytes(data, 0x5000'u64, archX64)
    check instrs.len == 2
    check instrs[0].address == 0x5000'u64
    check instrs[1].address == 0x5001'u64

  test "Invalid/garbage bytes return empty or partial result without crashing":
    requireCapstone()
    # 0xFF 0xFF is not a valid x64 instruction at this position; Capstone
    # may decode it partially or return empty, but must not raise.
    let data: seq[byte] = @[0xFF'u8, 0xFF'u8, 0xFF'u8, 0xFF'u8]
    let instrs = disassembleBytes(data, 0'u64, archX64)
    # We only check it did not crash; result may be empty or partial.
    check instrs.len >= 0

  test "Base address is reflected in instruction addresses":
    requireCapstone()
    let data: seq[byte] = @[0x90'u8]
    let base = 0xDEAD0000'u64
    let instrs = disassembleBytes(data, base, archX64)
    check instrs.len == 1
    check instrs[0].address == base

# ---------------------------------------------------------------------------
# Suite: disassembleSection (pure-Nim paths that do not need Capstone)
# ---------------------------------------------------------------------------
suite "disassembleSection":

  test "Section not found returns empty list":
    # BinaryInfo with no sections, does not need Capstone.
    let info = BinaryInfo(
      filePath:     "dummy",
      format:       bfELF,
      architecture: archX64,
      entryPoint:   0'u64,
      sections:     @[],
      rawBytes:     @[]
    )
    let instrs = disassembleSection(info, ".text")
    check instrs.len == 0

  test "Section with zero size returns empty list":
    let sec = Section(
      name:           ".text",
      virtualAddress: 0x1000'u64,
      fileOffset:     0'u64,
      size:           0'u64,
      flags:          SectionFlags(readable: true, writable: false, executable: true)
    )
    let info = BinaryInfo(
      filePath:     "dummy",
      format:       bfELF,
      architecture: archX64,
      entryPoint:   0'u64,
      sections:     @[sec],
      rawBytes:     @[]
    )
    let instrs = disassembleSection(info, ".text")
    check instrs.len == 0

# ---------------------------------------------------------------------------
# Suite: findDangerousCalls (pure-Nim, no Capstone required)
# ---------------------------------------------------------------------------
suite "findDangerousCalls":

  test "Empty instruction list returns empty result":
    check findDangerousCalls(@[]).len == 0

  test "Non-call instructions are ignored":
    let instrs = @[
      Instruction(address: 0, mnemonic: "mov",  opStr: "strcpy", rawBytes: @[]),
      Instruction(address: 1, mnemonic: "push", opStr: "gets",   rawBytes: @[])
    ]
    check findDangerousCalls(instrs).len == 0

  test "Call to strcpy is detected":
    let instrs = @[
      Instruction(address: 0x100, mnemonic: "call", opStr: "strcpy", rawBytes: @[])
    ]
    let found = findDangerousCalls(instrs)
    check "strcpy" in found

  test "Call to gets is detected":
    let instrs = @[
      Instruction(address: 0x200, mnemonic: "call", opStr: "gets", rawBytes: @[])
    ]
    let found = findDangerousCalls(instrs)
    check "gets" in found

  test "Call to sprintf is detected":
    let instrs = @[
      Instruction(address: 0x300, mnemonic: "call", opStr: "sprintf", rawBytes: @[])
    ]
    let found = findDangerousCalls(instrs)
    check "sprintf" in found

  test "PLT-style operand (strcpy@plt) is detected":
    let instrs = @[
      Instruction(address: 0x400, mnemonic: "call", opStr: "strcpy@plt", rawBytes: @[])
    ]
    let found = findDangerousCalls(instrs)
    check "strcpy" in found

  test "Multiple distinct dangerous calls each appear once":
    let instrs = @[
      Instruction(address: 0x100, mnemonic: "call", opStr: "strcpy", rawBytes: @[]),
      Instruction(address: 0x200, mnemonic: "call", opStr: "gets",   rawBytes: @[]),
      Instruction(address: 0x300, mnemonic: "call", opStr: "strcpy", rawBytes: @[])
    ]
    let found = findDangerousCalls(instrs)
    check found.len == 2
    check "strcpy" in found
    check "gets" in found

  test "Safe function calls are not flagged":
    let instrs = @[
      Instruction(address: 0x100, mnemonic: "call", opStr: "printf",  rawBytes: @[]),
      Instruction(address: 0x200, mnemonic: "call", opStr: "malloc",  rawBytes: @[]),
      Instruction(address: 0x300, mnemonic: "call", opStr: "strtol",  rawBytes: @[])
    ]
    check findDangerousCalls(instrs).len == 0

# ---------------------------------------------------------------------------
# Suite: scanImportStrings (pure-Nim, no Capstone required)
# ---------------------------------------------------------------------------
suite "scanImportStrings":

  test "Empty rawBytes returns empty result":
    let info = BinaryInfo(rawBytes: @[])
    check scanImportStrings(info).len == 0

  test "Binary containing 'strcpy' string is detected":
    var raw: seq[byte]
    for c in "strcpy": raw.add(byte(c))
    raw.add(0x00)
    let info = BinaryInfo(rawBytes: raw)
    check "strcpy" in scanImportStrings(info)

  test "Binary containing 'gets' string is detected":
    var raw: seq[byte]
    for c in "gets": raw.add(byte(c))
    raw.add(0x00)
    let info = BinaryInfo(rawBytes: raw)
    check "gets" in scanImportStrings(info)

  test "Binary with no dangerous strings returns empty result":
    var raw: seq[byte]
    for c in "main\x00printf\x00exit\x00": raw.add(byte(c))
    let info = BinaryInfo(rawBytes: raw)
    check scanImportStrings(info).len == 0
