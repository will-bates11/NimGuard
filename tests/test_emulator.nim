# NimGuard - Unit Tests for the Emulator Module
import unittest, emulator, binary
import bindings/unicorn

suite "Emulator Module Tests":

  test "isUnicornAvailable returns a boolean without raising":
    let available = isUnicornAvailable()
    check available == true or available == false

  test "createEmulator returns a context without raising":
    var ctx = createEmulator(archX64)
    defer: closeEmulator(ctx)
    if isUnicornAvailable():
      check ctx.engine != nil
    else:
      check ctx.engine == nil

  test "createEmulator works for x86 32-bit mode":
    var ctx = createEmulator(archX86)
    defer: closeEmulator(ctx)
    check ctx.arch == archX86

  test "createEmulator works for ARM mode":
    var ctx = createEmulator(archARM)
    defer: closeEmulator(ctx)
    check ctx.arch == archARM

  test "closeEmulator is safe to call on a nil engine":
    var ctx = EmulatorContext()
    closeEmulator(ctx)
    # Second call must not raise.
    closeEmulator(ctx)

  test "closeEmulator is safe to call twice on a real context":
    if not isUnicornAvailable():
      skip()
    else:
      var ctx = createEmulator(archX64)
      closeEmulator(ctx)
      closeEmulator(ctx)

  test "loadMemory returns false when engine is nil":
    var ctx = EmulatorContext()
    check ctx.loadMemory(0x1000'u64, @[0x90'u8]) == false

  test "loadMemory returns false for empty data":
    var ctx = createEmulator(archX64)
    defer: closeEmulator(ctx)
    check ctx.loadMemory(0x1000'u64, @[]) == false

  test "loadMemory succeeds with valid data when Unicorn available":
    if not isUnicornAvailable():
      skip()
    else:
      var ctx = createEmulator(archX64)
      defer: closeEmulator(ctx)
      let data: seq[byte] = @[0x90'u8, 0x90'u8]
      check ctx.loadMemory(0x00401000'u64, data) == true

  test "readRegister returns 0 for nil engine":
    let ctx = EmulatorContext()
    check ctx.readRegister(UC_X86_REG_RAX) == 0'u64

  test "writeRegister returns false for nil engine":
    var ctx = EmulatorContext()
    check ctx.writeRegister(UC_X86_REG_RAX, 42'u64) == false

  test "emulateRange returns failure with descriptive message for nil engine":
    var ctx = EmulatorContext()
    let res = ctx.emulateRange(0x1000'u64, 0x1010'u64)
    check res.success == false
    check res.errorMsg.len > 0

  test "addCodeHook returns false for nil engine":
    proc dummyHook(uc: ptr UcEngine, address: uint64, size: uint32,
                   userData: pointer) {.cdecl.} = discard
    var ctx = EmulatorContext()
    check ctx.addCodeHook(dummyHook) == false

  test "addMemoryHook returns false for nil engine":
    var ctx = EmulatorContext()
    check ctx.addMemoryHook(UC_HOOK_MEM_READ, nil) == false

  test "register write and read round-trip":
    if not isUnicornAvailable():
      skip()
    else:
      var ctx = createEmulator(archX64)
      defer: closeEmulator(ctx)
      check ctx.writeRegister(UC_X86_REG_RAX, 0xDEADBEEF'u64) == true
      check ctx.readRegister(UC_X86_REG_RAX) == 0xDEADBEEF'u64

  test "register write and read round-trip for RBX":
    if not isUnicornAvailable():
      skip()
    else:
      var ctx = createEmulator(archX64)
      defer: closeEmulator(ctx)
      check ctx.writeRegister(UC_X86_REG_RBX, 0x1234'u64) == true
      check ctx.readRegister(UC_X86_REG_RBX) == 0x1234'u64

  test "emulate a NOP sled executes without error":
    if not isUnicornAvailable():
      skip()
    else:
      var ctx = createEmulator(archX64)
      defer: closeEmulator(ctx)

      # Four NOP bytes. The emulator stops after maxInstructions = 4.
      let code: seq[byte] = @[0x90'u8, 0x90'u8, 0x90'u8, 0x90'u8]
      let base = 0x00401000'u64
      check ctx.loadMemory(base, code) == true

      let res = ctx.emulateRange(base, base + uint64(code.len), 4)
      check res.success == true

  test "emulate mov eax, 42 and read register result":
    if not isUnicornAvailable():
      skip()
    else:
      var ctx = createEmulator(archX64)
      defer: closeEmulator(ctx)

      # Encoding: b8 2a 00 00 00  (mov eax, 42)
      let code: seq[byte] = @[0xb8'u8, 0x2a'u8, 0x00'u8, 0x00'u8, 0x00'u8]
      let base = 0x00401000'u64
      check ctx.loadMemory(base, code) == true

      # Execute exactly 1 instruction and verify EAX.
      let res = ctx.emulateRange(base, base + uint64(code.len), 1)
      check res.success == true
      check ctx.readRegister(UC_X86_REG_EAX) == 42'u64

  test "emulate xor rax, rax zeroes the register":
    if not isUnicornAvailable():
      skip()
    else:
      var ctx = createEmulator(archX64)
      defer: closeEmulator(ctx)

      check ctx.writeRegister(UC_X86_REG_RAX, 0xFFFF'u64) == true

      # Encoding: 48 31 c0  (xor rax, rax)
      let code: seq[byte] = @[0x48'u8, 0x31'u8, 0xc0'u8]
      let base = 0x00401000'u64
      check ctx.loadMemory(base, code) == true

      let res = ctx.emulateRange(base, base + uint64(code.len), 1)
      check res.success == true
      check ctx.readRegister(UC_X86_REG_RAX) == 0'u64

  test "code hook fires for each instruction in a NOP sled":
    if not isUnicornAvailable():
      skip()
    else:
      var ctx = createEmulator(archX64)
      defer: closeEmulator(ctx)

      var counter: int = 0

      proc countHook(uc: ptr UcEngine, address: uint64, size: uint32,
                     userData: pointer) {.cdecl.} =
        var p = cast[ptr int](userData)
        p[] += 1

      let base = 0x00401000'u64
      let code: seq[byte] = @[0x90'u8, 0x90'u8, 0x90'u8, 0x90'u8]
      check ctx.loadMemory(base, code) == true
      check ctx.addCodeHook(countHook, addr counter) == true

      discard ctx.emulateRange(base, base + uint64(code.len), 4)
      check counter == 4

  test "loadBinary returns false when engine is nil":
    var ctx = EmulatorContext()
    let info = parseBinary("nonexistent_binary.elf")
    check ctx.loadBinary(info) == false

  test "loadBinary returns false for unknown binary format":
    if not isUnicornAvailable():
      skip()
    else:
      var ctx = createEmulator(archX64)
      defer: closeEmulator(ctx)
      # parseBinary on a nonexistent file returns bfUnknown with no sections.
      let info = parseBinary("nonexistent_binary_xyz.elf")
      check ctx.loadBinary(info, ".text") == false

  test "isUnicornAvailable does not raise when library is missing":
    # Regardless of whether Unicorn is installed, the call must not raise.
    let available = isUnicornAvailable()
    check available == true or available == false
