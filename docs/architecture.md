# NimGuard Architecture

## Overview

NimGuard is structured as a set of focused modules with a thin CLI entry point. C library features (disassembly, assembly, emulation) are loaded lazily at runtime so the binary can be built and run without those libraries installed.

## Module Structure

```
src/
  main.nim              CLI entry point and flag dispatch
  binary.nim            ELF and PE header parsing (pure Nim, no C deps)
  patcher.nim           Static patching and emulation-based patch testing
  rules.nim             JSON patch rule loading and default rule set
  instrumentation.nim   Pre/post-execution hook types and hook registration
  disassembler.nim      Capstone-backed disassembly (lazy-loaded)
  assembler.nim         Keystone-backed assembly (lazy-loaded)
  emulator.nim          Unicorn-backed CPU emulation (lazy-loaded)
  process.nim           Linux ptrace process control
  winprocess.nim        Windows Win32 debug API process control
  runtime.nim           Cross-platform dispatcher (ptrace on Linux, Win32 on Windows)
  winruntime.nim        Higher-level Windows instrumentation operations
  bindings/
    capstone.nim        Capstone C FFI declarations
    keystone.nim        Keystone C FFI declarations
    unicorn.nim         Unicorn C FFI declarations
```

## Module Descriptions

### main.nim

Parses CLI flags using `parseopt` and dispatches to the appropriate module procedures. Handles two top-level modes: static analysis (binary path required) and live process instrumentation (`--attach <pid>`).

### binary.nim

Pure-Nim ELF and PE parser. Reads 32-bit and 64-bit variants of both formats, extracts section headers with virtual addresses, file offsets, sizes, and RWX flags, and identifies the architecture (x86, x64, ARM, ARM64). No C libraries required.

### patcher.nim

Reads the parsed binary, applies `PatchRule` entries (byte substitution), and writes the result to an output file. Also provides `testPatchInEmulator`, which loads the binary into Unicorn and verifies a proposed patch does not crash emulation before the patch is written to disk.

### rules.nim

Loads patch rules from a JSON file. Provides a default rule set used when no `--rules` file is given. Each rule has an identifier, description, condition string, and patch string.

### instrumentation.nim

Defines `HookType` and `InstrumentationHook` types. Provides `setupHooks`, which runs `analyzeBinary` and registers a pre-execution hook for each flagged function name. Used by the `--monitor` flag.

### disassembler.nim + bindings/capstone.nim

`bindings/capstone.nim` declares the Capstone C API via `{.importc.}` and loads `libcapstone` at runtime using a manual lazy-loader so a missing library produces a clear error rather than a link failure. `disassembler.nim` wraps the FFI with Nim-typed procedures: `disassembleSection` returns a `seq[Instruction]`, and `isCapstoneAvailable` lets callers check availability before use.

### assembler.nim + bindings/keystone.nim

Same pattern as the Capstone layer. `bindings/keystone.nim` lazy-loads `libkeystone`. `assembler.nim` exposes `assembleBlock`, `assembleInstruction`, `generateNop`, and `isKeystoneAvailable`.

### emulator.nim + bindings/unicorn.nim

`bindings/unicorn.nim` lazy-loads `libunicorn`. `emulator.nim` provides `createEmulator`, `closeEmulator`, `loadBinary`, `emulateRange`, and `isUnicornAvailable`. Emulator contexts map the binary's `.text` section into Unicorn memory and run up to a configurable instruction count.

### ARM support

Binary parsing and disassembly support ARM and AArch64 via Capstone. `makeNops()` in `assembler.nim` generates correct NOP byte sequences for ARM (4-byte `MOV R0,R0`), ARM Thumb (2-byte `0x00 0xBF`), and AArch64 (4-byte `NOP`).

Runtime hooking and breakpoint injection are now architecture-aware:

- **`hookFunction`** generates the correct trampoline for the detected target architecture:
  - x86/x64: relative `JMP rel32` (5 bytes) or absolute indirect `JMP [RIP+0]` (14 bytes)
  - ARM32: `LDR PC, [PC, #-4]` + 4-byte absolute target (8 bytes total)
  - AArch64: `LDR X16, #8; BR X16` + 8-byte absolute target (16 bytes total)
- **`injectBreakpoint`** writes the correct trap instruction for the target architecture:
  - x86/x64: `INT3` (0xCC, 1 byte)
  - ARM32 ARM mode: `BKPT #0` (0xE1200070, 4 bytes, little-endian: `70 00 20 E1`)
  - ARM32 Thumb mode: `BKPT #0` (0xBE00, 2 bytes, little-endian: `00 BE`)
  - AArch64: `BRK #0` (0xD4200000, 4 bytes, little-endian: `00 00 20 D4`)

The helper procs `buildArm32Trampoline`, `buildAarch64Trampoline`, and `breakpointInstructionBytes` are exported from `runtime.nim` for unit testing. All byte-sequence tests run on x86 hosts without ARM hardware or QEMU. Live ARM instrumentation requires an ARM target process.

### process.nim

Wraps the Linux `ptrace(2)` syscall. Provides `attachProcess`, `detachProcess`, `readProcessMemory`, `writeProcessMemory`, `getRegisters`, `setRegisters`, `injectBreakpoint`, `removeBreakpoint`, and `traceSyscalls`. On non-Linux platforms all procedures return a `pePlatform` error without performing any action.

### winprocess.nim

Wraps the Windows debugging API (`OpenProcess`, `ReadProcessMemory`, `WriteProcessMemory`, `DebugActiveProcess`, `WaitForDebugEvent`, etc.). Provides the same logical interface as `process.nim`. On non-Windows platforms all procedures return a `wpPlatform` error.

### runtime.nim

Cross-platform dispatcher. On Linux it delegates to `process.nim`; on Windows it delegates to `winprocess.nim`; on other platforms it returns a not-supported error. Callers import only `runtime.nim` and never reference the platform modules directly.

### winruntime.nim

Higher-level Windows instrumentation built on `winprocess.nim`. Provides `attachProcess`, `detachProcess`, `patchProcessMemory`, `injectBreakpoint`, and `monitorSyscalls` with Windows-specific semantics (debug event loop, INT3 breakpoints via `WriteProcessMemory`).

## Data Flow

### Static analysis path

```
main.nim
  -> binary.nim          parseBinary()      -> BinaryInfo
  -> disassembler.nim    disassembleSection() -> seq[Instruction]
  -> patcher.nim         analyzeBinary()    -> BinaryAnalysis
  -> rules.nim           loadRules()        -> seq[PatchRule]
  -> patcher.nim         applyPatches()     -> patched file on disk
  -> emulator.nim        emulateRange()     -> EmulationResult
```

### Live instrumentation path

```
main.nim
  -> runtime.nim         attachProcess()
  -> runtime.nim         injectBreakpoint() / patchProcessMemory() / monitorSyscalls()
  -> runtime.nim         detachProcess()
```

## Dependency Notes

- The three C libraries (Capstone, Keystone, Unicorn) are optional at build time and runtime. Each binding module exports an `isXxxAvailable()` proc that returns false when the library is not found, allowing the caller to print a helpful message instead of crashing.
- `process.nim` and `winprocess.nim` compile on all platforms but are no-ops outside their target OS. This keeps the build matrix simple.
- No external Nim packages are required. All C interop uses direct FFI.
