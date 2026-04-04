# NimGuard - Dynamic Binary Patching & Instrumentation Tool

version       = "1.0.0"
author        = "Will Bates"
description   = "Binary patching and instrumentation tool for ELF and PE binaries."
license       = "MIT"
srcDir        = "src"

requires "nim >= 2.0.0"

# No external Nim packages are required. Capstone integration uses Nim FFI
# (src/bindings/capstone.nim) to bind directly to the system-installed C library.
#
# System-level C library dependencies (must be installed at the OS level):
#   Capstone (Phase 2, disassembly):
#     Linux:   sudo apt-get install libcapstone-dev
#     macOS:   brew install capstone
#     Windows: download capstone.dll from https://www.capstone-engine.org/
#
#   Keystone (Phase 3, assembly/patching):
#     Linux:   sudo apt-get install libkeystone-dev  (or build from source)
#     macOS:   brew install keystone
#     Windows: download keystone.dll from https://www.keystone-engine.org/
#
#   Unicorn  (Phase 4, emulation):
#     Linux:   sudo apt-get install libunicorn-dev
#     macOS:   brew install unicorn
#     Windows: download unicorn.dll from https://www.unicorn-engine.org/
#
#   ptrace   (Phase 5, runtime instrumentation, Linux only):
#     Linux kernel built-in; no extra packages needed.
#     ptrace_scope may need to be 0 for PTRACE_ATTACH tests:
#       echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope
#     Non-Linux: all process/runtime procs return a platform-not-supported error.
#
#   Win32 API (Phase 6, runtime instrumentation, Windows only):
#     Windows kernel built-in; no extra packages needed.
#     Non-Windows: all winprocess/winruntime procs return a platform-not-supported error.

# Include directories for external bindings
installDirs = @["src"]

# Testing
task test, "Run unit tests":
  exec "nim c -r --path:src tests/test_patcher.nim"
  exec "nim c -r --path:src tests/test_binary.nim"
  exec "nim c -r --path:src tests/test_disassembler.nim"
  exec "nim c -r --path:src tests/test_assembler.nim"
  exec "nim c -r --path:src tests/test_emulator.nim"
  exec "nim c -r --path:src tests/test_process.nim"
  exec "nim c -r --path:src tests/test_runtime.nim"
  exec "nim c -r --path:src tests/test_winprocess.nim"
  exec "nim c -r --path:src tests/test_winruntime.nim"

# Run only the Windows-specific tests
task test_windows, "Run Windows process and runtime tests":
  exec "nim c -r --path:src tests/test_winprocess.nim"
  exec "nim c -r --path:src tests/test_winruntime.nim"

# Custom build task
task build, "Compile NimGuard":
  exec "nim c -d:release --path:src -o:nimguard src/main.nim"
