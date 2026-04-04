# NimGuard - Dynamic Binary Patching & Instrumentation Tool

version       = "0.3.0"
author        = "William Bates"
description   = "Dynamic binary patching and instrumentation tool for legacy systems."
license       = "MIT"
srcDir        = "src"

# Specify required Nim version
requires "nim >= 1.6.0"

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
#   Unicorn  (Phase 4, emulation):           https://www.unicorn-engine.org/

# Include directories for external bindings
installDirs = @["src"]

# Testing
task test, "Run unit tests":
  exec "nim c -r --path:src tests/test_patcher.nim"
  exec "nim c -r --path:src tests/test_binary.nim"
  exec "nim c -r --path:src tests/test_disassembler.nim"
  exec "nim c -r --path:src tests/test_assembler.nim"

# Custom build task
task build, "Compile NimGuard":
  exec "nim c -d:release --path:src -o:nimguard src/main.nim"
