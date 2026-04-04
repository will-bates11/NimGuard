# NimGuard - Dynamic Binary Patching & Instrumentation Tool

version       = "0.1.0"
author        = "William Bates"
description   = "Dynamic binary patching and instrumentation tool for legacy systems."
license       = "MIT"
srcDir        = "src"

# Specify required Nim version
requires "nim >= 1.6.0"

# External C library dependencies (must be installed at the OS level):
#   Capstone:  https://www.capstone-engine.org/
#   Keystone:  https://www.keystone-engine.org/
#   Unicorn:   https://www.unicorn-engine.org/
# Nim FFI wrappers for these libraries will be added in Phase 2.

# Include directories for external bindings (modify if needed)
installDirs = @["src"]

# After installation, display usage information
afterInstall:
  echo "NimGuard has been installed successfully!"
  echo "Run './nimguard --help' to get started."

# Testing
task test, "Run unit tests":
  exec "nim c -r --path:src tests/test_patcher.nim"

# Custom build task
task build, "Compile NimGuard":
  exec "nim c -d:release --path:src -o:nimguard src/main.nim"
