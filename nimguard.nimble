# NimGuard - Dynamic Binary Patching & Instrumentation Tool

version       = "0.1.0"
author        = "William Bates"
description   = "Dynamic binary patching and instrumentation tool for legacy systems."
license       = "MIT"
srcDir        = "src"

# Specify required Nim version
requires "nim >= 1.6.0"

# Dependencies - Capstone, Keystone, and Unicorn for binary analysis, patching, and emulation
requires "https://github.com/PMunch/nim-capstone"
requires "https://github.com/PMunch/nim-keystone"
requires "https://github.com/PMunch/nim-unicorn"

# Additional system dependencies (if applicable)
# Ensure that Capstone, Keystone, and Unicorn shared libraries are installed on the system.

# Define an executable
bin           = @["nimguard"]

# Compiler Flags
# Enable optimizations and debugging symbols
compile "c"
passL "-O2"
passC "-g"

# Include directories for external bindings (modify if needed)
installDirs   = @["src"]

# Hooks
beforeInstall:
  echo "Building NimGuard..."
  exec "nimble build"

# After installation, display usage information
afterInstall:
  echo "NimGuard has been installed successfully!"
  echo "Run './nimguard --help' to get started."

# Testing
task test, "Run unit tests":
  exec "nimble test"

# Custom build task
task build, "Compile NimGuard":
  exec "nim c -d:release -o:nimguard src/main.nim"