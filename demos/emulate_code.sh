#!/usr/bin/env bash
# Demo: emulate the .text section of a binary through Unicorn.
# Unicorn loads the raw .text bytes into a minimal CPU emulator and runs
# up to 256 instructions, logging code hooks and stopping on any error.
#
# Note: real-world binaries will stop early because they reference memory
# (stack, imports, global variables) that is not mapped in the emulator.
# This is expected. The value of the emulator is testing small, self-contained
# code sequences, or emulating patched bytes before writing to disk.
#
# Usage: bash emulate_code.sh [binary]

set -e
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

if   [ -f "$REPO_ROOT/nimguard" ];     then NIMGUARD="$REPO_ROOT/nimguard"
elif [ -f "$REPO_ROOT/nimguard.exe" ]; then NIMGUARD="$REPO_ROOT/nimguard.exe"
else
  echo "[-] nimguard binary not found. Build it first: nim c -d:release src/nimguard.nim"
  exit 1
fi

if [ -n "$1" ]; then
  TARGET="$1"
elif [ -f "$SCRIPT_DIR/test_binary" ]; then
  TARGET="$SCRIPT_DIR/test_binary"
elif [ -f "$SCRIPT_DIR/test_binary.exe" ]; then
  TARGET="$SCRIPT_DIR/test_binary.exe"
else
  echo "[-] No target binary found."
  echo "    Compile the demo binary first:"
  echo "      nim c -d:release -o:demos/test_binary demos/create_test_binary.nim"
  exit 1
fi

echo "Emulating .text section of: $TARGET"
echo "---------------------------------------"
"$NIMGUARD" "$TARGET" --emulate
