#!/usr/bin/env bash
# Demo: disassemble the .text section of a binary using Capstone.
# Requires capstone.dll (Windows) or libcapstone.so (Linux) to be installed.
#
# Usage: bash disassemble_section.sh [binary]

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

echo "Disassembling .text section of: $TARGET"
echo "---------------------------------------"
"$NIMGUARD" "$TARGET" --disasm
