#!/usr/bin/env bash
# Demo: analyze a binary and report its format, sections, and dangerous calls.
# Works on Linux (ELF) and Windows (via Git Bash or WSL2 with PE binaries).
#
# Usage: bash analyze_binary.sh [binary]
#   If no binary is given, uses the compiled test_binary from this directory.

set -e
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

# Locate nimguard
if   [ -f "$REPO_ROOT/nimguard" ];     then NIMGUARD="$REPO_ROOT/nimguard"
elif [ -f "$REPO_ROOT/nimguard.exe" ]; then NIMGUARD="$REPO_ROOT/nimguard.exe"
else
  echo "[-] nimguard binary not found. Build it first: nim c -d:release src/nimguard.nim"
  exit 1
fi

# Target binary
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

echo "Analyzing: $TARGET"
echo "---------------------------------------"
"$NIMGUARD" "$TARGET" --analyze
