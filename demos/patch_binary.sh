#!/usr/bin/env bash
# Demo: patch a binary using a rules file.
# Identifies dangerous imports in the target binary and applies the rules
# defined in sample_rules.json, using Keystone to assemble each patch.
#
# Usage: bash patch_binary.sh [binary] [rules_file] [output_file]
#
# If no arguments are given, uses test_binary, sample_rules.json, and writes
# the patched binary to test_binary_patched (or .exe on Windows).

set -e
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

if   [ -f "$REPO_ROOT/nimguard" ];     then NIMGUARD="$REPO_ROOT/nimguard"
elif [ -f "$REPO_ROOT/nimguard.exe" ]; then NIMGUARD="$REPO_ROOT/nimguard.exe"
else
  echo "[-] nimguard binary not found. Build it first: nim c -d:release src/nimguard.nim"
  exit 1
fi

# Determine target binary
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

# Rules file
RULES="${2:-$SCRIPT_DIR/sample_rules.json}"
if [ ! -f "$RULES" ]; then
  echo "[-] Rules file not found: $RULES"
  exit 1
fi

# Output path
if [ -n "$3" ]; then
  OUTPUT="$3"
elif [[ "$TARGET" == *.exe ]]; then
  OUTPUT="${TARGET%.exe}_patched.exe"
else
  OUTPUT="${TARGET}_patched"
fi

echo "Target:  $TARGET"
echo "Rules:   $RULES"
echo "Output:  $OUTPUT"
echo "---------------------------------------"
"$NIMGUARD" "$TARGET" --patch --rules "$RULES" --output "$OUTPUT"

if [ -f "$OUTPUT" ]; then
  echo ""
  echo "Patch complete. Verifying patched binary:"
  "$NIMGUARD" "$OUTPUT" --analyze
fi
