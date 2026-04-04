# NimGuard - Thin FFI wrapper for the Keystone assembler library.
# Exposes only the subset of the Keystone C API needed for NimGuard:
#   ks_open, ks_asm, ks_free, ks_close, opaque engine type,
#   architecture/mode constants.
#
# System dependency: libkeystone must be installed at the OS level.
#   Linux:   sudo apt-get install libkeystone-dev  (or build from source)
#   macOS:   brew install keystone
#   Windows: download keystone.dll from https://www.keystone-engine.org/

when defined(windows):
  const keystoneDynlib* = "keystone.dll"
elif defined(macosx):
  const keystoneDynlib* = "libkeystone.dylib"
else:
  const keystoneDynlib* = "libkeystone.so"

# Architecture constants (ks_arch enum values from keystone.h).
const
  KS_ARCH_ARM*   = 1.cint   # ARM (including Thumb)
  KS_ARCH_ARM64* = 2.cint   # AArch64
  KS_ARCH_X86*   = 4.cint   # x86 and x86-64

# Mode constants (ks_mode enum bit flags from keystone.h).
const
  KS_MODE_LITTLE_ENDIAN* = 0.cint          # little-endian mode (default)
  KS_MODE_ARM*           = (1 shl 0).cint  # ARM mode
  KS_MODE_THUMB*         = (1 shl 4).cint  # Thumb mode (including Thumb-2)
  KS_MODE_16*            = (1 shl 1).cint  # x86 16-bit
  KS_MODE_32*            = (1 shl 2).cint  # x86 32-bit
  KS_MODE_64*            = (1 shl 3).cint  # x86 64-bit

# Error codes (ks_err enum values from keystone.h).
const
  KS_ERR_OK* = 0.cint  # No error

# Opaque engine type. Keystone uses ks_engine* as the working handle.
# Declared as an incomplete object so Nim never attempts to copy it.
type KsEngine* = object

# ks_open: initialise a Keystone handle for the given architecture and mode.
# Writes the new handle into *ks. Returns KS_ERR_OK on success.
proc ks_open*(arch: cint, mode: cint, ks: ptr ptr KsEngine): cint
  {.importc: "ks_open", dynlib: keystoneDynlib.}

# ks_asm: assemble a string of instructions at a given base address.
# On success returns 0 and writes the encoded byte buffer and its length
# into *encoding and *encodingSize. *statCount receives the number of
# statements assembled. The caller must release *encoding with ks_free.
proc ks_asm*(ks: ptr KsEngine, str: cstring, address: uint64,
             encoding: ptr ptr byte, encodingSize: ptr csize_t,
             statCount: ptr csize_t): cint
  {.importc: "ks_asm", dynlib: keystoneDynlib.}

# ks_free: release a byte buffer previously allocated by ks_asm.
proc ks_free*(p: ptr byte)
  {.importc: "ks_free", dynlib: keystoneDynlib.}

# ks_close: destroy a Keystone handle and release all associated resources.
proc ks_close*(ks: ptr KsEngine): cint
  {.importc: "ks_close", dynlib: keystoneDynlib.}
