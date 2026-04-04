# NimGuard - Thin FFI wrapper for the Keystone assembler library.
# Uses manual lazy loading (loadLib/symAddr) so the library is optional:
# if it is absent the wrapper procs return error values rather than crashing.
#
# System dependency: libkeystone must be installed at the OS level.
#   Linux:   sudo apt-get install libkeystone-dev  (or build from source)
#   macOS:   brew install keystone
#   Windows: download keystone.dll from https://www.keystone-engine.org/
import dynlib

when defined(windows):
  const keystoneDynlib* = "keystone.dll"
elif defined(macosx):
  const keystoneDynlib* = "libkeystone.dylib"
else:
  const keystoneDynlib* = "libkeystone.so"

# Architecture constants (ks_arch enum values from keystone.h).
const
  KS_ARCH_ARM*   = 1.cint
  KS_ARCH_ARM64* = 2.cint
  KS_ARCH_X86*   = 4.cint

# Mode constants (ks_mode enum bit flags from keystone.h).
const
  KS_MODE_LITTLE_ENDIAN* = 0.cint
  KS_MODE_ARM*           = (1 shl 0).cint
  KS_MODE_THUMB*         = (1 shl 4).cint
  KS_MODE_16*            = (1 shl 1).cint
  KS_MODE_32*            = (1 shl 2).cint
  KS_MODE_64*            = (1 shl 3).cint

# Error codes (ks_err enum values from keystone.h).
const
  KS_ERR_OK*   = 0.cint
  KS_ERR_ARCH* = 21.cint  # Returned when the library cannot be loaded.

# Opaque engine type.
type KsEngine* = object

# ---------------------------------------------------------------------------
# Lazy library loader.
# ---------------------------------------------------------------------------

type
  KsOpenFn  = proc(arch: cint, mode: cint, ks: ptr ptr KsEngine): cint {.cdecl.}
  KsAsmFn   = proc(ks: ptr KsEngine, str: cstring, address: uint64,
                   enc: ptr ptr byte, encSize: ptr csize_t,
                   statCount: ptr csize_t): cint {.cdecl.}
  KsFreeFn  = proc(p: ptr byte) {.cdecl.}
  KsCloseFn = proc(ks: ptr KsEngine): cint {.cdecl.}

var ksLib:      LibHandle
var ksOpenPtr:  KsOpenFn
var ksAsmPtr:   KsAsmFn
var ksFreePtr:  KsFreeFn
var ksClosePtr: KsCloseFn

proc ksLoad(): bool =
  if ksLib != nil: return true
  ksLib = loadLib(keystoneDynlib)
  if ksLib == nil: return false
  ksOpenPtr  = cast[KsOpenFn](symAddr(ksLib, "ks_open"))
  ksAsmPtr   = cast[KsAsmFn](symAddr(ksLib, "ks_asm"))
  ksFreePtr  = cast[KsFreeFn](symAddr(ksLib, "ks_free"))
  ksClosePtr = cast[KsCloseFn](symAddr(ksLib, "ks_close"))
  result = ksOpenPtr != nil

# ---------------------------------------------------------------------------
# Public API (mirrors the original {.dynlib.} declarations).
# ---------------------------------------------------------------------------

proc ks_open*(arch: cint, mode: cint, ks: ptr ptr KsEngine): cint =
  if not ksLoad() or ksOpenPtr == nil: return KS_ERR_ARCH
  ksOpenPtr(arch, mode, ks)

proc ks_asm*(ks: ptr KsEngine, str: cstring, address: uint64,
             encoding: ptr ptr byte, encodingSize: ptr csize_t,
             statCount: ptr csize_t): cint =
  if not ksLoad() or ksAsmPtr == nil: return KS_ERR_ARCH
  ksAsmPtr(ks, str, address, encoding, encodingSize, statCount)

proc ks_free*(p: ptr byte) =
  if ksLoad() and ksFreePtr != nil:
    ksFreePtr(p)

proc ks_close*(ks: ptr KsEngine): cint =
  if not ksLoad() or ksClosePtr == nil: return KS_ERR_ARCH
  ksClosePtr(ks)
