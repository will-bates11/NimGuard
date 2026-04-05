# NimGuard - Thin FFI wrapper for the Capstone disassembly library.
# Uses manual lazy loading (loadLib/symAddr) so the library is optional:
# if it is absent the wrapper procs return error values rather than crashing.
#
# System dependency: libcapstone must be installed at the OS level.
#   Linux:   sudo apt-get install libcapstone-dev
#   macOS:   brew install capstone
#   Windows: place capstone.dll (from the capstone PyPI wheel or a release
#            build) next to the nimguard binary.
#
# Version compatibility:
#   Capstone 4.x uses bytes[16] in cs_insn (MAX_INSN_SIZE=16).
#   Capstone 5.x uses bytes[24] in cs_insn (MAX_INSN_SIZE=24).
#   This binding detects the loaded version via cs_version() and computes
#   the correct field offsets at runtime.
import dynlib

when defined(windows):
  const capstoneDynlib* = "capstone.dll"
elif defined(macosx):
  const capstoneDynlib* = "libcapstone.dylib"
else:
  const capstoneDynlib* = "libcapstone.so"

# Architecture constants (cs_arch enum values from capstone.h).
const
  CS_ARCH_ARM*   = 0.cint
  CS_ARCH_ARM64* = 1.cint
  CS_ARCH_X86*   = 3.cint

# Mode constants (cs_mode enum bit flags from capstone.h).
const
  CS_MODE_ARM*   = 0.cint
  CS_MODE_THUMB* = (1 shl 4).cint
  CS_MODE_16*    = (1 shl 1).cint
  CS_MODE_32*    = (1 shl 2).cint
  CS_MODE_64*    = (1 shl 3).cint

# Error codes (cs_err enum values from capstone.h).
const
  CS_ERR_OK*   = 0.cint
  CS_ERR_ARCH* = 8.cint  # Returned when the library cannot be loaded.

# Opaque handle type (csh in C, defined as size_t).
type CsHandle* = csize_t

# CsInsn is treated as an opaque byte array. Field access is done via helper
# procs below that compute offsets at runtime based on the detected version.
# Using a fixed-size array avoids depending on a compile-time struct layout.
# 256 bytes is larger than any cs_insn size (v4: 240 B, v5: 248 B).
type CsInsn* = array[256, byte]

# ---------------------------------------------------------------------------
# Lazy library loader + version detection.
# ---------------------------------------------------------------------------

type
  CsOpenFn    = proc(arch: cint, mode: cint, h: ptr CsHandle): cint {.cdecl.}
  CsDisasmFn  = proc(h: CsHandle, code: ptr byte, sz: csize_t,
                     address: uint64, count: csize_t,
                     insn: ptr pointer): csize_t {.cdecl.}
  CsFreeFn    = proc(insn: pointer, count: csize_t) {.cdecl.}
  CsCloseFn   = proc(h: ptr CsHandle): cint {.cdecl.}
  CsVersionFn = proc(major: ptr cint, minor: ptr cint): cuint {.cdecl.}

var csLib:        LibHandle
var csOpenPtr:    CsOpenFn
var csDisPtr:     CsDisasmFn
var csFreePtr:    CsFreeFn
var csClosePtr:   CsCloseFn
var csVersionPtr: CsVersionFn

# Runtime-detected layout parameters (set once on first library load).
var csInsnBytesLen*:     int = 16  # 16 for v4, 24 for v5
var csInsnStride*:       int = 240 # sizeof(cs_insn): 240 for v4, 248 for v5
var csInsnMnemonicOff*:  int = 34  # offset of mnemonic field
var csInsnOpStrOff*:     int = 66  # offset of op_str field

proc csDetectLayout() =
  # cs_insn field layout (both versions):
  #   offset  0: id        (uint32,  4 B)
  #   offset  4: <padding> (         4 B, to align uint64)
  #   offset  8: address   (uint64,  8 B)
  #   offset 16: size      (uint16,  2 B)
  #   offset 18: bytes     (uint8[], 16 B v4 / 24 B v5)
  #   offset 34/42: mnemonic (char[32])
  #   offset 66/74: op_str   (char[160])
  #   padding + pointer:  struct total 240 B (v4) / 248 B (v5)
  if csVersionPtr == nil: return
  var maj, min: cint
  discard csVersionPtr(addr maj, addr min)
  if maj >= 5:
    csInsnBytesLen    = 24
    csInsnStride      = 248
    csInsnMnemonicOff = 42
    csInsnOpStrOff    = 74
  else:
    csInsnBytesLen    = 16
    csInsnStride      = 240
    csInsnMnemonicOff = 34
    csInsnOpStrOff    = 66

proc csLoad(): bool =
  if csLib != nil: return true
  csLib = loadLib(capstoneDynlib)
  if csLib == nil: return false
  csOpenPtr    = cast[CsOpenFn](symAddr(csLib, "cs_open"))
  csDisPtr     = cast[CsDisasmFn](symAddr(csLib, "cs_disasm"))
  csFreePtr    = cast[CsFreeFn](symAddr(csLib, "cs_free"))
  csClosePtr   = cast[CsCloseFn](symAddr(csLib, "cs_close"))
  csVersionPtr = cast[CsVersionFn](symAddr(csLib, "cs_version"))
  csDetectLayout()
  result = csOpenPtr != nil

# ---------------------------------------------------------------------------
# cs_insn field accessors (pointer-based, version-independent).
# ---------------------------------------------------------------------------

proc csInsnGetAddress*(p: pointer): uint64 {.inline.} =
  cast[ptr uint64](cast[int](p) + 8)[]

proc csInsnGetSize*(p: pointer): uint16 {.inline.} =
  cast[ptr uint16](cast[int](p) + 16)[]

proc csInsnGetByte*(p: pointer, i: int): byte {.inline.} =
  cast[ptr byte](cast[int](p) + 18 + i)[]

proc csInsnGetMnemonic*(p: pointer): string =
  let s = cast[cstring](cast[int](p) + csInsnMnemonicOff)
  result = $s

proc csInsnGetOpStr*(p: pointer): string =
  let s = cast[cstring](cast[int](p) + csInsnOpStrOff)
  result = $s

# Return a pointer to the i-th cs_insn in a contiguous array returned by
# cs_disasm, advancing by the runtime-detected struct stride.
proc csInsnAt*(base: pointer, i: int): pointer {.inline.} =
  cast[pointer](cast[int](base) + i * csInsnStride)

# ---------------------------------------------------------------------------
# Public API.
# ---------------------------------------------------------------------------

proc cs_open*(arch: cint, mode: cint, h: ptr CsHandle): cint =
  if not csLoad() or csOpenPtr == nil: return CS_ERR_ARCH
  csOpenPtr(arch, mode, h)

proc cs_disasm*(h: CsHandle, code: ptr byte, sz: csize_t,
                address: uint64, count: csize_t,
                insn: ptr pointer): csize_t =
  if not csLoad() or csDisPtr == nil: return csize_t(0)
  csDisPtr(h, code, sz, address, count, insn)

proc cs_free*(insn: pointer, count: csize_t) =
  if csLoad() and csFreePtr != nil:
    csFreePtr(insn, count)

proc cs_close*(h: ptr CsHandle): cint =
  if not csLoad() or csClosePtr == nil: return CS_ERR_ARCH
  csClosePtr(h)
