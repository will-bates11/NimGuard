# NimGuard - Thin FFI wrapper for the Capstone disassembly library.
# Uses manual lazy loading (loadLib/symAddr) so the library is optional:
# if it is absent the wrapper procs return error values rather than crashing.
#
# System dependency: libcapstone must be installed at the OS level.
#   Linux:   sudo apt-get install libcapstone-dev
#   macOS:   brew install capstone
#   Windows: download capstone.dll from https://www.capstone-engine.org/
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

# cs_insn: instruction information struct, matching the C layout exactly.
type
  CsInsn* = object
    id*:       cuint
    address*:  uint64
    size*:     uint16
    bytes*:    array[16, byte]
    mnemonic*: array[32, char]
    opStr*:    array[160, char]
    detail*:   pointer

# ---------------------------------------------------------------------------
# Lazy library loader.
# ---------------------------------------------------------------------------

type
  CsOpenFn   = proc(arch: cint, mode: cint, h: ptr CsHandle): cint {.cdecl.}
  CsDisasmFn = proc(h: CsHandle, code: ptr byte, sz: csize_t,
                    address: uint64, count: csize_t,
                    insn: ptr ptr CsInsn): csize_t {.cdecl.}
  CsFreeFn   = proc(insn: ptr CsInsn, count: csize_t) {.cdecl.}
  CsCloseFn  = proc(h: ptr CsHandle): cint {.cdecl.}

var csLib:      LibHandle
var csOpenPtr:  CsOpenFn
var csDisPtr:   CsDisasmFn
var csFreePtr:  CsFreeFn
var csClosePtr: CsCloseFn

proc csLoad(): bool =
  if csLib != nil: return true
  csLib = loadLib(capstoneDynlib)
  if csLib == nil: return false
  csOpenPtr  = cast[CsOpenFn](symAddr(csLib, "cs_open"))
  csDisPtr   = cast[CsDisasmFn](symAddr(csLib, "cs_disasm"))
  csFreePtr  = cast[CsFreeFn](symAddr(csLib, "cs_free"))
  csClosePtr = cast[CsCloseFn](symAddr(csLib, "cs_close"))
  result = csOpenPtr != nil

# ---------------------------------------------------------------------------
# Public API (mirrors the original {.dynlib.} declarations).
# ---------------------------------------------------------------------------

proc cs_open*(arch: cint, mode: cint, h: ptr CsHandle): cint =
  if not csLoad() or csOpenPtr == nil: return CS_ERR_ARCH
  csOpenPtr(arch, mode, h)

proc cs_disasm*(h: CsHandle, code: ptr byte, sz: csize_t,
                address: uint64, count: csize_t,
                insn: ptr ptr CsInsn): csize_t =
  if not csLoad() or csDisPtr == nil: return csize_t(0)
  csDisPtr(h, code, sz, address, count, insn)

proc cs_free*(insn: ptr CsInsn, count: csize_t) =
  if csLoad() and csFreePtr != nil:
    csFreePtr(insn, count)

proc cs_close*(h: ptr CsHandle): cint =
  if not csLoad() or csClosePtr == nil: return CS_ERR_ARCH
  csClosePtr(h)
