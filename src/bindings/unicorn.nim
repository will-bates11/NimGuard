# NimGuard - Thin FFI wrapper for the Unicorn CPU emulator library.
# Uses manual lazy loading (loadLib/symAddr) so the library is optional:
# if it is absent the wrapper procs return error values rather than crashing.
#
# System dependency: libunicorn must be installed at the OS level.
#   Linux:   sudo apt-get install libunicorn-dev
#   macOS:   brew install unicorn
#   Windows: download unicorn.dll from https://www.unicorn-engine.org/
import dynlib

when defined(windows):
  const unicornDynlib* = "unicorn.dll"
elif defined(macosx):
  const unicornDynlib* = "libunicorn.dylib"
else:
  const unicornDynlib* = "libunicorn.so"

# Architecture constants (uc_arch enum values from unicorn.h).
const
  UC_ARCH_ARM*   = 1.cint
  UC_ARCH_ARM64* = 2.cint
  UC_ARCH_X86*   = 4.cint

# Mode constants (uc_mode enum bit flags from unicorn.h).
const
  UC_MODE_LITTLE_ENDIAN* = 0.cint
  UC_MODE_ARM*           = 0.cint
  UC_MODE_THUMB*         = (1 shl 4).cint
  UC_MODE_16*            = (1 shl 1).cint
  UC_MODE_32*            = (1 shl 2).cint
  UC_MODE_64*            = (1 shl 3).cint

# Error codes (uc_err enum values from unicorn.h).
const
  UC_ERR_OK*   = 0.cint
  UC_ERR_ARCH* = 9.cint  # Returned when the library cannot be loaded.

# Memory permission flags.
const
  UC_PROT_NONE*  = 0.cuint
  UC_PROT_READ*  = 1.cuint
  UC_PROT_WRITE* = 2.cuint
  UC_PROT_EXEC*  = 4.cuint
  UC_PROT_ALL*   = 7.cuint

# Hook type flags.
const
  UC_HOOK_INTR*               = (1 shl 0).cint
  UC_HOOK_CODE*               = (1 shl 2).cint
  UC_HOOK_BLOCK*              = (1 shl 3).cint
  UC_HOOK_MEM_READ_UNMAPPED*  = (1 shl 4).cint
  UC_HOOK_MEM_WRITE_UNMAPPED* = (1 shl 5).cint
  UC_HOOK_MEM_READ*           = (1 shl 10).cint
  UC_HOOK_MEM_WRITE*          = (1 shl 11).cint

# x86 register IDs.
const
  UC_X86_REG_AX*     =  3.cint
  UC_X86_REG_BX*     =  8.cint
  UC_X86_REG_CX*     = 12.cint
  UC_X86_REG_DX*     = 18.cint
  UC_X86_REG_EAX*    = 19.cint
  UC_X86_REG_EBP*    = 20.cint
  UC_X86_REG_EBX*    = 21.cint
  UC_X86_REG_ECX*    = 22.cint
  UC_X86_REG_EDI*    = 23.cint
  UC_X86_REG_EDX*    = 24.cint
  UC_X86_REG_EFLAGS* = 25.cint
  UC_X86_REG_EIP*    = 26.cint
  UC_X86_REG_ESI*    = 29.cint
  UC_X86_REG_ESP*    = 30.cint
  UC_X86_REG_RAX*    = 35.cint
  UC_X86_REG_RBP*    = 36.cint
  UC_X86_REG_RBX*    = 37.cint
  UC_X86_REG_RCX*    = 38.cint
  UC_X86_REG_RDI*    = 39.cint
  UC_X86_REG_RDX*    = 40.cint
  UC_X86_REG_RIP*    = 41.cint
  UC_X86_REG_RSI*    = 43.cint
  UC_X86_REG_RSP*    = 44.cint

# Opaque engine type.
type UcEngine* = object

# Hook handle type (uc_hook is size_t in C).
type UcHook* = csize_t

# Callback proc type for UC_HOOK_CODE hooks.
type UcCodeHookCb* = proc(uc: ptr UcEngine, address: uint64, size: uint32,
                          userData: pointer) {.cdecl.}

# ---------------------------------------------------------------------------
# Lazy library loader.
# ---------------------------------------------------------------------------

type
  UcOpenFn      = proc(arch: cint, mode: cint, uc: ptr ptr UcEngine): cint {.cdecl.}
  UcCloseFn     = proc(uc: ptr UcEngine): cint {.cdecl.}
  UcMemMapFn    = proc(uc: ptr UcEngine, address: uint64,
                       size: csize_t, perms: cuint): cint {.cdecl.}
  UcMemWriteFn  = proc(uc: ptr UcEngine, address: uint64,
                       bytes: pointer, size: csize_t): cint {.cdecl.}
  UcMemReadFn   = proc(uc: ptr UcEngine, address: uint64,
                       bytes: pointer, size: csize_t): cint {.cdecl.}
  UcRegWriteFn  = proc(uc: ptr UcEngine, regid: cint,
                       value: pointer): cint {.cdecl.}
  UcRegReadFn   = proc(uc: ptr UcEngine, regid: cint,
                       value: pointer): cint {.cdecl.}
  UcEmuStartFn  = proc(uc: ptr UcEngine, begin: uint64, until: uint64,
                       timeout: uint64, count: csize_t): cint {.cdecl.}
  UcEmuStopFn   = proc(uc: ptr UcEngine): cint {.cdecl.}
  UcHookAddFn   = proc(uc: ptr UcEngine, hh: ptr UcHook, hookType: cint,
                       callback: pointer, userData: pointer,
                       begin: uint64, `end`: uint64): cint {.cdecl.}
  UcHookDelFn   = proc(uc: ptr UcEngine, hh: UcHook): cint {.cdecl.}

var ucLib:         LibHandle
var ucOpenPtr:     UcOpenFn
var ucClosePtr:    UcCloseFn
var ucMemMapPtr:   UcMemMapFn
var ucMemWritePtr: UcMemWriteFn
var ucMemReadPtr:  UcMemReadFn
var ucRegWritePtr: UcRegWriteFn
var ucRegReadPtr:  UcRegReadFn
var ucEmuStartPtr: UcEmuStartFn
var ucEmuStopPtr:  UcEmuStopFn
var ucHookAddPtr:  UcHookAddFn
var ucHookDelPtr:  UcHookDelFn

proc ucLoad(): bool =
  if ucLib != nil: return true
  ucLib = loadLib(unicornDynlib)
  if ucLib == nil: return false
  ucOpenPtr     = cast[UcOpenFn](symAddr(ucLib, "uc_open"))
  ucClosePtr    = cast[UcCloseFn](symAddr(ucLib, "uc_close"))
  ucMemMapPtr   = cast[UcMemMapFn](symAddr(ucLib, "uc_mem_map"))
  ucMemWritePtr = cast[UcMemWriteFn](symAddr(ucLib, "uc_mem_write"))
  ucMemReadPtr  = cast[UcMemReadFn](symAddr(ucLib, "uc_mem_read"))
  ucRegWritePtr = cast[UcRegWriteFn](symAddr(ucLib, "uc_reg_write"))
  ucRegReadPtr  = cast[UcRegReadFn](symAddr(ucLib, "uc_reg_read"))
  ucEmuStartPtr = cast[UcEmuStartFn](symAddr(ucLib, "uc_emu_start"))
  ucEmuStopPtr  = cast[UcEmuStopFn](symAddr(ucLib, "uc_emu_stop"))
  ucHookAddPtr  = cast[UcHookAddFn](symAddr(ucLib, "uc_hook_add"))
  ucHookDelPtr  = cast[UcHookDelFn](symAddr(ucLib, "uc_hook_del"))
  result = ucOpenPtr != nil

# ---------------------------------------------------------------------------
# Public API (mirrors the original {.dynlib.} declarations).
# ---------------------------------------------------------------------------

proc uc_open*(arch: cint, mode: cint, uc: ptr ptr UcEngine): cint =
  if not ucLoad() or ucOpenPtr == nil: return UC_ERR_ARCH
  ucOpenPtr(arch, mode, uc)

proc uc_close*(uc: ptr UcEngine): cint =
  if not ucLoad() or ucClosePtr == nil: return UC_ERR_ARCH
  ucClosePtr(uc)

proc uc_mem_map*(uc: ptr UcEngine, address: uint64,
                 size: csize_t, perms: cuint): cint =
  if not ucLoad() or ucMemMapPtr == nil: return UC_ERR_ARCH
  ucMemMapPtr(uc, address, size, perms)

proc uc_mem_write*(uc: ptr UcEngine, address: uint64,
                   bytes: pointer, size: csize_t): cint =
  if not ucLoad() or ucMemWritePtr == nil: return UC_ERR_ARCH
  ucMemWritePtr(uc, address, bytes, size)

proc uc_mem_read*(uc: ptr UcEngine, address: uint64,
                  bytes: pointer, size: csize_t): cint =
  if not ucLoad() or ucMemReadPtr == nil: return UC_ERR_ARCH
  ucMemReadPtr(uc, address, bytes, size)

proc uc_reg_write*(uc: ptr UcEngine, regid: cint, value: pointer): cint =
  if not ucLoad() or ucRegWritePtr == nil: return UC_ERR_ARCH
  ucRegWritePtr(uc, regid, value)

proc uc_reg_read*(uc: ptr UcEngine, regid: cint, value: pointer): cint =
  if not ucLoad() or ucRegReadPtr == nil: return UC_ERR_ARCH
  ucRegReadPtr(uc, regid, value)

proc uc_emu_start*(uc: ptr UcEngine, begin: uint64, until: uint64,
                   timeout: uint64, count: csize_t): cint =
  if not ucLoad() or ucEmuStartPtr == nil: return UC_ERR_ARCH
  ucEmuStartPtr(uc, begin, until, timeout, count)

proc uc_emu_stop*(uc: ptr UcEngine): cint =
  if not ucLoad() or ucEmuStopPtr == nil: return UC_ERR_ARCH
  ucEmuStopPtr(uc)

proc uc_hook_add*(uc: ptr UcEngine, hh: ptr UcHook, hookType: cint,
                  callback: pointer, userData: pointer,
                  begin: uint64, `end`: uint64): cint =
  if not ucLoad() or ucHookAddPtr == nil: return UC_ERR_ARCH
  ucHookAddPtr(uc, hh, hookType, callback, userData, begin, `end`)

proc uc_hook_del*(uc: ptr UcEngine, hh: UcHook): cint =
  if not ucLoad() or ucHookDelPtr == nil: return UC_ERR_ARCH
  ucHookDelPtr(uc, hh)
