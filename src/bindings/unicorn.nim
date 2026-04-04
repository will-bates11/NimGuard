# NimGuard - Thin FFI wrapper for the Unicorn CPU emulator library.
# Exposes the subset of the Unicorn C API needed for NimGuard:
#   uc_open, uc_close, uc_mem_map, uc_mem_write, uc_mem_read,
#   uc_reg_write, uc_reg_read, uc_emu_start, uc_emu_stop,
#   uc_hook_add, uc_hook_del.
# Architecture/mode constants, register IDs, memory permissions, hook types.
#
# System dependency: libunicorn must be installed at the OS level.
#   Linux:   sudo apt-get install libunicorn-dev
#   macOS:   brew install unicorn
#   Windows: download unicorn.dll from https://www.unicorn-engine.org/

when defined(windows):
  const unicornDynlib* = "unicorn.dll"
elif defined(macosx):
  const unicornDynlib* = "libunicorn.dylib"
else:
  const unicornDynlib* = "libunicorn.so"

# Architecture constants (uc_arch enum values from unicorn.h).
const
  UC_ARCH_ARM*   = 1.cint   # ARM (including Thumb)
  UC_ARCH_ARM64* = 2.cint   # AArch64
  UC_ARCH_X86*   = 4.cint   # x86 and x86-64

# Mode constants (uc_mode enum bit flags from unicorn.h).
const
  UC_MODE_LITTLE_ENDIAN* = 0.cint         # little-endian (default)
  UC_MODE_ARM*           = 0.cint         # 32-bit ARM
  UC_MODE_THUMB*         = (1 shl 4).cint # ARM Thumb mode
  UC_MODE_16*            = (1 shl 1).cint # x86 16-bit
  UC_MODE_32*            = (1 shl 2).cint # x86 32-bit
  UC_MODE_64*            = (1 shl 3).cint # x86 64-bit

# Error codes (uc_err enum values from unicorn.h).
const
  UC_ERR_OK* = 0.cint  # No error

# Memory permission flags (from unicorn.h).
const
  UC_PROT_NONE*  = 0.cuint  # no permissions
  UC_PROT_READ*  = 1.cuint  # read permission
  UC_PROT_WRITE* = 2.cuint  # write permission
  UC_PROT_EXEC*  = 4.cuint  # execute permission
  UC_PROT_ALL*   = 7.cuint  # read + write + execute

# Hook type flags (uc_hook_type enum from unicorn.h).
const
  UC_HOOK_INTR*               = (1 shl 0).cint  # interrupt/exception event
  UC_HOOK_CODE*               = (1 shl 2).cint  # instruction executed
  UC_HOOK_BLOCK*              = (1 shl 3).cint  # basic block entered
  UC_HOOK_MEM_READ_UNMAPPED*  = (1 shl 4).cint  # read from unmapped memory
  UC_HOOK_MEM_WRITE_UNMAPPED* = (1 shl 5).cint  # write to unmapped memory
  UC_HOOK_MEM_READ*           = (1 shl 10).cint # memory read
  UC_HOOK_MEM_WRITE*          = (1 shl 11).cint # memory write

# x86 register IDs (uc_x86_reg enum from unicorn/x86.h).
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

# Opaque engine type. Unicorn uses uc_engine* as the working handle.
# Declared as an incomplete object so Nim never attempts to copy it.
type UcEngine* = object

# Hook handle type (uc_hook is size_t in C).
type UcHook* = csize_t

# Callback proc type for UC_HOOK_CODE hooks (fires on every instruction).
# Matches the C signature:
#   void cb(uc_engine *uc, uint64_t address, uint32_t size, void *user_data)
type UcCodeHookCb* = proc(uc: ptr UcEngine, address: uint64, size: uint32,
                          userData: pointer) {.cdecl.}

# uc_open: initialise a Unicorn engine handle for the given arch and mode.
# Writes the new handle into *uc. Returns UC_ERR_OK on success.
proc uc_open*(arch: cint, mode: cint, uc: ptr ptr UcEngine): cint
  {.importc: "uc_open", dynlib: unicornDynlib.}

# uc_close: destroy a Unicorn engine handle and release all resources.
proc uc_close*(uc: ptr UcEngine): cint
  {.importc: "uc_close", dynlib: unicornDynlib.}

# uc_mem_map: map a memory region into the emulated address space.
# address must be 4 KB aligned. size must be a multiple of 4 KB.
proc uc_mem_map*(uc: ptr UcEngine, address: uint64,
                 size: csize_t, perms: cuint): cint
  {.importc: "uc_mem_map", dynlib: unicornDynlib.}

# uc_mem_write: copy bytes into the emulated memory region at address.
proc uc_mem_write*(uc: ptr UcEngine, address: uint64,
                   bytes: pointer, size: csize_t): cint
  {.importc: "uc_mem_write", dynlib: unicornDynlib.}

# uc_mem_read: copy bytes out of the emulated memory region at address.
proc uc_mem_read*(uc: ptr UcEngine, address: uint64,
                  bytes: pointer, size: csize_t): cint
  {.importc: "uc_mem_read", dynlib: unicornDynlib.}

# uc_reg_write: write a value into a CPU register.
# value must point to a variable sized to match the register (e.g. uint64).
proc uc_reg_write*(uc: ptr UcEngine, regid: cint, value: pointer): cint
  {.importc: "uc_reg_write", dynlib: unicornDynlib.}

# uc_reg_read: read the current value of a CPU register.
# value must point to a variable sized to match the register (e.g. uint64).
proc uc_reg_read*(uc: ptr UcEngine, regid: cint, value: pointer): cint
  {.importc: "uc_reg_read", dynlib: unicornDynlib.}

# uc_emu_start: begin emulation from begin up to (not including) until.
# timeout is in microseconds (0 = no timeout).
# count is the maximum number of instructions to execute (0 = no limit).
proc uc_emu_start*(uc: ptr UcEngine, begin: uint64, until: uint64,
                   timeout: uint64, count: csize_t): cint
  {.importc: "uc_emu_start", dynlib: unicornDynlib.}

# uc_emu_stop: request that a running emulation stop at the next safe point.
proc uc_emu_stop*(uc: ptr UcEngine): cint
  {.importc: "uc_emu_stop", dynlib: unicornDynlib.}

# uc_hook_add: register a callback over the address range [begin, end].
# hookType is one of the UC_HOOK_* constants.
# callback and userData are raw pointers; cast the callback proc as needed.
# For UC_HOOK_CODE, callback must match UcCodeHookCb.
proc uc_hook_add*(uc: ptr UcEngine, hh: ptr UcHook, hookType: cint,
                  callback: pointer, userData: pointer,
                  begin: uint64, `end`: uint64): cint
  {.importc: "uc_hook_add", dynlib: unicornDynlib.}

# uc_hook_del: remove a previously registered hook.
proc uc_hook_del*(uc: ptr UcEngine, hh: UcHook): cint
  {.importc: "uc_hook_del", dynlib: unicornDynlib.}
