# NimGuard - Thin FFI wrapper for the Capstone disassembly library.
# Exposes only the subset of the Capstone C API needed for NimGuard:
#   cs_open, cs_disasm, cs_free, cs_close, cs_insn struct,
#   architecture/mode constants.
#
# System dependency: libcapstone must be installed at the OS level.
#   Linux:   sudo apt-get install libcapstone-dev
#   macOS:   brew install capstone
#   Windows: download capstone.dll from https://www.capstone-engine.org/

when defined(windows):
  const capstoneDynlib* = "capstone.dll"
elif defined(macosx):
  const capstoneDynlib* = "libcapstone.dylib"
else:
  const capstoneDynlib* = "libcapstone.so"

# Architecture constants (cs_arch enum values from capstone.h).
const
  CS_ARCH_ARM*   = 0.cint   # ARM (including Thumb)
  CS_ARCH_ARM64* = 1.cint   # AArch64
  CS_ARCH_X86*   = 3.cint   # x86 and x86-64

# Mode constants (cs_mode enum bit flags from capstone.h).
const
  CS_MODE_ARM*   = 0.cint         # 32-bit ARM
  CS_MODE_THUMB* = (1 shl 4).cint # ARM Thumb
  CS_MODE_16*    = (1 shl 1).cint # x86 16-bit
  CS_MODE_32*    = (1 shl 2).cint # x86 32-bit
  CS_MODE_64*    = (1 shl 3).cint # x86 64-bit

# Error codes (cs_err enum values from capstone.h).
const
  CS_ERR_OK* = 0.cint  # No error

# Opaque handle type (csh in C, defined as size_t).
type CsHandle* = csize_t

# cs_insn: instruction information struct, matching the C layout exactly.
# C struct layout (GCC x86-64, no packing):
#   offset  0: id         (uint32)
#   offset  4: (4 bytes padding)
#   offset  8: address    (uint64)
#   offset 16: size       (uint16)
#   offset 18: bytes[16]  (uint8[16])
#   offset 34: mnemonic[32] (char[32])
#   offset 66: op_str[160]  (char[160])
#   offset 226: (6 bytes padding)
#   offset 232: detail    (pointer)
#   total: 240 bytes
type
  CsInsn* = object
    id*:       cuint
    address*:  uint64
    size*:     uint16
    bytes*:    array[16, byte]
    mnemonic*: array[32, char]
    opStr*:    array[160, char]
    detail*:   pointer

# cs_open: initialise a Capstone handle.
# Returns CS_ERR_OK on success.
proc cs_open*(arch: cint, mode: cint, handle: ptr CsHandle): cint
  {.importc: "cs_open", dynlib: capstoneDynlib.}

# cs_disasm: disassemble code. Returns the number of instructions decoded.
# Caller must free the returned array with cs_free.
proc cs_disasm*(handle: CsHandle, code: ptr byte, codeSize: csize_t,
                address: uint64, count: csize_t,
                insn: ptr ptr CsInsn): csize_t
  {.importc: "cs_disasm", dynlib: capstoneDynlib.}

# cs_free: release memory allocated by cs_disasm.
proc cs_free*(insn: ptr CsInsn, count: csize_t)
  {.importc: "cs_free", dynlib: capstoneDynlib.}

# cs_close: close a Capstone handle.
proc cs_close*(handle: ptr CsHandle): cint
  {.importc: "cs_close", dynlib: capstoneDynlib.}
