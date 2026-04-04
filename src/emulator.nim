# NimGuard - CPU emulation module backed by Unicorn.
# Provides higher-level types and procedures over the raw FFI bindings.
import binary
import bindings/unicorn

type
  EmulatorContext* = object
    engine*:   ptr UcEngine
    arch*:     Architecture
    hooks*:    seq[UcHook]

  EmulationResult* = object
    success*:    bool
    errorMsg*:   string
    instrCount*: int

# Map NimGuard Architecture to Unicorn arch/mode constants.
proc archToUnicorn(arch: Architecture): (cint, cint) =
  case arch
  of archX86:   (UC_ARCH_X86, UC_MODE_32)
  of archX64:   (UC_ARCH_X86, UC_MODE_64)
  of archARM:   (UC_ARCH_ARM, UC_MODE_ARM)
  of archARM64: (UC_ARCH_ARM64, UC_MODE_LITTLE_ENDIAN)
  else:         (UC_ARCH_X86, UC_MODE_64)

# Check whether the Unicorn shared library is available at runtime.
# Returns false if the library cannot be loaded or initialised.
proc isUnicornAvailable*(): bool =
  var uc: ptr UcEngine = nil
  try:
    let err = uc_open(UC_ARCH_X86, UC_MODE_64, addr uc)
    if err == UC_ERR_OK:
      discard uc_close(uc)
      return true
    return false
  except:
    return false

# Create an emulator context for the given architecture.
# Returns a context with engine == nil if Unicorn is not available or
# if initialisation fails.
proc createEmulator*(arch: Architecture): EmulatorContext =
  result.arch   = arch
  result.engine = nil
  var uc: ptr UcEngine = nil
  let (ucArch, ucMode) = archToUnicorn(arch)
  try:
    let err = uc_open(ucArch, ucMode, addr uc)
    if err == UC_ERR_OK:
      result.engine = uc
  except:
    discard

# Close an emulator context and release all resources.
# Safe to call on a context whose engine is nil.
proc closeEmulator*(ctx: var EmulatorContext) =
  if ctx.engine != nil:
    for h in ctx.hooks:
      discard uc_hook_del(ctx.engine, h)
    ctx.hooks = @[]
    discard uc_close(ctx.engine)
    ctx.engine = nil

# Map a memory region into the emulated address space and write data into it.
# address must be 4 KB aligned. The region size is rounded up to the next
# 4 KB boundary automatically. Returns true on success.
proc loadMemory*(ctx: var EmulatorContext, address: uint64,
                 data: seq[byte], perms: cuint = UC_PROT_ALL): bool =
  if ctx.engine == nil or data.len == 0:
    return false

  # Round up to 4 KB page boundary.
  const pageSize = 0x1000
  let alignedSize = ((data.len + pageSize - 1) div pageSize) * pageSize

  let mapErr = uc_mem_map(ctx.engine, address, csize_t(alignedSize), perms)
  if mapErr != UC_ERR_OK:
    return false

  let writeErr = uc_mem_write(ctx.engine, address,
                              unsafeAddr data[0], csize_t(data.len))
  writeErr == UC_ERR_OK

# Load a named section from a parsed binary into emulated memory at the
# section's virtual address. Returns true if the section was found and
# loaded successfully.
proc loadBinary*(ctx: var EmulatorContext, info: BinaryInfo,
                 sectionName: string = ".text"): bool =
  if ctx.engine == nil:
    return false
  for s in info.sections:
    if s.name == sectionName:
      let off  = int(s.fileOffset)
      let size = int(s.size)
      if off < 0 or size <= 0 or off + size > info.rawBytes.len:
        return false
      let slice = info.rawBytes[off ..< off + size]
      return ctx.loadMemory(s.virtualAddress, slice, UC_PROT_ALL)
  return false

# Read a 64-bit register value. Returns 0 if the engine is nil or the read
# fails (e.g. regid is invalid for the current architecture).
proc readRegister*(ctx: EmulatorContext, regId: cint): uint64 =
  if ctx.engine == nil:
    return 0
  var value: uint64 = 0
  let err = uc_reg_read(ctx.engine, regId, addr value)
  if err == UC_ERR_OK: value else: 0

# Write a 64-bit value into a CPU register. Returns true on success.
proc writeRegister*(ctx: var EmulatorContext, regId: cint,
                    value: uint64): bool =
  if ctx.engine == nil:
    return false
  var v = value
  uc_reg_write(ctx.engine, regId, addr v) == UC_ERR_OK

# Emulate instructions from startAddr up to (not including) endAddr.
# maxInstructions limits the total instruction count; 0 means no limit.
# Returns an EmulationResult describing success or the error code.
proc emulateRange*(ctx: var EmulatorContext, startAddr: uint64,
                   endAddr: uint64,
                   maxInstructions: int = 0): EmulationResult =
  if ctx.engine == nil:
    return EmulationResult(success: false,
                           errorMsg: "Unicorn not available",
                           instrCount: 0)
  let err = uc_emu_start(ctx.engine, startAddr, endAddr,
                         0, csize_t(maxInstructions))
  if err == UC_ERR_OK:
    EmulationResult(success: true, errorMsg: "", instrCount: maxInstructions)
  else:
    EmulationResult(success: false,
                    errorMsg: "uc_emu_start error code: " & $int(err),
                    instrCount: 0)

# Install a code hook that fires on every instruction in the range
# [begin, endAddr]. Pass begin=1, endAddr=0 to cover all addresses (Unicorn
# interprets this as the full address space).
# callback must match the UcCodeHookCb signature. Returns true on success.
proc addCodeHook*(ctx: var EmulatorContext, callback: UcCodeHookCb,
                  userData: pointer = nil,
                  begin: uint64 = 1, endAddr: uint64 = 0): bool =
  if ctx.engine == nil:
    return false
  var hh: UcHook = 0
  let err = uc_hook_add(ctx.engine, addr hh, UC_HOOK_CODE,
                        cast[pointer](callback), userData, begin, endAddr)
  if err == UC_ERR_OK:
    ctx.hooks.add(hh)
    return true
  return false

# Install a memory-event hook for the given hookType (e.g. UC_HOOK_MEM_READ
# or UC_HOOK_MEM_WRITE) over [begin, endAddr].
# callback is passed as a raw pointer; the caller is responsible for using
# the correct C signature for the chosen hook type. Returns true on success.
proc addMemoryHook*(ctx: var EmulatorContext, hookType: cint,
                    callback: pointer, userData: pointer = nil,
                    begin: uint64 = 1, endAddr: uint64 = 0): bool =
  if ctx.engine == nil:
    return false
  var hh: UcHook = 0
  let err = uc_hook_add(ctx.engine, addr hh, hookType,
                        callback, userData, begin, endAddr)
  if err == UC_ERR_OK:
    ctx.hooks.add(hh)
    return true
  return false
