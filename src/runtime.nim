# NimGuard - Cross-platform runtime instrumentation dispatcher.
# On Linux, delegates to the ptrace-based implementation in process.nim.
# On Windows, delegates to the Win32-based implementation in winprocess.nim.
# On other platforms, all procedures return a platform-not-supported error.
import disassembler, binary
when defined(linux):
  import times, os

when defined(linux):
  import process

elif defined(windows):
  import winprocess

type
  SyscallEvent* = object
    pid*:       int
    syscallNr*: int
    args*:      array[6, uint64]

  RuntimeResult* = object
    success*: bool
    msg*:     string

# Unified Breakpoint type: matches the platform's native breakpoint record.
when defined(linux):
  type Breakpoint* = process.Breakpoint
elif defined(windows):
  type Breakpoint* = winprocess.WinBreakpoint
else:
  type Breakpoint* = object
    address*:      uint64
    originalByte*: byte
    active*:       bool

# ---------------------------------------------------------------------------
# Internal helpers.
# ---------------------------------------------------------------------------

proc rtOk(): RuntimeResult =
  RuntimeResult(success: true, msg: "")

proc rtErr(m: string): RuntimeResult =
  RuntimeResult(success: false, msg: m)

when defined(linux):
  proc fromProcess(pr: ProcessResult): RuntimeResult =
    if pr.success: rtOk() else: rtErr(pr.msg)

elif defined(windows):
  proc fromProcess(pr: WinProcessResult): RuntimeResult =
    if pr.success: rtOk() else: rtErr(pr.msg)

# ---------------------------------------------------------------------------
# Availability.
# ---------------------------------------------------------------------------

# Returns true when live process instrumentation is available on this platform.
proc isRuntimeAvailable*(): bool =
  when defined(linux) or defined(windows):
    true
  else:
    false

# ---------------------------------------------------------------------------
# Process attachment.
# ---------------------------------------------------------------------------

proc attachProcess*(pid: int): RuntimeResult =
  when defined(linux):
    fromProcess(process.attachProcess(pid))
  elif defined(windows):
    fromProcess(winprocess.attachProcess(pid))
  else:
    rtErr("platform not supported")

proc detachProcess*(pid: int): RuntimeResult =
  when defined(linux):
    fromProcess(process.detachProcess(pid))
  elif defined(windows):
    fromProcess(winprocess.detachProcess(pid))
  else:
    rtErr("platform not supported")

# ---------------------------------------------------------------------------
# Architecture detection.
# ---------------------------------------------------------------------------

# Detect architecture of a running process from its executable on disk.
# Falls back to archX64 when the path cannot be read or parsed.
proc detectProcessArch*(pid: int): Architecture =
  when defined(linux):
    let exePath = "/proc/" & $pid & "/exe"
    let info = parseBinary(exePath)
    if info.format != bfUnknown:
      return info.architecture
    return archX64
  elif defined(windows):
    # IsWow64Process tells us if a 32-bit process is running on 64-bit Windows.
    # For simplicity, default to x64 on Windows targets.
    return archX64
  else:
    return archX64

# ---------------------------------------------------------------------------
# Breakpoint management.
# ---------------------------------------------------------------------------

proc injectBreakpoint*(pid: int,
                       address: uint64): (Breakpoint, RuntimeResult) =
  let arch = detectProcessArch(pid)
  when defined(linux):
    let (bp, pr) = process.setBreakpoint(pid, address, arch)
    if not pr.success:
      return (Breakpoint(), rtErr("injectBreakpoint: " & pr.msg))
    return (bp, rtOk())
  elif defined(windows):
    let (bp, pr) = winprocess.setBreakpoint(pid, address, arch)
    if not pr.success:
      return (Breakpoint(), rtErr("injectBreakpoint: " & pr.msg))
    return (bp, rtOk())
  else:
    return (Breakpoint(), rtErr("platform not supported"))

proc removeBreakpoint*(pid: int, bp: Breakpoint): RuntimeResult =
  when defined(linux):
    fromProcess(process.removeBreakpoint(pid, bp))
  elif defined(windows):
    fromProcess(winprocess.removeBreakpoint(pid, bp))
  else:
    rtErr("platform not supported")

# ---------------------------------------------------------------------------
# Architecture-specific trampoline and breakpoint instruction builders.
# These are pure byte-sequence constructors with no platform dependency,
# exposed for testing and internal use.
# ---------------------------------------------------------------------------

# Build an ARM32 absolute-jump trampoline (8 bytes):
#   LDR PC, [PC, #-4]   ; E51FF004 -> stored as 04 F0 1F E5 (little-endian)
#   <4-byte hookAddress in little-endian>
proc buildArm32Trampoline*(hookAddress: uint64): seq[byte] =
  result = @[0x04'u8, 0xF0'u8, 0x1F'u8, 0xE5'u8]
  for i in 0 ..< 4:
    result.add(byte((hookAddress shr (i * 8)) and 0xFF))

# Build an AArch64 absolute-jump trampoline (16 bytes):
#   LDR X16, #8   ; 58000050 -> stored as 50 00 00 58 (little-endian)
#   BR  X16       ; D61F0200 -> stored as 00 02 1F D6 (little-endian)
#   <8-byte hookAddress in little-endian>
proc buildAarch64Trampoline*(hookAddress: uint64): seq[byte] =
  result = @[0x50'u8, 0x00'u8, 0x00'u8, 0x58'u8,
             0x00'u8, 0x02'u8, 0x1F'u8, 0xD6'u8]
  for i in 0 ..< 8:
    result.add(byte((hookAddress shr (i * 8)) and 0xFF))

# Returns the breakpoint instruction bytes for the given architecture.
# ARM32 uses ARM mode (BKPT #0, 4 bytes). x86/x64 use INT3 (1 byte).
proc breakpointInstructionBytes*(arch: Architecture): seq[byte] =
  case arch
  of archARM64:
    # BRK #0 = D4200000 (big-endian), stored as 00 00 20 D4 (little-endian)
    @[0x00'u8, 0x00'u8, 0x20'u8, 0xD4'u8]
  of archARM:
    # BKPT #0 ARM mode = E1200070 (big-endian), stored as 70 00 20 E1 (little-endian)
    @[0x70'u8, 0x00'u8, 0x20'u8, 0xE1'u8]
  else:
    # x86/x64 INT3
    @[0xCC'u8]

# ---------------------------------------------------------------------------
# Memory patching.
# ---------------------------------------------------------------------------

proc patchProcessMemory*(pid: int, address: uint64,
                         bytes: seq[byte]): RuntimeResult =
  if bytes.len == 0:
    return rtErr("patchProcessMemory: empty patch bytes")
  when defined(linux):
    fromProcess(process.writeProcessMemory(pid, address, bytes))
  elif defined(windows):
    fromProcess(winprocess.writeProcessMemory(pid, address, bytes))
  else:
    rtErr("platform not supported")

proc hookFunction*(pid: int, address: uint64,
                   hookAddress: uint64): (seq[byte], RuntimeResult) =
  let targetArch = detectProcessArch(pid)

  # Determine patch size and trampoline bytes from the target architecture.
  var patchSize: int
  var trampBytes: seq[byte]

  case targetArch
  of archARM:
    # ARM32: LDR PC, [PC, #-4] + 4-byte absolute target (8 bytes total)
    patchSize = 8
    trampBytes = buildArm32Trampoline(hookAddress)
  of archARM64:
    # AArch64: LDR X16, #8; BR X16 + 8-byte absolute target (16 bytes total)
    patchSize = 16
    trampBytes = buildAarch64Trampoline(hookAddress)
  of archX86, archX64:
    # x86/x64: try rel32 JMP (5 bytes); fall back to absolute indirect (14 bytes)
    # when the displacement overflows a signed 32-bit value.
    let rel32 = int64(hookAddress) - int64(address) - 5
    let useAbs = rel32 > int64(high(int32)) or rel32 < int64(low(int32))
    patchSize = if useAbs: 14 else: 5
    if useAbs:
      # FF 25 00 00 00 00 = JMP [RIP+0]; followed by 8-byte absolute target
      trampBytes = @[0xFF'u8, 0x25'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8]
      for i in 0 ..< 8:
        trampBytes.add(byte((hookAddress shr (i * 8)) and 0xFF))
    else:
      trampBytes = @[0xE9'u8]
      trampBytes.add(byte(rel32 and 0xFF))
      trampBytes.add(byte((rel32 shr 8) and 0xFF))
      trampBytes.add(byte((rel32 shr 16) and 0xFF))
      trampBytes.add(byte((rel32 shr 24) and 0xFF))
  else:
    return (@[], rtErr("hookFunction: unsupported target architecture " &
                       $targetArch))

  when defined(linux):
    let (original, rr) = process.readProcessMemory(pid, address, patchSize)
    if not rr.success:
      return (@[], rtErr("hookFunction read: " & rr.msg))
    if original.len < patchSize:
      return (@[], rtErr("hookFunction: not enough bytes at target"))
    let wr = process.writeProcessMemory(pid, address, trampBytes)
    if not wr.success:
      return (@[], rtErr("hookFunction write: " & wr.msg))
    return (original, rtOk())
  elif defined(windows):
    let (original, rr) = winprocess.readProcessMemory(pid, address, patchSize)
    if not rr.success:
      return (@[], rtErr("hookFunction read: " & rr.msg))
    if original.len < patchSize:
      return (@[], rtErr("hookFunction: not enough bytes at target"))
    let wr = winprocess.writeProcessMemory(pid, address, trampBytes)
    if not wr.success:
      return (@[], rtErr("hookFunction write: " & wr.msg))
    return (original, rtOk())
  else:
    return (@[], rtErr("platform not supported"))

# ---------------------------------------------------------------------------
# Disassembly at a live process address.
# ---------------------------------------------------------------------------

proc disassembleAtAddress*(pid: int, address: uint64,
                           count: int,
                           arch: Architecture = archX64): seq[Instruction] =
  if count <= 0:
    return @[]
  let readSize = count * 15
  when defined(linux):
    let (bytes, rr) = process.readProcessMemory(pid, address, readSize)
    if not rr.success or bytes.len == 0:
      return @[]
    let instrs = disassembleBytes(bytes, address, arch)
    if instrs.len == 0:
      return @[]
    if instrs.len <= count:
      return instrs
    return instrs[0 ..< count]
  elif defined(windows):
    let (bytes, rr) = winprocess.readProcessMemory(pid, address, readSize)
    if not rr.success or bytes.len == 0:
      return @[]
    let instrs = disassembleBytes(bytes, address, arch)
    if instrs.len == 0:
      return @[]
    if instrs.len <= count:
      return instrs
    return instrs[0 ..< count]
  else:
    return @[]

# ---------------------------------------------------------------------------
# Syscall monitoring (Linux only; empty on other platforms).
# ---------------------------------------------------------------------------

proc monitorSyscalls*(pid: int, maxSyscalls: int = 1000,
                      timeoutMs: int = 0): seq[SyscallEvent] =
  when defined(linux):
    var events: seq[SyscallEvent]
    var i = 0
    let startMs = if timeoutMs > 0: int64(epochTime() * 1000.0) else: 0i64
    while i < maxSyscalls:
      # Wall-clock timeout check (WNOHANG-style: checked before blocking).
      if timeoutMs > 0 and
         int64(epochTime() * 1000.0) - startMs >= int64(timeoutMs):
        break
      let sr = process.stepToSyscall(pid)
      if not sr.success:
        break
      # Poll with WNOHANG so the wall-clock timeout fires even when the
      # target is blocked inside a long-running syscall (e.g. sleep).
      var wr: WaitResult
      var waitDone = false
      while not waitDone:
        if timeoutMs > 0 and
           int64(epochTime() * 1000.0) - startMs >= int64(timeoutMs):
          break
        let nwr = process.waitForSignalNonBlock(pid)
        case nwr.status
        of wsRunning:
          os.sleep(10)  # 10 ms poll interval
        else:
          wr = nwr
          waitDone = true
      if not waitDone:
        break  # timeout hit
      if wr.status != wsStopped:
        break
      let (regs, gr) = process.getRegisters(pid)
      if not gr.success:
        break
      events.add(SyscallEvent(
        pid:       pid,
        syscallNr: int(regs.origRax),
        args:      [regs.rdi, regs.rsi, regs.rdx, regs.r10, regs.r8, regs.r9]
      ))
      inc i
    return events
  else:
    return @[]

# ---------------------------------------------------------------------------
# Windows-only: remote memory allocation and thread suspension helpers.
# These were formerly in winruntime.nim; merged here under Windows guards.
# ---------------------------------------------------------------------------

proc allocateRemoteMemory*(pid: int, size: int): (uint64, RuntimeResult) =
  when defined(windows):
    let (remoteAddr, pr) = winprocess.allocateRemoteMemory(pid, size)
    if not pr.success:
      return (0'u64, rtErr("allocateRemoteMemory: " & pr.msg))
    return (remoteAddr, rtOk())
  else:
    return (0'u64, rtErr("platform not supported"))

# Suspend all threads of a process. Returns the count of threads suspended.
# Useful before writing to process memory to ensure consistency.
proc suspendAllThreads*(pid: int): (int, RuntimeResult) =
  when defined(windows):
    let (tids, er) = winprocess.enumerateThreads(pid)
    if not er.success:
      return (0, rtErr("suspendAllThreads: " & er.msg))
    var suspended = 0
    for tid in tids:
      let sr = winprocess.suspendThread(tid)
      if sr.success:
        inc suspended
    return (suspended, rtOk())
  else:
    return (0, rtErr("platform not supported"))

# Resume all threads of a process.
proc resumeAllThreads*(pid: int): (int, RuntimeResult) =
  when defined(windows):
    let (tids, er) = winprocess.enumerateThreads(pid)
    if not er.success:
      return (0, rtErr("resumeAllThreads: " & er.msg))
    var resumed = 0
    for tid in tids:
      let rr = winprocess.resumeThread(tid)
      if rr.success:
        inc resumed
    return (resumed, rtOk())
  else:
    return (0, rtErr("platform not supported"))
