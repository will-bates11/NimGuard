# NimGuard - Cross-platform runtime instrumentation dispatcher.
# On Linux, delegates to the ptrace-based implementation in process.nim.
# On Windows, delegates to the Win32-based implementation in winprocess.nim.
# On other platforms, all procedures return a platform-not-supported error.
import disassembler, binary
when defined(linux):
  import times

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
# Breakpoint management.
# ---------------------------------------------------------------------------

proc injectBreakpoint*(pid: int,
                       address: uint64): (Breakpoint, RuntimeResult) =
  when defined(linux):
    let (bp, pr) = process.setBreakpoint(pid, address)
    if not pr.success:
      return (Breakpoint(), rtErr("injectBreakpoint: " & pr.msg))
    return (bp, rtOk())
  elif defined(windows):
    let (bp, pr) = winprocess.setBreakpoint(pid, address)
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
# Memory patching.
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
  # hookFunction only supports x86 and x86-64 JMP encodings.
  # On ARM or AArch64 targets the caller must not use this procedure;
  # writing x86 JMP bytes into an ARM binary will corrupt it.
  let targetArch = detectProcessArch(pid)
  if targetArch notin [archX86, archX64]:
    return (@[], rtErr("hookFunction: JMP hook encoding is x86/x64 only; " &
                       "target architecture is " & $targetArch))

  # Build a JMP sequence. Try rel32 (5 bytes) first; fall back to
  # absolute indirect JMP (14 bytes: FF 25 00 00 00 00 + 8-byte addr)
  # when the displacement overflows a signed 32-bit value.
  let rel32 = int64(hookAddress) - int64(address) - 5
  let useAbs = rel32 > int64(high(int32)) or rel32 < int64(low(int32))
  let patchSize = if useAbs: 14 else: 5
  when defined(linux):
    let (original, rr) = process.readProcessMemory(pid, address, patchSize)
    if not rr.success:
      return (@[], rtErr("hookFunction read: " & rr.msg))
    if original.len < patchSize:
      return (@[], rtErr("hookFunction: not enough bytes at target"))
    var jmpBytes: seq[byte]
    if useAbs:
      # FF 25 00 00 00 00 = JMP [RIP+0]; followed by 8-byte absolute target
      jmpBytes = @[0xFF'u8, 0x25'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8]
      for i in 0 ..< 8:
        jmpBytes.add(byte((hookAddress shr (i * 8)) and 0xFF))
    else:
      jmpBytes = @[0xE9'u8]
      jmpBytes.add(byte(rel32 and 0xFF))
      jmpBytes.add(byte((rel32 shr 8) and 0xFF))
      jmpBytes.add(byte((rel32 shr 16) and 0xFF))
      jmpBytes.add(byte((rel32 shr 24) and 0xFF))
    let wr = process.writeProcessMemory(pid, address, jmpBytes)
    if not wr.success:
      return (@[], rtErr("hookFunction write: " & wr.msg))
    return (original, rtOk())
  elif defined(windows):
    let (original, rr) = winprocess.readProcessMemory(pid, address, patchSize)
    if not rr.success:
      return (@[], rtErr("hookFunction read: " & rr.msg))
    if original.len < patchSize:
      return (@[], rtErr("hookFunction: not enough bytes at target"))
    var jmpBytes: seq[byte]
    if useAbs:
      jmpBytes = @[0xFF'u8, 0x25'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8]
      for i in 0 ..< 8:
        jmpBytes.add(byte((hookAddress shr (i * 8)) and 0xFF))
    else:
      jmpBytes = @[0xE9'u8]
      jmpBytes.add(byte(rel32 and 0xFF))
      jmpBytes.add(byte((rel32 shr 8) and 0xFF))
      jmpBytes.add(byte((rel32 shr 16) and 0xFF))
      jmpBytes.add(byte((rel32 shr 24) and 0xFF))
    let wr = winprocess.writeProcessMemory(pid, address, jmpBytes)
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
      # Block until the process stops at the next syscall boundary.
      # Using a blocking waitpid avoids the busy-poll sleep loop.
      let wr = process.waitForSignal(pid)
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
