# NimGuard - Cross-platform runtime instrumentation dispatcher.
# On Linux, delegates to the ptrace-based implementation in process.nim.
# On Windows, delegates to the Win32-based implementation in winprocess.nim.
# On other platforms, all procedures return a platform-not-supported error.
import disassembler, binary

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
  when defined(linux):
    let (original, rr) = process.readProcessMemory(pid, address, 5)
    if not rr.success:
      return (@[], rtErr("hookFunction read: " & rr.msg))
    let rel32 = int64(hookAddress) - int64(address) - 5
    var jmpBytes: seq[byte] = @[0xE9'u8]
    jmpBytes.add(byte(rel32 and 0xFF))
    jmpBytes.add(byte((rel32 shr 8) and 0xFF))
    jmpBytes.add(byte((rel32 shr 16) and 0xFF))
    jmpBytes.add(byte((rel32 shr 24) and 0xFF))
    let wr = process.writeProcessMemory(pid, address, jmpBytes)
    if not wr.success:
      return (@[], rtErr("hookFunction write: " & wr.msg))
    return (original, rtOk())
  elif defined(windows):
    let (original, rr) = winprocess.readProcessMemory(pid, address, 5)
    if not rr.success:
      return (@[], rtErr("hookFunction read: " & rr.msg))
    let rel32 = int64(hookAddress) - int64(address) - 5
    var jmpBytes: seq[byte] = @[0xE9'u8]
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
                           count: int): seq[Instruction] =
  if count <= 0:
    return @[]
  let readSize = count * 15
  when defined(linux):
    let (bytes, rr) = process.readProcessMemory(pid, address, readSize)
    if not rr.success or bytes.len == 0:
      return @[]
    let instrs = disassembleBytes(bytes, address, archX64)
    if instrs.len == 0:
      return @[]
    if instrs.len <= count:
      return instrs
    return instrs[0 ..< count]
  elif defined(windows):
    let (bytes, rr) = winprocess.readProcessMemory(pid, address, readSize)
    if not rr.success or bytes.len == 0:
      return @[]
    let instrs = disassembleBytes(bytes, address, archX64)
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

proc monitorSyscalls*(pid: int, maxEvents: int): seq[SyscallEvent] =
  when defined(linux):
    var events: seq[SyscallEvent]
    var i = 0
    while i < maxEvents:
      let sr = process.stepToSyscall(pid)
      if not sr.success:
        break
      let wr = process.waitForSignal(pid)
      if wr.status == wsExited or wr.status == wsSignaled:
        break
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
