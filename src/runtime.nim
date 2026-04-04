# NimGuard - Runtime instrumentation built on the process control module.
# Provides higher-level operations for live process analysis and patching.
# Depends on process.nim for ptrace primitives. On non-Linux platforms all
# procedures return a platform-not-supported error.
import process, disassembler, binary

type
  SyscallEvent* = object
    pid*:       int
    syscallNr*: int
    args*:      array[6, uint64]  # rdi, rsi, rdx, r10, r8, r9

  RuntimeResult* = object
    success*: bool
    msg*:     string

# ---------------------------------------------------------------------------
# Internal helpers.
# ---------------------------------------------------------------------------

proc rtOk(): RuntimeResult =
  RuntimeResult(success: true, msg: "")

proc rtErr(m: string): RuntimeResult =
  RuntimeResult(success: false, msg: m)

proc fromProcess(pr: ProcessResult): RuntimeResult =
  if pr.success: rtOk() else: rtErr(pr.msg)

# ---------------------------------------------------------------------------
# Process attachment.
# ---------------------------------------------------------------------------

proc attachProcess*(pid: int): RuntimeResult =
  fromProcess(process.attachProcess(pid))

proc detachProcess*(pid: int): RuntimeResult =
  fromProcess(process.detachProcess(pid))

# ---------------------------------------------------------------------------
# Breakpoint management.
# ---------------------------------------------------------------------------

# Inject a software breakpoint (INT3) at address in the target process.
# Returns the Breakpoint record needed to remove it later.
proc injectBreakpoint*(pid: int,
                       address: uint64): (Breakpoint, RuntimeResult) =
  let (bp, pr) = process.setBreakpoint(pid, address)
  if not pr.success:
    return (Breakpoint(), rtErr("injectBreakpoint: " & pr.msg))
  return (bp, rtOk())

# Restore the original byte at the breakpoint address and deactivate it.
proc removeBreakpoint*(pid: int, bp: Breakpoint): RuntimeResult =
  fromProcess(process.removeBreakpoint(pid, bp))

# ---------------------------------------------------------------------------
# Memory patching.
# ---------------------------------------------------------------------------

# Write bytes directly into the target process at address.
proc patchProcessMemory*(pid: int, address: uint64,
                         bytes: seq[byte]): RuntimeResult =
  if bytes.len == 0:
    return rtErr("patchProcessMemory: empty patch bytes")
  fromProcess(process.writeProcessMemory(pid, address, bytes))

# Overwrite the first 5 bytes at address with a relative JMP to hookAddress.
# Returns the original 5 bytes so the hook can be removed later.
# Only generates a rel32 JMP (0xE9 <rel32>), so hookAddress must be within
# +/-2 GiB of address.
proc hookFunction*(pid: int, address: uint64,
                   hookAddress: uint64): (seq[byte], RuntimeResult) =
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

# ---------------------------------------------------------------------------
# Disassembly at a live process address.
# ---------------------------------------------------------------------------

# Read count instructions from the target process starting at address.
# Uses Capstone for disassembly. Returns an empty sequence on any error.
proc disassembleAtAddress*(pid: int, address: uint64,
                           count: int): seq[Instruction] =
  if count <= 0:
    return @[]
  # Each x86 instruction is at most 15 bytes; read enough to decode count.
  let readSize = count * 15
  let (bytes, rr) = process.readProcessMemory(pid, address, readSize)
  if not rr.success or bytes.len == 0:
    return @[]
  let instrs = disassembleBytes(bytes, address, archX64)
  if instrs.len == 0:
    return @[]
  if instrs.len <= count:
    return instrs
  return instrs[0 ..< count]

# ---------------------------------------------------------------------------
# Syscall monitoring.
# ---------------------------------------------------------------------------

# Trace up to maxEvents syscall entries in an already-attached process.
# Uses PTRACE_SYSCALL to advance execution to each syscall boundary,
# reads registers at entry, and collects the syscall number and arguments.
# Returns the collected events. Stops early on process exit or error.
proc monitorSyscalls*(pid: int, maxEvents: int): seq[SyscallEvent] =
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
