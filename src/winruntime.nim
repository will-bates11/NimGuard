# NimGuard - Runtime instrumentation built on the Windows process control module.
# Provides higher-level operations for live process analysis and patching on Windows.
# Depends on winprocess.nim for Win32 primitives. On non-Windows platforms all
# procedures return a platform-not-supported error.
import winprocess, disassembler

type
  WinRuntimeResult* = object
    success*: bool
    msg*:     string

# ---------------------------------------------------------------------------
# Internal helpers.
# ---------------------------------------------------------------------------

proc rtOk(): WinRuntimeResult =
  WinRuntimeResult(success: true, msg: "")

proc rtErr(m: string): WinRuntimeResult =
  WinRuntimeResult(success: false, msg: m)

proc fromWinProcess(pr: WinProcessResult): WinRuntimeResult =
  if pr.success: rtOk() else: rtErr(pr.msg)

# ---------------------------------------------------------------------------
# Process attachment.
# ---------------------------------------------------------------------------

proc attachProcess*(pid: int): WinRuntimeResult =
  fromWinProcess(winprocess.attachProcess(pid))

proc detachProcess*(pid: int): WinRuntimeResult =
  fromWinProcess(winprocess.detachProcess(pid))

# ---------------------------------------------------------------------------
# Breakpoint management.
# ---------------------------------------------------------------------------

# Inject a software breakpoint (INT3) at address in the target process.
# Returns the WinBreakpoint record needed to remove it later.
proc injectBreakpoint*(pid: int,
                       address: uint64): (WinBreakpoint, WinRuntimeResult) =
  let (bp, pr) = winprocess.setBreakpoint(pid, address)
  if not pr.success:
    return (WinBreakpoint(), rtErr("injectBreakpoint: " & pr.msg))
  return (bp, rtOk())

# Restore the original byte at the breakpoint address and deactivate it.
proc removeBreakpoint*(pid: int, bp: WinBreakpoint): WinRuntimeResult =
  fromWinProcess(winprocess.removeBreakpoint(pid, bp))

# ---------------------------------------------------------------------------
# Memory patching.
# ---------------------------------------------------------------------------

# Write bytes directly into the target process at address.
proc patchProcessMemory*(pid: int, address: uint64,
                         bytes: seq[byte]): WinRuntimeResult =
  if bytes.len == 0:
    return rtErr("patchProcessMemory: empty patch bytes")
  fromWinProcess(winprocess.writeProcessMemory(pid, address, bytes))

# Overwrite the first 5 bytes at address with a relative JMP to hookAddress.
# Returns the original 5 bytes so the hook can be removed later.
# Only generates a rel32 JMP (0xE9 <rel32>), so hookAddress must be within
# +/-2 GiB of address.
proc hookFunction*(pid: int, address: uint64,
                   hookAddress: uint64): (seq[byte], WinRuntimeResult) =
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

# ---------------------------------------------------------------------------
# Remote memory allocation (for code caves).
# ---------------------------------------------------------------------------

proc allocateRemoteMemory*(pid: int, size: int): (uint64, WinRuntimeResult) =
  let (addr_, pr) = winprocess.allocateRemoteMemory(pid, size)
  if not pr.success:
    return (0'u64, rtErr("allocateRemoteMemory: " & pr.msg))
  return (addr_, rtOk())

# ---------------------------------------------------------------------------
# Disassembly at a live process address.
# ---------------------------------------------------------------------------

# Read count instructions from the target process starting at address.
# Uses Capstone for disassembly. Returns an empty sequence on any error.
proc disassembleAtAddress*(pid: int, address: uint64,
                           count: int): seq[Instruction] =
  if count <= 0:
    return @[]
  let readSize = count * 15
  let (bytes, rr) = winprocess.readProcessMemory(pid, address, readSize)
  if not rr.success or bytes.len == 0:
    return @[]
  let instrs = disassembleBytes(bytes, address, archX64)
  if instrs.len == 0:
    return @[]
  if instrs.len <= count:
    return instrs
  return instrs[0 ..< count]

# ---------------------------------------------------------------------------
# Thread suspension helpers.
# ---------------------------------------------------------------------------

# Suspend all threads of a process. Returns the count of successfully
# suspended threads. Use before writing to process memory for consistency.
proc suspendAllThreads*(pid: int): (int, WinRuntimeResult) =
  let (tids, er) = winprocess.enumerateThreads(pid)
  if not er.success:
    return (0, rtErr("suspendAllThreads: " & er.msg))
  var suspended = 0
  for tid in tids:
    let sr = winprocess.suspendThread(tid)
    if sr.success:
      inc suspended
  return (suspended, rtOk())

# Resume all threads of a process.
proc resumeAllThreads*(pid: int): (int, WinRuntimeResult) =
  let (tids, er) = winprocess.enumerateThreads(pid)
  if not er.success:
    return (0, rtErr("resumeAllThreads: " & er.msg))
  var resumed = 0
  for tid in tids:
    let rr = winprocess.resumeThread(tid)
    if rr.success:
      inc resumed
  return (resumed, rtOk())
