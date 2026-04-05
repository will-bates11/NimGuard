# NimGuard - Process attachment and control via ptrace.
# Wraps Linux ptrace syscall for live process inspection and manipulation.
# Compiles on all platforms but only operates on Linux. On other platforms
# all procedures return a pePlatform error without performing any action.

type
  ProcessError* = enum
    peNone        = "none"
    pePlatform    = "platform not supported"
    peAttach      = "ptrace attach failed"
    peDetach      = "ptrace detach failed"
    pePeek        = "ptrace peek failed"
    pePoke        = "ptrace poke failed"
    peGetRegs     = "ptrace getregs failed"
    peSetRegs     = "ptrace setregs failed"
    peStep        = "ptrace singlestep failed"
    peContinue    = "ptrace continue failed"
    peWait        = "waitpid failed"
    peRange       = "invalid range or size"

  ProcessResult* = object
    success*: bool
    error*:   ProcessError
    msg*:     string

  # CPU register state. Fields reflect the x86-64 register file.
  # origRax holds the syscall number at syscall-entry stops.
  Registers* = object
    rip*, rsp*, rbp*:           uint64
    rax*, rbx*, rcx*, rdx*:     uint64
    rsi*, rdi*:                 uint64
    r8*, r9*, r10*, r11*:       uint64
    r12*, r13*, r14*, r15*:     uint64
    eflags*, cs*, ss*:          uint64
    origRax*:                   uint64

  Breakpoint* = object
    address*:      uint64
    originalByte*: byte
    active*:       bool

  WaitStatus* = enum
    wsRunning  = "running"
    wsStopped  = "stopped"
    wsExited   = "exited"
    wsSignaled = "signaled"
    wsUnknown  = "unknown"

  WaitResult* = object
    status*:   WaitStatus
    signal*:   int
    exitCode*: int

# ---------------------------------------------------------------------------
# Internal helpers (all platforms).
# ---------------------------------------------------------------------------

proc procOk(): ProcessResult =
  ProcessResult(success: true, error: peNone, msg: "")

proc procErr(e: ProcessError, m: string = ""): ProcessResult =
  let msg = if m.len == 0: $e else: $e & ": " & m
  ProcessResult(success: false, error: e, msg: msg)

# ---------------------------------------------------------------------------
# Linux implementation.
# ---------------------------------------------------------------------------

when defined(linux):
  import posix

  # ptrace request constants (from <sys/ptrace.h>).
  const
    PTRACE_TRACEME*    = clong(0)
    PTRACE_PEEKDATA*   = clong(2)
    PTRACE_POKEDATA*   = clong(5)
    PTRACE_CONT*       = clong(7)
    PTRACE_SINGLESTEP* = clong(9)
    PTRACE_GETREGS*    = clong(12)
    PTRACE_SETREGS*    = clong(13)
    PTRACE_ATTACH*     = clong(16)
    PTRACE_DETACH*     = clong(17)
    PTRACE_SYSCALL*    = clong(24)

  # Wait option constants.
  const WNOHANG* = cint(1)

  # errno is needed to distinguish ptrace PEEKDATA errors from the -1 value.
  var cerrno {.importc: "errno", header: "<errno.h>".}: cint

  # Raw ptrace binding. The request parameter is an int in Linux's ABI.
  proc ptrace_raw(request: clong, pid: Pid, `addr`: pointer,
                  data: pointer): clong
    {.importc: "ptrace", header: "<sys/ptrace.h>".}

  # user_regs_struct from <sys/user.h>, laid out to match the x86-64 C struct
  # exactly (27 x 8-byte unsigned long long fields, no padding).
  type
    UserRegsStruct {.pure.} = object
      r15, r14, r13, r12, rbp, rbx: uint64
      r11, r10, r9, r8:             uint64
      rax, rcx, rdx, rsi, rdi:      uint64
      orig_rax:                     uint64
      rip, cs, eflags, rsp, ss:     uint64
      fs_base, gs_base:             uint64
      ds, es, fs, gs:               uint64

  # POSIX wait-status predicates, implemented as per the POSIX specification.
  proc wIfExited(s: cint): bool   = (s and 0x7F) == 0
  proc wIfSignaled(s: cint): bool = ((s and 0x7F) != 0x7F) and
                                    ((s and 0x7F) != 0)
  proc wIfStopped(s: cint): bool  = (s and 0xFF) == 0x7F
  proc wExitStatus(s: cint): int  = int((s shr 8) and 0xFF)
  proc wTermSig(s: cint): int     = int(s and 0x7F)
  proc wStopSig(s: cint): int     = int((s shr 8) and 0xFF)

  # -------------------------------------------------------------------------
  # Public API - Linux.
  # -------------------------------------------------------------------------

  proc isPtraceAvailable*(): bool =
    # ptrace is present on all standard Linux kernels.
    true

  # Signal the kernel that this process should be traced by its parent.
  # Must be called from the child before raising a stop signal.
  proc traceMe*(): ProcessResult =
    let r = ptrace_raw(PTRACE_TRACEME, Pid(0), nil, nil)
    if r == -1:
      return procErr(peAttach, "PTRACE_TRACEME")
    return procOk()

  proc attachProcess*(pid: int): ProcessResult =
    let r = ptrace_raw(PTRACE_ATTACH, Pid(pid), nil, nil)
    if r == -1:
      return procErr(peAttach, "pid=" & $pid)
    return procOk()

  proc detachProcess*(pid: int): ProcessResult =
    let r = ptrace_raw(PTRACE_DETACH, Pid(pid), nil, nil)
    if r == -1:
      return procErr(peDetach, "pid=" & $pid)
    return procOk()

  proc waitForSignal*(pid: int): WaitResult =
    var status: cint = 0
    let ret = waitpid(Pid(pid), status, 0)
    if ret == -1:
      return WaitResult(status: wsUnknown)
    if wIfExited(status):
      return WaitResult(status: wsExited, exitCode: wExitStatus(status))
    if wIfSignaled(status):
      return WaitResult(status: wsSignaled, signal: wTermSig(status))
    if wIfStopped(status):
      return WaitResult(status: wsStopped, signal: wStopSig(status))
    return WaitResult(status: wsUnknown)

  # Non-blocking wait check (WNOHANG). Returns wsRunning when the process
  # has not yet changed state. Use in poll loops with a timeout.
  proc waitForSignalNonBlock*(pid: int): WaitResult =
    var status: cint = 0
    let ret = waitpid(Pid(pid), status, WNOHANG)
    if ret == 0:
      return WaitResult(status: wsRunning)
    if ret == -1:
      return WaitResult(status: wsUnknown)
    if wIfExited(status):
      return WaitResult(status: wsExited, exitCode: wExitStatus(status))
    if wIfSignaled(status):
      return WaitResult(status: wsSignaled, signal: wTermSig(status))
    if wIfStopped(status):
      return WaitResult(status: wsStopped, signal: wStopSig(status))
    return WaitResult(status: wsUnknown)

  # Read size bytes from the target process starting at address.
  # Uses PTRACE_PEEKDATA which transfers one machine word at a time.
  # Returns (bytes, result). On error, bytes may be partial.
  proc readProcessMemory*(pid: int, address: uint64,
                          size: int): (seq[byte], ProcessResult) =
    if size <= 0:
      return (@[], procErr(peRange, "size must be positive"))
    var bytes: seq[byte]
    let wordSize = sizeof(uint64)
    var pos = 0
    while pos < size:
      let wordAddr = address + uint64(pos)
      cerrno = cint(0)
      let word = ptrace_raw(PTRACE_PEEKDATA, Pid(pid),
                            cast[pointer](wordAddr), nil)
      if cerrno != cint(0):
        return (bytes, procErr(pePeek, "offset=" & $pos))
      let take = min(wordSize, size - pos)
      for i in 0 ..< take:
        bytes.add(byte((word shr (i * 8)) and 0xFF))
      pos += wordSize
    return (bytes, procOk())

  # Write bytes into the target process at address.
  # Handles partial words at the end by reading before writing.
  proc writeProcessMemory*(pid: int, address: uint64,
                           bytes: seq[byte]): ProcessResult =
    if bytes.len == 0:
      return procErr(peRange, "empty byte sequence")
    let wordSize = sizeof(uint64)
    var pos = 0
    while pos < bytes.len:
      let wordAddr = address + uint64(pos)
      let remaining = bytes.len - pos
      var word: int64 = 0
      if remaining < wordSize:
        # Preserve the trailing bytes not covered by the patch.
        cerrno = cint(0)
        word = int64(ptrace_raw(PTRACE_PEEKDATA, Pid(pid),
                                cast[pointer](wordAddr), nil))
        if cerrno != cint(0):
          return procErr(pePeek, "read-before-write offset=" & $pos)
        for i in 0 ..< remaining:
          let shift = i * 8
          word = word and not(int64(0xFF) shl shift)
          word = word or (int64(bytes[pos + i]) shl shift)
      else:
        for i in 0 ..< wordSize:
          word = word or (int64(bytes[pos + i]) shl (i * 8))
      let r = ptrace_raw(PTRACE_POKEDATA, Pid(pid),
                         cast[pointer](wordAddr), cast[pointer](word))
      if r == -1:
        return procErr(pePoke, "offset=" & $pos)
      pos += wordSize
    return procOk()

  proc getRegisters*(pid: int): (Registers, ProcessResult) =
    var uregs: UserRegsStruct
    let r = ptrace_raw(PTRACE_GETREGS, Pid(pid), nil, addr uregs)
    if r == -1:
      return (Registers(), procErr(peGetRegs, "pid=" & $pid))
    let regs = Registers(
      rip:    uregs.rip,
      rsp:    uregs.rsp,
      rbp:    uregs.rbp,
      rax:    uregs.rax,
      rbx:    uregs.rbx,
      rcx:    uregs.rcx,
      rdx:    uregs.rdx,
      rsi:    uregs.rsi,
      rdi:    uregs.rdi,
      r8:     uregs.r8,
      r9:     uregs.r9,
      r10:    uregs.r10,
      r11:    uregs.r11,
      r12:    uregs.r12,
      r13:    uregs.r13,
      r14:    uregs.r14,
      r15:    uregs.r15,
      eflags: uregs.eflags,
      cs:     uregs.cs,
      ss:     uregs.ss,
      origRax: uregs.orig_rax
    )
    return (regs, procOk())

  proc setRegisters*(pid: int, regs: Registers): ProcessResult =
    # Read the full register set first to preserve fields not in Registers.
    var uregs: UserRegsStruct
    let r0 = ptrace_raw(PTRACE_GETREGS, Pid(pid), nil, addr uregs)
    if r0 == -1:
      return procErr(peGetRegs, "read before setregs, pid=" & $pid)
    uregs.rip    = regs.rip
    uregs.rsp    = regs.rsp
    uregs.rbp    = regs.rbp
    uregs.rax    = regs.rax
    uregs.rbx    = regs.rbx
    uregs.rcx    = regs.rcx
    uregs.rdx    = regs.rdx
    uregs.rsi    = regs.rsi
    uregs.rdi    = regs.rdi
    uregs.r8     = regs.r8
    uregs.r9     = regs.r9
    uregs.r10    = regs.r10
    uregs.r11    = regs.r11
    uregs.r12    = regs.r12
    uregs.r13    = regs.r13
    uregs.r14    = regs.r14
    uregs.r15    = regs.r15
    uregs.eflags = regs.eflags
    uregs.cs     = regs.cs
    uregs.ss     = regs.ss
    let r = ptrace_raw(PTRACE_SETREGS, Pid(pid), nil, addr uregs)
    if r == -1:
      return procErr(peSetRegs, "pid=" & $pid)
    return procOk()

  proc singleStep*(pid: int): ProcessResult =
    let r = ptrace_raw(PTRACE_SINGLESTEP, Pid(pid), nil, nil)
    if r == -1:
      return procErr(peStep, "pid=" & $pid)
    return procOk()

  proc continueExecution*(pid: int): ProcessResult =
    let r = ptrace_raw(PTRACE_CONT, Pid(pid), nil, nil)
    if r == -1:
      return procErr(peContinue, "pid=" & $pid)
    return procOk()

  # Resume execution and stop at the next syscall entry or exit point.
  proc stepToSyscall*(pid: int): ProcessResult =
    let r = ptrace_raw(PTRACE_SYSCALL, Pid(pid), nil, nil)
    if r == -1:
      return procErr(peContinue, "PTRACE_SYSCALL pid=" & $pid)
    return procOk()

  # Inject a software breakpoint (INT3, 0xCC) at address.
  # Returns the Breakpoint record containing the original byte.
  proc setBreakpoint*(pid: int, address: uint64): (Breakpoint, ProcessResult) =
    let (orig, rr) = readProcessMemory(pid, address, 1)
    if not rr.success:
      return (Breakpoint(), rr)
    let wr = writeProcessMemory(pid, address, @[0xCC'u8])
    if not wr.success:
      return (Breakpoint(), wr)
    return (Breakpoint(address: address, originalByte: orig[0], active: true),
            procOk())

  # Remove a breakpoint by restoring the original byte.
  proc removeBreakpoint*(pid: int, bp: Breakpoint): ProcessResult =
    if not bp.active:
      return procOk()
    return writeProcessMemory(pid, bp.address, @[bp.originalByte])

# ---------------------------------------------------------------------------
# Non-Linux stubs: return platform errors without performing any action.
# ---------------------------------------------------------------------------

else:
  proc isPtraceAvailable*(): bool = false

  proc traceMe*(): ProcessResult =
    procErr(pePlatform)

  proc attachProcess*(pid: int): ProcessResult =
    procErr(pePlatform)

  proc detachProcess*(pid: int): ProcessResult =
    procErr(pePlatform)

  proc waitForSignal*(pid: int): WaitResult =
    WaitResult(status: wsUnknown)

  proc readProcessMemory*(pid: int, address: uint64,
                          size: int): (seq[byte], ProcessResult) =
    (@[], procErr(pePlatform))

  proc writeProcessMemory*(pid: int, address: uint64,
                           bytes: seq[byte]): ProcessResult =
    procErr(pePlatform)

  proc getRegisters*(pid: int): (Registers, ProcessResult) =
    (Registers(), procErr(pePlatform))

  proc setRegisters*(pid: int, regs: Registers): ProcessResult =
    procErr(pePlatform)

  proc singleStep*(pid: int): ProcessResult =
    procErr(pePlatform)

  proc continueExecution*(pid: int): ProcessResult =
    procErr(pePlatform)

  proc stepToSyscall*(pid: int): ProcessResult =
    procErr(pePlatform)

  proc setBreakpoint*(pid: int, address: uint64): (Breakpoint, ProcessResult) =
    (Breakpoint(), procErr(pePlatform))

  proc removeBreakpoint*(pid: int, bp: Breakpoint): ProcessResult =
    procErr(pePlatform)
