# NimGuard - Process attachment and control via Win32 API.
# Wraps Windows debugging API for live process inspection and manipulation.
# Compiles on all platforms but only operates on Windows. On other platforms
# all procedures return a wpPlatform error without performing any action.

type
  WinProcessError* = enum
    wpNone        = "none"
    wpPlatform    = "platform not supported"
    wpOpen        = "OpenProcess failed"
    wpClose       = "CloseProcess failed"
    wpReadMem     = "ReadProcessMemory failed"
    wpWriteMem    = "WriteProcessMemory failed"
    wpSuspend     = "SuspendThread failed"
    wpResume      = "ResumeThread failed"
    wpGetCtx      = "GetThreadContext failed"
    wpSetCtx      = "SetThreadContext failed"
    wpEnum        = "thread enumeration failed"
    wpBreakpoint  = "breakpoint injection failed"
    wpProtect     = "VirtualProtectEx failed"
    wpDebugEvent  = "WaitForDebugEvent failed"
    wpRange       = "invalid range or size"

  WinProcessResult* = object
    success*: bool
    error*:   WinProcessError
    msg*:     string

  WinRegisters* = object
    rip*, rsp*, rbp*:           uint64
    rax*, rbx*, rcx*, rdx*:     uint64
    rsi*, rdi*:                 uint64
    r8*, r9*, r10*, r11*:       uint64
    r12*, r13*, r14*, r15*:     uint64
    eflags*:                    uint64

  WinBreakpoint* = object
    address*:      uint64
    originalByte*: byte
    active*:       bool

  DebugEventKind* = enum
    deNone            = "none"
    deException       = "exception"
    deCreateThread    = "create_thread"
    deCreateProcess   = "create_process"
    deExitThread      = "exit_thread"
    deExitProcess     = "exit_process"
    deLoadDll         = "load_dll"
    deUnloadDll       = "unload_dll"
    deOutputDebugStr  = "output_debug_string"
    deUnknown         = "unknown"

  DebugEvent* = object
    kind*:      DebugEventKind
    processId*: int
    threadId*:  int

# ---------------------------------------------------------------------------
# Internal helpers (all platforms).
# ---------------------------------------------------------------------------

proc wpOk(): WinProcessResult =
  WinProcessResult(success: true, error: wpNone, msg: "")

proc wpErr(e: WinProcessError, m: string = ""): WinProcessResult =
  let msg = if m.len == 0: $e else: $e & ": " & m
  WinProcessResult(success: false, error: e, msg: msg)

# ---------------------------------------------------------------------------
# Windows implementation.
# ---------------------------------------------------------------------------

when defined(windows):
  import winlean, strutils

  # Win32 types not exposed by winlean.
  type
    HANDLE = pointer
    DWORD  = uint32
    BOOL   = int32
    WORD   = uint16

  const
    PROCESS_ALL_ACCESS*          = DWORD(0x1F0FFF)
    THREAD_ALL_ACCESS*           = DWORD(0x1F03FF)
    TH32CS_SNAPTHREAD*           = DWORD(0x00000004)
    CONTEXT_FULL*                = DWORD(0x10001F)
    PAGE_EXECUTE_READWRITE*      = DWORD(0x40)
    PAGE_EXECUTE_READ*           = DWORD(0x20)
    DBG_CONTINUE*                = DWORD(0x00010002)
    DBG_EXCEPTION_NOT_HANDLED*   = DWORD(0x80010001)
    EXCEPTION_BREAKPOINT*        = DWORD(0x80000003)
    EXCEPTION_SINGLE_STEP*       = DWORD(0x80000004)
    CREATE_THREAD_DEBUG_EVENT*   = DWORD(2)
    CREATE_PROCESS_DEBUG_EVENT*  = DWORD(3)
    EXIT_THREAD_DEBUG_EVENT*     = DWORD(4)
    EXIT_PROCESS_DEBUG_EVENT*    = DWORD(5)
    EXCEPTION_DEBUG_EVENT*       = DWORD(1)
    LOAD_DLL_DEBUG_EVENT*        = DWORD(6)
    UNLOAD_DLL_DEBUG_EVENT*      = DWORD(7)
    OUTPUT_DEBUG_STRING_EVENT*   = DWORD(8)
  let INVALID_HANDLE_VALUE* = cast[HANDLE](cast[int](-1))

  # THREADENTRY32 for CreateToolhelp32Snapshot / Thread32First / Thread32Next.
  type
    THREADENTRY32 {.pure.} = object
      dwSize:             DWORD
      cntUsage:           DWORD
      th32ThreadID:       DWORD
      th32OwnerProcessID: DWORD
      tpBasePri:          int32
      tpDeltaPri:         int32
      dwFlags:            DWORD

  # x86-64 CONTEXT structure (simplified - the fields we need).
  # The full CONTEXT is 1232 bytes. We map just the fields we use after the
  # mandatory header fields. Using a flat byte buffer avoids the complex
  # union layout; register offsets are derived from the Windows SDK spec.
  type
    CONTEXT64 {.pure.} = object
      P1Home:          uint64  # offset 0
      P2Home:          uint64  # offset 8
      P3Home:          uint64  # offset 16
      P4Home:          uint64  # offset 24
      P5Home:          uint64  # offset 32
      P6Home:          uint64  # offset 40
      ContextFlags:    DWORD   # offset 48
      MxCsr:           DWORD   # offset 52
      SegCs:           WORD    # offset 56
      SegDs:           WORD    # offset 58
      SegEs:           WORD    # offset 60
      SegFs:           WORD    # offset 62
      SegGs:           WORD    # offset 64
      SegSs:           WORD    # offset 66
      EFlags:          DWORD   # offset 68
      Dr0:             uint64  # offset 72
      Dr1:             uint64  # offset 80
      Dr2:             uint64  # offset 88
      Dr3:             uint64  # offset 96
      Dr6:             uint64  # offset 104
      Dr7:             uint64  # offset 112
      Rax:             uint64  # offset 120
      Rcx:             uint64  # offset 128
      Rdx:             uint64  # offset 136
      Rbx:             uint64  # offset 144
      Rsp:             uint64  # offset 152
      Rbp:             uint64  # offset 160
      Rsi:             uint64  # offset 168
      Rdi:             uint64  # offset 176
      R8:              uint64  # offset 184
      R9:              uint64  # offset 192
      R10:             uint64  # offset 200
      R11:             uint64  # offset 208
      R12:             uint64  # offset 216
      R13:             uint64  # offset 224
      R14:             uint64  # offset 232
      R15:             uint64  # offset 240
      Rip:             uint64  # offset 248
      # Remaining fields (floating point, vector) occupy rest of 1232 bytes.
      # Total CONTEXT size = 1232; fields above = 256; padding = 976.
      padding:         array[976, byte]

  # DEBUG_EVENT structure (simplified union layout).
  type
    EXCEPTION_RECORD {.pure.} = object
      ExceptionCode:    DWORD
      ExceptionFlags:   DWORD
      pExceptionRecord: pointer
      ExceptionAddress: pointer
      NumberParameters: DWORD
      ExceptionInformation: array[15, uint64]

    EXCEPTION_DEBUG_INFO {.pure.} = object
      ExceptionRecord: EXCEPTION_RECORD
      dwFirstChance:   DWORD

    DEBUG_EVENT {.pure.} = object
      dwDebugEventCode: DWORD
      dwProcessId:      DWORD
      dwThreadId:       DWORD
      # Union payload - we use the largest member to size the struct.
      # Only ExceptionDebug is inspected; other events are continued.
      u:                array[160, byte]

  # Win32 API imports.
  proc OpenProcess(dwDesiredAccess: DWORD, bInheritHandle: BOOL,
                   dwProcessId: DWORD): HANDLE
    {.importc: "OpenProcess", dynlib: "kernel32", stdcall.}

  proc CloseHandle(hObject: HANDLE): BOOL
    {.importc: "CloseHandle", dynlib: "kernel32", stdcall.}

  proc ReadProcessMemory(hProcess: HANDLE, lpBaseAddress: pointer,
                         lpBuffer: pointer, nSize: int,
                         lpNumberOfBytesRead: ptr int): BOOL
    {.importc: "ReadProcessMemory", dynlib: "kernel32", stdcall.}

  proc WriteProcessMemory(hProcess: HANDLE, lpBaseAddress: pointer,
                          lpBuffer: pointer, nSize: int,
                          lpNumberOfBytesWritten: ptr int): BOOL
    {.importc: "WriteProcessMemory", dynlib: "kernel32", stdcall.}

  proc VirtualProtectEx(hProcess: HANDLE, lpAddress: pointer,
                        dwSize: int, flNewProtect: DWORD,
                        lpflOldProtect: ptr DWORD): BOOL
    {.importc: "VirtualProtectEx", dynlib: "kernel32", stdcall.}

  proc VirtualAllocEx(hProcess: HANDLE, lpAddress: pointer,
                      dwSize: int, flAllocationType: DWORD,
                      flProtect: DWORD): pointer
    {.importc: "VirtualAllocEx", dynlib: "kernel32", stdcall.}

  proc VirtualFreeEx(hProcess: HANDLE, lpAddress: pointer,
                     dwSize: int, dwFreeType: DWORD): BOOL
    {.importc: "VirtualFreeEx", dynlib: "kernel32", stdcall.}

  proc OpenThread(dwDesiredAccess: DWORD, bInheritHandle: BOOL,
                  dwThreadId: DWORD): HANDLE
    {.importc: "OpenThread", dynlib: "kernel32", stdcall.}

  proc SuspendThread(hThread: HANDLE): DWORD
    {.importc: "SuspendThread", dynlib: "kernel32", stdcall.}

  proc ResumeThread(hThread: HANDLE): DWORD
    {.importc: "ResumeThread", dynlib: "kernel32", stdcall.}

  proc GetThreadContext(hThread: HANDLE, lpContext: ptr CONTEXT64): BOOL
    {.importc: "GetThreadContext", dynlib: "kernel32", stdcall.}

  proc SetThreadContext(hThread: HANDLE, lpContext: ptr CONTEXT64): BOOL
    {.importc: "SetThreadContext", dynlib: "kernel32", stdcall.}

  proc CreateToolhelp32Snapshot(dwFlags: DWORD, th32ProcessID: DWORD): HANDLE
    {.importc: "CreateToolhelp32Snapshot", dynlib: "kernel32", stdcall.}

  proc Thread32First(hSnapshot: HANDLE,
                     lpte: ptr THREADENTRY32): BOOL
    {.importc: "Thread32First", dynlib: "kernel32", stdcall.}

  proc Thread32Next(hSnapshot: HANDLE,
                    lpte: ptr THREADENTRY32): BOOL
    {.importc: "Thread32Next", dynlib: "kernel32", stdcall.}

  proc DebugActiveProcess(dwProcessId: DWORD): BOOL
    {.importc: "DebugActiveProcess", dynlib: "kernel32", stdcall.}

  proc DebugActiveProcessStop(dwProcessId: DWORD): BOOL
    {.importc: "DebugActiveProcessStop", dynlib: "kernel32", stdcall.}

  proc WaitForDebugEvent(lpDebugEvent: ptr DEBUG_EVENT,
                         dwMilliseconds: DWORD): BOOL
    {.importc: "WaitForDebugEvent", dynlib: "kernel32", stdcall.}

  proc ContinueDebugEvent(dwProcessId: DWORD, dwThreadId: DWORD,
                          dwContinueStatus: DWORD): BOOL
    {.importc: "ContinueDebugEvent", dynlib: "kernel32", stdcall.}

  proc GetLastError(): DWORD
    {.importc: "GetLastError", dynlib: "kernel32", stdcall.}

  # -------------------------------------------------------------------------
  # Public API - Windows.
  # -------------------------------------------------------------------------

  proc isWinDebugAvailable*(): bool = true

  # Open a process handle with full access rights.
  proc openProcessHandle*(pid: int): (HANDLE, WinProcessResult) =
    let h = OpenProcess(PROCESS_ALL_ACCESS, BOOL(0), DWORD(pid))
    if h == nil:
      return (nil, wpErr(wpOpen, "pid=" & $pid &
               " err=" & $GetLastError()))
    return (h, wpOk())

  proc closeProcessHandle*(h: HANDLE): WinProcessResult =
    if CloseHandle(h) == BOOL(0):
      return wpErr(wpClose, "err=" & $GetLastError())
    return wpOk()

  # Read size bytes from the target process at address.
  proc readProcessMemory*(pid: int, address: uint64,
                          size: int): (seq[byte], WinProcessResult) =
    if size <= 0:
      return (@[], wpErr(wpRange, "size must be positive"))
    let (h, hr) = openProcessHandle(pid)
    if not hr.success:
      return (@[], hr)
    defer: discard CloseHandle(h)
    var buf = newSeq[byte](size)
    var bytesRead: int = 0
    let ok = ReadProcessMemory(h, cast[pointer](address),
                               addr buf[0], size, addr bytesRead)
    if ok == BOOL(0):
      return (@[], wpErr(wpReadMem, "addr=0x" & toHex(address) &
               " err=" & $GetLastError()))
    buf.setLen(bytesRead)
    return (buf, wpOk())

  # Write bytes into the target process at address.
  proc writeProcessMemory*(pid: int, address: uint64,
                           bytes: seq[byte]): WinProcessResult =
    if bytes.len == 0:
      return wpErr(wpRange, "empty byte sequence")
    let (h, hr) = openProcessHandle(pid)
    if not hr.success:
      return hr
    defer: discard CloseHandle(h)
    # Make page writable.
    var oldProtect: DWORD = 0
    discard VirtualProtectEx(h, cast[pointer](address), bytes.len,
                             PAGE_EXECUTE_READWRITE, addr oldProtect)
    var written: int = 0
    let ok = WriteProcessMemory(h, cast[pointer](address),
                                unsafeAddr bytes[0], bytes.len,
                                addr written)
    # Restore original page protection.
    var dummy: DWORD = 0
    discard VirtualProtectEx(h, cast[pointer](address), bytes.len,
                             oldProtect, addr dummy)
    if ok == BOOL(0):
      return wpErr(wpWriteMem, "addr=0x" & toHex(address) &
               " err=" & $GetLastError())
    return wpOk()

  # Enumerate thread IDs belonging to a process.
  proc enumerateThreads*(pid: int): (seq[int], WinProcessResult) =
    let snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, DWORD(0))
    if snap == INVALID_HANDLE_VALUE:
      return (@[], wpErr(wpEnum, "pid=" & $pid &
               " err=" & $GetLastError()))
    defer: discard CloseHandle(snap)
    var entry: THREADENTRY32
    entry.dwSize = DWORD(sizeof(THREADENTRY32))
    var threads: seq[int]
    if Thread32First(snap, addr entry) == BOOL(0):
      return (@[], wpErr(wpEnum, "Thread32First failed"))
    while true:
      if int(entry.th32OwnerProcessID) == pid:
        threads.add(int(entry.th32ThreadID))
      if Thread32Next(snap, addr entry) == BOOL(0):
        break
    return (threads, wpOk())

  proc suspendThread*(tid: int): WinProcessResult =
    let h = OpenThread(THREAD_ALL_ACCESS, BOOL(0), DWORD(tid))
    if h == nil:
      return wpErr(wpSuspend, "tid=" & $tid & " err=" & $GetLastError())
    defer: discard CloseHandle(h)
    let prev = SuspendThread(h)
    if prev == DWORD(0xFFFFFFFF'u32):
      return wpErr(wpSuspend, "tid=" & $tid & " err=" & $GetLastError())
    return wpOk()

  proc resumeThread*(tid: int): WinProcessResult =
    let h = OpenThread(THREAD_ALL_ACCESS, BOOL(0), DWORD(tid))
    if h == nil:
      return wpErr(wpResume, "tid=" & $tid & " err=" & $GetLastError())
    defer: discard CloseHandle(h)
    let prev = ResumeThread(h)
    if prev == DWORD(0xFFFFFFFF'u32):
      return wpErr(wpResume, "tid=" & $tid & " err=" & $GetLastError())
    return wpOk()

  proc getThreadContext*(tid: int): (WinRegisters, WinProcessResult) =
    let h = OpenThread(THREAD_ALL_ACCESS, BOOL(0), DWORD(tid))
    if h == nil:
      return (WinRegisters(), wpErr(wpGetCtx,
               "tid=" & $tid & " err=" & $GetLastError()))
    defer: discard CloseHandle(h)
    var ctx: CONTEXT64
    ctx.ContextFlags = CONTEXT_FULL
    if GetThreadContext(h, addr ctx) == BOOL(0):
      return (WinRegisters(), wpErr(wpGetCtx,
               "tid=" & $tid & " err=" & $GetLastError()))
    let regs = WinRegisters(
      rip:    ctx.Rip,
      rsp:    ctx.Rsp,
      rbp:    ctx.Rbp,
      rax:    ctx.Rax,
      rbx:    ctx.Rbx,
      rcx:    ctx.Rcx,
      rdx:    ctx.Rdx,
      rsi:    ctx.Rsi,
      rdi:    ctx.Rdi,
      r8:     ctx.R8,
      r9:     ctx.R9,
      r10:    ctx.R10,
      r11:    ctx.R11,
      r12:    ctx.R12,
      r13:    ctx.R13,
      r14:    ctx.R14,
      r15:    ctx.R15,
      eflags: uint64(ctx.EFlags)
    )
    return (regs, wpOk())

  proc setThreadContext*(tid: int, regs: WinRegisters): WinProcessResult =
    let h = OpenThread(THREAD_ALL_ACCESS, BOOL(0), DWORD(tid))
    if h == nil:
      return wpErr(wpSetCtx, "tid=" & $tid & " err=" & $GetLastError())
    defer: discard CloseHandle(h)
    # Read existing context to preserve non-general-purpose fields.
    var ctx: CONTEXT64
    ctx.ContextFlags = CONTEXT_FULL
    if GetThreadContext(h, addr ctx) == BOOL(0):
      return wpErr(wpGetCtx, "read before set, tid=" & $tid)
    ctx.Rip    = regs.rip
    ctx.Rsp    = regs.rsp
    ctx.Rbp    = regs.rbp
    ctx.Rax    = regs.rax
    ctx.Rbx    = regs.rbx
    ctx.Rcx    = regs.rcx
    ctx.Rdx    = regs.rdx
    ctx.Rsi    = regs.rsi
    ctx.Rdi    = regs.rdi
    ctx.R8     = regs.r8
    ctx.R9     = regs.r9
    ctx.R10    = regs.r10
    ctx.R11    = regs.r11
    ctx.R12    = regs.r12
    ctx.R13    = regs.r13
    ctx.R14    = regs.r14
    ctx.R15    = regs.r15
    ctx.EFlags = DWORD(regs.eflags)
    if SetThreadContext(h, addr ctx) == BOOL(0):
      return wpErr(wpSetCtx, "tid=" & $tid & " err=" & $GetLastError())
    return wpOk()

  # Inject a software breakpoint (INT3, 0xCC) at address.
  proc setBreakpoint*(pid: int, address: uint64): (WinBreakpoint, WinProcessResult) =
    let (orig, rr) = readProcessMemory(pid, address, 1)
    if not rr.success:
      return (WinBreakpoint(), rr)
    let wr = writeProcessMemory(pid, address, @[0xCC'u8])
    if not wr.success:
      return (WinBreakpoint(), wr)
    return (WinBreakpoint(address: address, originalByte: orig[0], active: true),
            wpOk())

  # Remove a breakpoint by restoring the original byte.
  proc removeBreakpoint*(pid: int, bp: WinBreakpoint): WinProcessResult =
    if not bp.active:
      return wpOk()
    return writeProcessMemory(pid, bp.address, @[bp.originalByte])

  # Attach to a process for debugging via DebugActiveProcess.
  proc attachProcess*(pid: int): WinProcessResult =
    if DebugActiveProcess(DWORD(pid)) == BOOL(0):
      return wpErr(wpOpen, "DebugActiveProcess pid=" & $pid &
               " err=" & $GetLastError())
    return wpOk()

  # Detach from a process being debugged.
  proc detachProcess*(pid: int): WinProcessResult =
    if DebugActiveProcessStop(DWORD(pid)) == BOOL(0):
      return wpErr(wpClose, "DebugActiveProcessStop pid=" & $pid &
               " err=" & $GetLastError())
    return wpOk()

  # Wait for the next debug event from any attached process.
  # timeoutMs: milliseconds to wait; use high value (e.g. 5000) to block.
  proc waitForDebugEvent*(timeoutMs: int): (DebugEvent, WinProcessResult) =
    var de: DEBUG_EVENT
    if WaitForDebugEvent(addr de, DWORD(timeoutMs)) == BOOL(0):
      return (DebugEvent(), wpErr(wpDebugEvent,
               "err=" & $GetLastError()))
    var kind = deUnknown
    case de.dwDebugEventCode
    of EXCEPTION_DEBUG_EVENT:       kind = deException
    of CREATE_THREAD_DEBUG_EVENT:   kind = deCreateThread
    of CREATE_PROCESS_DEBUG_EVENT:  kind = deCreateProcess
    of EXIT_THREAD_DEBUG_EVENT:     kind = deExitThread
    of EXIT_PROCESS_DEBUG_EVENT:    kind = deExitProcess
    of LOAD_DLL_DEBUG_EVENT:        kind = deLoadDll
    of UNLOAD_DLL_DEBUG_EVENT:      kind = deUnloadDll
    of OUTPUT_DEBUG_STRING_EVENT:   kind = deOutputDebugStr
    else:                           kind = deUnknown
    let ev = DebugEvent(
      kind:      kind,
      processId: int(de.dwProcessId),
      threadId:  int(de.dwThreadId)
    )
    return (ev, wpOk())

  # Signal the debugger to continue execution after a debug event.
  proc continueDebugEvent*(pid: int, tid: int,
                           handled: bool): WinProcessResult =
    let status = if handled: DBG_CONTINUE else: DBG_EXCEPTION_NOT_HANDLED
    if ContinueDebugEvent(DWORD(pid), DWORD(tid), status) == BOOL(0):
      return wpErr(wpDebugEvent, "ContinueDebugEvent pid=" & $pid &
               " err=" & $GetLastError())
    return wpOk()

  # Allocate executable memory in the target process (for code caves).
  proc allocateRemoteMemory*(pid: int, size: int): (uint64, WinProcessResult) =
    let (h, hr) = openProcessHandle(pid)
    if not hr.success:
      return (0'u64, hr)
    defer: discard CloseHandle(h)
    let MEM_COMMIT   = DWORD(0x1000)
    let MEM_RESERVE  = DWORD(0x2000)
    let p = VirtualAllocEx(h, nil, size,
                           MEM_COMMIT or MEM_RESERVE,
                           PAGE_EXECUTE_READWRITE)
    if p == nil:
      return (0'u64, wpErr(wpOpen, "VirtualAllocEx size=" & $size &
               " err=" & $GetLastError()))
    return (cast[uint64](p), wpOk())

# ---------------------------------------------------------------------------
# Non-Windows stubs: return platform errors without performing any action.
# ---------------------------------------------------------------------------

else:
  proc isWinDebugAvailable*(): bool = false

  proc readProcessMemory*(pid: int, address: uint64,
                          size: int): (seq[byte], WinProcessResult) =
    (@[], wpErr(wpPlatform))

  proc writeProcessMemory*(pid: int, address: uint64,
                           bytes: seq[byte]): WinProcessResult =
    wpErr(wpPlatform)

  proc enumerateThreads*(pid: int): (seq[int], WinProcessResult) =
    (@[], wpErr(wpPlatform))

  proc suspendThread*(tid: int): WinProcessResult =
    wpErr(wpPlatform)

  proc resumeThread*(tid: int): WinProcessResult =
    wpErr(wpPlatform)

  proc getThreadContext*(tid: int): (WinRegisters, WinProcessResult) =
    (WinRegisters(), wpErr(wpPlatform))

  proc setThreadContext*(tid: int, regs: WinRegisters): WinProcessResult =
    wpErr(wpPlatform)

  proc setBreakpoint*(pid: int, address: uint64): (WinBreakpoint, WinProcessResult) =
    (WinBreakpoint(), wpErr(wpPlatform))

  proc removeBreakpoint*(pid: int, bp: WinBreakpoint): WinProcessResult =
    wpErr(wpPlatform)

  proc attachProcess*(pid: int): WinProcessResult =
    wpErr(wpPlatform)

  proc detachProcess*(pid: int): WinProcessResult =
    wpErr(wpPlatform)

  proc waitForDebugEvent*(timeoutMs: int): (DebugEvent, WinProcessResult) =
    (DebugEvent(), wpErr(wpPlatform))

  proc continueDebugEvent*(pid: int, tid: int,
                           handled: bool): WinProcessResult =
    wpErr(wpPlatform)

  proc allocateRemoteMemory*(pid: int, size: int): (uint64, WinProcessResult) =
    (0'u64, wpErr(wpPlatform))
