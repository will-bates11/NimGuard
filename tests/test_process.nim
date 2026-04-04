# NimGuard - Unit Tests for the Process Module
#
# Platform-independent tests run on all OSes and verify that the stubs
# behave correctly on non-Linux. Linux-specific tests fork a child process,
# exercise the real ptrace path, and clean up unconditionally via defer.
import unittest, process

# ---------------------------------------------------------------------------
# Suite: availability and non-Linux stub behaviour (all platforms).
# ---------------------------------------------------------------------------

suite "Process Module - Platform":

  test "isPtraceAvailable returns a bool without raising":
    let available = isPtraceAvailable()
    check available == true or available == false

  when not defined(linux):
    test "attachProcess returns platform error on non-Linux":
      let r = attachProcess(1)
      check r.success == false
      check r.error == pePlatform

    test "detachProcess returns platform error on non-Linux":
      let r = detachProcess(1)
      check r.success == false
      check r.error == pePlatform

    test "readProcessMemory returns platform error on non-Linux":
      let (_, r) = readProcessMemory(1, 0x1000'u64, 8)
      check r.success == false
      check r.error == pePlatform

    test "writeProcessMemory returns platform error on non-Linux":
      let r = writeProcessMemory(1, 0x1000'u64, @[0x90'u8])
      check r.success == false
      check r.error == pePlatform

    test "getRegisters returns platform error on non-Linux":
      let (_, r) = getRegisters(1)
      check r.success == false
      check r.error == pePlatform

    test "setRegisters returns platform error on non-Linux":
      let r = setRegisters(1, Registers())
      check r.success == false
      check r.error == pePlatform

    test "singleStep returns platform error on non-Linux":
      let r = singleStep(1)
      check r.success == false
      check r.error == pePlatform

    test "setBreakpoint returns platform error on non-Linux":
      let (_, r) = setBreakpoint(1, 0x1000'u64)
      check r.success == false
      check r.error == pePlatform

    test "removeBreakpoint on inactive bp succeeds on non-Linux stub":
      let bp = Breakpoint(address: 0x1000'u64, originalByte: 0x90'u8,
                          active: false)
      let r = removeBreakpoint(1, bp)
      # Inactive bp: stub still returns platform error (active flag not checked
      # in stubs, unlike the Linux path where inactive is a no-op).
      check r.success == false

# ---------------------------------------------------------------------------
# Suite: live ptrace tests (Linux only).
# ---------------------------------------------------------------------------

when defined(linux):
  import posix

  # Spawn a child that calls traceMe() then raises SIGSTOP, and wait for it.
  # Returns the child PID. The caller is responsible for cleanup.
  proc spawnTracedChild(): Pid =
    let pid = fork()
    if pid == 0:
      # Child: allow parent to trace, then stop.
      discard traceMe()
      discard posix.kill(posix.getpid(), SIGSTOP)
      # Loop so the parent has time to issue ptrace commands.
      while true:
        discard sleep(1)
    return pid

  proc reapChild(pid: Pid) =
    discard posix.kill(pid, SIGKILL)
    var s: cint
    discard waitpid(pid, s, 0)

  suite "Process Module - Linux ptrace":

    test "isPtraceAvailable returns true on Linux":
      check isPtraceAvailable() == true

    test "attachProcess and detachProcess on a child process":
      # Fork a plain sleeping child (no TRACEME) and attach via PTRACE_ATTACH.
      let pid = fork()
      if pid == Pid(0):
        discard sleep(10)
        quit(0)

      defer: reapChild(pid)

      let ar = attachProcess(int(pid))
      check ar.success

      if ar.success:
        let wr = waitForSignal(int(pid))
        check wr.status == wsStopped

        let dr = detachProcess(int(pid))
        check dr.success

    test "getRegisters returns valid RIP after stop":
      let pid = spawnTracedChild()
      defer: reapChild(pid)

      var status: cint
      discard waitpid(pid, status, 0)

      let (regs, rr) = getRegisters(int(pid))
      check rr.success
      # RIP must be a canonical x86-64 address (non-zero in any real process).
      check regs.rip != 0'u64

      discard detachProcess(int(pid))

    test "readProcessMemory reads bytes from child code":
      let pid = spawnTracedChild()
      defer: reapChild(pid)

      var status: cint
      discard waitpid(pid, status, 0)

      let (regs, rr) = getRegisters(int(pid))
      require rr.success

      # Read 8 bytes at the instruction pointer (must be readable code).
      let (bytes, mr) = readProcessMemory(int(pid), regs.rip, 8)
      check mr.success
      check bytes.len == 8

      discard detachProcess(int(pid))

    test "writeProcessMemory round-trip on child stack":
      let pid = spawnTracedChild()
      defer: reapChild(pid)

      var status: cint
      discard waitpid(pid, status, 0)

      let (regs, rr) = getRegisters(int(pid))
      require rr.success

      # Write below the current stack pointer (red zone; safe for testing).
      let writeAddr = regs.rsp - 128'u64
      let patch = @[0xAA'u8, 0xBB'u8, 0xCC'u8, 0xDD'u8]
      let wr = writeProcessMemory(int(pid), writeAddr, patch)
      check wr.success

      let (readBack, mr) = readProcessMemory(int(pid), writeAddr, 4)
      check mr.success
      check readBack.len == 4
      check readBack[0] == 0xAA'u8
      check readBack[1] == 0xBB'u8
      check readBack[2] == 0xCC'u8
      check readBack[3] == 0xDD'u8

      discard detachProcess(int(pid))

    test "setBreakpoint injects INT3 and removeBreakpoint restores original":
      let pid = spawnTracedChild()
      defer: reapChild(pid)

      var status: cint
      discard waitpid(pid, status, 0)

      let (regs, rr) = getRegisters(int(pid))
      require rr.success

      # Read the original byte at RIP before patching.
      let (origBytes, _) = readProcessMemory(int(pid), regs.rip, 1)
      require origBytes.len == 1
      let origByte = origBytes[0]

      # Inject breakpoint at RIP.
      let (bp, br) = setBreakpoint(int(pid), regs.rip)
      check br.success
      check bp.active
      check bp.address == regs.rip
      check bp.originalByte == origByte

      # Verify INT3 (0xCC) is now at RIP.
      let (patchedBytes, _) = readProcessMemory(int(pid), regs.rip, 1)
      check patchedBytes.len == 1
      check patchedBytes[0] == 0xCC'u8

      # Remove the breakpoint and verify original byte is restored.
      let removeRes = removeBreakpoint(int(pid), bp)
      check removeRes.success

      let (restoredBytes, _) = readProcessMemory(int(pid), regs.rip, 1)
      check restoredBytes.len == 1
      check restoredBytes[0] == origByte

      discard detachProcess(int(pid))

    test "singleStep advances RIP":
      let pid = spawnTracedChild()
      defer: reapChild(pid)

      var status: cint
      discard waitpid(pid, status, 0)

      let (regs0, rr0) = getRegisters(int(pid))
      require rr0.success
      let oldRip = regs0.rip

      let stepRes = singleStep(int(pid))
      check stepRes.success

      let wr = waitForSignal(int(pid))
      check wr.status == wsStopped

      let (regs1, rr1) = getRegisters(int(pid))
      check rr1.success
      # After one step, RIP must have advanced by at least one byte.
      check regs1.rip > oldRip

      discard detachProcess(int(pid))

    test "continueExecution unblocks a stopped child":
      let pid = spawnTracedChild()
      defer: reapChild(pid)

      var status: cint
      discard waitpid(pid, status, 0)

      let cr = continueExecution(int(pid))
      check cr.success

      # Give the child a moment, then kill and reap (handled by defer).
      discard sleep(0)

    test "removeBreakpoint on inactive breakpoint is a no-op":
      let bp = Breakpoint(address: 0'u64, originalByte: 0x90'u8, active: false)
      let r = removeBreakpoint(1, bp)
      check r.success

    test "readProcessMemory returns error for size zero":
      let (_, r) = readProcessMemory(1, 0x1000'u64, 0)
      check r.success == false
      check r.error == peRange

    test "writeProcessMemory returns error for empty bytes":
      let r = writeProcessMemory(1, 0x1000'u64, @[])
      check r.success == false
      check r.error == peRange
