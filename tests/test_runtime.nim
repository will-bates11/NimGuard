# NimGuard - Unit Tests for the Runtime Instrumentation Module
#
# Non-Linux tests verify that all operations degrade gracefully.
# Linux tests fork a traced child process to exercise live patching and
# breakpoint injection via the runtime API.
import unittest, runtime, process, disassembler

# ---------------------------------------------------------------------------
# Suite: non-Linux stub behaviour (all platforms).
# ---------------------------------------------------------------------------

suite "Runtime Module - Platform":

  test "attachProcess returns failure on non-Linux":
    when not defined(linux):
      let r = runtime.attachProcess(1)
      check r.success == false
    else:
      # On Linux this would actually attach; skip the negative test.
      check true

  test "detachProcess returns failure on non-Linux":
    when not defined(linux):
      let r = runtime.detachProcess(1)
      check r.success == false
    else:
      check true

  test "patchProcessMemory returns failure for empty bytes on all platforms":
    let r = runtime.patchProcessMemory(1, 0x1000'u64, @[])
    check r.success == false

  test "injectBreakpoint returns failure on non-Linux":
    when not defined(linux):
      let (_, r) = runtime.injectBreakpoint(1, 0x1000'u64)
      check r.success == false
    else:
      check true

  test "monitorSyscalls returns empty seq on non-Linux":
    when not defined(linux):
      let events = runtime.monitorSyscalls(1, 5)
      check events.len == 0
    else:
      check true

  test "disassembleAtAddress returns empty seq for zero count":
    let instrs = runtime.disassembleAtAddress(1, 0x1000'u64, 0)
    check instrs.len == 0

# ---------------------------------------------------------------------------
# Suite: live runtime tests (Linux only).
# ---------------------------------------------------------------------------

when defined(linux):
  import posix

  # Use _exit() in child branches so Nim's atexit/unittest handlers do not
  # run in the forked child and corrupt the parent's exit code.
  proc rawExit(code: cint) {.importc: "_exit", header: "<unistd.h>", noreturn.}

  proc spawnTracedChild(): Pid =
    let pid = fork()
    if pid == Pid(0):
      discard traceMe()
      discard posix.kill(posix.getpid(), SIGSTOP)
      while true:
        discard sleep(1)
    return pid

  proc reapChild(pid: Pid) =
    discard posix.kill(pid, SIGKILL)
    var s: cint
    discard waitpid(pid, s, 0)

  suite "Runtime Module - Linux live":

    test "patchProcessMemory writes bytes into a child process":
      let pid = spawnTracedChild()
      defer: reapChild(pid)

      var status: cint
      discard waitpid(pid, status, 0)

      let (regs, rr) = process.getRegisters(int(pid))
      require rr.success

      let writeAddr = regs.rsp - 128'u64
      let patch = @[0x11'u8, 0x22'u8, 0x33'u8, 0x44'u8]
      let wr = patchProcessMemory(int(pid), writeAddr, patch)
      check wr.success

      let (readBack, mr) = process.readProcessMemory(int(pid), writeAddr, 4)
      check mr.success
      check readBack.len == 4
      check readBack[0] == 0x11'u8
      check readBack[1] == 0x22'u8
      check readBack[2] == 0x33'u8
      check readBack[3] == 0x44'u8

      discard process.detachProcess(int(pid))

    test "injectBreakpoint injects INT3 at child RIP":
      let pid = spawnTracedChild()
      defer: reapChild(pid)

      var status: cint
      discard waitpid(pid, status, 0)

      let (regs, rr) = process.getRegisters(int(pid))
      require rr.success

      let (bp, br) = injectBreakpoint(int(pid), regs.rip)
      check br.success
      check bp.active

      # Verify INT3 is present.
      let (patched, mr) = process.readProcessMemory(int(pid), regs.rip, 1)
      check mr.success
      check patched.len == 1
      check patched[0] == 0xCC'u8

      discard process.detachProcess(int(pid))

    test "removeBreakpoint restores the original byte":
      let pid = spawnTracedChild()
      defer: reapChild(pid)

      var status: cint
      discard waitpid(pid, status, 0)

      let (regs, rr) = process.getRegisters(int(pid))
      require rr.success

      let (origBytes, _) = process.readProcessMemory(int(pid), regs.rip, 1)
      require origBytes.len == 1

      let (bp, br) = injectBreakpoint(int(pid), regs.rip)
      require br.success

      let rr2 = runtime.removeBreakpoint(int(pid), bp)
      check rr2.success

      let (restored, mr2) = process.readProcessMemory(int(pid), regs.rip, 1)
      check mr2.success
      check restored.len == 1
      check restored[0] == origBytes[0]

      discard process.detachProcess(int(pid))

    test "disassembleAtAddress decodes instructions from child memory":
      if not isCapstoneAvailable():
        skip()

      let pid = spawnTracedChild()
      defer: reapChild(pid)

      var status: cint
      discard waitpid(pid, status, 0)

      let (regs, rr) = process.getRegisters(int(pid))
      require rr.success

      let instrs = disassembleAtAddress(int(pid), regs.rip, 3)
      # Capstone may decode fewer if bytes are ambiguous, but at least one.
      check instrs.len >= 1

      discard process.detachProcess(int(pid))

    test "monitorSyscalls collects at least one event from a child":
      let pid = fork()
      if pid == Pid(0):
        # Child: set up tracing then make a known syscall (write).
        discard traceMe()
        discard posix.kill(posix.getpid(), SIGSTOP)
        # write(1, "x", 1) - syscall number 1 on x86-64 Linux.
        discard posix.write(FileHandle(1), cstring("x"), 1)
        rawExit(0)

      defer: reapChild(pid)

      var status: cint
      discard waitpid(pid, status, 0)

      # Collect up to 4 syscall events starting from the stopped child.
      let events = monitorSyscalls(int(pid), 4)
      check events.len >= 1
      # At least one event should be the write syscall (nr=1).
      var foundWrite = false
      for ev in events:
        if ev.syscallNr == 1:
          foundWrite = true
          break
      check foundWrite
