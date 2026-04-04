# NimGuard - Unit Tests for the Windows Runtime Instrumentation Module
#
# Non-Windows tests verify that all operations degrade gracefully via stubs.
# Windows tests exercise live Win32 patching and breakpoint injection via
# the winruntime API.
import unittest, winruntime, winprocess

# ---------------------------------------------------------------------------
# Suite: non-Windows stub behaviour (all platforms).
# ---------------------------------------------------------------------------

suite "WinRuntime Module - Platform":

  test "attachProcess returns failure on non-Windows":
    when not defined(windows):
      let r = winruntime.attachProcess(1)
      check r.success == false
    else:
      check true

  test "detachProcess returns failure on non-Windows":
    when not defined(windows):
      let r = winruntime.detachProcess(1)
      check r.success == false
    else:
      check true

  test "patchProcessMemory returns failure for empty bytes on all platforms":
    let r = winruntime.patchProcessMemory(1, 0x1000'u64, @[])
    check r.success == false

  test "injectBreakpoint returns failure on non-Windows":
    when not defined(windows):
      let (_, r) = winruntime.injectBreakpoint(1, 0x1000'u64)
      check r.success == false
    else:
      check true

  test "suspendAllThreads returns failure on non-Windows":
    when not defined(windows):
      let (count, r) = winruntime.suspendAllThreads(1)
      check r.success == false
      check count == 0
    else:
      check true

  test "resumeAllThreads returns failure on non-Windows":
    when not defined(windows):
      let (count, r) = winruntime.resumeAllThreads(1)
      check r.success == false
      check count == 0
    else:
      check true

  test "hookFunction returns failure on non-Windows":
    when not defined(windows):
      let (_, r) = winruntime.hookFunction(1, 0x1000'u64, 0x2000'u64)
      check r.success == false
    else:
      check true

  test "allocateRemoteMemory returns failure on non-Windows":
    when not defined(windows):
      let (remoteAddr, r) = winruntime.allocateRemoteMemory(1, 4096)
      check r.success == false
      check remoteAddr == 0'u64
    else:
      check true

# ---------------------------------------------------------------------------
# Suite: live Windows runtime tests (Windows only).
# ---------------------------------------------------------------------------

when defined(windows):
  import os

  suite "WinRuntime Module - Windows live":

    test "patchProcessMemory writes bytes into self":
      let selfPid = int(os.getCurrentProcessId())
      var target: array[4, byte] = [0x00'u8, 0x00, 0x00, 0x00]
      let remoteAddr = cast[uint64](addr target[0])
      let patch = @[0xDE'u8, 0xAD'u8, 0xBE'u8, 0xEF'u8]
      let wr = winruntime.patchProcessMemory(selfPid, remoteAddr, patch)
      check wr.success
      check target[0] == 0xDE'u8
      check target[1] == 0xAD'u8
      check target[2] == 0xBE'u8
      check target[3] == 0xEF'u8

    test "injectBreakpoint injects INT3 into self data buffer":
      let selfPid = int(os.getCurrentProcessId())
      var dataBuf: array[4, byte] = [0x90'u8, 0x90, 0x90, 0x90]
      let remoteAddr = cast[uint64](addr dataBuf[0])
      let (bp, br) = winruntime.injectBreakpoint(selfPid, remoteAddr)
      check br.success
      check bp.active
      check dataBuf[0] == 0xCC'u8
      # Clean up.
      discard winruntime.removeBreakpoint(selfPid, bp)

    test "removeBreakpoint restores original byte":
      let selfPid = int(os.getCurrentProcessId())
      var dataBuf: array[4, byte] = [0x42'u8, 0x43, 0x44, 0x45]
      let remoteAddr = cast[uint64](addr dataBuf[0])
      let origByte = dataBuf[0]
      let (bp, br) = winruntime.injectBreakpoint(selfPid, remoteAddr)
      require br.success
      let rr = winruntime.removeBreakpoint(selfPid, bp)
      check rr.success
      check dataBuf[0] == origByte

    test "suspendAllThreads and resumeAllThreads on self":
      let selfPid = int(os.getCurrentProcessId())
      let (suspended, sr) = winruntime.suspendAllThreads(selfPid)
      check sr.success
      check suspended >= 1
      # Resume immediately so the test process keeps running.
      let (resumed, rr) = winruntime.resumeAllThreads(selfPid)
      check rr.success
      check resumed >= 1

    test "allocateRemoteMemory allocates a page in self":
      let selfPid = int(os.getCurrentProcessId())
      let (remoteAddr, ar) = winruntime.allocateRemoteMemory(selfPid, 4096)
      check ar.success
      check remoteAddr != 0'u64
      # Write and read back to confirm allocation is usable.
      let patch = @[0x11'u8, 0x22'u8, 0x33'u8]
      let wr = winruntime.patchProcessMemory(selfPid, remoteAddr, patch)
      check wr.success
      let (readBack, rr) = winprocess.readProcessMemory(selfPid, remoteAddr, 3)
      check rr.success
      check readBack.len == 3
      check readBack[0] == 0x11'u8
      check readBack[1] == 0x22'u8
      check readBack[2] == 0x33'u8
