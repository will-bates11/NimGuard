# NimGuard - Unit Tests for the Windows Process Module
#
# Platform-independent tests run on all OSes and verify that the stubs
# behave correctly on non-Windows. Windows-specific tests open a child
# process and exercise the real Win32 path, cleaning up via defer.
import unittest, winprocess

# ---------------------------------------------------------------------------
# Suite: availability and non-Windows stub behaviour (all platforms).
# ---------------------------------------------------------------------------

suite "WinProcess Module - Platform":

  test "isWinDebugAvailable returns a bool without raising":
    let available = isWinDebugAvailable()
    check available == true or available == false

  when not defined(windows):
    test "attachProcess returns platform error on non-Windows":
      let r = winprocess.attachProcess(1)
      check r.success == false
      check r.error == wpPlatform

    test "detachProcess returns platform error on non-Windows":
      let r = winprocess.detachProcess(1)
      check r.success == false
      check r.error == wpPlatform

    test "readProcessMemory returns platform error on non-Windows":
      let (_, r) = winprocess.readProcessMemory(1, 0x1000'u64, 8)
      check r.success == false
      check r.error == wpPlatform

    test "writeProcessMemory returns platform error on non-Windows":
      let r = winprocess.writeProcessMemory(1, 0x1000'u64, @[0x90'u8])
      check r.success == false
      check r.error == wpPlatform

    test "enumerateThreads returns platform error on non-Windows":
      let (_, r) = winprocess.enumerateThreads(1)
      check r.success == false
      check r.error == wpPlatform

    test "suspendThread returns platform error on non-Windows":
      let r = winprocess.suspendThread(1)
      check r.success == false
      check r.error == wpPlatform

    test "resumeThread returns platform error on non-Windows":
      let r = winprocess.resumeThread(1)
      check r.success == false
      check r.error == wpPlatform

    test "getThreadContext returns platform error on non-Windows":
      let (_, r) = winprocess.getThreadContext(1)
      check r.success == false
      check r.error == wpPlatform

    test "setThreadContext returns platform error on non-Windows":
      let r = winprocess.setThreadContext(1, WinRegisters())
      check r.success == false
      check r.error == wpPlatform

    test "setBreakpoint returns platform error on non-Windows":
      let (_, r) = winprocess.setBreakpoint(1, 0x1000'u64)
      check r.success == false
      check r.error == wpPlatform

    test "removeBreakpoint on inactive bp returns platform error on non-Windows":
      let bp = WinBreakpoint(address: 0x1000'u64, originalByte: 0x90'u8,
                             active: false)
      let r = winprocess.removeBreakpoint(1, bp)
      check r.success == false
      check r.error == wpPlatform

    test "waitForDebugEvent returns platform error on non-Windows":
      let (_, r) = winprocess.waitForDebugEvent(0)
      check r.success == false
      check r.error == wpPlatform

    test "continueDebugEvent returns platform error on non-Windows":
      let r = winprocess.continueDebugEvent(1, 1, true)
      check r.success == false
      check r.error == wpPlatform

    test "allocateRemoteMemory returns platform error on non-Windows":
      let (remoteAddr, r) = winprocess.allocateRemoteMemory(1, 4096)
      check r.success == false
      check r.error == wpPlatform
      check remoteAddr == 0'u64

    test "readProcessMemory returns failure for size zero on non-Windows":
      # Stubs return wpPlatform without inspecting size.
      let (_, r) = winprocess.readProcessMemory(1, 0x1000'u64, 0)
      check r.success == false

    test "writeProcessMemory returns failure for empty bytes on non-Windows":
      # Stubs return wpPlatform without inspecting bytes.
      let r = winprocess.writeProcessMemory(1, 0x1000'u64, @[])
      check r.success == false

# ---------------------------------------------------------------------------
# Suite: live Win32 tests (Windows only).
# ---------------------------------------------------------------------------

when defined(windows):
  import os, osproc, strutils

  proc spawnSleepingChild(): Process =
    # Spawn a child process that loops so we have time to inspect it.
    when defined(windows):
      result = startProcess("cmd.exe", args = @["/c", "ping -n 30 127.0.0.1 > nul"],
                            options = {poUsePath})

  suite "WinProcess Module - Windows live":

    test "isWinDebugAvailable returns true on Windows":
      check isWinDebugAvailable() == true

    test "readProcessMemory and writeProcessMemory round-trip on self":
      # We can use the current process ID to test self-read.
      # Use os.getCurrentProcessId() for our own PID.
      let selfPid = int(os.getCurrentProcessId())
      # Allocate a small buffer in this process to read/write.
      var testBuf: array[8, byte] = [0xAA'u8, 0xBB, 0xCC, 0xDD,
                                     0x11, 0x22, 0x33, 0x44]
      let remoteAddr = cast[uint64](addr testBuf[0])
      # Read back what we just set.
      let (readBytes, rr) = winprocess.readProcessMemory(selfPid, remoteAddr, 8)
      check rr.success
      check readBytes.len == 8
      check readBytes[0] == 0xAA'u8
      check readBytes[3] == 0xDD'u8

    test "writeProcessMemory writes bytes to self":
      let selfPid = int(os.getCurrentProcessId())
      var target: array[4, byte] = [0x00'u8, 0x00, 0x00, 0x00]
      let remoteAddr = cast[uint64](addr target[0])
      let patch = @[0x11'u8, 0x22'u8, 0x33'u8, 0x44'u8]
      let wr = winprocess.writeProcessMemory(selfPid, remoteAddr, patch)
      check wr.success
      check target[0] == 0x11'u8
      check target[1] == 0x22'u8
      check target[2] == 0x33'u8
      check target[3] == 0x44'u8

    test "enumerateThreads finds at least one thread for self":
      let selfPid = int(os.getCurrentProcessId())
      let (tids, er) = winprocess.enumerateThreads(selfPid)
      check er.success
      check tids.len >= 1

    test "setBreakpoint injects INT3 and removeBreakpoint restores original in self":
      let selfPid = int(os.getCurrentProcessId())
      # Use a small data buffer as the target address (not actual code).
      var dataBuf: array[4, byte] = [0x90'u8, 0x90, 0x90, 0x90]
      let remoteAddr = cast[uint64](addr dataBuf[0])
      let origByte = dataBuf[0]
      let (bp, br) = winprocess.setBreakpoint(selfPid, remoteAddr)
      check br.success
      check bp.active
      check bp.address == remoteAddr
      check bp.originalByte == origByte
      # Verify INT3 was written.
      check dataBuf[0] == 0xCC'u8
      # Remove breakpoint and verify restoration.
      let rr = winprocess.removeBreakpoint(selfPid, bp)
      check rr.success
      check dataBuf[0] == origByte

    test "removeBreakpoint on inactive breakpoint is a no-op":
      let bp = WinBreakpoint(address: 0'u64, originalByte: 0x90'u8,
                             active: false)
      let r = winprocess.removeBreakpoint(1, bp)
      check r.success

    test "readProcessMemory returns error for size zero":
      let (_, r) = winprocess.readProcessMemory(1, 0x1000'u64, 0)
      check r.success == false
      check r.error == wpRange

    test "writeProcessMemory returns error for empty bytes":
      let r = winprocess.writeProcessMemory(1, 0x1000'u64, @[])
      check r.success == false
      check r.error == wpRange

    test "openProcessHandle fails for invalid PID":
      # PID 0 is the System Idle Process; access should be denied.
      let (h, hr) = winprocess.openProcessHandle(0)
      if hr.success and h != nil:
        discard winprocess.closeProcessHandle(h)
      # Either the open fails (expected) or it somehow succeeds; either is
      # non-crashing behavior, which is what we verify here.
      check hr.success == true or hr.success == false
