# NimGuard - Unit tests for the instrumentation module.
#
# These tests cover static analysis mode (no live process) and graceful
# handling of invalid inputs. Live breakpoint injection is not tested here
# because it requires a running process attached via ptrace or Win32 debug API.
import unittest, os, instrumentation

suite "Instrumentation Static Analysis":

  test "setupHooks on non-existent binary returns empty list":
    let result = setupHooks("no_such_binary_xyz.elf")
    check result.len == 0

  test "setupHooks with non-binary file in static mode returns empty list":
    let tmpFile = "test_instr_invalid.bin"
    writeFile(tmpFile, "not a valid binary")
    defer: removeFile(tmpFile)
    let result = setupHooks(tmpFile, -1)
    check result.len == 0

  test "setupHooks with pid=-1 does not crash on missing binary":
    let result = setupHooks("no_such_file_instrumentation_test.elf", -1)
    check result.len == 0

suite "Monitor Loop Guard":

  test "runMonitorLoop with no active breakpoints returns immediately":
    # With no breakpoints registered, runMonitorLoop should print a diagnostic
    # and return without crashing, regardless of the pid.
    runMonitorLoop(-1, 0)
