# NimGuard - Runtime Instrumentation & Monitoring
import strutils
import binary, disassembler, runtime

when defined(linux):
  import process

when defined(windows):
  import winprocess

type
  HookType* = enum
    PreExecution, PostExecution, MemoryAccess

  InstrumentationHook* = object
    hookType*:     HookType
    functionName*: string
    address*:      uint64
    callback*:     proc()

var hooks: seq[InstrumentationHook]

# Pairs each live breakpoint record with its associated hook so the monitor
# loop can look up the hook when a breakpoint fires.
var activeBreakpoints: seq[(Breakpoint, InstrumentationHook)]

# Log a detected function call (used as breakpoint callback).
proc monitorFunctionCall(functionName: string) =
  echo "[!] Function called: ", functionName

# Log a detected memory access.
proc monitorMemoryAccess(address: int, size: int) =
  echo "[!] Memory access detected at: ", address, " Size: ", size

# Register a hook entry.
proc registerHook(hook: InstrumentationHook) =
  hooks.add(hook)
  echo "[+] Hook registered for function: ", hook.functionName

# Set up function call hooks for a binary.
#
# When pid >= 0 and runtime instrumentation is available, this procedure
# attaches to the process, locates dangerous call sites via disassembly,
# and injects INT3 software breakpoints at each site. The breakpoints will
# trap execution when those CALL instructions are reached. Call
# runMonitorLoop() after this to service the breakpoints.
#
# When pid < 0 (static analysis mode), the procedure falls back to
# registering log-only closures without touching any live process.
# Output clearly indicates this is a preview of what would be hooked live.
#
# Returns the list of (function name, virtual address) pairs that were
# successfully hooked.
proc setupHooks*(binaryPath: string,
                 pid: int = -1): seq[(string, uint64)] =
  echo "[+] Setting up hooks for: ", binaryPath

  let info = parseBinary(binaryPath)
  if info.format == bfUnknown:
    if info.errorMsg.len > 0:
      echo "[-] ", info.errorMsg
    echo "[-] Cannot set up hooks: unknown binary format"
    return @[]

  # Disassemble .text to find dangerous call sites with virtual addresses.
  let instructions = disassembleSection(info, ".text")
  let callSites    = findDangerousCallSites(instructions)

  # Also include names detected only via import strings (no address).
  let importNames = scanImportStrings(info)

  if pid >= 0 and isRuntimeAvailable():
    # Live mode: inject INT3 breakpoints at each CALL site.
    for (name, siteVA) in callSites:
      let nameCopy = name
      let va       = siteVA
      let (bp, br) = runtime.injectBreakpoint(pid, va)
      if br.success:
        echo "[+] Breakpoint at 0x", toHex(va, 16), " (", name, ")"
        let hook = InstrumentationHook(
          hookType:     PreExecution,
          functionName: nameCopy,
          address:      va,
          callback:     proc() = monitorFunctionCall(nameCopy)
        )
        registerHook(hook)
        activeBreakpoints.add((bp, hook))
        result.add((name, va))
      else:
        echo "[-] Breakpoint failed for ", name, " at 0x", toHex(va, 16),
             ": ", br.msg

    # Report import-string-only names that have no patchable CALL site.
    for iname in importNames:
      var alreadyHooked = false
      for (n, _) in result:
        if n == iname:
          alreadyHooked = true
          break
      if not alreadyHooked:
        echo "[!] '", iname, "' detected in import table (no CALL site in .text)"
  else:
    # Static / log-only mode: register closures but do not touch any process.
    # This shows which functions would be hooked in live mode.
    var seen: seq[string]
    for (name, siteVA) in callSites:
      if name in seen: continue
      seen.add(name)
      let nameCopy = name
      let va       = siteVA
      registerHook(InstrumentationHook(
        hookType:     PreExecution,
        functionName: nameCopy,
        address:      va,
        callback:     proc() = monitorFunctionCall(nameCopy)
      ))
      echo "[+] Would hook: ", name, " at 0x", toHex(siteVA, 16),
           " (static analysis mode, use --attach <pid> for live monitoring)"

    for iname in importNames:
      if iname notin seen:
        echo "[+] Would hook: ", iname,
             " (import, no CALL site found; use --attach <pid> for live monitoring)"

  echo "[+] Runtime instrumentation setup complete."

# Run a debug event loop to service breakpoints set by setupHooks().
#
# On Linux, blocks on waitpid for SIGTRAP events. When a breakpoint fires,
# the matching hook callback is called, the original byte is restored, RIP
# is rewound to the breakpoint address, the process single-steps past the
# original instruction, the breakpoint is re-injected, and execution
# continues. This cycle repeats until maxEvents hooks fire or the process
# exits.
#
# On Windows, uses WaitForDebugEvent. When EXCEPTION_BREAKPOINT fires at a
# known breakpoint address, the same restore/single-step/re-inject cycle
# runs using the Win32 thread context API.
#
# In static analysis mode (no live breakpoints), this procedure returns
# immediately with a diagnostic message.
proc runMonitorLoop*(pid: int, maxEvents: int = 1000) =
  if activeBreakpoints.len == 0:
    echo "[-] No active breakpoints to monitor."
    return
  echo "[+] Starting monitor loop (", activeBreakpoints.len,
       " breakpoint(s), max ", maxEvents, " events). Press Ctrl-C to stop."
  var eventCount = 0

  when defined(linux):
    const SIGTRAP = 5
    while eventCount < maxEvents:
      # Block until the traced process changes state.
      let wr = process.waitForSignal(pid)
      if wr.status == wsExited or wr.status == wsSignaled:
        echo "[+] Process exited."
        break
      if wr.status != wsStopped:
        break
      if wr.signal != SIGTRAP:
        # Not a breakpoint hit; forward the signal and resume.
        discard process.continueExecution(pid)
        continue

      # After INT3, RIP points one byte past the breakpoint instruction.
      let (regs, gr) = process.getRegisters(pid)
      if not gr.success:
        discard process.continueExecution(pid)
        continue
      let hitAddr = regs.rip - 1

      # Find the matching breakpoint record.
      var matchIdx = -1
      for i in 0 ..< activeBreakpoints.len:
        if activeBreakpoints[i][0].address == hitAddr:
          matchIdx = i
          break
      if matchIdx < 0:
        # Not one of our breakpoints; resume normally.
        discard process.continueExecution(pid)
        continue

      let (bp, hook) = activeBreakpoints[matchIdx]
      echo "[!] Hook fired: ", hook.functionName, " at 0x", toHex(hitAddr, 16)
      hook.callback()
      inc eventCount

      # Restore the original instruction byte.
      discard runtime.removeBreakpoint(pid, bp)

      # Rewind RIP so execution resumes at the original instruction.
      var fixedRegs = regs
      fixedRegs.rip = hitAddr
      discard process.setRegisters(pid, fixedRegs)

      # Single-step past the original instruction.
      discard process.singleStep(pid)
      let sr = process.waitForSignal(pid)
      if sr.status == wsExited or sr.status == wsSignaled:
        echo "[+] Process exited during single-step."
        break

      # Re-inject the breakpoint so the next call is also caught.
      let (newBp, ir) = runtime.injectBreakpoint(pid, hitAddr)
      if ir.success:
        activeBreakpoints[matchIdx] = (newBp, hook)

      discard process.continueExecution(pid)

  elif defined(windows):
    while eventCount < maxEvents:
      let (ev, wr) = winprocess.waitForDebugEvent(5000)
      if not wr.success:
        break
      if ev.kind == deExitProcess:
        echo "[+] Process exited."
        break
      if ev.kind == deException:
        let tid = ev.threadId
        let (regs, cr) = winprocess.getThreadContext(tid)
        if cr.success:
          # On Windows, RIP points to the INT3 byte when the exception fires.
          let hitAddr = regs.rip
          var matchIdx = -1
          for i in 0 ..< activeBreakpoints.len:
            if activeBreakpoints[i][0].address == hitAddr:
              matchIdx = i
              break
          if matchIdx >= 0:
            let (bp, hook) = activeBreakpoints[matchIdx]
            echo "[!] Hook fired: ", hook.functionName,
                 " at 0x", toHex(hitAddr, 16)
            hook.callback()
            inc eventCount

            # Restore the original instruction byte.
            discard runtime.removeBreakpoint(pid, bp)

            # Set the processor trap flag to single-step past the instruction.
            var stepRegs = regs
            stepRegs.eflags = stepRegs.eflags or 0x100'u64
            discard winprocess.setThreadContext(tid, stepRegs)
            discard winprocess.continueDebugEvent(ev.processId, tid, true)

            # Wait for the single-step trap, then re-inject.
            let (ev2, _) = winprocess.waitForDebugEvent(5000)
            let (newBp, ir) = runtime.injectBreakpoint(pid, hitAddr)
            if ir.success:
              activeBreakpoints[matchIdx] = (newBp, hook)
            discard winprocess.continueDebugEvent(ev2.processId,
                                                  ev2.threadId, true)
            continue

      discard winprocess.continueDebugEvent(ev.processId, ev.threadId, false)

  else:
    echo "[-] runMonitorLoop: platform not supported."

  echo "[+] Monitor loop finished. ", eventCount, " event(s) logged."
