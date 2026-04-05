# NimGuard - Runtime Instrumentation & Monitoring
import strutils
import binary, disassembler, runtime

type
  HookType* = enum
    PreExecution, PostExecution, MemoryAccess

  InstrumentationHook* = object
    hookType*:     HookType
    functionName*: string
    address*:      uint64
    callback*:     proc()

var hooks: seq[InstrumentationHook]

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
# trap execution when those CALL instructions are reached.
#
# When pid < 0 (static analysis mode), the procedure falls back to
# registering log-only closures without touching any live process.
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
      let (_, br) = runtime.injectBreakpoint(pid, va)
      if br.success:
        echo "[+] Breakpoint at 0x", toHex(va, 16), " (", name, ")"
        registerHook(InstrumentationHook(
          hookType:     PreExecution,
          functionName: nameCopy,
          address:      va,
          callback:     proc() = monitorFunctionCall(nameCopy)
        ))
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
      echo "[+] Would hook: ", name, " at 0x", toHex(siteVA, 16)

    for iname in importNames:
      if iname notin seen:
        echo "[+] Would hook: ", iname, " (import, no CALL site found)"

  echo "[+] Runtime instrumentation setup complete."
