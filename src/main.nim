# NimGuard - Dynamic Binary Patching and Instrumentation Tool
import parseopt, strutils, patcher, instrumentation, rules, binary, disassembler,
       emulator, runtime

proc showHelp() =
  echo """
  NimGuard - Dynamic Binary Patching and Instrumentation Tool
  Usage:
    nimguard <binary> [options]
    nimguard --attach <pid> [options]

  Static analysis options (require <binary>):
    --analyze           Perform binary analysis and report dangerous function calls
    --disasm            Show full disassembly of the .text section
    --patch             Apply patches based on predefined rules
    --output <file>     Write the patched binary to this path (used with --patch)
    --monitor           Enable runtime instrumentation and logging
    --rules <file>      Load custom patching rules from a file
    --emulate           Run the .text section through the CPU emulator
    --test-patch        Test a NOP patch at offset 0 in the emulator before applying

  Runtime instrumentation options (require --attach, Linux and Windows):
    --attach <pid>      Attach to a running process by PID
    --inject <addr>:<hex>  Write hex bytes into process memory at hex address
    --breakpoint <addr> Set a software breakpoint at hex address
    --trace             Trace syscalls until the process exits

    --help              Show this help message

  Examples:
    ./nimguard target_binary --analyze
    ./nimguard target_binary --disasm
    ./nimguard target_binary --patch --rules custom_rules.json
    ./nimguard target_binary --patch --output patched_binary
    ./nimguard target_binary --emulate
    ./nimguard target_binary --test-patch
    ./nimguard --attach 1234 --breakpoint 0x401000
    ./nimguard --attach 1234 --inject 0x401000:9090
    ./nimguard --attach 1234 --trace
  """

proc formatFlags(flags: SectionFlags): string =
  result = ""
  result.add(if flags.readable:   "r" else: "-")
  result.add(if flags.writable:   "w" else: "-")
  result.add(if flags.executable: "x" else: "-")

proc printAnalysis(analysis: BinaryAnalysis) =
  echo "[+] Format:       ", $analysis.format
  echo "[+] Architecture: ", $analysis.architecture
  echo "[+] Entry point:  0x", toHex(analysis.entryPoint, 16)
  if analysis.sections.len == 0:
    echo "[+] Sections:     (none)"
  else:
    echo "[+] Sections (", analysis.sections.len, "):"
    for s in analysis.sections:
      let name = if s.name == "": "(unnamed)" else: s.name
      echo "    ", name.alignLeft(12), " vaddr=0x", toHex(s.virtualAddress, 16),
           " offset=0x", toHex(s.fileOffset, 8),
           " size=0x", toHex(s.size, 8),
           " [", formatFlags(s.flags), "]"
  if analysis.vulnerabilities.len == 0:
    echo "[+] Dangerous calls: (none detected)"
  else:
    echo "[+] Dangerous calls (", analysis.vulnerabilities.len, "):"
    for name in analysis.vulnerabilities:
      echo "    [!] ", name

proc printEmulation(binaryPath: string) =
  let info = parseBinary(binaryPath)
  if info.format == bfUnknown:
    echo "[-] Cannot emulate: unknown binary format"
    return

  if not isUnicornAvailable():
    echo "[-] Unicorn library not available. Install libunicorn-dev to enable emulation."
    return

  echo "[+] Emulating .text section of ", binaryPath
  var ctx = createEmulator(info.architecture)
  defer: closeEmulator(ctx)
  if ctx.engine == nil:
    echo "[-] Failed to create emulator context"
    return

  if not ctx.loadBinary(info, ".text"):
    echo "[-] Failed to load .text section into emulator"
    return

  var textAddr = 0'u64
  var textSize = 0
  for s in info.sections:
    if s.name == ".text":
      textAddr = s.virtualAddress
      textSize = int(s.size)
      break

  if textAddr == 0:
    echo "[-] .text section not found"
    return

  echo "[+] Emulating up to 256 instructions at 0x", toHex(textAddr, 16)
  let res = ctx.emulateRange(textAddr, textAddr + uint64(textSize), 256)
  if res.success:
    echo "[+] Emulation completed successfully"
  else:
    echo "[-] Emulation stopped: ", res.errorMsg

proc printDisassembly(binaryPath: string) =
  let info = parseBinary(binaryPath)
  if info.format == bfUnknown:
    echo "[-] Cannot disassemble: unknown binary format"
    return

  if not isCapstoneAvailable():
    echo "[-] Capstone library not available. Install libcapstone-dev to enable disassembly."
    return

  echo "[+] Disassembly of .text section:"
  let instructions = disassembleSection(info, ".text")
  if instructions.len == 0:
    echo "    (no instructions decoded, or .text section not found)"
    return

  for insn in instructions:
    echo "    0x", toHex(insn.address, 16), "  ",
         insn.mnemonic.alignLeft(10), " ", insn.opStr

# Parse a hex string (with or without 0x prefix) to uint64.
proc parseHexAddr(s: string): uint64 =
  let trimmed = if s.len > 2 and s[0..1] == "0x": s[2..^1] else: s
  try:
    result = parseHexInt(trimmed).uint64
  except:
    result = 0

# Parse a hex byte string (e.g. "9090CC") into a seq[byte].
proc parseHexBytes(s: string): seq[byte] =
  var i = 0
  while i + 1 < s.len:
    try:
      result.add(byte(parseHexInt(s[i..i+1])))
    except:
      return @[]
    i += 2

proc runAttachMode(pid: int, injectSpec: string, bpAddrStr: string,
                   trace: bool) =
  if not isRuntimeAvailable():
    echo "[-] Live process instrumentation is not available on this platform."
    return

  echo "[+] Attaching to PID ", pid, "..."
  let ar = runtime.attachProcess(pid)
  if not ar.success:
    echo "[-] Attach failed: ", ar.msg
    return
  echo "[+] Attached."

  if bpAddrStr != "":
    let bpAddr = parseHexAddr(bpAddrStr)
    echo "[+] Setting breakpoint at 0x", toHex(bpAddr, 16)
    let (bp, br) = runtime.injectBreakpoint(pid, bpAddr)
    if br.success:
      echo "[+] Breakpoint set (original byte: 0x", toHex(int(bp.originalByte), 2), ")"
    else:
      echo "[-] Breakpoint failed: ", br.msg

  if injectSpec != "":
    let colonPos = injectSpec.find(':')
    if colonPos < 0:
      echo "[-] --inject requires <hex_addr>:<hex_bytes> format"
    else:
      let addrStr  = injectSpec[0 ..< colonPos]
      let bytesStr = injectSpec[colonPos + 1 .. ^1]
      let injectAddr  = parseHexAddr(addrStr)
      let injectBytes = parseHexBytes(bytesStr)
      if injectBytes.len == 0:
        echo "[-] No valid bytes parsed from: ", bytesStr
      else:
        echo "[+] Injecting ", injectBytes.len, " byte(s) at 0x",
             toHex(injectAddr, 16)
        let wr = runtime.patchProcessMemory(pid, injectAddr, injectBytes)
        if wr.success:
          echo "[+] Memory patched."
        else:
          echo "[-] Patch failed: ", wr.msg

  if trace:
    echo "[+] Tracing syscalls (up to 64 events)..."
    let events = runtime.monitorSyscalls(pid, 64)
    if events.len == 0:
      echo "    (no syscall events captured)"
    else:
      for ev in events:
        echo "    syscall ", ev.syscallNr, "  args=[",
             toHex(ev.args[0], 16), ", ", toHex(ev.args[1], 16), ", ...]"

  let dr = runtime.detachProcess(pid)
  if dr.success:
    echo "[+] Detached from PID ", pid
  else:
    echo "[-] Detach failed: ", dr.msg

proc main() =
  var p = initOptParser()
  var binaryPath: string
  var analyze, patch, monitor, disasm, emulate, testPatch, trace: bool
  var ruleFile, outputPath: string
  var attachPid: int = -1
  var injectSpec: string
  var bpAddrStr: string

  while true:
    p.next()
    case p.kind
    of cmdEnd:
      break
    of cmdArgument:
      if binaryPath == "":
        binaryPath = p.key
    of cmdLongOption, cmdShortOption:
      case p.key
      of "help":
        showHelp()
        return
      of "analyze":
        analyze = true
      of "disasm":
        disasm = true
      of "patch":
        patch = true
      of "monitor":
        monitor = true
      of "emulate":
        emulate = true
      of "test-patch":
        testPatch = true
      of "trace":
        trace = true
      of "rules":
        ruleFile = p.val
      of "output":
        outputPath = p.val
      of "attach":
        try:
          attachPid = parseInt(p.val)
        except:
          echo "Error: --attach requires an integer PID."
          return
      of "inject":
        injectSpec = p.val
      of "breakpoint":
        bpAddrStr = p.val
      else:
        echo "Unknown option: --", p.key
        showHelp()
        return

  # Runtime attach mode: no binary path needed.
  if attachPid >= 0:
    runAttachMode(attachPid, injectSpec, bpAddrStr, trace)
    return

  if binaryPath == "":
    echo "Error: No binary specified."
    showHelp()
    return

  echo "[+] Processing binary: ", binaryPath

  if analyze:
    echo "[+] Running analysis on ", binaryPath
    let analysis = analyzeBinary(binaryPath)
    printAnalysis(analysis)

  if disasm:
    printDisassembly(binaryPath)

  var loadedRules: seq[PatchRule]
  if ruleFile != "":
    echo "[+] Loading rules from: ", ruleFile
    loadedRules = loadRules(ruleFile)
  else:
    loadedRules = loadDefaultRules()

  if patch:
    echo "[+] Applying patches..."
    if applyPatches(binaryPath, loadedRules, outputPath):
      echo "[+] Patching completed successfully."
    else:
      echo "[-] No patches applied."

  if emulate:
    printEmulation(binaryPath)

  if testPatch:
    echo "[+] Testing patch in emulator..."
    let info = parseBinary(binaryPath)
    if info.format != bfUnknown and info.rawBytes.len > 0:
      let nop = @[0x90'u8]
      let ok = testPatchInEmulator(binaryPath, 0, nop, info.architecture)
      if ok:
        echo "[+] Patch test in emulator: passed"
      else:
        echo "[-] Patch test in emulator: failed"
    else:
      echo "[-] Cannot test patch: unrecognised binary format"

  if monitor:
    echo "[+] Enabling runtime monitoring..."
    setupHooks(binaryPath)
    echo "[+] Monitoring started."

when isMainModule:
  main()
