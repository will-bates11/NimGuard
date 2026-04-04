# NimGuard - Dynamic Binary Patching and Instrumentation Tool
import parseopt, strutils, patcher, instrumentation, rules, binary, disassembler

proc showHelp() =
  echo """
  NimGuard - Dynamic Binary Patching and Instrumentation Tool
  Usage:
    nimguard <binary> [options]

  Options:
    --analyze           Perform binary analysis and report dangerous function calls
    --disasm            Show full disassembly of the .text section
    --patch             Apply patches based on predefined rules
    --output <file>     Write the patched binary to this path (used with --patch)
    --monitor           Enable runtime instrumentation and logging
    --rules <file>      Load custom patching rules from a file
    --help              Show this help message

  Example:
    ./nimguard target_binary --analyze
    ./nimguard target_binary --disasm
    ./nimguard target_binary --patch --rules custom_rules.json
    ./nimguard target_binary --patch --output patched_binary
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

proc main() =
  var p = initOptParser()
  var binaryPath: string
  var analyze, patch, monitor, disasm: bool
  var ruleFile: string
  var outputPath: string

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
      of "rules":
        ruleFile = p.val
      of "output":
        outputPath = p.val
      else:
        echo "Unknown option: --", p.key
        showHelp()
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

  if monitor:
    echo "[+] Enabling runtime monitoring..."
    setupHooks(binaryPath)
    echo "[+] Monitoring started."

when isMainModule:
  main()
