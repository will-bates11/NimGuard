# NimGuard - Dynamic Binary Patching and Instrumentation Tool
import parseopt, strutils, patcher, instrumentation, rules, binary

proc showHelp() =
  echo """
  NimGuard - Dynamic Binary Patching and Instrumentation Tool
  Usage:
    nimguard <binary> [options]

  Options:
    --analyze           Perform binary analysis
    --patch             Apply patches based on predefined rules
    --monitor           Enable runtime instrumentation and logging
    --rules <file>      Load custom patching rules from a file
    --help              Show this help message

  Example:
    ./nimguard target_binary.exe --analyze
    ./nimguard target_binary.exe --patch --rules custom_rules.json
  """

proc formatFlags(flags: SectionFlags): string =
  result = ""
  result.add(if flags.readable   then "r" else "-")
  result.add(if flags.writable   then "w" else "-")
  result.add(if flags.executable then "x" else "-")

proc printAnalysis(analysis: BinaryAnalysis) =
  echo "[+] Format:      ", $analysis.format
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
  echo "[+] Potential issues: ", analysis.vulnerabilities.len

proc main() =
  var p = initOptParser()
  var binaryPath: string
  var analyze, patch, monitor: bool
  var ruleFile: string

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
      of "patch":
        patch = true
      of "monitor":
        monitor = true
      of "rules":
        ruleFile = p.val
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

  var loadedRules: seq[PatchRule]
  if ruleFile != "":
    echo "[+] Loading rules from: ", ruleFile
    loadedRules = loadRules(ruleFile)
  else:
    loadedRules = loadDefaultRules()

  if patch:
    echo "[+] Applying patches..."
    if applyPatches(binaryPath, loadedRules):
      echo "[+] Patching completed successfully."
    else:
      echo "[-] No patches applied."

  if monitor:
    echo "[+] Enabling runtime monitoring..."
    setupHooks(binaryPath)
    echo "[+] Monitoring started."

when isMainModule:
  main()
