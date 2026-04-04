# NimGuard - Binary Analysis and Dynamic Patching
import rules, binary, disassembler

type
  BinaryAnalysis* = object
    filePath*:        string
    format*:          BinaryFormat
    architecture*:    Architecture
    entryPoint*:      uint64
    sections*:        seq[Section]
    vulnerabilities*: seq[string]

# Analyze a binary file and return structured metadata plus detected
# vulnerability sites. Uses Capstone disassembly (when available) to
# find calls to dangerous functions, and also scans the binary string
# table for imported dangerous symbol names.
proc analyzeBinary*(filePath: string): BinaryAnalysis =
  let info = parseBinary(filePath)
  result.filePath     = filePath
  result.format       = info.format
  result.architecture = info.architecture
  result.entryPoint   = info.entryPoint
  result.sections     = info.sections

  if info.format == bfUnknown or info.rawBytes.len == 0:
    result.vulnerabilities = @[]
    return

  # Disassemble the executable section and look for dangerous calls.
  let textSectionName = ".text"
  let instructions = disassembleSection(info, textSectionName)
  var found = findDangerousCalls(instructions)

  # Also scan the binary's string data for imported dangerous symbol names.
  # This catches PLT imports that are not symbolically resolved during
  # disassembly.
  for name in scanImportStrings(info):
    if name notin found:
      found.add(name)

  result.vulnerabilities = found

# Simulated patch application (to be replaced with Keystone in Phase 3).
proc applyPatch*(binaryPath: string, functionName: string, patch: string): bool =
  echo "[+] Applying patch to function: ", functionName
  echo "    - New instructions: ", patch
  # TODO Phase 3: use Keystone to assemble instructions and write to binary
  return true

# Apply patches based on detected vulnerabilities and defined rules.
proc applyPatches*(binaryPath: string, rules: seq[PatchRule]): bool =
  echo "[+] Applying patches to ", binaryPath
  let analysis = analyzeBinary(binaryPath)

  var patchesApplied = false
  for vuln in analysis.vulnerabilities:
    for rule in rules:
      if vuln == rule.identifier:
        if applyPatch(binaryPath, rule.identifier, rule.patch):
          echo "[+] Patch applied for ", vuln
          patchesApplied = true
        else:
          echo "[-] Failed to patch ", vuln

  return patchesApplied
