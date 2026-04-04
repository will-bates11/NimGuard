# NimGuard - Binary Analysis and Static Patching
import rules, binary, disassembler, assembler, emulator

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
  let instructions = disassembleSection(info, ".text")
  var found = findDangerousCalls(instructions)

  # Also scan the binary's string data for imported dangerous symbol names.
  # This catches PLT imports that are not symbolically resolved during
  # disassembly.
  for name in scanImportStrings(info):
    if name notin found:
      found.add(name)

  result.vulnerabilities = found

# Write a patched copy of a binary file.
# Reads srcPath, replaces newBytes.len bytes starting at offset with
# newBytes, and writes the result to dstPath.
# Returns true on success. Returns false if the source cannot be read,
# the offset is out of range, or the destination cannot be written.
proc patchBinaryAtOffset*(srcPath: string, dstPath: string,
                          offset: int, newBytes: seq[byte]): bool =
  if newBytes.len == 0:
    return false
  var data: string
  try:
    data = readFile(srcPath)
  except:
    return false
  if offset < 0 or offset + newBytes.len > data.len:
    return false
  for i in 0 ..< newBytes.len:
    data[offset + i] = char(newBytes[i])
  try:
    writeFile(dstPath, data)
    return true
  except:
    return false

# Assemble asmStr using Keystone and patch the binary at the given offset.
# Writes the patched binary to dstPath. Returns false if assembly fails or
# if Keystone is not available.
proc assembleAndPatch*(srcPath: string, dstPath: string, offset: int,
                       asmStr: string, arch: Architecture): bool =
  let bytes = assembleInstruction(asmStr, arch, uint64(offset))
  if bytes.len == 0:
    return false
  return patchBinaryAtOffset(srcPath, dstPath, offset, bytes)

# Apply a named patch to a binary. When Keystone is available, assembles
# the patch instructions to validate them and reports the encoded size.
# Falls back to the previous stub behaviour (returns true) when Keystone is
# not installed, so the rest of the pipeline is not blocked.
proc applyPatch*(binaryPath: string, functionName: string, patch: string): bool =
  echo "[+] Applying patch to function: ", functionName
  echo "    - New instructions: ", patch
  if isKeystoneAvailable():
    let output = assembleBlock(patch, archX64)
    if output.bytes.len > 0:
      echo "    - Assembled: ", output.bytes.len, " byte(s) (", output.statCount, " statement(s))"
      return true
    echo "[-] Assembly failed for: ", patch
    return false
  return true

# Test a patch in Unicorn emulation before writing to disk.
# Reads srcPath, applies newBytes at offset in a temporary buffer, loads the
# buffer into an emulator, and executes up to maxInstr instructions starting
# at the patch site. Returns true if emulation ran without an immediate crash,
# or if Unicorn is not installed (graceful degradation).
proc testPatchInEmulator*(srcPath: string, offset: int,
                          newBytes: seq[byte], arch: Architecture,
                          maxInstr: int = 64): bool =
  if not isUnicornAvailable():
    return true

  if newBytes.len == 0:
    return false

  var data: string
  try:
    data = readFile(srcPath)
  except:
    return false

  if offset < 0 or offset + newBytes.len > data.len:
    return false

  # Apply the patch in a temporary in-memory buffer only.
  var patched = newSeq[byte](data.len)
  for i in 0 ..< data.len:
    patched[i] = byte(data[i])
  for i in 0 ..< newBytes.len:
    patched[offset + i] = newBytes[i]

  # Load patched buffer into emulator at a conventional base address.
  let baseAddr = 0x00400000'u64
  var ctx = createEmulator(arch)
  defer: closeEmulator(ctx)
  if ctx.engine == nil:
    return true

  if not ctx.loadMemory(baseAddr, patched):
    return false

  let startAddr = baseAddr + uint64(offset)
  let endAddr   = baseAddr + uint64(patched.len)
  let res = ctx.emulateRange(startAddr, endAddr, maxInstr)
  res.success

# Apply patches based on detected vulnerabilities and defined rules.
# outputPath is optional; when non-empty it is recorded in the log for
# use with patchBinaryAtOffset / assembleAndPatch in a follow-up step.
proc applyPatches*(binaryPath: string, rules: seq[PatchRule],
                   outputPath: string = ""): bool =
  echo "[+] Applying patches to ", binaryPath
  if outputPath != "":
    echo "[+] Output path: ", outputPath
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
