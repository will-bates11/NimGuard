# NimGuard - Binary Analysis and Static Patching
import strutils, os
import rules, binary, disassembler, assembler, emulator

type
  BinaryAnalysis* = object
    filePath*:        string
    format*:          BinaryFormat
    architecture*:    Architecture
    entryPoint*:      uint64
    sections*:        seq[Section]
    vulnerabilities*: seq[string]
    errorMsg*:        string

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
  result.errorMsg     = info.errorMsg

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
  # Write to a temp file first, then atomically rename over the destination.
  # This prevents a partial write from corrupting the binary if the process
  # is interrupted mid-write.
  let tmpPath = dstPath & ".nimguard_tmp"
  try:
    writeFile(tmpPath, data)
  except:
    discard tryRemoveFile(tmpPath)
    return false
  try:
    moveFile(tmpPath, dstPath)
    return true
  except:
    discard tryRemoveFile(tmpPath)
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
# Assembles each rule's patch instructions with Keystone, locates the CALL
# site in the binary via disassembly, converts the virtual address to a file
# offset, and writes the bytes directly into the output file.
# When outputPath is non-empty the patched copy is written there; otherwise
# the source binary is patched in-place.
proc applyPatches*(binaryPath: string, rules: seq[PatchRule],
                   outputPath: string = ""): bool =
  echo "[+] Applying patches to ", binaryPath
  let info = parseBinary(binaryPath)
  if info.format == bfUnknown:
    if info.errorMsg.len > 0:
      echo "[-] ", info.errorMsg
    else:
      echo "[-] Cannot patch: unknown binary format"
    return false

  # Determine patch target. If an output path is specified, copy the original
  # binary there first so we write into the output, not the source.
  let patchTarget = if outputPath != "": outputPath else: binaryPath
  if outputPath != "" and outputPath != binaryPath:
    let tmpOut = outputPath & ".nimguard_tmp"
    try:
      writeFile(tmpOut, readFile(binaryPath))
      moveFile(tmpOut, outputPath)
      echo "[+] Output path: ", outputPath
    except CatchableError as e:
      discard tryRemoveFile(tmpOut)
      echo "[-] Failed to create output file: ", e.msg
      return false

  # Disassemble .text to find dangerous call sites with their addresses.
  let instructions = disassembleSection(info, ".text")
  let callSites    = findDangerousCallSites(instructions)

  # Also collect names detected via import string scanning as a fallback.
  let importNames = scanImportStrings(info)

  var patchesApplied = false

  for rule in rules:
    var callSiteFound = false

    # Try to patch each CALL instruction that matches this rule.
    for (name, siteVA) in callSites:
      if name != rule.identifier:
        continue
      callSiteFound = true

      let fileOff = virtualToFileOffset(info, siteVA)
      if fileOff < 0:
        echo "[-] No file offset for ", name, " at 0x", toHex(siteVA, 16)
        continue

      if not isKeystoneAvailable():
        echo "[-] Keystone unavailable, cannot assemble patch for: ", rule.identifier
        break

      let assembled = assembleBlock(rule.patch, info.architecture)
      if assembled.bytes.len == 0:
        echo "[-] Assembly failed for rule '", rule.identifier, "': ", rule.patch
        continue

      if patchBinaryAtOffset(patchTarget, patchTarget, fileOff, assembled.bytes):
        echo "[+] Patched '", name, "' at 0x", toHex(siteVA, 16),
             " (file=0x", toHex(fileOff, 8),
             ", ", assembled.bytes.len, " byte(s))"
        patchesApplied = true
      else:
        echo "[-] Write failed for ", name, " at file offset 0x", toHex(fileOff, 8)

    # If no CALL site was found by disassembly, check import string detection.
    if not callSiteFound and rule.identifier in importNames:
      echo "[!] '", rule.identifier,
           "' detected via import strings but no CALL site found in .text",
           " (PLT-only import, no direct patch target)"

  return patchesApplied
