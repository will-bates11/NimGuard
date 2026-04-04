# NimGuard - Disassembly module backed by Capstone.
# Provides higher-level types and procedures over the raw FFI bindings.
import binary
import bindings/capstone

# Names of functions commonly associated with memory-safety vulnerabilities.
const dangerousFunctionNames* = [
  "strcpy", "strncpy", "gets", "sprintf", "vsprintf",
  "strcat", "strncat", "scanf", "sscanf", "fscanf",
  "memcpy", "memmove", "read", "recv", "recvfrom"
]

type
  Instruction* = object
    address*:  uint64
    mnemonic*: string
    opStr*:    string
    rawBytes*: seq[byte]

# Convert a null-terminated char array to a Nim string.
proc charArrayToString(arr: openArray[char]): string =
  for c in arr:
    if c == '\0': break
    result.add(c)

# Map NimGuard Architecture to Capstone arch/mode constants.
proc archToCapstone(arch: Architecture): (cint, cint) =
  case arch
  of archX86:   (CS_ARCH_X86, CS_MODE_32)
  of archX64:   (CS_ARCH_X86, CS_MODE_64)
  of archARM:   (CS_ARCH_ARM, CS_MODE_ARM)
  of archARM64: (CS_ARCH_ARM64, CS_MODE_ARM)
  else:         (CS_ARCH_X86, CS_MODE_64)

# Check whether the Capstone shared library is available at runtime.
# Returns false if the library cannot be loaded or initialised.
proc isCapstoneAvailable*(): bool =
  var handle: CsHandle
  try:
    let err = cs_open(CS_ARCH_X86, CS_MODE_64, addr handle)
    if err == CS_ERR_OK:
      discard cs_close(addr handle)
      return true
    return false
  except:
    return false

# Disassemble a raw byte slice starting at baseAddr using the given
# architecture. Returns an empty sequence if Capstone is not available
# or if no instructions could be decoded.
proc disassembleBytes*(data: seq[byte], baseAddr: uint64,
                       arch: Architecture): seq[Instruction] =
  if data.len == 0:
    return @[]

  var handle: CsHandle
  let (csArch, csMode) = archToCapstone(arch)

  var openErr: cint
  try:
    openErr = cs_open(csArch, csMode, addr handle)
  except:
    return @[]

  if openErr != CS_ERR_OK:
    return @[]

  defer: discard cs_close(addr handle)

  var insnPtr: ptr CsInsn = nil
  let count = cs_disasm(handle, unsafeAddr data[0], csize_t(data.len),
                        baseAddr, 0, addr insnPtr)

  if count == 0 or insnPtr == nil:
    return @[]

  defer: cs_free(insnPtr, count)

  for i in 0 ..< int(count):
    let raw = cast[ptr UncheckedArray[CsInsn]](insnPtr)
    let insn = raw[i]

    var rawBytes: seq[byte]
    for j in 0 ..< int(insn.size):
      rawBytes.add(insn.bytes[j])

    result.add(Instruction(
      address:  insn.address,
      mnemonic: charArrayToString(insn.mnemonic),
      opStr:    charArrayToString(insn.opStr),
      rawBytes: rawBytes
    ))

# Disassemble a named section from a parsed binary.
# Returns an empty sequence if the section is not found or Capstone is
# unavailable.
proc disassembleSection*(info: BinaryInfo,
                         sectionName: string): seq[Instruction] =
  for s in info.sections:
    if s.name == sectionName:
      let fileOff = int(s.fileOffset)
      let size    = int(s.size)
      if fileOff < 0 or size <= 0 or fileOff + size > info.rawBytes.len:
        return @[]
      let slice = info.rawBytes[fileOff ..< fileOff + size]
      return disassembleBytes(slice, s.virtualAddress, info.architecture)
  return @[]

# Scan a list of instructions for calls to known dangerous functions.
# Looks for CALL instructions whose operand string contains a dangerous
# function name (e.g. "strcpy@plt", "strcpy", etc.).
# Returns the names of dangerous functions referenced.
proc findDangerousCalls*(instructions: seq[Instruction]): seq[string] =
  for insn in instructions:
    if insn.mnemonic == "call":
      for name in dangerousFunctionNames:
        if name in insn.opStr:
          if name notin result:
            result.add(name)

# Scan the raw bytes of a binary for strings matching dangerous function
# names. This catches imports visible in the string table even when
# disassembly cannot resolve call targets symbolically.
# A printable run matches if it equals the function name exactly or if
# it is the name followed by '@' (e.g. "strcpy@plt" in a .dynstr entry).
proc scanImportStrings*(info: BinaryInfo): seq[string] =
  var run = ""

  proc checkRun(run: string, result: var seq[string]) =
    if run.len < 3: return
    for name in dangerousFunctionNames:
      if name in result: continue
      if run == name:
        result.add(name)
      elif run.len > name.len and run[0 ..< name.len] == name and run[name.len] == '@':
        result.add(name)

  for b in info.rawBytes:
    if b >= 0x20'u8 and b <= 0x7e'u8:
      run.add(char(b))
    else:
      checkRun(run, result)
      run = ""
  checkRun(run, result)
