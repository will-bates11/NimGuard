# NimGuard - Binary Format Parsing
# Parses ELF and PE binary headers in pure Nim, no external libraries required.
import os

type
  BinaryFormat* = enum
    bfUnknown = "Unknown"
    bfELF     = "ELF"
    bfPE      = "PE"

  Architecture* = enum
    archUnknown = "Unknown"
    archX86     = "x86"
    archX64     = "x64"
    archARM     = "ARM"
    archARM64   = "ARM64"

  SectionFlags* = object
    readable*:   bool
    writable*:   bool
    executable*: bool

  Section* = object
    name*:           string
    virtualAddress*: uint64
    fileOffset*:     uint64
    size*:           uint64
    flags*:          SectionFlags

  BinaryInfo* = object
    filePath*:     string
    format*:       BinaryFormat
    architecture*: Architecture
    entryPoint*:   uint64
    sections*:     seq[Section]
    rawBytes*:     seq[byte]

# Read a little-endian uint16 from a byte buffer.
proc readU16(data: seq[byte], offset: int): uint16 =
  if offset < 0 or offset + 1 >= data.len: return 0
  uint16(data[offset]) or (uint16(data[offset + 1]) shl 8)

# Read a little-endian uint32 from a byte buffer.
proc readU32(data: seq[byte], offset: int): uint32 =
  if offset < 0 or offset + 3 >= data.len: return 0
  uint32(data[offset]) or
  (uint32(data[offset + 1]) shl 8) or
  (uint32(data[offset + 2]) shl 16) or
  (uint32(data[offset + 3]) shl 24)

# Read a little-endian uint64 from a byte buffer.
proc readU64(data: seq[byte], offset: int): uint64 =
  if offset < 0 or offset + 7 >= data.len: return 0
  uint64(data[offset]) or
  (uint64(data[offset + 1]) shl 8) or
  (uint64(data[offset + 2]) shl 16) or
  (uint64(data[offset + 3]) shl 24) or
  (uint64(data[offset + 4]) shl 32) or
  (uint64(data[offset + 5]) shl 40) or
  (uint64(data[offset + 6]) shl 48) or
  (uint64(data[offset + 7]) shl 56)

# Read a null-terminated string from a byte buffer starting at offset.
proc readCStr(data: seq[byte], offset: int): string =
  if offset < 0 or offset >= data.len: return ""
  var i = offset
  while i < data.len and data[i] != 0:
    result.add(char(data[i]))
    inc i

proc machineToArch(machine: uint16): Architecture =
  case machine
  of 3:   archX86    # EM_386
  of 40:  archARM    # EM_ARM
  of 62:  archX64    # EM_X86_64
  of 183: archARM64  # EM_AARCH64
  else:   archUnknown

# Parse an ELF binary (ELF32 or ELF64, little-endian).
proc parseELF(data: seq[byte]): BinaryInfo =
  result.format = bfELF
  result.architecture = archUnknown

  if data.len < 20:
    return

  let machine = readU16(data, 18)
  result.architecture = machineToArch(machine)

  let elfClass = data[4]  # 1 = 32-bit, 2 = 64-bit

  if elfClass == 2:
    # ELF64: header is 64 bytes
    if data.len < 64: return
    result.entryPoint = readU64(data, 24)
    let shoff     = int(readU64(data, 40))
    let shentsize = int(readU16(data, 58))
    let shnum     = int(readU16(data, 60))
    let shstrndx  = int(readU16(data, 62))

    if shoff > 0 and shnum > 0 and shentsize >= 64:
      # Locate the section name string table
      var strtabOffset = 0
      if shstrndx < shnum and shstrndx > 0:
        let strSecBase = shoff + shstrndx * shentsize
        if strSecBase + 31 < data.len:
          strtabOffset = int(readU64(data, strSecBase + 24))

      for i in 0 ..< shnum:
        let base = shoff + i * shentsize
        if base + 63 >= data.len: break

        let nameIdx = int(readU32(data, base))
        let shflags = readU64(data, base + 8)
        let vaddr   = readU64(data, base + 16)
        let foffset = readU64(data, base + 24)
        let size    = readU64(data, base + 32)

        let name = if strtabOffset > 0: readCStr(data, strtabOffset + nameIdx) else: ""

        result.sections.add(Section(
          name:           name,
          virtualAddress: vaddr,
          fileOffset:     foffset,
          size:           size,
          flags: SectionFlags(
            readable:   (shflags and 0x2) != 0,  # SHF_ALLOC
            writable:   (shflags and 0x1) != 0,  # SHF_WRITE
            executable: (shflags and 0x4) != 0   # SHF_EXECINSTR
          )
        ))

  elif elfClass == 1:
    # ELF32: header is 52 bytes
    if data.len < 52: return
    result.entryPoint = uint64(readU32(data, 24))
    let shoff     = int(readU32(data, 32))
    let shentsize = int(readU16(data, 46))
    let shnum     = int(readU16(data, 48))
    let shstrndx  = int(readU16(data, 50))

    if shoff > 0 and shnum > 0 and shentsize >= 40:
      var strtabOffset = 0
      if shstrndx < shnum and shstrndx > 0:
        let strSecBase = shoff + shstrndx * shentsize
        if strSecBase + 19 < data.len:
          strtabOffset = int(readU32(data, strSecBase + 16))

      for i in 0 ..< shnum:
        let base = shoff + i * shentsize
        if base + 39 >= data.len: break

        let nameIdx = int(readU32(data, base))
        let shflags = uint64(readU32(data, base + 8))
        let vaddr   = uint64(readU32(data, base + 12))
        let foffset = uint64(readU32(data, base + 16))
        let size    = uint64(readU32(data, base + 20))

        let name = if strtabOffset > 0: readCStr(data, strtabOffset + nameIdx) else: ""

        result.sections.add(Section(
          name:           name,
          virtualAddress: vaddr,
          fileOffset:     foffset,
          size:           size,
          flags: SectionFlags(
            readable:   (shflags and 0x2) != 0,
            writable:   (shflags and 0x1) != 0,
            executable: (shflags and 0x4) != 0
          )
        ))

# Parse a PE binary (PE32 or PE32+, little-endian).
proc parsePE(data: seq[byte]): BinaryInfo =
  result.format = bfPE
  result.architecture = archUnknown

  if data.len < 64: return

  # e_lfanew at offset 0x3C points to the PE signature
  let peOffset = int(readU32(data, 0x3C))
  if peOffset < 0 or peOffset + 3 >= data.len: return

  # Verify PE\x00\x00 signature
  if data[peOffset]     != 0x50 or data[peOffset + 1] != 0x45 or
     data[peOffset + 2] != 0x00 or data[peOffset + 3] != 0x00:
    return

  # COFF header starts at peOffset + 4
  let coffBase = peOffset + 4
  if coffBase + 19 >= data.len: return

  let machine       = readU16(data, coffBase)
  let numSections   = int(readU16(data, coffBase + 2))
  let optHeaderSize = int(readU16(data, coffBase + 16))

  result.architecture = case machine
    of 0x014c: archX86
    of 0x8664: archX64
    of 0x01c4: archARM
    of 0xAA64: archARM64
    else: archUnknown

  # Optional header starts at coffBase + 20
  let optBase = coffBase + 20
  if optBase + 1 >= data.len: return

  let optMagic = readU16(data, optBase)

  # AddressOfEntryPoint is at optBase + 16 for both PE32 and PE32+
  if optMagic == 0x010b or optMagic == 0x020b:
    result.entryPoint = uint64(readU32(data, optBase + 16))

  # Section table follows the optional header
  let sectionBase = optBase + optHeaderSize
  for i in 0 ..< numSections:
    let base = sectionBase + i * 40
    if base + 39 >= data.len: break

    var name: string
    for j in 0 ..< 8:
      let b = data[base + j]
      if b == 0: break
      name.add(char(b))

    let virtualAddr   = uint64(readU32(data, base + 12))
    let rawDataSize   = readU32(data, base + 16)
    let rawDataOffset = uint64(readU32(data, base + 20))
    let characteristics = readU32(data, base + 36)

    result.sections.add(Section(
      name:           name,
      virtualAddress: virtualAddr,
      fileOffset:     rawDataOffset,
      size:           uint64(rawDataSize),
      flags: SectionFlags(
        readable:   (characteristics and 0x40000000'u32) != 0,
        writable:   (characteristics and 0x80000000'u32) != 0,
        executable: (characteristics and 0x20000000'u32) != 0
      )
    ))

# Read a file into a byte sequence.
proc readFileBytes(filePath: string): seq[byte] =
  var f: File
  if not open(f, filePath, fmRead):
    return @[]
  defer: close(f)
  let size = getFileSize(f)
  if size <= 0: return @[]
  result = newSeq[byte](int(size))
  discard readBytes(f, result, 0, int(size))

# Parse a binary file and return structured metadata.
# Returns BinaryInfo with format=bfUnknown on any error.
proc parseBinary*(filePath: string): BinaryInfo =
  result.filePath     = filePath
  result.format       = bfUnknown
  result.architecture = archUnknown

  if not fileExists(filePath):
    echo "[-] Error: File not found: ", filePath
    return

  let data = readFileBytes(filePath)
  if data.len == 0:
    echo "[-] Error: File is empty or unreadable: ", filePath
    return

  result.rawBytes = data

  if data.len >= 4 and
     data[0] == 0x7f and data[1] == byte('E') and
     data[2] == byte('L') and data[3] == byte('F'):
    result = parseELF(data)
    result.filePath = filePath
    result.rawBytes = data

  elif data.len >= 2 and data[0] == byte('M') and data[1] == byte('Z'):
    result = parsePE(data)
    result.filePath = filePath
    result.rawBytes = data

  else:
    echo "[-] Unknown binary format: ", filePath
