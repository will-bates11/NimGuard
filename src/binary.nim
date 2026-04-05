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
    errorMsg*:     string

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
            readable:   (shflags and 0x2) != 0,  # SHF_ALLOC (allocatable, implies readable for loaded sections)
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
            readable:   (shflags and 0x2) != 0,  # SHF_ALLOC (allocatable, implies readable for loaded sections)
            writable:   (shflags and 0x1) != 0,  # SHF_WRITE
            executable: (shflags and 0x4) != 0   # SHF_EXECINSTR
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

# Convert a virtual address (or PE RVA) to a file offset using the section
# table. Returns -1 when no section contains the address.
proc virtualToFileOffset*(info: BinaryInfo, vaddr: uint64): int =
  for s in info.sections:
    if vaddr >= s.virtualAddress and vaddr < s.virtualAddress + s.size:
      return int(s.fileOffset + (vaddr - s.virtualAddress))
  return -1

# Find the index of a section by name. Returns -1 when not found.
proc findSectionIdx*(info: BinaryInfo, name: string): int =
  for i in 0 ..< info.sections.len:
    if info.sections[i].name == name:
      return i
  return -1

type
  ImportEntry* = object
    name*:           string  # Imported symbol name
    moduleName*:     string  # DLL/SO name (PE: DLL name, ELF: "")
    virtualAddress*: uint64  # VA of PLT stub (ELF) or IAT entry RVA (PE)
    fileOffset*:     uint64  # File offset of the PLT stub or IAT entry

# Parse ELF .dynsym + .dynstr + .rela.plt to enumerate PLT stubs.
# ELF64 only; returns empty seq for other formats or missing sections.
proc parseELFImports(info: BinaryInfo): seq[ImportEntry] =
  let data = info.rawBytes
  let is64 = info.architecture in [archX64, archARM64]

  let dynsymIdx  = info.findSectionIdx(".dynsym")
  let dynstrIdx  = info.findSectionIdx(".dynstr")
  let pltIdx     = info.findSectionIdx(".plt")
  # Try .rela.plt (ELF64) then .rel.plt (ELF32)
  var relapltIdx = info.findSectionIdx(".rela.plt")
  let useRela    = relapltIdx >= 0
  if not useRela:
    relapltIdx = info.findSectionIdx(".rel.plt")

  if dynsymIdx < 0 or dynstrIdx < 0 or relapltIdx < 0 or pltIdx < 0:
    return @[]

  let dynsym  = info.sections[dynsymIdx]
  let dynstr  = info.sections[dynstrIdx]
  let relaplt = info.sections[relapltIdx]
  let plt     = info.sections[pltIdx]

  # Symbol entry sizes: ELF64 = 24, ELF32 = 16
  let symEntSize = if is64: 24 else: 16
  let dynsymCount = if symEntSize > 0: int(dynsym.size) div symEntSize else: 0

  # Build symbol-index -> name table.
  var symNames = newSeq[string](dynsymCount)
  for i in 0 ..< dynsymCount:
    let base = int(dynsym.fileOffset) + i * symEntSize
    if base + 3 >= data.len: break
    let nameIdx = int(readU32(data, base))
    let strOff  = int(dynstr.fileOffset) + nameIdx
    if strOff < data.len:
      symNames[i] = readCStr(data, strOff)

  # Relocation entry sizes: rela = 24 (ELF64) / 12 (ELF32), rel = 8 (ELF32)
  let relaEntSize = if useRela: (if is64: 24 else: 12) else: 8
  let relaCount   = if relaEntSize > 0: int(relaplt.size) div relaEntSize else: 0

  # PLT entry and header sizes depend on the target architecture.
  # x86/x64 and AArch64 use 16-byte entries; ARM32 uses 12-byte entries with a 20-byte header.
  let pltEntrySize: uint64 = case info.architecture
    of archARM: 12
    else: 16  # x86, x64, aarch64
  let pltHeaderSize: uint64 = case info.architecture
    of archARM: 20  # ARM32 PLT header is 20 bytes
    else: 16

  for i in 0 ..< relaCount:
    let base = int(relaplt.fileOffset) + i * relaEntSize
    if base + relaEntSize - 1 >= data.len: break

    var symIdx: int
    if useRela and is64:
      let rInfo = readU64(data, base + 8)
      symIdx = int(rInfo shr 32)
    elif useRela and not is64:
      let rInfo = readU32(data, base + 4)
      symIdx = int(rInfo shr 8)
    else:
      # .rel.plt (ELF32)
      let rInfo = readU32(data, base + 4)
      symIdx = int(rInfo shr 8)

    if symIdx < 0 or symIdx >= symNames.len: continue
    let symName = symNames[symIdx]
    if symName.len == 0: continue

    let pltEntryVA = plt.virtualAddress + pltHeaderSize + uint64(i) * pltEntrySize
    let pltEntryFO = plt.fileOffset    + pltHeaderSize + uint64(i) * pltEntrySize

    result.add(ImportEntry(
      name:           symName,
      moduleName:     "",
      virtualAddress: pltEntryVA,
      fileOffset:     pltEntryFO
    ))

# Parse PE import directory (IMAGE_IMPORT_DESCRIPTOR chain).
# Works for both PE32 and PE32+.
proc parsePEImports(info: BinaryInfo): seq[ImportEntry] =
  let data = info.rawBytes
  if data.len < 64: return @[]

  let peOffset = int(readU32(data, 0x3C))
  if peOffset < 0 or peOffset + 3 >= data.len: return @[]

  let coffBase = peOffset + 4
  if coffBase + 19 >= data.len: return @[]

  let optBase  = coffBase + 20
  if optBase + 1 >= data.len: return @[]

  let optMagic = readU16(data, optBase)
  # DataDirectory[1] (Import Table) RVA offset in the optional header:
  #   PE32  (0x010b): optBase + 104
  #   PE32+ (0x020b): optBase + 120
  var importDirRVA: uint32 = 0
  if optMagic == 0x010b:
    if optBase + 111 < data.len:
      importDirRVA = readU32(data, optBase + 104)
  elif optMagic == 0x020b:
    if optBase + 127 < data.len:
      importDirRVA = readU32(data, optBase + 120)

  if importDirRVA == 0: return @[]

  let importDirFO = virtualToFileOffset(info, uint64(importDirRVA))
  if importDirFO < 0: return @[]

  let ptrSize = if optMagic == 0x020b: 8 else: 4

  # Walk IMAGE_IMPORT_DESCRIPTOR chain (20 bytes each).
  var descOff = importDirFO
  while descOff + 19 < data.len:
    let origFirstThunk = readU32(data, descOff)
    let nameRVA        = readU32(data, descOff + 12)
    let firstThunk     = readU32(data, descOff + 16)

    if origFirstThunk == 0 and nameRVA == 0 and firstThunk == 0:
      break

    let dllNameFO = virtualToFileOffset(info, uint64(nameRVA))
    let dllName   = if dllNameFO >= 0 and dllNameFO < data.len:
                      readCStr(data, dllNameFO)
                    else: ""

    let intFO = virtualToFileOffset(info, uint64(origFirstThunk))
    if intFO >= 0:
      var entryIdx = 0
      var intOff   = intFO
      while intOff + ptrSize - 1 < data.len:
        let entry = if ptrSize == 8: readU64(data, intOff)
                    else: uint64(readU32(data, intOff))
        if entry == 0: break

        let ordinalBit = if ptrSize == 8: 0x8000000000000000'u64
                         else: 0x80000000'u64
        if (entry and ordinalBit) == 0:
          let nameEntFO = virtualToFileOffset(info, uint64(uint32(entry)))
          if nameEntFO >= 0 and nameEntFO + 2 < data.len:
            let funcName = readCStr(data, nameEntFO + 2)  # skip 2-byte hint
            let iatRVA   = uint64(firstThunk) + uint64(entryIdx) * uint64(ptrSize)
            let iatFO    = virtualToFileOffset(info, iatRVA)
            result.add(ImportEntry(
              name:           funcName,
              moduleName:     dllName,
              virtualAddress: iatRVA,
              fileOffset:     if iatFO >= 0: uint64(iatFO) else: 0
            ))

        inc entryIdx
        intOff += ptrSize

    descOff += 20

# Parse the import table of a binary. Returns ELF PLT stubs or PE IAT entries.
proc parseImports*(info: BinaryInfo): seq[ImportEntry] =
  case info.format
  of bfELF: parseELFImports(info)
  of bfPE:  parsePEImports(info)
  else:     @[]

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
    result.errorMsg = "Error: File not found: " & filePath
    return

  let data = readFileBytes(filePath)
  if data.len == 0:
    result.errorMsg = "Error: File is empty or unreadable: " & filePath
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
    result.errorMsg = "Unknown binary format: " & filePath
