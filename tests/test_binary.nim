# NimGuard - Unit Tests for Binary Format Parsing
# Fixtures are constructed from byte arrays and written to temp files.
# No committed binary blobs required.
import unittest, os, binary

# Build a minimal valid ELF64 header (64 bytes, x86-64, no sections).
# e_entry is encoded at offset 24 as a little-endian uint64.
proc makeElf64(entryPoint: uint64 = 0x401000'u64,
               numSections: uint16 = 0,
               shoff: uint64 = 0): seq[byte] =
  result = newSeq[byte](64)
  # ELF ident
  result[0] = 0x7f; result[1] = byte('E'); result[2] = byte('L'); result[3] = byte('F')
  result[4] = 0x02  # EI_CLASS: 64-bit
  result[5] = 0x01  # EI_DATA: little-endian
  result[6] = 0x01  # EI_VERSION: 1
  # bytes 7-15: OS/ABI + padding (already zero)
  result[16] = 0x02; result[17] = 0x00  # e_type: ET_EXEC
  result[18] = 0x3e; result[19] = 0x00  # e_machine: EM_X86_64 (62 = 0x3e)
  result[20] = 0x01                      # e_version
  # e_entry at offset 24 (8 bytes LE)
  for i in 0 ..< 8:
    result[24 + i] = byte((entryPoint shr (i * 8)) and 0xff)
  # e_shoff at offset 40 (8 bytes LE)
  for i in 0 ..< 8:
    result[40 + i] = byte((shoff shr (i * 8)) and 0xff)
  result[52] = 0x40; result[53] = 0x00  # e_ehsize: 64
  result[54] = 0x38; result[55] = 0x00  # e_phentsize: 56
  result[58] = 0x40; result[59] = 0x00  # e_shentsize: 64
  result[60] = byte(numSections and 0xff)
  result[61] = byte((numSections shr 8) and 0xff)

# Build a minimal valid ELF32 header (52 bytes, x86, no sections).
proc makeElf32(entryPoint: uint32 = 0x08048000'u32): seq[byte] =
  result = newSeq[byte](52)
  result[0] = 0x7f; result[1] = byte('E'); result[2] = byte('L'); result[3] = byte('F')
  result[4] = 0x01  # EI_CLASS: 32-bit
  result[5] = 0x01  # little-endian
  result[6] = 0x01  # version
  result[16] = 0x02; result[17] = 0x00  # ET_EXEC
  result[18] = 0x03; result[19] = 0x00  # EM_386 (3)
  result[20] = 0x01
  # e_entry at offset 24 (4 bytes LE)
  for i in 0 ..< 4:
    result[24 + i] = byte((entryPoint shr (i * 8)) and 0xff)
  result[40] = 0x34; result[41] = 0x00  # e_ehsize: 52
  result[42] = 0x20; result[43] = 0x00  # e_phentsize: 32
  result[46] = 0x28; result[47] = 0x00  # e_shentsize: 40

# Build a minimal valid PE32+ header (x86-64, no sections).
# Layout: 64-byte DOS stub + 4-byte PE sig + 20-byte COFF + 112-byte optional.
proc makePE64(entryPoint: uint32 = 0x1000'u32): seq[byte] =
  let peOffset = 64
  let totalSize = peOffset + 4 + 20 + 112
  result = newSeq[byte](totalSize)

  # DOS header
  result[0] = byte('M'); result[1] = byte('Z')
  # e_lfanew at offset 0x3C = 60
  result[60] = byte(peOffset and 0xff)
  result[61] = byte((peOffset shr 8) and 0xff)

  # PE signature
  let ps = peOffset
  result[ps]     = byte('P'); result[ps + 1] = byte('E')
  result[ps + 2] = 0x00;      result[ps + 3] = 0x00

  # COFF header (at ps + 4)
  let ch = ps + 4
  result[ch]     = 0x64; result[ch + 1] = 0x86  # Machine: 0x8664 = AMD64 (LE)
  result[ch + 2] = 0x00; result[ch + 3] = 0x00  # NumberOfSections: 0
  result[ch + 16] = 0x70; result[ch + 17] = 0x00  # SizeOfOptionalHeader: 112

  # Optional header PE32+ (at ch + 20 = ps + 24)
  let oh = ch + 20
  result[oh]     = 0x0b; result[oh + 1] = 0x02  # Magic: 0x020b = PE32+
  # AddressOfEntryPoint at oh + 16
  for i in 0 ..< 4:
    result[oh + 16 + i] = byte((entryPoint shr (i * 8)) and 0xff)

# Write bytes to a temp file, return path.
proc writeTmp(name: string, data: seq[byte]): string =
  result = name
  let f = open(result, fmWrite)
  defer: close(f)
  discard writeBytes(f, data, 0, data.len)

suite "Binary Format Detection":

  test "ELF magic bytes detected as ELF":
    let path = writeTmp("_test_elf64.bin", makeElf64())
    defer: removeFile(path)
    let info = parseBinary(path)
    check info.format == bfELF

  test "PE magic bytes detected as PE":
    let path = writeTmp("_test_pe64.bin", makePE64())
    defer: removeFile(path)
    let info = parseBinary(path)
    check info.format == bfPE

  test "Text file returns Unknown format":
    let path = "_test_unknown.txt"
    defer: removeFile(path)
    writeFile(path, "this is not a binary file")
    let info = parseBinary(path)
    check info.format == bfUnknown

  test "Non-existent file returns Unknown format without crash":
    let info = parseBinary("_does_not_exist_99999.bin")
    check info.format == bfUnknown

  test "Empty file returns Unknown format without crash":
    let path = "_test_empty.bin"
    defer: removeFile(path)
    writeFile(path, "")
    let info = parseBinary(path)
    check info.format == bfUnknown

suite "ELF64 Parsing":

  test "ELF64 architecture detected as x64":
    let path = writeTmp("_test_elf64_arch.bin", makeElf64())
    defer: removeFile(path)
    let info = parseBinary(path)
    check info.architecture == archX64

  test "ELF64 entry point parsed correctly":
    let ep = 0x401000'u64
    let path = writeTmp("_test_elf64_ep.bin", makeElf64(entryPoint = ep))
    defer: removeFile(path)
    let info = parseBinary(path)
    check info.entryPoint == ep

  test "ELF64 with no sections returns empty section list":
    let path = writeTmp("_test_elf64_nosec.bin", makeElf64(numSections = 0))
    defer: removeFile(path)
    let info = parseBinary(path)
    check info.sections.len == 0

  test "ELF64 file path stored correctly":
    let path = writeTmp("_test_elf64_fp.bin", makeElf64())
    defer: removeFile(path)
    let info = parseBinary(path)
    check info.filePath == path

suite "ELF32 Parsing":

  test "ELF32 architecture detected as x86":
    let path = writeTmp("_test_elf32_arch.bin", makeElf32())
    defer: removeFile(path)
    let info = parseBinary(path)
    check info.architecture == archX86

  test "ELF32 entry point parsed correctly":
    let ep = 0x08048000'u32
    let path = writeTmp("_test_elf32_ep.bin", makeElf32(entryPoint = ep))
    defer: removeFile(path)
    let info = parseBinary(path)
    check info.entryPoint == uint64(ep)

suite "PE Parsing":

  test "PE32+ architecture detected as x64":
    let path = writeTmp("_test_pe64_arch.bin", makePE64())
    defer: removeFile(path)
    let info = parseBinary(path)
    check info.architecture == archX64

  test "PE32+ entry point parsed correctly":
    let ep = 0x1000'u32
    let path = writeTmp("_test_pe64_ep.bin", makePE64(entryPoint = ep))
    defer: removeFile(path)
    let info = parseBinary(path)
    check info.entryPoint == uint64(ep)

  test "PE with no sections returns empty section list":
    let path = writeTmp("_test_pe64_nosec.bin", makePE64())
    defer: removeFile(path)
    let info = parseBinary(path)
    check info.sections.len == 0

suite "ELF64 Section Header Parsing":

  # Build a minimal ELF64 with one concrete section header so that we can
  # verify name, virtualAddress, fileOffset, and size are parsed correctly.
  #
  # Layout:
  #   [0..63]   ELF64 header (e_shoff = 128, e_shnum = 2, e_shstrndx = 1)
  #   [64..127] Padding / section data placeholder (16 bytes of 0x90)
  #   [128..191] Section header 0 (null section, all zeros)
  #   [192..255] Section header 1 (.text section)
  #   [256..271] String table (\x00.text\x00)
  proc makeElf64WithSection(): seq[byte] =
    let shoff    = 128'u64
    let shnum    = 2'u16
    let shstrndx = 1'u16
    let shentsize = 64'u16
    let totalSize = 128 + 2 * 64 + 16  # header + 2 section headers + strtab
    result = newSeq[byte](totalSize)

    # ELF ident
    result[0] = 0x7f; result[1] = byte('E'); result[2] = byte('L'); result[3] = byte('F')
    result[4] = 0x02  # 64-bit
    result[5] = 0x01  # little-endian
    result[6] = 0x01  # version
    result[16] = 0x02; result[17] = 0x00  # ET_EXEC
    result[18] = 0x3e; result[19] = 0x00  # EM_X86_64
    result[20] = 0x01
    # e_entry = 0x401000
    let ep = 0x401000'u64
    for i in 0 ..< 8:
      result[24 + i] = byte((ep shr (i * 8)) and 0xff)
    # e_shoff
    for i in 0 ..< 8:
      result[40 + i] = byte((shoff shr (i * 8)) and 0xff)
    result[52] = 0x40; result[53] = 0x00  # e_ehsize = 64
    result[54] = 0x38; result[55] = 0x00  # e_phentsize = 56
    result[58] = byte(shentsize and 0xff); result[59] = byte((shentsize shr 8) and 0xff)
    result[60] = byte(shnum and 0xff); result[61] = byte((shnum shr 8) and 0xff)
    result[62] = byte(shstrndx and 0xff); result[63] = byte((shstrndx shr 8) and 0xff)

    # String table at offset 256 (= 128 + 2*64): \x00 .text \x00
    # name index 0 = "" (null), name index 1 = ".text"
    let strtabOff = 128 + 2 * 64
    result[strtabOff]     = 0x00          # index 0: empty name for null section
    result[strtabOff + 1] = byte('.')     # index 1: ".text"
    result[strtabOff + 2] = byte('t')
    result[strtabOff + 3] = byte('e')
    result[strtabOff + 4] = byte('x')
    result[strtabOff + 5] = byte('t')
    result[strtabOff + 6] = 0x00

    # Section header 0: null (all zeros, at offset 128)
    # Already zero.

    # Section header 1: .text (at offset 192 = 128 + 64)
    let sh1 = 128 + 64
    # sh_name = 1 (index into string table)
    result[sh1 + 0] = 0x01; result[sh1 + 1] = 0x00; result[sh1 + 2] = 0x00; result[sh1 + 3] = 0x00
    # sh_type = SHT_PROGBITS = 1
    result[sh1 + 4] = 0x01
    # sh_flags = SHF_ALLOC | SHF_EXECINSTR = 0x06
    result[sh1 + 8] = 0x06
    # sh_addr = 0x401000 (8 bytes LE)
    let vaddr = 0x401000'u64
    for i in 0 ..< 8:
      result[sh1 + 16 + i] = byte((vaddr shr (i * 8)) and 0xff)
    # sh_offset = 64 (8 bytes LE) - section data at file offset 64
    let foff = 64'u64
    for i in 0 ..< 8:
      result[sh1 + 24 + i] = byte((foff shr (i * 8)) and 0xff)
    # sh_size = 64 (8 bytes LE)
    let sz = 64'u64
    for i in 0 ..< 8:
      result[sh1 + 32 + i] = byte((sz shr (i * 8)) and 0xff)

    # Section header 1 is also the string table (shstrndx = 1). We need to
    # point it at our string data. Override sh_addr/sh_offset/sh_size for
    # the stringsection. In a well-formed ELF the shstrndx section IS the
    # string table, but here we want section 1 to represent a .text section.
    # Workaround: set shstrndx = 1 and make section 1's offset/size cover
    # the string table bytes we wrote above.
    # Adjust: sh_offset for sec 1 = strtabOff, sh_size = 7
    let strtabFO = uint64(strtabOff)
    for i in 0 ..< 8:
      result[sh1 + 24 + i] = byte((strtabFO shr (i * 8)) and 0xff)
    let strtabSz = 7'u64
    for i in 0 ..< 8:
      result[sh1 + 32 + i] = byte((strtabSz shr (i * 8)) and 0xff)
    # Set sh_addr back to 0x401000 (already set above, but strtab section
    # gets vaddr=0 in real ELFs). For testing section field parsing, keep
    # the vaddr and note: the name lookup uses the strtab fileOffset correctly.

  # Separate fixture: two section headers so shstrndx points to a separate
  # string-table-only section and section 0 can have its own fields.
  proc makeElf64TwoSections(): seq[byte] =
    # Layout:
    #   [0..63]   ELF64 header (e_shoff=192, e_shnum=3, e_shstrndx=2)
    #   [64..127]  .text data (64 bytes of 0x90)
    #   [128..191] padding
    #   [192..255] SH 0: null
    #   [256..319] SH 1: .text  (vaddr=0x401000, foff=64, size=64, flags=execinstr|alloc)
    #   [320..383] SH 2: .shstrtab (foff=384, size=13)
    #   [384..396] strtab: \0.text\0.shstrtab\0
    let shoff    = 192'u64
    let shnum    = 3'u16
    let shstrndx = 2'u16
    let strtabOff = 384
    # String table content: \0 (1) + ".text\0" (6) + ".shstrtab\0" (10) = 17 bytes
    let totalSize = strtabOff + 17
    result = newSeq[byte](totalSize)

    # ELF ident
    result[0] = 0x7f; result[1] = byte('E'); result[2] = byte('L'); result[3] = byte('F')
    result[4] = 0x02; result[5] = 0x01; result[6] = 0x01
    result[16] = 0x02; result[17] = 0x00
    result[18] = 0x3e; result[19] = 0x00
    result[20] = 0x01
    let ep = 0x401000'u64
    for i in 0 ..< 8:
      result[24 + i] = byte((ep shr (i * 8)) and 0xff)
    for i in 0 ..< 8:
      result[40 + i] = byte((shoff shr (i * 8)) and 0xff)
    result[52] = 0x40; result[53] = 0x00
    result[54] = 0x38; result[55] = 0x00
    result[58] = 0x40; result[59] = 0x00  # shentsize = 64
    result[60] = byte(shnum and 0xff); result[61] = byte((shnum shr 8) and 0xff)
    result[62] = byte(shstrndx); result[63] = 0x00

    # .text data at offset 64 (64 bytes of NOP)
    for i in 0 ..< 64:
      result[64 + i] = 0x90

    # String table at offset 384:
    # index 0: \0
    # index 1: .text\0
    # index 7: .shstrtab\0
    result[strtabOff + 0] = 0x00
    let stextStr = ".text"
    for i, c in stextStr:
      result[strtabOff + 1 + i] = byte(c)
    result[strtabOff + 6] = 0x00
    let sstrtabStr = ".shstrtab"
    for i, c in sstrtabStr:
      result[strtabOff + 7 + i] = byte(c)
    result[strtabOff + 16] = 0x00

    # SH 0: null (at 192) - all zeros, already done

    # SH 1: .text (at 256)
    let sh1 = 256
    # sh_name = 1
    result[sh1 + 0] = 0x01
    # sh_type = SHT_PROGBITS = 1
    result[sh1 + 4] = 0x01
    # sh_flags = SHF_ALLOC(2) | SHF_EXECINSTR(4) = 6
    result[sh1 + 8] = 0x06
    # sh_addr = 0x401000
    let textVaddr = 0x401000'u64
    for i in 0 ..< 8:
      result[sh1 + 16 + i] = byte((textVaddr shr (i * 8)) and 0xff)
    # sh_offset = 64
    let textFOff = 64'u64
    for i in 0 ..< 8:
      result[sh1 + 24 + i] = byte((textFOff shr (i * 8)) and 0xff)
    # sh_size = 64
    let textSize = 64'u64
    for i in 0 ..< 8:
      result[sh1 + 32 + i] = byte((textSize shr (i * 8)) and 0xff)

    # SH 2: .shstrtab (at 320)
    let sh2 = 320
    # sh_name = 7
    result[sh2 + 0] = 0x07
    # sh_type = SHT_STRTAB = 3
    result[sh2 + 4] = 0x03
    # sh_flags = SHF_ALLOC = 2
    result[sh2 + 8] = 0x02
    # sh_addr = 0
    # sh_offset = 384
    let stFOff = uint64(strtabOff)
    for i in 0 ..< 8:
      result[sh2 + 24 + i] = byte((stFOff shr (i * 8)) and 0xff)
    # sh_size = 17 (length of the strtab content)
    let stSize = 17'u64
    for i in 0 ..< 8:
      result[sh2 + 32 + i] = byte((stSize shr (i * 8)) and 0xff)

  # Build a PE32+ binary with one section (.text).
  # Section header: name=".text", VirtualAddress=0x1000, SizeOfRawData=64,
  # PointerToRawData=512, Characteristics=0x60000020 (code, exec, read).
  proc makePEWithSection(): seq[byte] =
    let peOffset = 64
    let optHdrSize = 112
    let coffBase = peOffset + 4
    let optBase = coffBase + 20
    let sectionBase = optBase + optHdrSize
    let sectionEntrySize = 40
    let rawDataOffset = 512  # section data starts at offset 512
    let rawDataSize   = 64
    let totalSize     = rawDataOffset + rawDataSize
    result = newSeq[byte](totalSize)

    # DOS header
    result[0] = byte('M'); result[1] = byte('Z')
    result[60] = byte(peOffset and 0xff)
    result[61] = byte((peOffset shr 8) and 0xff)

    # PE signature
    result[peOffset]     = byte('P'); result[peOffset + 1] = byte('E')
    result[peOffset + 2] = 0x00;      result[peOffset + 3] = 0x00

    # COFF header
    result[coffBase]     = 0x64; result[coffBase + 1] = 0x86  # AMD64
    result[coffBase + 2] = 0x01; result[coffBase + 3] = 0x00  # 1 section
    result[coffBase + 16] = byte(optHdrSize and 0xff)
    result[coffBase + 17] = byte((optHdrSize shr 8) and 0xff)

    # Optional header (PE32+)
    result[optBase]     = 0x0b; result[optBase + 1] = 0x02  # PE32+
    # AddressOfEntryPoint at optBase + 16
    result[optBase + 16] = 0x00; result[optBase + 17] = 0x10  # EP = 0x1000 (LE)

    # Section header
    let sh = sectionBase
    # Name: ".text\0\0\0"
    result[sh + 0] = byte('.'); result[sh + 1] = byte('t'); result[sh + 2] = byte('e')
    result[sh + 3] = byte('x'); result[sh + 4] = byte('t')
    # VirtualSize at sh+8 (uint32 LE) = 64
    result[sh + 8] = 0x40
    # VirtualAddress at sh+12 (uint32 LE) = 0x1000
    result[sh + 12] = 0x00; result[sh + 13] = 0x10
    # SizeOfRawData at sh+16 (uint32 LE) = 64
    result[sh + 16] = byte(rawDataSize and 0xff)
    # PointerToRawData at sh+20 (uint32 LE) = 512
    result[sh + 20] = byte(rawDataOffset and 0xff)
    result[sh + 21] = byte((rawDataOffset shr 8) and 0xff)
    # Characteristics at sh+36 (uint32 LE) = 0x60000020 (code|exec|read)
    result[sh + 36] = 0x20; result[sh + 37] = 0x00
    result[sh + 38] = 0x00; result[sh + 39] = 0x60

  test "ELF64 with two sections parses section count correctly":
    let data = makeElf64TwoSections()
    let path = writeTmp("_test_elf64_twosec.bin", data)
    defer: removeFile(path)
    let info = parseBinary(path)
    check info.format == bfELF
    # shnum=3 but section 0 is always null; we expect 3 entries in the seq
    check info.sections.len == 3

  test "ELF64 .text section has correct virtual address":
    let data = makeElf64TwoSections()
    let path = writeTmp("_test_elf64_sec_vaddr.bin", data)
    defer: removeFile(path)
    let info = parseBinary(path)
    var found = false
    for s in info.sections:
      if s.name == ".text":
        check s.virtualAddress == 0x401000'u64
        found = true
        break
    check found

  test "ELF64 .text section has correct file offset":
    let data = makeElf64TwoSections()
    let path = writeTmp("_test_elf64_sec_foff.bin", data)
    defer: removeFile(path)
    let info = parseBinary(path)
    var found = false
    for s in info.sections:
      if s.name == ".text":
        check s.fileOffset == 64'u64
        found = true
        break
    check found

  test "ELF64 .text section has correct size":
    let data = makeElf64TwoSections()
    let path = writeTmp("_test_elf64_sec_size.bin", data)
    defer: removeFile(path)
    let info = parseBinary(path)
    var found = false
    for s in info.sections:
      if s.name == ".text":
        check s.size == 64'u64
        found = true
        break
    check found

  test "ELF64 .text section has executable flag set":
    let data = makeElf64TwoSections()
    let path = writeTmp("_test_elf64_sec_exec.bin", data)
    defer: removeFile(path)
    let info = parseBinary(path)
    var found = false
    for s in info.sections:
      if s.name == ".text":
        check s.flags.executable == true
        found = true
        break
    check found

  test "PE with one section parses section count correctly":
    let data = makePEWithSection()
    let path = writeTmp("_test_pe_onesec.bin", data)
    defer: removeFile(path)
    let info = parseBinary(path)
    check info.format == bfPE
    check info.sections.len == 1

  test "PE .text section has correct virtual address (RVA)":
    let data = makePEWithSection()
    let path = writeTmp("_test_pe_sec_vaddr.bin", data)
    defer: removeFile(path)
    let info = parseBinary(path)
    check info.sections.len >= 1
    check info.sections[0].name == ".text"
    check info.sections[0].virtualAddress == 0x1000'u64

  test "PE .text section has correct file offset":
    let data = makePEWithSection()
    let path = writeTmp("_test_pe_sec_foff.bin", data)
    defer: removeFile(path)
    let info = parseBinary(path)
    check info.sections.len >= 1
    check info.sections[0].fileOffset == 512'u64

  test "PE .text section has correct size":
    let data = makePEWithSection()
    let path = writeTmp("_test_pe_sec_size.bin", data)
    defer: removeFile(path)
    let info = parseBinary(path)
    check info.sections.len >= 1
    check info.sections[0].size == 64'u64

  test "PE .text section has executable flag set":
    let data = makePEWithSection()
    let path = writeTmp("_test_pe_sec_exec.bin", data)
    defer: removeFile(path)
    let info = parseBinary(path)
    check info.sections.len >= 1
    check info.sections[0].flags.executable == true

suite "Raw Bytes":

  test "rawBytes field populated for ELF":
    let data = makeElf64()
    let path = writeTmp("_test_elf64_raw.bin", data)
    defer: removeFile(path)
    let info = parseBinary(path)
    check info.rawBytes.len == data.len

  test "rawBytes field populated for PE":
    let data = makePE64()
    let path = writeTmp("_test_pe64_raw.bin", data)
    defer: removeFile(path)
    let info = parseBinary(path)
    check info.rawBytes.len == data.len
