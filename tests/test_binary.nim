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
