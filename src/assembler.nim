# NimGuard - Assembly module backed by Keystone.
# Provides higher-level types and procedures over the raw FFI bindings.
import binary
import bindings/keystone

type
  AssembledOutput* = object
    bytes*:    seq[byte]  # raw encoded bytes
    statCount*: int       # number of statements assembled

# Map NimGuard Architecture to Keystone arch/mode constants.
proc archToKeystone(arch: Architecture): (cint, cint) =
  case arch
  of archX86:   (KS_ARCH_X86, KS_MODE_32)
  of archX64:   (KS_ARCH_X86, KS_MODE_64)
  of archARM:   (KS_ARCH_ARM, KS_MODE_ARM)
  of archARM64: (KS_ARCH_ARM64, KS_MODE_LITTLE_ENDIAN)
  else:         (KS_ARCH_X86, KS_MODE_64)

# Check whether the Keystone shared library is available at runtime.
# Returns false if the library cannot be loaded or initialised.
proc isKeystoneAvailable*(): bool =
  var ks: ptr KsEngine = nil
  try:
    let err = ks_open(KS_ARCH_X86, KS_MODE_64, addr ks)
    if err == KS_ERR_OK:
      discard ks_close(ks)
      return true
    return false
  except:
    return false

# Assemble one or more instructions at the given base address.
# Returns an AssembledOutput containing the encoded bytes and statement count.
# Returns an empty AssembledOutput if Keystone is not available, the input
# string is empty, or assembly fails.
proc assembleBlock*(asmStr: string, arch: Architecture,
                    address: uint64 = 0): AssembledOutput =
  if asmStr.len == 0:
    return AssembledOutput(bytes: @[], statCount: 0)

  var ks: ptr KsEngine = nil
  let (ksArch, ksMode) = archToKeystone(arch)

  try:
    let openErr = ks_open(ksArch, ksMode, addr ks)
    if openErr != KS_ERR_OK:
      return AssembledOutput(bytes: @[], statCount: 0)
  except:
    return AssembledOutput(bytes: @[], statCount: 0)

  defer: discard ks_close(ks)

  var encoding: ptr byte = nil
  var encodingSize: csize_t = 0
  var statCount: csize_t = 0

  let asmErr = ks_asm(ks, cstring(asmStr), address,
                      addr encoding, addr encodingSize, addr statCount)
  if asmErr != 0 or encoding == nil or encodingSize == 0:
    return AssembledOutput(bytes: @[], statCount: 0)

  defer: ks_free(encoding)

  var bytes: seq[byte]
  let arr = cast[ptr UncheckedArray[byte]](encoding)
  for i in 0 ..< int(encodingSize):
    bytes.add(arr[i])

  result = AssembledOutput(bytes: bytes, statCount: int(statCount))

# Assemble a single instruction string and return the raw encoded bytes.
# This is a convenience wrapper around assembleBlock.
# Returns an empty sequence if Keystone is not available or assembly fails.
proc assembleInstruction*(asmStr: string, arch: Architecture,
                          address: uint64 = 0): seq[byte] =
  assembleBlock(asmStr, arch, address).bytes

# Generate a sequence of n x86/x86-64 NOP bytes (0x90).
proc makeNops*(count: int): seq[byte] =
  result = newSeq[byte](count)
  for i in 0 ..< count:
    result[i] = 0x90'u8
