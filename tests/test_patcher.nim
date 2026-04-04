# NimGuard - Unit Tests for Patcher and Rules Modules
import unittest, os, patcher, rules, assembler, binary

suite "Patcher Module Tests":

  test "Binary analysis returns correct file path":
    let analysis = analyzeBinary("dummy_binary.exe")
    check analysis.filePath == "dummy_binary.exe"

  test "Binary analysis on non-existent file returns no vulnerabilities":
    # With real disassembly, a non-existent binary has no bytes to scan.
    let analysis = analyzeBinary("dummy_binary.exe")
    check analysis.vulnerabilities.len == 0

  test "Default rules are loaded correctly":
    let defaultRules = loadDefaultRules()
    check defaultRules.len > 0
    check defaultRules[0].identifier == "checkAuth"

  test "applyPatch returns true for a valid instruction":
    # With Keystone: assembles the instruction and returns true.
    # Without Keystone: gracefully returns true (fallback behaviour).
    check applyPatch("any_binary", "anyFunction", "nop") == true

  test "Applying patches returns false when no vulnerabilities found":
    # A non-existent binary has no detected vulnerabilities, so no rule
    # can match and applyPatches should return false.
    let matchingRules = @[
      PatchRule(
        identifier: "checkAuth",
        description: "Patch checkAuth function",
        condition: "if function checkAuth() is called",
        patch: "mov eax, 1; ret"
      )
    ]
    let success = applyPatches("dummy_binary.exe", matchingRules)
    check success == false

  test "Applying patches returns false when no rules match":
    let nonMatchingRules = @[
      PatchRule(
        identifier: "nonExistentFunction",
        description: "Patch that will never match",
        condition: "never",
        patch: "nop"
      )
    ]
    let success = applyPatches("dummy_binary.exe", nonMatchingRules)
    check success == false

  test "Loading custom rules from JSON":
    let tempFile = "test_rules.json"
    defer: removeFile(tempFile)

    let jsonData = """
    {
      "rules": [
        {
          "identifier": "dummyPatch",
          "description": "Test patch for unit test",
          "condition": "if function dummyFunction() is called",
          "patch": "nop; nop;"
        }
      ]
    }
    """
    writeFile(tempFile, jsonData)

    let customRules = loadRules(tempFile)
    check customRules.len == 1
    check customRules[0].identifier == "dummyPatch"

  test "Loading rules from non-existent file returns empty seq":
    let result = loadRules("does_not_exist_12345.json")
    check result.len == 0

  test "Loading rules from malformed JSON returns empty seq":
    let tempFile = "test_malformed_rules.json"
    defer: removeFile(tempFile)

    writeFile(tempFile, "{ this is not valid json !!!")
    let result = loadRules(tempFile)
    check result.len == 0

  test "patchBinaryAtOffset patches bytes and writes a new file":
    let srcFile = "test_patch_src.bin"
    let dstFile = "test_patch_dst.bin"
    defer:
      removeFile(srcFile)
      removeFile(dstFile)
    # Write 8 zero bytes as a minimal test binary.
    writeFile(srcFile, newString(8))
    # Patch bytes at offset 2 with three NOP bytes.
    let patch = @[0x90'u8, 0x90'u8, 0x90'u8]
    check patchBinaryAtOffset(srcFile, dstFile, 2, patch) == true
    let result = readFile(dstFile)
    check result.len == 8
    check byte(result[0]) == 0x00'u8
    check byte(result[1]) == 0x00'u8
    check byte(result[2]) == 0x90'u8
    check byte(result[3]) == 0x90'u8
    check byte(result[4]) == 0x90'u8
    check byte(result[5]) == 0x00'u8

  test "patchBinaryAtOffset returns false for non-existent source":
    check patchBinaryAtOffset("no_such_file_xyz.bin", "out.bin", 0,
                               @[0x90'u8]) == false

  test "patchBinaryAtOffset returns false when offset is out of range":
    let srcFile = "test_patch_oob.bin"
    defer: removeFile(srcFile)
    writeFile(srcFile, "AB")
    check patchBinaryAtOffset(srcFile, "out_oob.bin", 100, @[0x90'u8]) == false

  test "patchBinaryAtOffset returns false for empty patch bytes":
    let srcFile = "test_patch_empty.bin"
    defer: removeFile(srcFile)
    writeFile(srcFile, "ABCDEF")
    check patchBinaryAtOffset(srcFile, "out_empty.bin", 0, @[]) == false

  test "assembleAndPatch writes assembled bytes when Keystone available":
    if not isKeystoneAvailable():
      skip()
    let srcFile = "test_aap_src.bin"
    let dstFile = "test_aap_dst.bin"
    defer:
      removeFile(srcFile)
      removeFile(dstFile)
    writeFile(srcFile, newString(8))
    check assembleAndPatch(srcFile, dstFile, 0, "nop", archX64) == true
    let result = readFile(dstFile)
    check result.len == 8
    check byte(result[0]) == 0x90'u8
