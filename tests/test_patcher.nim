# NimGuard - Unit Tests for Patcher and Rules Modules
import unittest, os, patcher, rules

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

  test "applyPatch stub always returns true":
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
