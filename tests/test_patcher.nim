# NimGuard - Unit Tests for Patcher Module
import unittest, patcher, rules

suite "Patcher Module Tests":

  test "Binary analysis returns correct file path":
    let analysis = analyzeBinary("dummy_binary.exe")
    check analysis.filePath == "dummy_binary.exe"

  test "Binary analysis detects vulnerabilities":
    let analysis = analyzeBinary("dummy_binary.exe")
    check analysis.vulnerabilities.len > 0

  test "Default rules are loaded correctly":
    let defaultRules = loadDefaultRules()
    check defaultRules.len > 0
    check defaultRules[0].identifier == "checkAuth"

  test "Applying a patch succeeds":
    var dummyRules = @[
      PatchRule(
        identifier: "testFunction",
        description: "Patch test function",
        condition: "if function testFunction() is called",
        patch: "mov eax, 0; ret"
      )
    ]
    let success = applyPatches("dummy_binary.exe", dummyRules)
    check success == true

  test "Loading custom rules from JSON":
    # Create a temporary JSON rules file
    let tempFile = "test_rules.json"
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

    # Load rules and verify
    let customRules = loadRules(tempFile)
    check customRules.len == 1
    check customRules[0].identifier == "dummyPatch"

    # Cleanup test file
    removeFile(tempFile)

when isMainModule:
  runAllTests()