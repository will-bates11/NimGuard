# NimGuard - Rule-Based Patching System
import os, json

type
  PatchRule* = object
    identifier*: string  # Name of function or code section to patch
    description*: string # Explanation of the patch
    condition*: string   # Condition triggering the patch (simplified for now)
    patch*: string       # Assembly or pseudo-code patch instructions

# Load predefined patching rules targeting real unsafe C library functions.
# These identifiers match the names detected by findDangerousCallSites() and
# scanImportStrings() in disassembler.nim.
proc loadDefaultRules*(): seq[PatchRule] =
  result = @[
    PatchRule(
      identifier: "strcpy",
      description: "NOP out strcpy call site (unsafe unbounded string copy)",
      condition: "if strcpy is called",
      patch: "nop; nop; nop; nop; nop"
    ),
    PatchRule(
      identifier: "gets",
      description: "NOP out gets call site (gets is always unsafe)",
      condition: "if gets is called",
      patch: "nop; nop; nop; nop; nop"
    ),
    PatchRule(
      identifier: "sprintf",
      description: "NOP out sprintf call site (unsafe unbounded format output)",
      condition: "if sprintf is called",
      patch: "nop; nop; nop; nop; nop"
    )
  ]

# Load custom patching rules from a JSON file
proc loadRules*(filePath: string): seq[PatchRule] =
  if not fileExists(filePath):
    echo "[-] Error: Rules file not found: ", filePath
    return @[]

  try:
    let data = readFile(filePath)
    let jsonRules = parseJson(data)
    for rule in jsonRules["rules"]:
      try:
        result.add(PatchRule(
          identifier: rule["identifier"].getStr(),
          description: rule["description"].getStr(),
          condition: rule["condition"].getStr(),
          patch: rule["patch"].getStr()
        ))
      except CatchableError as e:
        echo "[-] Warning: Skipping invalid rule: ", e.msg
    echo "[+] Loaded ", result.len, " rules from file."
  except CatchableError as e:
    echo "[-] Error: Failed to parse rules file: ", e.msg
