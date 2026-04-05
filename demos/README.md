# NimGuard Demos

Runnable examples showing each major NimGuard feature.

## Setup

### 1. Build the test binary

The demos run against `demos/test_binary` (Linux) or `demos/test_binary.exe` (Windows),
a small compiled program that calls `memcpy`, `memmove`, and `sprintf` so the
analyzer has something concrete to report.

```bash
# Linux / WSL2
nim c -d:release -o:demos/test_binary demos/create_test_binary.nim

# Windows
nim c -d:release -o:demos\test_binary.exe demos\create_test_binary.nim
```

### 2. Install runtime libraries

NimGuard loads these at runtime via lazy dynamic linking. If a library is
absent the feature degrades gracefully instead of crashing.

**Windows** -- place the DLLs next to `nimguard.exe`:

| Library | Source |
|---------|--------|
| `capstone.dll` | [capstone PyPI wheel](https://pypi.org/project/capstone/) -- extract from the wheel (it is a zip) |
| `keystone.dll` | [keystone-engine/keystone releases](https://github.com/keystone-engine/keystone/releases) |
| `unicorn.dll` | [unicorn PyPI wheel](https://pypi.org/project/unicorn/) -- extract from the wheel |

**Linux**:
```bash
sudo apt-get install libcapstone-dev libunicorn-dev
# keystone is not in apt; build from source or skip (--patch degrades gracefully)
```

**macOS**:
```bash
brew install capstone unicorn keystone
```

### 3. Build NimGuard

```bash
nim c -d:release src/nimguard.nim
```

---

## Demos

### analyze_binary -- format, sections, dangerous calls

Parses the binary header, lists sections with permissions, and scans for
dangerous C function imports (memcpy, strcpy, gets, ...).

```bash
bash demos/analyze_binary.sh             # Linux / macOS / Git Bash
demos\analyze_binary.bat                 # Windows cmd
```

Sample output: `demos/analyze_binary.windows.output.txt`

---

### disassemble_section -- real x86-64 disassembly via Capstone

Disassembles the full `.text` section using Capstone and prints each
instruction with its address, mnemonic, and operands.

```bash
bash demos/disassemble_section.sh
demos\disassemble_section.bat
```

Sample output: `demos/disassemble_section.windows.output.txt`

---

### patch_binary -- assemble and apply patches via Keystone

Reads `sample_rules.json`, matches each rule against detected dangerous
imports, uses Keystone to assemble the replacement instructions, and writes
a patched copy of the binary.

```bash
bash demos/patch_binary.sh
demos\patch_binary.bat
```

Sample output: `demos/patch_binary.windows.output.txt`

The rules file format is documented in `demos/sample_rules.json`.

---

### emulate_code -- CPU emulation via Unicorn

Loads the raw `.text` bytes into a Unicorn emulator and runs up to 256
instructions. Real-world binaries stop early when they reference unmapped
memory (stack, imports), which is expected. The emulator is most useful for
testing self-contained code sequences or validating patched bytes before
writing to disk.

```bash
bash demos/emulate_code.sh
demos\emulate_code.bat
```

Sample output: `demos/emulate_code.windows.output.txt`

---

## Files

| File | Description |
|------|-------------|
| `create_test_binary.nim` | Source for the demo target binary |
| `sample_rules.json` | Example patch rules with explanations |
| `analyze_binary.sh/.bat` | Analyze demo script |
| `disassemble_section.sh/.bat` | Disassembly demo script |
| `patch_binary.sh/.bat` | Patch demo script |
| `emulate_code.sh/.bat` | Emulation demo script |
| `*.windows.output.txt` | Captured output from a Windows run |
| `*.linux.output.txt` | Captured output from a Linux (WSL2) run |

---

## Running against any binary

All scripts accept an optional binary path as the first argument:

```bash
bash demos/analyze_binary.sh /usr/bin/ls
demos\analyze_binary.bat "C:\Windows\System32\notepad.exe"
```
