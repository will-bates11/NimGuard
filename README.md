# NimGuard

**NimGuard** is a dynamic binary patching and instrumentation tool for legacy systems.
It enables runtime analysis, patch injection, and behavior monitoring, all without requiring source code modifications.

This tool is designed to help security researchers, DevSecOps engineers, and reverse engineers analyze, patch, and protect legacy binaries that are otherwise difficult to modify due to missing source code or vendor lock-in.

## Features

- **Binary Analysis:** Disassemble and analyze binaries using Capstone.
- **Dynamic Patching:** Assemble and inject patches at runtime using Keystone.
- **Instrumentation Hooks:** Insert monitoring hooks for logging, runtime protection, and anomaly detection.
- **Rule-Based Engine:** Define patching rules via a custom DSL for flexible, scenario-based modifications.
- **Live Debugging:** Emulate patched code before applying it using Unicorn.
- **Cross-Platform Support:** Works on Windows, Linux, and macOS with proper dependencies installed.

## Installation

### 1. Install Nim

Use [choosenim](https://github.com/dom96/choosenim) to install Nim:

```bash
curl https://nim-lang.org/choosenim/init.sh -sSf | sh
```

Verify installation:

```bash
nim -v
```

### 2. Install System Dependencies

NimGuard uses FFI bindings to C libraries that must be installed at the OS level.
No Nim package manager install is needed for these.

**Capstone** (disassembly, required for `--analyze` and `--disasm`):

```bash
# Linux (Debian/Ubuntu)
sudo apt-get install libcapstone-dev

# macOS
brew install capstone

# Windows
# Download capstone.dll from https://www.capstone-engine.org/ and place it
# in the same directory as the nimguard executable.
```

**Keystone** (assembly/patching, Phase 3, optional for now):
See https://www.keystone-engine.org/

**Unicorn** (emulation, Phase 4, optional for now):
See https://www.unicorn-engine.org/

### 3. Clone the Repository

```bash
git clone https://github.com/will-bates11/nimguard.git
cd nimguard
```

### 4. Build NimGuard

```bash
nimble build
```

### 5. Run Tests

```bash
nimble test
```

---

## Usage

### Analyze a binary

Report format, architecture, sections, and dangerous function calls found:

```bash
./nimguard target_binary --analyze
```

### Show full disassembly

Print every instruction in the `.text` section:

```bash
./nimguard target_binary --disasm
```

### Apply patches

```bash
./nimguard target_binary --patch
./nimguard target_binary --patch --rules custom_rules.json
```

### Enable live monitoring

```bash
./nimguard target_binary --monitor
```

### Rule-Based Patching

NimGuard supports a rule-based engine where you define patching rules:

```json
{
  "rules": [
    {
      "identifier": "auth_bypass",
      "description": "Bypass authentication in login function",
      "condition": "if function login() is called",
      "patch": "mov eax, 1; ret"
    }
  ]
}
```

Load a custom rule set:

```bash
./nimguard target_binary --rules my_rules.json
```

---

## Development Roadmap

### Phase 0 and 1: Binary format parsing

Implemented pure-Nim ELF and PE header parsing (no external libraries).

### Phase 2: Capstone integration

Real disassembly via Capstone FFI. The `--analyze` flag reports dangerous
function calls found in the binary. The `--disasm` flag shows full `.text`
disassembly.

### Phase 3: Keystone integration (planned)

Assembly and patch injection using Keystone.

### Phase 4: Unicorn integration (planned)

Emulation-based pre-flight testing of patches using Unicorn.

---

## Contributing

1. Fork the repository
2. Create a feature branch: `git checkout -b my-new-feature`
3. Commit your changes: `git commit -m "Add my feature"`
4. Push to the branch: `git push origin my-new-feature`
5. Submit a pull request

For major changes, please open an issue first to discuss your proposal.

---

## Legal Disclaimer

Use this tool only in a controlled and legal environment.
NimGuard is designed for research, security analysis, and ethical hacking purposes.
Misuse of this software in unauthorized systems may violate laws and regulations.
