# NimGuard

NimGuard is a binary patching and instrumentation tool for ELF and PE binaries. It supports static analysis, rule-based patching, CPU emulation testing, and live process instrumentation on Linux and Windows.

## Features

- **Binary analysis:** Pure-Nim ELF and PE header parsing. Detects architecture, sections, and dangerous function calls (strcpy, gets, sprintf, etc.)
- **Disassembly:** Full `.text` section disassembly via Capstone (optional C library)
- **Patching:** Rule-based static patching using JSON rule files; Keystone used for patch validation when available
- **Emulation testing:** Run the `.text` section through Unicorn before committing a patch (optional C library)
- **Live process instrumentation (Linux):** Attach to a running process via ptrace, read/write memory, inject breakpoints, trace syscalls
- **Live process instrumentation (Windows):** Attach to a running process via Win32 debug API, read/write memory, inject breakpoints, trace debug events
- **Cross-platform build:** Compiles on Linux, Windows, and macOS; C library features degrade gracefully when libraries are not installed

## Platform Support

| Feature | Linux | Windows | macOS |
|---|---|---|---|
| Binary parsing (ELF/PE) | Yes | Yes | Yes |
| Disassembly (Capstone) | Yes | Yes | Yes |
| Assembly/patching (Keystone) | Yes | Yes | Yes |
| Emulation (Unicorn) | Yes | Yes | Yes |
| ptrace instrumentation | Yes | No | No |
| Win32 debug instrumentation | No | Yes | No |

On macOS, runtime instrumentation flags (--attach, --inject, --breakpoint, --trace) will report that the platform is not supported.

## Installation

### 1. Install Nim 2.x

Use [choosenim](https://github.com/dom96/choosenim):

```bash
curl https://nim-lang.org/choosenim/init.sh -sSf | sh
```

Verify:

```bash
nim --version
```

### 2. Install C library dependencies (optional)

The C libraries are optional. NimGuard will still build and run without them; affected flags will report that the library is unavailable.

**Capstone** (required for `--disasm` and dangerous-call detection in `--analyze`):

```bash
# Debian/Ubuntu
sudo apt-get install libcapstone-dev

# macOS
brew install capstone

# Windows
# Download capstone.dll from https://www.capstone-engine.org/ and place it
# next to the nimguard executable.
```

**Keystone** (required for patch assembly validation):

```bash
# Debian/Ubuntu
sudo apt-get install libkeystone-dev   # or build from source

# macOS
brew install keystone

# Windows
# Download keystone.dll from https://www.keystone-engine.org/
```

**Unicorn** (required for `--emulate` and `--test-patch`):

```bash
# Debian/Ubuntu
sudo apt-get install libunicorn-dev

# macOS
brew install unicorn

# Windows
# Download unicorn.dll from https://www.unicorn-engine.org/
```

### 3. Clone and build

```bash
git clone https://github.com/will-bates11/nimguard.git
cd nimguard
nimble build
```

The binary is placed at `./nimguard` (Linux/macOS) or `.\nimguard.exe` (Windows).

### 4. Run tests

```bash
nimble test
```

## Usage

### Analyze a binary

Report format, architecture, sections, and dangerous function calls:

```bash
./nimguard target_binary --analyze
```

### Disassemble the .text section

```bash
./nimguard target_binary --disasm
```

### Apply patches

Apply default rules:

```bash
./nimguard target_binary --patch
```

Apply custom rules from a JSON file:

```bash
./nimguard target_binary --patch --rules custom_rules.json
```

Write the patched binary to a specific output path:

```bash
./nimguard target_binary --patch --output patched_binary
```

### Emulate the .text section

Run the `.text` section through Unicorn (up to 256 instructions):

```bash
./nimguard target_binary --emulate
```

### Test a patch in the emulator

Apply a NOP patch at offset 0 in the emulator before writing it to disk:

```bash
./nimguard target_binary --test-patch
```

### Enable hook-based monitoring

Register pre-execution hooks for functions flagged in analysis:

```bash
./nimguard target_binary --monitor
```

### Live process instrumentation

Attach to a running process (Linux and Windows only):

```bash
./nimguard --attach <pid>
```

Set a software breakpoint at a hex address:

```bash
./nimguard --attach <pid> --breakpoint 0x401000
```

Write bytes into process memory:

```bash
./nimguard --attach <pid> --inject 0x401000:9090
```

Trace syscalls (up to 64 events):

```bash
./nimguard --attach <pid> --trace
```

### Rule file format

Patch rules are JSON:

```json
{
  "rules": [
    {
      "identifier": "auth_bypass",
      "description": "Bypass authentication check",
      "condition": "if function login() is called",
      "patch": "mov eax, 1; ret"
    }
  ]
}
```

## Architecture

See [docs/architecture.md](docs/architecture.md) for a full breakdown of the module structure.

## Building from source

```bash
nimble build          # release build -> ./nimguard
nimble test           # run all tests
```

## License

MIT. See [LICENSE](LICENSE).

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).
