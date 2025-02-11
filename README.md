# NimGuard

**NimGuard** is a dynamic binary patching and instrumentation tool for legacy systems.  
It enables runtime analysis, patch injection, and behavior monitoring—all without requiring source code modifications.  

This tool is designed to help security researchers, DevSecOps engineers, and reverse engineers analyze, patch, and protect legacy binaries that are otherwise difficult to modify due to missing source code or vendor lock-in. 

## Features

✅ **Binary Analysis:** Disassemble and analyze binaries using Capstone.  
✅ **Dynamic Patching:** Assemble and inject patches at runtime using Keystone.  
✅ **Instrumentation Hooks:** Insert monitoring hooks for logging, runtime protection, and anomaly detection.  
✅ **Rule-Based Engine:** Define patching rules via a custom DSL for flexible, scenario-based modifications.  
✅ **Live Debugging:** Emulate patched code before applying it using Unicorn.  
✅ **Cross-Platform Support:** Works on Windows, Linux, and macOS with proper dependencies installed.  

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

### 2. Install Dependencies

Ensure you have the required dependencies installed:

```bash
nimble install capstone
nimble install keystone
nimble install unicorn
```

(If these libraries are not available in Nimble, you may need to install system-level bindings.)

### 3. Clone the Repository

```bash
git clone https://github.com/yourusername/nimguard.git
cd nimguard
```

### 4. Build NimGuard

Compile the project:

```bash
nimble build
```

### 5. Run Tests

To verify functionality, run:

```bash
nim c -r tests/test_patcher.nim
```

---

## Usage

### Basic Command

Run NimGuard to analyze and patch a binary:

```bash
./nimguard target_binary.exe
```

### Example Scenario: Patching a Vulnerability

If target_binary.exe contains a function with a known buffer overflow, NimGuard will:

1. Disassemble the function using Capstone.

2. Identify the overflow vulnerability.

3. Inject a runtime patch using Keystone (e.g., replacing a vulnerable instruction with a safer one).

4. Insert instrumentation hooks for logging and monitoring.

### Rule-Based Patching

NimGuard supports a rule-based engine where you define patching rules:

```yaml
rules:
  - identifier: "auth_bypass"
    description: "Bypass authentication in login function"
    condition: "if function login() is called"
    patch: "mov eax, 1; ret"
```

Load a custom rule set:

```bash
./nimguard target_binary.exe --rules my_rules.yaml
```

### Live Monitoring

To enable live monitoring and logging:

```bash
./nimguard target_binary.exe --monitor
```

This mode will attach runtime hooks to the binary and provide insights into function calls, arguments, and memory access.

---

## Development Roadmap

### Phase 1: Initial Functionality

✅ Implement binary analysis with Capstone.

✅ Develop basic runtime patching with Keystone.

✅ Set up instrumentation hooks for logging.

✅ Create rule-based patching system.

### Phase 2: Advanced Features

⏳ Add interactive shell for manual patching.

⏳ Implement a rollback mechanism for safe patching.

⏳ Support for ELF, PE, and Mach-O binaries.

⏳ Create a Web UI for real-time patching and monitoring.

⏳ Add stealth mode to evade anti-tampering mechanisms.

---

## Contributing

We welcome contributions! Follow these steps to contribute:

1. Fork the repository

2. Create a feature branch: `git checkout -b my-new-feature`

3. Commit your changes: `git commit -m "Add my feature"`

4. Push to the branch: `git push origin my-new-feature`

5. Submit a pull request

For major changes, please open an issue first to discuss your proposal.

---

## Legal Disclaimer

⚠ Use this tool only in a controlled and legal environment.
NimGuard is designed for research, security analysis, and ethical hacking purposes.
Misuse of this software in unauthorized systems may violate laws and regulations.