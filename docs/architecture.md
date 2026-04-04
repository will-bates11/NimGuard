# NimGuard System Architecture Document

## 1. Overview

NimGuard is a dynamic binary patching and instrumentation tool designed to analyze, modify, and monitor executable binaries without requiring source code access. It integrates disassembly, runtime patching, and behavior monitoring into a flexible system that can be used for security research, vulnerability mitigation, and reverse engineering.

The core architecture consists of three main components:

1. Binary Analysis & Disassembly (Capstone)
2. Dynamic Patching (Keystone)
3. Runtime Instrumentation & Hooking (Unicorn)

## 2. High-Level Architecture

NimGuard is structured into modular components to facilitate extensibility and performance while maintaining a clear separation of concerns.

```
+------------------------------------------+
|                NimGuard                   |
+------------------------------------------+
|      Command Line Interface (CLI)         |
+------------------------------------------+
|          Rule-Based Patch Engine          |
+------------------------------------------+
| Binary Analysis | Dynamic Patching | Instrumentation  |
|   (Capstone)    |    (Keystone)    |    (Unicorn)     |
+------------------------------------------+
|           Memory & Execution Hooks        |
+------------------------------------------+
|        Operating System Kernel API        |
+------------------------------------------+
```

Each major component plays a critical role in the system's operation.

## 3. Component Breakdown

### 3.1. Binary Analysis (Capstone)

NimGuard uses the Capstone disassembly engine to analyze binaries at runtime. The key responsibilities of this module include:

- Parsing binary files (ELF, PE, Mach-O)
- Identifying function entry points
- Recognizing known vulnerability patterns (e.g., unsafe strcpy, gets)
- Extracting control flow and call graphs

#### Workflow

1. Load the binary into memory
2. Identify function entry points
3. Disassemble functions and extract assembly instructions
4. Store results for further analysis

### 3.2. Dynamic Patching (Keystone)

Patching is handled via the Keystone assembler, which allows NimGuard to generate custom assembly instructions dynamically.

#### Patching Methods

1. Inline Code Replacement
   - Replace vulnerable instructions with safer alternatives (e.g., mov eax, 0 to bypass an authentication check)

2. NOP Sled Injection
   - Neutralize functions by inserting nop (no-operation) instructions

3. Code Cave Injection
   - Insert custom payloads in unused binary regions

4. Function Hooking
   - Redirect function calls to custom handlers

#### Example Workflow

1. Identify a vulnerable function (e.g., buffer overflow in main)
2. Generate replacement instructions using Keystone
3. Overwrite original instructions with patched code
4. Verify execution correctness via instrumentation

### 3.3. Runtime Instrumentation (Unicorn)

Instrumentation is achieved using the Unicorn emulator and low-level OS hooks.

#### Instrumentation Features

- Function Call Monitoring: Logs API calls and function parameters
- Memory Access Tracking: Detects suspicious reads/writes
- Execution Flow Analysis: Identifies control flow anomalies

#### Example Use Case

If an authentication function receives user input and returns a boolean, an instrumentation hook could log the return value before it is used in decision-making.

## 4. Rule-Based Patching Engine

NimGuard enables users to define custom patching rules using a simple YAML-based DSL.

### Example Rule Definition

```yaml
rules:
  - identifier: "auth_bypass"
    description: "Bypass authentication check"
    condition: "if function login() is called"
    patch: "mov eax, 1; ret"
```

### Rule Execution Flow

1. Parse Rules → Load YAML-based rule set
2. Apply Conditions → Check if function matches a rule
3. Generate Patch → Assemble new instructions with Keystone
4. Inject Patch → Apply changes dynamically
5. Monitor Execution → Verify patched function behavior

## 5. CLI and Configuration

The CLI provides multiple options to interact with NimGuard:

```bash
./nimguard target_binary.exe --analyze
./nimguard target_binary.exe --patch --rules custom_rules.yaml
./nimguard target_binary.exe --monitor
```

## 6. Memory and Execution Hooks

NimGuard interacts with the OS through low-level system calls for:

- Attaching to running processes
- Modifying executable memory regions
- Injecting and executing code dynamically

### Security and Rollback

To prevent system instability:

- All patches are reversible: NimGuard stores original instructions
- Patch verification: Ensures modified code does not crash the binary
- Safe mode: Allows dry-run patching to test changes before committing

## 7. Future Enhancements

### Phase 2: Advanced Features

- Automated Exploit Prevention: Use AI/ML for automatic vulnerability detection
- Web Dashboard for Monitoring: A lightweight interface to visualize execution logs
- Stealth Mode: Evade anti-tamper mechanisms for advanced security research
- Cross-Platform Enhancements: Improve compatibility with more architectures

## 8. Conclusion

NimGuard is designed to bridge the gap between static binary analysis and real-time security instrumentation. By combining disassembly, runtime patching, and execution monitoring, it provides a powerful toolkit for security researchers and reverse engineers working with legacy and closed-source binaries.

> ⚠ Warning: This tool should only be used in legally authorized environments. Unauthorized patching may violate software agreements and security policies.