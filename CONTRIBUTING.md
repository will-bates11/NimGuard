# Contributing to NimGuard

## Building

Requires Nim 2.x. Install with [choosenim](https://github.com/dom96/choosenim).

```bash
nimble build        # produces ./nimguard
```

Optional C libraries (Capstone, Keystone, Unicorn) are needed for disassembly, assembly, and emulation features. See the installation section in [README.md](README.md) for platform-specific instructions. The build succeeds without them; affected features will report that the library is unavailable at runtime.

## Running tests

```bash
nimble test
```

On Windows, the ptrace tests are skipped automatically (they return a platform-not-supported result). On Linux, the Win32 tests are similarly no-ops. The full test suite is expected to pass on both platforms.

If you need to run only the Windows-specific tests:

```bash
nimble test_windows
```

## Code style

Follow standard Nim conventions:

- `camelCase` for procedures and variables
- `PascalCase` for types
- Two-space indentation
- Module doc comment at the top of each file: `# NimGuard - <short description>`
- No trailing whitespace
- Keep procedures focused. If a proc is getting long, split it.

## Adding a feature

1. Open an issue describing the feature before starting work on anything substantial.
2. Create a branch from `main`.
3. Write tests alongside the implementation.
4. Make sure `nimble test` passes on Linux and Windows before opening a pull request.
5. Keep the PR focused. One feature or fix per PR.

## Pull request process

- Target the `main` branch.
- Describe what the change does and why in the PR description.
- If the change affects CLI behaviour, update [README.md](README.md).
- If the change affects module structure, update [docs/architecture.md](docs/architecture.md).

## Reporting bugs

Open an issue with a minimal reproduction case: the command you ran, the binary you ran it on (or a description of the binary format), and the output you got versus what you expected.
