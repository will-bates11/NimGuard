@echo off
rem Demo: emulate the .text section of a binary through Unicorn.
rem
rem Unicorn loads the raw .text bytes into a minimal CPU emulator and runs
rem up to 256 instructions. Real-world binaries stop early because they
rem reference memory not mapped in the emulator, which is expected.
rem
rem Usage: emulate_code.bat [binary]

setlocal

set "SCRIPT_DIR=%~dp0"
set "REPO_ROOT=%SCRIPT_DIR%.."

if exist "%REPO_ROOT%\nimguard.exe" (
    set "NIMGUARD=%REPO_ROOT%\nimguard.exe"
) else (
    echo [-] nimguard.exe not found. Build it first: nim c -d:release src\nimguard.nim
    exit /b 1
)

if not "%~1"=="" (
    set "TARGET=%~1"
) else if exist "%SCRIPT_DIR%test_binary.exe" (
    set "TARGET=%SCRIPT_DIR%test_binary.exe"
) else (
    echo [-] No target binary found.
    echo     Compile the demo binary first:
    echo       nim c -d:release -o:demos\test_binary.exe demos\create_test_binary.nim
    exit /b 1
)

echo Emulating .text section of: %TARGET%
echo ---------------------------------------
"%NIMGUARD%" "%TARGET%" --emulate
