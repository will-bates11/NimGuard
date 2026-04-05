@echo off
rem Demo: disassemble the .text section of a binary using Capstone.
rem Requires capstone.dll to be present in the repo root directory.
rem
rem Usage: disassemble_section.bat [binary]

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

echo Disassembling .text section of: %TARGET%
echo ---------------------------------------
"%NIMGUARD%" "%TARGET%" --disasm
