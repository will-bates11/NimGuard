@echo off
rem Demo: analyze a binary and report its format, sections, and dangerous calls.
rem
rem Usage: analyze_binary.bat [binary]
rem   If no binary is given, uses the compiled test_binary.exe from this directory.

setlocal

set "SCRIPT_DIR=%~dp0"
set "REPO_ROOT=%SCRIPT_DIR%.."

rem Locate nimguard.exe
if exist "%REPO_ROOT%\nimguard.exe" (
    set "NIMGUARD=%REPO_ROOT%\nimguard.exe"
) else (
    echo [-] nimguard.exe not found. Build it first: nim c -d:release src\nimguard.nim
    exit /b 1
)

rem Target binary
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

echo Analyzing: %TARGET%
echo ---------------------------------------
"%NIMGUARD%" "%TARGET%" --analyze
