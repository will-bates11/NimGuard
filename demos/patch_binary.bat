@echo off
rem Demo: patch a binary using a rules file.
rem Identifies dangerous imports and applies rules from sample_rules.json,
rem using Keystone to assemble each patch instruction.
rem
rem Usage: patch_binary.bat [binary] [rules_file] [output_file]
rem
rem If no arguments are given, uses test_binary.exe, sample_rules.json, and
rem writes the patched binary to test_binary_patched.exe.

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

if not "%~2"=="" (
    set "RULES=%~2"
) else (
    set "RULES=%SCRIPT_DIR%sample_rules.json"
)

if not exist "%RULES%" (
    echo [-] Rules file not found: %RULES%
    exit /b 1
)

if not "%~3"=="" (
    set "OUTPUT=%~3"
) else (
    set "OUTPUT=%TARGET:~0,-4%_patched.exe"
)

echo Target:  %TARGET%
echo Rules:   %RULES%
echo Output:  %OUTPUT%
echo ---------------------------------------
"%NIMGUARD%" "%TARGET%" --patch --rules "%RULES%" --output "%OUTPUT%"

if exist "%OUTPUT%" (
    echo.
    echo Patch complete. Verifying patched binary:
    "%NIMGUARD%" "%OUTPUT%" --analyze
)
