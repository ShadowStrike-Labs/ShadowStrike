@echo off
REM ============================================================================
REM ShadowStrike Driver Build Script
REM ============================================================================
REM
REM Prerequisites:
REM   - Windows Driver Kit (WDK) installed
REM   - Visual Studio 2022 with C++ desktop development
REM   - Run from Developer Command Prompt or set up environment
REM
REM Usage:
REM   build_all.cmd [Debug|Release] [x64|ARM64]
REM
REM ============================================================================

setlocal enabledelayedexpansion

REM Default configuration
set CONFIG=%1
set PLATFORM=%2

if "%CONFIG%"=="" set CONFIG=Debug
if "%PLATFORM%"=="" set PLATFORM=x64

echo.
echo ============================================================================
echo  ShadowStrike Driver Build
echo ============================================================================
echo  Configuration: %CONFIG%
echo  Platform:      %PLATFORM%
echo ============================================================================
echo.

REM Check for MSBuild
where msbuild >nul 2>&1
if %ERRORLEVEL% neq 0 (
    echo ERROR: MSBuild not found. Please run from Developer Command Prompt.
    echo        Or run: "C:\Program Files\Microsoft Visual Studio\2022\Enterprise\Common7\Tools\VsDevCmd.bat"
    exit /b 1
)

REM Navigate to driver directory
cd /d "%~dp0..\ShadowStrikeFlt"

REM Build the driver
echo Building ShadowStrikeFlt.sys...
echo.

msbuild ShadowStrikeFlt.vcxproj /p:Configuration=%CONFIG% /p:Platform=%PLATFORM% /t:Build /v:minimal

if %ERRORLEVEL% neq 0 (
    echo.
    echo ============================================================================
    echo  BUILD FAILED
    echo ============================================================================
    exit /b 1
)

echo.
echo ============================================================================
echo  BUILD SUCCESSFUL
echo ============================================================================
echo.
echo Output: bin\%PLATFORM%\%CONFIG%\ShadowStrikeFlt.sys
echo.

REM Check if driver was built
set DRIVER_PATH=..\..\bin\%PLATFORM%\%CONFIG%\ShadowStrikeFlt.sys
if exist "%DRIVER_PATH%" (
    echo Driver file exists: %DRIVER_PATH%
) else (
    echo WARNING: Driver file not found at expected location
)

exit /b 0
