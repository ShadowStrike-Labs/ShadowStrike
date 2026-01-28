@echo off
REM ============================================================================
REM ShadowStrike Driver Test Signing Script
REM ============================================================================
REM
REM This script creates a test certificate and signs the driver for development.
REM
REM IMPORTANT: Test-signed drivers only work when:
REM   1. Test signing is enabled: bcdedit /set testsigning on
REM   2. System is rebooted after enabling test signing
REM
REM For production, you need an EV certificate from a trusted CA.
REM
REM ============================================================================

setlocal enabledelayedexpansion

set CONFIG=%1
set PLATFORM=%2

if "%CONFIG%"=="" set CONFIG=Debug
if "%PLATFORM%"=="" set PLATFORM=x64

set DRIVER_PATH=..\bin\%PLATFORM%\%CONFIG%\ShadowStrikeFlt.sys
set INF_PATH=..\ShadowStrikeFlt\ShadowStrikeFlt.inf
set CERT_NAME=ShadowStrikeTestCert
set CERT_STORE=PrivateCertStore

echo.
echo ============================================================================
echo  ShadowStrike Driver Test Signing
echo ============================================================================
echo.

REM Check if driver exists
if not exist "%DRIVER_PATH%" (
    echo ERROR: Driver not found: %DRIVER_PATH%
    echo        Please build the driver first using build_all.cmd
    exit /b 1
)

REM Check for signtool
where signtool >nul 2>&1
if %ERRORLEVEL% neq 0 (
    echo ERROR: signtool not found. Please run from WDK Developer Command Prompt.
    exit /b 1
)

REM Check for inf2cat
where inf2cat >nul 2>&1
if %ERRORLEVEL% neq 0 (
    echo WARNING: inf2cat not found. Catalog file will not be created.
    set SKIP_CATALOG=1
)

echo Step 1: Creating test certificate...
echo.

REM Create test certificate if it doesn't exist
makecert -r -pe -ss %CERT_STORE% -n "CN=%CERT_NAME%" %CERT_NAME%.cer >nul 2>&1
if %ERRORLEVEL% neq 0 (
    echo Certificate may already exist, continuing...
)

echo Step 2: Signing driver...
echo.

REM Sign the driver
signtool sign /v /s %CERT_STORE% /n %CERT_NAME% /t http://timestamp.digicert.com "%DRIVER_PATH%"
if %ERRORLEVEL% neq 0 (
    echo ERROR: Failed to sign driver
    exit /b 1
)

echo.
echo Step 3: Verifying signature...
echo.

signtool verify /v /pa "%DRIVER_PATH%"

if not defined SKIP_CATALOG (
    echo.
    echo Step 4: Creating catalog file...
    echo.

    REM Create catalog file
    cd /d "%~dp0..\ShadowStrikeFlt"
    inf2cat /driver:. /os:10_x64 /verbose

    if exist ShadowStrikeFlt.cat (
        echo Signing catalog file...
        signtool sign /v /s %CERT_STORE% /n %CERT_NAME% /t http://timestamp.digicert.com ShadowStrikeFlt.cat
    )
)

echo.
echo ============================================================================
echo  SIGNING COMPLETE
echo ============================================================================
echo.
echo IMPORTANT: To load test-signed drivers, you must:
echo.
echo   1. Enable test signing (run as Administrator):
echo      bcdedit /set testsigning on
echo.
echo   2. Reboot the system
echo.
echo   3. You will see "Test Mode" watermark on desktop
echo.
echo ============================================================================

exit /b 0
