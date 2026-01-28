@echo off
REM ============================================================================
REM ShadowStrike Driver Installation Script
REM ============================================================================
REM
REM Installs the ShadowStrike minifilter driver.
REM Must be run as Administrator.
REM
REM Prerequisites:
REM   - Driver is built and signed (test or production)
REM   - Test signing enabled if using test certificate
REM
REM ============================================================================

setlocal enabledelayedexpansion

set CONFIG=%1
set PLATFORM=%2

if "%CONFIG%"=="" set CONFIG=Debug
if "%PLATFORM%"=="" set PLATFORM=x64

set DRIVER_NAME=ShadowStrikeFlt
set DRIVER_PATH=%~dp0..\bin\%PLATFORM%\%CONFIG%\%DRIVER_NAME%.sys
set DEST_PATH=%SystemRoot%\System32\drivers\%DRIVER_NAME%.sys

echo.
echo ============================================================================
echo  ShadowStrike Driver Installation
echo ============================================================================
echo.

REM Check for admin privileges
net session >nul 2>&1
if %ERRORLEVEL% neq 0 (
    echo ERROR: This script must be run as Administrator.
    echo        Right-click and select "Run as administrator"
    exit /b 1
)

REM Check if driver file exists
if not exist "%DRIVER_PATH%" (
    echo ERROR: Driver not found: %DRIVER_PATH%
    echo        Please build the driver first.
    exit /b 1
)

echo Step 1: Stopping existing driver (if running)...
echo.

sc stop %DRIVER_NAME% >nul 2>&1
fltmc unload %DRIVER_NAME% >nul 2>&1

REM Wait for driver to stop
timeout /t 2 /nobreak >nul

echo Step 2: Removing existing driver service (if exists)...
echo.

sc delete %DRIVER_NAME% >nul 2>&1

echo Step 3: Copying driver file...
echo.

copy /Y "%DRIVER_PATH%" "%DEST_PATH%"
if %ERRORLEVEL% neq 0 (
    echo ERROR: Failed to copy driver file
    exit /b 1
)

echo Step 4: Creating driver service...
echo.

sc create %DRIVER_NAME% ^
    type= filesys ^
    start= boot ^
    error= normal ^
    binPath= "%DEST_PATH%" ^
    group= "FSFilter Activity Monitor" ^
    DisplayName= "ShadowStrike Minifilter"

if %ERRORLEVEL% neq 0 (
    echo ERROR: Failed to create service
    exit /b 1
)

echo Step 5: Configuring minifilter registry settings...
echo.

REM Add minifilter instance configuration
reg add "HKLM\SYSTEM\CurrentControlSet\Services\%DRIVER_NAME%\Instances" /v "DefaultInstance" /t REG_SZ /d "ShadowStrike Instance" /f >nul
reg add "HKLM\SYSTEM\CurrentControlSet\Services\%DRIVER_NAME%\Instances\ShadowStrike Instance" /v "Altitude" /t REG_SZ /d "328451" /f >nul
reg add "HKLM\SYSTEM\CurrentControlSet\Services\%DRIVER_NAME%\Instances\ShadowStrike Instance" /v "Flags" /t REG_DWORD /d 0 /f >nul

echo Step 6: Loading driver...
echo.

fltmc load %DRIVER_NAME%
if %ERRORLEVEL% neq 0 (
    echo WARNING: Failed to load driver with fltmc
    echo          Trying sc start...
    sc start %DRIVER_NAME%
)

echo.
echo Step 7: Verifying installation...
echo.

fltmc | findstr /i %DRIVER_NAME%
if %ERRORLEVEL% neq 0 (
    echo WARNING: Driver may not be loaded. Check Event Viewer for errors.
) else (
    echo Driver is loaded and running!
)

echo.
echo ============================================================================
echo  INSTALLATION COMPLETE
echo ============================================================================
echo.
echo To verify the driver is working:
echo   1. Run: fltmc
echo   2. Look for ShadowStrikeFlt at altitude 328451
echo.
echo To view driver debug output:
echo   1. Install DebugView from Sysinternals
echo   2. Run as Administrator
echo   3. Enable "Capture Kernel" and "Enable Verbose Kernel Output"
echo.
echo ============================================================================

exit /b 0
