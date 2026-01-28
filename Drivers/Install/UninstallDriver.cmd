@echo off
REM ============================================================================
REM ShadowStrike Driver Uninstallation Script
REM ============================================================================
REM
REM Completely removes the ShadowStrike minifilter driver.
REM Must be run as Administrator.
REM
REM ============================================================================

setlocal

set DRIVER_NAME=ShadowStrikeFlt
set DRIVER_PATH=%SystemRoot%\System32\drivers\%DRIVER_NAME%.sys

echo.
echo ============================================================================
echo  ShadowStrike Driver Uninstallation
echo ============================================================================
echo.

REM Check for admin privileges
net session >nul 2>&1
if %ERRORLEVEL% neq 0 (
    echo ERROR: This script must be run as Administrator.
    exit /b 1
)

echo Step 1: Unloading driver from Filter Manager...
echo.

fltmc unload %DRIVER_NAME%
if %ERRORLEVEL% equ 0 (
    echo Driver unloaded from Filter Manager
) else (
    echo Driver was not loaded or already unloaded
)

echo.
echo Step 2: Stopping driver service...
echo.

sc stop %DRIVER_NAME% >nul 2>&1

REM Wait for driver to fully stop
timeout /t 3 /nobreak >nul

echo Step 3: Deleting driver service...
echo.

sc delete %DRIVER_NAME%
if %ERRORLEVEL% equ 0 (
    echo Service deleted successfully
) else (
    echo Service was not found or already deleted
)

echo.
echo Step 4: Removing driver file...
echo.

if exist "%DRIVER_PATH%" (
    del /f "%DRIVER_PATH%"
    if %ERRORLEVEL% equ 0 (
        echo Driver file removed
    ) else (
        echo WARNING: Could not remove driver file. It may be in use.
        echo          A reboot may be required.
    )
) else (
    echo Driver file not found (already removed)
)

echo.
echo Step 5: Cleaning up registry...
echo.

reg delete "HKLM\SYSTEM\CurrentControlSet\Services\%DRIVER_NAME%" /f >nul 2>&1

echo.
echo ============================================================================
echo  UNINSTALLATION COMPLETE
echo ============================================================================
echo.
echo The driver has been removed. If you see any warnings above about
echo files in use, please reboot the system to complete the removal.
echo.
echo ============================================================================

exit /b 0
