@echo off
REM =====================================================================
REM ShadowStrike Phantom Home - RESOLUTION / DISPLAY FIX
REM
REM On Windows 11, enabling kernel test-signing makes Windows fall back
REM to the Microsoft Basic Display adapter and locks the screen to
REM 1024x768. This script turns test-signing + related flags OFF so the
REM real GPU driver loads again.
REM
REM You lose the ability to load unsigned kernel drivers (the minifilter
REM sensor) -- the user-mode product still works fully without it.
REM To re-enable driver testing later use 05_enable_driver_dev.bat.
REM =====================================================================
setlocal ENABLEDELAYEDEXPANSION

set "STAGE=%LOCALAPPDATA%\ShadowStrike-Install"
if /I "%~dp0"=="%STAGE%\" goto staged

echo [stage] Copying to %STAGE% ...
if not exist "%STAGE%" mkdir "%STAGE%" 2>nul
for %%F in ("%~dp0*.bat" "%~dp0README.txt") do (
    if exist %%F copy /y %%F "%STAGE%\" >nul 2>&1
)
echo [stage] Launching local copy in a new window ...
start "ShadowStrike Phantom" cmd /k ""%STAGE%\%~nx0""
exit /b 0

:staged
net session >nul 2>&1
if not errorlevel 1 goto body

set "SELF=%~f0"
echo.
echo [elevate] Requesting Administrator rights. Click YES on the UAC prompt.
powershell -NoProfile -Command "try { Start-Process -FilePath cmd -Verb RunAs -ArgumentList ('/k ""' + $env:SELF + '""') -ErrorAction Stop } catch { Write-Host ('[elevate] ' + $_.Exception.Message); exit 1 }"
if errorlevel 1 (
    echo.
    echo [!] UAC cancelled or failed. Nothing was done.
    pause
)
exit /b 0

:body
echo === ShadowStrike Phantom Home - restore display ===
echo.
echo [1/3] Disabling kernel test-signing ...
bcdedit /set testsigning off
echo [2/3] Re-enabling kernel integrity checks ...
bcdedit /deletevalue nointegritychecks >nul 2>&1
bcdedit /deletevalue isolatedcontext   >nul 2>&1
echo [3/3] Current boot flags:
bcdedit /enum {current} | findstr /I "testsigning nointegritychecks isolatedcontext"

echo.
echo ============================================================
echo Done. REBOOT THE VM now.
echo After reboot you can change the screen resolution normally
echo from Settings - System - Display.
echo ============================================================
pause
exit /b 0
