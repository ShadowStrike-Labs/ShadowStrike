@echo off
REM =====================================================================
REM ShadowStrike Phantom Home - VM prep (USER-MODE ONLY).
REM
REM This used to enable kernel TESTSIGNING so the minifilter driver
REM would load. That also forces Windows 11 to fall back to the generic
REM display adapter (1024x768, resolution cannot be changed), which
REM most users do not want. By default we no longer touch test-signing
REM here - the Home product runs entirely in user mode.
REM
REM If you specifically want to test the kernel sensor driver, run
REM 05_enable_driver_dev.bat instead of this script.
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
echo === ShadowStrike Phantom Home - VM prep ===
echo.
echo [1/2] Relaxing UAC prompt level (less noisy during testing) ...
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v ConsentPromptBehaviorAdmin /t REG_DWORD /d 0 /f >nul 2>&1

echo [2/2] Verifying display flags are safe (test-signing should be OFF) ...
bcdedit /enum {current} | findstr /I "testsigning nointegritychecks"
echo.
echo If you see "testsigning Yes" above and your screen is stuck at
echo 1024x768, run 00a_fix_resolution.bat then reboot.

echo.
echo ============================================================
echo Prep done. Next steps:
echo   1) 00_disable_defender.bat    ^(Tamper Protection must be OFF^)
echo   2) reboot
echo   3) 02_install.bat
echo ============================================================
pause
exit /b 0
