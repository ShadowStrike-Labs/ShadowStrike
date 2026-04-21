@echo off
REM =====================================================================
REM ShadowStrike Phantom Home - OPTIONAL driver developer mode.
REM
REM Only needed if you specifically want to load the unsigned test
REM build of the PhantomSensor minifilter. WARNING: on Windows 11 this
REM usually forces the desktop into 1024x768 generic display mode until
REM you run 00a_fix_resolution.bat again. Use a snapshot.
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
echo === ShadowStrike Phantom Home - enable driver dev mode ===
echo.
echo WARNING: this will change the display adapter to generic and drop
echo          resolution to 1024x768 on most Windows 11 builds. Make
echo          sure you have a VM snapshot before proceeding.
echo.
choice /C YN /M "Continue"
if errorlevel 2 exit /b 0

bcdedit /set testsigning on
echo.
echo ============================================================
echo Test-signing enabled. REBOOT the VM, then run 02_install.bat.
echo When done, run 00a_fix_resolution.bat to restore the display.
echo ============================================================
pause
exit /b 0
