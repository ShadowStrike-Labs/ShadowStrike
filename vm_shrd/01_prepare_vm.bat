@echo off
REM =====================================================================
REM ShadowStrike Phantom Home - VM prep: enable TESTSIGNING so the driver
REM can load. Reboot REQUIRED afterwards.
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
echo [1/2] Enabling kernel TESTSIGNING (required for the test-signed driver)...
bcdedit /set testsigning on
if errorlevel 1 (
    echo [!] bcdedit failed. You may need to disable Secure Boot in the VM firmware.
    pause
    exit /b 1
)

echo [2/2] Relaxing UAC prompt level (optional, makes testing less noisy)...
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v ConsentPromptBehaviorAdmin /t REG_DWORD /d 0 /f >nul 2>&1

echo.
echo ============================================================
echo Prep done. REBOOT the VM now.
echo After reboot the desktop will show "Test Mode" watermark.
echo Then run 00_disable_defender.bat (if Tamper Protection is off),
echo followed by 02_install.bat.
echo ============================================================
pause
exit /b 0
