@echo off
REM =====================================================================
REM ShadowStrike Phantom Home - uninstaller.
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
set "DST=%ProgramFiles%\ShadowStrike\Phantom"
set "SVC=ShadowStrikePhantomService"

echo === ShadowStrike Phantom Home - uninstall ===

echo [1/6] Stopping tray / UI / service ...
taskkill /f /im ShadowStrikePhantomTray.exe >nul 2>&1
taskkill /f /im ShadowStrikePhantomUI.exe   >nul 2>&1
sc stop %SVC% >nul 2>&1
timeout /t 2 /nobreak >nul
REM Force-kill stuck service (survives START_PENDING / STOP_PENDING wedges).
for /f "tokens=2" %%P in ('sc queryex %SVC% 2^>nul ^| findstr /I "PID"') do (
    if not "%%P"=="0" (
        echo     Force-killing service PID %%P ...
        taskkill /f /pid %%P >nul 2>&1
    )
)
taskkill /f /im ShadowStrikePhantomService.exe >nul 2>&1

echo [2/6] Unloading minifilter driver ...
fltmc detach PhantomSensor >nul 2>&1
fltmc unload PhantomSensor >nul 2>&1

echo [3/6] Removing driver package ...
for /f "tokens=*" %%P in ('pnputil /enum-drivers ^| findstr /I "PhantomSensor.inf"') do (
    for /f "tokens=3" %%O in ('pnputil /enum-drivers ^| findstr /I /B "Published Name"') do (
        pnputil /delete-driver %%O /force /uninstall >nul 2>&1
    )
)

echo [4/6] Deleting service entry ...
sc delete %SVC% >nul 2>&1

echo [5/6] Removing autostart + Start-menu shortcut ...
reg delete "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" /v ShadowStrikePhantomTray /f >nul 2>&1
del /f /q "%ProgramData%\Microsoft\Windows\Start Menu\Programs\ShadowStrike Phantom.lnk" >nul 2>&1

echo [6/6] Removing install tree %DST% ...
if exist "%DST%" rd /s /q "%DST%" >nul 2>&1

echo.
echo ============================================================
echo Uninstall complete.
echo ============================================================
pause
exit /b 0
