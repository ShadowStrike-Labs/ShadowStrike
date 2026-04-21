@echo off
REM =====================================================================
REM ShadowStrike Phantom Home - uninstaller.
REM =====================================================================
setlocal ENABLEDELAYEDEXPANSION

set "STAGE=%LOCALAPPDATA%\ShadowStrike-Install"
if /I "%~dp0"=="%STAGE%\" goto local

echo [stage] Copying to %STAGE% ...
if not exist "%STAGE%" mkdir "%STAGE%" 2>nul
for %%F in ("%~dp0*.bat" "%~dp0README.txt") do (
    if exist %%F copy /y %%F "%STAGE%\" >nul 2>&1
)
echo [stage] Re-launching from local copy ...
start "ShadowStrike Phantom" cmd /k "\"%STAGE%\%~nx0\""
exit /b 0

:local
net session >nul 2>&1
if errorlevel 1 (
    echo.
    echo [elevate] Re-launching with Administrator rights. Click YES on the UAC prompt.
    powershell -NoProfile -Command "try { Start-Process -FilePath 'cmd.exe' -ArgumentList ('/k','\"%~f0\"') -Verb RunAs -ErrorAction Stop } catch { Write-Host ('[elevate] failed: ' + $_.Exception.Message) ; exit 1 }"
    if errorlevel 1 (
        echo.
        echo [!] UAC was cancelled. Nothing was done.
        pause
    )
    exit /b 0
)

set "DST=%ProgramFiles%\ShadowStrike\Phantom"
set "SVC=ShadowStrikePhantomService"

echo === ShadowStrike Phantom Home - uninstall ===

echo [1/6] Stopping tray / UI / service ...
taskkill /f /im ShadowStrikePhantomTray.exe >nul 2>&1
taskkill /f /im ShadowStrikePhantomUI.exe   >nul 2>&1
sc stop %SVC% >nul 2>&1
timeout /t 2 /nobreak >nul

echo [2/6] Unloading minifilter driver ...
fltmc detach ShadowStrikePhantomSensor >nul 2>&1
fltmc unload ShadowStrikePhantomSensor >nul 2>&1

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
