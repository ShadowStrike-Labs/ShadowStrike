@echo off
REM ShadowStrike Phantom Home - uninstaller for the manual (XCOPY) install.

setlocal

net session >nul 2>&1
if errorlevel 1 (
    echo.
    echo This script needs Administrator rights.
    echo A UAC prompt will appear; click YES.
    echo.
    powershell -NoProfile -Command "$p='%~f0'; if ($p -match '^([A-Za-z]):') { $d = Get-PSDrive $matches[1] -ErrorAction SilentlyContinue; if ($d -and $d.DisplayRoot) { $p = $d.DisplayRoot + $p.Substring(2) } }; try { Start-Process -FilePath 'cmd.exe' -ArgumentList ('/k','\"' + $p + '\"') -Verb RunAs -ErrorAction Stop } catch { Write-Host ('[elevate] failed: ' + $_.Exception.Message); exit 1 }"
    if errorlevel 1 (
        echo.
        echo [!] Elevation was cancelled or denied. Nothing was done.
        echo     Close this window and try again, clicking YES on the UAC prompt.
        echo.
        pause
    )
    exit /b 0
)

set "DST=%ProgramFiles%\ShadowStrike\Phantom"
set "SVC=ShadowStrikePhantomService"

echo === ShadowStrike Phantom Home - uninstall ===
echo.

echo [1/5] Stopping tray / UI / service...
taskkill /f /im ShadowStrikePhantomTray.exe >nul 2>&1
taskkill /f /im ShadowStrikePhantomUI.exe   >nul 2>&1
sc stop %SVC% >nul 2>&1
timeout /t 3 /nobreak >nul
taskkill /f /im ShadowStrikePhantomService.exe >nul 2>&1

echo [2/5] Unloading minifilter...
fltmc detach ShadowStrikePhantomSensor >nul 2>&1
fltmc unload ShadowStrikePhantomSensor >nul 2>&1

echo [3/5] Deleting driver package...
for /f "tokens=4" %%A in ('pnputil /enum-drivers ^| findstr /I "PhantomSensor.inf"') do pnputil /delete-driver %%A /uninstall /force >nul 2>&1

echo [4/5] Removing service + autostart...
sc delete %SVC% >nul 2>&1
reg delete "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" /v ShadowStrikePhantomTray /f >nul 2>&1
del /q "%ProgramData%\Microsoft\Windows\Start Menu\Programs\ShadowStrike Phantom.lnk" >nul 2>&1

echo [5/5] Removing files...
if exist "%DST%" rd /s /q "%DST%"
rd /q "%ProgramFiles%\ShadowStrike" >nul 2>&1

echo.
echo Uninstall complete.
pause
endlocal
