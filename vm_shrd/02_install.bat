@echo off
REM =====================================================================
REM ShadowStrike Phantom Home - VM installer (XCOPY + SCM; no MSI).
REM =====================================================================
setlocal ENABLEDELAYEDEXPANSION

net session >nul 2>&1
if errorlevel 1 (
    echo.
    echo This script needs Administrator rights.
    echo A UAC prompt will appear; click YES.
    echo.
    powershell -NoProfile -Command "try { Start-Process -FilePath 'cmd.exe' -ArgumentList '/k','\"%~f0\"' -Verb RunAs -ErrorAction Stop } catch { Write-Host ('[elevate] failed: ' + $_.Exception.Message); exit 1 }"
    if errorlevel 1 (
        echo.
        echo [!] Elevation was cancelled or denied. Nothing was done.
        pause
    )
    exit /b 0
)

set "HERE=%~dp0"
set "SRC=%HERE%payload\app"
set "DST=%ProgramFiles%\ShadowStrike\Phantom"
set "SVC=ShadowStrikePhantomService"

if not exist "%SRC%\ShadowStrikePhantomService.exe" (
    echo [!] payload\app not found next to this script.
    echo     Expected: %SRC%
    pause
    exit /b 1
)

echo.
echo === ShadowStrike Phantom Home - installer ===
echo Source : %SRC%
echo Target : %DST%
echo.

REM ---- Sanity: test mode must be on (driver is test-signed) --------------
bcdedit /enum {current} | findstr /I "testsigning" | findstr /I "Yes" >nul 2>&1
if errorlevel 1 (
    echo [!] Kernel TESTSIGNING is OFF. Run 01_prepare_vm.bat, reboot, then
    echo     try again. The minifilter will not load without it.
    pause
    exit /b 1
)

echo [1/7] Tearing down any previous install...
fltmc detach ShadowStrikePhantomSensor >nul 2>&1
fltmc unload ShadowStrikePhantomSensor >nul 2>&1
sc stop %SVC% >nul 2>&1
timeout /t 2 /nobreak >nul
sc query %SVC% >nul 2>&1
if not errorlevel 1 sc delete %SVC% >nul 2>&1
taskkill /f /im ShadowStrikePhantomService.exe >nul 2>&1
taskkill /f /im ShadowStrikePhantomTray.exe    >nul 2>&1
taskkill /f /im ShadowStrikePhantomUI.exe      >nul 2>&1
taskkill /f /im msiexec.exe                    >nul 2>&1

echo [2/7] Deploying files to %DST% ...
if not exist "%DST%" mkdir "%DST%" >nul 2>&1
robocopy "%SRC%" "%DST%" /E /MT:8 /R:2 /W:2 /NFL /NDL /NJH /NJS /NC /NS /NP
set RC=%ERRORLEVEL%
if %RC% geq 8 (
    echo [!] robocopy reported errors exit=%RC%. Aborting.
    pause
    exit /b 2
)

echo [3/7] Registering Windows service %SVC% ...
sc create %SVC% binPath= "\"%DST%\ShadowStrikePhantomService.exe\"" start= auto type= own DisplayName= "ShadowStrike Phantom Service"
if errorlevel 1 (
    echo [!] sc create failed. gle=%errorlevel%
    pause
    exit /b 3
)
sc description %SVC% "Provides ShadowStrike Phantom Home real-time protection, scanning, and telemetry." >nul
sc failure     %SVC% reset= 86400 actions= restart/60000/restart/60000/run/0 >nul

echo [4/7] Registering tray autostart...
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" /v ShadowStrikePhantomTray /t REG_SZ /d "\"%DST%\ShadowStrikePhantomTray.exe\"" /f >nul

echo [5/7] Creating Start-menu shortcut...
powershell -NoProfile -Command "$s=(New-Object -ComObject WScript.Shell).CreateShortcut('%ProgramData%\Microsoft\Windows\Start Menu\Programs\ShadowStrike Phantom.lnk'); $s.TargetPath='%DST%\ShadowStrikePhantomUI.exe'; $s.WorkingDirectory='%DST%'; $s.IconLocation='%DST%\ShadowStrikePhantomUI.exe,0'; $s.Save()" >nul 2>&1

echo [6/7] Starting service...
sc start %SVC%
set TRIES=0
:wait_running
timeout /t 1 /nobreak >nul
sc query %SVC% | findstr /I "RUNNING" >nul
if not errorlevel 1 goto running
set /a TRIES+=1
if !TRIES! lss 20 goto wait_running
echo [!] Service did not reach RUNNING within 20 s. Current state:
sc query %SVC%
echo.
echo     Last ShadowStrike events from Application log:
powershell -NoProfile -Command "Get-WinEvent -LogName Application -MaxEvents 200 -ErrorAction SilentlyContinue | Where-Object {$_.ProviderName -match 'ShadowStrike' -or $_.Message -match 'ShadowStrike'} | Select-Object -First 10 TimeCreated,LevelDisplayName,Message | Format-List"
echo     Run 04_collect_diagnostics.bat and send back diagnostics\.
goto driver
:running
echo     OK: service is RUNNING.

:driver
echo [7/7] Installing minifilter driver...
if exist "%DST%\Drivers\PhantomSensor.inf" (
    pnputil /add-driver "%DST%\Drivers\PhantomSensor.inf" /install
    fltmc load ShadowStrikePhantomSensor
    echo.
    fltmc filters | findstr /I "ShadowStrikePhantomSensor"
) else (
    echo     ^(no driver payload found at %DST%\Drivers; skipping^)
)

echo.
echo Launching tray for current session...
start "" "%DST%\ShadowStrikePhantomTray.exe"

echo.
echo ============================================================
echo Install complete.
echo   Service  : %DST%\ShadowStrikePhantomService.exe  (%SVC%)
echo   Tray     : autostart + just launched
echo   UI       : %DST%\ShadowStrikePhantomUI.exe
echo   Driver   : ShadowStrikePhantomSensor
echo ============================================================
echo.
echo Right-click the tray icon - "Open Dashboard" to launch the UI.
echo If the UI still does not open, run 04_collect_diagnostics.bat.
echo.
pause
endlocal
