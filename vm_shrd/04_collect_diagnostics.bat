@echo off
REM =====================================================================
REM ShadowStrike Phantom Home - diagnostics collector.
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
set "OUT=%STAGE%\diagnostics"
set "DST=%ProgramFiles%\ShadowStrike\Phantom"
set "LOGDIR=%ProgramData%\ShadowStrike\Logs"

if exist "%OUT%" rd /s /q "%OUT%"
mkdir "%OUT%" >nul 2>&1

echo === ShadowStrike diagnostics -^> %OUT% ===

echo [1/10] System info ...
systeminfo > "%OUT%\systeminfo.txt" 2>&1
bcdedit /enum {current} > "%OUT%\bcdedit.txt" 2>&1

echo [2/10] Service state ...
sc query ShadowStrikePhantomService > "%OUT%\service_state.txt" 2>&1
sc qc    ShadowStrikePhantomService >> "%OUT%\service_state.txt" 2>&1
sc queryex ShadowStrikePhantomService >> "%OUT%\service_state.txt" 2>&1

echo [3/10] Filter driver state ...
fltmc filters    > "%OUT%\fltmc.txt" 2>&1
fltmc instances >> "%OUT%\fltmc.txt" 2>&1

echo [4/10] Running processes ...
tasklist /v | findstr /I "ShadowStrike Phantom" > "%OUT%\processes.txt" 2>&1
tasklist /v > "%OUT%\tasklist_all.txt" 2>&1

echo [5/10] Named pipes ...
powershell -NoProfile -Command "Get-ChildItem \\.\pipe\ | Where-Object { $_.Name -match 'ShadowStrike|Phantom' } | Select-Object Name,Length" > "%OUT%\pipes.txt" 2>&1

echo [6/10] Event log (Application + System, ShadowStrike-related) ...
powershell -NoProfile -Command "Get-WinEvent -LogName Application -MaxEvents 500 -ErrorAction SilentlyContinue | Where-Object { $_.ProviderName -match 'ShadowStrike' -or $_.Message -match 'ShadowStrike|Phantom' } | Select-Object -First 100 TimeCreated,LevelDisplayName,ProviderName,Id,Message | Format-List" > "%OUT%\events_application.txt" 2>&1
powershell -NoProfile -Command "Get-WinEvent -LogName System -MaxEvents 500 -ErrorAction SilentlyContinue | Where-Object { $_.Message -match 'ShadowStrike|Phantom' } | Select-Object -First 100 TimeCreated,LevelDisplayName,ProviderName,Id,Message | Format-List" > "%OUT%\events_system.txt" 2>&1

echo [7/10] Service log files ...
if exist "%LOGDIR%" (
    xcopy /s /y "%LOGDIR%\*.*" "%OUT%\service_logs\" >nul 2>&1
    echo Collected logs from %LOGDIR% >> "%OUT%\service_logs\collection_note.txt"
) else (
    echo LOG DIR MISSING: %LOGDIR% > "%OUT%\service_logs_missing.txt"
    echo The service has not yet written any log files, or InitialiseLogger failed. >> "%OUT%\service_logs_missing.txt"
    echo Check that ShadowStrikePhantomService.exe is the build from 2026-04-23 or later. >> "%OUT%\service_logs_missing.txt"
)

REM --- UI error logs live in each interactive user's LOCALAPPDATA. The elevated
REM     console's %LOCALAPPDATA% points at the admin profile, not the user that
REM     actually saw the "Loading protection modules..." UI, so we walk every
REM     user profile on the box and collect whatever is there.
echo [7b/10] UI error logs (per-user) ...
mkdir "%OUT%\ui_logs" >nul 2>&1
for /d %%U in ("%SystemDrive%\Users\*") do (
    if exist "%%U\AppData\Local\ShadowStrike\Phantom\ui_errors.log" (
        copy /y "%%U\AppData\Local\ShadowStrike\Phantom\ui_errors.log" ^
            "%OUT%\ui_logs\%%~nU_ui_errors.log" >nul 2>&1
        echo Collected UI log from user %%~nU >> "%OUT%\ui_logs\collection_note.txt"
    )
)
if not exist "%OUT%\ui_logs\collection_note.txt" (
    echo No ui_errors.log found in any user profile. > "%OUT%\ui_logs\collection_note.txt"
    echo Either the UI has not been launched yet, or the log handler did not initialise. >> "%OUT%\ui_logs\collection_note.txt"
)

echo [8/10] Defender state ...
powershell -NoProfile -Command "Get-MpComputerStatus | Select RealTimeProtectionEnabled,AntivirusEnabled,AMServiceEnabled,TamperProtected" > "%OUT%\defender.txt" 2>&1

echo [9/10] Install tree directory listing ...
if exist "%DST%" (
    dir /s "%DST%" > "%OUT%\install_tree.txt" 2>&1
) else (
    echo INSTALL TREE MISSING: %DST% > "%OUT%\install_tree.txt"
)

echo [10/10] UI startup probe (launch, wait 8s, capture output, kill) ...
if exist "%DST%\ShadowStrikePhantomUI.exe" (
    start /b "" "%DST%\ShadowStrikePhantomUI.exe" > "%OUT%\ui_startup_stdout.txt" 2>&1
    timeout /t 8 /nobreak >nul 2>&1
    taskkill /im ShadowStrikePhantomUI.exe /f >nul 2>&1
    echo UI probe complete. Check ui_startup_stdout.txt >> "%OUT%\ui_startup_stdout.txt"
) else (
    echo UI EXE NOT FOUND at %DST% > "%OUT%\ui_startup_stdout.txt"
)

echo.
echo === Diagnostics collected in: %OUT% ===
echo Copy that folder back out of the VM and send it over.
echo Key files to check:
echo   service_logs\PhantomHome.Service*.log  --  service startup + module init log
echo   ui_logs\*_ui_errors.log                 --  UI-side crash / QML / IPC warnings
echo   ui_startup_stdout.txt                   --  UI connection probe output
echo   pipes.txt                               --  IPC pipe presence
echo   service_state.txt                       --  SCM service state
echo.
pause
exit /b 0
