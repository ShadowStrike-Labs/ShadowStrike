@echo off
REM ShadowStrike Phantom Home - VM diagnostics collector.
REM Dumps everything needed to figure out why the service/tray/UI is unhappy.

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

set "HERE=%~dp0"
set "OUT=%HERE%diagnostics"
set "DST=%ProgramFiles%\ShadowStrike\Phantom"

if exist "%OUT%" rd /s /q "%OUT%"
mkdir "%OUT%" >nul 2>&1

echo === Collecting diagnostics to %OUT% ===

echo [1] OS + boot config...
systeminfo                    > "%OUT%\00_systeminfo.txt" 2>&1
bcdedit /enum {current}       > "%OUT%\00_bcdedit.txt"    2>&1

echo [2] Install tree...
dir /s /b "%DST%"             > "%OUT%\10_install_tree.txt" 2>&1
where /r "%DST%" *.dll *.exe *.sys *.qml *.qrc > "%OUT%\10_install_files.txt" 2>&1

echo [3] Service state + recent history...
sc query  ShadowStrikePhantomService > "%OUT%\20_sc_query.txt"  2>&1
sc qc     ShadowStrikePhantomService > "%OUT%\20_sc_qc.txt"     2>&1
sc qfailure ShadowStrikePhantomService > "%OUT%\20_sc_qfailure.txt" 2>&1
sc qprivs ShadowStrikePhantomService > "%OUT%\20_sc_qprivs.txt" 2>&1

echo [4] Kernel driver state...
fltmc filters                  > "%OUT%\30_fltmc_filters.txt" 2>&1
fltmc instances                > "%OUT%\30_fltmc_instances.txt" 2>&1
pnputil /enum-drivers          > "%OUT%\30_pnputil_drivers.txt" 2>&1

echo [5] Running processes...
tasklist /v /fi "IMAGENAME eq ShadowStrikePhantom*" > "%OUT%\40_tasklist.txt" 2>&1

echo [6] Pipe enumeration - shows whether service is actually serving UI IPC...
powershell -NoProfile -Command ^
    "Get-ChildItem '\\.\pipe\' | Where-Object {$_.Name -like '*ShadowStrike*' -or $_.Name -like '*Phantom*'} | Select-Object Name | Format-Table -AutoSize" ^
    > "%OUT%\41_named_pipes.txt" 2>&1

echo [7] Session state...
query session                  > "%OUT%\42_sessions.txt" 2>&1

echo [8] Defender state (should be all False if 00_disable_defender.bat worked)...
powershell -NoProfile -Command ^
    "Get-MpComputerStatus | Select-Object RealTimeProtectionEnabled,AntivirusEnabled,AMServiceEnabled,IoavProtectionEnabled,BehaviorMonitorEnabled,OnAccessProtectionEnabled,TamperProtectionSource | Format-List" ^
    > "%OUT%\50_defender.txt" 2>&1

echo [9] Event log - Application + System errors/warnings for ShadowStrike...
powershell -NoProfile -Command ^
    "Get-WinEvent -FilterHashtable @{LogName='Application';Level=1,2,3;StartTime=(Get-Date).AddDays(-2)} -ErrorAction SilentlyContinue | Where-Object {$_.ProviderName -match 'ShadowStrike' -or $_.Message -match 'ShadowStrike'} | Select-Object TimeCreated,LevelDisplayName,ProviderName,Id,Message | Format-List" ^
    > "%OUT%\60_evt_application.txt" 2>&1
powershell -NoProfile -Command ^
    "Get-WinEvent -FilterHashtable @{LogName='System';Level=1,2,3;StartTime=(Get-Date).AddDays(-2)} -ErrorAction SilentlyContinue | Where-Object {$_.Message -match 'ShadowStrike' -or $_.Message -match 'Phantom'} | Select-Object TimeCreated,LevelDisplayName,ProviderName,Id,Message | Format-List" ^
    > "%OUT%\60_evt_system.txt" 2>&1

echo [10] Crash minidumps...
if exist "%ProgramData%\Microsoft\Windows\WER\ReportQueue" (
    robocopy "%ProgramData%\Microsoft\Windows\WER\ReportQueue" "%OUT%\wer" /E /NFL /NDL /NJH /NJS >nul
)
if exist "C:\Windows\Minidump" (
    robocopy "C:\Windows\Minidump" "%OUT%\minidump" /NFL /NDL /NJH /NJS >nul
)

echo [11] ShadowStrike-written logs (if any)...
if exist "%ProgramData%\ShadowStrike" (
    robocopy "%ProgramData%\ShadowStrike" "%OUT%\programdata_shadowstrike" /E /NFL /NDL /NJH /NJS >nul
)

echo [12] Standalone service smoke test - console run...
REM Launch the service EXE directly in the console with a short timeout. If
REM it crashes immediately, we capture the exit code + any stderr. This runs
REM as LocalAdmin, NOT LocalSystem - so orch failures unique to SYSTEM won't
REM show up - but DLL-load and import failures will.
pushd "%DST%" >nul 2>&1
if not errorlevel 1 (
    (start "SmokeTest" /b "%DST%\ShadowStrikePhantomService.exe" smoke > "%OUT%\70_service_stdout.txt" 2>&1)
    timeout /t 3 /nobreak >nul
    taskkill /f /im ShadowStrikePhantomService.exe >nul 2>&1
    popd >nul
)

echo [13] UI smoke test - direct launch + capture...
start "" /b "%DST%\ShadowStrikePhantomUI.exe"
timeout /t 3 /nobreak >nul
tasklist /fi "IMAGENAME eq ShadowStrikePhantomUI.exe" > "%OUT%\71_ui_running.txt"
REM Set QT_DEBUG_PLUGINS=1 before re-running UI for full plugin diagnostics.
taskkill /f /im ShadowStrikePhantomUI.exe >nul 2>&1

echo.
echo Done. Zip %OUT% and send it back.
explorer "%OUT%"
pause
endlocal
