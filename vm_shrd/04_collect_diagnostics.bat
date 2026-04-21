@echo off
REM =====================================================================
REM ShadowStrike Phantom Home - diagnostics collector.
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

set "HERE=%~dp0"
set "OUT=%HERE%diagnostics"
set "DST=%ProgramFiles%\ShadowStrike\Phantom"

if exist "%OUT%" rd /s /q "%OUT%"
mkdir "%OUT%" >nul 2>&1

echo === ShadowStrike diagnostics -^> %OUT% ===

echo [1/8] System info ...
systeminfo > "%OUT%\systeminfo.txt" 2>&1
bcdedit /enum {current} > "%OUT%\bcdedit.txt" 2>&1

echo [2/8] Service state ...
sc query ShadowStrikePhantomService > "%OUT%\service_state.txt" 2>&1
sc qc    ShadowStrikePhantomService >> "%OUT%\service_state.txt" 2>&1
sc queryex ShadowStrikePhantomService >> "%OUT%\service_state.txt" 2>&1

echo [3/8] Filter driver state ...
fltmc filters    > "%OUT%\fltmc.txt" 2>&1
fltmc instances >> "%OUT%\fltmc.txt" 2>&1

echo [4/8] Running processes ...
tasklist /v | findstr /I "ShadowStrike Phantom" > "%OUT%\processes.txt" 2>&1
tasklist /v > "%OUT%\tasklist_all.txt" 2>&1

echo [5/8] Named pipes ...
powershell -NoProfile -Command "Get-ChildItem \\.\pipe\ | Where-Object { $_.Name -match 'ShadowStrike|Phantom' } | Select-Object Name,Length" > "%OUT%\pipes.txt" 2>&1

echo [6/8] Event log (Application + System, ShadowStrike-related) ...
powershell -NoProfile -Command "Get-WinEvent -LogName Application -MaxEvents 500 -ErrorAction SilentlyContinue | Where-Object { $_.ProviderName -match 'ShadowStrike' -or $_.Message -match 'ShadowStrike|Phantom' } | Select-Object -First 100 TimeCreated,LevelDisplayName,ProviderName,Id,Message | Format-List" > "%OUT%\events_application.txt" 2>&1
powershell -NoProfile -Command "Get-WinEvent -LogName System -MaxEvents 500 -ErrorAction SilentlyContinue | Where-Object { $_.Message -match 'ShadowStrike|Phantom' } | Select-Object -First 100 TimeCreated,LevelDisplayName,ProviderName,Id,Message | Format-List" > "%OUT%\events_system.txt" 2>&1

echo [7/8] Defender state ...
powershell -NoProfile -Command "Get-MpComputerStatus | Select RealTimeProtectionEnabled,AntivirusEnabled,AMServiceEnabled,TamperProtected" > "%OUT%\defender.txt" 2>&1

echo [8/8] Install tree directory listing ...
if exist "%DST%" (
    dir /s "%DST%" > "%OUT%\install_tree.txt" 2>&1
) else (
    echo INSTALL TREE MISSING: %DST% > "%OUT%\install_tree.txt"
)

echo.
echo === Diagnostics collected in: %OUT% ===
echo Copy that folder back out of the VM and send it over.
echo.
pause
exit /b 0
