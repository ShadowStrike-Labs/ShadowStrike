@echo off
REM =====================================================================
REM ShadowStrike Phantom Home - neutralise Defender on a VM.
REM Tamper Protection MUST be OFF (Windows Security UI - Virus &amp;
REM threat protection - Manage settings) before running this.
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
set "INSTALL=%ProgramFiles%\ShadowStrike\Phantom"
set "STAGE=%LOCALAPPDATA%\ShadowStrike-Install"

echo === [1/5] Adding Defender exclusions for ShadowStrike paths ===
REM The single most important step: even if Defender runs, these paths
REM will be ignored. This is what the previous version was missing and
REM is why the service EXE kept being quarantined as PUP/virus.
powershell -NoProfile -Command ^
  "try { Add-MpPreference -ExclusionPath '%INSTALL%','%STAGE%','%STAGE%\payload' -ErrorAction Stop;" ^
  "Add-MpPreference -ExclusionProcess 'ShadowStrikePhantomService.exe','ShadowStrikePhantomTray.exe','ShadowStrikePhantomUI.exe' -ErrorAction Stop;" ^
  "Write-Host '    OK: exclusions registered.' } catch { Write-Host ('    [!] Add-MpPreference failed: ' + $_.Exception.Message) }"

echo === [2/5] Applying policy keys to disable Defender ===
set "WD=HKLM\SOFTWARE\Policies\Microsoft\Windows Defender"
reg add "%WD%"                      /v DisableAntiSpyware        /t REG_DWORD /d 1 /f >nul
reg add "%WD%"                      /v DisableAntiVirus          /t REG_DWORD /d 1 /f >nul
reg add "%WD%\Real-Time Protection" /v DisableRealtimeMonitoring /t REG_DWORD /d 1 /f >nul
reg add "%WD%\Real-Time Protection" /v DisableBehaviorMonitoring /t REG_DWORD /d 1 /f >nul
reg add "%WD%\Real-Time Protection" /v DisableOnAccessProtection /t REG_DWORD /d 1 /f >nul
reg add "%WD%\Real-Time Protection" /v DisableScanOnRealtimeEnable /t REG_DWORD /d 1 /f >nul
reg add "%WD%\Real-Time Protection" /v DisableIOAVProtection     /t REG_DWORD /d 1 /f >nul
reg add "%WD%\Spynet"               /v SpynetReporting           /t REG_DWORD /d 0 /f >nul
reg add "%WD%\Spynet"               /v SubmitSamplesConsent      /t REG_DWORD /d 2 /f >nul
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v EnableSmartScreen /t REG_DWORD /d 0 /f >nul

echo === [3/5] Disabling Defender services ===
for %%S in (WinDefend WdNisSvc WdNisDrv Sense SecurityHealthService) do (
    reg add "HKLM\SYSTEM\CurrentControlSet\Services\%%S" /v Start /t REG_DWORD /d 4 /f >nul 2>&1
    sc config %%S start= disabled >nul 2>&1
    sc stop   %%S >nul 2>&1
)

echo === [4/5] Disabling Defender scheduled tasks ===
for %%T in ("Microsoft\Windows\Windows Defender\Windows Defender Cache Maintenance" ^
            "Microsoft\Windows\Windows Defender\Windows Defender Cleanup" ^
            "Microsoft\Windows\Windows Defender\Windows Defender Scheduled Scan" ^
            "Microsoft\Windows\Windows Defender\Windows Defender Verification") do (
    schtasks /Change /TN %%T /DISABLE >nul 2>&1
)

echo === [5/5] Runtime preferences (best effort) ===
taskkill /f /im MsMpEng.exe               >nul 2>&1
taskkill /f /im NisSrv.exe                >nul 2>&1
taskkill /f /im SecurityHealthService.exe >nul 2>&1
powershell -NoProfile -Command "Set-MpPreference -DisableRealtimeMonitoring $true -DisableBehaviorMonitoring $true -DisableIOAVProtection $true -DisableScriptScanning $true -MAPSReporting Disabled -SubmitSamplesConsent NeverSend -ErrorAction SilentlyContinue" >nul 2>&1

echo.
echo ============================================================
echo Defender neutralised + install path excluded.
echo REBOOT THE VM for the policy changes to take effect.
echo After reboot verify with:
echo     powershell Get-MpPreference ^| Select ExclusionPath
echo Should list C:\Program Files\ShadowStrike\Phantom etc.
echo ============================================================
pause
exit /b 0
