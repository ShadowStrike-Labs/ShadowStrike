@echo off
REM =====================================================================
REM ShadowStrike Phantom Home - disable Windows Defender on a VM.
REM PREREQ: Tamper Protection must be OFF manually via Windows Security UI.
REM =====================================================================
setlocal ENABLEDELAYEDEXPANSION

set "STAGE=%LOCALAPPDATA%\ShadowStrike-Install"
if /I "%~dp0"=="%STAGE%\" goto local

REM ---- First invocation: copy to local disk, relaunch from there ------
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

echo === Applying Group Policy keys to disable Defender ===
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
reg add "%WD%\Signature Updates"    /v ForceUpdateFromMU         /t REG_DWORD /d 0 /f >nul
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v EnableSmartScreen /t REG_DWORD /d 0 /f >nul

echo === Disabling Defender services (Start=4) ===
for %%S in (WinDefend WdNisSvc WdNisDrv Sense SecurityHealthService) do (
    reg add "HKLM\SYSTEM\CurrentControlSet\Services\%%S" /v Start /t REG_DWORD /d 4 /f >nul 2>&1
    sc config %%S start= disabled >nul 2>&1
    sc stop   %%S >nul 2>&1
)

echo === Disabling Defender scheduled tasks ===
for %%T in ("Microsoft\Windows\Windows Defender\Windows Defender Cache Maintenance" ^
            "Microsoft\Windows\Windows Defender\Windows Defender Cleanup" ^
            "Microsoft\Windows\Windows Defender\Windows Defender Scheduled Scan" ^
            "Microsoft\Windows\Windows Defender\Windows Defender Verification") do (
    schtasks /Change /TN %%T /DISABLE >nul 2>&1
)

echo === Killing live Defender processes (best effort) ===
taskkill /f /im MsMpEng.exe             >nul 2>&1
taskkill /f /im NisSrv.exe              >nul 2>&1
taskkill /f /im SecurityHealthService.exe >nul 2>&1

echo === Setting runtime preferences (best effort) ===
powershell -NoProfile -Command "Set-MpPreference -DisableRealtimeMonitoring $true -DisableBehaviorMonitoring $true -DisableIOAVProtection $true -DisableScriptScanning $true -MAPSReporting Disabled -SubmitSamplesConsent NeverSend -ErrorAction SilentlyContinue" >nul 2>&1

echo.
echo [OK] Defender neutralised. REBOOT THE VM.
echo      After reboot verify with:
echo          powershell Get-MpComputerStatus ^| Select RealTimeProtectionEnabled
echo      Expected value: False
echo.
pause
exit /b 0
