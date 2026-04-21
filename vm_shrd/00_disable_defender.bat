@echo off
REM ShadowStrike Phantom Home - disable Windows Defender on a VM.
REM
REM PREREQ: Tamper Protection must be OFF (Windows Security UI, manual).
REM         Microsoft intentionally blocks programmatic disable while TP is on.

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

echo === Setting runtime preferences (best effort, TP may ignore) ===
powershell -NoProfile -Command "Set-MpPreference -DisableRealtimeMonitoring $true -DisableBehaviorMonitoring $true -DisableIOAVProtection $true -DisableScriptScanning $true -MAPSReporting Disabled -SubmitSamplesConsent NeverSend -ErrorAction SilentlyContinue" >nul 2>&1

echo.
echo [OK] Defender neutralised. REBOOT THE VM.
echo      After reboot verify with:
echo          powershell Get-MpComputerStatus ^| Select RealTimeProtectionEnabled
echo      Expected value: False
echo.
pause
exit /b 0
