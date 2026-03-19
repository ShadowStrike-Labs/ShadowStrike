@echo off
:: ShadowStrike VM Diagnostic Script
:: Run as Administrator
echo ============================================================
echo  ShadowStrike VM Environment Diagnostic
echo ============================================================
echo.

net session >nul 2>&1
if %errorlevel% neq 0 (
    echo [!] NOT running as Administrator!
    pause
    exit /b 1
)

echo --- Test Signing ---
bcdedit /enum {current} | findstr /i "testsigning"
echo.

echo --- Secure Boot ---
powershell -Command "try { $sb = Confirm-SecureBootUEFI; Write-Host 'Secure Boot: ' $sb } catch { Write-Host 'Secure Boot: Not supported / OFF' }"
echo.

echo --- HVCI / Memory Integrity ---
reg query "HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity" /v Enabled 2>nul
if %errorlevel% neq 0 echo    HVCI key not found (likely OFF)
echo.

echo --- VBS ---
reg query "HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard" /v EnableVirtualizationBasedSecurity 2>nul
if %errorlevel% neq 0 echo    VBS key not found
echo.

echo --- Code Integrity Policy ---
reg query "HKLM\SYSTEM\CurrentControlSet\Control\CI" /v UMCIAuditMode 2>nul
reg query "HKLM\SYSTEM\CurrentControlSet\Control\CI\Config" 2>nul
echo.

echo --- System Info ---
powershell -Command "Get-ComputerInfo | Select-Object OsName,OsVersion,OsBuildNumber | Format-List"
echo.

echo --- Driver Signature Enforcement ---
bcdedit /enum {current} | findstr /i "nointegritychecks"
echo.

echo --- Certificate Check ---
powershell -Command "Get-ChildItem Cert:\LocalMachine\Root | Where-Object { $_.Subject -like '*WDKTestCert*' } | Format-Table Subject,Thumbprint -AutoSize"
powershell -Command "Get-ChildItem Cert:\LocalMachine\TrustedPublisher | Where-Object { $_.Subject -like '*WDKTestCert*' } | Format-Table Subject,Thumbprint -AutoSize"
echo.

echo --- PhantomSensor.sys signature ---
powershell -Command "$s = Get-AuthenticodeSignature 'C:\Windows\System32\drivers\PhantomSensor.sys'; Write-Host 'Status:' $s.Status; Write-Host 'Signer:' $s.SignerCertificate.Subject"
echo.

echo --- Attempting load with nointegritychecks ---
echo Setting nointegritychecks ON (requires reboot to take effect)...
bcdedit /set nointegritychecks on
echo.
echo --- Disabling HVCI via registry ---
reg add "HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity" /v "Enabled" /t REG_DWORD /d 0 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard" /v "EnableVirtualizationBasedSecurity" /t REG_DWORD /d 0 /f
echo.
echo ============================================================
echo  REBOOT the VM, then run install_test.bat again!
echo  nointegritychecks + HVCI disabled should fix Access Denied
echo ============================================================
echo.
pause