@echo off
:: ShadowStrike - Deep Diagnostic v2
:: This checks Event Logs for the REAL reason driver load fails
:: Run as Administrator
echo ============================================================
echo  ShadowStrike - Deep Load Diagnostic
echo ============================================================
echo.

net session >nul 2>&1
if %errorlevel% neq 0 (
    echo [!] Run as Administrator!
    pause
    exit /b 1
)

echo [1] Clearing CodeIntegrity log...
wevtutil cl Microsoft-Windows-CodeIntegrity/Operational 2>nul
wevtutil cl System 2>nul

echo [2] Attempting fltmc load...
fltmc load PhantomSensor
echo     Result: %errorlevel%
echo.

echo [3] Checking CodeIntegrity events (last 10)...
echo.
powershell -Command "Get-WinEvent -LogName 'Microsoft-Windows-CodeIntegrity/Operational' -MaxEvents 10 2>$null | Format-List TimeCreated,Id,LevelDisplayName,Message"
echo.

echo [4] Checking System log for driver errors (last 20)...
echo.
powershell -Command "Get-WinEvent -LogName System -MaxEvents 50 2>$null | Where-Object { $_.ProviderName -match 'Service Control|CodeIntegrity|FilterManager|PhantomSensor' -or $_.Message -match 'PhantomSensor' } | Select-Object -First 10 | Format-List TimeCreated,ProviderName,Id,LevelDisplayName,Message"
echo.

echo [5] Checking CI Policy...
powershell -Command "Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard 2>$null | Format-List *"
echo.

echo [6] Smart App Control check...
reg query "HKLM\SYSTEM\CurrentControlSet\Control\CI\Policy" 2>nul
echo.

echo [7] Checking driver signature with sigcheck...
echo     (Using PowerShell Get-AuthenticodeSignature)
powershell -Command "$s = Get-AuthenticodeSignature 'C:\Windows\System32\drivers\PhantomSensor.sys'; $s | Format-List *"
echo.

echo [8] Alternative: trying net start...
net start PhantomSensor
echo.

echo ============================================================
echo  Copy ALL output above and send it
echo ============================================================
pause