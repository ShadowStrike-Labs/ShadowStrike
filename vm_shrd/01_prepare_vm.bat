@echo off
REM ShadowStrike Phantom Home - VM preparation (run ONCE per clean snapshot).
REM Auto-elevates to Administrator.

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

echo === Installing PhantomSensor test-signing cert into Root + TrustedPublisher ===
certutil -addstore Root            "%~dp0PhantomSensor.cer" || goto :err
certutil -addstore TrustedPublisher "%~dp0PhantomSensor.cer" || goto :err

echo.
echo === Enabling kernel test-signing mode (required for WDK-signed driver) ===
bcdedit /set testsigning on || goto :err

echo.
echo [OK] Preparation complete.
echo [!] REBOOT THE VM NOW, then run 02_install.bat.
pause
exit /b 0

:err
echo [X] Preparation step failed. Aborting.
pause
exit /b 1
