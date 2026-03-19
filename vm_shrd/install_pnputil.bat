@echo off
:: ShadowStrike - pnputil Install Script
:: Run as Administrator
:: All 3 files (sys+cat+inf) must be in SAME folder as this script
echo ============================================================
echo  ShadowStrike PhantomSensor - pnputil Installer
echo ============================================================
echo.

net session >nul 2>&1
if %errorlevel% neq 0 (
    echo [!] Run as Administrator!
    pause
    exit /b 1
)

echo [1/4] Unloading and removing old driver...
fltmc unload PhantomSensor >nul 2>&1
sc stop PhantomSensor >nul 2>&1
timeout /t 2 /nobreak >nul
sc delete PhantomSensor >nul 2>&1
timeout /t 2 /nobreak >nul
del /f /q "C:\Windows\System32\drivers\PhantomSensor.sys" >nul 2>&1

echo [2/4] Removing old pnputil driver package...
for /f "tokens=1" %%i in ('pnputil /enum-drivers 2^>nul ^| findstr /i "phantomsensor"') do (
    echo      Removing old package: %%i
    pnputil /delete-driver %%i /force >nul 2>&1
)

echo [3/4] Installing via pnputil...
pnputil /add-driver "%~dp0PhantomSensor.inf" /install
if %errorlevel% neq 0 (
    echo [!] pnputil failed! Trying alternative...
    echo.
    :: Fallback: manual INF install via rundll32
    rundll32.exe setupapi.dll,InstallHinfSection DefaultInstall.NTAMD64 128 %~dp0PhantomSensor.inf
    timeout /t 2 /nobreak >nul
)

echo [4/4] Loading PhantomSensor...
echo.
fltmc load PhantomSensor
if %errorlevel% neq 0 (
    echo.
    echo LOAD FAILED - trying sc start...
    sc start PhantomSensor
    if %errorlevel% neq 0 (
        echo.
        echo ============ STILL FAILED ============
        echo.
        echo -- Service registry --
        reg query "HKLM\SYSTEM\CurrentControlSet\Services\PhantomSensor" /v ImagePath
        echo.
        echo -- Driver file --
        if exist "C:\Windows\System32\drivers\PhantomSensor.sys" (
            for %%A in ("C:\Windows\System32\drivers\PhantomSensor.sys") do echo System32: %%~zA bytes
        ) else (
            echo NOT in System32\drivers
        )
        echo.
        echo -- DriverStore --
        dir /s /b "C:\Windows\System32\DriverStore\FileRepository\phantom*" 2>nul
        echo.
        echo -- Check events --
        powershell -Command "Get-WinEvent -LogName System -MaxEvents 20 2>$null | Where-Object { $_.Message -match 'PhantomSensor|FilterManager' } | Select-Object -First 5 | Format-List TimeCreated,Id,Message"
    )
) else (
    echo.
    echo ============ SUCCESS ============
    echo PhantomSensor is LOADED!
    echo.
    fltmc
)

echo.
pause