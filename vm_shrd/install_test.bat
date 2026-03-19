@echo off
:: ============================================================
:: ShadowStrike PhantomSensor - VM Test Install Script v3
:: Run as Administrator
:: ============================================================
setlocal

echo ============================================================
echo  ShadowStrike PhantomSensor - VM Installer v3
echo ============================================================
echo.

net session >nul 2>&1
if %errorlevel% neq 0 (
    echo [!] ERROR: Run as Administrator!
    pause
    exit /b 1
)

:: Step 0: Install test certificate into Trusted Root + Trusted Publishers
echo [0/6] Installing test signing certificate...
certutil -addstore Root "%~dp0PhantomSensorTest.cer"
certutil -addstore TrustedPublisher "%~dp0PhantomSensorTest.cer"
echo.

:: Step 1: Clean old driver
echo [1/6] Removing old driver...
fltmc unload PhantomSensor >nul 2>&1
sc stop PhantomSensor >nul 2>&1
timeout /t 2 /nobreak >nul
sc delete PhantomSensor >nul 2>&1
timeout /t 2 /nobreak >nul
del /f /q "C:\Windows\System32\drivers\PhantomSensor.sys" >nul 2>&1

:: Step 2: Copy driver
echo [2/6] Copying PhantomSensor.sys...
copy /y "%~dp0PhantomSensor.sys" "C:\Windows\System32\drivers\PhantomSensor.sys"
for %%A in ("C:\Windows\System32\drivers\PhantomSensor.sys") do (
    echo      Size: %%~zA bytes
)

:: Step 3: Create service
echo [3/6] Creating service...
sc create PhantomSensor type= filesys binPath= "system32\drivers\PhantomSensor.sys" start= demand group= "FSFilter Anti-Virus" DisplayName= "ShadowStrike PhantomSensor"

:: Step 4: Registry
echo [4/6] Setting minifilter registry...
reg add "HKLM\SYSTEM\CurrentControlSet\Services\PhantomSensor\Instances" /v "DefaultInstance" /t REG_SZ /d "PhantomSensor Instance" /f >nul
reg add "HKLM\SYSTEM\CurrentControlSet\Services\PhantomSensor\Instances\PhantomSensor Instance" /v "Altitude" /t REG_SZ /d "385210" /f >nul
reg add "HKLM\SYSTEM\CurrentControlSet\Services\PhantomSensor\Instances\PhantomSensor Instance" /v "Flags" /t REG_DWORD /d 0 /f >nul
reg add "HKLM\SYSTEM\CurrentControlSet\Services\PhantomSensor\Parameters" /f >nul

:: Step 5: Verify test signing
echo [5/6] Checking environment...
bcdedit /enum {current} | findstr /i "testsigning" | findstr /i "Yes" >nul 2>&1
if %errorlevel% neq 0 (
    echo [!] Test signing is OFF - enabling...
    bcdedit /set testsigning on
    echo [!] REBOOT required, then run again.
    pause
    exit /b 0
)
echo      Test signing: ON

:: Step 6: Load
echo [6/6] Loading PhantomSensor...
echo.
fltmc load PhantomSensor
if %errorlevel% neq 0 (
    echo.
    echo ============ LOAD FAILED ============
    echo.
    echo -- Service Status --
    sc query PhantomSensor
    echo.
    echo -- Service Config --
    sc qc PhantomSensor
    echo.
    echo -- Trying sc start instead --
    sc start PhantomSensor
    echo.
    echo -- Driver file --
    if exist "C:\Windows\System32\drivers\PhantomSensor.sys" (
        echo File EXISTS
        for %%A in ("C:\Windows\System32\drivers\PhantomSensor.sys") do echo Size: %%~zA bytes
    ) else (
        echo File MISSING!
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