@echo off
REM =====================================================================
REM ShadowStrike Phantom Home - VM installer (XCOPY + SCM, NO MSI).
REM =====================================================================
setlocal ENABLEDELAYEDEXPANSION

set "STAGE=%LOCALAPPDATA%\ShadowStrike-Install"
if /I "%~dp0"=="%STAGE%\" goto staged

REM ---- First invocation: copy to local disk, relaunch from there ------
echo [stage] Copying installer to %STAGE% ...
if not exist "%STAGE%" mkdir "%STAGE%" 2>nul
for %%F in ("%~dp0*.bat" "%~dp0README.txt") do (
    if exist %%F copy /y %%F "%STAGE%\" >nul 2>&1
)
if exist "%~dp0payload\app" (
    echo [stage] Copying payload to %STAGE%\payload ^(first run only, please wait^) ...
    robocopy "%~dp0payload" "%STAGE%\payload" /E /MT:8 /R:1 /W:1 /NFL /NDL /NJH /NJS /NC /NS /NP
    set RC=!ERRORLEVEL!
    if !RC! geq 8 (
        echo [!] robocopy failed copying payload. exit=!RC!
        echo     Check the shared folder is accessible from the VM, then retry.
        pause
        exit /b 1
    )
) else (
    echo [!] payload\app not found next to this script at %~dp0payload\app
    pause
    exit /b 1
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
set "HERE=%~dp0"
set "SRC=%HERE%payload\app"
set "DST=%ProgramFiles%\ShadowStrike\Phantom"
set "SVC=ShadowStrikePhantomService"

if not exist "%SRC%\ShadowStrikePhantomService.exe" (
    echo [!] Missing %SRC%\ShadowStrikePhantomService.exe
    echo     The staging copy did not include the payload tree.
    pause
    exit /b 1
)

echo.
echo === ShadowStrike Phantom Home - installer ===
echo Source : %SRC%
echo Target : %DST%
echo.

echo [1/6] Tearing down any previous install...
REM Stop service gracefully first, then force-kill if it is stuck in
REM START_PENDING (our previous builds could wedge there for minutes).
sc stop %SVC% >nul 2>&1
timeout /t 2 /nobreak >nul
for /f "tokens=2" %%P in ('sc queryex %SVC% 2^>nul ^| findstr /I "PID"') do (
    if not "%%P"=="0" (
        echo     Force-killing stuck service PID %%P ...
        taskkill /f /pid %%P >nul 2>&1
    )
)
taskkill /f /im ShadowStrikePhantomService.exe >nul 2>&1
taskkill /f /im ShadowStrikePhantomTray.exe    >nul 2>&1
taskkill /f /im ShadowStrikePhantomUI.exe      >nul 2>&1
taskkill /f /im msiexec.exe                    >nul 2>&1
fltmc detach PhantomSensor >nul 2>&1
fltmc unload PhantomSensor >nul 2>&1
sc query %SVC% >nul 2>&1
if not errorlevel 1 sc delete %SVC% >nul 2>&1
REM SCM can take a moment to truly release the binary after delete.
timeout /t 2 /nobreak >nul

echo [2/6] Deploying files to %DST% ...
if not exist "%DST%" mkdir "%DST%" >nul 2>&1
robocopy "%SRC%" "%DST%" /E /MT:8 /R:2 /W:2 /NFL /NDL /NJH /NJS /NC /NS /NP
set RC=!ERRORLEVEL!
if !RC! geq 8 (
    echo [!] robocopy reported errors exit=!RC!. Aborting.
    echo     Most common cause: Defender quarantined the service EXE.
    echo     Fix: run 00_disable_defender.bat, reboot, then retry.
    pause
    exit /b 2
)

echo [3/6] Registering Windows service %SVC% ...
sc create %SVC% binPath= "\"%DST%\ShadowStrikePhantomService.exe\"" start= auto type= own DisplayName= "ShadowStrike Phantom Service"
if errorlevel 1 (
    echo [!] sc create failed. gle=%errorlevel%
    pause
    exit /b 3
)
sc description %SVC% "Provides ShadowStrike Phantom Home real-time protection, scanning, and telemetry." >nul
sc failure     %SVC% reset= 86400 actions= restart/60000/restart/60000/run/0 >nul

echo [4/6] Registering tray autostart (HKLM Run) ...
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" /v ShadowStrikePhantomTray /t REG_SZ /d "\"%DST%\ShadowStrikePhantomTray.exe\"" /f >nul

echo [5/6] Creating Start-menu shortcut ...
powershell -NoProfile -Command "$s=(New-Object -ComObject WScript.Shell).CreateShortcut('%ProgramData%\Microsoft\Windows\Start Menu\Programs\ShadowStrike Phantom.lnk'); $s.TargetPath='%DST%\ShadowStrikePhantomUI.exe'; $s.WorkingDirectory='%DST%'; $s.IconLocation='%DST%\ShadowStrikePhantomUI.exe,0'; $s.Save()" >nul 2>&1

REM ---- PhantomCortex model directory (ProgramData, world-readable) ----
echo [5b/6] Preparing PhantomCortex model store ...
set "MODELDIR=%ProgramData%\ShadowStrike\Models"
if not exist "%MODELDIR%" mkdir "%MODELDIR%" >nul 2>&1
if exist "%SRC%\Models" (
    robocopy "%SRC%\Models" "%MODELDIR%" /E /R:1 /W:1 /NFL /NDL /NJH /NJS /NC /NS /NP >nul
)
REM Register the model directory so the service picks it up even without a
REM full CortexConfig.json deployment.
reg add "HKLM\SOFTWARE\ShadowStrike\PhantomCortex" /v ModelDirectory /t REG_SZ /d "%MODELDIR%" /f >nul 2>&1

echo [6/6] Starting service...
sc start %SVC%
set TRIES=0
:wait_running
timeout /t 1 /nobreak >nul
sc query %SVC% | findstr /I "RUNNING" >nul
if not errorlevel 1 goto running
set /a TRIES+=1
if !TRIES! lss 15 goto wait_running
echo [!] Service did not reach RUNNING within 15 s. Current state:
sc query %SVC%
echo     Run 04_collect_diagnostics.bat for details.
goto skip_driver
:running
echo     OK: service is RUNNING.

:skip_driver
REM ---- Minifilter driver is OPTIONAL on Home.
REM The user-mode product works fully without it; loading it requires
REM test-signing which breaks Windows 11 display. Use 05_enable_driver_dev.bat
REM if you specifically want to exercise the kernel sensor.
if exist "%DST%\Drivers\PhantomSensor.inf" (
    bcdedit /enum {current} 2>nul | findstr /I "testsigning" | findstr /I "Yes" >nul 2>&1
    if not errorlevel 1 (
        echo [*] test-signing is on, attempting to load PhantomSensor minifilter ...
        REM Trust the test-signing cert so pnputil accepts the driver package.
        if exist "%DST%\Drivers\PhantomSensor.cer" (
            certutil -addstore -f Root            "%DST%\Drivers\PhantomSensor.cer" >nul 2>&1
            certutil -addstore -f TrustedPublisher "%DST%\Drivers\PhantomSensor.cer" >nul 2>&1
        )
        pnputil /add-driver "%DST%\Drivers\PhantomSensor.inf" /install >nul 2>&1
        fltmc load PhantomSensor               >nul 2>&1
        fltmc filters 2>nul | findstr /I PhantomSensor >nul 2>&1
        if not errorlevel 1 (
            echo     OK: PhantomSensor minifilter is loaded.
        ) else (
            echo     [!] PhantomSensor did not load. Check fltmc output and 04_collect_diagnostics.bat.
        )
    ) else (
        echo [*] driver skipped ^(user-mode only install; run 05_enable_driver_dev.bat to enable^)
    )
)

echo.
echo Launching tray for current session...
start "" "%DST%\ShadowStrikePhantomTray.exe"

echo.
echo ============================================================
echo Install complete.
echo   Service  : %SVC% - %DST%\ShadowStrikePhantomService.exe
echo   Tray     : autostart + just launched
echo   UI       : %DST%\ShadowStrikePhantomUI.exe
echo ============================================================
echo.
echo Right-click the tray icon - "Show ShadowStrike Phantom" to launch the UI.
echo If the UI does not open, run 04_collect_diagnostics.bat.
echo.
pause
endlocal
exit /b 0
