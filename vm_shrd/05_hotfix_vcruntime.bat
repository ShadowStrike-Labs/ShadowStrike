@echo off
REM =====================================================================
REM ShadowStrike Phantom Home - VC++ Runtime hotfix for fresh Windows 11.
REM
REM Symptom: Tray's "Open Dashboard" flickers the mouse cursor then does
REM nothing. Root cause: ShadowStrikePhantomUI.exe (Qt6) fails loader with
REM STATUS_DLL_NOT_FOUND (0xC0000135) because MSVCP140.dll / VCRUNTIME140*
REM are not present on a fresh Win11 image.
REM
REM This script copies the redistributable DLLs shipped in payload\app\
REM directly into the installed program directory. Self-elevates to Admin
REM and stages itself into %LOCALAPPDATA% so it can reach inside
REM %ProgramFiles% without UNC permission issues from the shared folder.
REM =====================================================================
setlocal ENABLEDELAYEDEXPANSION

set "STAGE=%LOCALAPPDATA%\ShadowStrike-Install"
set "SRC=%~dp0payload\app"
set "DST=%ProgramFiles%\ShadowStrike\Phantom"

if /I "%~dp0"=="%STAGE%\" goto staged

echo [stage] Copying hotfix script and payload to %STAGE% ...
if not exist "%STAGE%\payload\app" mkdir "%STAGE%\payload\app" 2>nul
copy /y "%~f0" "%STAGE%\" >nul 2>&1
xcopy /y /i /e "%~dp0payload\app\*" "%STAGE%\payload\app\" >nul 2>&1
echo [stage] Launching elevated copy ...
start "ShadowStrike Hotfix" cmd /k ""%STAGE%\%~nx0""
exit /b 0

:staged
net session >nul 2>&1
if not errorlevel 1 goto body
echo.
echo [elevate] Requesting Administrator rights. Click YES on the UAC prompt.
powershell -NoProfile -Command "Start-Process -FilePath cmd -Verb RunAs -ArgumentList ('/k ""' + $env:LOCALAPPDATA + '\ShadowStrike-Install\%~nx0""')"
exit /b 0

:body
set "SRC=%LOCALAPPDATA%\ShadowStrike-Install\payload\app"

echo.
echo === ShadowStrike Phantom VC++ runtime hotfix ===
echo   Source:  %SRC%
echo   Target:  %DST%
echo.

if not exist "%DST%" (
    echo [!] Install directory not found: %DST%
    echo     Run 02_install.bat first.
    pause & exit /b 1
)

set "FILES=msvcp140.dll vcruntime140.dll vcruntime140_1.dll d3dcompiler_47.dll concrt140.dll msvcp140_1.dll msvcp140_2.dll vccorlib140.dll"
set COPIED=0
for %%F in (%FILES%) do (
    if exist "%SRC%\%%F" (
        copy /y "%SRC%\%%F" "%DST%\%%F" >nul 2>&1
        if not errorlevel 1 (
            echo [ok]   %%F
            set /a COPIED+=1
        ) else (
            echo [FAIL] %%F
        )
    ) else (
        echo [miss] %%F not present in payload
    )
)

echo.
echo %COPIED% file(s) installed into %DST%.

echo.
echo [tray] Restarting tray icon so it reconnects cleanly ...
taskkill /f /im ShadowStrikePhantomTray.exe >nul 2>&1
timeout /t 1 /nobreak >nul
start "" "%DST%\ShadowStrikePhantomTray.exe"

echo.
echo === Hotfix complete. Now right-click the tray icon -^> Open Dashboard. ===
pause
exit /b 0
