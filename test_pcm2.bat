@echo off
call "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat"
set CL_FLAGS=/std:c++20 /EHsc /W3 /MDd /Gy /FI"C:\ShadowStrike\ShadowStrike\src\pch.h" /I"C:\ShadowStrike\ShadowStrike\src" /I"C:\ShadowStrike\ShadowStrike\include" /I"C:\ShadowStrike\ShadowStrike\src\Shared_modules" /nologo
echo === ProcessCreationMonitor ===
cl.exe %CL_FLAGS% /c /Fo"C:\ShadowStrike\ShadowStrike\bin\pcm_test\ProcessCreationMonitor.obj" "C:\ShadowStrike\ShadowStrike\src\Shared_modules\RealTime\ProcessCreationMonitor.cpp" 2>&1 | findstr "error"
echo PCM_EXIT=%ERRORLEVEL%
