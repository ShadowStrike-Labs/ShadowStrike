@echo off
call "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat"
set SRC=C:\ShadowStrike\ShadowStrike\src
set INC=C:\ShadowStrike\ShadowStrike\include
set OUTDIR=C:\ShadowStrike\ShadowStrike\bin\zerohour_harness
set TESTS=C:\ShadowStrike\ShadowStrike\tests\unit\realtime_unit
set GTEST_LIB=C:\ShadowStrike\ShadowStrike\vendor\gtest_framework\gtest.lib
set CL_FLAGS=/std:c++20 /EHsc /W3 /MDd /Gy /FI"%SRC%\pch.h" /I"%SRC%" /I"%INC%" /nologo

if not exist "%OUTDIR%" mkdir "%OUTDIR%"

echo Compiling ZeroHourProtection.cpp...
cl.exe %CL_FLAGS% /c /Fo"%OUTDIR%\ZeroHourProtection.obj" "%SRC%\Shared_modules\RealTime\ZeroHourProtection.cpp"
echo ZHP_EXIT=%ERRORLEVEL%

echo Compiling stubs...
cl.exe %CL_FLAGS% /c /Fo"%OUTDIR%\ZeroHour_stubs.obj" "%TESTS%\ZeroHour_stubs.cpp"
echo STUBS_EXIT=%ERRORLEVEL%

echo Compiling utils...
cl.exe %CL_FLAGS% /c /Fo"%OUTDIR%\Logger.obj" "%SRC%\Shared_modules\Utils\Logger.cpp"
cl.exe %CL_FLAGS% /c /Fo"%OUTDIR%\StringUtils.obj" "%SRC%\Shared_modules\Utils\StringUtils.cpp"
cl.exe %CL_FLAGS% /c /Fo"%OUTDIR%\FileUtils.obj" "%SRC%\Shared_modules\Utils\FileUtils.cpp"
cl.exe %CL_FLAGS% /c /Fo"%OUTDIR%\SystemUtils.obj" "%SRC%\Shared_modules\Utils\SystemUtils.cpp"
cl.exe %CL_FLAGS% /c /Fo"%OUTDIR%\HashUtils.obj" "%SRC%\Shared_modules\Utils\HashUtils.cpp"

echo Compiling test files...
cl.exe %CL_FLAGS% /c /Fo"%OUTDIR%\test_main.obj" "C:\ShadowStrike\ShadowStrike\tests\test_main.cpp"
cl.exe %CL_FLAGS% /c /Fo"%OUTDIR%\ZeroHourProtection_Tests.obj" "%TESTS%\ZeroHourProtection_Tests.cpp"

echo Linking...
link.exe /nologo /OPT:REF /OPT:ICF "%OUTDIR%\ZeroHourProtection.obj" "%OUTDIR%\ZeroHour_stubs.obj" "%OUTDIR%\Logger.obj" "%OUTDIR%\StringUtils.obj" "%OUTDIR%\FileUtils.obj" "%OUTDIR%\SystemUtils.obj" "%OUTDIR%\HashUtils.obj" "%OUTDIR%\test_main.obj" "%OUTDIR%\ZeroHourProtection_Tests.obj" "%GTEST_LIB%" /OUT:"%OUTDIR%\zerohour_clean.exe" kernel32.lib user32.lib advapi32.lib ntdll.lib bcrypt.lib
echo LINK_EXIT=%ERRORLEVEL%
