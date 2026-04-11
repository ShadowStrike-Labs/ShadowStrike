@echo off
call "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat"
if not exist "C:\ShadowStrike\ShadowStrike\build\ep_test_obj" mkdir "C:\ShadowStrike\ShadowStrike\build\ep_test_obj"
cl.exe /std:c++20 /EHsc /W3 /Gy /FI"C:\ShadowStrike\ShadowStrike\src\pch.h" /I"C:\ShadowStrike\ShadowStrike\src" /I"C:\ShadowStrike\ShadowStrike\include" /c /Fo"C:\ShadowStrike\ShadowStrike\build\ep_test_obj\ExploitPrevention.obj" "C:\ShadowStrike\ShadowStrike\src\Shared_modules\RealTime\ExploitPrevention.cpp"
echo EXITCODE=%ERRORLEVEL%
